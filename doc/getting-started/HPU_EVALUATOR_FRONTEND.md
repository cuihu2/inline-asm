# Evaluator 前端入门

本页用于快速运行现有示例。完整应用代码、自定义构建目标和逐方法约束见
[HPU 应用编程手册](../reference/HPU_SEAL_API_REFERENCE.md)。

## 1. 当前入口

`hpu/seal/evaluator.hpp` 提供三个方案共用的应用前端：

- `ApplicationBuilder`：导入 SEAL 对象、记录计算图、标记输出并编译。
- `Ciphertext`、`Plaintext`：由 HPU 前端管理的逻辑值句柄。
- `Evaluator`：采用 SEAL 风格的方法名和输出参数。
- `CompiledApplication`：持有编译快照、交付包及验证结果。

context、编码、加密和密钥生成继续使用 native SEAL。前端自动准备应用需要的评估密钥、常量、twiddle 和工作区，应用代码无需手工添加这些资源。原有 `CkksOperationPlan`、`BfvOperationPlan`、`BgvOperationPlan` 接口仍可使用。它们生成的应用包在导出时也会自动执行相同的资源调度和严格逐指令验证。

## 2. 最小应用

下面代码假定已经准备好 `context` 和有效的 SEAL `encrypted_input`。它构造逐点加法应用；三种方案都支持此路径。

```cpp
#include "hpu/seal/evaluator.hpp"

hpu::seal_adapter::ApplicationBuilder application(context);
auto evaluator = application.evaluator();
const auto x = application.import_ciphertext("input/x", encrypted_input);

hpu::seal_adapter::Ciphertext y;
evaluator.add(x, x, y);
application.mark_output("y", y);

// 默认同时要求 SEAL、算子软件模型、最终指令模型的验证通过。
const auto compiled = application.compile("add_application");
compiled.write("outputs/add_application");
```

SEAL 方法调用在这里记录计算图，实际 host 执行及编译发生在 `compile()`。多次使用一个输入可以产生分支；调用顺序确定图的构造顺序，输入句柄决定依赖关系。

### 指定目标输出

只导出全部 `mark_output()` 指定的结果；没有标记时导出最后一个计算结果。
内部结果由编译器决定驻留、释放和 backing，不再为逐节点目标读回强制写回 DDR。
需要额外检查哪个中间值，就显式标记哪个值；主机仍运行逐节点 oracle 对照。

### 句柄与 inplace

句柄复制保留原逻辑值。`_inplace` 方法创建新的逻辑值，再更新传入的句柄：

```cpp
auto branch = x;
auto y = x;
evaluator.add_inplace(y, x);
// branch 仍指向原 x，y 指向 x+x。
```

输入与评估密钥以快照方式导入。编译结果独立持有图和资源，后续修改原始 SEAL 对象或继续构图不会改变已经编译的包。

### 显式元数据与后处理

`multiply` 和 `square` 的常用输入为二分量密文，输出三分量 tensor；`relinearize` 显式将其降为二分量。前端不会自动插入重线性化、rescale、mod_switch 或 scale 对齐。

```cpp
evaluator.multiply(x, mixed, y);
evaluator.relinearize_inplace(y, relin_keys);
evaluator.rescale_to_next_inplace(y); // CKKS
```

CKKS `set_scale` 是显式元数据视图：

```cpp
evaluator.set_scale(y, new_scale);
```

它共享密文数据，不发出算术指令，也不会重新量化系数。应用需要判断调整 scale 是否符合自己的数学计算。

## 3. 当前支持范围

| 操作 | CKKS | BFV | BGV |
| --- | --- | --- | --- |
| add / sub / multiply / square | 支持 | 支持 | 支持 |
| add_plain / sub_plain / multiply_plain | 支持 | 支持 | 支持 |
| relinearize：3 → 2 分量 | 支持 | 支持 | 支持 |
| negate | 支持 | 支持 | 前端暂不支持 |
| rescale_to_next | 支持 2、3 分量 | 不适用 | 不适用 |
| mod_switch_to_next | 前端暂不支持 | 支持 | 支持 |
| rotate_vector / complex_conjugate | 支持 | 不适用 | 不适用 |
| rotate_rows / rotate_columns | 不适用 | 支持 | 支持 |
| set_scale | 支持 | 不适用 | 不适用 |

除 CKKS rescale 和三分量重线性化外，目前多数算子使用二分量密文。BFV raw Multiply 要求当前 Q 至少有两个模数。上下文、level、scale、correction factor、密钥和输入句柄所属应用均在构图或编译时校验。

同一份 BFV 明文可以供不同消费者使用：前端按 Add/Sub 的系数域缩放方式或 MultiplyPlain 的 NTT 方式分别准备数据；BGV 明文准备同时考虑消费者的 correction factor。

## 4. 构建与运行三个示例

在仓库根目录执行：

```bash
cmake -S . -B build -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build -j --target \
  hpu_ckks_evaluator_example \
  hpu_bfv_evaluator_example \
  hpu_bgv_evaluator_example
```

三个示例分别见：

- [CKKS 前端应用](../../examples/ckks_evaluator_application.cpp)：`x*(RotateLeft(x,1)+Conjugate(x))+1`。
- [BFV 前端应用](../../examples/bfv_evaluator_application.cpp)：`x*(RotateRows(x,1)+RotateColumns(x))+7`，显式重线性化及降层。
- [BGV 前端应用](../../examples/bgv_evaluator_application.cpp)：相同整数表达式，使用 BGV 的 correction factor 和降层规则。

CLI 支持 `--degree N`、`--data-moduli COUNT`、`--seed UINT64`、`--emit-dir PATH`、
`--print-asm`、`--no-opt` 和 `--profile-execution`。后者尽可能提前加载，用一个连续窗口
测量全部算术及内部必要 IO，并排除原有尾部写回；目标回调及生成命令见
[单一连续窗口计时](HPU_EXECUTION_PROFILING.md)。默认 N=128、Q3+P1。`--data-moduli 4` 选择 Q4+P1，
`--seed` 固定测试 fixture；示例应用可用 N8192 做常规 IO 对照、N65536 做容量压力
测试。`--no-opt` 使用统一 SSA 后端生成原序基准，不承诺保持历史手写 DMA 和布局。
交付编译仍仅为 twiddle DLOAD 设置 CP=1，其余 DMA 为 0。

CKKS 示例在小 N 使用 `2^20` 输入 scale，大 N 使用原 composed 示例的 `2^35`，
保留 `1e-2` 解码容差。应用编程时仍需按计算深度和精度需求选择 scale。

### N8192、Q4、P1 的可重复 IO 对照

```sh
# 已构建三个 Evaluator 示例和 hpu_validate_package 后运行。
python3 tools/benchmark_io.py --build-dir build --output-root outputs/io_baseline --no-opt
python3 tools/benchmark_io.py --build-dir build --output-root outputs/io_optimized \
  --baseline-json outputs/io_baseline/io_summary.json

# 可选：单独测量 N65536，不要求有基线报告。
python3 tools/benchmark_io.py --build-dir build --output-root outputs/io_stress --degree 65536
```

runner 默认 N8192、Q4、P1、seed=0，可通过 `--degree`、`--data-moduli` 和 `--seed`
覆盖。它复用受管理的包发布工具，已有目录必须是可校验的同名同方案应用包；不会
把任意目录当作生成目录删除。三个包都生成并验证成功后，才发布根目录下的
`io_summary.json`。多次实验请使用不同输出根，以保留各次产物。

汇总文件记录实际参数、N/Q/P、fixture seed、完整导出输出集合、源码 provenance、
`candidate_schedules` 和所选调度。`metrics` 包括实际读写字节、DMA/指令次数、
spill/reload 次数与字节、精确副本 IO、重复范围读取、必需输出写回、初始镜像
大小及片上峰值；另保留逐 SSA value、逐 allocation、逐 kind 的 IO 和 SSA snapshot backing
映射。实际读写字节会再次按最终 DMA 清单核对。`exact_copy_bytes` 是报告中的
精确副本传输总量，不能当成独立 snapshot 写回字节。

`--baseline-json` 只接受该 runner 的报告，且三个方案的参数、fixture、导出
输出集合及 SEAL oracle payload 指纹必须分别完全一致，否则拒绝比较。比较结果按
数据类别列出读写字节差值，并单列 exact-copy、spill 和 reload 的基准值、当前值及
差值；这两种分类相互重叠，不能把各自总量相加。不提供它时只报告本次真实测量和本次
编译生成的候选，不推算历史收益。`all_checkpoint_dma_bytes` 是保留全部计算节点
checkpoint 的诊断流实际 IO；`output_policy_saved_dma_bytes` 是仅收敛导出根、
尚未做读取合并或转发时相对它减少的字节。`original_dma_bytes` 则是相同输出集合的
原序基准，后续复用和调度收益以它为准。`removed_checkpoint_min_write_bytes` 另给出
未导出 checkpoint 的最少写回量，不能与上述差值相加。

比较在线 PMUL 接入前后的产物时，可显式增加 `--allow-data-abi-change`。它仅允许
`ntt_table_abi` 不同，并在报告中记录前后 ABI；数学参数、fixture、输出集合及
oracle 指纹仍须一致。默认不允许这项差异。追加实测见
[PMUL 在线因子记录](../delivery/IO_OPTIMIZATION_RESULTS.md#6-pmul-在线因子扩展接入)。

单个用例也可直接执行 `hpu_ckks_evaluator_example --degree 8192 --data-moduli 4
--seed 0 --emit-dir PATH`，BFV/BGV 替换对应可执行文件即可。原始统计见包内
`oracle/report.json.compiler_resources`；runner 不模拟 LLC 命中或周期，真实性能
收益仍需 RTL/硬件测量。

### 默认生成与 NTT 软件契约

默认编译使用 `InstructionNttContract::raw_bit_reversed_coefficients`，并要求
SEAL、算子 SoftwareExecutor、最终指令模型逐字比较通过。正常生成使用下面的命令：

```bash
./build/hpu_ckks_evaluator_example --degree 128 \
  --emit-dir outputs/ckks_evaluator_application
./build/hpu_bfv_evaluator_example --degree 128 \
  --emit-dir outputs/bfv_evaluator_application
./build/hpu_bgv_evaluator_example --degree 128 \
  --emit-dir outputs/bgv_evaluator_application

# 保留基准调度
./build/hpu_ckks_evaluator_example --degree 128 --no-opt \
  --emit-dir outputs/ckks_evaluator_application_noopt

# 一次生成三个方案；部署目标使用 N=65536
cmake --build build --target hpu_frontend_delivery
cmake --build build -j2 --target hpu_frontend_deployment_delivery
```

前端目标与原有 `hpu_fhe_delivery` / `hpu_fhe_deployment_delivery` 分开，部署目录带
`_n65536`。生成命令不预先保证某个规模通过；实际结果以当次测试日志和包内报告为准。

新应用内部使用 BR 系数存储，导入/导出 SEAL 系数时保持自然序 API。twist、untwist、
lazy-scale 修正和归一化由显式在线 PMUL 完成，raw stage 不再增加软件边界 BR。
host 对拍不改变硬件验证状态。
完整变换和表索引见 [编程手册](../reference/HPU_PROGRAMMING_MANUAL.md#9-本项目的接入约定)，
镜像 ABI 与迁移要求见 [应用包 V1](../delivery/HPU_APPLICATION_PACKAGE_V1.md#新应用镜像的-ntt-表与软件边界)。

需要保留失败的指令模型报告进行诊断时，可显式选择：

```bash
./build/hpu_ckks_evaluator_example --degree 128 \
  --allow-unverified-instruction-model \
  --emit-dir outputs/ckks_evaluator_application_diagnostic
```

批量诊断目标仍为 `hpu_frontend_diagnostic_delivery` 和
`hpu_frontend_deployment_diagnostic_delivery`，输出目录带 `_diagnostic`。

C++ 的对应设置为 `CompileOptions.require_instruction_verification=false`；
`optimize_resources=false` 选择 NoOpt。诊断导出仍执行并记录指令验证，SEAL 与
算子 SoftwareExecutor 的比较必须通过；资源优化改变基准结果时也会失败。资源编译消费算子直接生成的 typed IR，`oracle/report.json.compiler_resources.ir_source` 为 `operator`。

### 显式选择回放契约

CLI 的 `--instruction-ntt-contract` 与 C++ 枚举对应如下：

| CLI 值 | `InstructionNttContract` | 用途 |
| --- | --- | --- |
| `raw-bit-reversed-coefficients` | `raw_bit_reversed_coefficients` | 默认，BR 系数和 BR pre/post 的新镜像 |
| `natural-coefficient-boundaries` | `natural_coefficient_boundaries` | 历史自然系数镜像回放 |
| `legacy-raw-stage` | `legacy_raw_stage` | 保留旧 raw stage，无整体边界 BR |

回放既有 raw 镜像时，可以对原指令、原 DMA span 和原镜像显式选择旧契约：

```cpp
hpu::model::InstructionExecutionOptions options;
options.ntt_contract = hpu::model::InstructionNttContract::legacy_raw_stage;
const auto replay = hpu::model::execute_instructions(
    old_program, old_dma_spans, old_image, options);
```

选择 profile 不重排表，也不修改 DMA、镜像或指令。新前端示例由 builder 准备 BR 系数及 BR 因子，选择 natural profile 会发生重复
重排；旧包应按原镜像 ABI 回放，迁移则重新生成完整包。
历史 `test/reference/main.cpp` 固定 profile 算子包保留 BR 系数镜像约定。
严格模式按所选契约比较全部 golden，失败即停止导出。

## 5. IT 应查看哪些结果

前端编译自动运行三个路径：

1. native SEAL Evaluator 按计算图生成独立 oracle，同时检查输出元数据。
2. 对应方案的 SoftwareExecutor 计算同一应用，逐节点与 oracle 比较。
3. 逐指令模型解码最终 `.inst32` 对应的指令字，使用实际镜像、DMA span 和 twiddle，再与 golden 比较。

优化模式还比较原序基准与优化流的全部导出结果。目标程序只强制写回全部
`mark_output` 指定的结果；未标记时保留最后计算结果。内部节点仍有主机 oracle，
但不保留逐节点目标读回空间。多个输出可同时标记，`set_scale` 视图不重复物理
输出；目标读回地址始终以最终 golden manifest 为准。

| 接口或字段 | 含义 |
| --- | --- |
| `compiled.verified()` | SEAL 与算子 SoftwareExecutor 的功能验证通过 |
| `compiled.instruction_verified()` | 最终指令模型与 oracle 的输出逐字匹配 |
| `oracle/report.json` → `host_instruction_model` | 指令验证状态、失败对象、字下标及 expected/actual |
| `host_instruction_model.ntt_contract` | 本次 host 回放使用的软件 NTT 契约 |
| `host_instruction_model.hardware_contract_verified` | 当前为 false；host 对拍不证明当前硬件映射 |
| `host_instruction_model.forward_boundary_conversions` | 本次实际执行的额外正向边界转换次数 |
| `host_instruction_model.inverse_boundary_conversions` | 本次实际执行的额外逆向边界转换次数 |
| `oracle/report.json` → `compiler_resources` | DDR、DMA、槽位、bank、spill 和逻辑缓冲区映射 |
| `optimization_equivalence_verified` | 优化流与 NoOpt 的保留输出一致性 |

`instruction_execution_verified`、`rtl_verified`、`hardware_verified` 等目标执行标记继续保留为 false。host 指令模型使用独立状态字段，不能替代目标平台验证。

应用的独立数学预期仍由用例作者编写，例如解密后与 `x²+1` 或槽位旋转表达式比较。框架可以发现两条实现路径之间的差异；用例的数学预期用于检查构图是否表达了原本想测试的公式。私钥仅用于 host 解密，不进入交付包。

交付包文件格式、Nexus-AM 消费方式与目标端读回要求见 [应用包 V1](../delivery/HPU_APPLICATION_PACKAGE_V1.md)；整体架构、runtime 和资源调度实现见 [HPU 项目架构](../architecture/HPU_ARCHITECTURE.md)。
