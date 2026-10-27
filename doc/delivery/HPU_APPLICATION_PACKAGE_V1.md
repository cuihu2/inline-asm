# 通用 HPU 应用交付包 v1

CKKS、BFV、BGV 使用同一目录协议。公共写入器位于 `hpu::delivery`，不依赖 SEAL；
SEAL 适配层负责参数、计算图、oracle 与物理输出格式的转换。
产物包含指令、初始数据和可编译的 C/H。Nexus AM 侧负责运行入口、内存装载、
RISC-V 编译链接及 ELF/BIN 生成；本项目的生成命令不执行板卡或驱动操作。
正式发布步骤、目标侧执行顺序和签字证据见
[IT 交接清单](IT_HANDOFF_CHECKLIST.md)。

## 生成与校验

```bash
cmake -S . -B build -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build -j --target hpu_fhe_delivery

# 也可按方案生成
cmake --build build -j --target hpu_ckks_delivery
cmake --build build -j --target hpu_bfv_delivery
cmake --build build -j --target hpu_bgv_delivery

# Evaluator 前端使用默认严格验证，不需要诊断选项
cmake --build build -j2 --target hpu_frontend_delivery

# 独立静态校验器，不会重新执行 SEAL
./build/hpu_validate_package outputs/bfv_rotation_application
```

| 目录 `outputs/<case>/` | 示例程序 | 计算内容 |
| --- | --- | --- |
| `ckks_polynomial_x2_plus_one` | `hpu_ckks_polynomial_example` | Square → Relinearize → Rescale → AddPlain |
| `ckks_composed_application` | `hpu_ckks_composed_application_example` | Rotate/Conjugate 分支 → Add → Multiply → Relinearize → Rescale → AddPlain |
| `bfv_multiply_modswitch_application` | `hpu_bfv_multiply_modswitch_example` | Multiply+Relinearize → ModSwitch → AddPlain |
| `bfv_rotation_application` | `hpu_bfv_rotation_example` | RotateRows/RotateColumns 分支 → Add |
| `bgv_plain_chain` | `hpu_bgv_plain_chain_example` | AddPlain → MultiplyPlain → SubtractPlain |
| `bgv_rotate_chain` | `hpu_bgv_rotate_chain_example` | AddPlain → RotateRows → AddPlain |
| `bgv_multiply_chain` | `hpu_bgv_multiply_chain_example` | AddPlain → Multiply+Relinearize → ModSwitch → AddPlain |
| `bgv_composed_application` | `hpu_bgv_composed_application_example` | RotateRows/RotateColumns 分支 → Add → Multiply → Relinearize → ModSwitch → AddPlain |

可以只生成一个案例，目标为 `<case>_delivery`。更改统一输出根目录使用
`-DHPU_APPLICATION_OUTPUT_ROOT=/path/to/packages`。

所有示例支持 `--degree N`（128 到 65536 的 2 次幂）和 `--emit-dir PATH`；目标目录要求不存在：

```bash
./build/hpu_bfv_rotation_example --emit-dir outputs/my_bfv_rotation
./build/hpu_bgv_multiply_chain_example --emit-dir outputs/my_bgv_multiply
```

构建目标通过 `tools/generate_application_package.py` 生成新包、校验后发布；
已有的同方案同案例有效包可以重复生成，普通目录、损坏包和旧扁平包不会被覆盖。
遇到旧包请先移动到备份目录，或选择新的输出根目录。生成失败时保留已有包。
生成时请勿同时改写或消费同一个目标目录。

每次示例运行使用新的 SEAL 随机密钥和加密随机数，因此跨次生成的字节可以不同；
同一次导出的指令、镜像和 golden 始终属于同一组测试。序列化对同一个请求是确定性的。
默认多项式示例为 N=65536，其余默认 N=128。所有示例提供 N=65536 配置，
部署规模通过 `hpu_fhe_deployment_delivery` 单独生成；目录后缀为 `_n65536`，
多项式示例沿用原目录。BFV 大规模配置使用 31-bit Q/P 和 20-bit batching t；
BGV 在 N=65536 使用 t=786433，满足 `2N | (t-1)`。这些配置用于功能测试，
不强制 SEAL 安全等级；实际参数记录在包内。SecretKey 和 PRNG seed 不进入交付包，执行所需的
重线性化/Galois key 已在初始镜像中。

## 部署规模生成

```bash
# 七个带 _n65536 后缀的包，加上原 N=65536 多项式包。
# 建议限制并行数，宿主需要同时准备密钥、软件模型和包镜像。
cmake --build build -j2 --target hpu_fhe_deployment_delivery

# 也可以只生成一个，或直接执行示例。
cmake --build build --target bgv_composed_application_n65536_delivery
./build/hpu_bgv_composed_application_example --degree 65536 --emit-dir outputs/my_bgv_n65536

# 将这些耗时包测试加入 CTest（默认不注册）。
cmake -S . -B build -DHPU_ENABLE_SEAL_INTEGRATION=ON \
  -DHPU_ENABLE_DEPLOYMENT_APPLICATION_TESTS=ON
ctest --test-dir build -L application-deployment --output-on-failure
```

BGV 图接口和完整分支示例见 [BGV 应用说明](../examples/BGV_COMPOSED_APPLICATION_EXAMPLE.md)。

## 目录与数据协议

```text
<case>/
├── package.json
├── program/
│   ├── <stem>.c / <stem>.h
│   ├── <stem>.asm / <stem>.inst32 / <stem>.cmd26
│   └── dma_relocation_manifest.csv
├── memory/
│   ├── hpu_mem_image.u32.bin
│   ├── line_map.csv / memory_manifest.csv
│   └── abi.json / hpu_mem_config.json
├── golden/
│   ├── golden_manifest.csv
│   └── objects/step_<index>/c<component>/mod<id>.u32.bin
├── metadata/
│   ├── parameters.json
│   └── operation_graph.json
├── oracle/report.json
├── semantic/decoded.json
└── provenance/
    ├── build.json
    └── files.csv
```

具体文件路径以 `package.json` 和清单中的 `path` 为准。`semantic/decoded.json`
在公共接口中是可选项，当前八个示例均提供。

- `package.json`：`schema=hpu-application-package`、`schema_version=1`、
  `scheme=ckks|bfv|bgv`、case 名称及各清单路径。
- `program/`：`.asm` 是指令流，`.inst32` 每行 32 位指令，`.cmd26` 每行 26 位
  command。C 文件提供 `hpu_program_<stem>(spans, count)` 和固定 DMA span 的
  `hpu_run_<stem>()`，供 Nexus AM 侧编译调用。动态入口保持原实现，每条 DMA
  分别设置 `x10/x11`；固定入口在生成前检查 span 范围、bank 容量及对象长度，
  使用一个连续汇编块，每条 DMA 前设置 `x10`，仅首次及长度变化时设置 `x11`。
  汇编块声明 `x10`、`x11` 和 `memory` clobber，HPU 指令次序及 DMA ABI 不变。
- 可选连续计时包增加 `package.json.execution_profile_manifest`，指向仅含一个窗口的
  `profiling/execution_window.csv`；使用 `hpu_run_<stem>_profiled()` 和目标完成回调，
  普通入口返回 `-5`。该窗口包含内部必要 DMA，使用方式见
  [单一连续窗口计时](../getting-started/HPU_EXECUTION_PROFILING.md)。
- DMA 清单统一为 15 列：`instruction_index,dma_index,operation_index,operation_id,`
  `operation_dma_index,direction,object_slot,type_or_release,flag,allocation_id,`
  `line_offset,line_count,word_hex,normalized_asm,cp`。三种方案均保留具体节点的 operation index/ID
  和节点内部 DMA 序号；公共模表加载使用 `$application`，operation index 为空。
  `type_or_release` 在 DLOAD 表示 MOD（0 普通对象、1 模表），在 DSTORE 表示 REL；
  `flag` 表示 DLOAD 的六位 bank mask（DSTORE 为 0），末列 `cp` 为每条 DMA 的 LLC 分配提示。
  接收方应按列名解析，旧 14 列清单不能替代当前清单。
- `memory/`：uint32 little-endian，每行 64 个 word，即 256 字节。
  镜像大小为 `used_lines * 256`，实际 HPU_MEM window 按 `capacity_lines` 配置。当前示例在布局完成后收紧容量，
  因此 `capacity_lines=used_lines`；构建时的容量上限不会变成目标窗口大小。
  `x10` 传 line offset，`x11` 传 line count；两者都是行数，不是字节地址。
  执行前加载初始镜像，output 与 workspace 从零开始。
- `golden_manifest.csv`：记录 object、component、MOD_ID、模数、domain、路径、
  目标行范围、有效 word 数、padding 和校验和。每个 `AllocationKind::output`
  恰有一个 golden limb。前端只导出全部标记结果，无标记则导出最后计算结果；
  Plan 默认只导出最终结果。内部 scratch 的 dstore 不必有独立 golden。`step_<index>` 与计算图中的 `golden_object_id` 相连。
- BFV golden 为 `coefficient_bit_reversed`；CKKS/BGV 为 `canonical_ntt_physical`。
  新应用包的系数域按每个 limb 独立 BR 存放。所有 word 均为 `[0,q)` 的 residue，文件补零到完整 HPU line。
- `parameters.json` 保存 N、plain modulus、安全等级、key-context 模数及各 level
  的 `parms_id`、Q 和 chain index。`operation_graph.json` 保存节点、输入引用、
  输出、level、scale/correction factor。节点的 `operation_index` 从 0 连续编号，
  `exported` 标明是否导出，只有导出节点具有 `golden_object_id=step_<index>`；
  未导出节点保留逻辑依赖，不声明不存在的持久 DDR 结果。
  BGV 只读资源可有多个逻辑名称，对外 memory 清单只列物理 allocation，
  DMA 的 `allocation_id` 始终指向这张清单中的物理对象。
- `provenance/files.csv` 列出其余文件的路径、角色、长度和 FNV-1a64。
  它用于发现损坏；不是发布者签名。`build.json` 记录 producer 信息。默认 revision
  和 worktree 状态采集于 CMake 配置时；正式生成可通过环境变量
  `HPU_DELIVERY_COMMIT`、`HPU_DELIVERY_WORKTREE_STATE` 提供实际生成版本。

不要将 golden 预加载进 HPU_MEM。IT 应加载 `memory/hpu_mem_image.u32.bin`，运行 C
入口，再按 golden 清单读回对应 span，比较有效 word 和补齐区域。
`.inst32`/`.cmd26` 本身不携带完整 CPU DMA sideband，也不是 ELF/BIN；可执行运行
需要使用 C wrapper 中的 span 设置，或等效实现 resolved DMA 清单。
固定入口的代码生成优化不改变包 V1：校验器同时接受新固定汇编入口和此前调用
动态入口的固定 wrapper。host 指令模型直接消费 DMA span，未执行 CPU wrapper；
目标代码中的寄存器设置由独立的
[目标 CPU 包装代码检查](IT_HANDOFF_CHECKLIST.md#31-目标-cpu-包装代码检查) 验证。

### 新应用镜像的 NTT 表与软件边界

自 2026-10-24 起，BFV、CKKS、BGV 统一采用 **BR 系数存储 ABI**。对每个
多项式、每个模数分量分别转换：`physical[j] = natural[BR_logN(j)]`。
对外 SEAL 系数接口仍使用自然序；NTT 域保持既有 canonical HPU physical 布局。

```text
pre_hw[j]  = psi^BR(j) mod q
post_hw[j] = raw_inverse.post_scale[j] * psi^(-BR(j)) mod q
NTT : BR coefficient -> online pre PMUL -> raw PNTT stages -> canonical NTT
INTT: canonical NTT -> raw PINTT stages -> online post PMUL -> BR coefficient
```

post 从完整正确的 raw inverse 后乘表出发，保留 lazy-scale 抵消和一次归一化；
modified-root INTT 使用对应 root 的完整表。不得只假设 post 等于 `N^-1*psi^-i`。
pre/post 完整物理向量由 `pack_online_pmul_factors` 压缩，必须验证全量展开一致；
无法精确压缩的参数直接报错。stage 表及其原有 loader/BF lane 顺序保持不变。

默认 `InstructionNttContract::raw_bit_reversed_coefficients` 只执行 raw stage，
**不在 stage0 或末级额外 BR**。报告中的两个 `*_boundary_conversions` 均为 0。
内部 INTT→系数运算→NTT 沿用 BR，无需 CPU/DDR 中途转换。
`natural_coefficient_boundaries` 和 `legacy_raw_stage` 仅供显式兼容回放，切换 profile
不会转换镜像；新 BR 镜像使用 natural profile 会重复重排。
修订依据与硬件证据范围见 [布局适配原文](../reference/HPU_NTT_SOFTWARE_LAYOUT_ADAPTATION_20261024.md)。
主机通过不代表 RTL/硬件通过，`hardware_contract_verified` 继续为 false。

BFV 和原生 INTT 的 `golden_manifest.csv.domain=coefficient_bit_reversed`：目标读回
物理 word 可直接逐字比较 golden；需要自然系数时，对每个 limb 解码 BR。
`coefficient` 保留表示历史自然系数输出。golden 的数学值仍来自独立 oracle，
只有交付时的排列转换；CKKS/BGV 的 NTT 输出不变。

新应用包的 `metadata/parameters.json` 记录实际的 NTT 数据 ABI：

```json
{
  "ntt_table_abi": {
    "version": 4,
    "coefficient_order": "bit_reversed",
    "external_coefficient_order": "natural",
    "pre_twist_order": "bit_reversed",
    "post_factor_order": "bit_reversed",
    "stage_twiddle_order": "reference_loader_batch_lane",
    "stage_twiddle_format": "hpu-twiddle-k8-v1",
    "twiddle_chains": 8,
    "stage_parameter_lines": 2,
    "online_pmul_format": "hpu-pmul-online-k8-v1",
    "online_pmul_parameter_lines": 2,
    "online_pmul_mode": 1,
    "online_pmul_parameter_bank_mask": 32,
    "canonical_ntt_layout": "reference_forward_layout",
    "normalization": "explicit_post_pmul",
    "twist_fused": false
  }
}
```

当前 PNTT/PINTT 的 PPARAM 是固定 **128 个 u32 / 2 line / 512 B** 的 K=8 参数对象。
第一条 line 是 64-lane 模板 U；第二条 line 保存 7 个 slot 初始化倍率 V、有效
stride-8 进位倍率 R，剩余 word 填 1。所有 N（包括 N=128）都使用这个布局，
PINTT stage 0 也必须加载参数。

pre/post 使用另一种固定两行模板 `hpu-pmul-online-k8-v1`，由对象 PMUL 的
`[15:14]=01` 按 U/V/R 递推完整物理因子，不要求相邻 word 等比。两者都是 512 B，但 **PMUL 的 B=N/64，stage 的
B=N/128**；PMUL post 的 U[0] 允许不为 1，不能套用要求首元素为 1 的 stage 校验。
模板字段与指令位见 [编程手册](../reference/HPU_PROGRAMMING_MANUAL.md#31-pmul-在线-prepost-因子2026-10-22-追加)
及 [硬件交接原文](../reference/PMUL_ONLINE_COMPILER_HANDOFF.md)。

`memory/abi.json` 同时记录 `stage_twiddle_format`、`twiddle_chains` 和
`stage_parameter_lines` 及上述四个 `online_pmul_*` 字段，供直接消费镜像的 IT
程序识别目标格式。package schema 仍为 v1；NTT 数据 ABI version=4、基础
ISA v1.2 与 package schema 是分别维护的版本。旧版完整 pre/post 向量包仍按其
原始声明校验；含在线 PMUL 的新包必须声明在线格式，完整重新生成镜像及指令。

该对象描述实际镜像布局，与回放 `ntt_contract` 分别记录。Package schema V1、
ISA v1.2、K=8 模板格式和 DMA 清单列数保持不变；数据 ABI 升至 4。
旧 version=3 的自然系数镜像不能直接用于当前 raw 执行路径。迁移时必须从源码重新
生成完整 image、golden、DMA spans、wrapper 和校验清单，不能只改元数据或 profile。
未声明 ABI 的历史包须按原生成版本回放。

旧完整 stage 表即使通过包结构和 checksum 验证，也不代表兼容在线生成 RTL。
当前 target 无完整表执行分支，必须重新生成镜像、DMA spans、sidecar 和 checksum；
不能只改 ABI 字段。旧 ISA 包会被当前 validator 拒绝；请在新输出目录重新生成。

## 验证依据

三种方案使用相同的主验证规则：独立 modified-SEAL `Evaluator` 在每个 plan 算子后
保存 ciphertext，适配器检查 ciphertext 的 level、component、scale/correction
factor，并转换为对应的 HPU 物理布局。指定导出结果的转换值构成包内 golden；
其他节点只用于 host 检查，不因此强制向目标程序增加写回。因此三个方案的
`seal_oracle_to_golden` 都必须为 `pass`，报告同时记录 `oracle_verified=true` 和
`golden_matches_oracle=true`。该项为必选检查（`required=true`）；通过后，三种方案
都记录统一的 `overall_status=pass`。

| 方案 | golden 物理域 | 额外 host 软件模型检查 |
| --- | --- | --- |
| CKKS | canonical NTT physical | `CkksSoftwareExecutor` 的逐算子输出必须与 SEAL 逐字相等，状态 `pass` |
| BFV | bit-reversed coefficient | `BfvSoftwareExecutor` 的逐算子输出必须与 SEAL 逐字相等，状态 `pass` |
| BGV | canonical NTT physical | `BgvSoftwareExecutor` 的逐算子输出必须与 SEAL 逐字相等，状态 `pass` |

三种方案都从初始 HPU_MEM 镜像执行独立 host 软件模型，并将每个 plan 输出的每个
RNS limb 与 SEAL oracle 转换后的 HPU 物理 word 比较。报告中的 `model_verified` 和
`raw_physical_words_equal` 均为 `true`。新程序应读取 `checks` 数组中的
`name/required/status`。`host_software_model_to_oracle` 也是必选检查
（`required=true`）；任一逐 word 比较失败都会停止生成交付包。

Evaluator 前端还记录 `host_instruction_model` 和资源优化前后的一致性比较。
默认严格编译要求最终编码指令的软件回放与 golden 一致；显式诊断模式才允许保存
带失败记录的指令模型报告。实际通过规模以当次日志和包内报告为准，不能沿用旧
旧 profile 或旧镜像的测试结果来声明新的 BR 数据 ABI 已通过。

所有包都记录 `instruction_execution_verified=false`、`rtl_verified=false`、
`hardware_verified=false`。软件数学模型逐字通过不代表编码指令已经在 RTL/HPU 上执行。
生成 C 只在 `__riscv` 下发射 HPU `.word`；host 编译运行用于接口检查，不能形成指令
执行证据。
`BgvSoftwareExecutor` 覆盖 plain/cipher arithmetic、row/column rotation、
KeySwitch、Multiply+Relinearize 和 ModSwitch，并从包内准备好的 key、常量、twiddle
及中间 allocation 按节点输入引用执行整张图，支持独立 Multiply（三分量）和
Relinearize，也保留旧接口的融合 Multiply+Relinearize。

公共写入器校验文件、编码一致性、DMA span、allocation、输出覆盖、初始零值和
物理 word 范围，并在私有 staging 目录中写入，通过落盘校验后发布新目录。
它不能证明调用者实际运行了独立 SEAL oracle，方案适配器与其测试是 golden 来源
的一部分。落盘校验也不重新执行 SEAL 或验证计算图算法语义。
实现要求 POSIX 文件系统；校验期间目录应保持不变。

## IT 编写新测试

### 与旧 CKKS 交付方式的差异

| 使用点 | 旧 CKKS 专用格式 | application package v1 |
| --- | --- | --- |
| 生成目标 | `hpu_ckks_delivery` | 原目标保留；另有 `hpu_bfv_delivery`、`hpu_bgv_delivery`、`hpu_fhe_delivery` |
| 单案例参数 | `--emit-dir PATH` | 参数保持不变；PATH 必须尚不存在 |
| 程序文件 | 直接位于包根目录 | 通过 `package.json` 定位，当前位于 `program/` |
| 初始镜像 | `test_data/hardware/hpu_mem_image.u32.bin` | `memory/hpu_mem_image.u32.bin` |
| DMA 映射 | 根目录 CSV，CKKS 专用 | `program/dma_relocation_manifest.csv`，三种方案统一 15 列 |
| 预期输出 | `expected_outputs.csv` 和按 dstore 导出的镜像 | `golden/golden_manifest.csv` 和指定输出的逐 RNS limb 文件 |
| 完整性检查 | 依赖案例自身检查 | `hpu_validate_package PACKAGE_DIR` 做统一静态校验 |
| C++ 写包接口 | `write_ckks_delivery_package(...)` | `make_*_application_package(...)` 后调用 `write_application_package(...)` |

IT 若只执行现有案例，构建命令 `hpu_ckks_delivery` 和示例的 `--emit-dir` 不需要改；
消费脚本必须改为先读取 `package.json`，不要再拼接旧的固定相对路径。这样同一套脚本
可以处理 CKKS、BFV、BGV，也能随 schema 后续扩展。

新增一个 C++ 示例，沿用现有的 context → image builder → plan → lowering → runtime
调用。用独立 `seal::Evaluator` 执行同一个表达式，每个计划算子之后保存 ciphertext
快照；BFV 的融合 Multiply+Relinearize 对应一个快照。随后调用方案适配器：

```cpp
#include "hpu/seal/application_delivery.hpp"

// oracle_after_step 与 lowered.operations 一一对应。
// model_words 来自软件执行器，不是 SEAL oracle 生成的镜像。
auto request = hpu::seal_adapter::make_bfv_application_package(
    "my_bfv_case", context, lowered, runtime, artifacts,
    image_builder.image(), oracle_after_step, executor.memory().words());

// 可选：应用验证过的真实解码结果。
request.semantic_report = hpu::seal_adapter::integer_delivery_semantics(decoded);
hpu::delivery::write_application_package("outputs/my_bfv_case", request);
```

CKKS 使用相同参数形状的 `make_ckks_application_package`。BGV 使用：

```cpp
#include "hpu/seal/bgv_software_executor.hpp"

hpu::seal_adapter::BgvSoftwareExecutor executor(context, application.image);
executor.execute(plan);
auto request = hpu::seal_adapter::make_bgv_application_package(
    "my_bgv_case", context, plan, application, oracle_after_step,
    executor.memory().words());
hpu::delivery::write_application_package("outputs/my_bgv_case", request);
```

兼容重载允许省略最后一个参数并在适配器内部执行相同模型；显式形式便于测试代码
单独检查各步 HPU_MEM 内容，也与 CKKS/BFV 的交付调用形状一致。

CKKS/BFV 以及带显式执行镜像的 BGV 适配器支持可选的
`exported_output_prefixes` 参数，指定需要持久化的完整逻辑结果前缀集合；
空集合默认只选最终输出。所有 oracle 快照仍须提供并检查。Evaluator 自动把全部
`mark_output()` 转成该集合，同一物理值的别名只导出一次。

返回的 request 借用初始 `HpuMemImage`；写出前应保持其存活、内容不变。
显式预留临时 ciphertext 工作区时，将 `reserve_ciphertext` 最后一个参数设为
`hpu::runtime::AllocationKind::workspace`。数据准备阶段默认仍是 `output`；导出适配器按选择集合将未导出的节点交给编译器
管理。最终包中的每个 output allocation 必须恰有一个 golden limb。

```cmake
add_executable(my_bfv_case examples/my_bfv_case.cpp)
target_link_libraries(my_bfv_case PRIVATE hpu_seal_delivery)
# 放在已定义 hpu_application_delivery 的位置之后，可自动注册构建目标和包测试。
hpu_application_delivery(bfv my_bfv_case my_bfv_case)
```

自动注册的包测试要求示例支持 `--emit-dir` 并提供 semantic report。也可只链接库、
自定义测试入口并调用独立校验器。公共层可直接接受 `ApplicationPackageRequest`，
未来新增方案需要补充方案标识、适配器和测试，无需复制落盘实现。

所有公开应用交付目标统一使用本规范。旧 CKKS 专用写入器、扁平格式以及
`inline_asm_codegen`、`inline_asm_encode_outputs`、`hpu_delivery`、
`hpu_delivery_with_seal` 直接汇编交付链均已移除。数学 reference 仅作为可选内部
差分 fixture 保留，底层算子测试也通过原生 SSA 和统一应用包入口生成产物。

## 回归命令

```bash
cmake --build build -j
ctest --test-dir build --output-on-failure
# 只检查公共写入器和默认应用包
ctest --test-dir build -L application-delivery --output-on-failure
```

### 显式 Multiply 与 Relinearize

CKKS、BFV、BGV 均可在 plan 中分别添加 Multiply（三分量输出）和 Relinearize（二分量输出），
每个节点保留独立的 `operation_index`；只有指定导出节点具有 golden 对象。
BFV 和 BGV 的原有融合乘法接口继续兼容，
融合节点标记为 `multiply_relinearize`；IT 用例必须提供对应的融合 SEAL oracle 快照。

## 原生算子资源编译

Evaluator 和 CKKS/BFV/BGV Plan 应用携带算子直接生成的资源 IR 与结构化 DMA 端口。
前端在编译时调度资源，旧 Plan 包在 `write_application_package()` 导出时自动调用
同一后端。导出在私有镜像中执行 SSA 读取复用、写读转发、死值消除及依赖调度，按需物化
workspace 并重新绑定 DMA 和指定输出的 golden 地址，
调用者的原始镜像保持不变。最终包保持 v1 文件和二进制格式。

`oracle/report.json.compiler_resources.ir_source="operator"` 标识原生路径；报告还记录
原始/最终 DDR、DMA 字节/次数、bank 峰值、spill/reload 和逐 allocation IO。
原序、复用和重排候选按 DMA 总字节、次数、指令数依次选择，`--no-opt` 使用统一
后端的原序基准，不承诺保留旧手写指令和布局。导出要求所有保留输出逐字匹配 SEAL
golden，并单独检查优化前后输出等价。RTL/硬件验证字段仍不由 host 对拍置为 true。
原始 `--print-asm` 可以用于对照，消费最终程序时应使用包内的指令及 DMA 清单。

## 64 对象目标 ABI

`memory/abi.json` 声明下列字段；package schema v1 本身不代表兼容同一 ISA：

| 字段 | 当前默认值 | 含义 |
| --- | --- | --- |
| `instruction_isa` | `hpu-objects64-v1.2` | 当前机器指令格式 |
| `dma_format` | `mod_rel_cp` | DLOAD 为 MOD/CP，DSTORE 为 REL/CP |
| `object_slots` | 64 | 逻辑对象 p0…p63 |
| `allocation_granule_lines` | 128 | 普通 SRAM 分配单元 |
| `mod_table_lines` | 4 | Bank 5 固定模表保留长度 |
| `stage_parameter_mod` | 0 | stage 参数通过普通 DLOAD 装入 |
| `stage_parameter_bank_mask` | 32 | 生成器显式选择 Bank 5 |
| `online_pmul_format` | `hpu-pmul-online-k8-v1` | 在线 pre/post 因子模板格式 |
| `online_pmul_parameter_lines` | 2 | 每个模板的实际长度 |
| `online_pmul_mode` | 1 | I=0 时 PMUL 的 MODE2 |
| `online_pmul_parameter_bank_mask` | 32 | 在线 PMUL 模板显式选择 Bank 5 |
| `default_cp` | 0 | 底层 API 省略 CP 参数时不请求 LLC 分配 |
| `dma_cache_policy` | `twiddle_loads_only` | 应用交付编译仅为 twiddle DLOAD 请求 LLC 分配 |

默认模表最多 64 contexts，其余 14 个参数槽由 stage 和在线 PMUL 模板共享，
按两条 line 对齐。每个参数对象实际为两条 line，长度在计算使用时检查；
不存在 TYPE3 装入类型。MOD=0、mask=0 选择普通 bank；生成器为两类参数
明确写出 mask=32。
DLOAD mask 不继承到结果，DSTORE REL=0 保留、REL=1 成功后释放。

应用交付编译采用 `twiddle_loads_only`：根据最终 `memory_manifest.csv` 的
`kind=twiddle` 将相应 DLOAD 的 CP 设为 1；包括两条 line 的 stage 参数和
在线 pre/post 模板。其他 DLOAD 和全部 DSTORE 的 CP 为 0，编译器插入的
reload 也遵守该规则，关闭资源优化时同样执行。校验器按分配元数据核对清单、
指令 CP 位和所声明的策略。应用编写者不需要更改 Evaluator 调用。

公共底层资源编译默认 `preserve`，保留手工设置的 CP，用于定向实验；导出此类
包时 `dma_cache_policy` 声明 `preserve`。较早的 v1.2 包若没有该字段，按
`preserve` 接收，重新生成后使用新策略；这不改变 ISA v1.2 或 CSV 的 15 列格式。

CP 与 MOD/REL、SRAM 位置独立，按命令选择。CP=0 仍可命中 LLC；CP=1 请求
读/写分配，不保证驻留。功能报告不模拟 LLC，DSTORE 完成不代表 DDR 写回完成，
仅为 twiddle 请求分配也不保证 LLC 中只有 twiddle。不能由数学对拍或 DMA 完成
时间推断缓存收益。性能和一致性要求见
[编程手册 4.5 节](../reference/HPU_PROGRAMMING_MANUAL.md#45-llc-分配提示-cp)。

v1.2 将 v1.1 的 TYPE 位改为 MOD/REL、CP；旧 TYPE1 位会变成普通对象 CP=1，
旧 TYPE3 位会变成模表 CP=1，因此旧包必须完整重新生成。生成器不会把旧包认定为
新目标可执行包，也不会删除无法通过当前校验的旧目录。升级时使用新的输出根目录，
例如 `-DHPU_APPLICATION_OUTPUT_ROOT=$PWD/outputs/isa12`，保留旧包便于追溯。
CPU/SoC 集成、实际 ARCACHE/AWCACHE 与板上执行须按
[RTL 交接](HPU_64OBJ_INTEGRATION_HANDOFF.md) 单独验收。
