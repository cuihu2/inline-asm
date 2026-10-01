# 通用 HPU 应用交付包 v1

CKKS、BFV、BGV 使用同一目录协议。公共写入器位于 `hpu::delivery`，不依赖 SEAL；
SEAL 适配层负责参数、计算图、oracle 与物理输出格式的转换。
产物包含指令、初始数据和可编译的 C/H。Nexus AM 侧负责运行入口、内存装载、
RISC-V 编译链接及 ELF/BIN 生成；本项目的生成命令不执行板卡或驱动操作。

## 生成与校验

```bash
cmake -S . -B build -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build -j --target hpu_fhe_delivery

# 也可按方案生成
cmake --build build -j --target hpu_ckks_delivery
cmake --build build -j --target hpu_bfv_delivery
cmake --build build -j --target hpu_bgv_delivery

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

可以只生成一个案例，目标为 `<case>_delivery`。更改统一输出根目录使用
`-DHPU_APPLICATION_OUTPUT_ROOT=/path/to/packages`。

所有示例也支持 `--emit-dir PATH`，该接口要求目标目录不存在：

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
示例参数用于功能测试：多项式示例为 N=65536，其余当前为 N=128，且不强制 SEAL
安全等级；实际参数记录在包内。SecretKey 和 PRNG seed 不进入交付包，执行所需的
重线性化/Galois key 已在初始镜像中。

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
在公共接口中是可选项，当前七个示例均提供。

- `package.json`：`schema=hpu-application-package`、`schema_version=1`、
  `scheme=ckks|bfv|bgv`、case 名称及各清单路径。
- `program/`：`.asm` 是指令流，`.inst32` 每行 32 位指令，`.cmd26` 每行 26 位
  command。C 文件提供 `hpu_program_<stem>(spans, count)` 和固定 DMA span 的
  `hpu_run_<stem>()`，供 Nexus AM 侧编译调用。
- DMA 清单统一为 14 列：`instruction_index,dma_index,operation_index,operation_id,`
  `operation_dma_index,direction,object_slot,type_or_release,flag,allocation_id,`
  `line_offset,line_count,word_hex,normalized_asm`。BGV 适配器将原六列 runtime 清单
  转换为此格式；其 operation 列使用 application 级标记，逐算子语义见计算图。
- `memory/`：uint32 little-endian，每行 64 个 word，即 256 字节。
  镜像大小为 `used_lines * 256`，实际 HPU_MEM window 按 `capacity_lines` 配置。
  `x10` 传 line offset，`x11` 传 line count；两者都是行数，不是字节地址。
  执行前加载初始镜像，output 与 workspace 从零开始。
- `golden_manifest.csv`：记录 object、component、MOD_ID、模数、domain、路径、
  目标行范围、有效 word 数、padding 和校验和。每个 `AllocationKind::output`
  恰有一个 golden limb。当前输出包括每个算子的结果；内部 scratch 的每次 dstore
  不一定有独立 golden。`step_<index>` 与计算图中的 `golden_object_id` 相连。
- BFV golden 为 `coefficient`；CKKS/BGV 为 `canonical_ntt_physical`。
  所有 word 均为 `[0,q)` 的 residue，文件补零到完整 HPU line。
- `parameters.json` 保存 N、plain modulus、安全等级、key-context 模数及各 level
  的 `parms_id`、Q 和 chain index。`operation_graph.json` 保存节点、输入引用、
  输出、level、scale/correction factor。CKKS/BFV 的多分支依赖关系会保留。
- `provenance/files.csv` 列出其余文件的路径、角色、长度和 FNV-1a64。
  它用于发现损坏；不是发布者签名。`build.json` 记录 producer 信息。默认 revision
  和 worktree 状态采集于 CMake 配置时；正式生成可通过环境变量
  `HPU_DELIVERY_COMMIT`、`HPU_DELIVERY_WORKTREE_STATE` 提供实际生成版本。

不要将 golden 预加载进 HPU_MEM。IT 应加载 `memory/hpu_mem_image.u32.bin`，运行 C
入口，再按 golden 清单读回对应 span，比较有效 word 和补齐区域。
`.inst32`/`.cmd26` 本身不携带完整 CPU DMA sideband，也不是 ELF/BIN；可执行运行
需要使用 C wrapper 中的 span 设置，或等效实现 resolved DMA 清单。

## 验证依据

| 方案 | golden 来源 | 软件执行比较 | 包内记录 |
| --- | --- | --- | --- |
| CKKS | 独立 modified-SEAL Evaluator 每步结果，经 NTT bridge 转成 HPU 物理顺序 | 与 CkksSoftwareExecutor 每步输出逐字相等 | `model_verified=true` |
| BFV | 独立 modified-SEAL Evaluator 每步 coefficient 结果 | 与 BfvSoftwareExecutor 每步输出逐字相等 | `model_verified=true` |
| BGV | 独立 modified-SEAL Evaluator 每步结果，经 NTT bridge 转成 HPU 物理顺序 | 当前组合包没有完整 BGV 软件执行器比较 | `model_verified=false`、`raw_physical_words_equal=null` |

所有包都记录 `instruction_execution_verified=false`、`rtl_verified=false`、
`hardware_verified=false`。软件数学模型逐字通过不代表编码指令已经在 RTL/HPU 上执行。
BGV plain-chain 示例还会检查局部点运算；它不构成三种 BGV 组合程序的完整执行验证。

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
| DMA 映射 | 根目录 CSV，CKKS 专用 | `program/dma_relocation_manifest.csv`，三种方案统一 14 列 |
| 预期输出 | `expected_outputs.csv` 和按 dstore 导出的镜像 | `golden/golden_manifest.csv` 和逐算子、逐 RNS limb 文件 |
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
auto request = hpu::seal_adapter::make_bgv_application_package(
    "my_bgv_case", context, plan, application, oracle_after_step);
hpu::delivery::write_application_package("outputs/my_bgv_case", request);
```

返回的 request 借用初始 `HpuMemImage`；写出前应保持其存活、内容不变。
显式预留临时 ciphertext 工作区时，将 `reserve_ciphertext` 最后一个参数设为
`hpu::runtime::AllocationKind::workspace`。默认仍是 `output`，会要求完整 golden。

```cmake
add_executable(my_bfv_case examples/my_bfv_case.cpp)
target_link_libraries(my_bfv_case PRIVATE hpu_seal_delivery)
# 放在已定义 hpu_application_delivery 的位置之后，可自动注册构建目标和包测试。
hpu_application_delivery(bfv my_bfv_case my_bfv_case)
```

自动注册的包测试要求示例支持 `--emit-dir` 并提供 semantic report。也可只链接库、
自定义测试入口并调用独立校验器。公共层可直接接受 `ApplicationPackageRequest`，
未来新增方案需要补充方案标识、适配器和测试，无需复制落盘实现。

原 CKKS 专用的 `write_ckks_delivery_package` 和扁平目录格式已删除；所有
`hpu_*_delivery` 应用目标统一使用本规范。旧固定 profile 算子交付目标
`hpu_delivery` 仍使用原协议，与新应用目标 `hpu_fhe_delivery` 分开。

## 回归命令

```bash
cmake --build build -j
ctest --test-dir build --output-on-failure
# 只检查公共写入器和七个实际应用包
ctest --test-dir build -L application-delivery --output-on-failure
```
