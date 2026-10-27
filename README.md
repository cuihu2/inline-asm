# HPU FHE 图编译器

本项目提供 CKKS、BFV、BGV 共用的 SEAL 风格 C++ 前端，将应用计算图编译为 HPU
指令、DMA 清单、初始数据镜像及目标侧 C 入口。Nexus-AM 或目标工具链继续负责把
C 入口与平台代码编译成可执行二进制，IT 负责 RTL/板端执行和结果读回。

程序员使用 `ApplicationBuilder`、`Evaluator` 和密文句柄描述计算。编译器通过
SSA 识别数据复用，安排片上对象和 bank，自动生成加载、释放、写回及 spill/reload。
顶层 API 不要求程序员填写物理对象号或决定释放时机。

## 1. 从这里开始

| 任务 | 文档 |
| --- | --- |
| 编写应用和 ST 用例 | [Evaluator 入门](doc/getting-started/HPU_EVALUATOR_FRONTEND.md)、[应用编程手册](doc/reference/HPU_SEAL_API_REFERENCE.md) |
| 理解 IR、调度、内存和 runtime | [项目架构](doc/architecture/HPU_ARCHITECTURE.md) |
| 消费数据、指令和 golden | [应用包 V1](doc/delivery/HPU_APPLICATION_PACKAGE_V1.md)、[IT 交接清单](doc/delivery/IT_HANDOFF_CHECKLIST.md) |
| 预加载后连续测量程序主体 | [单一连续窗口计时](doc/getting-started/HPU_EXECUTION_PROFILING.md) |
| 维护算子和适配层 | [底层 API](doc/reference/HPU_LOW_LEVEL_API_REFERENCE.md)、[SEAL 集成](doc/architecture/HPU_SEAL_INTEGRATION.md) |
| 对接 RTL | [编程手册](doc/reference/HPU_PROGRAMMING_MANUAL.md)、[Bank 分配指南](doc/reference/HPU_BANK_ALLOCATION_GUIDE.md) |

完整文档目录见 [doc/README.md](doc/README.md)。

## 2. 构建与生成

```sh
cmake -S . -B build -DHPU_ENABLE_SEAL_INTEGRATION=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build -j8
ctest --test-dir build --output-on-failure

# 三个 Evaluator 复合示例，默认 N=128
cmake --build build --target hpu_frontend_delivery -j8
# 显式 Plan 示例，使用相同编译后端及应用包格式
cmake --build build --target hpu_fhe_delivery -j8
```

编译器仍可在不启用 SEAL 集成时构建、运行核心与 ISA 测试；生成三方案应用需要
`HPU_ENABLE_SEAL_INTEGRATION=ON`。CMake 默认输出根为 `outputs/`，可通过
`-DHPU_APPLICATION_OUTPUT_ROOT=/absolute/path` 选择新目录。

### N=8192、Q=4、P=1 的 IO 对照

```sh
python3 tools/benchmark_io.py --build-dir build --output-root outputs/io_baseline --no-opt
python3 tools/benchmark_io.py --build-dir build --output-root outputs/io_optimized \
  --baseline-json outputs/io_baseline/io_summary.json
```

runner 默认使用 N8192、Q4、P1、seed=0，依次安全生成和验证三个方案的应用包，
把实际 DMA 字节、候选调度、spill/reload 和输出集合写入 `io_summary.json`。
`--baseline-json` 只比较参数、fixture 和导出输出完全一致的报告；不提供时只汇总
本次测量。`--degree 65536` 可改做容量压力测试。完整命令和字段说明见
[IO 基准说明](doc/getting-started/HPU_EVALUATOR_FRONTEND.md#n8192q4p1-的可重复-io-对照)。
本轮实测和分类收益见 [SSA 与 IO 优化记录](doc/delivery/IO_OPTIMIZATION_RESULTS.md)。

单独运行示例时也支持 `--degree 8192 --data-moduli 4 --seed 0`；`--data-moduli`
指实际数据 Q 的个数，另生成一个 special P，示例默认仍为 Q3。seed 仅用于可重复
测试 fixture。CP 提示的真实缓存收益需要 RTL/硬件测量。

直接写包要求目标目录不存在。需要安全重复发布时使用
`tools/generate_application_package.py`，具体命令见编程手册。

底层 CMULT、NTT、INTT 的固定 N8192 环算术用例使用
`hpu_native_kernel_application_example --case cmult|ntt|intt --emit-dir PATH`，同样输出
应用包；这些是未加密的数学与 IO fixture，使用方式见
[底层 API 的用例入口](doc/reference/HPU_LOW_LEVEL_API_REFERENCE.md#原生算子用例应用包)。

## 3. 编程与输出

```cpp
hpu::seal_adapter::ApplicationBuilder app(context);
auto evaluator = app.evaluator();
const auto x = app.import_ciphertext("input/x", encrypted_input);
hpu::seal_adapter::Ciphertext y;
evaluator.multiply(x, x, y);
evaluator.relinearize_inplace(y, relin_keys);
app.mark_output("y", y);
const auto compiled = app.compile("my_application");
compiled.write("outputs/my_application");
```

context、密钥、编码、加密、解密仍使用 native SEAL。重线性化、rescale、mod switch
由应用显式调用，遵循各方案的 level、scale 和 correction-factor 规则。

**默认只导出全部 `mark_output()` 指定的结果；没有标记时导出最后一个计算结果。**
内部结果由编译器管理，不再为逐节点目标读回强制写回 DDR。多个标签和 metadata
view 可引用同一物理结果，golden 不重复。需要 IT 检查中间值时显式标记输出。
主机仍检查方案 SoftwareExecutor 与各节点 SEAL oracle，`oracle_result(value)`
仍可查询编译快照中的参考结果。

## 4. 编译流程与代码组织

```text
Evaluator / Plan
  → OperatorProgram SSA：逻辑输入、计算、输出、模数上下文
  → 内存身份与版本、重复读取合并、写读转发、死值消除
  → 有依赖约束的调度候选
  → VirtualProgram：对象、bank、backing、按需 DMA 和生命周期
  → DDR 布局、DMA 重定位、ISA 编码与目标侧 C
  → application package v1
```

| 目录 | 职责 |
| --- | --- |
| `include/hpu/seal/`、`src/hpu/seal/` | 统一前端、方案适配、Plan、数据准备及软件执行器 |
| `include/hpu/compiler/`、`src/hpu/compiler/` | SSA 优化、调度、片上资源与 DDR 分配 |
| `scheme/`、`operator/`、`poly/`、`util/` 对应 include/src | 数学算法和原生算子资源表达 |
| `include/hpu/runtime/`、`src/hpu/runtime/` | 内存镜像、生命周期与共享 BankAllocator |
| `include/hpu/delivery/`、`src/hpu/delivery/` | 统一交付编译、包写入及落盘校验 |
| `encode/` | ISA 定义、编码/解析和 C wrapper 生成 |
| `test/` | 编译器、方案对拍、ISA、应用包和目标包装代码回归 |

原序、读取复用和重排候选按最终 **DMA 字节数、DMA 次数、指令数** 依次比较。
分配器考虑实际 bank 区间、瞬时结果空间、写回代价和后续读取；`spill=0` 不表示没有
重复加载，应同时看 `dload_bytes`、`dstore_bytes` 和 `io_by_allocation`。

旧 `inline_asm_codegen → inline_asm_encode_outputs → hpu_delivery` 直接汇编交付链
已移除。应用和底层算子用例统一通过原生 SSA、公共编译后端和 application package
写入器。`hpu_reference_vectors` 仅保留为可选数学差分 fixture，不是目标交付入口；
`config/fhe_test.conf` 只控制这些历史数学测试，应用参数在测试 C++ 中指定。

## 5. 交付边界

包内包括 `program/`、`memory/`、`golden/`、`metadata/`、`oracle/` 和 `provenance/`。
IT 应先读取 `package.json`，加载初始镜像、执行目标程序，再按 golden manifest
读回指定输出。golden 不得预加载到目标内存。

目标 ISA 为 `hpu-objects64-v1.2`：64 个逻辑对象、普通 bank 以 128 line 分配；
stage 和 pre/post 因子均使用 K=8 的 512 B 只读参数对象，pre/post 仍由独立
PMUL 执行。在线 PMUL 为 2026-10-22 追加扩展，目标 RTL 必须支持对象模式位
`01`；模板格式见 [硬件交接](doc/reference/PMUL_ONLINE_COMPILER_HANDOFF.md)。交付编译仅为
`kind=twiddle` 的 DLOAD 设置 CP=1，其余 DLOAD 与全部 DSTORE 为 0，包括编译器
重载和 NoOpt。ISA、参数格式与应用包 schema 分别版本化。

默认编译要求 SEAL、方案软件执行器及最终指令 host 模型通过。host 模型提供功能
证据，不能代替 CPU/SoC、RTL 或板端验收；包内硬件验证字段保持 false，实际目标
执行按 IT 清单单独记录。旧机器码或旧数据布局需要完整重新生成。
