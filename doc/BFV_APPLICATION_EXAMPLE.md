# BFV Multiply/ModSwitch 应用示例

`examples/bfv_multiply_modswitch_application.cpp` 面向使用 BFV planner 编写顶层应用的
开发者。示例把以下计算完整降低为可重定位 HPU 程序：

```text
left ─┐
      ├─ Ciphertext Multiply + Relinearize ─ ModSwitch(Q3→Q2) ─ AddPlain(3) ─ y
right ┘
```

对应表达式为：

```text
y = ModSwitch(left * right) + 3
```

其中 Multiply 内部包含 comparison-free BEHZ 和 rounded single-P KeySwitch；ModSwitch
是唯一显式 level 迁移。常数 `3` 不是运行时原始 plaintext，而是在构建 application
image 时按目标 Q2 level 预制的 AddPlain 表示。

## 构建和运行

```bash
cmake -S . -B build-seal -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build-seal -j --target hpu_bfv_multiply_modswitch_example
./build-seal/hpu_bfv_multiply_modswitch_example
```

默认使用教学参数 `N=128`，运行结果会显示 operation 数量、`Q3→Q2` level 迁移、
HPU_MEM 占用、DMA 绑定数量和编码后的指令数量。替换为部署参数时，planner/runtime
调用方式不变，但密钥、常量和 workspace 会显著增大。

打印完整汇编：

```bash
./build-seal/hpu_bfv_multiply_modswitch_example --print-asm
```

生成可交付运行包：

```bash
./build-seal/hpu_bfv_multiply_modswitch_example \
  --emit-dir output/bfv_multiply_modswitch_application
```

输出目录包含：

| 文件 | 内容 |
| --- | --- |
| `bfv_multiply_modswitch_application.asm` | 完整 HPU inline-assembly body |
| `bfv_multiply_modswitch_application.inst32` | 每行一条 32-bit 指令码 |
| `bfv_multiply_modswitch_application.cmd26` | 送往控制路径的 26-bit command |
| `bfv_multiply_modswitch_application.h/.c` | 固定 span 表和 `hpu_run_*()` 包装 |
| `bfv_multiply_modswitch_application.resolved_dma.csv` | 每条 DMA 的 operation、对象和 span 来源 |
| `bfv_multiply_modswitch_application.hpu_mem.u32.bin` | 已使用 HPU_MEM 行的 little-endian uint32 镜像 |

二进制镜像只写出 `used_lines()`，部署 backend 仍应按生成程序声明的 HPU_MEM capacity
配置实际 window，并在上传镜像前初始化其余区域。

## 1. 准备所有应用资源

示例在构造 plan 前完成全部准备：

```cpp
BfvApplicationImageBuilder image_builder(context, capacity_lines);
image_builder.add_modulus_table();
image_builder.add_canonical_twiddles();

auto left = image_builder.add_ciphertext("input/left", encrypted_left);
auto right = image_builder.add_ciphertext("input/right", encrypted_right);
auto bias = image_builder.add_add_subtract_plaintext(
    "constant/bias/next", bias_plaintext, next_level);

auto relin_key = image_builder.add_relinearization_key(
    "key/relinearization/top", relinearization_keys, top_level);
auto keyswitch_constants = image_builder.add_keyswitch_constants(
    "constants/keyswitch/top", top_level);
auto multiply_constants = image_builder.add_multiply_constants(
    "constants/multiply/top", top_level);
auto mod_switch_constants = image_builder.add_mod_switch_constants(
    "constants/mod_switch/top_to_next", top_level);
```

`add_multiply_constants` 会准备 BEHZ 所需的 B/`m_sk` 常量与 workspace；
`add_mod_switch_constants` 会准备 `floor(q_last/2)`、单源 BConv、
`q_last^-1 mod q_i` 和二分量 workspace。运行时不再进行 CPU 系数计算或比较。

## 2. 用 plan 表达应用

```cpp
BfvOperationPlan plan(image_builder);

auto product = plan.append_multiply(
    "multiply", left, right, relin_key,
    keyswitch_constants, multiply_constants,
    "intermediate/product/top");

auto switched = plan.append_mod_switch(
    "mod_switch", product, mod_switch_constants,
    "intermediate/product/next");

auto output = plan.append_add_plain(
    "add_bias", switched, bias, "output/y/next");
```

`append_multiply` 返回已经 relinearize 的二分量系数域密文，但保持 top level。
`append_mod_switch` 将输出明确迁移到相邻 `parms_id`。目标 Q2 plaintext 不能在 Q3
阶段使用，planner 会在生成代码前拒绝 level 或表示不匹配。

## 3. 降低并生成运行包

```cpp
auto lowered = lower_bfv_operation_plan(plan, context);
auto relocation = build_bfv_relocation_schedule(
    lowered, image_builder.image(), context);
auto runtime = lower_bfv_runtime_program(lowered, relocation);
auto artifacts = render_bfv_runtime_artifacts(
    "bfv_multiply_modswitch_application", runtime,
    image_builder.image().capacity_lines());
```

这四步分别完成 kernel 选择、DMA span 绑定、指令编码/ABI 对拍和 C runtime wrapper
生成。完整程序只加载一次模表并只在末尾发出一次 `psync`。

## 4. 当前验证边界

示例使用 `BfvSoftwareExecutor` 从同一份 HPU_MEM 镜像读取密文、twiddle、评估密钥和
预计算常量，依次执行 comparison-free BEHZ、branchless-SK、rounded single-P
KeySwitch、rounded ModSwitch 和 AddPlain。该执行路径不调用 `seal::Evaluator`；最终
两个密文分量与 modified-SEAL 独立 oracle 逐系数完全一致，再解密检查所有 batching
slots。因此 planner、预制资源和 BFV 数值链在 host 功能模型上形成了完整闭环。

真实裸机或 Linux 执行时，平台 runtime/driver 还需要分配并上传 HPU_MEM、配置 CSR、
维护 cache 一致性、执行生成的 `hpu_run_bfv_multiply_modswitch_application()`，并处理
完成 IRQ 与 fault。应用开发者不需要在 driver 中重新实现 BFV 算法。

## 5. 改写成其他 BFV 应用

1. 先标出每个值所在的 BFV level；
2. 在 image builder 中准备全部输入、plaintext、key、常量和 workspace；
3. 按数据依赖追加 planner operation；
4. 只在确实需要降 level 的位置调用 `append_mod_switch`；
5. 要求 `relocation.complete()` 后再生成部署包；
6. 使用 modified-SEAL 或已知答案验证应用语义。

当前 BFV planner 支持 Ciphertext Add/Subtract/Multiply/Negate、AddPlain/SubPlain、
MultiplyPlain、ModSwitch、RotateRows 和 RotateColumns。使用旋转时，先为目标步长或
换列准备 GaloisKey、modified-root twiddle 和 key-domain 为对应 Galois element 的
系数域 workspace，再调用 `append_rotate_rows` 或 `append_rotate_columns`。若应用需要
尚未覆盖的算子，应同时补齐 image resource、
planner metadata、codegen、relocation 和差分测试，而不是在顶层手写 DMA。

完整的 rotation 分支示例见 `doc/BFV_ROTATION_APPLICATION_EXAMPLE.md`。
