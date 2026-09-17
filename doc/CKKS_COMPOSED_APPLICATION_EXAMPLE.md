# CKKS 组合应用示例

`examples/ckks_composed_application.cpp` 面向使用 planner 编写顶层应用的开发者。
它把一张包含并行分支、Galois 操作、密文乘法和跨 level 迁移的计算图完整降低为
可重定位 HPU 程序：

```text
                 ┌─ RotateLeft(x, 1) ─┐
x ───────────────┤                     ├─ Add ─┐
                 └─ Conjugate(x) ─────┘       │
                                              ├─ Multiply(x, ...)
                                              └─ Relinearize
                                                 └─ Rescale
                                                    └─ AddPlain(1) → y
```

对应表达式为：

```text
y = x * (RotateLeft(x, 1) + Conjugate(x)) + 1
```

## 构建和运行

```bash
cmake --build build-hpu-seal-5931eef \
  --target hpu_ckks_composed_application_example -j2
./build-hpu-seal-5931eef/hpu_ckks_composed_application_example
```

传入 `--print-asm` 可打印完整 HPU inline-assembly body。示例默认使用 `N=128`，
目的是让开发者快速学习和回归；替换为部署参数 `N=65536` 时 planner/runtime API
保持不变，但 Galois key、twiddle 和内存镜像会显著增大。

## 1. 只生成应用实际使用的密钥

示例首先根据计算图创建：

- public key：加密输入；
- relinearization key：三分量乘法 tensor 回到两分量；
- rotate-left-1 Galois key；
- conjugation Galois key。

Rotate 和 Conjugate 对应不同 Galois element，因此 key、fused twiddle 和
coefficient workspace 不能混用。planner 会在生成汇编前验证这一点。

## 2. 在 application image 中准备资源

应用启动镜像包含：

- modulus table 和 canonical NTT/INTT twiddle；
- 输入 ciphertext 和下一 level 的 bias plaintext；
- relinearization/Galois evaluation keys；
- 当前 level 的 KeySwitch 和 Rescale 常量；
- 两个 Galois element 各自的 fused automorphism twiddle；
- Rotate/Conjugate coefficient-domain workspace。

workspace 的表示必须显式声明：

```cpp
auto rotation_workspace = image_builder.reserve_ciphertext(
    "scratch/rotate_left_1", input.metadata(), 2,
    hpu::runtime::PolynomialDomain::coefficient,
    rotation_element);
```

## 3. 用一个 plan 表达完整计算图

顶层应用代码只按依赖关系追加 operation：

```cpp
CkksOperationPlan plan(image_builder);

auto rotated = plan.append_rotate_slots(
    "rotate_left_1", input, 1,
    rotation_key, keyswitch_constants, rotation_twiddles,
    rotation_workspace, "intermediate/rotated/top");

auto conjugated = plan.append_conjugate(
    "conjugate", input, conjugation_key,
    keyswitch_constants, conjugation_twiddles,
    conjugation_workspace, "intermediate/conjugated/top");

auto mixed = plan.append_add(
    "mix_branches", rotated, conjugated,
    "intermediate/mixed/top");

auto tensor = plan.append_multiply(
    "multiply", input, mixed,
    "intermediate/product_tensor/top");

auto relinearized = plan.append_relinearize(
    "relinearize", tensor, relinearization_key,
    keyswitch_constants, "intermediate/product/top");

auto rescaled = plan.append_rescale(
    "rescale", relinearized, rescale_constants,
    "intermediate/product/next");

auto output = plan.append_add_plain(
    "add_bias", rescaled, bias, "output/y/next");
```

`append_multiply` 只产生三分量 tensor。Relinearize 和 Rescale 必须显式追加，因此
顶层代码可以清楚看到乘法深度、component 变化和 level 下降。

当前 planner 不会自动调整两个分支。调用 `append_add` 前，两个输入必须已经位于
同一 `parms_id` 且 scale 兼容；否则 plan 构造阶段会直接报错。

## 4. 降低为可执行程序

同一份 plan 依次经过：

```cpp
auto lowered = lower_ckks_operation_plan(plan, context);
auto relocation = build_ckks_relocation_schedule(
    lowered, image_builder.image(), context);
auto runtime = lower_ckks_runtime_program(lowered, relocation);
auto artifacts = render_ckks_runtime_artifacts(
    "ckks_composed_application", runtime,
    image_builder.image().capacity_lines());
```

各阶段职责分别是：

1. 选择每个 operation 的 HPU kernel body；
2. 把每条 DMA 精确绑定到 application image span；
3. 编码指令并核对 custom1 DMA ABI；
4. 生成 C header/source 和 resolved DMA manifest。

示例同时通过 `CkksSoftwareExecutor` 执行同一张图，并与独立 SEAL Evaluator 结果
逐字比较。它已注册为 CTest，因此后续添加算子或修改 relocation 时会自动回归。

## 5. 编写新应用时的推荐顺序

1. 先画出数据依赖和预期 level/scale；
2. 只创建图中使用的 Relin/Galois keys；
3. 用 image builder 准备常量、twiddle 和 workspace；
4. 用 `CkksOperationPlan` 按依赖顺序追加 operation；
5. 检查 `relocation.complete()`；
6. 用 SEAL oracle 或已知答案校验输出；
7. 再生成部署程序包。

如果新应用需要 planner 尚未覆盖的 operation，应当为该 operation 同时补齐 metadata
推导、kernel lowering、DMA relocation 和差分测试，而不是在顶层手工拼接 DMA。
