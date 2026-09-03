# 从工程搭建到第一个 CKKS/HPU 多项式程序

## 1. 工程是什么

本仓库正在把原来的 HPU 指令生成 demo，逐步整理为一个以 Microsoft SEAL CKKS
对象为入口的编译与运行栈。当前主线的职责是：

1. 由 `SEALContext` 决定 `N`、当前 level 的 Q、特殊模数 P 和评估密钥 digit；
2. 将 SEAL 的 NTT 对象转换为 HPU 的 canonical physical NTT 顺序；
3. 在应用启动前生成 HPU 可访问的 DDR window（HPU_MEM）；
4. 为 Multiply、Relinearize、Rescale、Rotate 和点运算生成 HPU 扩展指令流；
5. 用软件模型和 SEAL 语义结果验证各层边界。

目前已经具备“准备真实 CKKS 对象并生成 HPU 程序”的前端路径，但 Linux
driver/userspace backend 和真正消费整条指令流的软件执行器尚未完成。因此本文示例中：

- HPU_MEM 布局与 HPU 指令流来自本工程；
- 解密后的数值结果暂时由 `seal::Evaluator` 计算，只作为语义 oracle；
- 这个 oracle 通过并不等于 HPU 指令已经在硬件上执行。

原仓库的 `N=4096,Q=4,P=3,dnum=2` reference delivery 已降级为 legacy demo，
不再是 CKKS 主线的参数权威。

## 2. 代码结构

与 CKKS/HPU 主线最相关的目录如下：

```text
include/hpu/model, src/hpu/model
    HPU NTT/INTT 数学模型与硬件 physical layout

include/hpu/seal, src/hpu/seal
    SEALContext、level descriptor、NTT bridge、评估密钥和 HPU_MEM image

include/hpu/runtime, src/hpu/runtime
    应用生命周期、五个 regular-bank 槽位、dstore/psync 状态和 DDR image

include/scheme/ckks, src/scheme/ckks
    CKKS kernel 的 HPU inline-assembly codegen

examples/
    从真实 SEAL 对象到 HPU_MEM/指令流的可运行示例

test/
    数学模型、codegen、runtime 和 SEAL bridge 回归测试
```

HPU 的关键资源约束是：一个 `N=65536` 的 32-bit 多项式占 1024 个 256B line；
regular-bank 同时最多保留五个这样的活跃多项式。HPU_MEM 则是 DDR 中的应用级
window，密文、明文、评估密钥、模数/Barrett mu 和 twiddle 在启动前放入其中。
secret key 只留在 host，HPU_MEM builder 没有接收它的接口。

## 3. 构建

SEAL 固定为仓库子模块中的 v4.4.4。首次使用先初始化子模块：

```bash
git submodule update --init --recursive
```

配置并构建 CKKS 集成与示例：

```bash
cmake -S . -B build \
  -DHPU_ENABLE_SEAL_INTEGRATION=ON \
  -DHPU_ENABLE_LEGACY_FIXED_PROFILE_TESTS=OFF
cmake --build build -j --target hpu_ckks_polynomial_example
```

完整默认测试可以运行：

```bash
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## 4. 示例：计算 f(x)=x²+1

示例源文件是 `examples/ckks_polynomial_x2_plus_one.cpp`。输入的前三个 CKKS slot
为：

```text
x = [0.25, -1.5, 2.0]
```

期望输出为：

```text
f(x) = [1.0625, 3.25, 5.0]
```

它使用五个 32-bit 素数建立 SEAL key context。SEAL 将其解释为首层 `Q4 | P1`，
其中 P 只服务 KeySwitch；密文首层使用 Q4。求值过程为：

```text
Encrypt(x), Q4, scale=2^30
  -> Square                 # 三分量，scale=2^60
  -> Relinearize            # 用 s^2 evaluation key 回到两分量
  -> Rescale(q_last)        # 丢弃 Q4 的最后一个 q，进入 Q3
  -> AddPlain(1), Q3        # NTT 域逐点加法，不需要额外 NTT/INTT
  -> Ciphertext(Q3)
```

常数 `1` 不能沿用首层 plaintext：它在 Q3 的 `parms_id` 上、以 Rescale 后密文的
scale 重新编码。这样 AddPlain 的 level、RNS basis 和 scale 都匹配。

## 5. 示例如何映射到 HPU

### 5.1 应用启动阶段

`CkksApplicationImageBuilder` 依次准备：

- 全局 Q/P 模数和 48-bit Barrett mu 表；
- 所有 Q/P 的 canonical HPU NTT/INTT twiddle；
- 输入密文 `x` 的两个 Q4 分量；
- 当前 level 所需的 relinearization key digits；
- Q3 上编码的常数 `1`；
- `x²` 中间密文和 `x²+1` 输出密文的 DDR backing span。

每个 RNS limb 都是独立、256B 对齐的 allocation。对 N=65536，每个 limb 的
`line_count` 必须恰好为 1024。allocation 名称和 span 构成未来 Linux backend
执行 dload/dstore relocation 的依据。

### 5.2 指令生成阶段

示例把 Multiply/Relinearize/Rescale body 与 AddPlain body 组合在同一个应用级
生命周期中：

```text
dload complete modulus table -> small-bank       # 一次
CKKS Multiply + Relinearize + Rescale             # Q4 -> Q3
CKKS AddPlain                                     # Q3，纯逐点
dstore required output
pfree modulus table
psync                                             # 整个应用仅一次
```

这里复用通用 CiphertextMultiply kernel，把它的左右输入 relocation 都绑定到同一个
`input/x` span，从而得到 Square；不需要单独维护另一份相同密文。

组合接口通过 `manage_modulus_table=false` 告诉嵌套 kernel：small-bank 表由外层应用
管理，不要各自重复 dload/pfree；`append_psync=false` 则保证只有应用末尾发出 psync。

第一版 codegen 仍会在两个 kernel 的边界物化 `x²`，即 dstore 后再 dload。它是正确
但未优化的实现。后续 residency planner 可以在不超过五个活跃多项式的前提下保留
对象并删除这组 DDR 往返，而不改变 CKKS 语义。

## 6. 运行与查看结果

运行示例：

```bash
./build/hpu_ckks_polynomial_example
```

程序会打印：

- Q4/P1 到 Q3 的 level 变化；
- HPU_MEM 实际使用的 line 数；
- 预测 scale 和 SEAL scale；
- 解码结果与最大误差；
- 生成的 HPU 指令 body 大小。

如果希望查看完整 inline-assembly body：

```bash
./build/hpu_ckks_polynomial_example --print-asm
```

生成流里的 DMA 指令目前仍使用 ABI 规定的 `x10/x11` offset/count 寄存器。未来
runtime backend 会根据 HPU_MEM allocation manifest 在每次 DMA 前绑定具体 span。

## 7. 下一步

下一阶段的软件执行器会直接读取同一 HPU_MEM image，并解释 kernel 的模数选择、
DMA、NTT、逐点算术、KeySwitch 和 Rescale。届时本示例将同时运行：

1. HPU 软件执行器路径；
2. SEAL 语义 oracle；
3. HPU 输出到 SEAL NTT 的逐字转换与最终 Decode 对比。

这样 `seal::Evaluator` 将只负责给出独立期望值，而不再承担“被测试实现”的工作。
