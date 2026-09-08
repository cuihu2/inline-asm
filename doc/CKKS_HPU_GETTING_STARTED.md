# 从工程搭建到第一个 CKKS/HPU 多项式程序

## 1. 工程是什么

本仓库正在把原来的 HPU 指令生成 demo，逐步整理为一个以 Microsoft SEAL CKKS
对象为入口的编译与运行栈。当前主线的职责是：

1. 由 `SEALContext` 决定 `N`、当前 level 的 Q、特殊模数 P 和评估密钥 digit；
2. 将 SEAL 的 NTT 对象转换为 HPU 的 canonical physical NTT 顺序；
3. 在应用启动前生成 HPU 可访问的 DDR window（HPU_MEM）；
4. 为 Multiply、Relinearize、Rescale、raw/slot Rotate、Conjugate 和点运算生成
   HPU 扩展指令流；
5. 用软件模型和 SEAL 语义结果验证各层边界。

目前已经具备“准备真实 CKKS 对象并生成 HPU 程序”的前端路径，以及直接消费
HPU_MEM span 的软件执行器。该执行器已覆盖 canonical HPU NTT 域中的 Add、
Subtract、MultiplyPlain、AddPlain、SubtractPlain、Negate、通用密文 Multiply、Square、
KeySwitch、Relinearize、Rescale、raw/slot Rotate、Conjugate，以及由 HPU_MEM twiddle 驱动的 canonical
NTT/INTT，并与 SEAL NTT words 逐字比较。Linux driver/userspace backend 尚未完成。
因此本文 `x²+1` 示例中：

- HPU_MEM 布局与 HPU 指令流来自本工程；
- 完整算术链由 HPU_MEM 软件执行器运行，`seal::Evaluator` 只生成逐字 oracle；
- 这个 oracle 通过并不等于 HPU 指令已经在硬件上执行。

软件执行器本身不会调用 `seal::Evaluator`；测试只在执行完成后调用 Evaluator
生成独立期望值。

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
    应用生命周期、五个 regular-bank 槽位、dstore/psync 状态、DDR image
    和基础模运算软件执行器

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

SEAL v4.4.4 已作为普通源码固定在 `third_party/modified-SEAL`，不再需要初始化
submodule；普通 `git clone` 或 `git pull` 会同时取得依赖源码。

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
- KeySwitch 与 Rescale 的 level 专属只读常量；
- Q3 上编码的常数 `1`；
- Q4 三分量 tensor、重线性化结果、Q3 `x²` 和 `x²+1` 输出的 DDR backing span。

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

程序同时从同一 HPU_MEM image 执行
`Square -> Relinearize -> Rescale -> AddPlain`，把结果转换为 SEAL NTT 后先做
逐字比较，再解密和 Decode。因此 SEAL Evaluator 在示例中只生成 oracle，不承担
被测计算。

如果希望查看完整 inline-assembly body：

```bash
./build/hpu_ckks_polynomial_example --print-asm
```

生成流里的 DMA 指令目前仍使用 ABI 规定的 `x10/x11` offset/count 寄存器。未来
runtime backend 会根据 HPU_MEM allocation manifest 在每次 DMA 前绑定具体 span。

## 7. 当前软件执行器边界

`CkksSoftwareExecutor` 从 `HpuMemImage` 复制应用初始 DDR 内容，校验并加载一次
`constants/modulus_table`，随后以 allocation span 为地址执行模 q 运算。当前支持：

```text
Ciphertext + Ciphertext
Ciphertext - Ciphertext
Ciphertext * Ciphertext -> (t0,t1,t2)
Ciphertext * Plaintext
Ciphertext + Plaintext
Ciphertext - Plaintext
Negate(Ciphertext)
Square(Ciphertext) -> (t0,t1,t2)
KeySwitch(base, switching_component, evk) -> (base0+ks0, base1+ks1)
Relinearize(t0,t1,t2,rlk) -> (t0+ks0,t1+ks1)
Rescale(Qk) -> Q(k-1)
Rotate_k(Ciphertext) -> Ciphertext
RotateSlots_steps(Ciphertext) -> Ciphertext
Conjugate(Ciphertext) -> Ciphertext
coefficient <-> canonical HPU NTT
```

点运算、Multiply、Square 和 KeySwitch 的乘加直接工作在 canonical HPU NTT physical
order。KeySwitch 从当前 level descriptor 取得 active-Q singleton digits 和固定
P 的全局 MOD_ID，逐 digit 完成 INTT、跨基约减、NTT 和 evaluation-key 乘加，最后
按 P 做带舍入 ModDown。当前 frozen SEAL 版本使用一个 special prime，执行器会显式
拒绝多-P 形状；每次只流式保留一个 digit 的临时对象，符合最多 5 个活跃多项式的
SRAM 约束。应用 image 还为每个 level 预装带版本标记的 KeySwitch 常量记录，包含
P、P/2 和每个 active q 的 `P^-1 mod q_i`；执行时从 HPU_MEM 消费该记录。

变换路径会
从同一个 HPU_MEM image 读取 pre-twist、每个 stage 的 N/2 个 twiddle，以及
INTT post-untwist/scale；不会在执行时偷偷重新生成另一套表。
`hpu_seal_ckks_software_executor_test` 将输出转换回 SEAL NTT，并要求和独立
`seal::Evaluator` 输出逐字相同，包括不同输入的 Multiply→Relinearize→Rescale、
Square 后的独立 KeySwitch/Relinearize，
Rescale 后还必须迁移到准确的下一级 `parms_id`、scale 和 MOD_ID 前缀；同时要求
表驱动的 INTT→NTT 恢复原密文。Rescale 的 `q_last`、`q_last/2` 和各
`q_last^-1 mod q_i` 也在应用初始化时写入版本化 HPU_MEM 常量记录。

同一回归还建立 Q4|P1 image，并实际执行 Q4
Multiply→Relinearize→Rescale、Q3 fused Rotate、Q3
Multiply→Relinearize→Rescale 到 Q2。每一阶段都和 SEAL NTT words 逐字比较；Q3
只消费 active-Q 的 `{0,1,2}` 和固定 P 的 MOD_ID 4，从而覆盖跨 level 的 key digit、
modified-root twiddle、常量记录、`parms_id` 与 scale 迁移。

Rotate 使用 modified-root fused INTT，将两个 canonical HPU NTT 分量直接转换成
`domain=coefficient,key_domain=k`。随后 `sigma_k(c0)` 作为 base、`sigma_k(c1)`
作为 switching component 进入 Galois KeySwitch，输出恢复为
`canonical_ntt_physical,key_domain=1`。若两阶段拆成 kernel，必须跨边界保存的就是
这两个系数 workspace 及其 key-domain 元数据；不需要额外的 CPU coefficient
permutation，也不会在两阶段之间插入一对多余 NTT/INTT。

面向 CKKS slot 的接口把正 step 映射为左旋、负 step 映射为右旋，映射规则与
SEAL generator-3 完全一致；Conjugate 固定映射到 `2N-1`。它们都复用上述 fused
Rotate，差别只在应用初始化时选择的 Galois key 和 modified-root 表。零 step 应由
host/lowering 当作 no-op，不生成 KeySwitch。Negate 则始终停留在 canonical HPU NTT
域，通过 `(c-c)-c` 得到 `-c mod q`，不占用额外零多项式，也不产生 NTT/INTT。

## 8. 下一步

当前示例已经同时运行：

1. HPU 软件执行器路径；
2. SEAL 语义 oracle；
3. HPU 输出到 SEAL NTT 的逐字转换与最终 Decode 对比。

这样 `seal::Evaluator` 将只负责给出独立期望值，而不再承担“被测试实现”的工作。

当前冻结的 SEAL 4.4.4 只产生单 special-prime KeySwitch，因此多 P 已移出近期主线，
保留为未来脱离当前 SEAL 兼容范围后的独立扩展。多层软件执行验证已经覆盖
Q4→Q3→Q2，slot-step Rotate/Conjugate/Negate 也已接入；近期顺序是：ModSwitch
与自动 level/scale 管理，随后接入
application lowering、DMA relocation 和 Linux runtime backend。
