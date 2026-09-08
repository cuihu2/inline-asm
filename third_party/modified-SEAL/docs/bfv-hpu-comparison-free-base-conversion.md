# BFV 托管计算面向模加/模乘 HPU 的无中心化比较改造

## 1. 文档目的

本文档说明 Microsoft SEAL 中 BFV 的 BEHZ 密文乘法如何改造成适合模加、模乘型 HPU 的在线计算路径，重点包括：

- 删除输入基扩展后的 `SmMRq` 中心化比较；
- 删除乘法末尾 Shenoy–Kumaresan（SK）基转换中的中心化比较；
- 两项改动同时启用时的辅助基容量约束；
- 在线密文计算如何映射为模加、模乘、NTT 和固定地址置换；
- 改动对正确性、噪声、乘法深度、性能和 32 位 HPU 参数选择的影响。

本文档只讨论托管计算阶段。参数生成、常量预计算、编码、加密、解密以及明文提升可以在 CPU 上预先完成，不计入 HPU 在线数据路径。

## 2. 最终结论

实现提供两个独立实验宏：

```text
SEAL_EXPERIMENTAL_BFV_NO_SMRQ
SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK
```

推荐的 HPU 目标配置是两个宏同时开启：

```text
NO_SMRQ=ON
BRANCHLESS_SK=ON
```

其性质为：

1. BFV 密文乘法中的两处算法级中心化比较都被移除；
2. `branchless-SK` 是精确变换，不改变最终数值、噪声预算或可用乘法深度；
3. `no-SMRQ` 会增加中间值和噪声增长，实测通常损失 1–2 层乘法深度；
4. `branchless-SK` 需要扩大辅助基 `B`，当前 SEAL 软件实验通常增加一个 61 位辅助素数；
5. HPU 若只使用不超过 32 位的模数，可以使用更多 32 位辅助素数提供相同的 `B` 总位宽。

## 3. 原始 BEHZ 密文乘法路径

设数据 RNS 基为：

\[
\mathcal Q=\{q_0,\ldots,q_{k-1}\},\qquad Q=\prod_i q_i
\]

辅助基为：

\[
\mathcal B=\{b_0,\ldots,b_{\ell-1}\},\qquad B=\prod_j b_j
\]

并定义：

\[
\mathcal B_{sk}=\mathcal B\cup\{m_{sk}\}
\]

SEAL 的 BFV 密文乘法主要执行：

1. 输入密文从 `q` 扩展到 `Bsk ∪ {m_tilde}`；
2. 使用 `SmMRq` 消除快速基转换引入的 `Q` 倍数；
3. 在 `q` 和 `Bsk` 上分别执行 NTT；
4. 执行密文多项式逐点乘与累加；
5. 执行 INTT；
6. 所有分量乘明文模数 `t`；
7. `fast_floor` 完成近似除 `Q`，结果位于 `Bsk`；
8. `fastbconv_sk` 将结果从 `Bsk` 精确转换回 `q`。

对应入口位于：

- `native/src/seal/evaluator.cpp` 中的 `Evaluator::bfv_multiply`；
- `native/src/seal/evaluator.cpp` 中的 `Evaluator::bfv_square`。

原始路径有两处对运行时密文派生数据的中心化判断：

- `RNSTool::sm_mrq`：判断 `r_m_tilde >= m_tilde/2`；
- `RNSTool::fastbconv_sk`：判断 `alpha_sk > m_sk/2`。

## 4. 改动一：取消 SmMRq

### 4.1 新路径

开启：

```text
SEAL_EXPERIMENTAL_BFV_NO_SMRQ=ON
```

后，输入扩展由：

```text
q -> Bsk ∪ {m_tilde} -> SmMRq -> Bsk
```

改为：

```text
q -> FastBConv -> Bsk
```

实现函数为：

```cpp
RNSTool::fastbconv_q_to_Bsk_unreduced
```

它直接调用预计算好的快速基转换矩阵，不再生成 `m_tilde` 通道，也不再调用 `sm_mrq`。

### 4.2 未约减表示

快速 CRT 基转换的输出可写成：

\[
\widetilde x=x+aQ
\]

其中 `a` 是快速 CRT 和引入的整数倍数，数量级受数据基大小 `k` 限制。两个未约减输入相乘得到：

\[
(x+aQ)(y+bQ)
=xy+Q(ay+bx)+abQ^2
\]

因此，相对于原始乘积，中间值最多额外增长约 `k²` 倍。实现为辅助基容量增加：

\[
\delta_{ns}=\left\lceil\log_2(k^2)\right\rceil
\]

位。

理想整数公式中，额外的 `Q` 倍数在后续乘 `t`、除 `Q` 后转化为 `t` 的整数倍，不改变明文语义。但它显著扩大了 RNS 中间值，并放大 `fast_floor` 近似误差和密文噪声，因此不能认为它是“零代价”的精确替换。

### 4.3 噪声影响

实测表明 no-SMRQ 的影响是系统性的：

- 单次乘法通常先损失少量噪声预算；
- 链式乘法会累积并放大差异；
- 在噪声较紧的参数下，可用深度通常减少 1–2 层；
- 参数余量充足时，正确深度可能不变，但剩余噪声预算仍较低。

因此，no-SMRQ 必须作为参数选择的一部分进行评估，不能只根据单次乘法正确性判断是否可用。

## 5. 改动二：branchless SK

### 5.1 为什么不能直接删除 SK 修正

从基 `B` 做快速 CRT 转换时，首先得到未约减 CRT 和：

\[
\widetilde z
=\sum_j
\left[z_j\widehat B_j^{-1}\right]_{b_j}\widehat B_j
\]

它满足：

\[
\widetilde z=z+\alpha B
\]

冗余模数 `m_sk` 用来恢复：

\[
\alpha_{sk}
=\left(\widetilde z_{m_{sk}}-z_{m_{sk}}\right)B^{-1}\bmod m_{sk}
\]

如果真实 `alpha` 为负，它在 `m_sk` 下表现为高半区元素。原始实现因此需要比较 `alpha_sk > m_sk/2`，再选择 `+B` 或 `-B` 方向的修正。

如果完全不修正，输出会残留 `alpha * B mod Q`。`fastbconv_sk` 已经位于 BFV 乘法末尾，后面没有除 `B` 的步骤，这会直接造成错误，而不仅是增加少量噪声。

### 5.2 扩大 B 后固定低半区

开启：

```text
SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK=ON
```

后，辅助基扩大到足以保证 `fast_floor` 的有符号输出满足：

\[
-\frac B2<z<\frac B2
\]

快速 CRT 和满足：

\[
0\le\widetilde z<\ell B
\]

结合：

\[
\widetilde z=z+\alpha B
\]

可得：

\[
0\le\alpha\le\ell
\]

而 `m_sk` 远大于辅助基数量，所以：

\[
\alpha_{sk}=\alpha\le\ell\ll m_{sk}/2
\]

高半区分支在合法参数范围内不可能发生。SK 修正可以固定为：

\[
z_i
=\widetilde z_i-\alpha_{sk}B\pmod {q_i}
\]

即：

\[
z_i
=\widetilde z_i
+\alpha_{sk}(-B\bmod q_i)
\pmod {q_i}
\]

对应代码只保留一次模乘加，不再构造高半区候选，也没有运行时比较或条件选择。

### 5.3 软件调试断言

定义 `SEAL_DEBUG` 时，软件路径会额外检查：

\[
\alpha_{sk}\le\ell
\]

以及：

\[
\alpha_{sk}\le m_{sk}/2
\]

这些比较仅用于验证参数范围证明。正式 HPU 数据路径不需要执行断言。

### 5.4 数值和噪声性质

在范围条件成立时，branchless-SK 与原始 SK 执行相同的精确修正。因此预期结果不是“解密后相同”，而是最终 `q` 基下逐系数相同。

实验结果与该结论一致：

- `baseline` 与 `branchless-sk` 的全部配对分组 `mean_noise_delta = 0`；
- 最坏噪声差为 0；
- 正确深度和安全深度完全一致；
- `nosmrq` 与 `both` 同样为逐组零噪声差和相同深度。

因此 branchless-SK 是纯去分支改造，不补偿、也不进一步恶化 no-SMRQ 的噪声损失。

## 6. 两个宏组合时的辅助基范围

SEAL 原有界使用 32 位覆盖 `K * n` 等增长因素。设：

- `Q_bits` 为数据模数乘积 `Q` 的实际位宽；
- `t_bits` 为明文模数位宽；
- `k` 为数据层 `q_i` 数量；
- no-SMRQ 关闭时 `delta_ns = 0`；
- no-SMRQ 开启时 `delta_ns = ceil(log2(k²))`。

这里的 `k` 与诊断程序一致，取自 `first_context_data().coeff_modulus().size()`，不包含 key level 末尾的 special prime。

branchless-SK 的保守所需总位宽为：

\[
R
=33+t_{bits}+Q_{bits}+\delta_{ns}
\]

其中额外的 1 位用于保证有符号半区 `|z| < B/2`。

代码不直接假设一个 61 位素数完整贡献 61 位，而使用每个素数至少大于 `2^60` 的事实，按每个辅助素数至少贡献 60 位计算：

\[
60\ell>R
\]

若不满足则继续增加 `base_B_size`。

两个宏同时开启时，`delta_ns` 必须进入 branchless-SK 的范围计算。组合单测专门选择了一个处于增长边界的参数，以防止两个独立功能合并后遗漏 `k²` 容量。

## 7. 32 位 HPU 的辅助模数数量

本轮软件实验按要求没有强制把 SEAL 内部辅助素数改成 32 位。算法只依赖 `B` 的总位宽，因此 HPU 可以使用更多不超过 32 位的辅助素数提供相同范围。

对一个 32 位素数，完全不依赖具体素数值的保守保证是：

\[
b_j>2^{31}
\]

因此可按每个辅助素数至少贡献 31 位计算：

\[
31\ell>R
\]

即：

\[
\ell
=\max\left(
k,
\left\lfloor\frac R{31}\right\rfloor+1
\right)
\]

当 `t_bits = 17`、每个 `q_i` 约 32 位、两个宏同时开启时，保守参考如下：

| k | Q 约位宽 | delta_ns | B 中 32 位辅助素数数量 | Bsk 总通道数（含 m_sk） |
|---:|---:|---:|---:|---:|
| 2 | 64 | 2 | 4 | 5 |
| 3 | 96 | 4 | 5 | 6 |
| 4 | 128 | 4 | 6 | 7 |
| 5 | 160 | 5 | 7 | 8 |
| 6 | 192 | 6 | 9 | 10 |
| 8 | 256 | 6 | 11 | 12 |
| 10 | 320 | 7 | 13 | 14 |
| 12 | 384 | 8 | 15 | 16 |

该表使用最保守的 31 位贡献。实际部署时应在 CPU 参数初始化阶段生成具体辅助素数并计算真实乘积 `B`，只要满足：

\[
\log_2 B>R
\]

即可停止增加素数。由于实际素数通常接近 `2^32`，真实所需数量常比表中少一个。

还必须满足：

- 所有 `b_j`、`m_sk` 与 `Q` 两两互素；
- 所有在线 NTT 模数支持目标多项式长度；
- `m_sk/2` 大于可能的最大 `alpha`，即至少满足 `m_sk > 2 * base_B_size`；
- HPU 的累加位宽足以覆盖所选 lazy accumulation 策略。

## 8. 在线路径到 HPU 的映射

### 8.1 可全部预计算的内容

以下数据只依赖参数，可以在 CPU 初始化阶段生成并上传 HPU：

- 所有 NTT/INTT 旋转因子；
- `q -> Bsk`、`q -> B`、`B -> q`、`B -> m_sk` 的基转换矩阵；
- 各输入基的 punctured product 逆元；
- `Q^(-1) mod b_j`；
- `B^(-1) mod m_sk`；
- `-B mod q_i`；
- `t mod q_i`、`t mod b_j`；
- KeySwitch key 的 NTT 表示和模数切换因子；
- Galois 置换地址表和固定符号表。

### 8.2 快速基转换

从输入基 `P={p_i}` 转换到输出基 `R={r_j}` 时，在线执行：

\[
u_i=x_i c_i\pmod {p_i}
\]

\[
y_j=\sum_i u_i M_{j,i}\pmod {r_j}
\]

其中 `c_i` 和 `M_j_i` 均为预计算常量。HPU 映射为：

1. 每个输入 residue 与常量模乘；
2. 对每个输出模数执行模乘累加；
3. 不需要数据相关比较。

### 8.3 no-SMRQ 输入扩展

对每个密文多项式和每个系数：

```text
input[q]
  -> FastConv(q -> Bsk)
  -> NTT under every Bsk modulus
```

不再生成 `m_tilde` residue，也不再执行 SmMRq。

### 8.4 NTT 乘法

在 `q` 和 `Bsk` 的每个模数通道独立执行：

```text
NTT(input 1)
NTT(input 2)
pointwise modular multiply/accumulate
INTT(product)
```

NTT 蝶形中的约减属于模加、模乘原语内部行为，不是额外的算法级比较需求。

### 8.5 乘 t 和 fast_floor

先在 `q ∪ Bsk` 的每个通道乘预计算常量 `t`。

`fast_floor` 对每个辅助模数 `b_j` 计算：

\[
v_j=\operatorname{FastConv}_{q\rightarrow Bsk}(x_q)_j
\]

\[
z_j=(x_{Bsk,j}-v_j)Q^{-1}\pmod {b_j}
\]

映射为基转换、模减和常量模乘，没有中心化判断。

### 8.6 branchless SK

对每个系数执行：

1. `B -> q` 快速转换，得到未修正结果 `y_i`；
2. `B -> m_sk` 快速转换，得到 `temp`；
3. 计算：

\[
\alpha
=(temp-x_{m_{sk}})B^{-1}\pmod {m_{sk}}
\]

4. 对所有 `q_i` 广播同一个 `alpha`：

\[
out_i=y_i+\alpha(-B\bmod q_i)\pmod {q_i}
\]

`alpha` 每个多项式系数只计算一次，然后广播到所有 `q_i` 通道。在线操作只有模加、模乘和数据搬运。

### 8.7 模减与模负

若 HPU 没有独立模减，可以使用：

\[
a-b\pmod q
=a+(q-1)b\pmod q
\]

模负同理：

\[
-a\pmod q=(q-1)a\pmod q
\]

因此算术层只要求模加和模乘。

## 9. KeySwitch、重线性化和旋转

### 9.1 RNS decomposition

SEAL 的 KeySwitch decomposition 不是对大整数做位分解，也不需要判断系数大小。它直接把目标多项式在每个 `q_j` 下的 residue 作为第 `j` 个 decomposition operand。

在线路径为：

1. 读取第 `j` 个 RNS residue 多项式；
2. 必要时转换到目标 key modulus；
3. NTT；
4. 与第 `j` 组 KeySwitch key 逐点模乘；
5. 对所有 `j` 模累加；
6. 消去 special prime。

### 9.2 special-prime removal

消去 special prime 时数学上存在舍入，但 SEAL 使用固定常量加法实现：

\[
c_{q_k}\leftarrow c_{q_k}+\lfloor q_k/2\rfloor\pmod {q_k}
\]

随后执行跨模数转换、模减和乘预计算逆元。它不需要比较密文系数是否大于 `q_k/2`。

### 9.3 旋转

旋转由固定 Galois 地址置换和 KeySwitch 组成。系数域中的符号变化由公开下标决定，可预先生成控制表；取负本身可用常量模乘完成。

因此，在本项目的范围内，KeySwitch、重线性化和旋转不再引入类似 SmMRq/SK 的密文数据中心化比较。

## 10. 验证结果

### 10.1 四模式构建矩阵

Release 构建结果：

| 模式 | NO_SMRQ | BRANCHLESS_SK | sealtest |
|---|---:|---:|---:|
| base | OFF | OFF | 331/331 PASS |
| nosmrq | ON | OFF | 333/333 PASS |
| branchless-sk | OFF | ON | 333/333 PASS |
| both | ON | ON | 335/335 PASS |

组合模式的 BFV 乘法、平方、未约减基转换、branchless-SK 精确转换、基宽和组合增长测试全部通过。

### 10.2 调试范围验证

服务器环境缺少可用的原生 AddressSanitizer 动态库，因此使用 Release 优化配置并显式定义 `SEAL_DEBUG` 验证范围断言：

- 全量 335 个测试通过；
- `N=32768`、`p=60`、16 trials 深度扫描完成；
- branchless-SK 范围断言触发次数为 0。

这验证了扫描范围内：

\[
\alpha_{sk}\le base\_B\_size
\]

以及：

\[
\alpha_{sk}\le m_{sk}/2
\]

### 10.3 N=32768 深度结果

实际明文模数为：

\[
t=65537
\]

其位宽为 17。部分日志文件名保留了历史 `t16` 字样，分析时应以 CSV 内的 `t=65537,t_bits=17` 为准。

`p=60`、16 trials 的 `square_relinearize` 安全深度（噪声预算至少 20 位）为：

| k | base | nosmrq | branchless | both |
|---:|---:|---:|---:|---:|
| 2 | 2 | 2 | 2 | 2 |
| 3 | 4 | 3 | 4 | 3 |
| 4 | 6 | 5 | 6 | 5 |
| 5 | 8 | 6 | 8 | 6 |
| 6 | 10 | 8 | 10 | 8 |
| 8 | 12 | 10 | 12 | 10 |
| 10 | 12 | 12 | 12 | 12 |
| 12 | 12 | 12 | 12 | 12 |

深度扫描上限为 12，因此表中的 12 表示“至少支持扫描到 12”，不能据此断言最大深度恰好为 12。

### 10.4 正确理解 mismatch

所有 GTest 均通过，但深度诊断 CSV 中存在到达噪声极限后的 mismatch 行。这些行用于确定最大正确深度，不属于单元测试失败。

结论依据是相同输入、相同深度下的配对比较：

- `base` 对 `branchless-sk`：28 个分组全部零噪声差、深度相同；
- `nosmrq` 对 `both`：28 个分组全部零噪声差、深度相同。

### 10.5 性能

branchless-SK 多使用一个辅助素数时，测得相对时间比约为 `1.043–1.236`：

- 大 `k` 时通常增加约 4%–8%；
- 小 `k` 时额外辅助通道占比更高，最坏约增加 24%；
- no-SMRQ 的性能收益与 branchless-SK 的额外通道代价基本独立，可以叠加评估。

## 11. 参数选择建议

### 11.1 先确定应用深度

参数选择顺序建议为：

1. 确定应用需要的密文乘法深度 `L`；
2. 选择多项式次数 `N` 和 batching 明文模数 `t`；
3. 选择数据模数总位宽 `Q_bits`，使 `both` 模式在深度 `L` 后仍保留安全噪声余量；
4. 根据 `Q_bits` 和单个 `q_i` 宽度确定 `k`；
5. 根据 branchless 总位宽公式生成辅助基 `B`；
6. 使用实际生成的 `B` 乘积复核范围；
7. 在目标 HPU 上执行端到端深度和性能验证。

不应只依据“单次乘法能够解密”选择参数。建议把目标深度后的剩余噪声预算下限设为至少 20 位，并根据应用容错要求继续增加裕量。

### 11.2 N=32768、t=65537 的初始参考

根据当前 p60 扫描：

- 需要安全深度 3：no-SMRQ 至少从 `k=3` 起评估；
- 需要安全深度 5：至少从 `k=4` 起评估；
- 需要安全深度 6：至少从 `k=5` 起评估；
- 需要安全深度 8：至少从 `k=6` 起评估；
- 需要安全深度 10：至少从 `k=8` 起评估；
- 更深应用必须提高扫描上限重新测量，不能从当前 capped-at-12 数据外推。

这些只是当前实现、当前密文结构和当前输入分布下的起点，不替代应用自己的噪声评估。

## 12. 已知限制与后续工作

1. no-SMRQ 仍是带噪声代价的实验路径，不应默认替换通用 SEAL BFV；
2. 当前 32 位辅助模数数量是根据已验证的总位宽不等式换算，尚未在本轮软件实验中强制所有辅助素数为 32 位；
3. 真正使用 32 位 HPU 前，应增加一个可配置的辅助模数位宽参数，并用实际 32 位 NTT 素数重新运行四模式或至少 `nosmrq`/`both` 对比；
4. 当前 `RNSTool` 构造函数只看到 `q` 和 `t`，无法直接区分 BFV 与 BGV。实验宏可能让 BGV 上下文也分配更大的辅助基，虽然 BGV 不使用该 BFV 路径；产品化时应把扩容严格限制到 BFV；
5. 如果应用产生大于当前假设的密文尺寸或更多交叉项，需要重新评估预留的 `K * n` 位宽；
6. HPU 模乘接口必须明确是否接受非 canonical 的全宽输入。跨模数转换若输入可能大于目标模数，需要由模乘单元完成输入约减，或增加独立的跨模数约减步骤；
7. NTT、KeySwitch 和旋转虽然不需要数据中心化比较，但仍需要高带宽访存、地址置换和多通道调度能力。

## 13. 代码与测试位置

- 构建选项：`CMakeLists.txt`
- 导出配置：`cmake/SEALConfig.cmake.in`
- 编译宏：`native/src/seal/util/config.h.in`
- BFV 乘法/平方路径：`native/src/seal/evaluator.cpp`
- RNS 边界与转换实现：`native/src/seal/util/rns.cpp`
- RNS 接口：`native/src/seal/util/rns.h`
- 单元测试：`native/tests/seal/util/rns.cpp`
- 深度诊断：`native/tests/seal/bfv_no_smrq_diagnostics.cpp`
- 对比脚本：`tools/analyze_no_smrq_diagnostics.py`

## 14. 推荐交付配置

用于 HPU 架构验证的推荐 CMake 配置：

```bash
cmake -S . -B build/both \
  -DSEAL_BUILD_TESTS=ON \
  -DSEAL_BUILD_BFV_NO_SMRQ_DIAGNOSTICS=ON \
  -DSEAL_EXPERIMENTAL_BFV_NO_SMRQ=ON \
  -DSEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK=ON
```

最终交付判断应同时满足：

- 应用要求深度内无解密错误；
- 目标深度后仍有预定噪声余量；
- debug 范围断言不触发；
- 实际 `B` 总位宽满足 branchless 范围；
- HPU 上的辅助通道数量、存储容量和吞吐达到性能目标。
