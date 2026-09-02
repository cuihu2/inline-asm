# HPU 指令流与验证数据交付说明

## 1. 交付结论

本仓库已形成可复现的软件交付闭环：生成 HPU 算子指令流、编码为 32-bit RV 指令和 26-bit HPU 命令、生成完整密文乘法及重线性化的 RNS golden 数据、执行软件解密校验，并生成 RV 接口冒烟用例。当前数据可交付给 IT 开展确定性功能联调；“数据可交付”不等于“目标硬件 qualification 已通过”。

一键生成和验收：

```bash
cmake -S . -B build
cmake --build build -j --target hpu_delivery
ctest --test-dir build --output-on-failure
```

需要增加独立 SEAL 数学门禁时使用：

```bash
cmake -S . -B build-seal \
  -DHPU_ENABLE_SEAL_DIFFERENTIAL_ORACLE=ON \
  -DHPU_SEAL_SOURCE_DIR=/home/songyexin/fhe/SEAL
cmake --build build-seal -j --target hpu_delivery_with_seal
```

该目标先执行完整 `hpu_delivery`，再用同一批 host fixture 对 BFV、BGV、CKKS
进行差分。普通交付仍不依赖 SEAL；差分报告写入
`build-seal/seal_oracle/report.csv`，依赖 commit、实验选项和关键源码 SHA-256
写入同目录 `metadata.txt`。该验证使用 `sec_level_type::none`，只表示功能正确性，
不构成安全参数认证。

成功后，`outputs/DELIVERY_REPORT.txt` 中应包含：

```text
SOFTWARE_DELIVERY=PASS
FHE_REFERENCE=PASS
ASM_ENCODING=PASS
PRECODE_CMD26=PASS
MOD_CTX_SMALL_BANK_FLAG=PASS
INSTRUCTION_SET_11=PASS
PFREE_LIFECYCLE=PASS
RV_INTERFACE_SMOKE=PASS
OPERATOR_UT_PACKAGES=PASS
HARDWARE_UINT32_IMAGES=PASS
HPU_LINE_LAYOUT_256B=PASS
CUSTOM1_LINE_SIDEBAND=PASS
HPU_MEM_CSR_MAP=PASS
MOD_CTX_Q32_MU48=PASS
MOD_TABLE_BASE_0X1400=PASS
STAGE_TWIDDLE_LAYOUT=PASS
NEGACYCLIC_FACTORS_EXPLICIT=PASS
NTT_PHYSICAL_OUT_OF_PLACE=PASS
SCHEME_ENCODE_HOST_BOUNDARY=PASS
CKKS_GENERATOR3_CANONICAL_EMBEDDING=PASS
BGV_GENERATOR3_BATCHING=PASS
BGV_AUTO_X3_ROW_ROTATION=PASS
CKKS_RESCALE_ROUNDED_DROP_LAST=PASS
CKKS_MULTIPLY_RELINEARIZE_RESCALE=PASS
BGV_MULTIPLY_CORRECTION_FACTOR=PASS
BGV_MODSWITCH_DROP_LAST=PASS
BGV_CONTEXT_ORDER_Q_P_T=PASS
TEST_VECTOR_SCOPE=FUNCTIONAL_ONLY
HARDWARE_EXECUTION=CONDITIONAL
PENDING=target RTL/board execution and external monitor evidence
```

`HARDWARE_EXECUTION=CONDITIONAL` 不是算法或数据失败。`uint32` 镜像、256B line、`mod_ctx`、twiddle、`.cmd26`、custom1 sideband、类型化 DMA span 和 CSR 偏移均已生成或冻结；生成的 C 后端在每条 DMA 前绑定 `x10/x11`。Nexus-AM IT runtime 已解析实际 line offset/count、scratch、cache、FAULT/IRQ 和 HPU_MEM window。这里剩余的条件是目标 RTL/板级执行及 monitor 证据，而不是软件 DMA 占位。

Nexus-AM host 用例属于 `PASS_PROBE` 自检：非 RISC-V 分支把嵌入镜像中的 golden
复制到输出区，再检查 manifest、输出边界和 guard，因此 CTest 应将其显示为
`qualification-pending/Skipped`。它可以证明测试程序和数据组织自洽，但不能作为
HPU 算术通过证据。目标证据必须来自 RISC-V 分支真正发出的 HPU 程序。

### 1.1 2026-08-28 审计基线

| 检查项 | 结果 |
| --- | --- |
| 算子数据包 | 21 个目录：18 个 HPU 算子包，以及 3 个 CKKS/BGV/BFV host-only Encode/Decode 包 |
| 数学与硬件文件 | 所有 manifest 路径、字节数、FNV-1a、256B line geometry、主镜像切片和连续 line map 均通过 |
| Nexus-AM 同步副本 | BFV 硬件用例为单 kernel CiphertextMultiply 和 ModSwitch；Encode/Decode 不再同步为 HPU 用例，旧双 kernel 包不作为本版签字依据 |
| HPU_MEM 容量 | BFV CiphertextMultiply 统一镜像为 30913 line；所有包均由交付门禁检查不超过配置的 65536 line |
| 本仓库自检 | 指令编码、方案 Encode 和 reference 均通过 |
| Nexus-AM host 自检 | 53 项无内部失败，但 53 项均按 `PASS_PROBE` 标为 `qualification-pending/Skipped` |

NTT、INTT 和 BConv 使用 Nexus-AM 的专用 transform/BConv testcase，而不是通用
generated-operator relocation manifest；这不影响其独立数据包交付，但两种覆盖
方式不能在统计时混为一谈。

## 2. 程序入口与执行顺序

项目包含三个独立可执行入口，不存在 `test/reference/main.cpp` 替代 `src/main.cpp` 的关系：

| 顺序 | 源入口 | 可执行文件 | 职责 |
| --- | --- | --- | --- |
| 1 | `src/main.cpp` | `inline_asm_codegen` | 生成 `output/*.cpp` 和 `output/*.asm` 指令流 |
| 2 | `test/encode/main.cpp` | `inline_asm_encode_outputs` | 归档到 `outputs/`、编码 `.inst32`/`.cmd26`、生成 RV 冒烟流 |
| 3 | `test/reference/main.cpp` | `hpu_reference_vectors` | 生成并校验完整乘法 golden，拆分各算子 UT 数据 |

顶层 `hpu_delivery` 依次执行三个程序，再调用 `test/delivery/check_delivery.cmake` 检查文件完整性、FHE 校验结果、阶段标记和指令数量。单独执行 `hpu_reference_vectors` 只会生成数据，不会生成或更新 HPU ASM。

`config/fhe_test.conf` 是唯一的参数输入。HPU 指令生成器和软件 reference 通过
`hpu_test_config` 共享解析库读取同一份
`N/num_q/num_p/bfv_num_b/hpu_mem_max_lines/dnum/auto_index/plaintext_modulus/seed`。默认
`plaintext_modulus=65537`；BGV 以 `Q|P|t` 排列上下文，BFV 以
`Q|Pks|B|m_sk|t` 排列。顶层 `hpu_delivery` 显式向两个程序传递
CMake cache 变量 `HPU_TEST_CONFIG` 指向的同一路径，避免指令流与数据来自不同参数。

`outputs/*/test_data/params.json` 是 reference 写出的结果清单，不是配置入口。修改
它不会影响生成逻辑，并会在下一次执行 `hpu_delivery` 时被覆盖。自定义配置可通过
`cmake -S . -B build -DHPU_TEST_CONFIG=/abs/path/fhe_test.conf` 选择。

`outputs/seal_oracle/parameters.csv` 是同一次 reference 生成的差分接口，冻结 N、
Q、P0、t、seed、CKKS scale 和各检查点误差上限。SEAL key context 使用
`Q|P0`，首个密文 context 使用 Q，一次 ModSwitch/Rescale 后使用
`Q_without_last`。SEAL 只比较方案语义，不比较 HPU twiddle、RNS 中间基、密钥或
密文的逐字节表示。

### 2.1 正式交付包

`outputs/` 是生成目录并被 `.gitignore` 忽略，Git clone 不会携带其中约定的指令和
测试数据。向 IT 正式交付时必须：

1. 从同一源码 commit 执行完整 `hpu_delivery`，不得单独手改 `outputs/`。
2. 整体归档 `outputs/`，保留各算子的 `artifact_manifest.csv`、
   `hardware_manifest.csv`、`line_map.csv`、`hpu_mem_config.json`、指令文件和
   `DELIVERY_REPORT.txt`。
3. 随包记录源码 commit 与归档 SHA-256；指令、resolved relocation manifest 和
   HPU_MEM 镜像必须来自同一生成批次。
4. 如果同时交付 Nexus-AM IT runtime，应将它作为受版本控制的独立交付物，并附带
   对应源码 fingerprint、内存 profile 和逐条 resolved relocation manifest。

## 3. FHE 算法流程

Golden 严格执行以下顺序：

```text
Encrypt(ctA, ctB)
  -> PMUL psi^i, then staged NTT(ctA[0], ctA[1], ctB[0], ctB[1]) over Q
  -> TensorProduct(t0, t1, t2) over Q
  -> staged INTT(t0, t1, t2), then PMUL N^-1*psi^-i
  -> Decompose t2 into Q digits
  -> ModUp each digit to full Q union P
  -> PMUL psi^i, then staged NTT over Q union P
  -> Multiply-accumulate with rlk[digit][0..1]
  -> staged INTT over Q union P, then PMUL N^-1*psi^-i
  -> ModDown P from both key-switch components
  -> (out0, out1) = (t0 + ks0, t1 + ks1)
  -> Decrypt and compare with mA * mB in Z_t[x]/(x^N+1)
```

默认配置为 `N=4096`、`num_q=4`、`num_p=3`、`bfv_num_b=6`、`dnum=2`、
`t=65537`、`hpu_mem_max_lines=65536`。主硬件数据使用确定性零噪声、Pks 可整除的功能测试评估密钥，以获得
逐位可比结果；BFV 另生成非零误差 host smoke。两者用于 UT/IT 定位，不代表生产密钥安全性。

方案闭环从 host Encode 开始：CKKS 对 `N/2` 个复数槽位执行 generator-3 canonical
embedding，BGV/BFV 对 `N` 个槽位执行 generator-3 两行 batching；Decode 同样在 host
执行。三者不再生成 HPU Encode 指令、RNS-Q NTT 镜像或 DMA。公共乘法之后，CKKS 执行 rounded Rescale 并验证
`scale_out=scale_a*scale_b/q_last` 与近似误差；BGV 使用 correction factor `3`、`5`
执行乘法，再按 `u=-c_last*q_last^-1 mod t` 降层并验证
`cf_out=cf_in*q_last^-1 mod t`；`X->X^3` 还经过功能密文 Auto、Galois KeySwitch、
解密和 BatchDecode，验证两行分别左旋一格。BFV 使用 no-SMRQ FastBConv、
Q/Bsk tensor product、FastFloor 和 branchless-SK 生成三分量 Q 密文；同一指令流
随即从相同 HPU_MEM span 执行 Q/Pks Relinearization，只有最终一个 `psync`，没有
host copy 或第二次 window commit。随后可独立执行 rounded ModSwitch。完整边界见
`HPU_PROGRAMMING_MANUAL.md` 第 8.8 节。

生成器和 reference 共同检查 `N` 为 2 的幂且 `ceil(N/64) <= 1024`，对应当前普通 bank 的最大可承载次数 `N=65536`。`dnum` 必须整除 `num_q`；BFV 上下文必须满足
`num_q+num_p+bfv_num_b+2<=256`。BGV/BFV batching 要求 `t` 为 PE 范围内素数、
`2N | (t-1)`，并与其他模数互素。BFV 还要求所有 Q/Pks/B/m_sk 为互异的
`1 mod 2N` 32-bit 素数、`m_sk>2*bfv_num_b`，以及 B 总位宽严格超过 no-SMRQ
误差门限。`dload load_type` 只接受 `0=seg`、`1=poly`、`2=mod_ctx`；编码值 3 为保留值并纳入 RV 负例。

## 4. 数据格式

完整乘法数据位于 `outputs/ciphertext_multiply/test_data/`：

| 文件 | 用途 |
| --- | --- |
| `params.json` | 模数、根、环参数、NTT 约定和安全属性 |
| `artifact_manifest.csv` | 每个二进制及可读文本的路径、shape、字节数和 FNV-1a 校验值 |
| `memory_map.json` | 指向 `uint32` HPU_MEM 镜像、256B line map 和剩余联调字段 |
| `dma_plan.csv` | 各算法阶段的输入、输出、域和基顺序 |
| `input/*.bin` | 两个输入密文、测试明文和测试私钥 |
| `constants/*.bin` | `rlk[digit][component][basis][coefficient]` |
| `expected/*.bin` | NTT、tensor、ModUp、KeySwitch、ModDown 和最终结果检查点 |
| `VALIDATION.txt` | 软件参考模型最终校验结果 |

顶层 `.bin` 均采用 little-endian `uint64_t` canonical residue，只作为数学 golden。多维数组按 C row-major 展平，最后一维始终是 coefficient；基顺序固定为 `Q[0..num_q-1]` 后接 `P[0..num_p-1]`。

每个 `.bin` 都有同名 `.dec.txt` 人工可读版本，例如 `input.bin` 对应 `input.dec.txt`。其中数据值采用无符号十进制；文本文件头包含用途、shape、维度含义和编码说明，多维数据按 component/digit/basis 分块，并在每行标注 coefficient 范围。

每个完整乘法包和独立 UT 包还包含 `hardware/`：

| 文件 | 用途 |
| --- | --- |
| `hpu_mem_image.u32.bin` | 可整体装入 HPU_MEM window 的连续 `uint32` 镜像 |
| `images/**/*.u32.bin` | 输入、常量、期望结果的独立 256B-line-padded 镜像 |
| `line_map.csv` | 每个对象的 byte address、line offset、line count、payload/padded 大小 |
| `constants/mod_ctx.u32.bin` / `mod_ctx_map.csv` | 每个 Q/Pks/B/m_sk/t 模数的 q 与 `floor(2^64/q)` Barrett mu 物理记录；具体 context 由各包裁剪 |
| `constants/twiddle/**/*.u32.bin` / `twiddle_map.csv` | 仅含 `pntt/pintt` 的包生成；记录每个 basis、方向、phase、stage 的物理 twiddle 和 line 位置 |
| `hpu_mem_config.json` | HPU_MEM base/size、256B line 参数、`0x00..0x18` CSR 偏移和编程顺序 |
| `abi.json` | `uint32`、小端、Bank 5、mod context word 布局；`twiddle_images_included` 标明当前包是否携带 NTT/INTT twiddle |

每个 HPU 方案 kernel 均独立生成 `dma_plan.csv`。`ckks_encode`、`bgv_encode` 和
`bfv_encode` 则是纯 host 包，只包含 `params.json`、可读 CSV、round-trip 结果、
`host/host_manifest.csv` 和说明文件；它们不包含 `hardware/`、DMA plan 或指令文件。
BGV ModSwitch 将 `q_last -> t` 和面向 `Q'` 的 BConv target 常量拆成不同文件，
runtime 不应跨目标基复用其物理 span。
BFV CiphertextMultiply 另外生成 `memory_lifetime.csv`；BEHZ 输出三分量直接占用后续
Relinearization 输入 span，runtime 只提交一份 HPU_MEM 镜像和一条完整指令流。
`dma_plan.csv` 按 3153 条 DMA 的真实顺序覆盖两个算法阶段，不存在中间 host copy。

硬件模上下文 V1 每条记录占 128 bit，按低位到高位为
`{q[31:0], mu[47:0], reserved[47:0]}`，其中
`mu=floor(2^64/q)`，且 `65537 <= q <= 2^32-1`。按 `uint32` word
查看时是 `q`、`mu[31:0]`、`{16'b0,mu[47:32]}`、全零保留字。模表通过
`dload type=2, flag[0]=1` 请求分配到 small Bank 5，DMA 与后续访问的
一致性由硬件维护，软件可直接由 `pmodld MOD_ID` 选择表项。Bank 5 固定为
`0x1400..0x141F` 共 32 line，物理可放 512 条记录；但 `MOD_ID` 为 8 bit，
所以软件只允许 256 个 context，寻址 `0x1400..0x140F`。

Twiddle 与硬件组 `autotest/hw_ntt_intt_complete.py` 的 128-register 模型一致。
系数域镜像为 bit-reversed order，NTT 域镜像为全部前向 P 网络后的物理
layout。NTT stage 0 前显式执行物理顺序的 `PMUL psi^i`；每个 PNTT batch
由 64 个 BF lane 消费 64 个 twiddle，随后执行 P。PINTT 反向遍历对应的
前向 stage，每批先执行 `P^-1`，再使用 dual schedule 的 lazy-scale BF
twiddle。最终显式执行物理顺序的 `PMUL (N^-1 * psi^-i)`，不依赖 PE 隐式
归一化或 twist。每个 stage 固定 `N/2` 个 `uint32`、`N/128` 条 256B line；
默认 `N=4096` 时为 2048 words、32 line。

硬件组原始 round-trip 自测只能证明 PNTT/PINTT 互逆，不能证明逐点乘对应 FHE
卷积；自然顺序输入曾出现 round-trip 通过而卷积失败。当前 reference 因此额外检查
`PNTT(a) * PNTT(b) -> PINTT` 的 negacyclic convolution，并逐项对照 coefficient
image、NTT image、pre/post factor 和全部 stage twiddle。默认 Q0 的冻结结果为
`AUTOTEST_ORACLE=PASS q=50061313 N=4096 ntt_stages=12 intt_stages=12`。

## 5. 失败定位

| 首个失败检查点 | 优先排查模块 |
| --- | --- |
| `ckks_encode/host/decoded_*.csv` | generator-3 映射、共轭布局、FFT 方向、scale |
| `bgv_encode/host/batch_decoded_slots.csv` | generator-3 两行映射、模 t NTT、batching 参数 |
| `inputs_ntt_q` | NTT、twiddle、模上下文、数据排列 |
| `tensor_ntt_q` | PE 的 `pmul/pmac`、活动模上下文 |
| `tensor_coeff_q` | INTT、归一化因子、输出排列 |
| `modup_t2_coeff_qp` | BConv 常数、digit 偏移、Q/P context 编号 |
| `keyswitch_accum_ntt_qp` | rlk 布局、digit/component/basis 步长、PMAC 累加 |
| `keyswitch_moddown_q` | P->Q BConv、`P^-1 mod q_i`、减法方向 |
| `ciphertext_out_q` | 最终 `padd`、输出 component 顺序 |
| `ckks_ciphertext_multiply/.../ciphertext_out_qprime` | CKKS Rescale、level 与 scale 处理 |
| `bgv_modswitch/intermediate/u_mod_t` | `q_last -> t` BConv、模 t 取负和逆元 |
| `bgv_modswitch/expected_qprime` | BGV delta 符号、`q_last^-1`、correction factor |
| `bfv_ciphertext_multiply/expected/fast_floor_bsk` | no-SMRQ Q->Bsk、`Q^-1 mod Bsk` 与 FastFloor 减法方向 |
| `bfv_ciphertext_multiply/expected/alpha_msk` | `B->m_sk`、`B^-1 mod m_sk` 与 branchless alpha 上界 |
| `bfv_ciphertext_multiply/expected/ciphertext_tensor_q` | `out=y+alpha*(-B) mod Q` 和内部三分量顺序 |
| `bfv_ciphertext_multiply/expected/ciphertext_out_q` | 无 host copy 的 Q/Pks KeySwitch 和三分量到二分量合成 |
| `bfv_modswitch/expected/ciphertext_qprime` | rounded drop-last 与 BFV scale-and-round 解密 |
| 最终解密 | 上述节点均通过时再检查方案参数和 host 数据解释 |

同一 reference 还会拆分到 `outputs/{ntt,intt,ckks_encode,bgv_encode,bfv_encode,ckks_rescale,ckks_ciphertext_multiply,bgv_ciphertext_multiply,bgv_modswitch,bfv_ciphertext_multiply,bfv_modswitch,mm,bconv,modup,pmult,cmult,moddown,keyswitch,relinearization,auto,ciphertext_multiply}/test_data/`。其中 18 个 HPU 算子目录包含 `params.json`、数学输入/期望输出、checksum，以及按实际指令需求裁剪的 `hardware/` 镜像、上下文和 line map。三个 `*_encode` 目录只保留 host 数学、元数据、可读向量与 `host_manifest.csv`。NTT、INTT、三种方案 CiphertextMultiply、KeySwitch、Relinearization、Auto 和公共 CiphertextMultiply 包含 twiddle；其余硬件算子不包含。

BFV/BGV host batching 使用与 SEAL 一致的最小 primitive `2N` 次单位根和
generator-3 两行映射。启用差分门禁后，两个整数方案对 N 个编码系数和全部 N 个
slots 精确比较；CKKS 对全部 `N/2` 个复数 slots 按生成参数中的误差上限比较。

## 6. RV 接口用例

`outputs/rv_interface_smoke/` 包含：

- `rv_interface_smoke.asm`：覆盖 11 条体系结构指令、三种合法 DLoad type、DStore retain/release 和最大合法字段；type 3 作为 reserved 负例。
- `rv_interface_smoke.inst32`：对应 32-bit 指令流。
- `rv_interface_smoke.cmd26`：对应控制逻辑的 26-bit 命令流。
- `test_data/expected_decode.csv`：逐条期望 word、command26、`custom0/custom1` 路由和归一化汇编。
- `test_data/expected_cmd26.csv`：逐条验证 `cmd26[25]=custom_kind`、custom0 payload 直通和 custom1 语义字段重排。
- `test_data/negative_cases.asm.txt`：包含越界用例，以及必须拒绝的旧 `pshcfg/pshuf/pseed/psample` 助记符。

建议 RV 接口 IT 依次验证 decode 路由、队列 backpressure、顺序发射、`dload -> pmodld -> compute` 的硬件一致性、`dload -> compute -> pfree/dstore rel=1` ownership，以及末尾 `psync` 的 CPU 完成通知。`pfree` 必须在目标对象最后一次使用后生效；已经由 `dstore rel=1` 释放的对象不得重复释放。

## 7. 硬件联调边界

软件与 Nexus-AM IT runtime 已完成以下事项，不再列为 pending：

1. 按 `GPR[rs1]=line_offset`、`GPR[rs2]=line_count` 的 256B-line ABI，将
   `line_map.csv` 的实际编号逐条绑定到 `dload/dstore`，并输出 resolved relocation
   manifest；每条记录都必须是 `RESOLVED`。
2. 为 ct、tensor、ModUp、rlk、KeySwitch 等中间对象分配 scratch，并在提交前检查
   整个 span 不超过 HPU_MEM window；当前软件上限为 65536 line，BFV 单 kernel
   实际配置 30913 line，末尾 guard 由 IT runtime 在真实 window 之外维护。
3. 配置 HPU_MEM CSR，执行提交前 cache clean、读回前 invalidate，并处理
   `HPU_STATUS`、`HPU_FAULT_STATUS`、W1C fault 和完成 IRQ。
4. `psync` 只放在完整程序末尾，用于向 CPU 报告程序完成；算子内部不把它作为
   DMA 等待或阶段屏障。

硬件 qualification 仍需 IT 在目标 RTL/板级确认并留存以下证据：

1. RTL 正确接受 V1 `mod_ctx = {reserved48, mu48, q32}`、32-line Bank 5 与固定
   `MOD_TABLE_BASE_LINE=0x1400`。
2. `pntt/pintt stage` 按 `twiddle_map.csv` 的 `N/2` 个值，以 `autotest` 定义的
   batch/lane 和 P/P^-1 次序执行，采用物理 out-of-place 提交和显式 pre/post
   PMUL；当前数据为 canonical residue，不是 Montgomery 域。
3. DMA、allocator 和 PE 对 `pfree`、`dstore rel=1`、对象生命周期、FAULT/IRQ 的
   目标实现与软件 ABI 一致。
4. 目标输出逐字等于 golden，尾部 guard 未被改写，并提供外部 monitor/波形或板端
   日志。只有这些证据完成后，才可把 `HARDWARE_EXECUTION` 从 `CONDITIONAL`
   升级为 `PASS`。
