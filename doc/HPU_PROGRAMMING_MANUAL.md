# HPU 软件编程手册

版本：0.4
适用实现：`inline-asm` 当前软件实现
日期：2026-08-23

## 前言

本手册描述当前 `inline-asm` 仓库实际支持的 HPU 汇编语言、32-bit 指令编码和软件可见编程约定。章节组织参考 RISC-V 指令集手册：先定义编程模型和公共指令格式，再逐条说明指令的语法、操作、约束和编码示例。

本手册的规范对象是以下代码：

- `encode/include/instruction.hpp`：助记符、格式和结构化字段。
- `encode/src/parser.cpp`：文本语法和操作数检查。
- `encode/src/encoder.cpp`：32-bit 机器指令编码。
- `include/util/hpu_asm.hpp`：算子生成器使用的汇编封装。
- `src/`：算子级和完整密文乘法指令流。

除特别说明外，本文中的“当前实现”均指上述软件实现。26-bit HPU 命令以 `cmd26[25]` 区分 custom0/custom1；custom0 的 `inst[31:7]` 直接成为 `cmd26[24:0]`，custom1 则在 precode 阶段按控制逻辑字段重排。`pmodld` 采用 8-bit `MOD_ID`；模表对象通过 `dload type=2, flag[0]=1` 分配到 small Bank 5。

## 1. 编程模型

### 1.1 指令类别

HPU 指令均为 32-bit 定长指令，使用两个 RISC-V custom opcode：

| 类别 | 低 7-bit opcode | 用途 |
| --- | --- | --- |
| `custom0` | `0001011` (`0x0B`) | 模运算、NTT/INTT、配置、完成通知和对象释放 |
| `custom1` | `0101011` (`0x2B`) | 外部存储器与 HPU 对象之间的数据搬运 |

当前软件 ISA 包含 11 条指令：

| 指令 | 格式 | OPC/DIR | 功能 |
| --- | --- | --- | --- |
| `padd` | AR3 | `OPC=0000` | 逐系数模加 |
| `psub` | AR3 | `OPC=0001` | 逐系数模减 |
| `pmul` | AR3 | `OPC=0010` | 逐系数模乘或小常数乘 |
| `pmac` | AR3 | `OPC=0011` | 逐系数模乘加 |
| `pntt` | STG | `OPC=0100` | 前向 NTT 的一个 stage |
| `pintt` | STG | `OPC=0101` | 逆向 NTT 的一个 stage |
| `pmodld` | MOD | `OPC=0110` | 按 `MOD_ID` 选择并激活固定模表项 |
| `psync` | SYNC | `OPC=0111` | 在程序末尾通知 CPU 执行完成 |
| `pfree` | CFG | `OPC=1000` | 释放对象槽位 |
| `dload` | DMA | `DIR=0` | 外部存储器到 HPU 对象 |
| `dstore` | DMA | `DIR=1` | HPU 对象到外部存储器 |

`OPC=1001..1111` 保留。旧助记符 `pshcfg`、`pshuf`、`pseed` 和 `psample` 不属于当前 ISA，汇编器必须拒绝。

### 1.2 多项式对象槽位

HPU 软件使用 `p0` 到 `p7` 表示 8 个 3-bit 对象槽位。对象槽位不是 RISC-V 通用寄存器或 SRAM bank 编号，而是对象状态表的逻辑标识。每个对象由硬件维护 `ALLOC/V/busy/base/len`；allocator 再将其映射到具体 SRAM bank。

每个 live 对象至少具有以下软件可见属性：

- 对象类型，例如多项式、模上下文或 twiddle。
- 系数数据，硬件镜像使用 little-endian `uint32` canonical residue。
- 以 HPU line 为单位的长度。
- 生命周期状态：未分配、正在搬运、有效、忙或可释放。

编码器只检查对象编号为 0..7，不检查对象是否 live、长度是否匹配或数据域是否正确。这些条件由指令生成器、runtime 和硬件对象状态机共同保证。

### 1.3 数据粒度

当前硬件数据包采用以下基本布局：

```text
1 coefficient = 32 bit
1 HPU line     = 64 coefficients = 2048 bit = 256 byte
```

`dload/dstore` 对应的硬件数据来自 `test_data/hardware/` 下的 `uint32` 镜像。对象的 line offset 和 line count 记录在 `line_map.csv`。

### 1.4 活动模上下文

`padd`、`psub`、`pmul`、`pmac`、`pntt` 和 `pintt` 均使用当前活动模上下文。上下文至少包含：

```text
q  = 32-bit modulus, 65537 <= q <= 2^32 - 1
mu = floor(2^64 / q), 48-bit Barrett reciprocal
```

每条上下文是一个 little-endian 128-bit record，从最低位到最高位为
`{q[31:0], mu[47:0], reserved[47:0]}`。按 `uint32` word 查看时依次为：
`word0=q`、`word1=mu[31:0]`、`word2[15:0]=mu[47:32]`，
`word2[31:16]` 与 `word3` 全部为 0。生成器会同时检查 q 范围和
`mu >> 48 == 0`。

模上下文对象通过 `dload type=2, flag[0]=1` 请求 small-bank 分配。最新硬件
配置包含 Bank 0-4 五个 1024-line 普通 bank，以及
`SMALL_BANK_ID=5` 的 32-line small bank；Bank 5 固定 line 范围为
`0x1400..0x141F`，模表基址 `MOD_TABLE_BASE_LINE=0x1400`。Bank 5 物理上
可容纳 512 个 128-bit context，但 `pmodld` 的 `MOD_ID` 只有 8 bit，因此
当前软件 ABI 最多寻址 256 个 context，对应 `0x1400..0x140F`。其余 Bank 5
空间不扩展 `MOD_ID` 编码。DMA 与后续访问的一致性由硬件维护，软件可在模表
`dload` 后直接通过 `pmodld MOD_ID` 选择当前上下文；切换 Q/P limb 前必须重新执行 `pmodld`。

### 1.5 指令顺序和对象生命周期

当前生成器按程序顺序建立数据依赖，推荐遵循以下规则：

1. 使用对象前先执行对应 `dload`；硬件负责等待对象有效并维护 DMA 一致性。
2. 先执行 `pmodld`，再发出使用该模数的计算指令。
3. `pmac` 的目的对象是读写操作数，执行前必须已有有效累加值。
4. `pntt/pintt` 的数据对象在软件层面是读写对象。
5. 不再使用的输入、常量、twiddle 和模上下文使用 `pfree` 释放。
6. 输出使用 `dstore rel=1` 写回时，由 DMA 完成路径释放，之后不得再次 `pfree` 同一对象。
7. 一段完整 HPU 程序只在最后发出一次 `psync`，向 CPU 报告程序完成；组合算子的内部阶段不发出 `psync`。

## 2. 汇编语言约定

### 2.1 寄存器和立即数

| 写法 | 范围 | 含义 |
| --- | --- | --- |
| `p0`..`p7` | 0..7 | HPU 对象槽位 |
| `x0`..`x31` | 0..31 | custom1 使用的 RISC-V 通用寄存器编号 |
| `cimm8` | 0..255 | `pmul/pmac` 小立即数 |
| `stage` | 0..15 | NTT/INTT stage |
| `mode` | 0..3 | custom0 2-bit 模式 |
| `flag` | 0..1 | custom0 1-bit 标志 |
| `mod_id` | 编码 0..255，当前物理表 0..127 | 模上下文表编号 |
| `small_bank` | 0..1 | `dload flag[0]`，1 请求 small Bank 5 |

整数支持十进制和 `0x` 前缀十六进制。助记符不区分大小写，但对象和寄存器前缀应写成小写 `p`、`x`。

### 2.2 注释和源文件

解析器接受单条 ASM，也可以从生成的 C++ 内联汇编字符串中提取指令。支持以下注释：

```text
// comment
# comment
; comment
/* comment */
```

项目生成的 `.cpp` 文件是中间表示；当前编码流程由项目自身的 parser/encoder 产生 `.inst32`，不要求系统 GNU assembler 原生认识这些 HPU 助记符。

### 2.3 26-bit precode

控制逻辑命令固定把类别放在最高位：

```text
cmd26[25]   = cmd_kind: 0=custom0, 1=custom1
cmd26[24:0] = payload
```

custom0 的 payload 与原始指令去掉低 7-bit opcode 后完全相同：

```text
custom0: cmd26 = {1'b0, inst[31:7]}
```

custom1 的 `rs1/rs2` 用于核侧形成 `mem_line_offset/mem_len_lines` sideband，不进入命令本体。其语义已经冻结为
`mem_line_offset=GPR[rs1]`、`mem_len_lines=GPR[rs2]`，二者均以 256B HPU line
为单位；`mem_len_lines` 必须非零且 `offset+count` 不得超过
`HPU_MEM_SIZE_LINES`。旧《RISC-V核内接口设计》中的 DTLB descriptor 方案不再作为本项目 ABI。precode 从原始 DMA 指令提取语义字段并重排为：

```text
cmd26[25]    = 1
cmd26[24:14] = 0
cmd26[13:10] = {3'b000, flag[0]}
cmd26[9:6]   = 0
cmd26[5:3]   = OBJ_ID
cmd26[2:1]   = dload: TYPE
                 dstore: {REL, 1'b0}
cmd26[0]     = DIR
```

项目为每个可编码算子同时生成 `.inst32` 和 `.cmd26`。`outputs/rv_interface_smoke/test_data/expected_cmd26.csv` 提供逐条 32→26-bit 对拍数据。

## 3. 32-bit 指令格式

### 3.1 AR3 格式

```text
 31      28 27    25 24    22 21             14 13       10 9    8 7 6       0
+----------+--------+--------+-----------------+-------------+------+--+---------+
|   OPC4   |  PDST  | PSRC1  |      OP2_8      | STAGE4=0    | MODE2| F| 0001011 |
+----------+--------+--------+-----------------+-------------+------+--+---------+
```

编码公式：

```text
word = (OPC4 << 28) | (PDST << 25) | (PSRC1 << 22)
     | (OP2_8 << 14) | (MODE2 << 8) | (FLAG1 << 7) | 0x0B
```

- 对象模式：`OP2_8[2:0]=PSRC2`，高 5-bit 为 0，`MODE2=0`。
- 立即数模式：`OP2_8=cimm8`，编码器设置 `MODE2[0]=1`。
- 算术文本语法不直接暴露 `FLAG1`，其值为 0。

### 3.2 STG 格式

```text
 31      28 27    25 24    22 21             14 13       10 9    8 7 6       0
+----------+--------+--------+-----------------+-------------+------+--+---------+
|   OPC4   | PDATA  | PTWID  |  reserved=0     |   STAGE4    | MODE2| F| 0001011 |
+----------+--------+--------+-----------------+-------------+------+--+---------+
```

编码公式：

```text
word = (OPC4 << 28) | (PDATA << 25) | (PTWID << 22)
     | (STAGE4 << 10) | (MODE2 << 8) | (FLAG1 << 7) | 0x0B
```

`stage`、`mode` 和 `flag` 均由汇编显式给出；当前生成器使用 `mode=0, flag=0`。

### 3.3 MOD 格式

```text
 31      28 27             22 21             14 13              7 6       0
+----------+-----------------+-----------------+------------------+---------+
|   0110   |   reserved=0    |     MOD_ID8     |    reserved=0    | 0001011 |
+----------+-----------------+-----------------+------------------+---------+
```

编码公式：

```text
word = (0b0110 << 28) | (MOD_ID8 << 14) | 0x0B
```

经过 custom0 precode 后，`MOD_ID8` 位于 `cmd26[14:7]`。其余操作数字段必须为 0。

### 3.4 PFREE 格式

```text
 31      28 27    25 24    22 21                                  7 6       0
+----------+--------+--------+--------------------------------------+---------+
|   1000   | reserved| OBJ_ID |             reserved=0               | 0001011 |
+----------+--------+--------+--------------------------------------+---------+
```

编码公式：

```text
word = (0b1000 << 28) | (OBJ_ID << 22) | 0x0B
```

`OBJ_ID` 使用 custom0 的 `PSRC` 位段，其他载荷位必须为 0。

### 3.5 SYNC 格式

```text
 31      28 27                                                       7 6       0
+----------+----------------------------------------------------------+---------+
|   0111   |                       reserved=0                         | 0001011 |
+----------+----------------------------------------------------------+---------+
```

编码公式：

```text
word = (0b0111 << 28) | 0x0B
```

`psync` 不携带 tag/mode，所有载荷位必须为 0。

### 3.6 DMA 格式

```text
 31             25 24    20 19    15 14 13    12 11     9 8 7 6       0
+-----------------+--------+--------+--+--------+---------+--+-+---------+
|   reserved=0    |  RS2   |  RS1   |D | TYPE2  | OBJ_ID  |SB|0| 0101011 |
+-----------------+--------+--------+--+--------+---------+--+-+---------+
```

编码公式：

```text
word = (RS2 << 20) | (RS1 << 15) | (DIR << 14)
     | (TYPE2 << 12) | (OBJ_ID << 9)
     | (SMALL_BANK << 8) | 0x2B
```

`SMALL_BANK` 是 dload 的 `flag[0]`；1 表示请求 allocator 将小对象放入 `SMALL_BANK_ID=5`。dstore 中该位必须为 0。`RS1/RS2` 编码的是寄存器编号，不是寄存器值。

原始 custom1 的 `RS1/RS2` 由核侧读取并转换成 `mem_line_offset/mem_len_lines` sideband。precode 只把 `SMALL_BANK/OBJ_ID/TYPE/DIR` 重排到 26-bit 命令，因而 `SMALL_BANK=1` 最终表现为 `cmd26.flag[0]=cmd26[10]=1`。

## 4. 算术指令

本章伪代码使用：

```text
P[n][i]  对象 pn 的第 i 个系数
q        当前活动模数
L        对象的系数数量
```

除 `pmac` 外，算术指令的目的对象可以是新对象或可覆盖对象。编码器不检查对象别名和长度；后端必须保证源对象和目的对象具有兼容布局。

### 4.1 PADD - 多项式模加

**语法**

```asm
padd pdst, psrc1, psrc2
```

**操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = (P[psrc1][i] + P[psrc2][i]) mod q
```

**编码**：AR3，`OPC4=0000`，只支持对象形式。

**示例**

```asm
padd p2, p0, p1       # 0x0400400B
```

### 4.2 PSUB - 多项式模减

**语法**

```asm
psub pdst, psrc1, psrc2
```

**操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = (P[psrc1][i] - P[psrc2][i]) mod q
```

结果按 canonical residue 归一化到 `[0,q)`。

**编码**：AR3，`OPC4=0001`，只支持对象形式。

**示例**

```asm
psub p2, p0, p1       # 0x1400400B
```

### 4.3 PMUL - 多项式逐点模乘

**语法**

```asm
pmul pdst, psrc1, psrc2
pmul pdst, psrc1, cimm8
```

**对象模式操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = P[psrc1][i] * P[psrc2][i] mod q
```

**立即数模式操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = P[psrc1][i] * cimm8 mod q
```

对象模式设置 `MODE2=0`；立即数模式设置 `MODE2[0]=1`。`cimm8` 范围为 0..255。

**示例**

```asm
pmul p2, p0, p1       # 0x2400400B
pmul p2, p0, 255      # 0x243FC10B
```

### 4.4 PMAC - 多项式逐点模乘加

**语法**

```asm
pmac pdst, psrc1, psrc2
pmac pdst, psrc1, cimm8
```

**对象模式操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = (P[pdst][i] + P[psrc1][i] * P[psrc2][i]) mod q
```

**立即数模式操作**

```text
for i = 0 .. L-1:
    P[pdst][i] = (P[pdst][i] + P[psrc1][i] * cimm8) mod q
```

`pdst` 是读写累加器，执行前必须已经包含当前模数下的有效数据。第一个累加项通常使用 `pmul` 初始化，后续项使用 `pmac`。

**示例**

```asm
pmac p2, p0, p1       # 0x3400400B
pmac p2, p0, 255      # 0x343FC10B
```

## 5. 变换指令

### 5.1 PNTT - 前向 NTT stage

**语法**

```asm
pntt pdata, ptwiddle, stage, mode, flag
```

**操作**

```text
P[pdata] = NTT_STAGE(P[pdata], P[ptwiddle], stage, mode, flag, q)
```

当前生成器把 `pdata` 视为同一 logical object id 下的读写对象，每条 `pntt`
只执行一个 stage。物理执行固定为 out-of-place：controller 分配下一物理
base，完成后提交给同一 logical object id 并释放旧 base。完整长度为 `N` 的
NTT 发出 `log2(N)` 条指令，stage 从 0 递增到 `log2(N)-1`。

| 操作数 | 范围 | 当前用法 |
| --- | --- | --- |
| `pdata` | `p0`..`p7` | 数据对象 |
| `ptwiddle` | `p0`..`p7` | 当前 stage 的 twiddle 对象 |
| `stage` | 0..15 | 编入 `STAGE4` |
| `mode` | 0..3 | 当前生成器写 0 |
| `flag` | 0..1 | 当前生成器写 0 |

**示例**

```asm
pntt p0, p3, 15, 0, 0    # 0x40C03C0B
```

软件通常在每个 stage 前加载 twiddle，并在该 stage 后释放：

```asm
dload x12, x13, p3, 1, 0
pntt  p0, p3, 0, 0, 0
pfree p3
```

完整 negacyclic NTT 在 stage 0 前还会显式加载 `pre_twist.u32.bin`，并执行
`pmul pdata, pdata, ptwiddle`，实现逐系数乘 `psi^i`。该步骤不是
`pntt stage=0` 的隐含行为。

硬件镜像遵循硬件组 `autotest/hw_ntt_intt_complete.py` 的物理执行模型。
系数域多项式先按 `memory[p] = coefficient[bit_reverse(p)]` 排列，因此
`pre_twist[p] = psi^bit_reverse(p)`。每个 stage 处理 `N/128` 个 batch；每个
batch 装入 128 个寄存器，由 64 个 BF lane 顺序消费 64 个 twiddle，BF 后
对 7-bit 寄存器索引执行一次 P 网络，再写回本 batch。`m=2^stage < 128`
时 loader 连续装入 128 words；`m >= 128` 时从蝶形的上下两半各取 64 words
交错装入。stage twiddle 文件严格按“batch 顺序、batch 内 lane 顺序”写出，
共 `N/2` 个 little-endian `uint32`，即 `N/128` 条 256B line。默认
`N=4096` 时为 2048 words、32 line。

完成所有 stage 后，NTT 域数据保持 P 网络产生的物理排列：
`memory[p] = logical_ntt[forward_layout[p]]`。因此 NTT 域明文、密钥和中间
结果也必须使用同一排列；不能把自然顺序 NTT 数据直接作为硬件镜像。

### 5.2 PINTT - 逆向 NTT stage

**语法**

```asm
pintt pdata, ptwiddle, stage, mode, flag
```

**操作**

```text
P[pdata] = INTT_STAGE(P[pdata], P[ptwiddle], stage, mode, flag, q)
```

操作数范围和生命周期与 `pntt` 相同。当前汇编生成器按
`stage=0..log2(N)-1` 的顺序执行 INTT；`pdata` 的逻辑对象号在所有 stage
之间保持不变，控制器对每个 stage 执行物理 out-of-place，完成后提交新的
base 并释放旧空间。每个 stage 依次生成 `dload`、`pintt` 和 `pfree`：

```asm
dload ..., ptwiddle, 1, 0
pintt pdata, ptwiddle, stage, 0, 0
pfree ptwiddle
```

硬件 PINTT 使用与前向变换严格对偶的 schedule。指令的 `stage=k` 对应前向
`stage=log2(N)-1-k` 的 loader；每个 batch 先执行一次 P 的逆网络 `P^-1`，
再进入 64 个 BF lane。逆表不是简单的自然顺序 `omega^-j` 表，而是由 dual
schedule 跟踪每个物理位置的 lazy scale，逐 lane 生成
`w_bf = alpha * beta^-1 mod q`。这样全部 PINTT stage 结束后，物理布局和
lazy scale 都恢复到系数域约定。

随后显式加载 `post_untwist_scale.u32.bin` 并执行
`dload + pmul + pfree`。物理位置 `p` 的值为
`N^-1 * psi^-bit_reverse(p) mod q`，同时完成归一化和 negacyclic inverse
twist。完整的 `PNTT -> pointwise multiply -> PINTT` 已由 reference 与硬件
schedule 模型逐字比较，结果对应系数域的 negacyclic convolution。
runtime 按 `twiddle_map.csv` 绑定 pre-twist、各 stage twiddle 和 post factor
的 line offset/count。

**示例**

```asm
pintt p0, p3, 15, 0, 0   # 0x50C03C0B
```

## 6. 配置与生命周期指令

### 6.1 PMODLD - 激活模上下文

**语法**

```asm
pmodld mod_id
```

**操作**

```text
line = MOD_TABLE_BASE_LINE + (mod_id >> 4)
slot = mod_id & 0xF
active_mod_context = MOD_TABLE[line][slot]
```

| 操作数 | 范围 | 含义 |
| --- | --- | --- |
| `mod_id` | 0..255 | Bank 5 模上下文表中的 8-bit 表项编号 |

一条 256B HPU line 可容纳 16 个 128-bit 模上下文，因此
`mod_id[7:4]` 选择 `0x1400..0x140F` 中的相对 line，`mod_id[3:0]` 选择
line 内 slot。Bank 5 共 32 line，但 8-bit `MOD_ID` 只能寻址前 16 line，
所以生成器上限是 256 个 context。`pmodld` 不携带对象号，也不产生多项式
结果；它改变后续模运算使用的 q/Barrett mu。

模表的数据搬入与上下文选择是两个独立步骤。`dload type=2, flag[0]=1` 为模表逻辑对象建立 `ALLOC/V/busy/base/len` 状态，并请求 allocator 将物理 base 放到 Bank 5。DMA 与 `pmodld` 之间的一致性由硬件维护，软件无需插入 `psync`；`pmodld` 只携带 `MOD_ID`，通过 cfg 读口访问模表并更新活动 q/mu。

**示例**

```asm
pmodld 0              # 0x6000000B
pmodld 1              # 0x6000400B
pmodld 255            # 0x603FC00B
```

旧语法 `pmodld psrc, idx1, cfg` 已删除，汇编器必须拒绝。

### 6.2 PFREE - 释放对象

**语法**

```asm
pfree psrc
```

**操作**

```text
require OBJ[psrc] is allocated and not busy
release OBJ[psrc]
```

`pfree` 的目标对象编码在 custom0 `PSRC/OBJ_ID` 位段，其他载荷位为 0。它必须排在对象最后一次读取之后。

**示例**

```asm
pfree p4              # 0x8100000B
```

对已经使用 `dstore rel=1` 释放的对象再次执行 `pfree` 属于非法生命周期操作。

### 6.3 PSYNC - 程序完成通知

**语法**

```asm
psync
```

**当前软件语义**

```text
notify_cpu(program_complete)
```

`psync` 没有操作数。根据硬件负责人确认的软件使用约定，它只在一段完整 HPU 程序的最后发出一次，用于向 CPU 报告整个程序完成。DMA 与计算之间的依赖、顺序和可见性由硬件维护；生成器不得在模表 `dload` 与 `pmodld` 之间或任何算子内部阶段插入 `psync`。

**示例**

```asm
psync                  # 0x7000000B
```

## 7. 外部访存指令

### 7.1 DLOAD - 外部存储器加载

**语法**

```asm
dload rs1, rs2, pdst, load_type, small_bank
```

**操作**

```text
enqueue_load(GPR[rs1], GPR[rs2], pdst, load_type, small_bank)
on completion:
    OBJ[pdst] becomes valid
```

| `load_type` | 名称 | 当前项目用途 |
| --- | --- | --- |
| 0 | `seg` | 多项式片段/普通分段数据 |
| 1 | `poly` | 完整多项式、twiddle 或多项式常量 |
| 2 | `mod_ctx` | 模上下文集合 |
| 3 | reserved | 当前软件 ABI 不定义语义，parser/encoder 必须拒绝 |

`small_bank=0` 使用普通 bank 分配；`small_bank=1` 设置 `flag[0]`，请求把
长度不超过 32 line 的小对象分配到 Bank 5。模上下文生成器固定使用
`type=2, small_bank=1`，模表固定从 `0x1400` 开始。

完整多项式对象包含 `N` 个 32-bit word。由于每个 HPU line 包含 64 word、
普通 bank 最多容纳 1024 line，所有 NTT、INTT、KeySwitch 和完整密文乘法
生成入口都要求 `ceil(N/64) <= 1024`。结合 radix-2 要求，当前允许的最大
多项式次数为 `N=65536`；超出该范围时生成器返回 invalid config，不生成指令流。

`rs1` 和 `rs2` 是 5-bit RISC-V 寄存器编号。执行时固定解释为
`GPR[rs1]=HPU_MEM line offset`、`GPR[rs2]=line count`，单位均为 256B；
不存在另一套 DTLB descriptor 解释。生成的 `hpu_program_*` 入口逐条消费
`hpu_dma_span_t`，在 custom1 发射前把 line offset/count 装入固定的
`x10/x11`；DLOAD 和 DSTORE 的 `line count` 都必须非零，DSTORE 不得把
`x11` 置零。
调用方必须使用与硬件布局一致、已通过范围和生命周期检查的 span 数组。

**示例**

```asm
dload x10, x11, p0, 0, 0  # 0x00B5002B
dload x10, x11, p4, 2, 1  # 0x00B5292B
```

### 7.2 DSTORE - 外部存储器写回

**语法**

```asm
dstore rs1, rs2, psrc, rel
```

**操作**

```text
enqueue_store(GPR[rs1], GPR[rs2], psrc)
on completion:
    if rel == 1:
        release OBJ[psrc]
```

| `rel` | 语义 |
| --- | --- |
| 0 | 写回完成后保留源对象 |
| 1 | 写回完成后释放源对象 |

`rel` 只允许 0 或 1。源对象必须已经有效，且在 DMA 读取期间不得被覆盖或提前 `pfree`。

**示例**

```asm
dstore x10, x11, p2, 1    # 0x00B5542B
```

<!-- ### 7.3 HPU_MEM CSR

HPU_MEM window 使用以下已冻结的 CSR 偏移：

| 偏移 | 名称 | 访问 | 有效字段 |
| --- | --- | --- | --- |
| `0x00` | `HPU_MEM_BASE_LO` | RW | `base[31:0]` |
| `0x04` | `HPU_MEM_BASE_HI` | RW | `base[39:32]` |
| `0x08` | `HPU_MEM_SIZE_LINES_LO` | RW | `size_lines[31:0]` |
| `0x0C` | `HPU_MEM_SIZE_LINES_HI` | RW | `size_lines[32]` |
| `0x10` | `HPU_MEM_COMMIT` | W1 | `commit[0]` |
| `0x14` | `HPU_STATUS` | RO | `window_valid[0]`、`hpu_busy[1]`、`fault_valid[2]` |
| `0x18` | `HPU_FAULT_STATUS` | RO/W1C | `fault_valid[0]`、`is_load[1]`、`obj_id[6:4]` |

软件先写 base low/high 和 size low/high，再向 `HPU_MEM_COMMIT` 写 1，最后读
`HPU_STATUS`，要求 `window_valid=1` 且 `fault_valid=0`。故障处理完成后向
`HPU_FAULT_STATUS.fault_valid` 写 1 清除。生成文件
`hardware/hpu_mem_config.json` 给出当前镜像的具体值和同一编程顺序。 -->

## 8. 推荐编程序列

### 8.1 逐点模乘

以下序列展示一个 RNS limb 上的多项式逐点乘。寄存器中的实际 offset/count 由 runtime 准备：

```asm
dload  x10, x11, p4, 2, 1  # allocate the mod-table object in small Bank 5
pmodld 0                   # activate q0 by MOD_ID
dload  x12, x13, p0, 1, 0  # left polynomial
dload  x14, x15, p1, 1, 0  # right polynomial
pmul   p2, p0, p1
pfree  p0
pfree  p1
dstore x16, x17, p2, 1
pfree  p4
psync                       # final instruction: notify CPU of program completion
```

### 8.2 乘加累积

```asm
pmul p2, p0, p1            # initialize accumulator
pmac p2, p3, p5            # p2 += p3 * p5
pmac p2, p6, 7             # p2 += p6 * 7
```

### 8.3 完整 NTT

对于 `N=4096`，当前生成器发出 12 个 stage：

```asm
# q already selected with pmodld
dload x10, x11, p0, 1, 0   # polynomial

dload x12, x13, p3, 1, 0   # pre_twist = psi^i
pmul  p0, p0, p3
pfree p3

dload x12, x13, p3, 1, 0   # stage 0 twiddle
pntt  p0, p3, 0, 0, 0
pfree p3

# repeat for stage 1 .. 11
dload x14, x15, p3, 1, 0
pntt  p0, p3, 11, 0, 0
pfree p3

dstore x16, x17, p0, 1
psync
```

完整 INTT 在最后一个 `pintt` 后还必须加载
`post_untwist_scale = N^-1 * psi^-i` 并显式 `pmul`，再执行 `dstore`。

### 8.4 RNS 循环

HPU 同一时刻只有一个活动模上下文。对 Q/P 多个 limb 执行同一算子时，软件按 limb 循环：

```text
for each modulus context i:
    pmodld i
    dload operands for limb i
    execute arithmetic/NTT instructions
    dstore result for limb i
```

不能在一次 `pmodld` 后混合处理不同模数的数据。

### 8.5 公共算子层与方案算子层

`util`、`poly` 和 `operator` 提供方案无关的 RNS、NTT、KeySwitch、
Relinearization 和原始 CiphertextMultiply。`scheme/ckks`、`scheme/bgv` 与 `scheme/bfv`
位于其上，只组合方案特有步骤并维护软件元数据。方案层当前统一采用系数域输入、
系数域输出边界；内部 NTT/INTT 仍由公共算子生成。

三个 `scheme/*/encode` 分别定义方案数学。CKKS 使用 generator-3
槽位映射、共轭半区和 radix-2 复数 FFT，把最多 `N/2` 个复数槽位量化为带 scale
的 signed 系数；BGV/BFV 支持 signed coefficient encoding，并在 `t` 为素数且
`2N | (t-1)` 时以 generator-3 映射提供两行、共 `N` 槽 batching。Decode 均在
host 执行。三种 Encode 把 RNS-Q 系数 limbs 交给公共 `plaintext_ntt` 后端，由 HPU
执行逐 limb 负循环 NTT。

BGV/BFV 的模 `t` 负循环 NTT 从全部 primitive `2N` 次单位根中选择数值最小者，
再应用 generator-3 两行索引映射；该选择与本项目使用的 SEAL BatchEncoder ABI
一致。选择另一个 primitive root 虽可形成自洽 Encode/Decode，但会改变明文
多项式系数，不能混入本交付数据。

### 8.6 CKKS Rescale 与完整乘法

CKKS Rescale 对每个密文分量执行：

```text
rounded_i = x_i + floor(q_last/2) mod q_i
out_i = (rounded_i - BConv_q_last_to_q_i(rounded_last))
        * q_last^-1 mod q_i
```

输出基为 `Q_without_last`，level 减一。HPU 指令不携带浮点 scale；调用方必须使用
`multiply_scale(scale_a, scale_b)` 和 `rescale_scale(product_scale, q_last)` 更新
软件元数据。`ckks_ciphertext_multiply` 的固定顺序是公共 tensor product、
重线形化、CKKS Rescale，最终只发出一次 `psync`。

### 8.7 BGV 乘法和 ModSwitch

BGV 固定模上下文顺序为：

```text
MOD_ID 0 .. num_q-1              : Q
MOD_ID num_q .. num_q+num_p-1    : P
MOD_ID num_q+num_p               : plaintext modulus t
```

因此配置必须满足 `num_q + num_p + 1 <= 256`。当前默认 `t=65537`，可作为
`q32+mu48` 模上下文由 `dload type=2, flag[0]=1` 安装。BGV 乘法复用公共
CiphertextMultiply，软件同时更新：

```text
correction_factor_out = correction_factor_a * correction_factor_b mod t
```

BGV ModSwitch 对每个分量先用单源 BConv 得到 `c_last mod t`，然后计算：

```text
u = -c_last * q_last^-1 mod t
delta_i = c_last + q_last * u mod q_i
c_i' = (c_i - delta_i) * q_last^-1 mod q_i
```

`c_last` 和 `u` 分别通过单源 BConv 从 `q_last`/`t` 提升到各个保留的 `q_i`。
输出仍为系数域，level 减一，软件元数据更新为：

```text
correction_factor_out = correction_factor_in * q_last^-1 mod t
```

该流程不需要比较或条件选择，但要求 `gcd(q_last,t)=1`。完整中间值和常量位于
`outputs/bgv_modswitch/test_data/`。

### 8.8 BFV comparison-free BEHZ、重线形化和 ModSwitch

| 方案能力 | 状态 | 当前边界 |
| --- | --- | --- |
| CKKS Encode/Decode / Rescale / Multiply | 已实现 | host 复数编解码 + HPU RNS-Q NTT/方案算子 |
| BGV coefficient/batch Encode/Decode / Multiply / ModSwitch | 已实现 | host 模 t 编解码 + HPU RNS-Q NTT/方案算子 |
| BFV coefficient/batch Encode/Decode | 已实现 | host 模 t 编解码 + HPU RNS-Q NTT |
| BFV BEHZ Multiply / Relinearization / ModSwitch | 已实现 | no-SMRQ + branchless-SK 单 kernel 乘法功能通路 |

BFV 使用修改版 SEAL 对应的 `NO_SMRQ + BRANCHLESS_SK` 关系，不生成 `m_tilde`，
也不执行依赖阈值判断的 centered correction。模上下文固定为：

```text
Q    = MOD_ID [0, num_q)
Pks  = MOD_ID [num_q, num_q+num_p)
B    = MOD_ID [num_q+num_p, num_q+num_p+bfv_num_b)
m_sk = MOD_ID num_q+num_p+bfv_num_b
t    = MOD_ID m_sk+1
```

其中 `Pks` 仅供乘法流后半段的 KeySwitch 使用，不能与 BEHZ 的 B 基混用。参数必须满足
总 context 不超过 256、所有模数互异且为 `1 mod 2N` 的 32-bit 素数、
`m_sk > 2*bfv_num_b`，并满足：

```text
log2(B) > 33 + bitlen(t) + bitlen(Q) + ceil(log2(num_q^2))
```

单 kernel 的 BEHZ 阶段对两个二分量密文执行：

```text
FastBConv Q -> Bsk                 // 不做 SmMRq
NTT under Q and Bsk
three-component tensor product
INTT under Q and Bsk
multiply every limb by t
v = FastConv(Q -> Bsk)
z = (x_Bsk - v) * Q^-1 mod Bsk    // FastFloor
y = FastConv(B -> Q)
temp = FastConv(B -> m_sk)
alpha = (temp - z_msk) * B^-1 mod m_sk
out = y + alpha * (-B) mod Q       // branchless-SK
```

参数门禁保证 `alpha` 位于已证明的下半区；最后一步始终执行同一条模算术路径，
所以 11 条 ISA 不需要新增比较、掩码或条件选择。该阶段把三分量系数域 Q 密文
`dstore` 到统一 HPU_MEM 中，随后的 Q/Pks Relinearization 直接从相同 span `dload`，
把三分量密文变回二分量；中间不发出 `psync`，也不需要 host copy 或 window 切换。
完整 `bfv_ciphertext_multiply` 只在 Relinearization 完成后发出一个终止 `psync`。
默认统一镜像为 30913 line；软件 profile 通过 `hpu_mem_max_lines=65536` 设置验收
上限，`HPU_MEM_SIZE_LINES` 仍写入当前镜像的真实 line 数。

BFV ModSwitch 对单 kernel 输出的两个
输出分量复用公共 rounded drop-last：

```text
c' = round(c / q_last) mod Q_without_last
```

level 减一；BFV 没有 CKKS scale 或 BGV correction factor 元数据。主硬件包使用
零噪声、Pks 可整除的精确功能 key，以便逐 stage 定位；
`outputs/bfv_ciphertext_multiply/test_data/host/noise_smoke/` 另用确定性非零误差完成
Encode、Multiply、Relinearization、ModSwitch、Decrypt、Decode 闭环。

算法实现以 `/home/songyexin/fhe/SEAL` 中同时启用
`SEAL_EXPERIMENTAL_BFV_NO_SMRQ` 和
`SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK` 的修改流程为差分依据；正常构建不依赖 SEAL。

生产密钥生成、安全参数选择、随机数接口、多 level 模数链以及噪声/精度预算仍属于
后续 host runtime/compiler 工作。当前 Encode/Decode 是自包含的功能实现，但不承担
生产参数选择或密文元数据持久化。当前主硬件测试使用确定性零噪声、P 可整除的功能 fixture，必须标记为
`TEST_VECTOR_SCOPE=FUNCTIONAL_ONLY`。

## 9. 汇编器检查和错误

当前汇编器在编码前检查：

- 助记符是否属于 11 条当前指令。
- 操作数数量是否正确。
- `p` 对象和 `x` 寄存器是否越界。
- stage、mode、flag、立即数、type/rel 和 small-bank hint 是否在编码范围内。
- 只有 `pmul/pmac` 可以使用整数第三操作数。
- `pfree` 只能有一个对象操作数。
- `dstore rel` 只能为 0 或 1。

这些是软件编码错误，表现为 assembler 抛出错误，不等价于 RISC-V 运行时 trap。对象未加载、长度不匹配、模上下文错误、DMA 越界和 busy 冲突属于硬件/runtime 验证范围。

## 10. 构建与输出

生成指令流、编码和测试数据：

```bash
cmake -S . -B build
cmake --build build -j --target hpu_delivery
ctest --test-dir build --output-on-failure
```

主要输出：

| 文件 | 内容 |
| --- | --- |
| `outputs/<case>/<case>.asm` | HPU 汇编指令流 |
| `outputs/<case>/<case>.cpp` | C++ 内联汇编形式 |
| `outputs/<case>/<case>.inst32` | 每行一个 32-bit 二进制字符串 |
| `outputs/<case>/<case>.cmd26` | 每行一个控制逻辑 26-bit 二进制命令 |
| `outputs/rv_interface_smoke/test_data/expected_decode.csv` | 指令字、路由和规范化汇编 |
| `outputs/<case>/test_data/hardware/` | `uint32` HPU 数据镜像和 line map |

`.inst32`/`.cmd26` 分别是每行 32/26 个 `0/1` 字符的文本，不是可直接按字节加载的 little-endian ELF 或 binary。接入硬件测试平台时应明确其文本解析或另行打包为目标字节序。

## 附录 A：指令编码速查

| 指令示例 | 32-bit 机器码 | 26-bit 控制命令 |
| --- | --- | --- |
| `padd p2, p0, p1` | `0x0400400B` | `0x0080080` |
| `psub p2, p0, p1` | `0x1400400B` | `0x0280080` |
| `pmul p2, p0, p1` | `0x2400400B` | `0x0480080` |
| `pmul p2, p0, 255` | `0x243FC10B` | `0x0487F82` |
| `pmac p2, p0, p1` | `0x3400400B` | `0x0680080` |
| `pmac p2, p0, 255` | `0x343FC10B` | `0x0687F82` |
| `pntt p0, p3, 15, 0, 0` | `0x40C03C0B` | `0x0818078` |
| `pintt p0, p3, 15, 0, 0` | `0x50C03C0B` | `0x0A18078` |
| `pmodld 0` | `0x6000000B` | `0x0C00000` |
| `pmodld 255` | `0x603FC00B` | `0x0C07F80` |
| `psync` | `0x7000000B` | `0x0E00000` |
| `pfree p4` | `0x8100000B` | `0x1020000` |
| `dload x10, x11, p0, 0, 0` | `0x00B5002B` | `0x2000000` |
| `dload x10, x11, p4, 2, 1` | `0x00B5292B` | `0x2000424` |
| `dstore x10, x11, p2, 1` | `0x00B5542B` | `0x2000015` |

## 附录 B：当前实现边界

以下内容不由当前编码器单独保证：

1. relocation/runtime 是否把每条 DMA 的实际 line offset/count 装入 `rs1/rs2`。
2. runtime 是否按 `MOD_TABLE_BASE_LINE=0x1400` 将模表 DMA 搬入 Bank 5。
3. RTL 是否按 `autotest` 的 batch/lane、P/P^-1 次序消费 twiddle，并按 out-of-place 协议提交各 stage 新 base。
4. cache maintenance、中断和 fault 的 runtime 实现。

这些事项不由指令编码器证明；当前软件完成度与剩余 RTL/板级签字项以
`HPU_TEST_DELIVERY.md` 为准，它们不是 ABI 的备选解释。

## 附录 C：DLOAD/DSTORE 数据绑定

### C.1 通用规则

- `dload/dstore` 固定编码 `x10/x11`；runtime 在发射前写入当前对象的 256B line
  offset/count，权威物理位置来自各用例的 `hardware/line_map.csv`。
- `dload type=2, flag[0]=1` 把模表对象分配到 small Bank 5；随后由
  `pmodld MOD_ID` 选择上下文。模表顺序必须与 MOD_ID 一致。
- `dstore rel=1` 在写回后释放对象；只读对象最后一次使用后由 `pfree` 释放。
- 组合算子 body 不发 `psync`，只有最外层完整程序在末尾发出一次。
- NTT stage 0 前显式加载并乘 `pre_twist`；INTT 结束后显式加载并乘
  `post_untwist_scale`。每个 stage 都重新加载该 stage 的 twiddle。

| 槽位 | 当前生成器的常见角色 |
| --- | --- |
| `p0` | 当前输入 limb 或工作对象 A |
| `p1` | 第二输入、预计算常量或评估密钥 |
| `p2` | 累加器和输出对象 |
| `p3` | 复合算子 twiddle 或临时标量；独立 NTT/INTT 的 twiddle 使用 `p1` |
| `p4` | 模表逻辑对象，物理分配到 small Bank 5 |
| `p5..p7` | 当前生成器未固定占用，不能假设其中已有 live 对象 |

### C.2 BConv、ModUp 与 ModDown

#### BConv

`generate_hpu_bconv_contexts_body_asm` 的输入基和目标基均由 MOD_ID 列表显式给出。
运行时必须按以下出现顺序为每条 DMA 绑定数据：

| 阶段 | MOD_ID | 目标槽位 | dload 数据 | dstore 数据 |
| --- | --- | --- | --- | --- |
| 开始 | - | `p4` | 完整 source/target 模表，`type=2,flag[0]=1` | - |
| Stage 1，每个 source `j` | `source_contexts[j]` | `p0` | source limb `a_j` | - |
| Stage 1，每个 source `j` | 同上 | `p1` | `qhat_inv_j` | - |
| Stage 1，每个 source `j` | 同上 | `p0` | - | `x_j=a_j*qhat_inv_j mod source_j` |
| Stage 2，每个 target `i`、source `j` | `target_contexts[i]` | `p0` | Stage 1 的 `x_j` | - |
| Stage 2，每个 target `i`、source `j` | 同上 | `p1` | `qhat_j mod target_i` | - |
| Stage 2，每个 target `i` | 同上 | `p2` | - | `sum_j(x_j*qhat_j) mod target_i` |

`p2` 是 `pmul/pmac` 累加目标，不需要在首个 source 前加载；非首项使用 `pmac`。

#### ModUp

ModUp 把一个 Q digit 扩展到完整 `Q union P`：

1. 对 digit 内每个已有 Q limb，`dload p0` 后立即 `dstore p0,rel=1`，原样保留。
2. 以该 digit 为 BConv source，以 `Q_without_digit union P` 为 target，按上一表加载
   source limb、`qhat_inv` 和 target residues。
3. 原样保留的 limb 与 `p2` 写出的 BConv target limbs 共同组成完整基。

#### ModDown

ModDown 的 source context 是 P，target context 是 Q：

| 阶段 | 目标槽位 | dload 数据 | dstore 数据 |
| --- | --- | --- | --- |
| Stage 1 | `p0/p1/p2/p4` | 按 BConv 规则加载 `P -> Q` 数据和常量 | Q 基 correction |
| Stage 2 开始 | `p4` | 完整 `Q|P` 模表 | - |
| Stage 2，每个 `q_i` | `p0` | 当前 Q limb | - |
| Stage 2，每个 `q_i` | `p1` | Stage 1 correction limb | - |
| Stage 2，每个 `q_i` | `p2` | `P^-1 mod q_i` | - |
| Stage 2，每个 `q_i` | `p0` | - | `(q-correction)*P^-1 mod q_i` |

### C.3 NTT、INTT 与方案 Encode

NTT/INTT body 假定数据对象和活动模上下文已由外层准备。独立用例使用 `p0` 作为
数据、`p1` 作为 twiddle；复合算子使用 `p0` 和 `p3`。

| 顺序 | NTT dload | INTT dload | 使用后动作 |
| --- | --- | --- | --- |
| 1 | `pre_twist=psi^i` | stage 0 twiddle | `pmul` / `pintt` 后 `pfree twiddle` |
| 2..logN | 当前 stage twiddle | 后续每个 stage twiddle | 每 stage 后 `pfree twiddle` |
| 最后 | - | `post_untwist_scale=N^-1*psi^-i` | `pmul` 后 `pfree twiddle` |

每个 stage 都重新执行一次 twiddle `dload`，不会由硬件从上一 stage 自动更新。
每份 stage 表固定包含 `N/2` 个 `uint32`。数据对象 `p0` 跨 stage 保持同一逻辑
OBJ_ID，但控制器可按 out-of-place 协议提交新的物理 base。

CKKS Encode 的 host 顺序是：generator-3 槽位映射、填充共轭半区、复数逆嵌入、
乘 scale 并舍入为 `int64`、按每个 `q_i` 转为 canonical residue。BGV coefficient
Encode 将 centered signed 值映射到 `mod t`；BatchEncode 把两行 `N/2` 槽写入
generator-3 根次序，以最小 primitive `2N` 次单位根执行模 `t` 逆负循环 NTT，
再将系数 canonical lift 到 Q。

三种方案交给 HPU 的逻辑输入都是 `[num_q,N]` 系数域 limbs。指令顺序为：加载
`p4=Q table`；对每个 `q_i` 执行 `pmodld i`、`dload p0=plaintext_coeff_q[i]`、
加载 `p3` pre-twist/stage twiddle 并完成 NTT，最后
`dstore p0=plaintext_ntt_q[i],rel=1`。Decode 不生成 HPU 指令。

### C.4 PMULT 与 CMULT

`generate_hpu_mm_body_asm` 本身不包含 DMA，只对调用方已经置为 live 的对象执行
`pmul`；独立 MM wrapper 才负责加载模表和输入。PMULT/CMULT 在其上定义如下顺序。

PMULT 对每个 `q_i` 的 DMA 顺序固定为：

```text
dload p4 = Q mod table                    # 整个算子只加载一次
pmodld i
dload p0 = ct0[i]
dload p1 = plaintext[i]
pmul p2,p0,p1
dstore p2 = out0[i], rel=1
dload p0 = ct1[i]                         # p1 仍保持 live
pmul p2,p0,p1
dstore p2 = out1[i], rel=1
```

plaintext `p1` 在两次乘法之间不能被 runtime 替换，第二次乘法后才 `pfree p1`。

CMULT 输入必须已经处于 NTT/evaluation domain。对每个 `q_i`，DLoad 顺序为：

| 输出 | 依次加载到 `p0/p1` | 计算与写回 |
| --- | --- | --- |
| `t0` | `a0,b0` | `p2=a0*b0`，随后 dstore `t0` |
| `t1` | `a0,b1`，再加载 `a1,b0` | 先 `pmul p2`，再 `pmac p2`，随后 dstore `t1` |
| `t2` | `a1,b1` | `p2=a1*b1`，随后 dstore `t2` |

### C.5 KeySwitch、Relinearization 与完整乘法

KeySwitch 接口语义是
`KeySwitch(base,switching_component,evk)->(base+ks0,ks1)`。对每个 digit 执行：

| 步骤 | dload 绑定 | dstore 结果 |
| --- | --- | --- |
| 1. ModUp | 当前 `switching_component` digit、BConv 常量、`p4=Q|P table` | 完整 QP digit |
| 2. NTT | `p0=QP digit limb,p3=pre/stage twiddle` | NTT 域 QP digit |
| 3. EVK 乘加 | `p0=digit NTT,p1=evk[d][v][basis]`；非首 digit 另加载 `p2=previous accumulator` | `p2=accumulator[v][basis]` |
| 4. INTT | `p0=accumulator,p3=stage/post twiddle,p4=Q|P table` | 系数域 QP accumulator |
| 5. ModDown | 两个 accumulator 分别按 C.2 执行 | Q 基 `ks0/ks1` |
| 6. 合并 base | `p0=ks0,p1=base,p4=Q table` | `p2=base+ks0` |

Relinearization 把 `t0` 绑定为 base、`t2` 绑定为 switching component、`rlk` 绑定为
EVK。KeySwitch 输出第一分量后，对每个 `q_i` 再加载 `p0=t1`、`p1=ks1`，以
`p2=t1+ks1` 写回第二分量。

完整 CiphertextMultiply 的外存阶段顺序是：

```text
ctA[0],ctA[1] coefficient/Q -> NTT
ctB[0],ctB[1] coefficient/Q -> NTT
CMULT -> t0,t1,t2 NTT/Q
t0,t1,t2 -> INTT -> coefficient/Q
KeySwitch(base=t0,switching=t2,evk=rlk)
merge t1+ks1
dstore ciphertext_out_q[0], ciphertext_out_q[1]
```

Auto 的 HPU 侧绑定与 KeySwitch 相同；差异是 host 先对两个输入分量执行负循环
`X->X^3`，随后以旋转后的 `c0` 为 base、旋转后的 `c1` 为 switching component，
EVK 使用 Galois key。

### C.6 CKKS 方案算子

CKKS Rescale 输入为 `[component,Q,coefficient]`。对每个 component：

| 阶段 | dload 绑定 | dstore 结果 |
| --- | --- | --- |
| 舍入预处理 | `p4=Q table`；每个 `q_i` 加载 `p0=input_q[component][i]`、`p1=floor(q_last/2) mod q_i` | `p0=rounded_numerator[i]` |
| 单源 BConv | source 为 rounded `q_last` limb；加载值为 1 的 `qhat_inv`/target residues | Q' correction |
| 除以 `q_last` | `p0=rounded Q' limb,p1=correction,p2=q_last^-1 mod q_i` | `expected_qprime[component][i]` |

最终计算为：

```text
((x + floor(q_last/2)) - BConv_q_last(x + floor(q_last/2)))
    * q_last^-1 mod q_i
```

CKKS CiphertextMultiply 先完整执行 C.5 的公共乘法，再把两个 Q 分量按本节顺序
Rescale。只有最外层发出 `psync`；scale 和 level 不通过 DMA 进入 HPU，由软件更新为
`scale_out=scale_a*scale_b/q_last`、`level_out=level_in-1`。

### C.7 BGV 方案算子

BGV Multiply 的 DMA 次序与公共 CiphertextMultiply 相同，但模表镜像顺序固定为
`Q|P|t`。`t` 不参与乘法指令；软件在成功后更新
`factor_out=factor_a*factor_b mod t`。

BGV ModSwitch 对每个 component 依次执行：

| 阶段 | dload 绑定 | dstore 结果 |
| --- | --- | --- |
| `q_last -> t` | 单源 BConv：`c_last`、`bconv_qhat_inv`、`bconv_qhat_target_t`、`p4=Q|P|t table` | `c_last_mod_t` |
| 计算 `u` | `p0=zero,p1=c_last_mod_t,p3=q_last^-1 mod t` | `p0=u_mod_t` |
| `q_last -> Q'` | 单源 BConv：`c_last` 和面向 Q' 的 target constants | `c_last_mod_qprime` |
| `t -> Q'` | 单源 BConv：`u_mod_t` 和面向 Q' 的 target constants | `u_mod_qprime` |
| 最终校正 | `p0=c_i,p1=c_last_mod_q_i,p2=u_mod_q_i,p3=q_last mod q_i`；运算后再加载 `p3=q_last^-1 mod q_i` | `p0=c_i'` |

最终校正执行：

```text
p2 = p2 * p3
p1 = p1 + p2
p0 = p0 - p1
p0 = p0 * q_last^-1
```

对应 `c_i'=(c_i-c_last-q_last*u)*q_last^-1 mod q_i`。软件同时更新
`factor_out=factor_in*q_last^-1 mod t`。

### C.8 BFV 单 kernel 方案算子

`bfv_encode` 的 HPU 边界与 BGV Encode 相同：host 先完成 coefficient/batch
Encode 和 RNS-Q lift，HPU 只执行逐 Q limb NTT，Decode 留在 host。

`bfv_ciphertext_multiply` 的前半段按指令出现顺序绑定四个 Q 输入分量、
`Q->Bsk` FastBConv 常量、Q/Bsk twiddle、`t mod Q/Bsk`、`Q^-1 mod Bsk`、
`B->Q/m_sk` 常量、`B^-1 mod m_sk` 和 `-B mod Q`。输出 shape 固定为
`[3,num_q,N]`。包内 `memory_lifetime.csv` 规定何时可用已死亡输入或常量区域承接
scratch。三分量结果占用的 span 随后直接作为 KeySwitch 输入；后半段从同一 window
加载 Q/Pks twiddle、relinearization key 和 ModUp/ModDown 常量，最终原位写回两个
Q 分量。默认 `N=4096,Q=4,Pks=3,B=6` 的统一 window 为 30913 line，完整 DMA
顺序和地址只由同一目录中的 `dma_plan.csv` 与 `hardware/line_map.csv` 规定。

`bfv_modswitch` 接收单 kernel 的二分量 Q 密文，先加 `floor(q_last/2)`，再把
`q_last` 当单元素 P 基复用 ModDown；输出为 `[2,num_q-1,N]`。其数学 golden 与
`direct_rounded_divide_last` 逐 limb 比较，随后执行 BFV scale-and-round Decrypt
和 BatchDecode。

### C.9 物理 span 与数据文件

本附录定义每条 DMA 的逻辑数据身份和先后顺序，不硬编码外存地址。生成包中的文件
共同构成最终绑定契约：

| 文件 | 权威内容 |
| --- | --- |
| `dma_plan.csv` | 算法阶段、逻辑对象、域和基 |
| `artifact_manifest.csv` | `uint64` 数学 golden 的 path、shape 和 checksum |
| `hardware/hardware_manifest.csv` | 独立 `uint32` 硬件镜像及 checksum |
| `hardware/line_map.csv` | 每个对象的 byte address、line offset/count 和 padding |
| `hardware/mod_ctx_map.csv` | Q/P/t 的 MOD_ID 与 Bank 5 记录位置 |
| `hardware/twiddle_map.csv` | phase/stage twiddle 的物理位置与 line 数 |

runtime 必须按照生成 ASM 中 custom1 的出现顺序消费 relocation/span 记录。不能只凭
槽位号推断数据，因为同一个 `p0` 会在不同阶段依次表示输入 limb、scratch 和输出。
