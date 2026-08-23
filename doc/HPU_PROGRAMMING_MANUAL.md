# HPU 软件编程手册

版本：0.3
适用实现：`inline-asm` 当前软件实现
日期：2026-07-24

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

硬件镜像为每个 stage 固定生成 `N/2` 个 little-endian `uint32`
twiddle，即 `N/128` 条 256B line。当前物理顺序是 group-major DIT：
对每个长度为 `length=2^(stage+1)` 的 butterfly group，依次写出
`step^j mod q`（`j=0..length/2-1`），再写下一个 group；因此不同 group
需要的相同 twiddle 也会在镜像中重复出现。当前 `N=4096` 时，每个 stage
均为 2048 words、32 line，而不是仅保存一份可复用的唯一幂表。

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

软件 reference 的数学行为是 radix-2 DIT 逆循环 NTT，随后逐系数乘
`N^-1 * psi^-i mod q`，同时完成归一化和负循环 inverse twist。硬件数据包
为每个 RNS 模数生成逐 stage 的逆 DIT twiddle以及
`post_untwist_scale.u32.bin`；其中第 `i` 项为 `N^-1 * psi^-i mod q`。
最终 `pintt` 后，生成器显式执行一次 `dload + pmul + pfree` 消费该 post
factor，不再假设 PE 或最后一个 stage 隐式融合它。

软件 reference 中的 bit-reversal 循环是其 radix-2 DIT 实现细节，不对应一条
独立 HPU 指令。硬件通过 stream_ctrl 的 stage 地址生成与 PE lane transpose
形成各 stage 配对，不再声明“stage 0 前隐式执行一次全多项式 shuffle”。
runtime 需按 `twiddle_map.csv` 分别绑定 pre-twist、各 stage twiddle 和
post factor 的 line offset/count。

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
3. RTL 是否按已生成的 group-major 次序消费 twiddle，并按 out-of-place 协议提交各 stage 新 base。
4. cache maintenance、中断和 fault 的 runtime 实现。

上述列表是尚未实现的 runtime/RTL 行为，不是这些ABI 的备选解释。
