# HPU 最新文档符合性审计

> 2026-08-21 注：本文是修复前审计，其中 `x0/x0` DMA 结论已失效。
> 当前生成入口固定使用 `x10/x11`，并由类型化 span 与 Nexus-AM resolved
> manifest 绑定具体 line offset/count。DLOAD 使用 `rs2` 的 count；DSTORE
> 的当前 RTL 实际使用 `OBJ.len`，span count 仅用于软件一致性和边界检查。

审计日期：2026-08-18

## 1. 审计基线

本审计以以下飞书文档为依据：

1. [HPU 控制逻辑设计文档](https://icnj64z5e8zz.feishu.cn/wiki/KOlSwfEEtiMuqvkTppPcyJElnyf)，v0.4，2026-05-31。作为当前 26-bit 命令、对象状态、`pmodld`、`pfree` 和 `psync` 的编码/控制基线。
2. [HPU 集成与编程手册](https://icnj64z5e8zz.feishu.cn/wiki/NZEgwsvshiQ6Twkrxvtck3UGnXg)，V0.2，2026-07-10。用于跨模块接口、CSR、SRAM、DMA 和软件流程；对 Bank 深度、固定地址和物理 NTT 策略等后更新字段优先于 5 月控制文档。
3. [RISC-V核内接口设计](https://icnj64z5e8zz.feishu.cn/wiki/QE8MwYGIciNwoYkjomCcZbnmnOh)。核内 custom2/custom1 发射路径基线；其中 custom1 章节与集成手册存在冲突，见第 4 节。
4. [HPU_PE_反串讲](https://icnj64z5e8zz.feishu.cn/wiki/T7pTwV4eiiJbXHkTkrAcgDzxn0g)，v0.1，2026-06-22。PE 位宽、Barrett、twiddle 和 NTT/INTT 数据通路验证基线。
5. [HPU](https://icnj64z5e8zz.feishu.cn/wiki/MZkHwbivGiOs7ekMGb0cMSk5nTY)。知识库根文档，包含新旧章节，只用于定位历史约定，不作为单一冻结版本。
6. [HPU 通过 DMA 访问主存的实现方案讨论稿](https://icnj64z5e8zz.feishu.cn/wiki/KOfhwRW4Oi33f6kPEXWcJJwDnSS)。该文档明确是讨论稿；当它与集成手册冲突时，以集成手册为准。
7. 硬件负责人于 2026-08-18 确认：DMA 一致性由硬件维护，`psync` 不作为 DMA 等待屏障，只在整个程序完成后用于通知 CPU。该确认覆盖此前文档中关于软件插入 DMA 屏障的推断。
8. 硬件同学修订的本地《HPU 编程手册》`HPU_PROGRAMMING_MANUAL (1).md`，
   2026-09-07 作为 64 项软件 MOD_ID 上限和 DSTORE `OBJ.len`/总是释放语义的
   基线。
9. 硬件组 2026-09-10 提供的 `third_party/ntt_run_data`：包含 PNTT stage 0、PINTT stage
   0/1 的 512-word RTL dump，以及设计师完整 N=512 batch/lane、P/P^-1 和
   lazy-scale golden。该执行证据更新并覆盖第 8 项中的 group-major NTT 口径。

## 2. 已完成修复

### A0. `pfree` / `psync` OPC 反置

- 文档来源：《HPU 集成与编程手册》3.1.3。
- 文档约定：`PSYNC=0111`，`PFREE=1000`。
- 原项目：`PFREE=0111`，`PSYNC=1000`。
- 当前状态：已修复编码器、编码单测、delivery 检查和项目指令手册。
- 当前 RV 编码示例：`pfree p5 = 0x8140005B`，`psync = 0x7000005B`。

### A1. custom2 与 26-bit precode 字段契约（已修复，2026-07-23）

冻结映射为：

```text
cmd26[25]   = command_kind (0=custom2 compute, 1=custom1 DMA)
cmd26[24:0] = control payload
```

当前实现已经：

1. STG 在 `[27:25]`、`[24:22]` 分别编码 `PDST`、`PSRC1`，在 `[16:14]`
   编码 3-bit `PTWID`；stage、mode、flag 分别使用 `[13:10]`、`[9:8]`、`[7]`。
2. 将 AR3 立即数模式移动到 2-bit MODE 的 `[9:8]`。
3. 增加 `precode_command26()`，所有可编码算子同时输出 `.inst32` 和 `.cmd26`。
4. custom1 的原始 32-bit payload 已按 `reserved/OBJ_ID/RS2/RS1/TYPE_OR_REL/DIR/reserved/flag` 控制字段排布，precode 直接使用 `cmd26={1'b1,inst[31:7]}`；`cmd26[20:18]=OBJ_ID`、`cmd26[17:13]=RS2`、`cmd26[12:8]=RS1`。
5. 生成 `expected_cmd26.csv`，逐条记录源 payload、控制 payload、custom kind 和最终命令。

## 3. 项目与最新文档的差异

### A2. `pmodld` 旧“模上下文对象”语义（已修复，2026-07-21）

文档来源：《HPU 控制逻辑设计文档》“PMODLD 指令详细位段”和 `hpu_cfg_state_regs` 章节；《HPU 集成与编程手册》3.1.3、3.5.4、3.6.1。

当前实现已经完成以下迁移：

1. 汇编语法改为 `pmodld mod_id`，范围 0..255；旧 `psrc/idx1/cfg15` 语法作为负例拒绝。
2. 原始 32-bit 指令的 `MOD_ID` 编码在 `[21:14]`，经过 custom2 precode 后对应 `cmd26[14:7]`。
3. 所有算子生成器均改为 `pmodld(i)`，不再把 `p4` 编入 `pmodld`。
4. `MOD_ID` 编码仍为 8-bit；Bank 5 为 32 line、物理可放 512 个 context，但当前应用软件 ABI 要求 `MOD_ID[7:6]=0`，生成器最多使用 64 个。对象槽位仍独立保持 8 个。

`dload type=2, flag[0]=1` 现在显式请求 allocator 将模表对象分配到 small Bank 5。模表对象是具有 `ALLOC/V/busy/base/len` 的真实逻辑对象，不再描述为“仅 DMA 句柄”。DMA 与首条 `pmodld` 的一致性由硬件维护，生成器不再在两者之间插入 `psync`。`MOD_TABLE_BASE_LINE` 已按最新集成手册冻结为 `0x1400`。

### A3. `pfree` 对象字段和 `psync` 载荷（已修复，2026-08-18 更新语义）

`pfree` 对象位于原始 custom2 `PSRC/OBJ_ID=[24:22]`；其他载荷位为 0。`psync` 语法为无操作数、所有载荷位为 0；根据 2026-08-18 硬件负责人确认，它只作为完整程序最后一条指令通知 CPU，不再作为统一 inflight 或 DMA 屏障使用。

### A4. DMA line sideband 与 relocation（已修复，2026-08-21）

文档来源：硬件修订稿第 7.1、7.2 节。DLOAD 的 `rs1/rs2` sideband 给出
256B line offset 和非零 line count；DSTORE 的 offset 来自 `rs1`，传输长度
来自对象表 `OBJ.len`，当前 RTL 忽略 `rs2` 的长度值。

当前生成器为 custom1 固定编码 `x10/x11`。生成的可执行 C 入口在每条 DMA 前从类型化
`hpu_dma_span_t[]` 装载实际 offset/count；DSTORE 发射前额外检查 span count 与
软件跟踪的 `OBJ.len` 相等。生命周期分析按当前 RTL 在任意 `rel` 值的 DSTORE
成功后清除对象。交付门禁拒绝 `x0/x0`、零 span、未解析记录和 HPU_MEM 越界。

### A5. stage twiddle 物理布局与硬件执行模型不一致（已按 RTL UT 重修，2026-09-10）

原实现为 stage `s` 只生成 `2^s` 个唯一 twiddle，并声明由 butterfly group
复用，不符合 PE 的物理搬运数量。

文档来源：《HPU_PE_反串讲》13.2、13.3：每个 stage 的物理 twiddle 对象为 `N/2` 个 32-bit 元素；以 `N=65536` 为例正好是 512 line。每个 stage 前独立 DLoad。

2026-09-10 的 RTL UT 数据证明实际执行使用 128-register loader 和 64 个 BF lane：
PNTT 每 batch 蝶形后执行 P，PINTT 每 batch 蝶形前执行 P^-1。每级仍消费
`N/2` 个 twiddle，但顺序是 batch-major/lane-major，不是 group-major；PINTT
按正向 stage 的逆序执行，并使用 lazy-scale `w_bf=alpha/beta`。

当前生成器已采用 bit-reversed 系数物理镜像、P-network NTT 物理镜像和对应
pre/post factor。独立 C++ 回归逐字命中三个 RTL stage 的全部 512 words，逐级
匹配完整 N=512 Python golden，并以 schoolbook negacyclic convolution 验证 FHE
乘法语义，避免只通过 round-trip 的同源错误。

### A6. HPU_MEM CSR 数字地址（已修复，2026-07-24）

原生成文件写 `RTL_CONFIRM_REQUIRED`，使用 `*_SHADOW`、合并的
`SIZE_LINES_SHADOW` 和旧状态寄存器名称。

文档来源：《HPU 集成与编程手册》5.2.3 表 5.6。

最新映射为：

| offset | register |
| --- | --- |
| `0x00` | `HPU_MEM_BASE_LO` |
| `0x04` | `HPU_MEM_BASE_HI` |
| `0x08` | `HPU_MEM_SIZE_LINES_LO` |
| `0x0C` | `HPU_MEM_SIZE_LINES_HI` |
| `0x10` | `HPU_MEM_COMMIT` |
| `0x14` | `HPU_STATUS` |
| `0x18` | `HPU_FAULT_STATUS` |

当前 `hpu_mem_config.json` 已输出上述数字 offset、访问属性、字段定义和具体值，
size 已拆为 low/high；delivery 门禁会拒绝 `RTL_CONFIRM_REQUIRED`，项目文档也已
删除“CSR 数字偏移待确认”。

### A7. 模上下文 q32/mu48 ABI（已修复，2026-07-24）

原镜像虽然字节兼容，但元数据把记录描述为 `mu64+reserved32`，且只检查
`modulus > 1`。

文档来源：《HPU 集成与编程手册》3.1.2、3.5.4；《HPU_PE_反串讲》6.3。PE 有效 `mu` 为 48-bit，且模数必须满足 `65537 <= q <= 2^32-1`。

当前生成器和 ABI 已统一为从低位到高位
`{q[31:0], mu[47:0], reserved[47:0]}`，显式将 `word2[31:16]` 和 `word3`
清零，并断言 `65537 <= q <= 2^32-1`、`mu >> 48 == 0`。delivery 门禁检查
q 范围、`mu_bits=48` 和 `reserved_bits=48`。

### A8. 参数检查没有覆盖本地 SRAM/PE 能力（部分修复，2026-08-18）

当前共享目标约束已定义 64 word/line、普通 Bank 1024 line，并在 NTT、INTT、
KeySwitch、Auto 和完整密文乘法入口统一检查 `ceil(N/64) <= 1024`。因此 radix-2
多项式上限被冻结为 `N <= 65536`；reference 对相同条件执行编译期断言。
context 数已按最新应用软件 ABI 限制为 64，虽然机器码仍保留 8-bit 字段。

文档来源：《HPU 集成与编程手册》3.1.2、3.4；《HPU 控制逻辑设计文档》allocator 章节。

外部 HPU_MEM 的 scratch line layout 和可配置 window 越界检查已经由软件交付门禁
覆盖；当前 `hpu_mem_max_lines=65536`，BFV 单 kernel 实际使用 30913 line。
剩余工作是目标 allocator 对 8 个并发对象以及普通
bank/half-bank 峰值驻留的硬件资格验证；这与外部 HPU_MEM span 是否已绑定是
两个问题。对象数与 RNS limb/context 数仍必须分开建模。

### A9. PE golden 是数学结果，不是位精确硬件 reference（P1）

本地证据：`test/reference/main.cpp::mul_mod` 使用 128-bit 乘法后直接 `% modulus`。

文档来源：《HPU_PE_反串讲》6.3 和 14 章。该文档要求 reference 按 48-bit mu、33-bit `q_hat`、33-bit 低位乘法和一次修正建模，并覆盖 Barrett 修正分支。

修改建议：保留现有数学 golden，再增加独立 PE bit-exact model 和 corner vectors。两者结果应相同，但 bit-exact model 用于定位截断、流水线和边界实现错误。

### A10. runtime non-coherent 与故障协议（软件侧已修复，2026-08-21）

Nexus-AM IT runtime 已实现 HPU_MEM window 配置、提交前 cache clean、读回前
invalidate、`HPU_STATUS/FAULT_STATUS` 检查、W1C fault 和完成 IRQ 等待；
生成算子还会在执行前 poison 输出与 scratch，并在执行后逐字比较 golden 和检查
尾部 guard。此前“只有指令、镜像和配置 JSON”的结论已失效。

文档来源：《HPU 集成与编程手册》5.2、5.2.8、9.1。

剩余工作：上述协议仍需在目标 RTL/板级执行中取得 FAULT/IRQ、cache 一致性和外部
monitor 证据。Host `PASS_PROBE` 自检不执行 HPU 算术，不能替代该资格证据。

### A11. NTT/INTT 物理 in-place/out-of-place（已冻结，2026-07-24）

本地证据：项目手册和 `src/util/ntt.cpp` 声明 NTT/INTT 原地执行。

文档来源：较新的《HPU 集成与编程手册》3.4.6 明确 allocator 为
NTT/INTT out-of-place 提供 base 管理；5 月《HPU 控制逻辑设计文档》也描述
完成后提交新 base。较旧《HPU_PE_反串讲》13.6 仅记录当时尚未确认的疑问。

当前软件 ABI 冻结为三对象 `PDST/PSRC1/PTWID`。每 stage 的 `PDST` 必须是
空闲对象，生成器在 data/scratch 间 ping-pong，完成后显式释放旧数据源和
twiddle；最终结果保证回到调用者指定的数据对象。PE 文档中的旧疑问不再作为
备选 ABI。

### A12. Bank 5 深度与模表基址（已修复，2026-07-24）

旧项目和 5 月《HPU 控制逻辑设计文档》allocator 章节使用
`SMALL_BANK_LINES=8`，因此软件将 context 上限错误收紧为 128。

较新的《HPU 集成与编程手册》3.1.2、3.4.1、3.4.2.1 和 3.4.3.4，以及
2026-07-15 更新的《SRAM逻辑设计》均给出：Bank 0-4 各 1024 line，Bank 5
为 32 line，固定有效范围 `0x1400..0x141F`，默认保留为模上下文表。

当前目标常量和 `abi.json` 已改为 32-line Bank 5、
`MOD_TABLE_BASE_LINE=0x1400`、物理容量 512 context。PMODLD 保留 8-bit
机器码能力，但应用软件只使用 `MOD_ID=0..63`，对应前 4 line。

### A13. negacyclic pre/post factor 被错误假设为硬件隐式行为（已修复，2026-07-24）

原 `abi.json` 声称 stage 0 前由内部 shuffle 完成 bit reversal，编程手册又要求
最后一个 PINTT stage 隐式融合 `N^-1 * psi^-i`，但生成的 pre/post 镜像没有
任何指令消费。

文档来源：《HPU 集成与编程手册》3.5.2 将 PNTT/PINTT 定义为使用 twiddle
的标准 butterfly，3.5.3 只定义 stage 配对的 lane transpose；没有定义
negacyclic twist 或 INTT 归一化融合。《HPU_PE_反串讲》13.2 也要求一条指令
只执行一个 stage。

当前 NTT 在 stage 0 前显式生成 `dload pre_twist -> pmul -> pfree`；INTT 在
最终 stage 后显式生成 `dload post_untwist_scale -> pmul -> pfree`。按照新版
A5，物理位置 `p` 使用 `pre_twist=psi^bit_reverse(p)` 和
`post=N^-1*psi^-bit_reverse(p)`；stage 内的 P/P^-1 由硬件执行模型定义。

### A14. 未定义的 `dload load_type=3`（已修复，2026-08-18）

最新飞书文档没有为 `load_type=3` 给出可执行语义。项目已删除原
`DataType::shuffle_cfg`，将 dload 正向范围收紧为 0..2，从 RV 冒烟流移除
type 3，并将其加入 parser/encoder 和 delivery 负例。原始 TYPE2 位段宽度保持
2 bit；值 3 作为 reserved 编码处理。

## 4. 飞书文档历史矛盾与当前冻结结果

下表记录来源之间的矛盾及按“新文档优先”或项目负责人决定采用的口径：

| ID | 矛盾 | 来源文档 | 建议冻结口径 |
| --- | --- | --- | --- |
| C1 | `psync` 是否等待 custom1/DMA | 旧版《HPU 控制逻辑设计文档》曾引出统一 inflight 屏障解释；硬件负责人于 2026-08-18 进一步确认 DMA 一致性由硬件维护 | `psync` 仅在完整程序末尾通知 CPU；模表 dload 后不插入 `psync`，内部算子阶段也不使用它 |
| C2 | custom1 是 rs1/rs2 line sideband，还是 VA 经 DTLB 后形成 `{paddr,len,dir,flags}` descriptor | 集成手册与较旧《RISC-V核内接口设计》custom1 HpuUnit 章节相反；最新修订稿进一步区分 DLOAD/DSTORE | DLOAD 使用 `rs1=offset,rs2=count`；DSTORE 使用 `rs1=offset,OBJ.len=count`，当前 RTL 忽略其 `rs2` 值 |
| C3 | 模上下文记录是 `mu64+reserved32` 还是 `mu48+reserved48` | 较旧《HPU 控制逻辑设计文档》写 `{reserved[31:0],mu[63:0],q[31:0]}`；较新的《HPU 集成与编程手册》3.5.4 写 `{reserved[47:0],mu[47:0],q[31:0]}`，PE 端口也是 48-bit mu | 以较新的集成手册为准，项目已统一为 `q32+mu48+reserved48` |
| C4 | NTT/INTT 物理 in-place 或 out-of-place | 较新的《HPU 集成与编程手册》3.4.6 与 2026-09-10 RTL UT 均为 out-of-place | 每 stage 显式编码 `PDST/PSRC1/PTWID`，data/scratch 对象 ping-pong |
| C5 | 32-bit 原始指令与 26-bit 内部命令映射 | 项目负责人根据硬件组最新说明确认两类 custom 指令均原样保留 `inst[31:7]`，并于 2026-09-07 补充最新 DMA 位域 | `cmd26={custom_kind,inst[31:7]}`；custom1 为 `{1,4'b0,OBJ_ID,RS2,RS1,TYPE_OR_REL,DIR,4'b0,flag}` |
| C6 | NTT 使用 P/P^-1 network 物理排列或 group-major DIT 自然排列 | 2026-09-10 RTL dump 与设计师模型晚于 2026-09-07 修订稿，且给出逐字执行证据 | 使用 bit-reversed 系数镜像、P-network NTT 镜像和 batch/lane twiddle；PNTT 后 P，PINTT 前 P^-1 |
| C7 | 8-bit `MOD_ID` 是否允许软件使用 256 项 | 修订稿第 6.1 节增加应用 ABI 上限 | 编码器仍接受 0..255；生成器只使用 0..63，`MOD_ID[7:6]=0` |
| C8 | DSTORE `rel=0` 是否保留对象 | 修订稿第 7.2 节记录当前 RTL 无条件清 V/ALLOC/busy | `rel` 位仍编码，但静态和 runtime 生命周期对 0/1 都视为释放 |

## 5. 建议实施顺序

1. C1-C5 均已冻结，并写入 machine-readable target ABI；持续回归其 delivery 检查。
2. 持续用 RV smoke 回归 32/26-bit 编码、DMA relocation、CSR 和生命周期协议。
3. 补齐 A8 的片上对象峰值驻留资格验证和 A9 的 PE bit-exact corner UT。
4. 将指令、HPU_MEM image、CSR sequence 和 checkpoints 一起接入 RTL/FPGA；取得外部证据后才能把 `HARDWARE_EXECUTION` 改为 `PASS`。
