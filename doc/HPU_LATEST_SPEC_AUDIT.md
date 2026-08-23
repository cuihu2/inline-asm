# HPU 最新文档符合性审计

> 2026-08-21 注：本文是修复前审计，其中 `x0/x0` DMA 结论已失效。
> 当前生成入口固定使用 `x10/x11`，并由类型化 span 与 Nexus-AM resolved
> manifest 绑定具体 line offset/count；DLOAD 和 DSTORE 均从 span 装载非零
> line count，不再使用旧的 DSTORE `x11=0` 约定。

审计日期：2026-08-18

## 1. 审计基线

本审计以以下飞书文档为依据：

1. [HPU 控制逻辑设计文档](https://icnj64z5e8zz.feishu.cn/wiki/KOlSwfEEtiMuqvkTppPcyJElnyf)，v0.4，2026-05-31。作为当前 26-bit 命令、对象状态、`pmodld`、`pfree` 和 `psync` 的编码/控制基线。
2. [HPU 集成与编程手册](https://icnj64z5e8zz.feishu.cn/wiki/NZEgwsvshiQ6Twkrxvtck3UGnXg)，V0.2，2026-07-10。用于跨模块接口、CSR、SRAM、DMA 和软件流程；对 Bank 深度、固定地址和物理 NTT 策略等后更新字段优先于 5 月控制文档。
3. [RISC-V核内接口设计](https://icnj64z5e8zz.feishu.cn/wiki/QE8MwYGIciNwoYkjomCcZbnmnOh)。核内 custom0/custom1 发射路径基线；其中 custom1 章节与集成手册存在冲突，见第 4 节。
4. [HPU_PE_反串讲](https://icnj64z5e8zz.feishu.cn/wiki/T7pTwV4eiiJbXHkTkrAcgDzxn0g)，v0.1，2026-06-22。PE 位宽、Barrett、twiddle 和 NTT/INTT 数据通路验证基线。
5. [HPU](https://icnj64z5e8zz.feishu.cn/wiki/MZkHwbivGiOs7ekMGb0cMSk5nTY)。知识库根文档，包含新旧章节，只用于定位历史约定，不作为单一冻结版本。
6. [HPU 通过 DMA 访问主存的实现方案讨论稿](https://icnj64z5e8zz.feishu.cn/wiki/KOfhwRW4Oi33f6kPEXWcJJwDnSS)。该文档明确是讨论稿；当它与集成手册冲突时，以集成手册为准。
7. 硬件负责人于 2026-08-18 确认：DMA 一致性由硬件维护，`psync` 不作为 DMA 等待屏障，只在整个程序完成后用于通知 CPU。该确认覆盖此前文档中关于软件插入 DMA 屏障的推断。

## 2. 已完成修复

### A0. `pfree` / `psync` OPC 反置

- 文档来源：《HPU 集成与编程手册》3.1.3。
- 文档约定：`PSYNC=0111`，`PFREE=1000`。
- 原项目：`PFREE=0111`，`PSYNC=1000`。
- 当前状态：已修复编码器、编码单测、delivery 检查和项目指令手册。
- 当前 RV 编码示例：`pfree p5 = 0x8140000B`，`psync = 0x7000000B`。

### A1. custom0 与 26-bit precode 字段契约（已修复，2026-07-23）

冻结映射为：

```text
cmd26[25]   = custom_kind (0=custom0, 1=custom1)
cmd26[24:0] = control payload
```

当前实现已经：

1. 将 STG 的 stage 移到原始指令 `[13:10]`，mode/flag 分别使用 `[9:8]`、`[7]`。
2. 将 AR3 立即数模式移动到 2-bit MODE 的 `[9:8]`。
3. 增加 `precode_command26()`，所有可编码算子同时输出 `.inst32` 和 `.cmd26`。
4. custom1 precode 将原始指令的 `flag/OBJ_ID/TYPE/DIR` 重排到控制 payload，`rs1/rs2` 作为 line offset/count sideband。
5. 生成 `expected_cmd26.csv`，逐条记录源 payload、控制 payload、custom kind 和最终命令。

## 3. 项目与最新文档的差异

### A2. `pmodld` 旧“模上下文对象”语义（已修复，2026-07-21）

文档来源：《HPU 控制逻辑设计文档》“PMODLD 指令详细位段”和 `hpu_cfg_state_regs` 章节；《HPU 集成与编程手册》3.1.3、3.5.4、3.6.1。

当前实现已经完成以下迁移：

1. 汇编语法改为 `pmodld mod_id`，范围 0..255；旧 `psrc/idx1/cfg15` 语法作为负例拒绝。
2. 原始 32-bit 指令的 `MOD_ID` 编码在 `[21:14]`，经过 custom0 precode 后对应 `cmd26[14:7]`。
3. 所有算子生成器均改为 `pmodld(i)`，不再把 `p4` 编入 `pmodld`。
4. `MOD_ID` 编码仍为 8-bit；Bank 5 为 32 line、物理可放 512 个 context，但生成器受编码限制最多生成 256 个。对象槽位仍独立保持 8 个。

`dload type=2, flag[0]=1` 现在显式请求 allocator 将模表对象分配到 small Bank 5。模表对象是具有 `ALLOC/V/busy/base/len` 的真实逻辑对象，不再描述为“仅 DMA 句柄”。DMA 与首条 `pmodld` 的一致性由硬件维护，生成器不再在两者之间插入 `psync`。`MOD_TABLE_BASE_LINE` 已按最新集成手册冻结为 `0x1400`。

### A3. `pfree` 对象字段和 `psync` 载荷（已修复，2026-08-18 更新语义）

`pfree` 对象已移动到原始 custom0 `PSRC/OBJ_ID=[24:22]`；其他载荷位为 0。`psync` 语法为无操作数、所有载荷位为 0；根据 2026-08-18 硬件负责人确认，它只作为完整程序最后一条指令通知 CPU，不再作为统一 inflight 或 DMA 屏障使用。

### A4. 当前 `.inst32` 不是硬件可执行 DMA 流（P0）

本地证据：`src/operator/ciphertext_multiply.cpp` 和各算子生成器全部输出 `dload/dstore x0, x0`；`output/ciphertext_multiply.asm` 因而没有真实 line offset/count。

文档来源：《HPU 集成与编程手册》3.3、5.2.2、9.1。`rs1/rs2` sideband 应给出 256B line offset 和非零 line count；长度为 0 或越界会触发 fault。

修改建议：

1. 增加指令流 relocation/scheduling 阶段，读取 `line_map.csv` 并为每条 DMA 指令绑定 offset/count。
2. 输出可直接运行的 host harness：装载寄存器、发射 `.inst32`、等待完成、检查 fault。
3. 将“所有 DMA 使用 x0/x0”改成 delivery 失败条件；仅显式 `--symbolic-dma` 模式允许占位符。

### A5. stage twiddle 物理布局与 PE 文档不一致（已修复，2026-07-24）

原实现为 stage `s` 只生成 `2^s` 个唯一 twiddle，并声明由 butterfly group
复用，不符合 PE 的物理搬运数量。

文档来源：《HPU_PE_反串讲》13.2、13.3：每个 stage 的物理 twiddle 对象为 `N/2` 个 32-bit 元素；以 `N=65536` 为例正好是 512 line。每个 stage 前独立 DLoad。

当前生成器已按 group-major DIT butterfly 顺序展开每个 stage：每个 group
依次写 `step^j`，相同值在不同 group 中物理重复。每个 stage 固定为 `N/2`
个 `uint32`、`N/128` line；默认 `N=4096` 为 2048 words/32 lines。
`twiddle_map.csv` 新增 `group_count` 和 `twiddles_per_group`，delivery 门禁逐一检查
NTT/INTT 的 12 个 stage。negacyclic pre/post factor 已按 A13 显式执行。

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
context 数也已按 8-bit `MOD_ID` 限制为 256。

文档来源：《HPU 集成与编程手册》3.1.2、3.4；《HPU 控制逻辑设计文档》allocator 章节。

外部 HPU_MEM 的 scratch line layout 和 19201-line window 越界检查已经由
Nexus-AM runtime 固化。剩余工作是目标 allocator 对 8 个并发对象以及普通
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

当前软件 ABI 冻结为“同一 logical object id、每 stage 物理 out-of-place、
完成后提交新 base 并释放旧 base”，delivery 门禁检查该 machine-readable
字段。PE 文档中的旧疑问不再作为备选 ABI。

### A12. Bank 5 深度与模表基址（已修复，2026-07-24）

旧项目和 5 月《HPU 控制逻辑设计文档》allocator 章节使用
`SMALL_BANK_LINES=8`，因此软件将 context 上限错误收紧为 128。

较新的《HPU 集成与编程手册》3.1.2、3.4.1、3.4.2.1 和 3.4.3.4，以及
2026-07-15 更新的《SRAM逻辑设计》均给出：Bank 0-4 各 1024 line，Bank 5
为 32 line，固定有效范围 `0x1400..0x141F`，默认保留为模上下文表。

当前目标常量和 `abi.json` 已改为 32-line Bank 5、
`MOD_TABLE_BASE_LINE=0x1400`、物理容量 512 context。由于 PMODLD 的
`MOD_ID` 仍是 8 bit，软件寻址上限取 `min(512, 2^8)=256`，对应前 16 line；
不能因 SRAM 剩余空间而越过指令编码范围。

### A13. negacyclic pre/post factor 被错误假设为硬件隐式行为（已修复，2026-07-24）

原 `abi.json` 声称 stage 0 前由内部 shuffle 完成 bit reversal，编程手册又要求
最后一个 PINTT stage 隐式融合 `N^-1 * psi^-i`，但生成的 pre/post 镜像没有
任何指令消费。

文档来源：《HPU 集成与编程手册》3.5.2 将 PNTT/PINTT 定义为使用 twiddle
的标准 butterfly，3.5.3 只定义 stage 配对的 lane transpose；没有定义
negacyclic twist 或 INTT 归一化融合。《HPU_PE_反串讲》13.2 也要求一条指令
只执行一个 stage。

当前 NTT 在 stage 0 前显式生成 `dload pre_twist -> pmul -> pfree`；INTT 在
最终 stage 后显式生成
`dload post_untwist_scale -> pmul -> pfree`。软件 reference 的 bit-reversal
循环只作为 DIT 数学实现细节；硬件 stage 配对由 stream_ctrl 地址生成和 PE
lane transpose 实现，不再虚构独立隐式 shuffle。

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
| C2 | custom1 是 rs1/rs2 line sideband，还是 VA 经 DTLB 后形成 `{paddr,len,dir,flags}` descriptor | 较新的《HPU 集成与编程手册》5.2.2/9.1 与较旧《RISC-V核内接口设计》custom1 HpuUnit 章节相反 | 以较新的集成手册为准：`GPR[rs1]=line_offset`、`GPR[rs2]=line_count`，单位 256B；旧 DTLB descriptor 方案不再是项目 ABI |
| C3 | 模上下文记录是 `mu64+reserved32` 还是 `mu48+reserved48` | 较旧《HPU 控制逻辑设计文档》写 `{reserved[31:0],mu[63:0],q[31:0]}`；较新的《HPU 集成与编程手册》3.5.4 写 `{reserved[47:0],mu[47:0],q[31:0]}`，PE 端口也是 48-bit mu | 以较新的集成手册为准，项目已统一为 `q32+mu48+reserved48` |
| C4 | NTT/INTT 物理 in-place 或 out-of-place | 较新的《HPU 集成与编程手册》3.4.6 与控制文档均为 out-of-place；较旧《HPU_PE_反串讲》13.6 只是未决记录 | 以较新的集成手册为准：每 stage 物理 out-of-place，完成后向同一 logical object id 提交新 base |
| C5 | 32-bit 原始指令与 26-bit 内部命令映射 | 《HPU 控制逻辑设计文档》v0.4 规定 `cmd[25]=cmd_kind`；《RISC-V核内接口设计》只确认核侧可提取 custom0 的 `inst[31:7]`，其中后续 custom1 descriptor 方案与控制逻辑的统一命令入口不同 | 按项目负责人最新确认，以《HPU 控制逻辑设计文档》为准：kind 位于最高位，custom1 由 precode 重排语义字段并携带独立 sideband |

## 5. 建议实施顺序

1. C1-C5 均已冻结，并写入 machine-readable target ABI；持续回归其 delivery 检查。
2. A1/A2/A3 已完成，持续用 RV smoke 的 32/26-bit 期望表回归。
3. 完成 A4、A10：生成真实 DMA relocation/GPR 装载、CSR runtime 和可运行 host harness；A6 的数字 CSR 表已完成。
4. 继续完成 A8 的峰值驻留/scratch 校验和 A9 的 PE bit-exact UT；N/line 容量校验已完成。
5. 将 `.inst32 + cmd26 + HPU_MEM image + CSR sequence + expected checkpoints` 一起接入 RTL IT；只有该流程通过后，才能把 `HARDWARE_EXECUTION` 从 `CONDITIONAL` 改为 `PASS`。
