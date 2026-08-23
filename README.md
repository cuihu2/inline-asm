# HPU Inline Assembly Codegen

本项目用于为全同态加密在自研 HPU（Homomorphic Processing Unit）硬件上，提供 C++ 内联汇编（Inline Assembly）的生成器。项目基于 HPU 的 3-bit 寻址槽位和流水线执行语义进行抽象，支持从底层通用计算直至高层复杂 FHE 算子的自动代码生成，并可将生成后的 ASM 继续转译为 32 位指令编码文本。

## 1. 项目结构

代码按照功能依赖分层，并分别维护在 `include` 及 `src` 目录下，包含三大类生成模块，以及独立的编码、reference 与测试辅助模块：

### 1) 基础工具层 (`util`)
- **`util/hpu_asm.hpp/cpp`**：基础 HPU 汇编助记符封装和生成接口，遵循《HPU_INSTRUCTION_MANUAL.md》。
- **`util/ntt.hpp/cpp`**：按 stage 推进的基于对象槽位语义的 NTT / INTT 汇编生成。
- **`util/mm.hpp/cpp`**：对象槽位级别的四则运算，特别是逐点向量乘法、乘加积累等（`pmul` / `pmac`）。
- **`util/bconv.hpp/cpp`**：对象槽位上带参数 `q_offset` 支持分组扩展的基础 Basis Conversion 两阶段汇编生成。

### 2) 多项式级操作层 (`poly`)
调用并复用 `util` 层的基础算子，组合出同态相关的复杂多项式算子：
- **`poly/pmult.hpp/cpp`**：明密文相乘 (Plaintext-Ciphertext Multiplication)。
- **`poly/cmult.hpp/cpp`**：密文乘法的张量积阶段，将二元密文 $(a_0,a_1)$ 与 $(b_0,b_1)$ 乘成三元中间结果 $(t_0,t_1,t_2)$。
- **`poly/modup.hpp/cpp`**：模提升 (ModUp) 操作，负责保留当前 Q digit 并通过 BConv 补齐其他 Q/P limbs，最终扩展到完整 $Q \cup P$。
- **`poly/moddown.hpp/cpp`**：模回缩 (ModDown) 操作，负责将中间结果缩放回 $Q$ 基，纠正缩放因子。

### 3) 高级算子层 (`operator`)
拼装多项式级与基础工具算子，完整实现核心同态运算：
- **`operator/keyswitch.hpp/cpp`**：完整密钥切换 (KeySwitch) 逻辑生成，语义为 `KeySwitch(base, switching_component, evk) -> (base + ks0, ks1)`。
- **`operator/relinearization.hpp/cpp`**：重线性化算子，以 `t0` 为 KeySwitch 的 base、切换 `t2`，再计算 `t1 + ks1`，输出标准二分量密文。
- **`operator/ciphertext_multiply.hpp/cpp`**：完整密文乘法生成，执行输入分量 NTT、`cmult` 三分量张量积、INTT，并复用 `relinearization` 完成最终合成。
- **`operator/encode.hpp/cpp`**：硬件 Encode 边界；宿主先完成有符号系数到 RNS-Q 的嵌入，HPU 再逐 Q limb 执行负循环 NTT，输出可直接供 `pmult` 使用的明文。
- **`operator/rescale.hpp/cpp`**：系数域二分量密文的带舍入层级缩减；对各 Q limb 加 `floor(q_last/2)`，再复用 `ModDown(Q', {q_last})` 丢弃最后一个模数。

### 4) 指令编码模块 (`encode`)
将生成出的 HPU 汇编进一步转译为 32 位机器码文本：
- **`encode/include/*.hpp`**：定义指令数据结构、解析、编码及组装接口。
- **`encode/src/*.cpp`**：实现 ASM / C++ 内联汇编解析、格式归一化以及 `custom0` / `custom1` 指令编码。
- **`hpu_encode`**：由 `encode/CMakeLists.txt` 生成的静态库，供后续测试或上层流程复用。

### 5) 编码测试辅助模块 (`test/encode`)
用于把主生成流程输出的 ASM 继续转换为 `.inst32` 和 `.cmd26` 文件：
- **`test/encode/main.cpp`**：读取主流程生成的 `output/<case>.cpp` 与 `output/<case>.asm`，归档到 `outputs/<case>/`，再调用 `hpu_encode` 生成 32-bit 指令和 26-bit precode 文本。
- **`inline_asm_encode_outputs`**：构建后生成的测试编码工具。

### 6) 软件 Reference (`test/reference`)
- **`test/reference/main.cpp`**：独立的软件算法入口，生成确定性的 RNS/RLWE 输入、重线性化密钥、完整密文乘法 golden、中间检查点和各算子 UT 数据，并执行解密一致性校验。
- **`hpu_reference_vectors`**：构建后生成的 reference 数据工具；它不生成 HPU 指令，也不替代 `src/main.cpp`。

### 7) 项目文档 (`doc`)
- **`doc/HPU_PROGRAMMING_MANUAL.md`**：当前项目 11 条 HPU 指令的编程模型、32-bit 编码、逐指令语义和推荐序列。
- **`doc/HPU_INSTRUCTION_MANUAL.md`**：当前 HPU 指令格式和语义说明。
- **`doc/HPU_TEST_DELIVERY.md`**：指令流、完整密文乘法 golden、RV 接口冒烟用例、验收命令和硬件联调前置项。
- **`doc/HPU_LATEST_SPEC_AUDIT.md`**：项目与最新飞书集成/控制/RV/PE 文档的逐项符合性审计、来源和修改顺序。

### 8) 三个程序入口

| 可执行文件 | 源入口 | 职责 | 主要输出 |
| --- | --- | --- | --- |
| `inline_asm_codegen` | `src/main.cpp` | 调用各级 codegen，生成 HPU C++ 内联汇编和 ASM body | `output/*.cpp`、`output/*.asm` |
| `inline_asm_encode_outputs` | `test/encode/main.cpp` | 归档生成结果、编码 `.inst32/.cmd26`、生成 RV 接口冒烟流 | `outputs/<case>/*`、`outputs/rv_interface_smoke/*` |
| `hpu_reference_vectors` | `test/reference/main.cpp` | 计算软件 golden、解密校验并拆分 UT/IT 数据包 | `outputs/<case>/test_data/*` |

`src/main.cpp` 仍是指令生成主入口。`test/reference/main.cpp` 是另一独立可执行文件的入口，两者没有替代关系。顶层 `hpu_delivery` 目标只是按上述顺序编排三个程序并运行交付检查。

---

## 2. 一键构建与运行

```bash
mkdir -p build
cd build
cmake ..
cmake --build . -j
```
构建完成后，生成的可执行文件 `inline_asm_codegen` 支持通过命令行参数控制输出内容：
```bash
# 只输出 .asm 文件
./build/inline_asm_codegen asm

# 只输出 .cpp 文件
./build/inline_asm_codegen cpp

# 两者皆输出 (默认行为，等价于不传参)
./build/inline_asm_codegen both
```

若需要继续将可编码的 ASM 转成 32 位指令文本，可在生成 ASM 后执行：

```bash
./build/test/encode/inline_asm_encode_outputs
```

推荐使用统一交付目标，一次完成指令生成、编码、FHE reference 数据生成和交付门禁检查：

```bash
cmake --build build -j --target hpu_delivery
ctest --test-dir build --output-on-failure
```

主生成程序仍保持主分支的输出方式，先在根目录生成扁平的 `output/` 文件夹；编码辅助工具随后会把 `.cpp` 与 `.asm` 归档到 `outputs/<case>/`，并将可直接编码的结果写回同一目录。仍含符号寄存器占位符的文件会被显式跳过。

执行 `inline_asm_codegen` 后会先得到主分支约定的扁平输出：
- `output/ntt.cpp`
- `output/ntt.asm`
- `output/intt.cpp`
- `output/intt.asm`
- `...`

执行 `inline_asm_encode_outputs` 后，会进一步整理出根目录下的 `outputs/` 文件夹。执行 `hpu_reference_vectors` 后，各算子目录会补充输入、期望结果和可读 golden：
- `outputs/ntt/`
- `outputs/intt/`
- `outputs/encode/`
- `outputs/rescale/`
- `outputs/mm/`
- `outputs/bconv/`
- `outputs/pmult/`
- `outputs/cmult/`
- `outputs/modup/`
- `outputs/moddown/`
- `outputs/auto/`
- `outputs/keyswitch/`
- `outputs/relinearization/`
- `outputs/ciphertext_multiply/`
- `outputs/rv_interface_smoke/`

例如 `outputs/ntt/` 下会包含：

- `ntt.cpp`
- `ntt.asm`
- `ntt.inst32`（运行编码工具后生成）
- `ntt.cmd26`（与 `.inst32` 逐条对应）
- `test_data/input.bin`、`test_data/input.hex.txt`
- `test_data/expected.bin`、`test_data/expected.hex.txt`
- `test_data/params.json`、`test_data/artifact_manifest.csv`
- `test_data/hardware/hpu_mem_image.u32.bin`、`line_map.csv`、`hpu_mem_config.json`
- `test_data/hardware/mod_ctx_map.csv`、`twiddle_map.csv`、`abi.json`

`outputs/` 是 `hpu_delivery` 生成的交付产物，当前被 `.gitignore` 忽略；仅向测试
同学发送 Git commit 或让其重新 clone 本仓库不会包含这些数据。正式交付应在同一
次 `hpu_delivery` 成功后整体归档 `outputs/`，同时记录源码 commit、归档
SHA-256 和 `outputs/DELIVERY_REPORT.txt`。不得混合不同生成批次的指令、
relocation manifest、line map 与 HPU_MEM 镜像。

---

## 3. 入口与参数

当前完整流程由三个阶段组成：

1. `inline_asm_codegen` 从 `src/main.cpp` 进入，向 `output/` 生成 `.cpp` 与 `.asm`。
2. `inline_asm_encode_outputs` 从 `test/encode/main.cpp` 进入，归档结果并把可编码 ASM 转成 `.inst32/.cmd26`。
3. `hpu_reference_vectors` 从 `test/reference/main.cpp` 进入，计算并验证 test data，然后写入 `outputs/<case>/test_data/`。

当前参数尚未收敛到单一配置文件：

- HPU 指令流参数位于 `src/main.cpp` 的 `kNttCfg`、`kEncodeCfg`、`kRescaleCfg`、`kPmultCfg`、`kCmultCfg`、`kModdownCfg`、`kAutoCfg` 和 `kCiphertextMultiplyCfg`。
- Reference 参数位于 `test/reference/main.cpp` 的 `kN`、`kNumQ`、`kNumP`、`kDnum`、`kPlainModulus` 和 `kSeed`。
- `outputs/*/test_data/params.json` 是生成结果，不是输入配置；直接修改后会在下一次生成时被覆盖。

修改 `N/Q/P/dnum` 时必须同步修改两处源配置，并满足 `N` 为 2 的幂、`ceil(N/64) <= 1024`（即 `N <= 65536`）、`num_q % dnum == 0`、`num_q + num_p <= 256`、所有 Q/P 模数可用 `uint32` 表示等约束。当前统一示例为 `N=4096, Q=4, P=3, dnum=2`。small Bank 5 为 32 line，固定范围 `0x1400..0x141F`，物理可放 512 个 context；由于 `MOD_ID` 只有 8 bit，软件可寻址上限为 256。它与 8 个并发对象槽位是两个独立资源。

`hpu_delivery` 会为 `ciphertext_multiply` 自动生成与主配置一致的 `N=4096, Q=4, P=3, dnum=2` 输入、评估密钥、阶段 golden、最终输出、明文校验和 artifact checksum。它同时生成独立的 `uint32` HPU_MEM 镜像、q/Barrett 上下文、逐 stage twiddle、256B line offset/count，并从同一 reference 拆分出 NTT、INTT、Encode、Rescale、MM、BConv、ModUp、PMULT、CMULT、ModDown、Auto、KeySwitch 和 Relinearization 的独立 UT 数据包。


## 4. 关键设计实现说明

- **基于 HPU 对象槽的 NTT/INTT：**
  底层不再关注向量的大块切片 `l`。针对 `stage=0~log2(N)-1` 的蝶形运算，`pntt/pintt` 以**第一个对象槽位作为稳定的逻辑数据对象**，**第二个对象槽位作为 twiddle 对象**。控制器按物理 out-of-place 执行并在 stage 完成时提交新的 base；调用方保持逻辑对象号。Negacyclic NTT 在 stage 0 前显式 `PMUL psi^i`，INTT 在最终 stage 后显式 `PMUL (N^-1*psi^-i)`。
  
- **切片感知的模提升运算：**
  为了支持分解字（Digit Decomposition），`modup` 接口显式接收完整 `num_q`、处理宽度 `num_q_digit` 和 `q_offset`。它保留当前 digit，并对 `Q\digit ∪ P` 执行 BConv，从而为后续 KeySwitch 产生完整 $Q \cup P$ 表示。单纯 Q→P 的基转换仍由独立 `bconv` 原语提供。
  
- **流水线的统一复用：**
  复杂的算子不需要从头生成具体的 `hpu::pmul` 等语句。`relinearization` 复用完整 `keyswitch`，`ciphertext_multiply` 再复用 `relinearization`；全部由 `generate_hpu_*_body_asm` 函数段拼接。Body Generator 的 `append_psync` 默认关闭，只有形成独立完整程序时才开启；完整 `generate_hpu_*_asm` 接口默认在末尾追加通知。

- **完整密文乘法语义：**
  `cmult` 只负责 FHE 密文乘法中的张量积阶段，即 $t_0=a_0b_0$、$t_1=a_0b_1+a_1b_0$、$t_2=a_1b_1$。`relinearization` 调用 `KeySwitch(base=t0, switching_component=t2, evk=rlk)` 得到 $(t_0+ks_0,ks_1)$，再生成 $t_1+ks_1$；`ciphertext_multiply` 直接复用该算子。

- **Encode 的软硬件边界：**
  当前 reference 的 Encode 是整数明文的 signed-to-RNS 嵌入，不是 CKKS 复数槽位 FFT。冻结的 11 条 HPU ISA 没有比较或条件选择指令，无法从单份 `mod t` 规范余数恢复正负号；因此宿主负责生成 `plaintext_coeff_q[basis][coefficient]`，HPU Encode 负责逐 limb 负循环 NTT，输出 `plaintext_ntt_q`。

- **Rescale 舍入语义：**
  对 `Q={q_0,...,q_last}` 上的每个密文分量，先在每个 limb 加入 `floor(q_last/2)`，再把最后一个 context 当作单元素 P 基复用 ModDown。输出基为 `Q'={q_0,...,q_{last-1}}`，计算的是 `round(x/q_last) mod Q'`；算子只处理系数域数据，不维护上层 CKKS scale 元数据。

- **生成与编码分层解耦：**
  `inline-asm` 仍负责汇编生成，`encode` 模块则负责解析、归一化和 32 位编码。两者保留独立边界，但通过同一 CMake 工程统一构建，从而降低汇编语义更新后生成器与编码器失配的风险。

- **11 条指令与对象生命周期：**
  当前体系结构指令固定为 `padd/psub/pmul/pmac/pntt/pintt/pmodld/pfree/psync/dload/dstore`。旧的 `pshcfg/pshuf/pseed/psample` 已从枚举和编码表移除。临时输入、twiddle 和 small-bank 模表对象会在最后一次使用后生成 `pfree`；以 `dstore rel=1` 导出的结果由 DMA 完成后释放，不再重复 `pfree`。

- **双输入形式兼容：**
  编码器既可处理纯 ASM body，也可处理带有 `__asm__ volatile(...)` 包装的 C++ 内联汇编文本。对于 `void hpu_xxx(void) {`、`: "memory"`、`);` 等生成边界，解析器会做定向忽略；但非法汇编指令本身仍会被保留为错误。


---

## 5. 对象槽位与参数注意事项

调用方需要保证：

- `N` 为 2 的幂，且 `ceil(N/64) <= 1024`（当前硬件上限 `N <= 65536`）
- 仅允许 3 个工作槽位：`p0/p1/p2`
- 复杂算子（Encode/Rescale/PMULT/CMULT/MODUP/MODDOWN）使用 `dload/dstore` 流式搬运，不在本地长期保留多基对象
- `dload type=2, flag[0]=1` 将模表逻辑对象分配到 small Bank 5；DMA 与后续指令的一致性由硬件维护，可直接使用 `pmodld MOD_ID` 激活表项
- 每个可编码算子同时生成 `.inst32` 和 `.cmd26`；`cmd26[25]` 区分 custom0/custom1，custom0 直接携带 `inst[31:7]`，custom1 按控制逻辑字段重排并另带 offset/count sideband
- `psync` 只在完整程序的最后发出，用于通知 CPU 整个 HPU 程序已经完成；不得将其插入算子内部作为 DMA 等待或阶段屏障
- 所有 custom1 指令固定编码 `x10/x11`。可执行 runtime 必须在每条 DMA 前把当前对象的 HPU_MEM line offset/count 装入这两个寄存器；`auto` 也进入统一编码链路。
- `cmult`、`keyswitch`、`relinearization` 与 `ciphertext_multiply` 均已进入统一 `.asm -> .inst32/.cmd26` 生成链路；后三者要求 `num_q % dnum == 0` 且 `num_q + num_p <= 256`
- `ciphertext_multiply/test_data` 已由软件 reference 自动生成；二进制格式、shape 和校验值见其中的 `params.json` 与 `artifact_manifest.csv`
- 顶层 `.bin` 是 `uint64` 数学 golden；真正面向 HPU 加载的是 `test_data/hardware/` 下按 256B line 补齐的 `.u32.bin`
- `hardware/line_map.csv` 给出每个对象的 byte address、line offset 和 line count；custom1 固定使用 `GPR[rs1]=line_offset`、`GPR[rs2]=line_count`（256B line 单位），`hpu_mem_config.json` 给出 HPU_MEM window 值和 `0x00..0x18` CSR 编程顺序
- 生成的 `hpu_program_*` 入口接收与 DMA 指令等长的 `hpu_dma_span_t[]`；每条 DLOAD/DSTORE custom1 发射前都把非零 line offset/count 装入 `x10/x11`。`nexus-am/tests/hpu-it` 根据硬件布局生成逐行可审计的 resolved relocation manifest。

---

## 6. 当前交付边界

软件侧已完成指令生成、编码、完整密文乘法/重线性化 reference golden、独立 `uint32` 硬件镜像、`q32+mu48+reserved48` 模上下文、每 stage 固定 `N/2` 个物理 twiddle、显式 negacyclic pre/post factor、256B line 映射、类型化 DMA span、生命周期门禁和 RV 可执行后端。Nexus-AM IT runtime 已完成 HPU_MEM CSR、cache、FAULT/IRQ、scratch 与 DMA relocation 绑定；硬件 qualification 仍需目标 RTL/板级运行和外部 monitor 证据。详细签字项见 `doc/HPU_TEST_DELIVERY.md`。

当前 golden 使用确定性零噪声和 P 可整除的功能测试评估密钥，适合 UT/IT 的
逐字定位，不是安全性或噪声预算测试向量。Nexus-AM 的 host 模式只验证 testcase、
oracle、relocation 和内存边界自洽；目标算术是否通过必须以 RISC-V 路径在目标
RTL/板级执行后的逐字比对、FAULT/IRQ 状态和外部 monitor 记录为准。
