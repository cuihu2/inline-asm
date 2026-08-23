# 2026-05-18 编码模块接入与历史交付流程

> 2026-08-21 注：本文保留旧问题的发现过程；其中关于 `x0/x0`、Auto
> 符号寄存器和“不可执行”的结论不再描述当前实现。当前状态以 README、
> `doc/HPU_PROGRAMMING_MANUAL.md` 和 Nexus-AM resolved relocation manifest 为准。

本文件记录编码链路接入工作；当前状态说明已更新到 2026 年 8 月 21 日，用于描述 HPU 指令生成、32-bit RV 指令、26-bit HPU 命令、FHE 软件 reference 和测试数据交付流程。

## 1. 当前结论

工程当前有三个独立程序入口：

| 可执行文件 | 源入口 | 职责 |
| --- | --- | --- |
| `inline_asm_codegen` | `src/main.cpp` | 生成 HPU C++ 内联汇编与 ASM body |
| `inline_asm_encode_outputs` | `test/encode/main.cpp` | 归档输出、编码 `.inst32`、生成 RV 接口冒烟流 |
| `hpu_reference_vectors` | `test/reference/main.cpp` | 生成并自校验 FHE golden、UT/IT 输入输出数据 |

`test/reference/main.cpp` 没有替代 `src/main.cpp`。前者是软件算法 reference 的入口，后者仍是 HPU 指令流生成入口。顶层 `hpu_delivery` 目标负责依次调用三个程序，并执行交付门禁检查。

## 2. 编码模块接入

编码模块位于：

```text
encode/
├── CMakeLists.txt
├── include/
│   ├── assembler.hpp
│   ├── encoder.hpp
│   ├── instruction.hpp
│   └── parser.hpp
└── src/
    ├── assembler.cpp
    ├── encoder.cpp
    ├── instruction.cpp
    └── parser.cpp
```

该模块通过静态库 `hpu_encode` 提供解析和编码能力。顶层构建同时接入：

```cmake
add_subdirectory(encode)
add_subdirectory(test/encode)
add_subdirectory(test/reference)
```

编码器可处理纯 ASM body 和带 `__asm__ volatile(...)` 包装的 C++ 内联汇编。对 C++ 输入只忽略函数与内联汇编包装边界，真实的非法指令仍会报错。

## 3. 推荐执行方式

完整交付使用统一目标：

```bash
cmake -S . -B build
cmake --build build -j --target hpu_delivery
ctest --test-dir build --output-on-failure
```

`hpu_delivery` 的执行顺序为：

1. `inline_asm_codegen both`：向 `output/` 写入 `.cpp` 与 `.asm`。
2. `inline_asm_encode_outputs`：归档到 `outputs/<case>/`，并生成 `.inst32` 与 RV 冒烟流。
3. `hpu_reference_vectors`：生成完整密文乘法 reference，并拆分各算子 UT 数据包。
4. `check_delivery.cmake`：检查必要文件、算法验证结果和指令编码数量。

需要单步调试时，可手工执行：

```bash
./build/inline_asm_codegen both
./build/test/encode/inline_asm_encode_outputs
./build/test/reference/hpu_reference_vectors \
  outputs/ciphertext_multiply/test_data outputs
```

## 4. 输出目录

`src/main.cpp` 保留原有扁平输出：

```text
output/
├── ntt.cpp
├── ntt.asm
├── ciphertext_multiply.cpp
├── ciphertext_multiply.asm
└── ...
```

编码与 reference 阶段进一步整理出：

```text
outputs/<case>/
├── <case>.cpp
├── <case>.asm
├── <case>.inst32
├── <case>.cmd26
└── test_data/
    ├── README.md
    ├── params.json
    ├── artifact_manifest.csv
    ├── *.bin
    ├── *.hex.txt
    └── hardware/
        ├── hpu_mem_image.u32.bin
        ├── hpu_mem_config.json
        ├── line_map.csv
        ├── mod_ctx_map.csv
        ├── twiddle_map.csv
        ├── constants/
        └── images/
```

具体文件名随算子变化。顶层 `.bin` 是小端 `uint64_t` 数学 golden，不直接作为 HPU load image；`hardware/` 下的 `.u32.bin` 才是 64×32-bit、每 line 256B 的硬件镜像。两类数据都有带用途、shape 和分块注释的 `.hex.txt` 人工可读版本；两个 manifest 分别记录逻辑 golden 与物理镜像的大小和校验值。

当前覆盖目录包括 `ntt`、`intt`、`encode`、`rescale`、`mm`、`bconv`、`pmult`、`cmult`、`modup`、`moddown`、`keyswitch`、`relinearization`、`auto`、`ciphertext_multiply` 和 `rv_interface_smoke`。

完整密文乘法目录额外包含：

- `memory_map.json`：指向完整 HPU_MEM 镜像、256B line map 和 window 配置。
- `dma_plan.csv`：各 FHE 阶段的输入、输出、域和基顺序。
- `VALIDATION.txt`：解密一致性与阶段验证结果。
- `input/`、`constants/`、`expected/`：密文、重线性化密钥和中间/最终 golden。

## 5. 当前编码状态

当前编码器只接受 11 条体系结构指令：`padd`、`psub`、`pmul`、`pmac`、`pntt`、`pintt`、`pmodld`、`pfree`、`psync`、`dload` 和 `dstore`。`pmodld` 使用 MOD 格式，只接受一个 8-bit `MOD_ID` 并编码到 `OP2_8`；`pfree` 使用 CFG 格式，由 `PSRC` 指定释放对象，其余字段为零；`psync` 不携带软件操作数。旧的 `pshcfg/pshuf/pseed/psample` 已移除并放入 RV 负例；`pmul/pmac` 的小立即数形式继续使用原助记符，不再使用 `pmuli/pmaci`。

每条编码结果同时生成两种表示：

- `.inst32`：RV 侧看到的原始 32-bit custom 指令。
- `.cmd26`：控制逻辑接收的命令，`cmd26[25]=custom_kind`。custom0 的 payload 为 `inst[31:7]`；custom1 将 `flag/OBJ_ID/TYPE/DIR` 重排进 payload，`rs1/rs2` 形成独立 line offset/count sideband。

`dload` 语法为 `dload rs1, rs2, pdst, type, small_bank`。`small_bank` 编码到原始 `inst[8]`；模上下文固定使用 `type=2, small_bank=1` 请求 Bank 5。DMA 一致性由硬件维护，首条 `pmodld` 前不需要 `psync`；`psync` 仅作为完整程序的最后一条指令通知 CPU。

| 算子 | ASM | `.inst32` / `.cmd26` | reference test data |
| --- | --- | --- | --- |
| `ntt/intt/encode/rescale/mm/bconv/pmult/cmult/modup/moddown/keyswitch/relinearization/auto` | 已生成 | 已生成 | 已生成 |
| `ciphertext_multiply` | 已生成 | 已生成 | 已生成完整 FHE 流程数据 |
| `rv_interface_smoke` | 已生成 | 已生成 | decode 期望与非法输入用例 |

当前所有可编码算子的 custom1 指令均固定使用 `x10/x11`，实际 line offset/count
由 runtime 的 DMA span 在发射前写入；Auto 已进入同一编码和 relocation 链路。

## 6. 参数配置

参数只来自 `config/fhe_test.conf`。指令流生成器和 FHE reference 使用同一个
`hpu_test_config` 解析库；`hpu_delivery` 通过 CMake cache 变量 `HPU_TEST_CONFIG`
将同一路径显式传给二者。`outputs/*/test_data/params.json` 是生成结果，不是输入
配置，重新生成时会覆盖。

配置需要满足 `N` 为不小于 2 的 2 次幂、`ceil(N/64) <= 1024`、
`num_q >= 2`、`num_q % dnum == 0`、`num_q + num_p <= 256`，且当前仅支持
`auto_index=1`。8 个逻辑对象槽位与 8-bit `MOD_ID` 编码空间是独立资源；Bank 5
为 32 line、固定基址 `0x1400`，物理可放 512 个 context，但 `MOD_ID` 最多寻址
256 个。默认完整乘法参数为 `N=4096, Q=4, P=3, dnum=2`。

## 7. 当前交付边界

软件侧已经完成指令生成、`.inst32`/`.cmd26` 编码、完整密文乘法与重线性化
reference、算子 UT 数据、RV 接口冒烟流，以及 Nexus-AM runtime 中的逐条 DMA
span、scratch、HPU_MEM CSR、cache、FAULT/IRQ 绑定。当前不再存在 `x0/x0` 或
Auto 符号 DMA 寄存器阻塞项。

剩余条件只有目标 RTL/板级执行和外部 monitor 证据。Host `PASS_PROBE` 自检只证明
testcase、oracle、relocation 与 guard 自洽，不能代替硬件算术验收。测试向量采用
确定性零噪声功能密钥，不用于安全性或噪声预算验证。

此外，`outputs/` 是被 `.gitignore` 忽略的生成目录，正式交付必须整体归档并附带
源码 commit、归档 SHA-256 和 `DELIVERY_REPORT.txt`，不能只发送仓库 commit，
也不能混合不同生成批次的数据、指令和 relocation manifest。

完整验收项和硬件联调签字表见 `doc/HPU_TEST_DELIVERY.md`。
