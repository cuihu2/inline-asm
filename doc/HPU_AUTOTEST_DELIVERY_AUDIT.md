# HPU autotest 对照与 IT ELF 交付审计

审计日期：2026-08-23

## 1. 结论

当前软件生成链已按硬件负责人提供的 `/home/songyexin/fhe/autotest` 对齐
PNTT/PINTT 的 128-register loader、64-lane BF、P/P^-1 网络和 INTT lazy
scale。默认参数 `N=4096, Q=4, P=3, dnum=2` 下，算子 reference、硬件
`uint32` 镜像、DMA relocation、Nexus-AM host 用例和 49 套 RISC-V ELF 构建
均通过软件门禁。

这表示交付物在软件、算法和 ELF 静态层面自洽。最终目标算术仍须在 RTL/FPGA
上逐字比对输出，并检查 FAULT/IRQ、cache、对象生命周期和 guard line，不能由
host 模型替代。

## 2. autotest 的有效基线

`autotest/hw_ntt_intt_complete.py` 冻结了以下物理行为：

- 128 个本地寄存器和 64 个固定 BF lane（第 30-32 行）。
- P 网络为 7-bit 寄存器索引右循环一位，`P^-1=P^6`（第 184-217 行）。
- PNTT 为 `load -> BF -> P -> store`（第 415-440 行）。
- `stage < 7` 连续加载 128 words，之后交错加载上下各 64 words
  （第 242-267 行）。
- PINTT 反向遍历前向 stage，每批先执行 `P^-1` 再执行 BF
  （第 475-512 行）。
- PINTT BF twiddle 使用 `w_bf=alpha/beta` 的 data-independent lazy scale
  （第 321-394 行）。

`intt_twiddle_gen.py` 对同一 dual schedule 给出独立实现。`toy_fhe_auto.py`
描述的是使用修改后 twist 融合 automorphism 的可选优化，不包含控制、DMA、
对象槽位或 ELF ABI，因此不是当前 Auto 指令流必须采用的接口定义。

## 3. P0：round-trip 不等于 FHE 卷积

硬件组脚本的 self-test 只检查 reference round-trip、硬件 round-trip 和 layout
恢复（`hw_ntt_intt_complete.py` 第 614-650 行），没有检查
`NTT(a) * NTT(b) -> INTT` 是否等于多项式卷积。直接使用脚本示例的自然顺序
输入时，实测 `AUTOTEST_ROUNDTRIP=PASS`，但
`AUTOTEST_NORMAL_INPUT_CONVOLUTION=FAIL`。

原因是脚本使用 stride 从 1 递增的 radix-2 DIT BF，却未在输入侧执行
bit reversal；该变换可逆，但不是仅对标准 DFT 输出做一次排列。逐点乘因此不再
对应 FHE 所需卷积。

当前软件不修改硬件 schedule，而是冻结以下硬件数据 ABI：

- 系数域：`memory[p] = coefficient[bit_reverse(p)]`。
- pre-twist：`psi^bit_reverse(p)`。
- PNTT stage 表：按实际 loader batch、batch 内 BF lane 消费顺序生成。
- NTT 域：`memory[p] = logical_ntt[forward_layout[p]]`；NTT 域明文、rlk、
  Galois key 和中间结果均使用该 layout。
- PINTT：反向 stage、每批 `P^-1 -> BF`，使用 `alpha/beta` 表。
- post factor：`N^-1 * psi^-bit_reverse(p)`。

reference 内置模型同时检查前向结果和
`PNTT -> pointwise multiply -> PINTT` 的卷积语义。使用 Q0
`q=50061313, N=4096` 对硬件组 Python 模型逐项比较 coefficient image、NTT
image、12 张 PNTT 表、12 张 PINTT 表和 pre/post factor，结果为：

```text
AUTOTEST_ORACLE=PASS q=50061313 N=4096 ntt_stages=12 intt_stages=12
```

## 4. FHE 算子与 reference

完整 reference 流程为：RLWE 输入 -> negacyclic NTT -> 三分量 tensor product ->
INTT -> digit ModUp 到 Q union P -> NTT -> 与 relinearization key 相乘累加 ->
INTT -> ModDown by P -> 合成二分量密文 -> 解密。它执行以下独立断言：

- KeySwitch 输出解密值等于 `t2*s^2`。
- 重线形化后二分量密文解密值等于 tensor 三分量解密值。
- 最终明文等于 `Z_t[X]/(X^N+1)` 中的 negacyclic message product。
- Auto 的系数域 `X -> X^3` 与 Galois KeySwitch 解密结果一致。
- Encode signed-to-RNS、Rescale rounded drop-last、BConv、ModUp/ModDown 和所有
  中间 checkpoint 均由同一确定性 reference 生成。

评估密钥是零噪声、P-divisible 的功能测试 fixture，只用于 UT/IT 精确定位；它
不是生产安全密钥，也不覆盖噪声预算。

## 5. ELF 与 DMA 证据

发布目录：

```text
/home/songyexin/fhe/nexus-am/tests/hpu-it/build/nexus-audit/images/
  hpu-0x87000000-19201-4701a28645549c73/
```

验证结果：

- 49 套 ELF/bin/objdump 全部通过 `validate_artifacts.sh`；48 套为
  `EXECUTABLE_PASS_READY`，`HPU_IT_DIR_CMB_015` 因外部算法契约明确标记
  `BLOCKED_EXTERNAL_ALGORITHM_CONTRACT`。
- 完整应用 `HPU_IT_DIR_APP_001.elf` 为 little-endian ELF64 RISC-V EXEC，入口
  `0x80000000`，GCC 11.4.0，SHA-256 为
  `44fc6c87b5e03cfd4d3621921d4f78428d82cd3b194d93b954b9c349e9011199`。
- 从 ELF 的 `hpu_program_ciphertext_multiply` 提取 3141 个 custom word，与
  `ciphertext_multiply.inst32` 的 3141 条逐位一致。
- 随应用 ELF 发布的 `.dma.csv` 与 host resolved manifest 字节一致；11 份
  manifest 全部为 `RESOLVED`，每条 `line_count > 0` 且
  `end_line_exclusive <= 19201`。
- HPU_MEM profile 为 base `0x87000000`、19201 line、每 line 256B；master 为
  16961 line，runtime 为 scratch 和尾部 guard 保留其余空间。

## 6. IT 上板签字项

上板后仍须保留以下证据，完成后才能把 `HARDWARE_EXECUTION` 从
`CONDITIONAL` 改为 `PASS`：

1. 目标 RTL 实际消费 twiddle 的顺序与本报告第 2 节一致。
2. 每个算子及完整应用的 DStore 输出逐字等于硬件 `uint32` golden。
3. HPU_STATUS、FAULT W1C、完成 IRQ 和 timeout 路径符合 runtime 预期。
4. 输入提交前 cache clean、输出读取前 invalidate 在目标平台生效。
5. 所有对象释放、DStore release 和 out-of-place stage 提交没有 use-after-free。
6. 末尾 guard line 未被写坏，并归档板端日志或外部 monitor/波形。
