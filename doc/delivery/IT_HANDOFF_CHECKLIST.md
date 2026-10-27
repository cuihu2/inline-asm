# HPU 应用包 IT 交接清单

本文用于交接 `hpu_fhe_delivery` 生成的 CKKS、BFV、BGV application package v1。
包内已经包含指令、resolved DMA、初始 HPU_MEM 镜像、指定输出 golden 和软件验证报告；
RISC-V 编译、Nexus-AM 接入以及 RTL/板级执行由 IT 环境完成。

`hpu_native_kernel_delivery` 生成的 CMULT、NTT、INTT 也使用同样的文件格式，
但属于未加密环算术测试。先检查 `metadata/parameters.json.test_layer`：
`native_ring_arithmetic` 包使用独立整数计算或既有 NTT 功能模型作为参考，
不提供 SEAL 密文差分、解密结果或安全参数证据；下文的 SEAL 双路径要求适用于
三方案加密应用包。原生用例仍须通过包校验及最终指令模型比较。

带 `execution_profile_manifest` 的包使用单一连续计时入口，须接入时钟与 PSYNC 完成
回调；窗口内必要 DMA 仍计时，普通入口返回 `-5`。具体操作见
[单一连续窗口计时](../getting-started/HPU_EXECUTION_PROFILING.md)。

## 64 对象版本接收要求

本轮改为 `hpu-objects64-v1.2` ISA。接收时检查 `memory/abi.json` 的
`instruction_isa`、`object_slots=64`、`allocation_granule_lines=128`、
`mod_table_lines=4`、`dma_format=mod_rel_cp`、`default_cp=0`、
`stage_parameter_mod=0`、`stage_parameter_bank_mask=32`。stage 参数为两条 line，
通过普通 MOD=0 显式选择 Bank 5；DSTORE REL=0 保留对象。
DMA 清单当前为 15 列，末列 `cp`；`type_or_release` 对读/写分别表示 MOD/REL，
`flag` 是 DLOAD bank mask。检查 CP 位没有截断完整的 rs2 字段。
新应用包另声明 `dma_cache_policy=twiddle_loads_only`：按最终 memory manifest
的 `kind=twiddle`，仅相应 DLOAD 的 CP=1；stage 参数与在线 pre/post 模板均包括在内，
其他 DLOAD 和全部 DSTORE 的 CP=0。该规则包括编译器 reload，关闭资源优化也
保持不变。`default_cp=0` 是底层接口默认值，不表示包内全部 DMA 的 CP 为 0。
`preserve` 策略用于手工 CP 实验；较早 v1.2 包缺少策略字段时按 `preserve`
校验，重新生成后采用新策略。请按包内声明和实际指令验收缓存提示。
所有旧 `.inst32/.cmd26` 与 ELF 必须重新生成。CPU/SoC 的有效 RTL、六位 fault
通路及命令 sideband 仍需按 [RTL 交接说明](HPU_64OBJ_INTEGRATION_HANDOFF.md)
同步；HPU 子模块的局部验证不代表 SoC IT 通过。

升级时保留旧包，以新根目录生成，例如：

```sh
cmake -S . -B build-ckks-delivery -DHPU_APPLICATION_OUTPUT_ROOT="$PWD/outputs/isa12"
cmake --build build-ckks-delivery --target hpu_frontend_delivery -j6
```

## 1. 当前交付判定

满足以下条件时，应用包可以交给 IT 开展功能联调：

- 包来自一个明确且干净的源码 commit；
- `hpu_validate_package` 对每个包返回成功；
- `oracle/report.json` 的 `overall_status` 为 `pass`；
- `seal_oracle_to_golden` 和 `host_software_model_to_oracle` 都是必选且为 `pass`；
- 包目录与归档文件的 SHA-256 随交付记录保存。

`instruction_execution_verified`、`rtl_verified` 和 `hardware_verified` 在发布方生成的包中
固定为 `false`。这些字段说明包尚未取得目标执行证据，不影响 IT 开始接入。

Evaluator 和现有 Plan 导出的包都包含 `host_instruction_model` 和 `compiler_resources`。
`compiler_resources.ir_source=operator` 表示资源 IR 由算子直接生成。
默认编译采用 `raw_bit_reversed_coefficients`，要求 host 逐指令结果与 golden 一致；
正常生成使用 `hpu_frontend_delivery`。显式诊断目标
`hpu_frontend_diagnostic_delivery` 才允许导出带指令模型差异记录的联调包。
诊断包的 `overall_status=pass` 表示必选的 SEAL 与算子软件模型检查通过，
不能据此声明 host 指令模型通过。接收时同时记录
`host_instruction_model_verified` 和 `optimization_equivalence_verified`。
前端的命令及当前验证边界见 [Evaluator 前端入门](../getting-started/HPU_EVALUATOR_FRONTEND.md)。

新 builder 的三方案内部系数存储均为 `physical[j]=natural[BR(j)]`，pre/post 因子
按相同物理索引打包。NTT 域排列不变。raw stage 不增加整体边界 BR；接收时确认
`forward_boundary_conversions=0`、`inverse_boundary_conversions=0`，并记录
`hardware_contract_verified=false`。BFV 与原生 INTT 的 golden domain 是
`coefficient_bit_reversed`，直接按物理 word 比较；解码自然系数需每个 limb 单独 BR。

`natural_coefficient_boundaries` 和 `legacy_raw_stage` 仅为历史包兼容 profile，
选择 profile 不转换镜像。新 BR 镜像不应使用 natural profile。
修订原文见 [2026-10-24 布局适配](../reference/HPU_NTT_SOFTWARE_LAYOUT_ADAPTATION_20261024.md)。
目标端仍需依次验收独立 NTT、INTT、NTT→PMUL→INTT 环乘法，再扩展组合算子。

新包的数据 ABI 位于 `metadata/parameters.json.ntt_table_abi`，它描述镜像而非
回放 profile。缺少该字段的旧包不能仅凭 schema v1 判断其系数布局；迁移时重新生成
完整包，不手工补字段替代数据转换。字段明细见 [应用包 V1](HPU_APPLICATION_PACKAGE_V1.md#新应用镜像的-ntt-表与软件边界)。

当前 NTT 数据 ABI version=4，stage 参数格式为 `hpu-twiddle-k8-v1`、K=8。
每个 PNTT/PINTT 的参数 DLOAD 必须为 **2 line / 512 B**，包括 N=128 和
PINTT stage 0。pre/post 使用 `online_pmul_format=hpu-pmul-online-k8-v1`，
`online_pmul_parameter_lines=2`、`online_pmul_mode=1`、
`online_pmul_parameter_bank_mask=32`，这些字段同时记录于 NTT 数据 ABI 和
`memory/abi.json`。旧完整表镜像不能直接交给新模式，必须连同 spans、window、
manifest 和校验值重新生成。
物理普通 bank 的分配粒度继续由目标 allocator 决定。

接入 [2026-10-22 在线 PMUL 扩展](../reference/PMUL_ONLINE_COMPILER_HANDOFF.md)
还需核对：

- I=0 时 PMUL 的 `[15:14]=01` 原样进入 HPU，示例 `p40,p40,p63` 编码
  `0x2A287F5B`；I=1 时 64、192、255 仍作为完整 imm8。
- PMUL 模板采用 **B=N/64**，与 NTT 的 N/128 区分；BR pre/post 必须全量展开相等，
  post 保留完整 lazy-scale 修正，归一化仅执行一次；在线 PMUL 不增加 butterfly、shuffle 或 CPU 寄存器读取。
- 参数和数据/目的不能同 ID，参数实际两行且全为普通模剩余数，不能引用模表。
  默认 14 个 Bank 5 模板槽为 stage 与 pre/post 共享，不能各算 14 份。
- 硬件组的局部 RTL 回归记录不等于 CPU/DMAC/NoC 整机 IT 证据；核侧若检查
  PMUL 保留位，必须同步放行合法模式。交接原文中的测试链接属于硬件工作区。

硬件组历史迁移记录提到过 HpuCmdMerge 背压越序问题；这不是当前版本已复现
或已修复的结论。目标验收仍需确认命令合流在背压下保持程序顺序，并保存完整 IT
结果；本次编译器不新增每 stage 软件等待。历史背景见
[迁移说明第 8.1 节](../reference/TWIDDLE_COMPILER_MIGRATION.md#81-已知硬件合流器问题与参数迁移分开验收)。

### 导出结果与 IO 验收

目标端只按 `golden_manifest.csv` 读回导出结果。Evaluator 使用全部 `mark_output()`
标记，无标记时保留最后计算结果；Plan 默认保留最终结果。内部逻辑节点不保证在
程序结束后拥有可读 DDR 地址，不能按节点名称自行拼接地址。需要中间检查点时，
请用例作者显式增加输出标记并重新生成完整包。

软件资源报告以 `dma_bytes` 为主，分开记录读/写、重复范围读取和初始镜像大小。
比较原序与优化结果时保持相同 N、Q/P、输入和导出集合。默认性能条件可使用
`--degree 8192 --data-moduli 4 --seed 0`，加 `--no-opt` 生成原序对照。
硬件阶段另记录实际 DDR 流量、执行周期及 LLC 行为。

## 2. 发布方生成步骤

从干净工作区重新配置构建目录。CMake 在配置时记录源码 commit 和工作区状态，因此
不能复用记录了旧 commit 或 `dirty-at-configure` 的配置结果。

```bash
git status --porcelain
cmake -S . -B build-delivery \
  -DHPU_ENABLE_SEAL_INTEGRATION=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-delivery -j --target hpu_fhe_delivery
# 如交接 Evaluator 前端包，使用默认严格目标
cmake --build build-delivery -j2 --target hpu_frontend_delivery
ctest --test-dir build-delivery -L application-delivery --output-on-failure
```

逐包执行静态校验：

```bash
for package in \
  ckks_polynomial_x2_plus_one \
  ckks_composed_application \
  bfv_multiply_modswitch_application \
  bfv_rotation_application \
  bgv_plain_chain \
  bgv_rotate_chain \
  bgv_multiply_chain \
  bgv_composed_application
do
  ./build-delivery/hpu_validate_package "outputs/${package}"
done
```

交付时整体归档八个默认目录并计算 SHA-256。归档名称应包含源码 commit：

```bash
revision=$(git rev-parse --short=12 HEAD)
tar -C outputs -czf "hpu-applications-${revision}.tar.gz" \
  ckks_polynomial_x2_plus_one \
  ckks_composed_application \
  bfv_multiply_modswitch_application \
  bfv_rotation_application \
  bgv_plain_chain bgv_rotate_chain bgv_multiply_chain bgv_composed_application
sha256sum "hpu-applications-${revision}.tar.gz" \
  > "hpu-applications-${revision}.tar.gz.sha256"
```

## 3. 发布前机器检查

对每个目录检查以下字段：

```text
package.json.schema                  = hpu-application-package
package.json.schema_version          = 1
provenance/build.json.commit         = 本次源码 commit
provenance/build.json.worktree_state = clean-at-configure
oracle/report.json.overall_status    = pass
```

`provenance/files.csv` 的 FNV-1a64 用于包内逐文件损坏检查；交付归档的 SHA-256 用于
确认传输前后拿到的是同一个归档。

### 3.1 目标 CPU 包装代码检查

host 指令模型直接使用 resolved DMA span，不执行 C wrapper。要检查 CPU 编译后
每条 DMA 实际使用的 `x10/x11`，配置支持 RV32 和 RV64 的 RISC-V GCC：

```bash
cmake -S . -B build-delivery \
  -DHPU_ENABLE_SEAL_INTEGRATION=ON \
  -DHPU_RISCV_C_COMPILER=/path/to/riscv64-unknown-elf-gcc \
  -DHPU_RISCV_OBJDUMP=/path/to/riscv64-unknown-elf-objdump
cmake --build build-delivery --target hpu_fixed_executable_test
ctest --test-dir build-delivery \
  -R '^hpu_(fixed_executable|target_dma_codegen)_test$' --output-on-failure
```

`hpu_fixed_executable_test` 检查固定入口生成契约及非法 span/形状拒绝行为。
`hpu_target_dma_codegen_test` 对测试夹具执行 RV32/RV64、`-O0/-O2` 编译，并运行
CPU 包装代码，核对 HPU 指令次序、每条 DMA 的 offset/count、`x11` 设置次数及
寄存器保护。固定入口要求每条 DMA 设置 `x10`，`x11` 只在首次和长度变化时设置。
objdump 为可选项，用于保存反汇编；未找到编译器时，目标测试返回 77，CTest
显示 `Skipped`，此时没有目标代码验证结果。

对实际交付包可直接执行脚本，重复 `--package` 检查多个目录：

```bash
python3 test/target_dma_codegen_test.py \
  --cc /path/to/riscv64-unknown-elf-gcc \
  --objdump /path/to/riscv64-unknown-elf-objdump \
  --package outputs/ckks_evaluator_application \
  --package outputs/bfv_evaluator_application \
  --package outputs/bgv_evaluator_application \
  --output-dir build-delivery/target-dma-check
```

此检查将自定义指令作为检查点记录，HPU 数学结果仍由指令模型和设备读回验证。
保存生成的 ELF、反汇编和检查日志，作为所用目标工具链的代码生成证据。
它不设置包内 RTL/硬件验证状态，也不替代下面的设备验收。

### 3.2 v1.2 DMA 与 LLC 提示验收

- 检查 DLOAD `[14]=MOD`、DSTORE `[14]=REL`，两者 `[13]=CP`，完整 rs2 位段保持 `[24:20]`。
- 分别覆盖 MOD=0/1、REL=0/1 与 CP=0/1；确认 CP 每条命令锁存，不从旧对象继承。
- 对 `twiddle_loads_only` 包核对每条 resolved DMA 与最终分配 kind：仅 twiddle
  DLOAD 的 CP 为 1，全部 DSTORE 为 0；同时覆盖 stage 参数、在线 pre/post 模板和
  编译器插入的 reload。LLC 命中率、DDR 流量和耗时需单独测量，软件对拍不证明收益。
- 在外部内存端观察 CP=0 的 ARCACHE/AWCACHE 均为 0x3；CP=1 时分别为 0x7/0xB。内部 SRAM 属性保持 0x3。
- 需要评估收益时分别记录计算总耗时、随后重载和最终 DDR 写回。CP=1 不保证驻留，DMA 完成/B 响应不等于 DDR 已完成写回。

软件功能模型验证编码、结果和生命周期，不给出 LLC 时序或命中率证据。

## 4. IT 消费顺序

1. 先解析 `package.json`，使用其中的路径定位文件，不拼接固定子目录。
2. 按 `memory/hpu_mem_config.json` 的 `capacity_lines * 256` 分配并配置 HPU_MEM window。
3. 清零 window，再把 `memory/hpu_mem_image.u32.bin` 从 line 0 开始加载。
4. 将 `program/<stem>.c`、`program/<stem>.h` 编入 RISC-V/Nexus-AM testcase，调用
   `hpu_run_<stem>()`。生成 C 在非 RISC-V host 上不会发射 `.word` 指令，因此 host
   返回值不能作为 HPU 执行通过证据。
5. 按目标平台的一致性协议完成输入/输出的 cache clean、invalidate 或等效操作；
   等待完成 IRQ，记录 `HPU_STATUS` 和 `HPU_FAULT_STATUS`。CP 不是 cache clean、
   invalidate 或 DDR flush，CP=0 也不表示绕过缓存。
6. 按 `golden/golden_manifest.csv` 逐条读取目标 line span。比较有效 word，并检查
   padding、未使用区域或外部 guard 没有被越界写入。
7. 先用 golden 条目的 `object_id` 匹配计算图节点的 `golden_object_id`，再用
   节点的 `operation_index`、`id` 匹配 DMA 清单，定位算子、DMA 和对象槽位。
   旧 v1 包若没有显式 `operation_index`，使用 `operations` 数组的零起始下标；
   公共模表 DMA 使用 `$application`，不对应具体算子。

## 5. IT 应回传的签字证据

每个执行案例至少记录：

- 交付归档 SHA-256、Inline-asm commit、Nexus-AM commit 和 RISC-V 工具链版本；
- RTL/FPGA/芯片版本、HPU_MEM 基址与容量；
- testcase 返回值、完成 IRQ、最终 status/fault；
- 每个 golden object 的比较结果和首个失败位置；
- window guard 或等价的越界检查结果；
- 目标侧日志，以及需要时的 DMA/指令 monitor 或波形。

上述证据全部通过后，才能在 IT 的执行报告中声明 instruction、RTL 或 hardware
验证通过。发布方的原始包和 `oracle/report.json` 应保持不变。

## 6. 当前参数范围

| 案例 | N | 用途 |
| --- | ---: | --- |
| `ckks_polynomial_x2_plus_one` | 65536 | CKKS 部署规模功能包 |
| 其余七个默认案例 | 128 | 快速算子、分支和组合流程联调 |
| `*_n65536` 七个部署配置 | 65536 | CKKS 复合应用、BFV/BGV 算子及分支组合验收 |

这些都是功能测试参数，没有安全等级声明。部署规模生成：

```bash
cmake --build build-delivery -j2 --target hpu_fhe_deployment_delivery
for package in outputs/*_n65536; do
  ./build-delivery/hpu_validate_package "$package"
done
```

N=65536 配置也必须完成 oracle 对拍、包校验和目标执行证据。按各包的
`capacity_lines` 配置内存与目标超时；当前示例会把容量收紧到实际 `used_lines`，
不再要求目标分配构建时的预留上限。软件生成成功仍不代表平台已支持相应窗口。
部署包可以单独归档，也可以加入默认八包归档；保存归档 SHA-256 和完整案例清单。
新 BR 数据 ABI 的 N=65536 结果以当次测试与包报告为准，本文列出生成入口和
验收要求，不将历史 raw profile 的通过结果视为新 profile 已通过。
