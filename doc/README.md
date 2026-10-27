# 项目文档导航

本文档目录按读者任务组织。项目根目录的 [README](../README.md) 说明整体能力、构建方式和代码结构；这里提供各专题文档的入口。

## 快速选择

| 目标 | 建议阅读顺序 |
| --- | --- |
| 使用 SEAL 风格 Evaluator 编写三方案应用 | [Evaluator 前端入门](getting-started/HPU_EVALUATOR_FRONTEND.md) → [应用编程手册](reference/HPU_SEAL_API_REFERENCE.md) → [应用包 V1](delivery/HPU_APPLICATION_PACKAGE_V1.md) |
| 理解整体架构、编译流程、runtime 与资源管理 | [项目架构](architecture/HPU_ARCHITECTURE.md) → [SEAL 集成设计](architecture/HPU_SEAL_INTEGRATION.md) |
| 使用 CKKS 的显式 Plan 接口 | [CKKS 入门](getting-started/CKKS_HPU_GETTING_STARTED.md) → [CKKS 复合应用](examples/CKKS_COMPOSED_APPLICATION_EXAMPLE.md) → [底层 API 参考](reference/HPU_LOW_LEVEL_API_REFERENCE.md) |
| 为 IT 编写应用测试 | [应用编程手册](reference/HPU_SEAL_API_REFERENCE.md) → [应用包 V1](delivery/HPU_APPLICATION_PACKAGE_V1.md) → [IT 交接清单](delivery/IT_HANDOFF_CHECKLIST.md) |
| 预载后连续测量程序主体，排除尾部写回 | [单一连续窗口计时](getting-started/HPU_EXECUTION_PROFILING.md) |
| 对接 Nexus-AM 或 HPU runtime | [应用包 V1](delivery/HPU_APPLICATION_PACKAGE_V1.md) → [IT 交接清单](delivery/IT_HANDOFF_CHECKLIST.md) → [HPU 编程手册](reference/HPU_PROGRAMMING_MANUAL.md) |
| 维护 SEAL 与 HPU 适配层 | [SEAL 集成设计](architecture/HPU_SEAL_INTEGRATION.md) → [底层 API 参考](reference/HPU_LOW_LEVEL_API_REFERENCE.md) |
| 核对 NTT 软件契约及验证边界 | [HPU 编程手册](reference/HPU_PROGRAMMING_MANUAL.md) → [项目架构的验证说明](architecture/HPU_ARCHITECTURE.md#8-验证路径与证据边界) |
| 查看硬件规范符合性记录 | [2026-08 符合性审计](audits/HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md) |
| 对接 K=8 在线 twiddle 参数格式 | [硬件组编译器迁移说明](reference/TWIDDLE_COMPILER_MIGRATION.md) |
| 核对 BR 系数及在线 pre/post 布局修订 | [2026-10-24 布局适配原文](reference/HPU_NTT_SOFTWARE_LAYOUT_ADAPTATION_20261024.md) → [应用包 ABI](delivery/HPU_APPLICATION_PACKAGE_V1.md#新应用镜像的-ntt-表与软件边界) |
| 对接在线 pre/post PMUL 与两行模板 | [PMUL 硬件交接原文](reference/PMUL_ONLINE_COMPILER_HANDOFF.md) → [编程手册](reference/HPU_PROGRAMMING_MANUAL.md#31-pmul-在线-prepost-因子2026-10-22-追加) |

## 目录说明

### `getting-started/`

- [HPU_EVALUATOR_FRONTEND.md](getting-started/HPU_EVALUATOR_FRONTEND.md)：三方案统一句柄和 Evaluator、自动验证、严格编译与诊断导出。
- [HPU_EXECUTION_PROFILING.md](getting-started/HPU_EXECUTION_PROFILING.md)：容量安全预加载、单一连续计时窗口、目标回调及残留 IO 统计。
- [CKKS_HPU_GETTING_STARTED.md](getting-started/CKKS_HPU_GETTING_STARTED.md)：从 SEAL context、应用镜像和 operation plan 到 HPU 交付包的入门流程。

### `examples/`

- [CKKS_COMPOSED_APPLICATION_EXAMPLE.md](examples/CKKS_COMPOSED_APPLICATION_EXAMPLE.md)：CKKS 分支计算图、软件执行器和 SEAL oracle 对比。
- [BGV_COMPOSED_APPLICATION_EXAMPLE.md](examples/BGV_COMPOSED_APPLICATION_EXAMPLE.md)：BGV 分支计算图、独立 Multiply/Relinearize、软件对拍和部署规模生成。
- [BFV_APPLICATION_EXAMPLE.md](examples/BFV_APPLICATION_EXAMPLE.md)：BFV Multiply、Relinearize、ModSwitch 应用。
- [BFV_ROTATION_APPLICATION_EXAMPLE.md](examples/BFV_ROTATION_APPLICATION_EXAMPLE.md)：BFV 行旋转和列旋转应用。

### `reference/`

- [HPU_SEAL_API_REFERENCE.md](reference/HPU_SEAL_API_REFERENCE.md)：面向应用程序员的手册，包含完整程序、自定义构建目标、顶层 API、三方案规则、golden 与诊断排查。
- [HPU_LOW_LEVEL_API_REFERENCE.md](reference/HPU_LOW_LEVEL_API_REFERENCE.md)：供维护适配层、显式 Plan、镜像构建器、软件执行器和算子生成接口时查询。
- [HPU_PROGRAMMING_MANUAL.md](reference/HPU_PROGRAMMING_MANUAL.md)：HPU ISA v1.2 及 2026-10-22 在线 PMUL 扩展的指令编码、MOD/REL/CP、对象生命周期和 DMA 约定。
- [HPU_NTT_SOFTWARE_LAYOUT_ADAPTATION_20261024.md](reference/HPU_NTT_SOFTWARE_LAYOUT_ADAPTATION_20261024.md)：硬件组 2026-10-24 修订原文；明确系数与 pre/post 因子共同 BR、exact packing 和 raw stage 验收范围，优先于旧自然边界说明。
- [PMUL_ONLINE_COMPILER_HANDOFF.md](reference/PMUL_ONLINE_COMPILER_HANDOFF.md)：硬件组在线因子 PMUL 交接原文，包含模式位、固定 512 B 模板及分配成本；原文路径和测试记录属于硬件仓库。
- [TWIDDLE_COMPILER_MIGRATION.md](reference/TWIDDLE_COMPILER_MIGRATION.md)：硬件组提供的 stage twiddle K=8 ABI、512 B 参数布局、DMA 迁移与目标验收要求；其中旧 pre/post 全长向量说明已由 PMUL 在线交接更新。硬件仓库路径和附属报告需到相应硬件工作区查看。

- [HPU_BANK_ALLOCATION_GUIDE.md](reference/HPU_BANK_ALLOCATION_GUIDE.md)：64 对象、128-line 分配、Bank 5 隔离、确定性 bank 选择与预测边界。

### `architecture/`

- [HPU_ARCHITECTURE.md](architecture/HPU_ARCHITECTURE.md)：整体分层、顶层 API、计算图编译流程、SSA 优化、IO 调度、资源 IR 与统一资源管理、runtime 职责、验证边界和交付链路。
- [HPU_SEAL_INTEGRATION.md](architecture/HPU_SEAL_INTEGRATION.md)：modified-SEAL 依赖、NTT 物理模型、模数链和三方案适配设计。

### `delivery/`

- [HPU_APPLICATION_PACKAGE_V1.md](delivery/HPU_APPLICATION_PACKAGE_V1.md)：当前通用应用交付包格式，适用于 CKKS、BGV 和 BFV。
- [IT_HANDOFF_CHECKLIST.md](delivery/IT_HANDOFF_CHECKLIST.md)：发布、归档、目标执行和 IT 签字所需的逐项检查。
- [IO_OPTIMIZATION_RESULTS.md](delivery/IO_OPTIMIZATION_RESULTS.md)：SSA 重构、N8192/Q4/P1 与 N65536 的实测 IO、局部验收和复现命令。

- [HPU_64OBJ_INTEGRATION_HANDOFF.md](delivery/HPU_64OBJ_INTEGRATION_HANDOFF.md)：v1.2 接入要点、RTL 提供方历史交接记录及 CPU/SoC 验收范围。

### `audits/`

- [HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md](audits/HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md)：2026 年 8 月硬件文档符合性审计快照。它记录当时的修复依据和遗留项，不代替当前接口规范。
- [HPU_NTT_CONTRACT_AUDIT_2026-10.md](audits/HPU_NTT_CONTRACT_AUDIT_2026-10.md)：自然系数边界、独立数学反例、CKKS 舍入修复及软件验收快照；当前接口以编程手册和应用包 V1 为准。

## 文档状态约定

- `reference/`、`delivery/HPU_APPLICATION_PACKAGE_V1.md` 和应用示例随代码维护，可作为当前接口依据。
- `audits/` 保存带日期的历史证据；其中的“当前状态”只对应审计日期。
- `outputs/` 是生成目录且不纳入 Git。需要交付时应从同一源码 commit 重新生成完整目录。
