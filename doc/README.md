# 项目文档导航

本文档目录按读者任务组织。项目根目录的 [README](../README.md) 说明整体能力、构建方式和代码结构；这里提供各专题文档的入口。

## 快速选择

| 目标 | 建议阅读顺序 |
| --- | --- |
| 使用 CKKS API 编写应用 | [CKKS 入门](getting-started/CKKS_HPU_GETTING_STARTED.md) → [CKKS 复合应用](examples/CKKS_COMPOSED_APPLICATION_EXAMPLE.md) → [仿 SEAL API 参考](reference/HPU_SEAL_API_REFERENCE.md) |
| 为 IT 编写应用测试 | [应用包 V1](delivery/HPU_APPLICATION_PACKAGE_V1.md) → [应用示例](examples/) → [仿 SEAL API 参考](reference/HPU_SEAL_API_REFERENCE.md) |
| 对接 Nexus-AM 或 HPU runtime | [应用包 V1](delivery/HPU_APPLICATION_PACKAGE_V1.md) → [IT 交接清单](delivery/IT_HANDOFF_CHECKLIST.md) → [HPU 编程手册](reference/HPU_PROGRAMMING_MANUAL.md) |
| 维护 SEAL 与 HPU 适配层 | [SEAL 集成设计](architecture/HPU_SEAL_INTEGRATION.md) → [仿 SEAL API 参考](reference/HPU_SEAL_API_REFERENCE.md) |
| 回归旧算子交付流水线 | [Legacy 测试交付说明](delivery/HPU_TEST_DELIVERY.md) |
| 查看硬件规范符合性记录 | [2026-08 符合性审计](audits/HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md) |

## 目录说明

### `getting-started/`

- [CKKS_HPU_GETTING_STARTED.md](getting-started/CKKS_HPU_GETTING_STARTED.md)：从 SEAL context、应用镜像和 operation plan 到 HPU 交付包的入门流程。

### `examples/`

- [CKKS_COMPOSED_APPLICATION_EXAMPLE.md](examples/CKKS_COMPOSED_APPLICATION_EXAMPLE.md)：CKKS 分支计算图、软件执行器和 SEAL oracle 对比。
- [BFV_APPLICATION_EXAMPLE.md](examples/BFV_APPLICATION_EXAMPLE.md)：BFV Multiply、Relinearize、ModSwitch 应用。
- [BFV_ROTATION_APPLICATION_EXAMPLE.md](examples/BFV_ROTATION_APPLICATION_EXAMPLE.md)：BFV 行旋转和列旋转应用。

### `reference/`

- [HPU_SEAL_API_REFERENCE.md](reference/HPU_SEAL_API_REFERENCE.md)：CKKS、BGV、BFV 的应用构建器、operation plan、软件执行器和交付接口。
- [HPU_PROGRAMMING_MANUAL.md](reference/HPU_PROGRAMMING_MANUAL.md)：HPU 指令、编码、对象生命周期、DMA 和方案算子底层约定。

### `architecture/`

- [HPU_SEAL_INTEGRATION.md](architecture/HPU_SEAL_INTEGRATION.md)：modified-SEAL 依赖、NTT 物理模型、模数链和三方案适配设计。

### `delivery/`

- [HPU_APPLICATION_PACKAGE_V1.md](delivery/HPU_APPLICATION_PACKAGE_V1.md)：当前通用应用交付包格式，适用于 CKKS、BGV 和 BFV。
- [IT_HANDOFF_CHECKLIST.md](delivery/IT_HANDOFF_CHECKLIST.md)：发布、归档、目标执行和 IT 签字所需的逐项检查。
- [HPU_TEST_DELIVERY.md](delivery/HPU_TEST_DELIVERY.md)：由 `config/fhe_test.conf` 驱动的旧固定参数算子包，仅用于兼容和回归。

### `audits/`

- [HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md](audits/HPU_SPEC_COMPLIANCE_AUDIT_2026-08.md)：2026 年 8 月硬件文档符合性审计快照。它记录当时的修复依据和遗留项，不代替当前接口规范。

## 文档状态约定

- `reference/`、`delivery/HPU_APPLICATION_PACKAGE_V1.md` 和应用示例随代码维护，可作为当前接口依据。
- `audits/` 保存带日期的历史证据；其中的“当前状态”只对应审计日期。
- `delivery/HPU_TEST_DELIVERY.md` 明确标记为 Legacy，仅描述旧固定参数流水线。
- `outputs/` 是生成目录且不纳入 Git。需要交付时应从同一源码 commit 重新生成完整目录。
