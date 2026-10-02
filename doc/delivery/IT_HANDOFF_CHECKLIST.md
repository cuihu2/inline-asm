# HPU 应用包 IT 交接清单

本文用于交接 `hpu_fhe_delivery` 生成的 CKKS、BFV、BGV application package v1。
包内已经包含指令、resolved DMA、初始 HPU_MEM 镜像、逐算子 golden 和软件验证报告；
RISC-V 编译、Nexus-AM 接入以及 RTL/板级执行由 IT 环境完成。

## 1. 当前交付判定

满足以下条件时，应用包可以交给 IT 开展功能联调：

- 包来自一个明确且干净的源码 commit；
- `hpu_validate_package` 对每个包返回成功；
- `oracle/report.json` 的 `overall_status` 为 `pass`；
- `seal_oracle_to_golden` 和 `host_software_model_to_oracle` 都是必选且为 `pass`；
- 包目录与归档文件的 SHA-256 随交付记录保存。

`instruction_execution_verified`、`rtl_verified` 和 `hardware_verified` 在发布方生成的包中
固定为 `false`。这些字段说明包尚未取得目标执行证据，不影响 IT 开始接入。

## 2. 发布方生成步骤

从干净工作区重新配置构建目录。CMake 在配置时记录源码 commit 和工作区状态，因此
不能复用记录了旧 commit 或 `dirty-at-configure` 的配置结果。

```bash
git status --porcelain
cmake -S . -B build-delivery \
  -DHPU_ENABLE_SEAL_INTEGRATION=ON \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-delivery -j --target hpu_fhe_delivery
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

## 4. IT 消费顺序

1. 先解析 `package.json`，使用其中的路径定位文件，不拼接固定子目录。
2. 按 `memory/hpu_mem_config.json` 的 `capacity_lines * 256` 分配并配置 HPU_MEM window。
3. 清零 window，再把 `memory/hpu_mem_image.u32.bin` 从 line 0 开始加载。
4. 将 `program/<stem>.c`、`program/<stem>.h` 编入 RISC-V/Nexus-AM testcase，调用
   `hpu_run_<stem>()`。生成 C 在非 RISC-V host 上不会发射 `.word` 指令，因此 host
   返回值不能作为 HPU 执行通过证据。
5. 执行前完成 cache clean；等待完成 IRQ，记录 `HPU_STATUS` 和
   `HPU_FAULT_STATUS`；读回前执行 cache invalidate。
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
