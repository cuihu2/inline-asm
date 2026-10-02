# BGV 分支应用与 IT 用例编写

源码：`examples/bgv_composed_application.cpp`。该用例计算：

```text
y = ModSwitch(Relinearize(x * (RotateRows(x, 1) + RotateColumns(x)))) + 7
```

计划包含七个节点。两种旋转共用输入 x，Add 合并两个分支；Multiply 产生三分量
密文，Relinearize 显式恢复二分量，ModSwitch 降到相邻 level，最后加入明文偏置。

## 构建与生成

```bash
cmake -S . -B build-seal -DHPU_ENABLE_SEAL_INTEGRATION=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-seal -j --target bgv_composed_application_delivery
./build-seal/hpu_validate_package outputs/bgv_composed_application

# N=65536 配置，输出到独立目录。
cmake --build build-seal --target bgv_composed_application_n65536_delivery
./build-seal/hpu_validate_package outputs/bgv_composed_application_n65536

# 自选目录必须尚不存在；默认 N=128。
./build-seal/hpu_bgv_composed_application_example --emit-dir outputs/my_bgv_graph
./build-seal/hpu_bgv_composed_application_example --degree 65536 --emit-dir outputs/my_bgv_large
```

## 图接口

```cpp
#include "hpu/seal/bgv_operation_plan.hpp"

hpu::seal_adapter::BgvOperationPlan plan(context);
const auto x = plan.add_ciphertext("input/x", encrypted);
const auto rows = plan.append_rotate_rows("rows", x, 1, galois_keys);
const auto columns = plan.append_rotate_columns("columns", x, galois_keys);
const auto mixed = plan.append_add("mix", rows, columns);
const auto tensor = plan.append_multiply("multiply", x, mixed);
const auto product = plan.append_relinearize("relinearize", tensor, relin_keys);
const auto next = plan.append_modswitch_to_next("drop", product);
const auto y = plan.append_add_plain("bias", next, encoded_bias);
plan.set_output(y);
auto application = plan.lower(construction_limit_lines);
```

返回的 `BgvPlannedValue` 可以传给多个后继节点。每个节点依据自身输入推导 level、
correction factor 和分量数；某个分支降层后，另一个分支仍可以继续使用顶层 x。
Add/Sub/Multiply 的两个输入必须处于同一 level，跨计划或被修改的句柄会被拒绝。

`set_output` 选择最终输出；没有调用时默认最后追加的节点。其他节点仍导出逐步
输出以供 IT 定位。查询 producer 镜像时使用 `plan.allocation_prefix(value)`；
导出后的 IT 消费方使用包内 DMA、memory 和 golden 清单。

计划保存导入数据的只读快照。重复密钥在节点间共享；相同的只读物理 payload 在
HPU_MEM 中共享 allocation。可变 workspace 和每步 golden 输出保持独立，不会
被后续节点覆盖。lowering 使用的临时独立应用逐节点销毁，减少宿主峰值内存。

## Oracle、软件模型与交付

例子分别运行：

1. `BgvSoftwareExecutor::execute(plan)`：读取初始镜像、密钥、常量和 twiddle，
   按图依赖计算每个节点，密文数学运算不调用 SEAL Evaluator。
2. 独立 `seal::Evaluator`：执行同一个表达式，每个节点后保存 ciphertext 快照。
3. `make_bgv_application_package`：检查每步元数据并逐 RNS limb 比较模型与 SEAL。
   任一步不一致会停止生成；三分量 Multiply 也有独立 golden。
4. SEAL 解密、BatchEncoder 解码：检查槽位是否等于预期表达式。

交付文件和 IT 加载顺序见 [应用包 v1](../delivery/HPU_APPLICATION_PACKAGE_V1.md) 与
[IT 交接清单](../delivery/IT_HANDOFF_CHECKLIST.md)。软件对拍与静态校验不替代
编码指令、RTL 或实际 HPU 执行证据。

## 兼容原用例

`bgv_plain_operation_plan.hpp` 和 `bgv_linear_operation_plan.hpp` 保留为兼容入口，
`BgvPlainOperationPlan`、`BgvLinearOperationPlan` 均为 `BgvOperationPlan` 的别名。
原来不传输入句柄的调用仍沿尾节点追加；旧
`append_multiply(id, seal_ciphertext, relin_keys)` 仍表示融合 Multiply+Relinearize。
图接口 `append_multiply(id, left_value, right_value)` 则保留三分量；融合形式应显式
调用 `append_multiply_relinearize`。两种形式的 oracle 快照数量应分别匹配节点数。
