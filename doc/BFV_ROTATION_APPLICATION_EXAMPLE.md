# BFV Rotation 应用示例

[`examples/bfv_rotation_application.cpp`](../examples/bfv_rotation_application.cpp) 演示一个保持
同一 BFV level 的分支应用：

```text
                  ┌─ RotateRows(x, +2) ───┐
input x ──────────┤                       ├─ Add ─ y
                  └─ RotateColumns(x) ────┘
```

输入、输出和两个分支结果都是二分量系数域密文。RotateRows 将每行槽位左移两格，
RotateColumns 交换两行。示例在 host 侧验证每个输出槽位以及密文的全部 RNS 系数。

## 构建与运行

```bash
cmake -S . -B build-seal -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build-seal -j --target hpu_bfv_rotation_example
./build-seal/hpu_bfv_rotation_example
```

默认使用便于快速运行的 `N=128` 参数。打印汇编或写出部署产物：

```bash
./build-seal/hpu_bfv_rotation_example --print-asm
./build-seal/hpu_bfv_rotation_example --emit-dir output/bfv_rotation_application
```

`--emit-dir` 输出 `.asm`、`.inst32`、`.cmd26`、生成的 `.h/.c` runtime wrapper、
`.resolved_dma.csv` 和 `.hpu_mem.u32.bin`。输出文件共享
`bfv_rotation_application` 前缀；二进制镜像只包含已使用的 HPU_MEM 行。

## 应用调用顺序

先用 modified-SEAL 生成 PublicKey、包含行旋转 `+2` 与换列 Galois element 的
GaloisKeys，并将输入加密。SecretKey 仅供 host 验证，不进入 HPU_MEM。接着在
`BfvApplicationImageBuilder` 中预制：

```cpp
image_builder.add_modulus_table();
auto canonical = image_builder.add_canonical_twiddles();
auto input = image_builder.add_ciphertext("input/x", encrypted);
auto constants = image_builder.add_keyswitch_constants("constants/keyswitch/top", level);
auto row_key = image_builder.add_row_rotation_key(
    "key/rotate_rows_2/top", galois_keys, 2, level);
auto column_key = image_builder.add_column_rotation_key(
    "key/rotate_columns/top", galois_keys, level);
auto row_twiddles = image_builder.add_row_rotation_twiddles(
    "rotate_rows_2/top", 2, level);
auto column_twiddles = image_builder.add_column_rotation_twiddles(
    "rotate_columns/top", level);
auto row_workspace = image_builder.reserve_ciphertext(
    "scratch/rotate_rows_2", level, 2,
    hpu::runtime::PolynomialDomain::coefficient, row_element);
auto column_workspace = image_builder.reserve_ciphertext(
    "scratch/rotate_columns", level, 2,
    hpu::runtime::PolynomialDomain::coefficient, column_element);
```

`row_element` 与 `column_element` 来自 `scheme/bfv/galois.hpp`。两个 workspace 的
`key_domain` 各自等于对应的 Galois element。每个 rotation 对两分量执行 canonical
NTT→modified-root INTT 得到 `sigma_k(c0), sigma_k(c1)`，随后使用 BFV rounded
KeySwitch 恢复常规密钥域；Add 因此可以直接合并两条分支。

```cpp
BfvOperationPlan plan(image_builder);
auto rows = plan.append_rotate_rows(
    "rotate_rows_2", input, 2, row_key, constants, row_twiddles,
    row_workspace, "intermediate/rows");
auto columns = plan.append_rotate_columns(
    "rotate_columns", input, column_key, constants, column_twiddles,
    column_workspace, "intermediate/columns");
auto output = plan.append_add("add", rows, columns, "output/y");
```

对同一计划调用 `lower_bfv_operation_plan`、`build_bfv_relocation_schedule`、
`lower_bfv_runtime_program` 和 `render_bfv_runtime_artifacts`，得到汇编、具体 HPU_MEM
span、编码指令及运行包装。示例要求每条 DMA 都有绑定，模表在整个计划中只装载一次，
末尾只发出一次 `psync`。

`BfvSoftwareExecutor` 从同一镜像执行两个 rotation 和 Add，不调用 SEAL Evaluator。
独立的 modified-SEAL oracle 用 `rotate_rows`、`rotate_columns` 和 `add` 计算相同表达式；
示例比较全部密文系数，并解密 oracle 对照手工槽位公式。该验证是软件功能验证，
裸机 HPU 执行仍需平台侧上传镜像、配置 DMA window 并运行生成的 wrapper。
