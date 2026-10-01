# HPU 仿 SEAL API 参考

本文件记录当前仓库中所有“仿 Microsoft SEAL”的对外 API，即那些在内部会
调用 `src/` 下、最终落到 HPU 指令（`padd`/`psub`/`pmul`/`pmac`/`pntt`/`pintt`/
`pmodld`/`pfree`/`psync`/`dload`/`dstore`）或对应软件执行语义的接口。

仿 SEAL API 分两条独立路径，分别对应两个 namespace：

| 层次 | namespace | 职责 | 对应 SEAL 概念 |
| --- | --- | --- | --- |
| host 侧 SEAL-facing | `hpu::seal_adapter` | 从 `SEALContext`/`Ciphertext`/`Plaintext`/`RelinKeys`/`GaloisKeys` 派生 HPU 布局、HPU_MEM 镜像，并做软件执行 | `SEALContext`、`Evaluator`、`KeyGenerator`、`NTT` |
| 指令生成（codegen） | `hpu::scheme::{ckks,bfv}` | 直接生成 HPU 汇编 body，内部复用 `operator`/`poly`/`util` 层 | `Evaluator::add/sub/multiply/rotate/rescale/...` |

---

## 1. HPU 指令集速查

所有仿 SEAL API 内部最终都落到下列 11 条指令（定义见
`include/util/hpu_asm.hpp`）：

| 指令 | 类型 | 语义 |
| --- | --- | --- |
| `dload` | custom1 | 从 HPU_MEM 搬运到对象槽位；`flag[0]=1` 分配到 small Bank 5 |
| `dstore` | custom1 | 对象槽位写回 HPU_MEM；当前 RTL 对 `rel=0/1` 都在 DMA 完成后释放对象，传输长度取 `OBJ.len` |
| `padd` | custom0 | 对象级逐点模加 |
| `psub` | custom0 | 对象级逐点模减 |
| `pmul` | custom0 | 对象级逐点模乘（或 `pmul imm` 整数乘） |
| `pmac` | custom0 | 对象级逐点乘加（乘积累加） |
| `pntt` | custom0 | 按 stage 的负循环前向 NTT（数据对象 + twiddle 对象） |
| `pintt` | custom0 | 按 stage 的负循环逆 NTT |
| `pmodld` | custom0 | 激活 small-bank 模上下文表项 |
| `pfree` | custom0 | 释放对象槽位 |
| `psync` | custom0 | 通知 CPU 整个 HPU 程序完成（仅程序末尾一次） |

---

## 2. host 侧 SEAL-facing API：`hpu::seal_adapter`

这一层不直接生成 HPU 汇编，而是以 SEAL 对象为输入，产出 HPU 可消费的
布局/镜像，或直接在 HPU_MEM 镜像上做软件执行。头文件位于
`include/hpu/seal/`，实现位于 `src/hpu/seal/`。

### 2.1 Context：仿 `seal::SEALContext`

`include/hpu/seal/ckks_context.hpp`

```cpp
struct CkksContextSpec {
    std::size_t poly_modulus_degree = 65536;
    std::vector<int> coeff_modulus_bits;   // 完整 key-context 模数列表
};
struct CkksContextBundle {
    std::shared_ptr<::seal::SEALContext> context;
    std::vector<std::uint32_t> data_moduli;
    std::vector<std::uint32_t> special_moduli;
};
CkksContextBundle create_ckks_context(const CkksContextSpec& spec);
```

- 约束：每个 q/P 素数必须能装入一个 uint32；`sec_level_type::none` 为功能路径。
- Q/P 划分不在此冻结，由 `SEALContext` 的 key/data context 链决定。

BFV 使用独立的 modified-SEAL context 工厂：

```cpp
struct BfvContextSpec {
    std::size_t poly_modulus_degree = 65536;
    std::vector<int> coeff_modulus_bits;   // data Q + 恰好一个 special P
    int plain_modulus_bits = 17;
};
struct BfvContextBundle {
    std::shared_ptr<::seal::SEALContext> context;
    std::vector<std::uint32_t> data_moduli;
    std::uint32_t special_modulus;
    std::uint32_t plain_modulus;
};
BfvContextBundle create_bfv_context(const BfvContextSpec& spec);
```

- 当前 HPU BFV profile 要求 Q/P/t 不超过 31 bit；32-bit 素数宽度保留给
  modified-SEAL 自动选择的 `B/m_sk` 辅助基。
- 要求 batching 可用，并以 `sec_level_type::none` 构造功能验证 context；这里不作
  生产安全性声明。

### 2.2 Level 描述：仿 SEAL 模数链

`include/hpu/seal/ckks_level.hpp`

```cpp
struct CkksLevelDescriptor {
    ::seal::parms_id_type parms_id;
    std::size_t chain_index;
    std::vector<std::uint32_t> q_moduli;
    std::vector<std::uint32_t> special_moduli;
    hpu::RnsDecompositionLayout rns_layout;          // 应用级全局 MOD_ID
    std::vector<std::size_t> evaluation_key_digit_indices;
    std::uint32_t q_last;
};

std::vector<CkksLevelDescriptor> create_ckks_level_descriptors(
    const ::seal::SEALContext& context);

class CkksLevelChain {
public:
    explicit CkksLevelChain(const ::seal::SEALContext&);

    std::size_t size() const noexcept;
    const std::vector<CkksLevelDescriptor>& levels() const noexcept;
    const CkksLevelDescriptor& top() const noexcept;
    const CkksLevelDescriptor& bottom() const noexcept;
    const CkksLevelDescriptor& at(std::size_t ordinal) const;
    const CkksLevelDescriptor& require(const ::seal::parms_id_type&) const;
    const CkksLevelDescriptor& require_chain_index(std::size_t) const;
    std::size_t ordinal(const ::seal::parms_id_type&) const;
    bool has_next(const ::seal::parms_id_type&) const;
    bool has_previous(const ::seal::parms_id_type&) const;
    const CkksLevelDescriptor& next(const ::seal::parms_id_type&) const;
    const CkksLevelDescriptor& previous(const ::seal::parms_id_type&) const;
    bool is_direct_successor(
        const ::seal::parms_id_type& source,
        const ::seal::parms_id_type& destination) const;
};
```

- 遍历从 `first_context_data()` 到单素数层的所有 data-context 节点。
- P 的 MOD_ID 保持全局固定（初始 Q 为 `[0..Qmax)`，P 为 `[Qmax..Qmax+P)`），
  即使低层 Q 变短也不重新编号。
- `CkksLevelChain` 的 ordinal 从 top level 的 0 开始递增；它不同于随着 Q
  逐层移除而递减的 SEAL `chain_index`。业务代码应通过 `next/previous`
  导航，不应依赖裸 `levels[i]`。
- 未知 `parms_id`、未知 `chain_index` 和越过 top/bottom 的迁移都会被拒绝。

#### 2.2.1 BFV Level 与全局模表

`include/hpu/seal/bfv_level.hpp`

```cpp
struct BfvLevelDescriptor {
    ::seal::parms_id_type parms_id;
    std::size_t chain_index;
    std::vector<std::uint32_t> q_moduli;
    std::uint32_t special_modulus;
    std::vector<std::uint32_t> b_moduli;
    std::uint32_t m_sk, plaintext_modulus;
    hpu::RnsDecompositionLayout keyswitch_layout;
    std::vector<int> b_mod_ids;
    int m_sk_mod_id, plaintext_mod_id;
    std::vector<std::size_t> evaluation_key_digit_indices;
    std::uint32_t q_last;
};
struct BfvLevelRegistry {
    std::size_t poly_modulus_degree;
    std::vector<std::uint32_t> modulus_table;
    std::vector<BfvLevelDescriptor> levels;
};
```

- `create_bfv_level_registry` 逐层读取 modified-SEAL 的真实 Q、`RNSTool::base_B()`、
  `m_sk` 和 t，不接收手工 `num_b/dnum`。
- 全局 MOD_ID 表以前缀 `Qmax|P` 开始，再追加所有 level 的 B/m_sk 并复用相同素数，
  t 最后登记；完整 union 必须不超过 64 项。
- 每层 KeySwitch 固定为 single-P、每个 active-Q 对应一个 singleton digit；P 在
  降 level 后不重新编号。
- `BfvLevelChain` 提供 `top/bottom/at/require/next/has_next`，未知或越界 level 直接
  拒绝。

#### 2.2.2 BFV 应用镜像

`include/hpu/seal/bfv_application_image.hpp`

```cpp
BfvApplicationImageBuilder builder(context, capacity_lines);
auto moduli = builder.add_modulus_table();
auto twiddles = builder.add_canonical_twiddles();
const auto &level = builder.level_chain().top();
auto input = builder.add_ciphertext("input/a", ciphertext);
auto add_plain = builder.add_add_subtract_plaintext(
    "plain/add", plaintext, level);
auto multiply_plain = builder.add_multiply_plaintext(
    "plain/multiply", plaintext, level);
auto output = builder.reserve_ciphertext("output/result", level);
auto relin = builder.add_relinearization_key("relin/top", keys, level);
auto ks = builder.add_keyswitch_constants("constants/keyswitch/top", level);
auto mul = builder.add_multiply_constants("constants/multiply/top", level);
auto mod_switch = builder.add_mod_switch_constants(
    "constants/mod_switch/top", level);
```

- 模表直接使用 `BfvLevelRegistry` 的全局 Q/P/B/`m_sk`/t MOD_ID；t 不生成 evaluator
  NTT twiddle。
- level-specific RelinKeys 只保留 active Q 与固定 P limb，每个 active-Q singleton
  digit 的顺序由 descriptor 决定。
- KeySwitch 镜像展开 Q→Q|P ModUp、Q|P 上的 `floor(P/2)` residue、P→Q BConv、
  `P^{-1} mod q` 和所需工作区。舍入数据全是只读 HPU 常量，不需要运行时比较或
  CPU 数值计算。
- Multiply 镜像展开 comparison-free BEHZ 所需的 Q→Bsk、t residue、
  `Q^{-1} mod Bsk`、B→Q/`m_sk`、`B^{-1} mod m_sk`、`m_sk`→Q 与 `-B mod Q`。
  同一 B 基的 qhat inverse 在 B→Q 与 B→`m_sk` 之间共享，不重复占用 HPU_MEM。
- ModSwitch 镜像为相邻 level 预制每个 source-Q limb 的 `floor(q_last/2)` residue、
  dropped-Q→retained-Q 单源 BConv 常量、`q_last^{-1} mod q_i` 和二分量工作区。
  这些对象足以在 HPU 上完成 rounded coefficient-domain drop-last，不需要运行时比较。
- builder 不接收 legacy `bfv_num_b/dnum`。未知 `parms_id` 会被拒绝；SecretKey
  从 API 和镜像中均不可见。
- BFV Ciphertext 保持 SEAL 的系数域 Q 表示并按 limb 打包；`reserve_ciphertext` 可为
  指定 level、分量数和域预留输出或中间对象。`register_bfv_rns_object` 将每个 limb
  的 level、MOD_ID、domain、key-domain 和 required-output 状态交给 runtime。
- plaintext 必须在建镜像时预制，且两种表示不能混用：
  `add_add_subtract_plaintext` 生成与 SEAL scaling variant 完全相同的系数域
  `Delta*m`；`add_multiply_plaintext` 生成中心提升至 Q 后的 canonical HPU NTT 表示。
  因而实际算子执行期间不做 host plaintext lift、缩放或 NTT。
- 当前 API 已完成参数、输入/输出对象、预制 plaintext、评估密钥与预计算常量镜像。

#### 2.2.3 BFV 基础算子 Planner 与重定位

`include/hpu/seal/bfv_operation_plan.hpp`、
`include/hpu/seal/bfv_operation_codegen.hpp`、
`include/hpu/seal/bfv_operation_relocation.hpp`

```cpp
BfvOperationPlan plan(builder);
auto sum = plan.append_add("add", left, right, "output/sum");
auto with_plain = plan.append_add_plain(
    "add_plain", sum, prepared_add_plain, "output/result");
auto product = plan.append_multiply_plain(
    "multiply_plain", left, prepared_multiply_plain, "output/product");
auto ciphertext_product = plan.append_multiply(
    "multiply", left, right, prepared_relin_key,
    prepared_keyswitch_constants, prepared_multiply_constants,
    "output/ciphertext_product");
auto switched = plan.append_mod_switch(
    "mod_switch", ciphertext_product, prepared_mod_switch_constants,
    "output/next_level");
auto rotated = plan.append_rotate_rows(
    "rotate_rows_2", left, 2, prepared_row_galois_key,
    prepared_keyswitch_constants, prepared_row_twiddles,
    prepared_row_workspace, "output/rotated");
auto swapped = plan.append_rotate_columns(
    "rotate_columns", left, prepared_column_galois_key,
    prepared_keyswitch_constants, prepared_column_twiddles,
    prepared_column_workspace, "output/swapped");
auto program = lower_bfv_operation_plan(plan, context);
auto relocation = build_bfv_relocation_schedule(
    program, builder.image(), context);
```

- 首层 planner 支持 Ciphertext Add/Subtract/Multiply、Negate、AddPlain/SubtractPlain、
  MultiplyPlain、ModSwitch、RotateRows 与 RotateColumns。
  所有输入与输出都必须是同一 `parms_id` 的二分量系数域 Q 密文；算子保持 level、
  component 数、输出 domain 和 `key_domain=1`。除显式 ModSwitch 外不会隐式降 level。
- AddPlain/SubtractPlain 只接受 builder 生成的只读系数域 `Delta*m` 对象；为
  MultiplyPlain 准备的 NTT plaintext 会被明确拒绝。运行时仅执行 `padd/psub`，不做
  host plaintext 缩放或系数计算。
- MultiplyPlain 只接受中心提升后的 canonical HPU NTT plaintext。对密文的每个
  component/Q limb，lowering 显式执行 canonical NTT、`pmul` 和 INTT，结果恢复为
  BFV 系数域；pre-twist、正逆 stage twiddle 与 post-scale 都由 relocation 绑定到
  builder 预制的只读 HPU_MEM 对象，不存在 CPU 计算回退。
- Ciphertext Multiply 接收同 level 的两个二分量系数域密文，并要求同 level 的
  `PreparedEvaluationKey`、`PreparedKeySwitchConstants` 与
  `PreparedBfvMultiplyConstants`。lowering 生成 comparison-free BEHZ 与 rounded
  single-P relinearization 的融合流，输出仍为二分量系数域密文。BEHZ 输入扩基、tensor、
  FastFloor、branchless SK 和 KeySwitch 的全部中间多项式都由 builder 预留，relocation
  逐条绑定；三分量 tensor 不暴露给 host，也不存在 CPU 同步或数值回退。
- ModSwitch 只接受存在相邻下一层的二分量系数域密文。它按 modified-SEAL 的
  `divide_and_round_q_last_inplace` 语义先加 `floor(q_last/2)`，再用单源 BConv 和
  `q_last^{-1}` 完成 rounded drop-last；输出被 planner 注册到下一 `parms_id`。
  Multiply→ModSwitch 可作为同一计划一次 lowering、relocation 和 runtime 物化。
- RotateRows/RotateColumns 使用预制的 active-Q GaloisKey、canonical NTT twiddle、
  与 Galois element 匹配的 modified-root INTT twiddle，以及
  `{domain=coefficient,key_domain=k}` 的二分量 workspace。每个输入 Q limb 执行
  canonical NTT→modified-root INTT，形成 `sigma_k(c0),sigma_k(c1)`；然后用 BFV
  rounded single-P KeySwitch 恢复 `key_domain=1`。输出保持系数域和原 level。
  planner 校验 workspace、twiddle 和 level；relocation 绑定所有 DMA，整个计算没有
  CPU 系数运算。正向/负向行旋转和换列均与 modified-SEAL 逐系数对拍。
- lowering 为整个计划只装载一次 small-bank 模表、在末尾只发出一次 `psync`。
  relocation 按生成汇编中每条 `dload/dstore` 的顺序绑定具体 HPU_MEM limb，并拒绝
  shape、level、domain、只读属性或 DMA ABI 不匹配的对象。
- `include/hpu/seal/bfv_operation_runtime.hpp` 将完整 relocation schedule 与汇编一起
  物化为 `BfvRuntimeProgram`，逐条复核编码后的 custom1。`render_bfv_runtime_artifacts`
  输出固定指令字、resolved span 数组、`hpu_run_<stem>()` 包装和带 BFV operation/
  allocation provenance 的 CSV；任何不完整 schedule、编码字段漂移或越界 span 都会被拒绝。
- `include/hpu/seal/bfv_software_executor.hpp` 提供 HPU_MEM 功能执行层。当前可执行
  Add/Subtract/Negate、AddPlain/SubtractPlain、MultiplyPlain、融合
  Multiply/Relinearize、ModSwitch、RotateRows 和 RotateColumns。MultiplyPlain 消费预制的 canonical HPU NTT
  plaintext 与 twiddle，完成系数域→NTT→逐点乘法→系数域；Ciphertext Multiply
  直接复现 no-SMRQ BEHZ、FastFloor、branchless-SK 和 rounded single-P KeySwitch。
  所有路径读取 builder 预制资源，不调用 `seal::Evaluator`。
- BFV application image 的 `add_row_rotation_key/twiddles` 与
  `add_column_rotation_key/twiddles` 按 SEAL generator-3 batching 约定，把预定步长映射
  为 Galois element，并准备 active-Q GaloisKey 和 `psi^(1/k)` modified-root INTT 表。
  资源转换支持任意合法 `k`；顶层行旋转 API 接受预定的非零步长。

#### 2.2.4 CKKS 操作元数据规则

`include/hpu/seal/ckks_metadata.hpp`

```cpp
struct CkksValueMetadata {
    ::seal::parms_id_type parms_id;
    std::size_t chain_index;
    double scale;
};

CkksValueMetadata infer_ckks_preserving_metadata(
    const CkksLevelChain&, const CkksValueMetadata& input);
CkksValueMetadata infer_ckks_add_sub_metadata(
    const CkksLevelChain&, const CkksValueMetadata& left,
    const CkksValueMetadata& right);
CkksValueMetadata infer_ckks_multiply_metadata(
    const CkksLevelChain&, const CkksValueMetadata& left,
    const CkksValueMetadata& right);
CkksValueMetadata infer_ckks_rescale_metadata(
    const CkksLevelChain&, const CkksValueMetadata& input);
```

- 保持型操作（Negate、Relinearize、Rotate、NTT/INTT）保持 level 与 scale。
- Add/Sub 要求两个输入位于同一 level 且 scale 在相对误差内匹配。
- Multiply 保持 level，并把输出 scale 推导为两个输入 scale 的乘积。
- Rescale 只能迁移到直接下一层，输出 scale 为 `input.scale / q_last`。
- 每个输入都会同时校验 `parms_id`、`chain_index` 和有限正 scale；底层
  Rescale、跨层运算、scale 不匹配及乘法 scale 溢出都会在分配或执行前拒绝。
- 这里只管理元数据，不自动插入 Rescale，也不改变算子的数学/表示域路径。

#### 2.2.5 BGV 单次 ModSwitch 应用包

`include/hpu/seal/bgv_modswitch_application.hpp`

```cpp
auto program = build_bgv_modswitch_application(context, ciphertext, capacity_lines);
auto artifacts = render_bgv_modswitch_runtime_artifacts("bgv_modswitch", program);
```

- 要求 modified-SEAL 的 NTT 域 BGV 密文及直接下一层；全局模表按 `Qmax|P|t`
  固定，降层后 `t` 的 MOD_ID 不变。输入经系数域桥转换为 canonical HPU NTT，
  密文、twiddle、三个常量族、`c_last/u_t` 工作区及输出均装入 HPU_MEM。
- `program.instructions` 包含可编码的完整单次操作流，`program.dma` 与
  `program.spans()` 按 custom1 顺序给出 resolved 绑定；构建时逐条检查对象号、
  load/store 类型、字数、只读属性和 span。渲染产生固定指令字、span 数组、
  `hpu_run_<stem>()` 包装及 resolved DMA manifest。
- `program.destination_parms_id` 与 `program.correction_factor` 是 host 元数据。
  两级逐 limb 与 HPU 物理 NTT 差分已对齐 modified-SEAL；目前不支持 BGV
  多算子组合计划，也未完成逐指令软件执行或实体 HPU 测试。

#### 2.2.6 BGV 单次 KeySwitch / Relinearize 应用包

`include/hpu/seal/bgv_keyswitch_application.hpp`

```cpp
auto program = build_bgv_keyswitch_application(
    context, three_component_product, relin_keys, capacity_lines);
auto artifacts = render_bgv_keyswitch_runtime_artifacts("bgv_relin", program);
```

- 要求 modified-SEAL 的三分量 NTT 域 BGV 乘积和同一 key context 的
  `RelinKeys`。当前入口仅执行 Relinearize，不包含前置密文乘法或 Galois 自同构。
- 全局 MOD_ID 固定为 `Qmax|P|t`；降层只缩短 active Q，P/t 不重编号。密文和
  evaluation key 通过表示桥变换到 canonical HPU NTT，模表、双向 twiddle、
  `-P^-1 mod t`、`P mod q_i`、`P^-1 mod q_i` 和全部工作区都在 HPU_MEM 中。
- `program.dma`/`program.spans()` 与编码 custom1 逐条对应；渲染产物含固定
  指令字、resolved span 数组、`hpu_run_<stem>()` 入口和 DMA manifest。
  `parms_id` 与 `correction_factor` 保持原产品的 host 元数据，不经 PE 更新。
- 顶层和降一级的镜像内容已在 HPU 物理 NTT 数学模型中与 modified-SEAL
  Relinearize 逐 limb 对齐；尚无逐指令软件执行或实体 HPU 运行证据。
- `estimate_bgv_keyswitch_image_lines(N, active_q, key_modulus_count)` 给出当前
  all-resident 布局的精确容量，并在构建前检查 `capacity_lines`。例如
  `N=65536,Q=3,P=1` 需 136193 个 256B line，超过旧的 65536-line 软件 profile；
  若平台允许更大的 HPU_MEM window，可直接按估计值或以上配置，而无需为这一步
  引入分段调度。目标 `N=65536,Q=3,P=1` 的真实镜像已按 136193 line 构建，
  475 个 DMA 绑定和 runtime manifest 均通过软件检查；这不替代实体 DMA/window 验证。

#### 2.2.7 BGV 连续 Multiply+Relinearize 应用包

`include/hpu/seal/bgv_keyswitch_application.hpp`

```cpp
const auto lines = estimate_bgv_multiply_relinearize_image_lines(
    degree, active_q_count, key_modulus_count);
auto program = build_bgv_multiply_relinearize_application(
    context, left, right, relin_keys, lines);
auto artifacts = render_bgv_keyswitch_runtime_artifacts("bgv_multiply_relin", program);
```

- 输入为同 level 的两个二分量 modified-SEAL BGV NTT 密文；构建器将输入与
  evaluation key 准备为 canonical HPU NTT。三分量乘积在镜像里只预留可写
  span，不由 CPU 或 SEAL 预计算。`CMULT` 写入这些 span，KeySwitch 随即读取；
  中间无 `psync`、host copy 或 window 切换。
- 完整流只有一次模表加载与末尾 `psync`。`parms_id` 保持原 level，
  `correction_factor` 在 host 更新为两输入因子的乘积模 `t`。
- `N=65536,Q=3,P=1` 的实际镜像占 148481 个 256B line，包含 508 个
  resolved DMA 绑定。顶层及降一级 tensor 与 modified-SEAL 差分一致，
  KeySwitch 后缀与独立运行包逐条一致；尚无实体 HPU 执行证据。

#### 2.2.8 BGV 单次密文和明文算术应用包

`include/hpu/seal/bgv_arithmetic_application.hpp`

```cpp
auto add = build_bgv_add_application(context, left, right, capacity_lines);
auto sub = build_bgv_subtract_application(context, left, right, capacity_lines);
auto neg = build_bgv_negate_application(context, left, capacity_lines);
auto add_plain = build_bgv_add_plain_application(context, left, plain, capacity_lines);
auto sub_plain = build_bgv_subtract_plain_application(context, left, plain, capacity_lines);
auto mul_plain = build_bgv_multiply_plain_application(context, left, plain, capacity_lines);
auto artifacts = render_bgv_arithmetic_runtime_artifacts("bgv_add", add);
```

- 输入为同 level 的二分量 BGV NTT 密文。不同 `correction_factor` 的
  Add/Sub 按 modified-SEAL 的平衡规则准备标量 splat，HPU 以 `PMUL`
  缩放各 limb 后执行 `PADD/PSUB`；host 只保留输出 factor 元数据。
- 每个包含固定 `Qmax|P|t` 模表、canonical HPU NTT 输入、输出和逐条
  resolved DMA；不执行 CPU 密文加减或缩放。Negate 保持 factor 不变。
- 已对顶层、降一级和不同 factor 组合做 modified-SEAL 逐 limb 差分；
  尚无逐指令软件执行或实体 HPU 验证。
- 明文输入须为有效的系数域 BGV `Plaintext`。构建镜像时将其预制为
  canonical HPU NTT；AddPlain/SubPlain 先按密文 factor 模 `t` 缩放明文，
  然后由 HPU 只更新 `c0` 并复制 `c1`。MultiplyPlain 对两个密文分量
  做 `PMUL`，factor 保持不变。顶层及降一级已与 modified-SEAL 差分。

#### 2.2.9 BGV 单次行旋转与列交换应用包

`include/hpu/seal/bgv_keyswitch_application.hpp`

```cpp
auto rows = build_bgv_rotate_rows_application(context, ciphertext, galois_keys,
                                              steps, capacity_lines);
auto columns = build_bgv_rotate_columns_application(context, ciphertext,
                                                    galois_keys, capacity_lines);
auto lines = estimate_bgv_rotation_image_lines(degree, active_q_count,
                                               key_modulus_count);
auto artifacts = render_bgv_keyswitch_runtime_artifacts("bgv_rows", rows);
```

- 要求 batching、二分量 BGV NTT 密文及对应的 Galois key。行旋转使用
  非零有符号步长，列交换对应 `X -> X^(2N-1)`。当前单次包只执行一个
  Galois 元素；不自动合成缺失密钥的多步旋转。
- HPU 以改根 INTT 实现自同构、canonical NTT 返回密文表示，再在同一
  指令流中执行 BGV Galois KeySwitch；不通过 CPU 计算旋转后密文。
  `parms_id` 与 `correction_factor` 保持不变，只有末尾一次 `psync`。
- 正/负行步长及列交换在顶层和降一级与 modified-SEAL 逐 limb 差分；
  `N=65536,Q=3,P=1` 估算需 169985 个 256B line。尚无逐指令软件
  执行或实体 HPU 验证。

#### 2.2.10 BGV 跨 level 线性操作计划

`include/hpu/seal/bgv_linear_operation_plan.hpp`

```cpp
BgvLinearOperationPlan plan(context, encrypted);
plan.append_add("mix_ciphertext", another_ciphertext);
plan.append_add_plain("add_bias", bias);
plan.append_multiply_plain("multiply_polynomial", multiplier);
plan.append_subtract("subtract_ciphertext", another_ciphertext);
plan.append_multiply("multiply_ciphertext", another_ciphertext, relin_keys);
plan.append_rotate_rows("rotate_left_1", 1, galois_keys);
plan.append_modswitch_to_next("drop_level");
plan.append_rotate_columns("swap_rows", galois_keys);
plan.append_subtract_plain("subtract_offset", offset);
auto package = plan.lower(capacity_lines);
auto runtime = render_bgv_keyswitch_runtime_artifacts("bgv_plain_chain", package);
```

- `BgvLinearOperationPlan` 是原 `BgvPlainOperationPlan` 的语义化别名。
  计划接受二分量 BGV NTT 密文，并支持预制明文 Add/Sub/Multiply、
  密文 Add/Sub、`append_multiply`（含重线性化）、行旋转、列交换及显式
  `append_modswitch_to_next`。
  追加密文操作时，右操作数必须处于计划当前 level。
- 密文 Add/Sub 遇到不同 `correction_factor` 时逐步求平衡标量，
  由 HPU `PMUL` 缩放并 `PADD/PSUB`。输出 factor 会更新；其后的
  AddPlain/SubPlain 按更新后的 factor 模 `t` 预制明文。MultiplyPlain
  不改变 factor。
- 降低后只有一次模表加载和末尾一次 `psync`；每步的输出 HPU_MEM span
  是下一步的输入 DMA span，没有 CPU 中间密文计算或复制。
- 旋转重定位已验证的单次 Galois 包：改根 twiddle、Galois key、KeySwitch
  工作区分别归属该步骤，输入绑定前一步输出；旋转保持 level 与 factor。
  多个旋转步骤在同一镜像中有独立资源命名。
- ModSwitch 重定位单次 NTT 包，输出少一个 Q limb，随后按新 level
  预制明文及旋转资源；`parms_id` 和 `correction_factor` 与 modified-SEAL
  同步推进。模表仍只加载一次，所有步骤共用一个 HPU_MEM 与末尾同步。
- 密文乘法重定位单次 `CMULT -> KeySwitch` 包：左输入绑定前一步输出，
  右输入与 relinearization key 预制在镜像中，三分量 tensor 保持为 HPU
  生成并由后续 KeySwitch 读取的可变 span。乘法后的 factor 按模 `t`
  更新，可接 ModSwitch、明文操作或下一次乘法。未引入 CPU 中间密文计算。
- `examples/bgv_plain_chain_application.cpp` 展示
  `((x + 3) * (2x + 1)) - 5`。运行
  `./build-seal/hpu_bgv_plain_chain_example`；加 `--print-dma` 可查看
  resolved DMA manifest。示例逐步与 modified-SEAL 差分；降一级的
  非平凡 factor、密文 Add/Sub 与后继 AddPlain 的组合另有测试。
  `./build-seal/hpu_bgv_rotate_chain_example` 演示
  `RotateRows(x + 3, 1) + 5`；计划测试还覆盖连续行旋转与列交换。
  `./build-seal/hpu_bgv_multiply_chain_example` 演示
  `ModSwitch((x + 5) * multiplier) + 7`，可用 `--print-dma` 查看重定位后的 span。
  计划测试另覆盖两次连续跨 level ModSwitch，以及两次密文乘法、
  中间 ModSwitch 与后继明文操作；尚未经过逐指令
  软件执行或实体 HPU 验证。

完整 plan 在交付包生成阶段还会由 `BgvSoftwareExecutor` 从同一初始
`HpuMemImage` 执行。它读取准备好的 operand、key、常量和 twiddle，逐步写回每个
output/workspace，并将每一步 canonical HPU NTT word 与独立 SEAL oracle 比较。

### 2.3 NTT 表示桥：仿 SEAL NTT 表示转换

`include/hpu/seal/ntt_bridge.hpp`

```cpp
struct HpuRnsPolynomial {
    std::size_t degree;
    std::vector<std::uint32_t> moduli;
    std::vector<std::uint8_t> modulus_ids;
    std::vector<std::uint32_t> words;   // [modulus][coefficient]，HPU 物理 NTT 序
};

HpuRnsPolynomial ciphertext_component_to_hpu(const ::seal::Ciphertext&, std::size_t component,
                                             const ::seal::SEALContext&);
HpuRnsPolynomial ciphertext_component_to_hpu(const ::seal::Ciphertext&, std::size_t component,
                                             const ::seal::SEALContext&,
                                             const std::vector<std::size_t>& modulus_indices);
HpuRnsPolynomial plaintext_to_hpu(const ::seal::Plaintext&, const ::seal::SEALContext&);
std::vector<std::uint64_t> hpu_to_seal_ntt(const HpuRnsPolynomial&,
                                           ::seal::parms_id_type,
                                           const ::seal::SEALContext&);
```

- 转换故意经由系数域（SEAL `inverse_ntt_negacyclic_harvey` → 系数 → HPU 负循环
  模型），因此不假设 SEAL 与 HPU 的求值点顺序一致。
- `hpu_to_seal_ntt` 是逆桥，供差分测试与结果回导使用。

### 2.4 评估密钥：仿 `seal::RelinKeys` / `seal::GaloisKeys`

`include/hpu/seal/evaluation_key.hpp`

```cpp
struct HpuKeySwitchDigit {
    HpuRnsPolynomial key_component_0;
    HpuRnsPolynomial key_component_1;
};
std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(const ::seal::RelinKeys&,
                                                          const ::seal::SEALContext&);
std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(const ::seal::RelinKeys&,
                                                          const ::seal::SEALContext&,
                                                          const CkksLevelDescriptor&);
std::vector<HpuKeySwitchDigit> galois_key_to_hpu(const ::seal::GaloisKeys&,
                                                 std::uint32_t galois_element,
                                                 const ::seal::SEALContext&);
std::vector<HpuKeySwitchDigit> galois_key_to_hpu(const ::seal::GaloisKeys&,
                                                 std::uint32_t galois_element,
                                                 const ::seal::SEALContext&,
                                                 const CkksLevelDescriptor&);
```

- digit 数量与 Q|P 形状完全由 SEAL 决定，不写死旧 demo 的 `P=3`/`dnum=2`。
- **不接收、不保存 `SecretKey`**，秘密材料不会经此进入 HPU_MEM。

### 2.5 融合自同构表：仿 modified-root NTT 表

`include/hpu/seal/automorphism.hpp`

```cpp
struct FusedInverseAutomorphismTables {
    std::uint32_t modulus, canonical_psi, modified_psi;
    std::vector<std::vector<std::uint32_t>> stages;
    std::vector<std::uint32_t> post_untwist_scale;
};
std::vector<FusedInverseAutomorphismTables> create_fused_inverse_automorphism_tables(
    ::seal::parms_id_type parms_id, std::uint32_t galois_element,
    const ::seal::SEALContext& context);
```

- 为 `parms_id` 处每个活跃数据模数生成 `NTT_psi → INTT_{psi^(1/k)} → a(X^k)`
  的 modified-root 表；调用方把 payload 预加载到 HPU_MEM 并绑定 fused INTT 的 p3 dload。

### 2.6 应用镜像构建：仿加密对象/密钥/常量的 HPU_MEM 打包

`include/hpu/seal/application_image.hpp`

```cpp
class CkksApplicationImageBuilder {
public:
    CkksApplicationImageBuilder(const ::seal::SEALContext& context, std::uint64_t capacity_lines);

    hpu::runtime::HpuMemSpan add_modulus_table();
    std::vector<PreparedCanonicalTwiddles> add_canonical_twiddles();
    PreparedRnsObject add_ciphertext(std::string id, const ::seal::Ciphertext&);
    PreparedRnsObject add_plaintext(std::string id, const ::seal::Plaintext&);
    PreparedEvaluationKey add_relinearization_key(std::string id, const ::seal::RelinKeys&,
                                                  const CkksLevelDescriptor&);
    PreparedKeySwitchConstants add_keyswitch_constants(std::string id, const CkksLevelDescriptor&);
    PreparedRescaleConstants add_rescale_constants(std::string id, const CkksLevelDescriptor&);
    PreparedEvaluationKey add_galois_key(std::string id, const ::seal::GaloisKeys&,
                                         std::uint32_t galois_element, const CkksLevelDescriptor&);
    PreparedEvaluationKey add_rotation_key(std::string id, const ::seal::GaloisKeys&,
                                           int steps, const CkksLevelDescriptor&);
    PreparedEvaluationKey add_conjugation_key(std::string id, const ::seal::GaloisKeys&,
                                              const CkksLevelDescriptor&);
    std::vector<PreparedFusedAutomorphismTwiddles>
        add_fused_automorphism_twiddles(std::string id, std::uint32_t galois_element,
                                        const CkksLevelDescriptor&);
    std::vector<PreparedFusedAutomorphismTwiddles>
        add_rotation_twiddles(std::string id, int steps, const CkksLevelDescriptor&);
    std::vector<PreparedFusedAutomorphismTwiddles>
        add_conjugation_twiddles(std::string id, const CkksLevelDescriptor&);
    PreparedRnsObject reserve_ciphertext(std::string id, const CkksLevelDescriptor&,
                                         std::size_t component_count, double scale,
                                         hpu::runtime::PolynomialDomain domain = ...,
                                         std::uint64_t key_domain = 1);
    PreparedRnsObject reserve_ciphertext(std::string id, const CkksValueMetadata&,
                                         std::size_t component_count,
                                         hpu::runtime::PolynomialDomain domain = ...,
                                         std::uint64_t key_domain = 1);
    const hpu::runtime::HpuMemImage& image() const noexcept;
    const CkksLevelChain& level_chain() const noexcept;
    const std::vector<CkksLevelDescriptor>& levels() const noexcept;
};

void register_rns_object(hpu::runtime::Application& application,
                         const PreparedRnsObject& object, bool required_output);
```

- 每个 RNS limb 是独立 256B 行对齐分配；`N=65536` 时每个 limb 恰好 1024 行，
  自然映射为一个 regular-bank 常驻对象。
- 推荐把 `infer_ckks_*_metadata` 的结果直接交给 metadata overload，避免调用方
  手工组合下一层 `parms_id` 和 scale；descriptor + scale overload 继续保留兼容。
- `add_keyswitch_constants` 同时写入紧凑 `KSW1` 软件执行记录，以及 generic
  Relinearize codegen 所需的多项式级 ModUp/ModDown BConv 常量、P inverse 和可复用
  Q|P workspace；`PreparedKeySwitchConstants` 记录硬件资源前缀与常量/workspace 数量。
- `add_rescale_constants` 同样保留紧凑 `RSC1` 记录，并展开每个 source-Q 的 half、
  dropped-Q→retained-Q BConv、`q_last` inverse，以及两分量 rounded/correction
  workspace。
- `register_rns_object` 把每个 limb 注册为独立对象，跨 kernel 驻留决策留给
  `hpu::runtime::Application`。

#### 2.6.1 显式操作计划

`include/hpu/seal/operation_plan.hpp`

```cpp
CkksOperationPlan plan(image_builder);
auto sum = plan.append_add("add", left, right, "output/sum");
auto difference = plan.append_subtract(
    "subtract", left, right, "output/difference");
auto product_tensor = plan.append_multiply(
    "multiply", left, right, "intermediate/product_tensor");
auto scaled = plan.append_multiply_plain(
    "multiply_plain", left, encoded_weight, "output/scaled");
auto tensor = plan.append_square("square", input, "intermediate/tensor");
auto relin = plan.append_relinearize(
    "relinearize", tensor, relinearization_key, keyswitch_constants,
    "intermediate/relinearized");
auto rescaled = plan.append_rescale(
    "rescale", relin, rescale_constants, "intermediate/rescaled");
auto output = plan.append_add_plain(
    "add_one", rescaled, encoded_one, "output/x2_plus_one");
auto shifted = plan.append_subtract_plain(
    "subtract_bias", output, encoded_bias, "output/shifted");
auto negative = plan.append_negate(
    "negate", shifted, "output/negative");
auto rotated = plan.append_rotate_slots(
    "rotate_left_2", input, 2, rotation_key, keyswitch_constants,
    rotation_twiddles, rotation_workspace, "output/rotate_left_2");
auto conjugated = plan.append_conjugate(
    "conjugate", input, conjugation_key, keyswitch_constants,
    conjugation_twiddles, conjugation_workspace, "output/conjugate");
```

- 每一步都显式给出；`append_multiply` 只生成三分量 tensor，plan 不会自动插入
  Relinearize 或 Rescale。
- 输出由前一步 metadata 推导后直接在同一个 `HpuMemImage` 中分配；输入对象的
  allocation ID/span 也必须属于该 image。
- Relinearize 会绑定并校验当前 level 的 evaluation key、KeySwitch 常量和
  canonical twiddle 需求；Rescale 会绑定相邻 level 的常量和 twiddle 需求。
- Rotate/Conjugate 会验证 Galois element、对应 evaluation key、modified-root fused
  INTT 表、canonical NTT 表以及 `{domain=coefficient,key_domain=k}` workspace；不同
  Galois element 的 key、twiddle 或 workspace 不能混用。
- `steps()` 保留有序的输入/输出 metadata、组件数、表示域和资源 ID，供下一阶段
  的 codegen/runtime lowering 使用。目前覆盖 Add/Subtract、Multiply/MultiplyPlain、
  AddPlain/SubtractPlain、Negate、Square、Relinearize、Rescale、Rotate 和 Conjugate。

`include/hpu/seal/operation_codegen.hpp`

```cpp
CkksLoweredProgram lowered = lower_ckks_operation_plan(
    plan, context, /* append_psync=*/true,
    /* manage_modulus_table=*/true);
```

- lowering 按每个 step 的输入 level 选择已有 kernel：基础算术选择对应 pointwise
  body，Multiply/Square→CMULT tensor，Relinearize→standalone NTT Relinearize，
  Rescale→standalone NTT Rescale，Rotate/Conjugate→fused automorphism + Galois
  KeySwitch + canonical output NTT。
- `CkksLoweredProgram::operations` 保留 step 与各自 body 的一一映射，供后续 DMA
  relocation backend 绑定对象和资源 ID；`body_asm` 是按原顺序拼接的完整程序。
- 嵌套 kernel 不加载/释放模表也不发 `psync`，完整程序默认只在外层管理一次。
- 当前不做跨 step 的 NTT/INTT 或 dstore/dload 融合，因此比专用复合 Multiply
  kernel 更长；这是后续优化点，不影响显式计划和 CKKS 语义。

`include/hpu/seal/operation_relocation.hpp`

```cpp
CkksRelocationSchedule schedule = build_ckks_relocation_schedule(
    lowered, image_builder.image(), context);
```

- 每条已解析记录同时保存 program/operation 内 DMA 序号、DLOAD/DSTORE 参数、
  allocation ID 和 `HpuMemSpan`；runtime 可按 `program_dma_index` 在发指令前把
  `line_offset/line_count` 装入 `x10/x11`。
- resolver 会解析实际生成的 assembly，并逐条核对方向、对象槽、load type/bank
  flag 或 store release；codegen 和 relocation 配方发生漂移时立即报错。
- 当前模表及所有 planner operation 均已完整解析。Relinearize 覆盖前后
  NTT/INTT twiddle、逐 digit ModUp、evaluation-key 乘加、P→Q ModDown、base merge
  及所有 workspace；Rescale 覆盖 half、单源 BConv、inverse、跨 level 输出及前后
  transform；Rotate/Conjugate 覆盖 fused INTT、coefficient workspace、Galois key、
  KeySwitch workspace 和输出 NTT。由标准 image builder 构造的计划满足
  `schedule.complete()`。
- 只有 `unresolved_operations` 为空且绑定数等于 `expected_dma_count` 时，
  `schedule.complete()` 才返回 true。

`include/hpu/seal/operation_runtime.hpp`、
`include/hpu/seal/bfv_operation_runtime.hpp`

```cpp
CkksRuntimeProgram runtime = lower_ckks_runtime_program(lowered, schedule);
CkksRuntimeArtifacts artifacts = render_ckks_runtime_artifacts(
    "ckks_x2_plus_one", runtime, image_builder.image().capacity_lines());

BfvRuntimeProgram bfv_runtime = lower_bfv_runtime_program(
    bfv_lowered, bfv_schedule);
BfvRuntimeArtifacts bfv_artifacts = render_bfv_runtime_artifacts(
    "bfv_fused_multiply", bfv_runtime, bfv_builder.image().capacity_lines());
```

- runtime lowering 通过公共 assembler 生成 `EncodedInstruction`，执行 object lifetime
  校验，再把 encoder 识别出的每条 custom1 与 schedule 的方向、p 槽、type/release、
  flag 和 DMA 序号逐项比较。
- `runtime.spans()` 按 custom1 消费顺序返回 `{line_offset,line_count}`；两者分别在
  指令前绑定到 `x10/x11`。
- artifacts 包含声明 `hpu_run_<stem>()` 的 header、固定 instruction word 加 resolved
  span 数组的 source，以及同时记录 operation/allocation provenance 和编码信息的 CSV。
- renderer 要求每个 span 非零、落在给定 HPU_MEM 容量内，并符合当前
  `hpu_dma_span_t` 的 uint32 地址 ABI。

### 2.7 软件执行器：仿 `seal::Evaluator`

CKKS、BFV、BGV 分别使用 `software_executor.hpp`、`bfv_software_executor.hpp`、
`bgv_software_executor.hpp`。
在 `HpuMemImage` 之上做功能执行，**不调用 `seal::Evaluator`**；SEAL 仅作为差分 oracle。

```cpp
class CkksSoftwareExecutor {
public:
    CkksSoftwareExecutor(const ::seal::SEALContext& context,
                         const hpu::runtime::HpuMemImage& image);

    void add(const PreparedRnsObject& l, const PreparedRnsObject& r, const PreparedRnsObject& o);
    void subtract(const PreparedRnsObject& l, const PreparedRnsObject& r, const PreparedRnsObject& o);
    void multiply_plain(const PreparedRnsObject& ct, const PreparedRnsObject& pt, const PreparedRnsObject& o);
    void add_plain(const PreparedRnsObject& ct, const PreparedRnsObject& pt, const PreparedRnsObject& o);
    void subtract_plain(const PreparedRnsObject& ct, const PreparedRnsObject& pt, const PreparedRnsObject& o);
    void negate(const PreparedRnsObject& ct, const PreparedRnsObject& o);
    void square(const PreparedRnsObject& ct, const PreparedRnsObject& tensor_o);
    void multiply(const PreparedRnsObject& l, const PreparedRnsObject& r, const PreparedRnsObject& tensor_o);
    void key_switch(const PreparedRnsObject& base, const PreparedRnsObject& switching,
                    const PreparedEvaluationKey& ek, const PreparedKeySwitchConstants& c,
                    const PreparedRnsObject& o, const std::vector<PreparedCanonicalTwiddles>& t);
    void relinearize(const PreparedRnsObject& tensor, const PreparedEvaluationKey& rlk,
                     const PreparedKeySwitchConstants& c, const PreparedRnsObject& o,
                     const std::vector<PreparedCanonicalTwiddles>& t);
    void rescale(const PreparedRnsObject& in, const PreparedRescaleConstants& c,
                 const PreparedRnsObject& o, const std::vector<PreparedCanonicalTwiddles>& t);
    void rotate(const PreparedRnsObject& in, std::uint32_t galois_element,
                const PreparedEvaluationKey& gk, const PreparedKeySwitchConstants& c,
                const std::vector<PreparedFusedAutomorphismTwiddles>& fused_t,
                const std::vector<PreparedCanonicalTwiddles>& canonical_t,
                const PreparedRnsObject& coeff_ws, const PreparedRnsObject& o);
    void rotate_slots(const PreparedRnsObject& in, int steps, ...);   // 正步左旋/负步右旋
    void conjugate(const PreparedRnsObject& in, ...);                  // galois = 2N-1
    void forward_ntt(const PreparedRnsObject& coeff, const PreparedRnsObject& ntt,
                     const std::vector<PreparedCanonicalTwiddles>& t);
    void inverse_ntt(const PreparedRnsObject& ntt, const PreparedRnsObject& coeff,
                     const std::vector<PreparedCanonicalTwiddles>& t);
    HpuRnsPolynomial export_component(const PreparedRnsObject& object, std::size_t component) const;
    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;
};

class BgvSoftwareExecutor {
public:
    BgvSoftwareExecutor(const ::seal::SEALContext& context,
                        const hpu::runtime::HpuMemImage& image);
    void execute(const BgvLinearOperationPlan& plan);
    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;
};
```

`BgvSoftwareExecutor::execute` 覆盖明文/密文算术、行旋转、列交换、
Multiply+Relinearize 和 ModSwitch。它按 plan 的 allocation edge 执行整图，并消费
镜像中的 canonical/fused NTT twiddle、evaluation key 和 BGV correction 常量。

**SEAL 等价关系**（用于逐字比对）：

| 执行器方法 | seal::Evaluator 对应 |
| --- | --- |
| `add` | `add` |
| `subtract` | `sub` |
| `multiply_plain` | `multiply_plain` |
| `add_plain` | `add_plain` |
| `subtract_plain` | `sub_plain` |
| `negate` | `negate` |
| `square` | `square` |
| `multiply` | `multiply`（张量积 t0/t1/t2） |
| `relinearize` | `relinearize` |
| `rescale` | `rescale_to_next` |
| `rotate` / `rotate_slots` / `conjugate` | `apply_galois` |

**内部落地的 HPU 语义**（`src/hpu/runtime/software_executor.cpp` 的 `HpuSoftwareExecutor`）：

| 运行时方法 | 对应 HPU 指令语义 |
| --- | --- |
| `pointwise(..., add)` | `padd` |
| `pointwise(..., subtract)` | `psub` |
| `pointwise(..., multiply)` | `pmul` |
| `multiply_accumulate(...)` | `pmac` |
| `read`/`write`/`copy` | `dload`/`dstore` |
| `load_modulus_table`/`modulus` | `pmodld`（small-bank 模表） |

---

## 3. HPU 指令生成 API：`hpu::scheme::{ckks,bfv}`

这一层直接生成 HPU 汇编 body（字符串），是“仿 SEAL 算子”的 codegen 入口。
头文件位于 `include/scheme/{ckks,bfv}/`，实现位于 `src/scheme/{ckks,bfv}/`。所有函数返回
包含 HPU 指令的 `std::string`；`*_asm` 版本返回带 `__asm__ volatile(...)` 包装的
完整 C++ 内联汇编函数，`*_body_asm` 版本只返回 body。

### 3.1 逐点运算：仿 `Evaluator` 的 add/sub/multiply_plain/...

`include/scheme/ckks/basic_arithmetic.hpp`

```cpp
std::string generate_add_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
std::string generate_subtract_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
std::string generate_multiply_plain_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
std::string generate_add_plain_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
std::string generate_subtract_plain_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
std::string generate_negate_body_asm(int num_q, bool append_psync = true, bool manage_modulus_table = true);
// *_asm 包装版本：generate_add_asm / generate_subtract_asm / ...
bool compatible_add_scales(double l, double r, double tol = 1e-6);
double multiply_plain_scale(double ct_scale, double pt_scale);
```

- 所有操作数使用同一 SEAL `parms_id` 与 canonical HPU NTT 物理序。
- 刻意**不发出任何 `pntt`/`pintt`**（零变换）。
- 内部指令：`dload(poly)`、`pmodld`、`padd`/`psub`/`pmul`、`pfree`、`dstore`；
  `manage_modulus_table=true` 时额外包含模表 `dload`+`pfree` 与末尾 `psync`。
- `negate` 用两个 `psub`（`(c-c)-c`）在 NTT 域合成负元，无额外零多项式。
- `compatible_add_scales` / `multiply_plain_scale` 是 host 侧的 scale 元数据判定，不发指令。

### 3.2 密文乘法：仿 `Evaluator::multiply`

`include/scheme/ckks/ciphertext_multiply.hpp`

```cpp
std::string generate_ciphertext_multiply_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                                  bool append_psync = false, bool manage_modulus_table = true);
std::string generate_ciphertext_multiply_body_asm(int N, int num_q, int num_p, int dnum,
                                                  bool append_psync = false, bool manage_modulus_table = true);
std::string generate_ciphertext_multiply_asm(int N, int num_q, int num_p, int dnum,
                                             bool append_psync = true);
double multiply_scale(double scale_a, double scale_b);
```

- 输入是 canonical HPU NTT 序的两个密文，输出两个 `Q_without_last` 上的 canonical
  HPU NTT 分量。
- 内部组合：张量积 `cmult`（`pmul`/`pmac` 得 t0/t1/t2）→ 系数域 KeySwitch
  relinearization（`pintt`/`pntt` + BConv `pmul`/`pmac`）→ Rescale（`moddown` 舍入）。
- `multiply_scale` 计算 `scale_a * scale_b`。

### 3.3 重线性化：仿 `Evaluator::relinearize`

`include/scheme/ckks/relinearize.hpp`

```cpp
std::string generate_relinearize_ntt_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                              bool append_psync = true);
std::string generate_relinearize_ntt_body_asm(int N, int num_q, int num_p, int dnum,
                                              bool append_psync = true);
std::string generate_relinearize_ntt_asm(int N, int num_q, int num_p, int dnum,
                                         bool append_psync = true);
```

- 输入三分量 canonical HPU NTT 张量，输出两分量 canonical HPU NTT。
- 内部指令：`pintt`（分量转到系数域）→ KeySwitch（`pntt`/`pintt`/`pmul`/`pmac`/BConv）→ 输出 `pntt`。

### 3.4 Rescale：仿 `Evaluator::rescale_to_next`

`include/scheme/ckks/rescale.hpp`

```cpp
std::string generate_rescale_body_asm(int num_q, int num_components,
                                      bool append_psync = false, bool manage_modulus_table = true);
std::string generate_rescale_asm(int num_q, int num_components, bool append_psync = true);
std::string generate_rescale_ntt_body_asm(int N, int num_q, bool append_psync = true);
std::string generate_rescale_ntt_asm(int N, int num_q, bool append_psync = true);
double rescale_scale(double scale, std::uint64_t q_last);
```

- 系数域舍入 RNS 降层：以最后一个 Q limb 为除数并从每个分量移除。
- `*_ntt_*` 是 SEAL-facing 独立 kernel，输入/输出 canonical HPU NTT，输出落在
  `Q_without_last`。
- 内部指令：`dload`、`pmodld`、`moddown`（BConv + `pmul`/`padd`/`psub`）、`dstore`。

### 3.5 Rotate / 槽旋转 / 共轭：仿 `Evaluator::apply_galois`

`include/scheme/ckks/rotate.hpp`

```cpp
std::string generate_rotate_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                     std::uint32_t galois_element, bool append_psync = true);
std::string generate_rotate_steps_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                           int steps, bool append_psync = true);
std::string generate_conjugate_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                        bool append_psync = true);
// 以及 num_q/num_p/dnum 整数版本与 *_asm 包装版本
```

- 三分量 canonical HPU NTT 输入，两分量输出；第一阶段 p3 必须绑定
  `create_fused_inverse_automorphism_tables` 生成的 modified-root 表。
- 内部指令：fused INTT（`pintt`）→ Galois KeySwitch → 输出 `pntt`；无 CPU 系数置换。
- 跨 kernel 仅保留 `domain=coefficient, key_domain=k`。

`include/scheme/ckks/galois.hpp`（host 侧，无指令）：

```cpp
std::uint32_t conjugation_galois_element(std::size_t degree);     // 2N-1
std::uint32_t rotation_galois_element(std::size_t degree, int steps);  // generator-3 槽映射
```

- 正 step 左旋、负 step 右旋，与 SEAL generator-3 槽布局一致；step=0 拒绝。

### 3.6 BFV 显式布局密文乘法

`include/scheme/bfv/ciphertext_multiply.hpp`

```cpp
struct BfvCiphertextMultiplyLayout {
    hpu::RnsDecompositionLayout keyswitch_layout; // active Q、固定 single-P、singleton digits
    std::vector<int> b_mod_ids;
    int m_sk_mod_id;
    int plaintext_mod_id;
};
std::string generate_ciphertext_multiply_body_asm(
    int N, const BfvCiphertextMultiplyLayout& layout,
    std::uint64_t plaintext_modulus,
    bool append_psync = false, bool manage_modulus_table = true);
```

- 该入口组合 comparison-free/no-SMRQ BEHZ、branchless-SK 与 BFV rounded single-P
  Relinearization；不使用 generic CKKS ModDown 语义。
- Q/P/B/`m_sk`/t 全部使用调用者提供的全局 MOD_ID，允许降 level 后 P 和辅助基不重编号；
  重复、越界、非 singleton-Q digit、multi-P 或不足的 B 基会被拒绝。
- `manage_modulus_table=true` 时整个融合流只装载/释放一次 small-bank 模表；嵌入更大
  planner 时可传 `false`，由外层统一管理模表和终止 `psync`。

---

## 4. 内部组合层（被 `hpu::scheme::ckks` 复用）

这些不是仿 SEAL 的直接入口，而是 codegen 复用的底层算子，各自返回 HPU 汇编：

| 层 | 头文件 | 关键接口 | 内部 HPU 指令 |
| --- | --- | --- | --- |
| util NTT | `include/util/ntt.hpp` | `generate_hpu_ntt_body_asm` / `generate_hpu_intt_body_asm` | `pmul`（预/后扭转）、`pntt`/`pintt`、`dload`、`pfree` |
| util MM | `include/util/mm.hpp` | 逐点向量乘法 / 乘加 | `pmul`、`pmac` |
| util BConv | `include/util/bconv.hpp` | 基转换两阶段 | `pmul`、`pmac`、`dload`、`dstore` |
| poly CMult | `include/poly/cmult.hpp` | 张量积 t0/t1/t2 | `pmul`、`pmac` |
| poly ModUp | `include/poly/modup.hpp` | 模提升 | `pmul`、`pmac`、`dload`、`dstore` |
| poly ModDown | `include/poly/moddown.hpp` | 模回缩/舍入降层 | `pmul`、`padd`、`psub`、`dload`、`dstore` |
| operator KeySwitch | `include/operator/keyswitch.hpp` | 完整密钥切换 | `pntt`/`pintt`、`pmul`、`pmac`、`dload`、`dstore` |
| operator Relinearization | `include/operator/relinearization.hpp` | 以 t0 为 base 切换 t2 | 复用 KeySwitch |
| operator CiphertextMultiply | `include/operator/ciphertext_multiply.hpp` | 公共密文乘法 | 复用 CMult + Relinearization |

### 5. runtime 状态机（非 SEAL 概念，但被仿 SEAL 层消费）

`include/hpu/runtime/application.hpp` 与 `include/hpu/runtime/memory_image.hpp`：

```cpp
class hpu::runtime::Application;   // 平台无关应用生命周期状态机
class hpu::runtime::HpuMemImage;   // 256B 行对齐 DDR 镜像
```

- `Application` 记录对象驻留、dload/dstore、kernel 边界与唯一 `psync`；不依赖
  Linux 驱动/用户态后端。
- `HpuMemImage` 拥有确定性行对齐镜像，不持有任何秘密密钥。

---

## 6. 端到端示例

`examples/ckks_polynomial_x2_plus_one.cpp` 演示完整链：

```
SEALContext → Encrypt(x) → HPU_MEM 镜像 → Square → Relinearize → Rescale → AddPlain(1)
```

SEAL 仅作为逐字 oracle 与最终解密验证；HPU 软件执行器运行整条计算链。
运行 `./build-seal/hpu_ckks_polynomial_example`，`--print-asm` 可输出完整 HPU 指令 body。

多分支顶层应用参考 `examples/ckks_composed_application.cpp`，运行
`./build-seal/hpu_ckks_composed_application_example`。它演示
Rotate/Conjugate→Add→Multiply→Relinearize→Rescale→AddPlain 的完整 planner、
relocation 和 runtime artifact 流程；详细说明见
`doc/CKKS_COMPOSED_APPLICATION_EXAMPLE.md`。

BFV 顶层应用参考 `examples/bfv_multiply_modswitch_application.cpp`。它实现
`ModSwitch(left*right)+3`，其中 bias 在目标 level 预制，并把同一 plan 降低为完整
relocation/runtime。传入 `--emit-dir PATH` 可输出 `.asm/.inst32/.cmd26`、生成的
`hpu_run_*()` C 包装、resolved DMA CSV 和 HPU_MEM uint32 镜像；完整说明见
`doc/BFV_APPLICATION_EXAMPLE.md`。

BFV rotation 应用参考 `examples/bfv_rotation_application.cpp`。它将
`RotateRows(x,2)` 与 `RotateColumns(x)` 两个分支合并为一次 Add，展示预制
GaloisKey、modified-root twiddle、key-domain workspace、完整编码与 relocation；
调用说明见 `doc/BFV_ROTATION_APPLICATION_EXAMPLE.md`。


## 通用应用交付接口

`#include "hpu/seal/application_delivery.hpp"`，链接 `hpu_seal_delivery`。
`make_ckks_application_package`、`make_bfv_application_package` 接收 plan lowering、
runtime、初始镜像、按算子顺序保存的 SEAL ciphertext oracle 和软件执行后的镜像。
`make_bgv_application_package` 接收线性 plan、lower 后的 application 和 oracle 快照。
它们返回同一种 `hpu::delivery::ApplicationPackageRequest`，由
`write_application_package(directory, request)` 写出，再用
`validate_application_package_on_disk(directory)` 独立校验。

每个应用输出必须有 golden；显式预留的临时对象应在 `reserve_ciphertext` 最后一个参数中
传入 `AllocationKind::workspace`。默认仍为 `output`。
参数和请求中不包含 SecretKey。三种方案都要求 SEAL oracle 到 golden 的检查为
`pass`，并要求对应软件执行器与 SEAL 的每一步 HPU 物理输出逐字一致。详见
[HPU_APPLICATION_PACKAGE_V1.md](HPU_APPLICATION_PACKAGE_V1.md)。
