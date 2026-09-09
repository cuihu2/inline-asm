# HPU 仿 SEAL API 参考

本文件记录当前仓库中所有“仿 Microsoft SEAL”的对外 API，即那些在内部会
调用 `src/` 下、最终落到 HPU 指令（`padd`/`psub`/`pmul`/`pmac`/`pntt`/`pintt`/
`pmodld`/`pfree`/`psync`/`dload`/`dstore`）或对应软件执行语义的接口。

仿 SEAL API 分两条独立路径，分别对应两个 namespace：

| 层次 | namespace | 职责 | 对应 SEAL 概念 |
| --- | --- | --- | --- |
| host 侧 SEAL-facing | `hpu::seal_adapter` | 从 `SEALContext`/`Ciphertext`/`Plaintext`/`RelinKeys`/`GaloisKeys` 派生 HPU 布局、HPU_MEM 镜像，并做软件执行 | `SEALContext`、`Evaluator`、`KeyGenerator`、`NTT` |
| 指令生成（codegen） | `hpu::scheme::ckks` | 直接生成 HPU 汇编 body，内部复用 `operator`/`poly`/`util` 层 | `Evaluator::add/sub/multiply/rotate/rescale/...` |

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

#### 2.2.1 CKKS 操作元数据规则

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
- `register_rns_object` 把每个 limb 注册为独立对象，跨 kernel 驻留决策留给
  `hpu::runtime::Application`。

#### 2.6.1 显式操作计划

`include/hpu/seal/operation_plan.hpp`

```cpp
CkksOperationPlan plan(image_builder);
auto tensor = plan.append_square("square", input, "intermediate/tensor");
auto relin = plan.append_relinearize(
    "relinearize", tensor, relinearization_key, keyswitch_constants,
    "intermediate/relinearized");
auto rescaled = plan.append_rescale(
    "rescale", relin, rescale_constants, "intermediate/rescaled");
auto output = plan.append_add_plain(
    "add_one", rescaled, encoded_one, "output/x2_plus_one");
```

- 每一步都显式给出，plan 不会自动插入 Relinearize 或 Rescale。
- 输出由前一步 metadata 推导后直接在同一个 `HpuMemImage` 中分配；输入对象的
  allocation ID/span 也必须属于该 image。
- Relinearize 会绑定并校验当前 level 的 evaluation key、KeySwitch 常量和
  canonical twiddle 需求；Rescale 会绑定相邻 level 的常量和 twiddle 需求。
- `steps()` 保留有序的输入/输出 metadata、组件数、表示域和资源 ID，供下一阶段
  的 codegen/runtime lowering 使用。目前覆盖示例需要的 Square、Relinearize、
  Rescale、AddPlain。

### 2.7 软件执行器：仿 `seal::Evaluator`

`include/hpu/seal/software_executor.hpp`，实现 `src/hpu/seal/software_executor.cpp`。
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
```

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

## 3. HPU 指令生成 API：`hpu::scheme::ckks`

这一层直接生成 HPU 汇编 body（字符串），是“仿 SEAL 算子”的 codegen 入口。
头文件位于 `include/scheme/ckks/`，实现位于 `src/scheme/ckks/`。所有函数返回
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
