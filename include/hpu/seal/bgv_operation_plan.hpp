#pragma once

#include "hpu/seal/bgv_keyswitch_application.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

// Legacy names add/subtract/multiply refer to plaintext operations.
// multiply_ciphertext is fused Multiply+Relinearize; multiply_tensor is
// SEAL Multiply with a three-component result.
enum class BgvPlainOperationKind {
    add, subtract, multiply, add_ciphertext, subtract_ciphertext,
    rotate_rows, rotate_columns, modswitch_to_next, multiply_ciphertext,
    multiply_tensor, relinearize
};
using BgvOperationKind = BgvPlainOperationKind;

class BgvOperationPlan;

struct BgvPlannedValue {
    std::string id;
    ::seal::parms_id_type parms_id{};
    std::uint64_t correction_factor = 1;
    std::size_t component_count = 0;

private:
    friend class BgvOperationPlan;
    std::shared_ptr<const int> owner_;
    std::size_t index_ = 0;
};

struct BgvOperationStep {
    std::string id;
    BgvOperationKind kind = BgvOperationKind::add;
    std::vector<BgvPlannedValue> inputs;
    BgvPlannedValue output;
    std::shared_ptr<const ::seal::Plaintext> plaintext;
    std::shared_ptr<const ::seal::GaloisKeys> galois_keys;
    std::shared_ptr<const ::seal::RelinKeys> relin_keys;
    int rotation_steps = 0;
};
using BgvPlainOperationStep = BgvOperationStep;

// Topologically ordered graph over canonical NTT ciphertext values. Values
// can feed multiple branches; metadata inference never executes Evaluator.
class BgvOperationPlan {
public:
    explicit BgvOperationPlan(const ::seal::SEALContext& context);
    BgvOperationPlan(const ::seal::SEALContext& context, const ::seal::Ciphertext& input);
    BgvOperationPlan(const BgvOperationPlan&) = delete;
    BgvOperationPlan& operator=(const BgvOperationPlan&) = delete;

    BgvPlannedValue add_ciphertext(std::string id, const ::seal::Ciphertext& input);
    const BgvPlannedValue& input() const;
    const BgvPlannedValue& final_output() const;
    void set_output(const BgvPlannedValue& output);
    std::string allocation_prefix(const BgvPlannedValue& value) const;

    BgvPlannedValue append_add_plain(std::string id, const BgvPlannedValue& input,
                                    const ::seal::Plaintext& plain, std::string output_id = {});
    BgvPlannedValue append_subtract_plain(std::string id, const BgvPlannedValue& input,
                                         const ::seal::Plaintext& plain, std::string output_id = {});
    BgvPlannedValue append_multiply_plain(std::string id, const BgvPlannedValue& input,
                                         const ::seal::Plaintext& plain, std::string output_id = {});
    BgvPlannedValue append_add(std::string id, const BgvPlannedValue& left,
                              const BgvPlannedValue& right, std::string output_id = {});
    BgvPlannedValue append_subtract(std::string id, const BgvPlannedValue& left,
                                   const BgvPlannedValue& right, std::string output_id = {});
    BgvPlannedValue append_multiply(std::string id, const BgvPlannedValue& left,
                                   const BgvPlannedValue& right, std::string output_id = {});
    BgvPlannedValue append_relinearize(std::string id, const BgvPlannedValue& tensor,
                                      const ::seal::RelinKeys& keys, std::string output_id = {});
    BgvPlannedValue append_multiply_relinearize(
        std::string id, const BgvPlannedValue& left, const BgvPlannedValue& right,
        const ::seal::RelinKeys& keys, std::string output_id = {});
    BgvPlannedValue append_rotate_rows(std::string id, const BgvPlannedValue& input,
                                      int steps, const ::seal::GaloisKeys& keys,
                                      std::string output_id = {});
    BgvPlannedValue append_rotate_columns(std::string id, const BgvPlannedValue& input,
                                         const ::seal::GaloisKeys& keys,
                                         std::string output_id = {});
    BgvPlannedValue append_modswitch_to_next(std::string id, const BgvPlannedValue& input,
                                            std::string output_id = {});

    // Compatibility calls append to the current tail, including fused multiply.
    void append_add_plain(std::string id, const ::seal::Plaintext& plain);
    void append_subtract_plain(std::string id, const ::seal::Plaintext& plain);
    void append_multiply_plain(std::string id, const ::seal::Plaintext& plain);
    void append_add(std::string id, const ::seal::Ciphertext& right);
    void append_subtract(std::string id, const ::seal::Ciphertext& right);
    void append_multiply(std::string id, const ::seal::Ciphertext& right,
                         const ::seal::RelinKeys& keys);
    void append_rotate_rows(std::string id, int steps, const ::seal::GaloisKeys& keys);
    void append_rotate_columns(std::string id, const ::seal::GaloisKeys& keys);
    void append_modswitch_to_next(std::string id);

    const std::vector<BgvOperationStep>& steps() const noexcept;
    // capacity_lines limits construction; the emitted window uses the actual layout.
    BgvKeySwitchApplication lower(std::uint64_t capacity_lines) const;

private:
    struct ValueRecord {
        BgvPlannedValue value;
        std::shared_ptr<const ::seal::Ciphertext> imported;
    };
    void require_step_id(const std::string& id) const;
    void validate_value(const BgvPlannedValue& value, std::size_t components) const;
    const BgvPlannedValue& tail() const;
    BgvPlannedValue commit(BgvOperationStep step, std::string output_id,
                           ::seal::parms_id_type parms_id, std::uint64_t factor,
                           std::size_t components);
    BgvPlannedValue append_plain(std::string id, BgvOperationKind kind,
                                 const BgvPlannedValue& input, const ::seal::Plaintext& plain,
                                 std::string output_id);
    BgvPlannedValue append_binary(std::string id, BgvOperationKind kind,
                                  const BgvPlannedValue& left, const BgvPlannedValue& right,
                                  std::string output_id);
    BgvPlannedValue append_rotation(std::string id, BgvOperationKind kind,
                                    const BgvPlannedValue& input, int steps,
                                    const ::seal::GaloisKeys& keys, std::string output_id);
    std::shared_ptr<const ::seal::RelinKeys> share_keys(const ::seal::RelinKeys& keys);
    std::shared_ptr<const ::seal::GaloisKeys> share_keys(const ::seal::GaloisKeys& keys);

    const ::seal::SEALContext& context_;
    std::shared_ptr<const int> owner_ = std::make_shared<const int>(0);
    std::vector<ValueRecord> values_;
    std::vector<BgvOperationStep> steps_;
    std::vector<std::shared_ptr<const ::seal::RelinKeys>> relin_keys_;
    std::vector<std::shared_ptr<const ::seal::GaloisKeys>> galois_keys_;
    std::vector<std::shared_ptr<const ::seal::Plaintext>> plaintexts_;
    std::size_t output_index_ = 0;
    bool explicit_output_ = false;
};

using BgvPlainOperationPlan = BgvOperationPlan;
using BgvLinearOperationPlan = BgvOperationPlan;

} // namespace hpu::seal_adapter
