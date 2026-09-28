#pragma once

#include "hpu/seal/bgv_keyswitch_application.hpp"

#include <seal/seal.h>

#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

enum class BgvPlainOperationKind {
    add, subtract, multiply, add_ciphertext, subtract_ciphertext,
    rotate_rows, rotate_columns
};

struct BgvPlainOperationStep {
    std::string id;
    BgvPlainOperationKind kind;
    ::seal::Plaintext plaintext;
    ::seal::Ciphertext ciphertext;
    ::seal::GaloisKeys galois_keys;
    int rotation_steps = 0;
};

// Linear same-level chain over one two-component BGV ciphertext. Plaintexts
// secondary ciphertexts and Galois keys are prepared before execution; intermediate
// ciphertexts remain in HPU_MEM. Binary Add/Sub balance correction factors.
class BgvPlainOperationPlan {
public:
    BgvPlainOperationPlan(const ::seal::SEALContext& context,
                          const ::seal::Ciphertext& input);

    void append_add_plain(std::string id, const ::seal::Plaintext& plaintext);
    void append_subtract_plain(std::string id, const ::seal::Plaintext& plaintext);
    void append_multiply_plain(std::string id, const ::seal::Plaintext& plaintext);
    void append_add(std::string id, const ::seal::Ciphertext& right);
    void append_subtract(std::string id, const ::seal::Ciphertext& right);
    void append_rotate_rows(std::string id, int steps,
                            const ::seal::GaloisKeys& keys);
    void append_rotate_columns(std::string id,
                               const ::seal::GaloisKeys& keys);

    const std::vector<BgvPlainOperationStep>& steps() const noexcept;
    BgvKeySwitchApplication lower(std::uint64_t capacity_lines) const;

private:
    void append(std::string id, BgvPlainOperationKind kind,
                const ::seal::Plaintext& plaintext);
    void append(std::string id, BgvPlainOperationKind kind,
                const ::seal::Ciphertext& right);
    void append_rotation(std::string id, BgvPlainOperationKind kind,
                         int steps, const ::seal::GaloisKeys& keys);
    void require_step_id(const std::string& id) const;

    const ::seal::SEALContext& context_;
    ::seal::Ciphertext input_;
    std::vector<BgvPlainOperationStep> steps_;
};

using BgvLinearOperationPlan = BgvPlainOperationPlan;

} // namespace hpu::seal_adapter
