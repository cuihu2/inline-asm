#pragma once

#include "operator/rns_layout.hpp"

#include <cstdint>
#include <string>

namespace hpu::scheme::bgv {

// SEAL-facing BGV multiply: two canonical HPU NTT ciphertexts -> tensor
// product -> BGV KeySwitch -> two canonical HPU NTT output components.
// correction_factor is host metadata, not an HPU coefficient operation.
std::string generate_ciphertext_multiply_ntt_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    int plaintext_mod_id,
    bool append_psync = false,
    bool manage_modulus_table = false);

// Coefficient-domain BGV multiply and relinearize. The correction factor is
// software metadata and is updated with multiply_correction_factor.
std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = false);

std::string generate_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = true);

std::uint64_t multiply_correction_factor(
    std::uint64_t factor_a,
    std::uint64_t factor_b,
    std::uint64_t plaintext_modulus);

} // namespace hpu::scheme::bgv
