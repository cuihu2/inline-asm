#pragma once

#include <cstdint>
#include <string>

namespace hpu::scheme::bgv {

struct CorrectionBalance {
    std::uint32_t output_factor = 1;
    std::uint32_t left_scalar = 1;
    std::uint32_t right_scalar = 1;
};

// Mirrors modified-SEAL's BGV correction-factor balancing. The scalar
// multiplication of ciphertext limbs belongs to HPU, not to this host helper.
CorrectionBalance balance_correction_factors(
    std::uint32_t left_factor,
    std::uint32_t right_factor,
    std::uint32_t plaintext_modulus);

// Canonical HPU NTT inputs/outputs. When a scalar is not one, each component
// and Q limb consumes one prepared N-word scalar splat before PADD/PSUB.
std::string generate_add_body_asm(
    int num_q, const CorrectionBalance& balance,
    bool append_psync = false, bool manage_modulus_table = false);
std::string generate_subtract_body_asm(
    int num_q, const CorrectionBalance& balance,
    bool append_psync = false, bool manage_modulus_table = false);
std::string generate_negate_body_asm(
    int num_q, bool append_psync = false,
    bool manage_modulus_table = false);

} // namespace hpu::scheme::bgv
