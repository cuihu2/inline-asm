#pragma once

#include <cstdint>
#include <string>

namespace hpu::scheme::bgv {

// Coefficient-domain BGV modulus switch from Q to Q without its final limb.
// The global context order is Q followed by P followed by plaintext modulus t.
std::string generate_modswitch_body_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync = false);

std::string generate_modswitch_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync = true);

std::uint64_t modswitch_correction_factor(
    std::uint64_t factor,
    std::uint64_t q_last,
    std::uint64_t plaintext_modulus);

} // namespace hpu::scheme::bgv
