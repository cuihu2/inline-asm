#pragma once

#include <cstdint>
#include <string>

namespace hpu::scheme::ckks {

// Coefficient-domain rounded RNS rescale. The final Q limb is used as the
// divisor and removed from every ciphertext component.
std::string generate_rescale_body_asm(
    int num_q,
    int num_components,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_rescale_asm(
    int num_q,
    int num_components,
    bool append_psync = true);

// SEAL-facing standalone kernel. Input and output are canonical HPU NTT;
// output uses Q without q_last. The coefficient-domain body above remains the
// reusable core for a larger application stream.
std::string generate_rescale_ntt_body_asm(
    int N,
    int num_q,
    bool append_psync = true);

std::string generate_rescale_ntt_asm(
    int N,
    int num_q,
    bool append_psync = true);

double rescale_scale(double scale, std::uint64_t q_last);

} // namespace hpu::scheme::ckks
