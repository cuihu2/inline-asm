#pragma once

#include <cstdint>
#include <string>

namespace hpu::scheme::bfv {

std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int num_b,
    int dnum,
    std::uint64_t plaintext_modulus,
    bool append_psync = false);

std::string generate_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int num_b,
    int dnum,
    std::uint64_t plaintext_modulus,
    bool append_psync = true);

} // namespace hpu::scheme::bfv
