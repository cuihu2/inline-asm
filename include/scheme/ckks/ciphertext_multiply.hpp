#pragma once

#include <string>

namespace hpu::scheme::ckks {

// Coefficient-domain CKKS multiply, relinearize, and rounded level drop.
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

double multiply_scale(double scale_a, double scale_b);

} // namespace hpu::scheme::ckks
