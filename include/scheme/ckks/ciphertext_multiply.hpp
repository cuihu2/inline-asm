#pragma once

#include <string>

namespace hpu::scheme::ckks {

// Multiply two SEAL/HPU-bridge ciphertexts that are already in canonical HPU
// NTT order, relinearize in the coefficient-domain KeySwitch path, rescale,
// and return two canonical HPU NTT components over Q without q_last.
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
