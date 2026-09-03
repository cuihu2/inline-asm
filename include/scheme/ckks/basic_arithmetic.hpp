#pragma once

#include <string>

namespace hpu::scheme::ckks {

// All operands use the same SEAL parms_id and canonical HPU NTT physical order.
// These pointwise kernels intentionally emit no NTT/INTT instructions. A
// composed application passes manage_modulus_table=false so the outer program
// owns the single application-lifetime small-bank dload/pfree pair.
std::string generate_add_body_asm(
    int num_q,
    bool append_psync = true,
    bool manage_modulus_table = true);
std::string generate_subtract_body_asm(
    int num_q,
    bool append_psync = true,
    bool manage_modulus_table = true);
std::string generate_multiply_plain_body_asm(
    int num_q,
    bool append_psync = true,
    bool manage_modulus_table = true);
std::string generate_add_plain_body_asm(
    int num_q,
    bool append_psync = true,
    bool manage_modulus_table = true);
std::string generate_subtract_plain_body_asm(
    int num_q,
    bool append_psync = true,
    bool manage_modulus_table = true);

std::string generate_add_asm(int num_q, bool append_psync = true);
std::string generate_subtract_asm(int num_q, bool append_psync = true);
std::string generate_multiply_plain_asm(
    int num_q,
    bool append_psync = true);
std::string generate_add_plain_asm(int num_q, bool append_psync = true);
std::string generate_subtract_plain_asm(
    int num_q,
    bool append_psync = true);

bool compatible_add_scales(
    double left_scale,
    double right_scale,
    double relative_tolerance = 1e-6);
double multiply_plain_scale(double ciphertext_scale, double plaintext_scale);

} // namespace hpu::scheme::ckks
