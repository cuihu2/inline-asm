#pragma once

#include <string>

std::string generate_hpu_cmult_body_asm(
    int num_q,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_cmult_asm(
    int num_q,
    bool append_psync = true);

// std::string generate_hpu_cmult_ntt_asm(
//     int N,
//     int num_q,
//     bool append_psync = false);
