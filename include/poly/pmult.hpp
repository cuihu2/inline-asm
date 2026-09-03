#pragma once

#include <string>

std::string generate_hpu_pmult_body_asm(
    int num_q,
    bool append_psync = false,
    // False when an enclosing application already owns the small-bank table.
    bool manage_modulus_table = true);

std::string generate_hpu_pmult_asm(
    int num_q,
    bool append_psync = true);

std::string generate_hpu_pmult_ntt_asm(
    int N,
    int num_q,
    bool append_psync = true);
