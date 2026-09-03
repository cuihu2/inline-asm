#pragma once

#include <string>

std::string generate_hpu_moddown_body_asm(
    int num_q,
    int num_p,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_moddown_asm(
    int num_q,
    int num_p,
    bool append_psync = true);
