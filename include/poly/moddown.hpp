#pragma once

#include <string>
#include <vector>

std::string generate_hpu_moddown_contexts_body_asm(
    const std::vector<int>& q_contexts,
    const std::vector<int>& p_contexts,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_moddown_body_asm(
    int num_q,
    int num_p,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_moddown_asm(
    int num_q,
    int num_p,
    bool append_psync = true);
