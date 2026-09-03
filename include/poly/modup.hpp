#pragma once

#include <string>
#include <vector>

std::string generate_hpu_modup_contexts_body_asm(
    const std::vector<int>& q_contexts,
    const std::vector<int>& p_contexts,
    const std::vector<int>& source_contexts,
    bool append_psync = false,
    bool manage_modulus_table = true);

// Extend Q[q_offset:q_offset + num_q_digit) to the complete Q union P basis.
// Source digit limbs are retained verbatim; all other Q and P limbs are
// materialized through BConv.
std::string generate_hpu_modup_body_asm(
    int num_q,
    int num_p,
    int num_q_digit,
    int q_offset,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_modup_asm(
    int num_q,
    int num_p,
    int num_q_digit,
    int q_offset,
    bool append_psync = true);
