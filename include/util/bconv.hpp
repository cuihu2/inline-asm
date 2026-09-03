#pragma once

#include <string>
#include <vector>

// Generate a basis conversion using explicit pmodld context identifiers.
// source_contexts and target_contexts also define the external-memory limb order
// expected by the generated dload/dstore stream.
std::string generate_hpu_bconv_contexts_body_asm(
    const std::vector<int>& source_contexts,
    const std::vector<int>& target_contexts,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_bconv_body_asm(
    int num_q,
    int num_p,
    int q_offset = 0,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_bconv_asm(
    int num_q,
    int num_p,
    int q_offset = 0,
    bool append_psync = true);
