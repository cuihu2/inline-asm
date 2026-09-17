#pragma once

#include <string>
#include <vector>

// Coefficient-domain rounded RNS division by one explicit special modulus P.
// Each component is represented over q_contexts union {p_context}. The result
// drops P, remains over q_contexts, and stays in coefficient form.
std::string generate_hpu_rounded_single_p_moddown_contexts_body_asm(
    const std::vector<int>& q_contexts,
    int p_context,
    int num_components,
    bool append_psync = false,
    bool manage_modulus_table = true);

// Coefficient-domain rounded RNS division by the final Q modulus. The final
// limb is removed and the result remains in coefficient form.
std::string generate_hpu_rounded_drop_last_body_asm(
    int num_q,
    int num_components,
    bool append_psync = false,
    bool manage_modulus_table = true);
