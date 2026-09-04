#pragma once

#include <string>

// Coefficient-domain rounded RNS division by the final Q modulus. The final
// limb is removed and the result remains in coefficient form.
std::string generate_hpu_rounded_drop_last_body_asm(
    int num_q,
    int num_components,
    bool append_psync = false);
