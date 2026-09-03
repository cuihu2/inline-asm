#pragma once

#include <string>

// Relinearize (t0, t1, t2) by applying the complete KeySwitch operator to
// (base=t0, switching_component=t2), then composing t1 + ks1.
std::string generate_hpu_relinearization_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_relinearization_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = true);
