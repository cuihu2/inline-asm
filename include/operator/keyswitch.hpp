#pragma once

#include <string>

// Complete two-component key switch:
// KeySwitch(base, switching_component, evaluation_key) -> (base + ks0, ks1).
std::string generate_hpu_keyswitch_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = false,
    bool manage_modulus_table = true);

std::string generate_hpu_keyswitch_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = true);
