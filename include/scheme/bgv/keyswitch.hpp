#pragma once

#include "operator/rns_layout.hpp"

#include <string>

namespace hpu::scheme::bgv {

// SEAL-compatible singleton-digit BGV KeySwitch. The switching component and
// both base components are canonical HPU NTT; outputs remain canonical NTT.
// The fixed plaintext MOD_ID must be distinct from active Q and special P.
// For Relinearize use base=(tensor c0,c1), switch=tensor c2. For Galois use
// base=(sigma(c0),zero), switch=sigma(c1).
//
// Caller supplies prepared key digits and N-word splats of -P^-1 mod t,
// P mod q_i and P^-1 mod q_i (the same shape as NTT ModSwitch constants).
std::string generate_keyswitch_ntt_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    int plaintext_mod_id,
    bool append_psync = false,
    bool manage_modulus_table = false);

} // namespace hpu::scheme::bgv
