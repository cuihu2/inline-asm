#pragma once

#include <string>

// Internal scheme-independent backend used after host-side plaintext encoding.
// The host supplies one coefficient-domain RNS-Q limb for every q_i; the HPU
// transforms each limb to the negacyclic NTT domain.
std::string generate_plaintext_ntt_body_asm(
    int N,
    int num_q,
    bool append_psync = false);

