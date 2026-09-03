#pragma once

#include "operator/rns_layout.hpp"

#include <string>

namespace hpu::scheme::ckks {

// Standalone SEAL-facing relinearization. Input is a three-component tensor in
// canonical HPU NTT order; output is a two-component canonical HPU NTT object.
std::string generate_relinearize_ntt_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    bool append_psync = true);

std::string generate_relinearize_ntt_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = true);

std::string generate_relinearize_ntt_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync = true);

} // namespace hpu::scheme::ckks
