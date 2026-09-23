#pragma once

#include "operator/rns_layout.hpp"

#include <cstdint>
#include <string>

namespace hpu::scheme::bfv {

// BFV ciphertexts enter and leave in coefficient form. Each input limb is
// transformed with the canonical root and immediately inverted with the
// modified root for k, producing sigma_k(c0), sigma_k(c1), before the
// comparison-free rounded BFV KeySwitch restores the canonical key domain.
std::string generate_rotate_body_asm(
    int N, const hpu::RnsDecompositionLayout& layout, std::uint32_t galois_element,
    bool append_psync = true, bool manage_modulus_table = true);

} // namespace hpu::scheme::bfv
