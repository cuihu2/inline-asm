#pragma once

#include "operator/rns_layout.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::seal_adapter {

struct CkksLevelDescriptor {
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
    std::vector<std::uint32_t> q_moduli;
    std::vector<std::uint32_t> special_moduli;

    // Stable application-global IDs: initial Q is [0..Qmax), and P keeps
    // [Qmax..Qmax+P) even after active Q becomes shorter.
    hpu::RnsDecompositionLayout rns_layout;

    // Indices into the SEAL evaluation-key digit vector. SEAL 4.4 uses one
    // active digit per remaining data modulus at these CKKS levels.
    std::vector<std::size_t> evaluation_key_digit_indices;
    std::uint32_t q_last = 0;
};

// Describes every data-context node from first_context_data() to the final
// one-prime level without renumbering P in the application modulus table.
std::vector<CkksLevelDescriptor> create_ckks_level_descriptors(
    const ::seal::SEALContext& context);

} // namespace hpu::seal_adapter
