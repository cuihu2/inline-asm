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

// Immutable, context-derived CKKS modulus-chain registry. Ordinals start at
// zero for first_context_data(); they are deliberately distinct from SEAL's
// chain_index values, which decrease as data moduli are dropped.
class CkksLevelChain {
public:
    explicit CkksLevelChain(const ::seal::SEALContext& context);

    std::size_t size() const noexcept;
    const std::vector<CkksLevelDescriptor>& levels() const noexcept;
    const CkksLevelDescriptor& top() const noexcept;
    const CkksLevelDescriptor& bottom() const noexcept;
    const CkksLevelDescriptor& at(std::size_t ordinal) const;
    const CkksLevelDescriptor& require(
        const ::seal::parms_id_type& parms_id) const;
    const CkksLevelDescriptor& require_chain_index(
        std::size_t chain_index) const;
    std::size_t ordinal(const ::seal::parms_id_type& parms_id) const;
    bool has_next(const ::seal::parms_id_type& parms_id) const;
    bool has_previous(const ::seal::parms_id_type& parms_id) const;
    const CkksLevelDescriptor& next(
        const ::seal::parms_id_type& parms_id) const;
    const CkksLevelDescriptor& previous(
        const ::seal::parms_id_type& parms_id) const;
    bool is_direct_successor(
        const ::seal::parms_id_type& source,
        const ::seal::parms_id_type& destination) const;

private:
    std::vector<CkksLevelDescriptor> levels_;
};

} // namespace hpu::seal_adapter
