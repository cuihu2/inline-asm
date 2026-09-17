#pragma once

#include "operator/rns_layout.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::seal_adapter {

struct BfvLevelDescriptor {
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
    std::vector<std::uint32_t> q_moduli;
    std::uint32_t special_modulus = 0;
    std::vector<std::uint32_t> b_moduli;
    std::uint32_t m_sk = 0;
    std::uint32_t plaintext_modulus = 0;

    hpu::RnsDecompositionLayout keyswitch_layout;
    std::vector<int> b_mod_ids;
    int m_sk_mod_id = -1;
    int plaintext_mod_id = -1;
    std::vector<std::size_t> evaluation_key_digit_indices;
    std::uint32_t q_last = 0;
};

// Application-global modulus table. Indices are the MOD_IDs used by every
// level descriptor; equal auxiliary primes are shared across levels.
struct BfvLevelRegistry {
    std::size_t poly_modulus_degree = 0;
    std::vector<std::uint32_t> modulus_table;
    std::vector<BfvLevelDescriptor> levels;
};

BfvLevelRegistry create_bfv_level_registry(
    const ::seal::SEALContext& context);

class BfvLevelChain {
public:
    explicit BfvLevelChain(const ::seal::SEALContext& context);

    const BfvLevelRegistry& registry() const noexcept;
    std::size_t size() const noexcept;
    const std::vector<BfvLevelDescriptor>& levels() const noexcept;
    const BfvLevelDescriptor& top() const noexcept;
    const BfvLevelDescriptor& bottom() const noexcept;
    const BfvLevelDescriptor& at(std::size_t ordinal) const;
    const BfvLevelDescriptor& require(
        const ::seal::parms_id_type& parms_id) const;
    std::size_t ordinal(const ::seal::parms_id_type& parms_id) const;
    bool has_next(const ::seal::parms_id_type& parms_id) const;
    const BfvLevelDescriptor& next(
        const ::seal::parms_id_type& parms_id) const;

private:
    BfvLevelRegistry registry_;
};

} // namespace hpu::seal_adapter
