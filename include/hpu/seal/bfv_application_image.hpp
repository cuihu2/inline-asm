#pragma once

#include "hpu/seal/application_image.hpp"
#include "hpu/seal/bfv_level.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct BfvValueMetadata {
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
};

struct PreparedBfvRnsObject {
    std::string id;
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
    hpu::runtime::PolynomialDomain domain = hpu::runtime::PolynomialDomain::coefficient;
    std::uint64_t key_domain = 1;
    std::vector<PreparedPolynomial> components;

    BfvValueMetadata metadata() const noexcept
    {
        return {parms_id, chain_index};
    }
};

struct PreparedBfvMultiplyConstants {
    std::string id;
    ::seal::parms_id_type data_parms_id{};
    std::size_t chain_index = 0;
    hpu::runtime::HpuMemSpan values;
    std::string hardware_prefix;
    std::vector<int> q_mod_ids;
    std::vector<int> b_mod_ids;
    int m_sk_mod_id = -1;
    int plaintext_mod_id = -1;
    std::size_t hardware_constant_polynomial_count = 0;
    std::size_t hardware_workspace_polynomial_count = 0;
};

struct PreparedBfvModSwitchConstants {
    std::string id;
    ::seal::parms_id_type source_parms_id{};
    ::seal::parms_id_type destination_parms_id{};
    std::size_t source_chain_index = 0;
    std::size_t destination_chain_index = 0;
    int dropped_mod_id = -1;
    hpu::runtime::HpuMemSpan values;
    std::string hardware_prefix;
    std::size_t hardware_component_capacity = 0;
    std::size_t hardware_constant_polynomial_count = 0;
    std::size_t hardware_workspace_polynomial_count = 0;
};

// Builds a BFV HPU_MEM application image. Parameters, per-level bases, input
// objects, prepared plaintexts, outputs, keys, and constants all use identities
// derived from modified-SEAL; legacy bfv_num_b/dnum configuration is rejected.
class BfvApplicationImageBuilder {
public:
    BfvApplicationImageBuilder(const ::seal::SEALContext& context, std::uint64_t capacity_lines);

    hpu::runtime::HpuMemSpan add_modulus_table();
    std::vector<PreparedCanonicalTwiddles> add_canonical_twiddles();
    PreparedBfvRnsObject add_ciphertext(std::string id, const ::seal::Ciphertext& ciphertext);
    PreparedBfvRnsObject add_add_subtract_plaintext(std::string id,
                                                    const ::seal::Plaintext& plaintext,
                                                    const BfvLevelDescriptor& level);
    PreparedBfvRnsObject add_multiply_plaintext(std::string id, const ::seal::Plaintext& plaintext,
                                                const BfvLevelDescriptor& level);
    PreparedEvaluationKey add_relinearization_key(std::string id, const ::seal::RelinKeys& keys,
                                                  const BfvLevelDescriptor& level);
    PreparedEvaluationKey add_galois_key(std::string id, const ::seal::GaloisKeys& keys,
                                         std::uint32_t galois_element,
                                         const BfvLevelDescriptor& level);
    PreparedEvaluationKey add_row_rotation_key(std::string id, const ::seal::GaloisKeys& keys,
                                               int steps, const BfvLevelDescriptor& level);
    PreparedEvaluationKey add_column_rotation_key(std::string id,
                                                  const ::seal::GaloisKeys& keys,
                                                  const BfvLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles> add_fused_automorphism_twiddles(
        std::string id, std::uint32_t galois_element, const BfvLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles> add_row_rotation_twiddles(
        std::string id, int steps, const BfvLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles> add_column_rotation_twiddles(
        std::string id, const BfvLevelDescriptor& level);
    PreparedKeySwitchConstants add_keyswitch_constants(std::string id,
                                                       const BfvLevelDescriptor& level);
    PreparedBfvMultiplyConstants add_multiply_constants(std::string id,
                                                        const BfvLevelDescriptor& level);
    PreparedBfvModSwitchConstants add_mod_switch_constants(std::string id,
                                                           const BfvLevelDescriptor& source_level,
                                                           std::size_t component_capacity = 2);
    PreparedBfvRnsObject reserve_ciphertext(
        std::string id, const BfvLevelDescriptor& level, std::size_t component_count = 2,
        hpu::runtime::PolynomialDomain domain = hpu::runtime::PolynomialDomain::coefficient,
        std::uint64_t key_domain = 1);

    const hpu::runtime::HpuMemImage& image() const noexcept;
    const BfvLevelChain& level_chain() const noexcept;
    const BfvLevelRegistry& registry() const noexcept;
    const std::vector<BfvLevelDescriptor>& levels() const noexcept;

private:
    PreparedPolynomial add_polynomial(std::string id, const HpuRnsPolynomial& polynomial,
                                      hpu::runtime::AllocationKind kind, bool read_only);
    PreparedEvaluationKey add_evaluation_key(std::string id,
                                             const std::vector<HpuKeySwitchDigit>& digits,
                                             const BfvLevelDescriptor& level);
    const BfvLevelDescriptor& require_level(::seal::parms_id_type parms_id) const;

    const ::seal::SEALContext& context_;
    hpu::runtime::HpuMemImage image_;
    BfvLevelChain level_chain_;
    bool modulus_table_added_ = false;
    bool canonical_twiddles_added_ = false;
};

void register_bfv_rns_object(hpu::runtime::Application& application,
                             const PreparedBfvRnsObject& object, bool required_output);

} // namespace hpu::seal_adapter
