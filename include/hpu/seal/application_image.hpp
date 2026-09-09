#pragma once

#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/automorphism.hpp"
#include "hpu/seal/ckks_level.hpp"
#include "hpu/seal/ckks_metadata.hpp"
#include "hpu/seal/evaluation_key.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct PreparedPolynomial {
    std::string id;
    std::size_t degree = 0;
    std::vector<std::uint8_t> modulus_ids;
    std::vector<hpu::runtime::HpuMemSpan> limbs;
};

struct PreparedRnsObject {
    std::string id;
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
    double scale = 1.0;
    hpu::runtime::PolynomialDomain domain =
        hpu::runtime::PolynomialDomain::canonical_ntt_physical;
    std::uint64_t key_domain = 1;
    std::vector<PreparedPolynomial> components;

    CkksValueMetadata metadata() const noexcept
    {
        return {parms_id, chain_index, scale};
    }
};

struct PreparedEvaluationKey {
    std::string id;
    ::seal::parms_id_type data_parms_id{};
    std::size_t chain_index = 0;
    hpu::RnsDecompositionLayout rns_layout;
    std::vector<std::vector<PreparedPolynomial>> digits;
};

struct PreparedKeySwitchConstants {
    ::seal::parms_id_type data_parms_id{};
    std::size_t chain_index = 0;
    hpu::runtime::HpuMemSpan values;
};

struct PreparedRescaleConstants {
    ::seal::parms_id_type source_parms_id{};
    ::seal::parms_id_type destination_parms_id{};
    std::size_t source_chain_index = 0;
    std::size_t destination_chain_index = 0;
    hpu::runtime::HpuMemSpan values;
};

struct PreparedCanonicalTwiddles {
    std::uint8_t modulus_id = 0;
    std::uint32_t modulus = 0;
    std::uint32_t canonical_psi = 0;
    hpu::runtime::HpuMemSpan pre_twist;
    std::vector<hpu::runtime::HpuMemSpan> forward_stages;
    std::vector<hpu::runtime::HpuMemSpan> inverse_stages;
    hpu::runtime::HpuMemSpan post_untwist_scale;
};

struct PreparedFusedAutomorphismTwiddles {
    std::uint8_t modulus_id = 0;
    std::uint32_t modulus = 0;
    std::uint32_t canonical_psi = 0;
    std::uint32_t modified_psi = 0;
    std::vector<hpu::runtime::HpuMemSpan> inverse_stages;
    hpu::runtime::HpuMemSpan post_untwist_scale;
};

// Creates the complete, named HPU_MEM initialization image before an
// application starts. Every RNS limb is a distinct line-aligned allocation;
// at N=65536 it therefore occupies exactly 1024 lines and maps naturally to
// one regular-bank resident object. SecretKey is deliberately absent here.
class CkksApplicationImageBuilder {
public:
    CkksApplicationImageBuilder(
        const ::seal::SEALContext& context,
        std::uint64_t capacity_lines);

    hpu::runtime::HpuMemSpan add_modulus_table();
    std::vector<PreparedCanonicalTwiddles> add_canonical_twiddles();
    PreparedRnsObject add_ciphertext(
        std::string id,
        const ::seal::Ciphertext& ciphertext);
    PreparedRnsObject add_plaintext(
        std::string id,
        const ::seal::Plaintext& plaintext);
    PreparedEvaluationKey add_relinearization_key(
        std::string id,
        const ::seal::RelinKeys& keys,
        const CkksLevelDescriptor& level);
    PreparedKeySwitchConstants add_keyswitch_constants(
        std::string id,
        const CkksLevelDescriptor& level);
    PreparedRescaleConstants add_rescale_constants(
        std::string id,
        const CkksLevelDescriptor& source_level);
    PreparedEvaluationKey add_galois_key(
        std::string id,
        const ::seal::GaloisKeys& keys,
        std::uint32_t galois_element,
        const CkksLevelDescriptor& level);
    PreparedEvaluationKey add_rotation_key(
        std::string id,
        const ::seal::GaloisKeys& keys,
        int steps,
        const CkksLevelDescriptor& level);
    PreparedEvaluationKey add_conjugation_key(
        std::string id,
        const ::seal::GaloisKeys& keys,
        const CkksLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles>
    add_fused_automorphism_twiddles(
        std::string id,
        std::uint32_t galois_element,
        const CkksLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles>
    add_rotation_twiddles(
        std::string id,
        int steps,
        const CkksLevelDescriptor& level);
    std::vector<PreparedFusedAutomorphismTwiddles>
    add_conjugation_twiddles(
        std::string id,
        const CkksLevelDescriptor& level);
    PreparedRnsObject reserve_ciphertext(
        std::string id,
        const CkksLevelDescriptor& level,
        std::size_t component_count,
        double scale,
        hpu::runtime::PolynomialDomain domain =
            hpu::runtime::PolynomialDomain::canonical_ntt_physical,
        std::uint64_t key_domain = 1);
    PreparedRnsObject reserve_ciphertext(
        std::string id,
        const CkksValueMetadata& metadata,
        std::size_t component_count,
        hpu::runtime::PolynomialDomain domain =
            hpu::runtime::PolynomialDomain::canonical_ntt_physical,
        std::uint64_t key_domain = 1);

    const hpu::runtime::HpuMemImage& image() const noexcept;
    const CkksLevelChain& level_chain() const noexcept;
    const std::vector<CkksLevelDescriptor>& levels() const noexcept;

private:
    PreparedPolynomial add_polynomial(
        std::string id,
        const HpuRnsPolynomial& polynomial,
        hpu::runtime::AllocationKind kind,
        bool read_only);
    PreparedEvaluationKey add_evaluation_key(
        std::string id,
        const std::vector<HpuKeySwitchDigit>& digits,
        const CkksLevelDescriptor& level);
    const CkksLevelDescriptor& require_level(::seal::parms_id_type parms_id) const;

    const ::seal::SEALContext& context_;
    hpu::runtime::HpuMemImage image_;
    CkksLevelChain level_chain_;
    bool modulus_table_added_ = false;
    bool canonical_twiddles_added_ = false;
};

// Registers every limb as an independently resident HPU object. This keeps
// cross-kernel residency decisions in runtime::Application and requires a
// dstore only for limbs marked as final outputs.
void register_rns_object(
    hpu::runtime::Application& application,
    const PreparedRnsObject& object,
    bool required_output);

} // namespace hpu::seal_adapter
