#pragma once

#include "hpu/seal/application_image.hpp"
#include "hpu/seal/bfv_level.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

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
};

// Builds the immutable BFV parameter/key/constant portion of one HPU_MEM
// application image. Its modulus identities and per-level B base come only
// from modified-SEAL; legacy bfv_num_b/dnum configuration is not accepted.
class BfvApplicationImageBuilder {
public:
    BfvApplicationImageBuilder(const ::seal::SEALContext& context, std::uint64_t capacity_lines);

    hpu::runtime::HpuMemSpan add_modulus_table();
    std::vector<PreparedCanonicalTwiddles> add_canonical_twiddles();
    PreparedEvaluationKey add_relinearization_key(std::string id, const ::seal::RelinKeys& keys,
                                                  const BfvLevelDescriptor& level);
    PreparedKeySwitchConstants add_keyswitch_constants(std::string id,
                                                       const BfvLevelDescriptor& level);
    PreparedBfvMultiplyConstants add_multiply_constants(std::string id,
                                                        const BfvLevelDescriptor& level);

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

} // namespace hpu::seal_adapter
