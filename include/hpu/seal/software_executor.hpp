#pragma once

#include "hpu/runtime/software_executor.hpp"
#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_metadata.hpp"
#include "hpu/seal/ntt_bridge.hpp"

#include <seal/seal.h>

#include <cstddef>

namespace hpu::seal_adapter {

// SEAL-facing functional execution layer over HpuMemImage. Operations consume
// application-preloaded tables, keys, and constants; no seal::Evaluator call
// is made by this class.
class CkksSoftwareExecutor {
public:
    CkksSoftwareExecutor(
        const ::seal::SEALContext& context,
        const hpu::runtime::HpuMemImage& image);

    void add(
        const PreparedRnsObject& left,
        const PreparedRnsObject& right,
        const PreparedRnsObject& output);
    void subtract(
        const PreparedRnsObject& left,
        const PreparedRnsObject& right,
        const PreparedRnsObject& output);
    void multiply_plain(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& plaintext,
        const PreparedRnsObject& output);
    void add_plain(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& plaintext,
        const PreparedRnsObject& output);
    void subtract_plain(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& plaintext,
        const PreparedRnsObject& output);
    void negate(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& output);
    void square(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& tensor_output);
    void multiply(
        const PreparedRnsObject& left,
        const PreparedRnsObject& right,
        const PreparedRnsObject& tensor_output);
    void key_switch(
        const PreparedRnsObject& base_ciphertext,
        const PreparedRnsObject& switching_component,
        const PreparedEvaluationKey& evaluation_key,
        const PreparedKeySwitchConstants& constants,
        const PreparedRnsObject& output,
        const std::vector<PreparedCanonicalTwiddles>& tables);
    void relinearize(
        const PreparedRnsObject& tensor,
        const PreparedEvaluationKey& relinearization_key,
        const PreparedKeySwitchConstants& constants,
        const PreparedRnsObject& output,
        const std::vector<PreparedCanonicalTwiddles>& tables);
    void rescale(
        const PreparedRnsObject& input,
        const PreparedRescaleConstants& constants,
        const PreparedRnsObject& output,
        const std::vector<PreparedCanonicalTwiddles>& tables);
    void rotate(
        const PreparedRnsObject& input,
        std::uint32_t galois_element,
        const PreparedEvaluationKey& galois_key,
        const PreparedKeySwitchConstants& constants,
        const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
        const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
        const PreparedRnsObject& coefficient_workspace,
        const PreparedRnsObject& output);
    void rotate_slots(
        const PreparedRnsObject& input,
        int steps,
        const PreparedEvaluationKey& galois_key,
        const PreparedKeySwitchConstants& constants,
        const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
        const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
        const PreparedRnsObject& coefficient_workspace,
        const PreparedRnsObject& output);
    void conjugate(
        const PreparedRnsObject& input,
        const PreparedEvaluationKey& galois_key,
        const PreparedKeySwitchConstants& constants,
        const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
        const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
        const PreparedRnsObject& coefficient_workspace,
        const PreparedRnsObject& output);

    // The coefficient object uses normal logical coefficient order. Twiddle
    // payloads are read from HPU_MEM and consumed in hardware stage order.
    void forward_ntt(
        const PreparedRnsObject& coefficient,
        const PreparedRnsObject& canonical_ntt,
        const std::vector<PreparedCanonicalTwiddles>& tables);
    void inverse_ntt(
        const PreparedRnsObject& canonical_ntt,
        const PreparedRnsObject& coefficient,
        const std::vector<PreparedCanonicalTwiddles>& tables);

    HpuRnsPolynomial export_component(
        const PreparedRnsObject& object,
        std::size_t component) const;
    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;

private:
    void ciphertext_binary(
        const PreparedRnsObject& left,
        const PreparedRnsObject& right,
        const PreparedRnsObject& output,
        hpu::runtime::PointwiseOperation operation);
    void plaintext_binary(
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& plaintext,
        const PreparedRnsObject& output,
        hpu::runtime::PointwiseOperation operation);
    void validate_object(
        const PreparedRnsObject& object,
        std::size_t component_count) const;
    void transform(
        const PreparedRnsObject& input,
        const PreparedRnsObject& output,
        const std::vector<PreparedCanonicalTwiddles>& tables,
        bool inverse);
    std::vector<std::uint32_t> transform_limb(
        const std::vector<std::uint32_t>& words,
        std::size_t degree,
        std::uint8_t modulus_id,
        const std::vector<PreparedCanonicalTwiddles>& tables,
        bool inverse) const;
    void validate_evaluation_key(
        const PreparedEvaluationKey& evaluation_key,
        const PreparedRnsObject& operand) const;
    void key_switch_impl(
        const PreparedRnsObject& base_ciphertext,
        const PreparedRnsObject& switching_component,
        const PreparedEvaluationKey& evaluation_key,
        const PreparedKeySwitchConstants& constants,
        const PreparedRnsObject& output,
        const std::vector<PreparedCanonicalTwiddles>& tables,
        bool switching_is_coefficient);

    const ::seal::SEALContext& context_;
    CkksLevelChain level_chain_;
    hpu::runtime::HpuSoftwareExecutor memory_;
};

} // namespace hpu::seal_adapter
