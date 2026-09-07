#pragma once

#include "hpu/runtime/software_executor.hpp"
#include "hpu/seal/application_image.hpp"
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
    void square(
        const PreparedRnsObject& ciphertext,
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
    void require_same_level(
        const PreparedRnsObject& left,
        const PreparedRnsObject& right,
        const PreparedRnsObject& output) const;
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

    const ::seal::SEALContext& context_;
    hpu::runtime::HpuSoftwareExecutor memory_;
};

} // namespace hpu::seal_adapter
