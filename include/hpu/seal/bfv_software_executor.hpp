#pragma once

#include "hpu/runtime/software_executor.hpp"
#include "hpu/seal/bfv_application_image.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

// Functional execution of the HPU BFV coefficient-domain path over the same
// prepared HpuMemImage used by codegen/relocation. This class does not call
// seal::Evaluator; modified-SEAL remains an independent differential oracle.
class BfvSoftwareExecutor {
public:
    BfvSoftwareExecutor(const ::seal::SEALContext& context, const hpu::runtime::HpuMemImage& image);

    void add(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
             const PreparedBfvRnsObject& output);
    void subtract(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
                  const PreparedBfvRnsObject& output);
    void multiply(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
                  const PreparedEvaluationKey& relinearization_key,
                  const PreparedKeySwitchConstants& keyswitch_constants,
                  const PreparedBfvMultiplyConstants& multiply_constants,
                  const std::vector<PreparedCanonicalTwiddles>& tables,
                  const PreparedBfvRnsObject& output);
    void mod_switch(const PreparedBfvRnsObject& input,
                    const PreparedBfvModSwitchConstants& constants,
                    const PreparedBfvRnsObject& output);
    void add_plain(const PreparedBfvRnsObject& ciphertext, const PreparedBfvRnsObject& plaintext,
                   const PreparedBfvRnsObject& output);
    void subtract_plain(const PreparedBfvRnsObject& ciphertext,
                        const PreparedBfvRnsObject& plaintext, const PreparedBfvRnsObject& output);
    void multiply_plain(const PreparedBfvRnsObject& ciphertext,
                        const PreparedBfvRnsObject& plaintext,
                        const std::vector<PreparedCanonicalTwiddles>& tables,
                        const PreparedBfvRnsObject& output);
    void negate(const PreparedBfvRnsObject& ciphertext, const PreparedBfvRnsObject& output);
    void rotate_rows(const PreparedBfvRnsObject& input, int steps,
                     const PreparedEvaluationKey& galois_key,
                     const PreparedKeySwitchConstants& keyswitch_constants,
                     const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
                     const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
                     const PreparedBfvRnsObject& coefficient_workspace,
                     const PreparedBfvRnsObject& output);
    void rotate_columns(const PreparedBfvRnsObject& input,
                        const PreparedEvaluationKey& galois_key,
                        const PreparedKeySwitchConstants& keyswitch_constants,
                        const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
                        const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
                        const PreparedBfvRnsObject& coefficient_workspace,
                        const PreparedBfvRnsObject& output);

    HpuRnsPolynomial export_component(const PreparedBfvRnsObject& object,
                                      std::size_t component) const;
    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;

private:
    using Limb = std::vector<std::uint32_t>;
    using RnsPolynomial = std::vector<Limb>;

    void validate_object(const PreparedBfvRnsObject& object, std::size_t component_count,
                         hpu::runtime::PolynomialDomain domain,
                         std::uint64_t key_domain = 1) const;
    RnsPolynomial read_polynomial(const PreparedPolynomial& polynomial) const;
    void write_polynomial(const PreparedPolynomial& polynomial, const RnsPolynomial& words);
    std::uint32_t constant_value(const std::string& id, std::size_t degree,
                                 std::uint32_t modulus) const;
    Limb transform_limb(const Limb& words, std::size_t degree, std::uint8_t modulus_id,
                        const std::vector<PreparedCanonicalTwiddles>& tables, bool inverse) const;
    RnsPolynomial base_convert(const RnsPolynomial& input, const std::vector<int>& sources,
                               const std::vector<int>& targets, const std::string& prefix,
                               const std::string& inverse_prefix = {});
    void ciphertext_binary(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
                           const PreparedBfvRnsObject& output,
                           hpu::runtime::PointwiseOperation operation);
    void plaintext_binary(const PreparedBfvRnsObject& ciphertext,
                          const PreparedBfvRnsObject& plaintext, const PreparedBfvRnsObject& output,
                          hpu::runtime::PointwiseOperation operation);
    void key_switch_coefficients(const RnsPolynomial& switching, const RnsPolynomial& base0,
                                 const RnsPolynomial* base1,
                                 const BfvLevelDescriptor& level,
                                 const PreparedEvaluationKey& evaluation_key,
                                 const PreparedKeySwitchConstants& constants,
                                 const std::vector<PreparedCanonicalTwiddles>& tables,
                                 const PreparedBfvRnsObject& output);
    void rotate(const PreparedBfvRnsObject& input, std::uint32_t galois_element,
                const PreparedEvaluationKey& galois_key,
                const PreparedKeySwitchConstants& keyswitch_constants,
                const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
                const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
                const PreparedBfvRnsObject& coefficient_workspace,
                const PreparedBfvRnsObject& output);

    const hpu::runtime::HpuMemImage& image_;
    BfvLevelChain level_chain_;
    hpu::runtime::HpuSoftwareExecutor memory_;
};

} // namespace hpu::seal_adapter
