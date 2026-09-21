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

    HpuRnsPolynomial export_component(const PreparedBfvRnsObject& object,
                                      std::size_t component) const;
    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;

private:
    using Limb = std::vector<std::uint32_t>;
    using RnsPolynomial = std::vector<Limb>;

    void validate_object(const PreparedBfvRnsObject& object, std::size_t component_count,
                         hpu::runtime::PolynomialDomain domain) const;
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

    const hpu::runtime::HpuMemImage& image_;
    BfvLevelChain level_chain_;
    hpu::runtime::HpuSoftwareExecutor memory_;
};

} // namespace hpu::seal_adapter
