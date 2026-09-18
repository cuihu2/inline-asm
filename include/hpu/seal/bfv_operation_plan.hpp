#pragma once

#include "hpu/seal/bfv_application_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace hpu::seal_adapter {

enum class BfvOperationKind {
    add,
    subtract,
    multiply,
    add_plain,
    subtract_plain,
    multiply_plain,
    negate,
    mod_switch
};

struct BfvPlannedValue {
    std::string id;
    BfvValueMetadata metadata;
    std::size_t component_count = 0;
    hpu::runtime::PolynomialDomain domain = hpu::runtime::PolynomialDomain::coefficient;
    std::uint64_t key_domain = 1;
};

struct BfvOperationResources {
    bool requires_modulus_table = true;
    bool requires_canonical_twiddles = false;
    std::string evaluation_key_id;
    std::string keyswitch_constants_id;
    std::string multiply_constants_id;
    std::string mod_switch_constants_id;
};

struct BfvOperationStep {
    std::string id;
    BfvOperationKind kind = BfvOperationKind::add;
    std::vector<BfvPlannedValue> inputs;
    BfvPlannedValue output;
    BfvOperationResources resources;
};

// Plans BFV operations that preserve the two-component coefficient-domain
// ciphertext shape and canonical secret-key domain. No implicit level
// transition is inserted: only append_mod_switch moves to the adjacent level.
// MultiplyPlain explicitly owns its NTT/INTT round trip.
class BfvOperationPlan {
public:
    explicit BfvOperationPlan(BfvApplicationImageBuilder& image_builder);

    PreparedBfvRnsObject append_add(std::string step_id, const PreparedBfvRnsObject& left,
                                    const PreparedBfvRnsObject& right, std::string output_id);
    PreparedBfvRnsObject append_subtract(std::string step_id, const PreparedBfvRnsObject& left,
                                         const PreparedBfvRnsObject& right, std::string output_id);
    PreparedBfvRnsObject append_multiply(std::string step_id, const PreparedBfvRnsObject& left,
                                         const PreparedBfvRnsObject& right,
                                         const PreparedEvaluationKey& relinearization_key,
                                         const PreparedKeySwitchConstants& keyswitch_constants,
                                         const PreparedBfvMultiplyConstants& multiply_constants,
                                         std::string output_id);
    PreparedBfvRnsObject append_add_plain(std::string step_id,
                                          const PreparedBfvRnsObject& ciphertext,
                                          const PreparedBfvRnsObject& plaintext,
                                          std::string output_id);
    PreparedBfvRnsObject append_subtract_plain(std::string step_id,
                                               const PreparedBfvRnsObject& ciphertext,
                                               const PreparedBfvRnsObject& plaintext,
                                               std::string output_id);
    PreparedBfvRnsObject append_multiply_plain(std::string step_id,
                                               const PreparedBfvRnsObject& ciphertext,
                                               const PreparedBfvRnsObject& plaintext,
                                               std::string output_id);
    PreparedBfvRnsObject append_negate(std::string step_id, const PreparedBfvRnsObject& ciphertext,
                                       std::string output_id);
    PreparedBfvRnsObject append_mod_switch(std::string step_id,
                                           const PreparedBfvRnsObject& ciphertext,
                                           const PreparedBfvModSwitchConstants& constants,
                                           std::string output_id);

    const std::vector<BfvOperationStep>& steps() const noexcept;

private:
    void require_new_step(const std::string& step_id) const;
    void commit_step(BfvOperationStep step);
    BfvPlannedValue describe(const PreparedBfvRnsObject& object) const;
    void validate_value(const PreparedBfvRnsObject& object, std::size_t component_count,
                        hpu::runtime::PolynomialDomain domain, bool require_prepared_plaintext,
                        const char* role) const;
    void validate_canonical_twiddles(const BfvLevelDescriptor& level,
                                     bool include_multiply_auxiliary = false) const;
    void validate_multiply_resources(const BfvLevelDescriptor& level,
                                     const PreparedEvaluationKey& relinearization_key,
                                     const PreparedKeySwitchConstants& keyswitch_constants,
                                     const PreparedBfvMultiplyConstants& multiply_constants) const;
    void require_same_level(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
                            const char* role) const;
    PreparedBfvRnsObject append_ciphertext_binary(BfvOperationKind kind, std::string step_id,
                                                  const PreparedBfvRnsObject& left,
                                                  const PreparedBfvRnsObject& right,
                                                  std::string output_id);
    PreparedBfvRnsObject append_plain_binary(BfvOperationKind kind, std::string step_id,
                                             const PreparedBfvRnsObject& ciphertext,
                                             const PreparedBfvRnsObject& plaintext,
                                             std::string output_id);

    BfvApplicationImageBuilder& image_builder_;
    std::vector<BfvOperationStep> steps_;
    std::unordered_set<std::string> step_ids_;
};

} // namespace hpu::seal_adapter
