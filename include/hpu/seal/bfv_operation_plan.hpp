#pragma once

#include "hpu/seal/bfv_application_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace hpu::seal_adapter {

enum class BfvOperationKind { add, subtract, add_plain, subtract_plain, negate };

struct BfvPlannedValue {
    std::string id;
    BfvValueMetadata metadata;
    std::size_t component_count = 0;
    hpu::runtime::PolynomialDomain domain = hpu::runtime::PolynomialDomain::coefficient;
    std::uint64_t key_domain = 1;
};

struct BfvOperationResources {
    bool requires_modulus_table = true;
};

struct BfvOperationStep {
    std::string id;
    BfvOperationKind kind = BfvOperationKind::add;
    std::vector<BfvPlannedValue> inputs;
    BfvPlannedValue output;
    BfvOperationResources resources;
};

// Plans BFV operations that preserve level, component count, coefficient
// domain, and canonical secret-key domain. No implicit transform or level
// transition is inserted.
class BfvOperationPlan {
public:
    explicit BfvOperationPlan(BfvApplicationImageBuilder& image_builder);

    PreparedBfvRnsObject append_add(std::string step_id, const PreparedBfvRnsObject& left,
                                    const PreparedBfvRnsObject& right, std::string output_id);
    PreparedBfvRnsObject append_subtract(std::string step_id, const PreparedBfvRnsObject& left,
                                         const PreparedBfvRnsObject& right, std::string output_id);
    PreparedBfvRnsObject append_add_plain(std::string step_id,
                                          const PreparedBfvRnsObject& ciphertext,
                                          const PreparedBfvRnsObject& plaintext,
                                          std::string output_id);
    PreparedBfvRnsObject append_subtract_plain(std::string step_id,
                                               const PreparedBfvRnsObject& ciphertext,
                                               const PreparedBfvRnsObject& plaintext,
                                               std::string output_id);
    PreparedBfvRnsObject append_negate(std::string step_id, const PreparedBfvRnsObject& ciphertext,
                                       std::string output_id);

    const std::vector<BfvOperationStep>& steps() const noexcept;

private:
    void require_new_step(const std::string& step_id) const;
    void commit_step(BfvOperationStep step);
    BfvPlannedValue describe(const PreparedBfvRnsObject& object) const;
    void validate_value(const PreparedBfvRnsObject& object, std::size_t component_count,
                        bool require_prepared_plaintext, const char* role) const;
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
