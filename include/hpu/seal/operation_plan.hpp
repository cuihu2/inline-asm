#pragma once

#include "hpu/seal/application_image.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace hpu::seal_adapter {

enum class CkksOperationKind {
    square,
    relinearize,
    rescale,
    add_plain
};

struct CkksPlannedValue {
    std::string id;
    CkksValueMetadata metadata;
    std::size_t component_count = 0;
    hpu::runtime::PolynomialDomain domain =
        hpu::runtime::PolynomialDomain::canonical_ntt_physical;
    std::uint64_t key_domain = 1;
};

struct CkksOperationResources {
    bool requires_modulus_table = true;
    bool requires_canonical_twiddles = false;
    std::vector<std::string> evaluation_key_ids;
    std::vector<std::string> constant_ids;
};

struct CkksOperationStep {
    std::string id;
    CkksOperationKind kind = CkksOperationKind::square;
    std::vector<CkksPlannedValue> inputs;
    CkksPlannedValue output;
    CkksOperationResources resources;
};

// Builds an explicit CKKS operation sequence while allocating each output in
// the application image. Methods never insert an implicit operation: a caller
// that needs Rescale or Relinearize must append it explicitly.
class CkksOperationPlan {
public:
    explicit CkksOperationPlan(CkksApplicationImageBuilder& image_builder);

    PreparedRnsObject append_square(
        std::string step_id,
        const PreparedRnsObject& input,
        std::string output_id);
    PreparedRnsObject append_relinearize(
        std::string step_id,
        const PreparedRnsObject& tensor,
        const PreparedEvaluationKey& evaluation_key,
        const PreparedKeySwitchConstants& constants,
        std::string output_id);
    PreparedRnsObject append_rescale(
        std::string step_id,
        const PreparedRnsObject& input,
        const PreparedRescaleConstants& constants,
        std::string output_id);
    PreparedRnsObject append_add_plain(
        std::string step_id,
        const PreparedRnsObject& ciphertext,
        const PreparedRnsObject& plaintext,
        std::string output_id);

    const std::vector<CkksOperationStep>& steps() const noexcept;

private:
    void require_new_step(const std::string& step_id) const;
    void commit_step(CkksOperationStep step);
    CkksPlannedValue describe(const PreparedRnsObject& object) const;
    void validate_value(
        const PreparedRnsObject& object,
        std::size_t component_count,
        const char* role) const;

    CkksApplicationImageBuilder& image_builder_;
    std::vector<CkksOperationStep> steps_;
    std::unordered_set<std::string> step_ids_;
};

} // namespace hpu::seal_adapter
