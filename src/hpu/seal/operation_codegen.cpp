#include "hpu/seal/operation_codegen.hpp"

#include "poly/cmult.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "scheme/ckks/relinearize.hpp"
#include "scheme/ckks/rescale.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

constexpr int kModulusTableObject = 4;
constexpr auto kCanonicalDomain =
    hpu::runtime::PolynomialDomain::canonical_ntt_physical;

void require_value_shape(
    const CkksLevelChain& level_chain,
    const CkksPlannedValue& value,
    std::size_t components,
    const char* role)
{
    validate_ckks_metadata(level_chain, value.metadata, role);
    if (value.id.empty() || value.component_count != components
        || value.domain != kCanonicalDomain || value.key_domain != 1) {
        throw std::invalid_argument(
            std::string(role) + " has an incompatible shape or representation");
    }
}

void require_common_step_contract(const CkksOperationStep& step)
{
    if (step.id.empty() || !step.resources.requires_modulus_table) {
        throw std::invalid_argument(
            "lowered CKKS step lacks its id or modulus-table requirement");
    }
}

void require_resource_ids(
    const std::vector<std::string>& ids,
    std::size_t expected_size,
    const char* role)
{
    if (ids.size() != expected_size) {
        throw std::invalid_argument(
            std::string(role) + " has an incorrect resource count");
    }
    for (const auto& id : ids) {
        if (id.empty()) {
            throw std::invalid_argument(
                std::string(role) + " has an empty resource id");
        }
    }
}

std::string lower_step(
    const CkksOperationStep& step,
    const CkksLevelChain& level_chain,
    int degree)
{
    require_common_step_contract(step);
    switch (step.kind) {
    case CkksOperationKind::square: {
        if (step.inputs.size() != 1
            || step.resources.requires_canonical_twiddles
            || !step.resources.evaluation_key_ids.empty()
            || !step.resources.constant_ids.empty()) {
            throw std::invalid_argument("invalid planned CKKS Square resources");
        }
        require_value_shape(
            level_chain, step.inputs.front(), 2, "planned CKKS Square input");
        require_value_shape(
            level_chain, step.output, 3, "planned CKKS Square output");
        require_ckks_metadata_matches(
            level_chain,
            infer_ckks_multiply_metadata(
                level_chain, step.inputs.front().metadata,
                step.inputs.front().metadata),
            step.output.metadata, "planned CKKS Square output");
        const auto& level = level_chain.require(
            step.inputs.front().metadata.parms_id);
        return ::generate_hpu_cmult_body_asm(
            static_cast<int>(level.q_moduli.size()), false, false);
    }
    case CkksOperationKind::relinearize: {
        if (step.inputs.size() != 1
            || !step.resources.requires_canonical_twiddles) {
            throw std::invalid_argument(
                "invalid planned CKKS Relinearize resources");
        }
        require_resource_ids(
            step.resources.evaluation_key_ids, 1,
            "planned CKKS Relinearize");
        require_resource_ids(
            step.resources.constant_ids, 1,
            "planned CKKS Relinearize");
        require_value_shape(
            level_chain, step.inputs.front(), 3,
            "planned CKKS Relinearize input");
        require_value_shape(
            level_chain, step.output, 2,
            "planned CKKS Relinearize output");
        require_ckks_metadata_matches(
            level_chain,
            infer_ckks_preserving_metadata(
                level_chain, step.inputs.front().metadata),
            step.output.metadata, "planned CKKS Relinearize output");
        const auto& level = level_chain.require(
            step.inputs.front().metadata.parms_id);
        return hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
            degree, level.rns_layout, false, false);
    }
    case CkksOperationKind::rescale: {
        if (step.inputs.size() != 1
            || !step.resources.requires_canonical_twiddles
            || !step.resources.evaluation_key_ids.empty()) {
            throw std::invalid_argument(
                "invalid planned CKKS Rescale resources");
        }
        require_resource_ids(
            step.resources.constant_ids, 1, "planned CKKS Rescale");
        const auto components = step.inputs.front().component_count;
        if (components == 0 || step.output.component_count != components) {
            throw std::invalid_argument(
                "planned CKKS Rescale changed its component count");
        }
        require_value_shape(
            level_chain, step.inputs.front(), components,
            "planned CKKS Rescale input");
        require_value_shape(
            level_chain, step.output, components,
            "planned CKKS Rescale output");
        require_ckks_metadata_matches(
            level_chain,
            infer_ckks_rescale_metadata(
                level_chain, step.inputs.front().metadata),
            step.output.metadata, "planned CKKS Rescale output");
        if (components != 2) {
            throw std::invalid_argument(
                "standalone CKKS Rescale codegen currently requires two components");
        }
        const auto& level = level_chain.require(
            step.inputs.front().metadata.parms_id);
        return hpu::scheme::ckks::generate_rescale_ntt_body_asm(
            degree, static_cast<int>(level.q_moduli.size()), false, false);
    }
    case CkksOperationKind::add_plain: {
        if (step.inputs.size() != 2
            || step.resources.requires_canonical_twiddles
            || !step.resources.evaluation_key_ids.empty()
            || !step.resources.constant_ids.empty()) {
            throw std::invalid_argument("invalid planned CKKS AddPlain resources");
        }
        require_value_shape(
            level_chain, step.inputs[0], 2,
            "planned CKKS AddPlain ciphertext");
        require_value_shape(
            level_chain, step.inputs[1], 1,
            "planned CKKS AddPlain plaintext");
        require_value_shape(
            level_chain, step.output, 2,
            "planned CKKS AddPlain output");
        require_ckks_metadata_matches(
            level_chain,
            infer_ckks_add_sub_metadata(
                level_chain, step.inputs[0].metadata,
                step.inputs[1].metadata),
            step.output.metadata, "planned CKKS AddPlain output");
        const auto& level = level_chain.require(
            step.inputs[0].metadata.parms_id);
        return hpu::scheme::ckks::generate_add_plain_body_asm(
            static_cast<int>(level.q_moduli.size()), false, false);
    }
    }
    throw std::invalid_argument("unknown planned CKKS operation kind");
}

} // namespace

CkksLoweredProgram lower_ckks_operation_plan(
    const CkksOperationPlan& plan,
    const ::seal::SEALContext& context,
    bool append_psync,
    bool manage_modulus_table)
{
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::ckks
        || key_data->parms().poly_modulus_degree()
            > static_cast<std::size_t>(std::numeric_limits<int>::max())
        || !hpu::is_valid_ntt_size(
            static_cast<int>(key_data->parms().poly_modulus_degree()))) {
        throw std::invalid_argument(
            "CKKS operation lowering requires a valid HPU CKKS context");
    }
    if (plan.steps().empty()) {
        throw std::invalid_argument("cannot lower an empty CKKS operation plan");
    }

    const int degree = static_cast<int>(
        key_data->parms().poly_modulus_degree());
    const CkksLevelChain level_chain(context);
    CkksLoweredProgram result;
    result.operations.reserve(plan.steps().size());
    if (manage_modulus_table) {
        result.body_asm += hpu::dload(
            kModulusTableObject,
            hpu::DataType::mod_ctx,
            hpu::DloadFlag::small_bank);
    }
    for (const auto& step : plan.steps()) {
        CkksLoweredOperation lowered;
        lowered.operation = step;
        lowered.body_asm = lower_step(step, level_chain, degree);
        result.body_asm += lowered.body_asm;
        result.operations.push_back(std::move(lowered));
    }
    if (manage_modulus_table) {
        result.body_asm += hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        result.body_asm += hpu::psync();
    }
    return result;
}

} // namespace hpu::seal_adapter
