#include "hpu/seal/operation_plan.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

constexpr auto canonical_domain =
    hpu::runtime::PolynomialDomain::canonical_ntt_physical;

void require_resource_id(const std::string& id, const char* role)
{
    if (id.empty()) {
        throw std::invalid_argument(std::string(role) + " has an empty id");
    }
}

bool same_span(
    const hpu::runtime::HpuMemSpan& left,
    const hpu::runtime::HpuMemSpan& right)
{
    return left.line_offset == right.line_offset
        && left.line_count == right.line_count;
}

void require_image_allocation(
    const hpu::runtime::HpuMemImage& image,
    const std::string& id,
    const hpu::runtime::HpuMemSpan& span,
    std::size_t word_count,
    const char* role)
{
    try {
        const auto& allocation = image.allocation(id);
        if (!same_span(allocation.span, span)
            || allocation.word_count != word_count) {
            throw std::invalid_argument(
                std::string(role) + " does not belong to this HPU_MEM image");
        }
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(
            std::string(role) + " is absent from this HPU_MEM image");
    }
}

void validate_polynomial_allocations(
    const hpu::runtime::HpuMemImage& image,
    const PreparedPolynomial& polynomial,
    const std::vector<std::uint8_t>& expected_modulus_ids,
    const char* role)
{
    if (polynomial.id.empty() || polynomial.degree == 0
        || polynomial.modulus_ids != expected_modulus_ids
        || polynomial.limbs.size() != expected_modulus_ids.size()) {
        throw std::invalid_argument(
            std::string(role) + " has an invalid RNS allocation shape");
    }
    for (std::size_t basis = 0; basis < polynomial.limbs.size(); ++basis) {
        require_image_allocation(
            image,
            polynomial.id + "/mod"
                + std::to_string(polynomial.modulus_ids[basis]),
            polynomial.limbs[basis], polynomial.degree, role);
    }
}

std::vector<std::uint8_t> modulus_ids(
    const std::vector<int>& q_ids,
    const std::vector<int>& p_ids = {})
{
    std::vector<std::uint8_t> result;
    result.reserve(q_ids.size() + p_ids.size());
    for (int id : q_ids) {
        result.push_back(static_cast<std::uint8_t>(id));
    }
    for (int id : p_ids) {
        result.push_back(static_cast<std::uint8_t>(id));
    }
    return result;
}

void validate_evaluation_key_resource(
    const hpu::runtime::HpuMemImage& image,
    const CkksLevelDescriptor& level,
    const PreparedEvaluationKey& evaluation_key,
    std::size_t degree)
{
    if (evaluation_key.rns_layout.q_mod_ids
            != level.rns_layout.q_mod_ids
        || evaluation_key.rns_layout.p_mod_ids
            != level.rns_layout.p_mod_ids
        || evaluation_key.rns_layout.key_digits
            != level.rns_layout.key_digits
        || evaluation_key.digits.size()
            != level.rns_layout.key_digits.size()) {
        throw std::invalid_argument(
            "CKKS Relinearize evaluation key has the wrong RNS layout");
    }
    const auto expected_modulus_ids = modulus_ids(
        level.rns_layout.q_mod_ids, level.rns_layout.p_mod_ids);
    for (const auto& digit : evaluation_key.digits) {
        if (digit.size() != 2) {
            throw std::invalid_argument(
                "CKKS Relinearize evaluation-key digit needs two components");
        }
        for (const auto& polynomial : digit) {
            if (polynomial.degree != degree) {
                throw std::invalid_argument(
                    "CKKS Relinearize evaluation-key degree mismatch");
            }
            validate_polynomial_allocations(
                image, polynomial, expected_modulus_ids,
                "CKKS Relinearize evaluation key");
        }
    }
}

void validate_constant_resource(
    const hpu::runtime::HpuMemImage& image,
    const std::string& id,
    const hpu::runtime::HpuMemSpan& span,
    const char* role)
{
    require_resource_id(id, role);
    try {
        const auto& allocation = image.allocation(id);
        if (!same_span(allocation.span, span)
            || allocation.kind != hpu::runtime::AllocationKind::constant
            || !allocation.read_only) {
            throw std::invalid_argument(
                std::string(role) + " does not match its HPU_MEM allocation");
        }
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(
            std::string(role) + " is absent from this HPU_MEM image");
    }
}

} // namespace

CkksOperationPlan::CkksOperationPlan(
    CkksApplicationImageBuilder& image_builder)
    : image_builder_(image_builder)
{}

PreparedRnsObject CkksOperationPlan::append_square(
    std::string step_id,
    const PreparedRnsObject& input,
    std::string output_id)
{
    require_new_step(step_id);
    validate_value(input, 2, "CKKS Square input");
    const auto output_metadata = infer_ckks_multiply_metadata(
        image_builder_.level_chain(), input.metadata(), input.metadata());
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), output_metadata, 3);

    CkksOperationStep step;
    step.id = std::move(step_id);
    step.kind = CkksOperationKind::square;
    step.inputs = {describe(input)};
    step.output = describe(output);
    commit_step(std::move(step));
    return output;
}

PreparedRnsObject CkksOperationPlan::append_relinearize(
    std::string step_id,
    const PreparedRnsObject& tensor,
    const PreparedEvaluationKey& evaluation_key,
    const PreparedKeySwitchConstants& constants,
    std::string output_id)
{
    require_new_step(step_id);
    validate_value(tensor, 3, "CKKS Relinearize input");
    require_resource_id(evaluation_key.id, "CKKS Relinearize evaluation key");
    if (evaluation_key.data_parms_id != tensor.parms_id
        || evaluation_key.chain_index != tensor.chain_index
        || constants.data_parms_id != tensor.parms_id
        || constants.chain_index != tensor.chain_index) {
        throw std::invalid_argument(
            "CKKS Relinearize resources do not match the tensor level");
    }
    const auto& level = image_builder_.level_chain().require(tensor.parms_id);
    validate_evaluation_key_resource(
        image_builder_.image(), level, evaluation_key,
        tensor.components.front().degree);
    validate_constant_resource(
        image_builder_.image(), constants.id, constants.values,
        "CKKS Relinearize constants");

    const auto output_metadata = infer_ckks_preserving_metadata(
        image_builder_.level_chain(), tensor.metadata());
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), output_metadata, 2);

    CkksOperationStep step;
    step.id = std::move(step_id);
    step.kind = CkksOperationKind::relinearize;
    step.inputs = {describe(tensor)};
    step.output = describe(output);
    step.resources.requires_canonical_twiddles = true;
    step.resources.evaluation_key_ids = {evaluation_key.id};
    step.resources.constant_ids = {constants.id};
    commit_step(std::move(step));
    return output;
}

PreparedRnsObject CkksOperationPlan::append_rescale(
    std::string step_id,
    const PreparedRnsObject& input,
    const PreparedRescaleConstants& constants,
    std::string output_id)
{
    require_new_step(step_id);
    if (input.components.empty()) {
        throw std::invalid_argument("CKKS Rescale input has no components");
    }
    validate_value(input, input.components.size(), "CKKS Rescale input");
    const auto output_metadata = infer_ckks_rescale_metadata(
        image_builder_.level_chain(), input.metadata());
    if (constants.source_parms_id != input.parms_id
        || constants.source_chain_index != input.chain_index
        || constants.destination_parms_id != output_metadata.parms_id
        || constants.destination_chain_index != output_metadata.chain_index) {
        throw std::invalid_argument(
            "CKKS Rescale constants do not match the adjacent level transition");
    }
    validate_constant_resource(
        image_builder_.image(), constants.id, constants.values,
        "CKKS Rescale constants");
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), output_metadata, input.components.size());

    CkksOperationStep step;
    step.id = std::move(step_id);
    step.kind = CkksOperationKind::rescale;
    step.inputs = {describe(input)};
    step.output = describe(output);
    step.resources.requires_canonical_twiddles = true;
    step.resources.constant_ids = {constants.id};
    commit_step(std::move(step));
    return output;
}

PreparedRnsObject CkksOperationPlan::append_add_plain(
    std::string step_id,
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& plaintext,
    std::string output_id)
{
    require_new_step(step_id);
    validate_value(ciphertext, 2, "CKKS AddPlain ciphertext");
    validate_value(plaintext, 1, "CKKS AddPlain plaintext");
    const auto output_metadata = infer_ckks_add_sub_metadata(
        image_builder_.level_chain(),
        ciphertext.metadata(), plaintext.metadata());
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), output_metadata, 2);

    CkksOperationStep step;
    step.id = std::move(step_id);
    step.kind = CkksOperationKind::add_plain;
    step.inputs = {describe(ciphertext), describe(plaintext)};
    step.output = describe(output);
    commit_step(std::move(step));
    return output;
}

const std::vector<CkksOperationStep>& CkksOperationPlan::steps() const noexcept
{
    return steps_;
}

void CkksOperationPlan::require_new_step(const std::string& step_id) const
{
    if (step_id.empty()) {
        throw std::invalid_argument("CKKS operation step id cannot be empty");
    }
    if (step_ids_.find(step_id) != step_ids_.end()) {
        throw std::invalid_argument("duplicate CKKS operation step id: " + step_id);
    }
}

void CkksOperationPlan::commit_step(CkksOperationStep step)
{
    step_ids_.insert(step.id);
    steps_.push_back(std::move(step));
}

CkksPlannedValue CkksOperationPlan::describe(
    const PreparedRnsObject& object) const
{
    return {
        object.id,
        object.metadata(),
        object.components.size(),
        object.domain,
        object.key_domain
    };
}

void CkksOperationPlan::validate_value(
    const PreparedRnsObject& object,
    std::size_t component_count,
    const char* role) const
{
    if (object.id.empty() || object.components.size() != component_count) {
        throw std::invalid_argument(
            std::string(role) + " has an invalid id or component count");
    }
    validate_ckks_metadata(
        image_builder_.level_chain(), object.metadata(), role);
    if (object.domain != canonical_domain || object.key_domain != 1) {
        throw std::invalid_argument(
            std::string(role) + " is not in canonical NTT/key domain");
    }
    const auto& level = image_builder_.level_chain().require(object.parms_id);
    const auto expected_modulus_ids = modulus_ids(
        level.rns_layout.q_mod_ids);
    for (std::size_t component = 0;
         component < object.components.size(); ++component) {
        if (object.components[component].id
            != object.id + "/c" + std::to_string(component)) {
            throw std::invalid_argument(
                std::string(role) + " has an inconsistent component id");
        }
        validate_polynomial_allocations(
            image_builder_.image(), object.components[component],
            expected_modulus_ids, role);
    }
}

} // namespace hpu::seal_adapter
