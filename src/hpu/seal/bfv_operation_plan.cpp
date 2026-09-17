#include "hpu/seal/bfv_operation_plan.hpp"

#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

bool same_span(const hpu::runtime::HpuMemSpan& left, const hpu::runtime::HpuMemSpan& right)
{
    return left.line_offset == right.line_offset && left.line_count == right.line_count;
}

std::vector<std::uint8_t> q_modulus_ids(const BfvLevelDescriptor& level)
{
    std::vector<std::uint8_t> result;
    result.reserve(level.keyswitch_layout.q_mod_ids.size());
    for (int id : level.keyswitch_layout.q_mod_ids) {
        result.push_back(static_cast<std::uint8_t>(id));
    }
    return result;
}

} // namespace

BfvOperationPlan::BfvOperationPlan(BfvApplicationImageBuilder& image_builder)
    : image_builder_(image_builder)
{
}

PreparedBfvRnsObject BfvOperationPlan::append_add(std::string step_id,
                                                  const PreparedBfvRnsObject& left,
                                                  const PreparedBfvRnsObject& right,
                                                  std::string output_id)
{
    return append_ciphertext_binary(BfvOperationKind::add, std::move(step_id), left, right,
                                    std::move(output_id));
}

PreparedBfvRnsObject BfvOperationPlan::append_subtract(std::string step_id,
                                                       const PreparedBfvRnsObject& left,
                                                       const PreparedBfvRnsObject& right,
                                                       std::string output_id)
{
    return append_ciphertext_binary(BfvOperationKind::subtract, std::move(step_id), left, right,
                                    std::move(output_id));
}

PreparedBfvRnsObject BfvOperationPlan::append_add_plain(std::string step_id,
                                                        const PreparedBfvRnsObject& ciphertext,
                                                        const PreparedBfvRnsObject& plaintext,
                                                        std::string output_id)
{
    return append_plain_binary(BfvOperationKind::add_plain, std::move(step_id), ciphertext,
                               plaintext, std::move(output_id));
}

PreparedBfvRnsObject BfvOperationPlan::append_subtract_plain(std::string step_id,
                                                             const PreparedBfvRnsObject& ciphertext,
                                                             const PreparedBfvRnsObject& plaintext,
                                                             std::string output_id)
{
    return append_plain_binary(BfvOperationKind::subtract_plain, std::move(step_id), ciphertext,
                               plaintext, std::move(output_id));
}

PreparedBfvRnsObject BfvOperationPlan::append_negate(std::string step_id,
                                                     const PreparedBfvRnsObject& ciphertext,
                                                     std::string output_id)
{
    require_new_step(step_id);
    validate_value(ciphertext, 2, false, "BFV Negate input");
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), image_builder_.level_chain().require(ciphertext.parms_id));

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = BfvOperationKind::negate;
    step.inputs = {describe(ciphertext)};
    step.output = describe(output);
    commit_step(std::move(step));
    return output;
}

const std::vector<BfvOperationStep>& BfvOperationPlan::steps() const noexcept
{
    return steps_;
}

void BfvOperationPlan::require_new_step(const std::string& step_id) const
{
    if (step_id.empty()) {
        throw std::invalid_argument("BFV operation step id cannot be empty");
    }
    if (step_ids_.find(step_id) != step_ids_.end()) {
        throw std::invalid_argument("duplicate BFV operation step id: " + step_id);
    }
}

void BfvOperationPlan::commit_step(BfvOperationStep step)
{
    step_ids_.insert(step.id);
    steps_.push_back(std::move(step));
}

BfvPlannedValue BfvOperationPlan::describe(const PreparedBfvRnsObject& object) const
{
    return {object.id, object.metadata(), object.components.size(), object.domain,
            object.key_domain};
}

void BfvOperationPlan::validate_value(const PreparedBfvRnsObject& object,
                                      std::size_t component_count, bool require_prepared_plaintext,
                                      const char* role) const
{
    if (object.id.empty() || object.components.size() != component_count ||
        object.domain != hpu::runtime::PolynomialDomain::coefficient || object.key_domain != 1) {
        throw std::invalid_argument(std::string(role) +
                                    " has an incompatible shape or representation");
    }
    const auto& level = image_builder_.level_chain().require(object.parms_id);
    if (object.chain_index != level.chain_index) {
        throw std::invalid_argument(std::string(role) + " has inconsistent BFV level metadata");
    }
    const auto expected_modulus_ids = q_modulus_ids(level);
    const std::size_t degree = image_builder_.registry().poly_modulus_degree;
    for (std::size_t component = 0; component < object.components.size(); ++component) {
        const auto& polynomial = object.components[component];
        if (polynomial.id != object.id + "/c" + std::to_string(component) ||
            polynomial.degree != degree || polynomial.modulus_ids != expected_modulus_ids ||
            polynomial.limbs.size() != expected_modulus_ids.size()) {
            throw std::invalid_argument(std::string(role) + " has an invalid RNS allocation shape");
        }
        for (std::size_t basis = 0; basis < polynomial.limbs.size(); ++basis) {
            const std::string allocation_id =
                polynomial.id + "/mod" + std::to_string(polynomial.modulus_ids[basis]);
            try {
                const auto& allocation = image_builder_.image().allocation(allocation_id);
                if (!same_span(allocation.span, polynomial.limbs[basis]) ||
                    allocation.word_count != degree ||
                    (require_prepared_plaintext &&
                     (allocation.kind != hpu::runtime::AllocationKind::plaintext ||
                      !allocation.read_only))) {
                    throw std::invalid_argument(std::string(role) +
                                                " does not belong to this BFV HPU_MEM image");
                }
            } catch (const std::out_of_range&) {
                throw std::invalid_argument(std::string(role) +
                                            " is absent from this BFV HPU_MEM image");
            }
        }
    }
}

void BfvOperationPlan::require_same_level(const PreparedBfvRnsObject& left,
                                          const PreparedBfvRnsObject& right, const char* role) const
{
    if (left.parms_id != right.parms_id || left.chain_index != right.chain_index) {
        throw std::invalid_argument(std::string(role) + " operands must use the same BFV level");
    }
}

PreparedBfvRnsObject BfvOperationPlan::append_ciphertext_binary(BfvOperationKind kind,
                                                                std::string step_id,
                                                                const PreparedBfvRnsObject& left,
                                                                const PreparedBfvRnsObject& right,
                                                                std::string output_id)
{
    require_new_step(step_id);
    if (kind != BfvOperationKind::add && kind != BfvOperationKind::subtract) {
        throw std::invalid_argument("invalid BFV ciphertext binary kind");
    }
    validate_value(left, 2, false, "BFV binary left input");
    validate_value(right, 2, false, "BFV binary right input");
    require_same_level(left, right, "BFV ciphertext binary");
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), image_builder_.level_chain().require(left.parms_id));

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = kind;
    step.inputs = {describe(left), describe(right)};
    step.output = describe(output);
    commit_step(std::move(step));
    return output;
}

PreparedBfvRnsObject BfvOperationPlan::append_plain_binary(BfvOperationKind kind,
                                                           std::string step_id,
                                                           const PreparedBfvRnsObject& ciphertext,
                                                           const PreparedBfvRnsObject& plaintext,
                                                           std::string output_id)
{
    require_new_step(step_id);
    if (kind != BfvOperationKind::add_plain && kind != BfvOperationKind::subtract_plain) {
        throw std::invalid_argument("invalid BFV plaintext binary kind");
    }
    validate_value(ciphertext, 2, false, "BFV plaintext binary ciphertext");
    validate_value(plaintext, 1, true, "BFV prepared Add/Sub plaintext");
    require_same_level(ciphertext, plaintext, "BFV plaintext binary");
    auto output = image_builder_.reserve_ciphertext(
        std::move(output_id), image_builder_.level_chain().require(ciphertext.parms_id));

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = kind;
    step.inputs = {describe(ciphertext), describe(plaintext)};
    step.output = describe(output);
    commit_step(std::move(step));
    return output;
}

} // namespace hpu::seal_adapter
