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

std::size_t ntt_stage_count(std::size_t degree)
{
    std::size_t stages = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        ++stages;
    }
    return stages;
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

PreparedBfvRnsObject BfvOperationPlan::append_multiply_plain(std::string step_id,
                                                             const PreparedBfvRnsObject& ciphertext,
                                                             const PreparedBfvRnsObject& plaintext,
                                                             std::string output_id)
{
    require_new_step(step_id);
    validate_value(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV MultiplyPlain ciphertext");
    validate_value(plaintext, 1, hpu::runtime::PolynomialDomain::canonical_ntt_physical, true,
                   "BFV prepared MultiplyPlain plaintext");
    require_same_level(ciphertext, plaintext, "BFV MultiplyPlain");
    const auto& level = image_builder_.level_chain().require(ciphertext.parms_id);
    validate_canonical_twiddles(level);
    auto output = image_builder_.reserve_ciphertext(std::move(output_id), level);

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = BfvOperationKind::multiply_plain;
    step.inputs = {describe(ciphertext), describe(plaintext)};
    step.output = describe(output);
    step.resources.requires_canonical_twiddles = true;
    commit_step(std::move(step));
    return output;
}

PreparedBfvRnsObject BfvOperationPlan::append_negate(std::string step_id,
                                                     const PreparedBfvRnsObject& ciphertext,
                                                     std::string output_id)
{
    require_new_step(step_id);
    validate_value(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV Negate input");
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
                                      std::size_t component_count,
                                      hpu::runtime::PolynomialDomain domain,
                                      bool require_prepared_plaintext, const char* role) const
{
    if (object.id.empty() || object.components.size() != component_count ||
        object.domain != domain || object.key_domain != 1) {
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

void BfvOperationPlan::validate_canonical_twiddles(const BfvLevelDescriptor& level) const
{
    const std::size_t degree = image_builder_.registry().poly_modulus_degree;
    const std::size_t stages = ntt_stage_count(degree);
    const auto require_twiddle = [&](const std::string& id, std::size_t words) {
        try {
            const auto& allocation = image_builder_.image().allocation(id);
            if (allocation.word_count != words || allocation.span.line_count == 0 ||
                allocation.kind != hpu::runtime::AllocationKind::twiddle || !allocation.read_only) {
                throw std::invalid_argument(
                    "BFV MultiplyPlain canonical twiddle has an incompatible allocation: " + id);
            }
        } catch (const std::out_of_range&) {
            throw std::invalid_argument("BFV MultiplyPlain canonical twiddle is absent: " + id);
        }
    };
    for (int modulus_id : level.keyswitch_layout.q_mod_ids) {
        const std::string prefix = "constants/twiddle/canonical/mod" + std::to_string(modulus_id);
        require_twiddle(prefix + "/ntt/pre_twist", degree);
        for (std::size_t stage = 0; stage < stages; ++stage) {
            require_twiddle(prefix + "/ntt/stage" + std::to_string(stage), degree / 2);
            require_twiddle(prefix + "/intt/stage" + std::to_string(stage), degree / 2);
        }
        require_twiddle(prefix + "/intt/post_untwist_scale", degree);
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
    validate_value(left, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV binary left input");
    validate_value(right, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV binary right input");
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
    validate_value(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV plaintext binary ciphertext");
    validate_value(plaintext, 1, hpu::runtime::PolynomialDomain::coefficient, true,
                   "BFV prepared Add/Sub plaintext");
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
