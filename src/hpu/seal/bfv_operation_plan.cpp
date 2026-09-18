#include "hpu/seal/bfv_operation_plan.hpp"

#include <algorithm>
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

std::vector<std::uint8_t> full_keyswitch_modulus_ids(const BfvLevelDescriptor& level)
{
    auto result = q_modulus_ids(level);
    for (int id : level.keyswitch_layout.p_mod_ids) {
        result.push_back(static_cast<std::uint8_t>(id));
    }
    return result;
}

void require_resource_id(const std::string& id, const char* role)
{
    if (id.empty()) {
        throw std::invalid_argument(std::string(role) + " id cannot be empty");
    }
}

void validate_constant_resource(const hpu::runtime::HpuMemImage& image, const std::string& id,
                                const hpu::runtime::HpuMemSpan& span, const char* role)
{
    require_resource_id(id, role);
    try {
        const auto& allocation = image.allocation(id);
        if (!same_span(allocation.span, span) || allocation.word_count == 0 ||
            allocation.kind != hpu::runtime::AllocationKind::constant || !allocation.read_only) {
            throw std::invalid_argument(std::string(role) +
                                        " does not match its BFV HPU_MEM allocation");
        }
    } catch (const std::out_of_range&) {
        throw std::invalid_argument(std::string(role) + " is absent from this BFV HPU_MEM image");
    }
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

PreparedBfvRnsObject BfvOperationPlan::append_multiply(
    std::string step_id, const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
    const PreparedEvaluationKey& relinearization_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const PreparedBfvMultiplyConstants& multiply_constants, std::string output_id)
{
    require_new_step(step_id);
    validate_value(left, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV Multiply left input");
    validate_value(right, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV Multiply right input");
    require_same_level(left, right, "BFV Multiply");
    const auto& level = image_builder_.level_chain().require(left.parms_id);
    validate_canonical_twiddles(level, true);
    validate_multiply_resources(level, relinearization_key, keyswitch_constants,
                                multiply_constants);
    auto output = image_builder_.reserve_ciphertext(std::move(output_id), level);

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = BfvOperationKind::multiply;
    step.inputs = {describe(left), describe(right)};
    step.output = describe(output);
    step.resources.requires_canonical_twiddles = true;
    step.resources.evaluation_key_id = relinearization_key.id;
    step.resources.keyswitch_constants_id = keyswitch_constants.id;
    step.resources.multiply_constants_id = multiply_constants.id;
    commit_step(std::move(step));
    return output;
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

PreparedBfvRnsObject
BfvOperationPlan::append_mod_switch(std::string step_id, const PreparedBfvRnsObject& ciphertext,
                                    const PreparedBfvModSwitchConstants& constants,
                                    std::string output_id)
{
    require_new_step(step_id);
    validate_value(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient, false,
                   "BFV ModSwitch input");
    const auto& source = image_builder_.level_chain().require(ciphertext.parms_id);
    if (!image_builder_.level_chain().has_next(source.parms_id)) {
        throw std::invalid_argument("BFV ModSwitch input has no next data level");
    }
    const auto& destination = image_builder_.level_chain().next(source.parms_id);
    if (constants.source_parms_id != source.parms_id ||
        constants.source_chain_index != source.chain_index ||
        constants.destination_parms_id != destination.parms_id ||
        constants.destination_chain_index != destination.chain_index ||
        constants.dropped_mod_id != source.keyswitch_layout.q_mod_ids.back()) {
        throw std::invalid_argument(
            "BFV ModSwitch constants do not match the adjacent level transition");
    }
    validate_constant_resource(image_builder_.image(), constants.id, constants.values,
                               "BFV ModSwitch constants");
    if (constants.hardware_prefix != constants.id + "/hardware" ||
        constants.hardware_component_capacity < ciphertext.components.size() ||
        constants.hardware_constant_polynomial_count == 0 ||
        constants.hardware_workspace_polynomial_count == 0) {
        throw std::invalid_argument("BFV ModSwitch constants lack hardware-expanded resources");
    }
    auto output = image_builder_.reserve_ciphertext(std::move(output_id), destination);

    BfvOperationStep step;
    step.id = std::move(step_id);
    step.kind = BfvOperationKind::mod_switch;
    step.inputs = {describe(ciphertext)};
    step.output = describe(output);
    step.resources.mod_switch_constants_id = constants.id;
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

void BfvOperationPlan::validate_canonical_twiddles(const BfvLevelDescriptor& level,
                                                   bool include_multiply_auxiliary) const
{
    const std::size_t degree = image_builder_.registry().poly_modulus_degree;
    const std::size_t stages = ntt_stage_count(degree);
    const auto require_twiddle = [&](const std::string& id, std::size_t words) {
        try {
            const auto& allocation = image_builder_.image().allocation(id);
            if (allocation.word_count != words || allocation.span.line_count == 0 ||
                allocation.kind != hpu::runtime::AllocationKind::twiddle || !allocation.read_only) {
                throw std::invalid_argument(
                    "BFV canonical twiddle has an incompatible allocation: " + id);
            }
        } catch (const std::out_of_range&) {
            throw std::invalid_argument("BFV canonical twiddle is absent: " + id);
        }
    };
    std::vector<int> contexts = level.keyswitch_layout.q_mod_ids;
    if (include_multiply_auxiliary) {
        contexts.insert(contexts.end(), level.keyswitch_layout.p_mod_ids.begin(),
                        level.keyswitch_layout.p_mod_ids.end());
        contexts.insert(contexts.end(), level.b_mod_ids.begin(), level.b_mod_ids.end());
        contexts.push_back(level.m_sk_mod_id);
    }
    std::sort(contexts.begin(), contexts.end());
    contexts.erase(std::unique(contexts.begin(), contexts.end()), contexts.end());
    for (int modulus_id : contexts) {
        const std::string prefix = "constants/twiddle/canonical/mod" + std::to_string(modulus_id);
        require_twiddle(prefix + "/ntt/pre_twist", degree);
        for (std::size_t stage = 0; stage < stages; ++stage) {
            require_twiddle(prefix + "/ntt/stage" + std::to_string(stage), degree / 2);
            require_twiddle(prefix + "/intt/stage" + std::to_string(stage), degree / 2);
        }
        require_twiddle(prefix + "/intt/post_untwist_scale", degree);
    }
}

void BfvOperationPlan::validate_multiply_resources(
    const BfvLevelDescriptor& level, const PreparedEvaluationKey& relinearization_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const PreparedBfvMultiplyConstants& multiply_constants) const
{
    if (!hpu::is_seal_single_p_rns_decomposition_layout(
            static_cast<int>(image_builder_.registry().poly_modulus_degree),
            level.keyswitch_layout) ||
        level.keyswitch_layout.q_mod_ids.size() < 2 ||
        level.b_mod_ids.size() < level.keyswitch_layout.q_mod_ids.size() || level.m_sk_mod_id < 0 ||
        level.plaintext_mod_id < 0) {
        throw std::invalid_argument("BFV Multiply level has an unsupported HPU layout");
    }
    const auto matches_level = [&](const ::seal::parms_id_type& parms_id, std::size_t chain_index) {
        return parms_id == level.parms_id && chain_index == level.chain_index;
    };
    if (!matches_level(relinearization_key.data_parms_id, relinearization_key.chain_index) ||
        !matches_level(keyswitch_constants.data_parms_id, keyswitch_constants.chain_index) ||
        !matches_level(multiply_constants.data_parms_id, multiply_constants.chain_index)) {
        throw std::invalid_argument("BFV Multiply resources do not match the ciphertext level");
    }
    if (relinearization_key.rns_layout.q_mod_ids != level.keyswitch_layout.q_mod_ids ||
        relinearization_key.rns_layout.p_mod_ids != level.keyswitch_layout.p_mod_ids ||
        relinearization_key.rns_layout.key_digits != level.keyswitch_layout.key_digits ||
        relinearization_key.digits.size() != level.keyswitch_layout.key_digits.size()) {
        throw std::invalid_argument("BFV Multiply relinearization key has the wrong RNS layout");
    }
    require_resource_id(relinearization_key.id, "BFV Multiply relinearization key");
    const auto expected_key_modulus_ids = full_keyswitch_modulus_ids(level);
    const std::size_t degree = image_builder_.registry().poly_modulus_degree;
    for (std::size_t digit = 0; digit < relinearization_key.digits.size(); ++digit) {
        if (relinearization_key.digits[digit].size() != 2) {
            throw std::invalid_argument(
                "BFV Multiply relinearization-key digit needs two components");
        }
        for (std::size_t component = 0; component < 2; ++component) {
            const auto& polynomial = relinearization_key.digits[digit][component];
            if (polynomial.id != relinearization_key.id + "/d" + std::to_string(digit) + "/c" +
                                     std::to_string(component) ||
                polynomial.degree != degree || polynomial.modulus_ids != expected_key_modulus_ids ||
                polynomial.limbs.size() != expected_key_modulus_ids.size()) {
                throw std::invalid_argument(
                    "BFV Multiply relinearization key has an invalid allocation shape");
            }
            for (std::size_t basis = 0; basis < polynomial.limbs.size(); ++basis) {
                const std::string allocation_id =
                    polynomial.id + "/mod" + std::to_string(polynomial.modulus_ids[basis]);
                try {
                    const auto& allocation = image_builder_.image().allocation(allocation_id);
                    if (!same_span(allocation.span, polynomial.limbs[basis]) ||
                        allocation.word_count != degree ||
                        allocation.kind != hpu::runtime::AllocationKind::evaluation_key ||
                        !allocation.read_only) {
                        throw std::invalid_argument(
                            "BFV Multiply relinearization key does not belong to this image");
                    }
                } catch (const std::out_of_range&) {
                    throw std::invalid_argument(
                        "BFV Multiply relinearization key is absent from this image");
                }
            }
        }
    }

    validate_constant_resource(image_builder_.image(), keyswitch_constants.id,
                               keyswitch_constants.values, "BFV Multiply KeySwitch constants");
    if (keyswitch_constants.hardware_prefix != keyswitch_constants.id + "/hardware" ||
        keyswitch_constants.hardware_constant_polynomial_count == 0 ||
        keyswitch_constants.hardware_workspace_polynomial_count == 0) {
        throw std::invalid_argument(
            "BFV Multiply KeySwitch constants lack hardware-expanded resources");
    }

    validate_constant_resource(image_builder_.image(), multiply_constants.id,
                               multiply_constants.values, "BFV Multiply BEHZ constants");
    if (multiply_constants.hardware_prefix != multiply_constants.id + "/hardware" ||
        multiply_constants.q_mod_ids != level.keyswitch_layout.q_mod_ids ||
        multiply_constants.b_mod_ids != level.b_mod_ids ||
        multiply_constants.m_sk_mod_id != level.m_sk_mod_id ||
        multiply_constants.plaintext_mod_id != level.plaintext_mod_id ||
        multiply_constants.hardware_constant_polynomial_count == 0 ||
        multiply_constants.hardware_workspace_polynomial_count == 0) {
        throw std::invalid_argument("BFV Multiply constants have the wrong BEHZ layout");
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
