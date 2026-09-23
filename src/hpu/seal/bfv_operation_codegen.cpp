#include "hpu/seal/bfv_operation_codegen.hpp"

#include "scheme/bfv/basic_arithmetic.hpp"
#include "scheme/bfv/ciphertext_multiply.hpp"
#include "scheme/bfv/galois.hpp"
#include "scheme/bfv/modswitch.hpp"
#include "scheme/bfv/rotate.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

constexpr int kModulusTableObject = 4;

const BfvLevelDescriptor& require_value_shape(const BfvLevelChain& level_chain,
                                              const BfvPlannedValue& value, std::size_t components,
                                              hpu::runtime::PolynomialDomain domain,
                                              const char* role)
{
    const auto& level = level_chain.require(value.metadata.parms_id);
    if (value.id.empty() || value.metadata.chain_index != level.chain_index ||
        value.component_count != components || value.domain != domain || value.key_domain != 1) {
        throw std::invalid_argument(std::string(role) +
                                    " has an incompatible shape or representation");
    }
    return level;
}

const BfvLevelDescriptor& require_coefficient_value_shape(const BfvLevelChain& level_chain,
                                                          const BfvPlannedValue& value,
                                                          std::size_t components, const char* role)
{
    return require_value_shape(level_chain, value, components,
                               hpu::runtime::PolynomialDomain::coefficient, role);
}

void require_same_level(const BfvPlannedValue& left, const BfvPlannedValue& right, const char* role)
{
    if (left.metadata.parms_id != right.metadata.parms_id ||
        left.metadata.chain_index != right.metadata.chain_index) {
        throw std::invalid_argument(std::string(role) + " operands use different BFV levels");
    }
}

std::string lower_step(const BfvOperationStep& step, const BfvLevelChain& level_chain, int degree)
{
    if (step.id.empty() || !step.resources.requires_modulus_table) {
        throw std::invalid_argument("lowered BFV step lacks its id or modulus-table requirement");
    }
    switch (step.kind) {
    case BfvOperationKind::add:
    case BfvOperationKind::subtract: {
        if (step.inputs.size() != 2 || step.resources.requires_canonical_twiddles) {
            throw std::invalid_argument("invalid planned BFV Add/Subtract inputs");
        }
        const auto& level = require_coefficient_value_shape(level_chain, step.inputs[0], 2,
                                                            "planned BFV Add/Subtract left input");
        require_coefficient_value_shape(level_chain, step.inputs[1], 2,
                                        "planned BFV Add/Subtract right input");
        require_coefficient_value_shape(level_chain, step.output, 2,
                                        "planned BFV Add/Subtract output");
        require_same_level(step.inputs[0], step.inputs[1], "planned BFV Add/Subtract");
        require_same_level(step.inputs[0], step.output, "planned BFV Add/Subtract output");
        const int num_q = static_cast<int>(level.q_moduli.size());
        return step.kind == BfvOperationKind::add
                   ? hpu::scheme::bfv::generate_add_body_asm(num_q, false, false)
                   : hpu::scheme::bfv::generate_subtract_body_asm(num_q, false, false);
    }
    case BfvOperationKind::multiply: {
        if (step.inputs.size() != 2 || !step.resources.requires_canonical_twiddles ||
            step.resources.evaluation_key_id.empty() ||
            step.resources.keyswitch_constants_id.empty() ||
            step.resources.multiply_constants_id.empty()) {
            throw std::invalid_argument("invalid planned BFV Multiply resources");
        }
        const auto& level = require_coefficient_value_shape(level_chain, step.inputs[0], 2,
                                                            "planned BFV Multiply left input");
        require_coefficient_value_shape(level_chain, step.inputs[1], 2,
                                        "planned BFV Multiply right input");
        require_coefficient_value_shape(level_chain, step.output, 2, "planned BFV Multiply output");
        require_same_level(step.inputs[0], step.inputs[1], "planned BFV Multiply");
        require_same_level(step.inputs[0], step.output, "planned BFV Multiply output");
        hpu::scheme::bfv::BfvCiphertextMultiplyLayout layout;
        layout.keyswitch_layout = level.keyswitch_layout;
        layout.b_mod_ids = level.b_mod_ids;
        layout.m_sk_mod_id = level.m_sk_mod_id;
        layout.plaintext_mod_id = level.plaintext_mod_id;
        if (!hpu::scheme::bfv::is_valid_ciphertext_multiply_layout(degree, layout,
                                                                   level.plaintext_modulus)) {
            throw std::invalid_argument("planned BFV Multiply level has an unsupported layout");
        }
        return hpu::scheme::bfv::generate_ciphertext_multiply_body_asm(
            degree, layout, level.plaintext_modulus, false, false);
    }
    case BfvOperationKind::add_plain:
    case BfvOperationKind::subtract_plain: {
        if (step.inputs.size() != 2 || step.resources.requires_canonical_twiddles) {
            throw std::invalid_argument("invalid planned BFV AddPlain/SubtractPlain inputs");
        }
        const auto& level = require_coefficient_value_shape(
            level_chain, step.inputs[0], 2, "planned BFV AddPlain/SubtractPlain ciphertext");
        require_coefficient_value_shape(level_chain, step.inputs[1], 1,
                                        "planned BFV AddPlain/SubtractPlain plaintext");
        require_coefficient_value_shape(level_chain, step.output, 2,
                                        "planned BFV AddPlain/SubtractPlain output");
        require_same_level(step.inputs[0], step.inputs[1], "planned BFV AddPlain/SubtractPlain");
        require_same_level(step.inputs[0], step.output,
                           "planned BFV AddPlain/SubtractPlain output");
        const int num_q = static_cast<int>(level.q_moduli.size());
        return step.kind == BfvOperationKind::add_plain
                   ? hpu::scheme::bfv::generate_add_plain_body_asm(num_q, false, false)
                   : hpu::scheme::bfv::generate_subtract_plain_body_asm(num_q, false, false);
    }
    case BfvOperationKind::multiply_plain: {
        if (step.inputs.size() != 2 || !step.resources.requires_canonical_twiddles) {
            throw std::invalid_argument("invalid planned BFV MultiplyPlain resources");
        }
        const auto& level = require_coefficient_value_shape(level_chain, step.inputs[0], 2,
                                                            "planned BFV MultiplyPlain ciphertext");
        require_value_shape(level_chain, step.inputs[1], 1,
                            hpu::runtime::PolynomialDomain::canonical_ntt_physical,
                            "planned BFV MultiplyPlain plaintext");
        require_coefficient_value_shape(level_chain, step.output, 2,
                                        "planned BFV MultiplyPlain output");
        require_same_level(step.inputs[0], step.inputs[1], "planned BFV MultiplyPlain");
        require_same_level(step.inputs[0], step.output, "planned BFV MultiplyPlain output");
        return hpu::scheme::bfv::generate_multiply_plain_body_asm(
            degree, static_cast<int>(level.q_moduli.size()), false, false);
    }
    case BfvOperationKind::negate: {
        if (step.inputs.size() != 1 || step.resources.requires_canonical_twiddles) {
            throw std::invalid_argument("invalid planned BFV Negate inputs");
        }
        const auto& level = require_coefficient_value_shape(level_chain, step.inputs.front(), 2,
                                                            "planned BFV Negate input");
        require_coefficient_value_shape(level_chain, step.output, 2, "planned BFV Negate output");
        require_same_level(step.inputs.front(), step.output, "planned BFV Negate output");
        return hpu::scheme::bfv::generate_negate_body_asm(static_cast<int>(level.q_moduli.size()),
                                                          false, false);
    }
    case BfvOperationKind::mod_switch: {
        if (step.inputs.size() != 1 || step.resources.requires_canonical_twiddles ||
            step.resources.mod_switch_constants_id.empty()) {
            throw std::invalid_argument("invalid planned BFV ModSwitch resources");
        }
        const auto& source = require_coefficient_value_shape(level_chain, step.inputs.front(), 2,
                                                             "planned BFV ModSwitch input");
        const auto& destination = require_coefficient_value_shape(level_chain, step.output, 2,
                                                                  "planned BFV ModSwitch output");
        if (!level_chain.has_next(source.parms_id) ||
            level_chain.next(source.parms_id).parms_id != destination.parms_id ||
            destination.q_moduli.size() + 1 != source.q_moduli.size()) {
            throw std::invalid_argument("planned BFV ModSwitch output is not the adjacent level");
        }
        return hpu::scheme::bfv::generate_modswitch_body_asm(
            static_cast<int>(source.q_moduli.size()), 2, false, false);
    }
    case BfvOperationKind::rotate_rows:
    case BfvOperationKind::rotate_columns: {
        if (step.inputs.size() != 1 || step.workspaces.size() != 1 ||
            !step.resources.requires_canonical_twiddles ||
            step.resources.galois_element == 0 || step.resources.evaluation_key_id.empty() ||
            step.resources.keyswitch_constants_id.empty()) {
            throw std::invalid_argument("invalid planned BFV rotation resources");
        }
        const auto& level = require_coefficient_value_shape(
            level_chain, step.inputs.front(), 2, "planned BFV rotation input");
        require_coefficient_value_shape(level_chain, step.output, 2,
                                        "planned BFV rotation output");
        require_same_level(step.inputs.front(), step.output, "planned BFV rotation output");
        const auto& workspace = step.workspaces.front();
        if (workspace.id.empty() || workspace.metadata.parms_id != level.parms_id ||
            workspace.metadata.chain_index != level.chain_index || workspace.component_count != 2 ||
            workspace.domain != hpu::runtime::PolynomialDomain::coefficient ||
            workspace.key_domain != step.resources.galois_element ||
            step.resources.fused_twiddle_ids.size() != level.keyswitch_layout.q_mod_ids.size()) {
            throw std::invalid_argument("planned BFV rotation workspace is incompatible");
        }
        if (step.kind == BfvOperationKind::rotate_columns &&
            step.resources.galois_element !=
                hpu::scheme::bfv::column_rotation_galois_element(degree)) {
            throw std::invalid_argument("planned BFV RotateColumns has the wrong Galois element");
        }
        return hpu::scheme::bfv::generate_rotate_body_asm(
            degree, level.keyswitch_layout, step.resources.galois_element, false, false);
    }
    }
    throw std::invalid_argument("unknown planned BFV operation kind");
}

} // namespace

BfvLoweredProgram lower_bfv_operation_plan(const BfvOperationPlan& plan,
                                           const ::seal::SEALContext& context, bool append_psync,
                                           bool manage_modulus_table)
{
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::bfv ||
        key_data->parms().poly_modulus_degree() >
            static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(key_data->parms().poly_modulus_degree()))) {
        throw std::invalid_argument("BFV operation lowering requires a valid HPU BFV context");
    }
    if (plan.steps().empty()) {
        throw std::invalid_argument("cannot lower an empty BFV operation plan");
    }

    const BfvLevelChain level_chain(context);
    BfvLoweredProgram result;
    result.operations.reserve(plan.steps().size());
    if (manage_modulus_table) {
        result.body_asm +=
            hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    }
    for (const auto& step : plan.steps()) {
        BfvLoweredOperation lowered;
        lowered.operation = step;
        lowered.body_asm = lower_step(step, level_chain,
                                      static_cast<int>(key_data->parms().poly_modulus_degree()));
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
