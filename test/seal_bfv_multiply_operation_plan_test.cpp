#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "scheme/bfv/ciphertext_multiply.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Function> void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        spec.plain_modulus_bits = 17;
        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);

        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> left_slots(encoder.slot_count());
        std::vector<std::uint64_t> right_slots(encoder.slot_count());
        for (std::size_t index = 0; index < encoder.slot_count(); ++index) {
            left_slots[index] = (index + 3) % bundle.plain_modulus;
            right_slots[index] = (2 * index + 1) % bundle.plain_modulus;
        }
        ::seal::Plaintext left_plain;
        ::seal::Plaintext right_plain;
        encoder.encode(left_slots, left_plain);
        encoder.encode(right_slots, right_plain);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(left_plain, encrypted_left);
        encryptor.encrypt(right_plain, encrypted_right);

        hpu::seal_adapter::BfvApplicationImageBuilder image_builder(*bundle.context, 8192);
        image_builder.add_modulus_table();
        image_builder.add_canonical_twiddles();
        const auto& level = image_builder.level_chain().top();
        const auto left = image_builder.add_ciphertext("input/left", encrypted_left);
        const auto right = image_builder.add_ciphertext("input/right", encrypted_right);
        const auto relinearization_key =
            image_builder.add_relinearization_key("key/relinearization/top", relin_keys, level);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants("constants/keyswitch/top", level);
        const auto multiply_constants =
            image_builder.add_multiply_constants("constants/multiply/top", level);

        hpu::seal_adapter::BfvOperationPlan plan(image_builder);
        const auto output =
            plan.append_multiply("multiply", left, right, relinearization_key, keyswitch_constants,
                                 multiply_constants, "output/product");
        require(output.parms_id == level.parms_id && output.chain_index == level.chain_index &&
                    output.components.size() == 2 &&
                    output.domain == hpu::runtime::PolynomialDomain::coefficient &&
                    output.key_domain == 1,
                "BFV Multiply output metadata is incorrect");
        require(plan.steps().size() == 1 &&
                    plan.steps().front().kind == hpu::seal_adapter::BfvOperationKind::multiply &&
                    plan.steps().front().resources.requires_canonical_twiddles &&
                    plan.steps().front().resources.evaluation_key_id == relinearization_key.id &&
                    plan.steps().front().resources.keyswitch_constants_id ==
                        keyswitch_constants.id &&
                    plan.steps().front().resources.multiply_constants_id == multiply_constants.id,
                "BFV Multiply plan lost its prepared resources");

        hpu::scheme::bfv::BfvCiphertextMultiplyLayout layout;
        layout.keyswitch_layout = level.keyswitch_layout;
        layout.b_mod_ids = level.b_mod_ids;
        layout.m_sk_mod_id = level.m_sk_mod_id;
        layout.plaintext_mod_id = level.plaintext_mod_id;
        const auto lowered =
            hpu::seal_adapter::lower_bfv_operation_plan(plan, *bundle.context, true, true);
        require(lowered.operations.size() == 1 &&
                    lowered.operations.front().body_asm ==
                        hpu::scheme::bfv::generate_ciphertext_multiply_body_asm(
                            static_cast<int>(spec.poly_modulus_degree), layout,
                            level.plaintext_modulus, false, false),
                "BFV Multiply lowering did not select the explicit-layout fused kernel");

        const auto relocations = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, image_builder.image(), *bundle.context);
        require(relocations.complete() && !relocations.bindings.empty() &&
                    relocations.bindings.front().allocation_id == "constants/modulus_table",
                "BFV Multiply relocation is incomplete");
        const auto has_binding = [&](const std::string& allocation_id,
                                     hpu::seal_adapter::BfvDmaDirection direction) {
            return std::any_of(
                relocations.bindings.begin(), relocations.bindings.end(), [&](const auto& binding) {
                    return binding.operation_id == "multiply" &&
                           binding.allocation_id == allocation_id && binding.direction == direction;
                });
        };
        const int first_q = level.keyswitch_layout.q_mod_ids.front();
        const int first_b = level.b_mod_ids.front();
        require(has_binding("input/left/c0/mod" + std::to_string(first_q),
                            hpu::seal_adapter::BfvDmaDirection::load) &&
                    has_binding(multiply_constants.hardware_prefix + "/q_to_bsk/qhat_inv/mod" +
                                    std::to_string(first_q),
                                hpu::seal_adapter::BfvDmaDirection::load) &&
                    has_binding(multiply_constants.hardware_prefix + "/workspace/tensor/c2/mod" +
                                    std::to_string(first_b),
                                hpu::seal_adapter::BfvDmaDirection::store) &&
                    has_binding(relinearization_key.id + "/d0/c0/mod" + std::to_string(first_q),
                                hpu::seal_adapter::BfvDmaDirection::load) &&
                    has_binding("output/product/c0/mod" + std::to_string(first_q),
                                hpu::seal_adapter::BfvDmaDirection::store) &&
                    has_binding("output/product/c1/mod" + std::to_string(first_q),
                                hpu::seal_adapter::BfvDmaDirection::store),
                "BFV Multiply relocation omitted a required input, workspace, key, or output");

        const auto runtime = hpu::seal_adapter::lower_bfv_runtime_program(lowered, relocations);
        const auto runtime_spans = runtime.spans();
        require(runtime.instructions.size() > runtime.dma.size() &&
                    runtime.dma.size() == relocations.expected_dma_count &&
                    runtime_spans.size() == runtime.dma.size() &&
                    runtime.dma.front().instruction_index == 0 &&
                    runtime.dma.front().binding.allocation_id == "constants/modulus_table" &&
                    runtime.dma.back().binding.allocation_id.find("output/product/") == 0 &&
                    runtime_spans.back().line_offset ==
                        relocations.bindings.back().span.line_offset,
                "BFV runtime lowering lost encoded instructions or resolved spans");
        const auto artifacts = hpu::seal_adapter::render_bfv_runtime_artifacts(
            "bfv_fused_multiply", runtime, image_builder.image().capacity_lines());
        require(artifacts.header.find("int hpu_run_bfv_fused_multiply(void);") !=
                        std::string::npos &&
                    artifacts.source.find("static const hpu_dma_span_t "
                                          "hpu_program_bfv_fused_multiply_resolved_spans[]") !=
                        std::string::npos &&
                    artifacts.source.find("hpu_program_bfv_fused_multiply(") != std::string::npos &&
                    artifacts.resolved_dma_manifest.find(
                        "instruction_index,dma_index,operation_index,operation_id") == 0 &&
                    artifacts.resolved_dma_manifest.find("\"multiply\"") != std::string::npos &&
                    artifacts.resolved_dma_manifest.find("\"output/product/c1/mod") !=
                        std::string::npos,
                "BFV runtime artifacts lost their wrapper or relocation provenance");

        auto incomplete_relocations = relocations;
        incomplete_relocations.bindings.pop_back();
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::lower_bfv_runtime_program(lowered, incomplete_relocations);
            },
            "BFV runtime accepted an incomplete relocation schedule");
        auto corrupted_relocations = relocations;
        corrupted_relocations.bindings[1].object_slot = 7;
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::lower_bfv_runtime_program(lowered, corrupted_relocations);
            },
            "BFV runtime accepted a DMA binding that disagrees with the encoded instruction");
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::render_bfv_runtime_artifacts(
                    "bfv_fused_multiply", runtime, image_builder.image().used_lines() - 1);
            },
            "BFV runtime rendered an output span beyond the declared HPU_MEM capacity");

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.multiply(encrypted_left, encrypted_right, expected);
        evaluator.relinearize_inplace(expected, relin_keys);
        require(expected.parms_id() == output.parms_id &&
                    expected.size() == output.components.size(),
                "BFV Multiply planner metadata differs from modified-SEAL");

        auto missing_workspace = multiply_constants;
        missing_workspace.hardware_workspace_polynomial_count = 0;
        require_invalid_argument(
            [&] {
                (void)plan.append_multiply("missing_workspace", left, right, relinearization_key,
                                           keyswitch_constants, missing_workspace,
                                           "invalid/missing_workspace");
            },
            "BFV Multiply accepted constants without expanded workspaces");

        auto wrong_level_constants = multiply_constants;
        wrong_level_constants.data_parms_id =
            image_builder.level_chain().next(level.parms_id).parms_id;
        require_invalid_argument(
            [&] {
                (void)plan.append_multiply("wrong_level", left, right, relinearization_key,
                                           keyswitch_constants, wrong_level_constants,
                                           "invalid/wrong_level");
            },
            "BFV Multiply accepted wrong-level constants");

        hpu::seal_adapter::BfvApplicationImageBuilder no_twiddle_builder(*bundle.context, 8192);
        no_twiddle_builder.add_modulus_table();
        const auto no_twiddle_left =
            no_twiddle_builder.add_ciphertext("input/left", encrypted_left);
        const auto no_twiddle_right =
            no_twiddle_builder.add_ciphertext("input/right", encrypted_right);
        const auto& no_twiddle_level = no_twiddle_builder.level_chain().top();
        const auto no_twiddle_key = no_twiddle_builder.add_relinearization_key(
            "key/relinearization/top", relin_keys, no_twiddle_level);
        const auto no_twiddle_keyswitch =
            no_twiddle_builder.add_keyswitch_constants("constants/keyswitch/top", no_twiddle_level);
        const auto no_twiddle_multiply =
            no_twiddle_builder.add_multiply_constants("constants/multiply/top", no_twiddle_level);
        hpu::seal_adapter::BfvOperationPlan no_twiddle_plan(no_twiddle_builder);
        require_invalid_argument(
            [&] {
                (void)no_twiddle_plan.append_multiply("multiply", no_twiddle_left, no_twiddle_right,
                                                      no_twiddle_key, no_twiddle_keyswitch,
                                                      no_twiddle_multiply, "output/product");
            },
            "BFV Multiply accepted an image without canonical twiddles");

        std::cout << "SEAL BFV fused Multiply planner/relocation/runtime path passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL BFV Multiply operation plan test failed: " << error.what() << '\n';
        return 1;
    }
}
