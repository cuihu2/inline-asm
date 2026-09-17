#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/operation_runtime.hpp"
#include "hpu/seal/software_executor.hpp"
#include "scheme/ckks/galois.hpp"
#include "scheme/ckks/rotate.hpp"
#include "util/hpu_asm.hpp"

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

template <typename Function>
void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

void require_exact(
    const ::seal::Ciphertext& expected,
    const hpu::seal_adapter::PreparedRnsObject& actual,
    const hpu::seal_adapter::CkksSoftwareExecutor& executor,
    const ::seal::SEALContext& context,
    const char* operation)
{
    if (expected.parms_id() != actual.parms_id
        || expected.size() != actual.components.size()) {
        throw std::runtime_error(
            std::string(operation) + " planned result shape differs from SEAL");
    }
    for (std::size_t component = 0; component < expected.size(); ++component) {
        const auto words = hpu::seal_adapter::hpu_to_seal_ntt(
            executor.export_component(actual, component),
            actual.parms_id, context);
        if (!std::equal(
                words.begin(), words.end(), expected.data(component))) {
            throw std::runtime_error(
                std::string(operation) + " planned result differs from SEAL");
        }
    }
}

std::size_t count_token(const std::string& text, const std::string& token)
{
    std::size_t count = 0;
    std::size_t position = 0;
    while ((position = text.find(token, position)) != std::string::npos) {
        ++count;
        position += token.size();
    }
    return count;
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const hpu::seal_adapter::CkksLevelChain level_chain(*bundle.context);
        const auto& top = level_chain.top();
        constexpr int rotation_steps = 2;
        const auto rotation_element =
            hpu::scheme::ckks::rotation_galois_element(
                spec.poly_modulus_degree, rotation_steps);
        const auto conjugation_element =
            hpu::scheme::ckks::conjugation_galois_element(
                spec.poly_modulus_degree);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::GaloisKeys galois_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{
                rotation_element, conjugation_element},
            galois_keys);

        constexpr double scale = 4096.0;
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_input;
        encoder.encode(
            std::vector<double>{0.25, -1.0, 1.5, 0.75},
            scale, encoded_input);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_input;
        encryptor.encrypt(encoded_input, encrypted_input);

        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 1024);
        image_builder.add_modulus_table();
        const auto canonical_twiddles =
            image_builder.add_canonical_twiddles();
        const auto input = image_builder.add_ciphertext(
            "input/x", encrypted_input);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants(
                "constants/keyswitch/top", top);
        const auto rotation_key = image_builder.add_rotation_key(
            "key/rotate_left_2/top", galois_keys,
            rotation_steps, top);
        const auto conjugation_key = image_builder.add_conjugation_key(
            "key/conjugate/top", galois_keys, top);
        const auto rotation_twiddles =
            image_builder.add_rotation_twiddles(
                "rotate_left_2/top", rotation_steps, top);
        const auto conjugation_twiddles =
            image_builder.add_conjugation_twiddles(
                "conjugate/top", top);
        const auto rotation_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_left_2", input.metadata(), 2,
            hpu::runtime::PolynomialDomain::coefficient,
            rotation_element);
        const auto conjugation_workspace = image_builder.reserve_ciphertext(
            "scratch/conjugate", input.metadata(), 2,
            hpu::runtime::PolynomialDomain::coefficient,
            conjugation_element);

        hpu::seal_adapter::CkksOperationPlan plan(image_builder);
        auto wrong_workspace = rotation_workspace;
        wrong_workspace.key_domain = conjugation_element;
        require_invalid_argument(
            [&] {
                (void)plan.append_rotate_slots(
                    "invalid_workspace", input, rotation_steps,
                    rotation_key, keyswitch_constants, rotation_twiddles,
                    wrong_workspace, "invalid/rotate");
            },
            "Rotate planner accepted a workspace in the wrong key domain");
        require_invalid_argument(
            [&] {
                (void)plan.append_rotate_slots(
                    "invalid_twiddles", input, rotation_steps,
                    rotation_key, keyswitch_constants,
                    conjugation_twiddles, rotation_workspace,
                    "invalid/twiddles");
            },
            "Rotate planner accepted twiddles for another Galois element");

        const auto rotated = plan.append_rotate_slots(
            "rotate_left_2", input, rotation_steps,
            rotation_key, keyswitch_constants, rotation_twiddles,
            rotation_workspace, "output/rotate_left_2");
        const auto conjugated = plan.append_conjugate(
            "conjugate", input, conjugation_key,
            keyswitch_constants, conjugation_twiddles,
            conjugation_workspace, "output/conjugate");

        const auto& steps = plan.steps();
        require(
            steps.size() == 2
                && steps[0].kind
                    == hpu::seal_adapter::CkksOperationKind::rotate
                && steps[1].kind
                    == hpu::seal_adapter::CkksOperationKind::conjugate
                && steps[0].resources.galois_element == rotation_element
                && steps[1].resources.galois_element
                    == conjugation_element
                && steps[0].workspaces[0].id == "scratch/rotate_left_2"
                && steps[1].workspaces[0].id == "scratch/conjugate"
                && steps[0].resources.fused_twiddle_ids.size()
                    == top.rns_layout.q_mod_ids.size(),
            "Galois planner lost operation-specific resources");

        const auto lowered = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context);
        require(
            lowered.operations.size() == 2
                && lowered.operations[0].body_asm
                    == hpu::scheme::ckks::generate_rotate_body_asm(
                        static_cast<int>(spec.poly_modulus_degree),
                        top.rns_layout, rotation_element, false, false)
                && lowered.operations[1].body_asm
                    == hpu::scheme::ckks::generate_conjugate_body_asm(
                        static_cast<int>(spec.poly_modulus_degree),
                        top.rns_layout, false, false)
                && count_token(
                    lowered.body_asm,
                    hpu::dload(
                        4, hpu::DataType::mod_ctx,
                        hpu::DloadFlag::small_bank)) == 1
                && count_token(lowered.body_asm, hpu::pfree(4)) == 1,
            "Galois lowering selected the wrong kernel or duplicated the modulus table");

        const auto relocations =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                lowered, image_builder.image(), *bundle.context);
        require(
            relocations.complete()
                && relocations.bindings.size()
                    == relocations.expected_dma_count,
            "Galois relocation is incomplete");
        const auto has_binding = [&relocations](
            const std::string& operation,
            const std::string& allocation) {
            return std::any_of(
                relocations.bindings.begin(), relocations.bindings.end(),
                [&](const hpu::seal_adapter::CkksDmaBinding& binding) {
                    return binding.operation_id == operation
                        && binding.allocation_id == allocation;
                });
        };
        require(
            has_binding(
                "rotate_left_2",
                "constants/twiddle/rotate_left_2/top/mod0/intt/stage0")
                && has_binding(
                    "rotate_left_2", "scratch/rotate_left_2/c1/mod0")
                && has_binding(
                    "rotate_left_2", "key/rotate_left_2/top/d0/c0/mod0")
                && has_binding(
                    "rotate_left_2", "output/rotate_left_2/c1/mod0")
                && has_binding(
                    "conjugate",
                    "constants/twiddle/conjugate/top/mod0/intt/stage0")
                && has_binding(
                    "conjugate", "key/conjugate/top/d0/c0/mod0")
                && has_binding(
                    "conjugate", "output/conjugate/c1/mod0"),
            "Galois relocation omitted an operand class");

        const auto runtime = hpu::seal_adapter::lower_ckks_runtime_program(
            lowered, relocations);
        require(
            runtime.dma.size() == relocations.expected_dma_count
                && runtime.spans().size() == relocations.expected_dma_count,
            "Galois runtime lowering lost resolved DMA spans");

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, image_builder.image());
        executor.rotate_slots(
            input, rotation_steps, rotation_key, keyswitch_constants,
            rotation_twiddles, canonical_twiddles,
            rotation_workspace, rotated);
        executor.conjugate(
            input, conjugation_key, keyswitch_constants,
            conjugation_twiddles, canonical_twiddles,
            conjugation_workspace, conjugated);

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.rotate_vector(
            encrypted_input, rotation_steps, galois_keys, expected);
        require_exact(
            expected, rotated, executor, *bundle.context, "Rotate");
        evaluator.complex_conjugate(
            encrypted_input, galois_keys, expected);
        require_exact(
            expected, conjugated, executor, *bundle.context, "Conjugate");

        std::cout
            << "SEAL CKKS Rotate/Conjugate operation plan passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS Galois operation plan test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
