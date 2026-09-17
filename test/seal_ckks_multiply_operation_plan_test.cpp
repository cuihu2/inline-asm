#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/operation_runtime.hpp"
#include "hpu/seal/software_executor.hpp"
#include "poly/cmult.hpp"

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

void require_exact(
    const ::seal::Ciphertext& expected,
    const hpu::seal_adapter::PreparedRnsObject& actual,
    const hpu::seal_adapter::CkksSoftwareExecutor& executor,
    const ::seal::SEALContext& context)
{
    require(
        expected.parms_id() == actual.parms_id
            && expected.size() == actual.components.size(),
        "planned Multiply pipeline shape differs from SEAL");
    for (std::size_t component = 0; component < expected.size(); ++component) {
        const auto words = hpu::seal_adapter::hpu_to_seal_ntt(
            executor.export_component(actual, component),
            actual.parms_id, context);
        require(
            std::equal(
                words.begin(), words.end(), expected.data(component)),
            "planned Multiply pipeline words differ from SEAL");
    }
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

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);

        constexpr double scale = 4096.0;
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_left;
        ::seal::Plaintext encoded_right;
        encoder.encode(std::vector<double>{0.25, -1.0}, scale, encoded_left);
        encoder.encode(std::vector<double>{1.5, 0.75}, scale, encoded_right);

        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(encoded_left, encrypted_left);
        encryptor.encrypt(encoded_right, encrypted_right);

        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 512);
        image_builder.add_modulus_table();
        const auto canonical_twiddles =
            image_builder.add_canonical_twiddles();
        const auto left = image_builder.add_ciphertext(
            "input/left", encrypted_left);
        const auto right = image_builder.add_ciphertext(
            "input/right", encrypted_right);
        const auto relinearization_key =
            image_builder.add_relinearization_key(
                "key/relinearization/top", relin_keys, top);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants(
                "constants/keyswitch/top", top);
        const auto rescale_constants =
            image_builder.add_rescale_constants(
                "constants/rescale/top_to_next", top);

        hpu::seal_adapter::CkksOperationPlan plan(image_builder);
        const auto tensor = plan.append_multiply(
            "multiply", left, right, "intermediate/product_tensor");
        const auto relinearized = plan.append_relinearize(
            "relinearize", tensor, relinearization_key,
            keyswitch_constants, "intermediate/relinearized_product");
        const auto output = plan.append_rescale(
            "rescale", relinearized, rescale_constants,
            "output/product");

        const auto& steps = plan.steps();
        require(
            steps.size() == 3
                && steps[0].kind
                    == hpu::seal_adapter::CkksOperationKind::multiply
                && steps[1].kind
                    == hpu::seal_adapter::CkksOperationKind::relinearize
                && steps[2].kind
                    == hpu::seal_adapter::CkksOperationKind::rescale,
            "Multiply pipeline lost its explicit operation sequence");
        require(
            steps[0].inputs.size() == 2
                && steps[0].inputs[0].id == "input/left"
                && steps[0].inputs[1].id == "input/right"
                && steps[0].output.component_count == 3
                && steps[0].output.metadata.scale == scale * scale
                && steps[1].output.component_count == 2
                && steps[2].output.metadata.parms_id
                    == level_chain.next(top.parms_id).parms_id,
            "Multiply pipeline inferred incorrect shape or metadata");

        const auto lowered = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context);
        require(
            lowered.operations.size() == 3
                && lowered.operations[0].body_asm
                    == ::generate_hpu_cmult_body_asm(
                        static_cast<int>(top.q_moduli.size()), false, false),
            "Multiply lowering did not select the raw tensor kernel");

        const auto relocations =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                lowered, image_builder.image(), *bundle.context);
        require(
            relocations.complete()
                && relocations.bindings.size()
                    == relocations.expected_dma_count,
            "Multiply pipeline relocation is incomplete");
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
            has_binding("multiply", "input/left/c0/mod0")
                && has_binding("multiply", "input/right/c1/mod0")
                && has_binding(
                    "multiply", "intermediate/product_tensor/c2/mod0")
                && has_binding(
                    "relinearize", "intermediate/product_tensor/c2/mod0")
                && has_binding("rescale", "output/product/c1/mod1"),
            "Multiply pipeline relocation omitted an operand class");

        const auto runtime = hpu::seal_adapter::lower_ckks_runtime_program(
            lowered, relocations);
        require(
            runtime.dma.size() == relocations.expected_dma_count
                && runtime.spans().size() == relocations.expected_dma_count,
            "Multiply pipeline runtime lowering lost resolved DMA spans");

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, image_builder.image());
        executor.multiply(left, right, tensor);
        executor.relinearize(
            tensor, relinearization_key, keyswitch_constants,
            relinearized, canonical_twiddles);
        executor.rescale(
            relinearized, rescale_constants, output,
            canonical_twiddles);

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.multiply(encrypted_left, encrypted_right, expected);
        evaluator.relinearize_inplace(expected, relin_keys);
        evaluator.rescale_to_next_inplace(expected);
        require_exact(expected, output, executor, *bundle.context);

        std::cout
            << "SEAL CKKS Multiply->Relinearize->Rescale plan passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS Multiply operation plan test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
