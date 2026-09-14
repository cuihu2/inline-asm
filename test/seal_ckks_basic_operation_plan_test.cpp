#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/operation_runtime.hpp"
#include "hpu/seal/software_executor.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"

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
    const ::seal::SEALContext& context,
    const char* operation)
{
    if (expected.parms_id() != actual.parms_id
        || expected.size() != actual.components.size()) {
        throw std::runtime_error(
            std::string(operation) + " planned result shape differs from SEAL");
    }
    for (std::size_t component = 0; component < expected.size(); ++component) {
        const auto seal_words = hpu::seal_adapter::hpu_to_seal_ntt(
            executor.export_component(actual, component),
            actual.parms_id, context);
        if (!std::equal(
                seal_words.begin(), seal_words.end(),
                expected.data(component))) {
            throw std::runtime_error(
                std::string(operation) + " planned result differs from SEAL");
        }
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

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        key_generator.create_public_key(public_key);

        constexpr double scale = 4096.0;
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_left;
        ::seal::Plaintext encoded_right;
        ::seal::Plaintext encoded_plain;
        encoder.encode(std::vector<double>{0.25, -1.0}, scale, encoded_left);
        encoder.encode(std::vector<double>{1.5, 0.75}, scale, encoded_right);
        encoder.encode(std::vector<double>{2.0, -0.5}, scale, encoded_plain);

        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(encoded_left, encrypted_left);
        encryptor.encrypt(encoded_right, encrypted_right);

        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 256);
        image_builder.add_modulus_table();
        const auto left = image_builder.add_ciphertext(
            "input/left", encrypted_left);
        const auto right = image_builder.add_ciphertext(
            "input/right", encrypted_right);
        const auto plain = image_builder.add_plaintext(
            "input/plain", encoded_plain);

        hpu::seal_adapter::CkksOperationPlan plan(image_builder);
        const auto added = plan.append_add(
            "add", left, right, "output/add");
        const auto subtracted = plan.append_subtract(
            "subtract", left, right, "output/subtract");
        const auto multiplied_plain = plan.append_multiply_plain(
            "multiply_plain", left, plain, "output/multiply_plain");
        const auto subtracted_plain = plan.append_subtract_plain(
            "subtract_plain", left, plain, "output/subtract_plain");
        const auto negated = plan.append_negate(
            "negate", left, "output/negate");

        const auto& steps = plan.steps();
        require(
            steps.size() == 5
                && steps[0].kind
                    == hpu::seal_adapter::CkksOperationKind::add
                && steps[1].kind
                    == hpu::seal_adapter::CkksOperationKind::subtract
                && steps[2].kind
                    == hpu::seal_adapter::CkksOperationKind::multiply_plain
                && steps[3].kind
                    == hpu::seal_adapter::CkksOperationKind::subtract_plain
                && steps[4].kind
                    == hpu::seal_adapter::CkksOperationKind::negate,
            "basic operation plan lost its explicit step sequence");
        require(
            steps[0].output.metadata.scale == scale
                && steps[1].output.metadata.scale == scale
                && steps[2].output.metadata.scale == scale * scale
                && steps[3].output.metadata.scale == scale
                && steps[4].output.metadata.scale == scale,
            "basic operation plan inferred incorrect scales");

        const auto lowered = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context);
        const int num_q = static_cast<int>(
            hpu::seal_adapter::CkksLevelChain(*bundle.context)
                .top().q_moduli.size());
        require(
            lowered.operations.size() == 5
                && lowered.operations[0].body_asm
                    == hpu::scheme::ckks::generate_add_body_asm(
                        num_q, false, false)
                && lowered.operations[1].body_asm
                    == hpu::scheme::ckks::generate_subtract_body_asm(
                        num_q, false, false)
                && lowered.operations[2].body_asm
                    == hpu::scheme::ckks::generate_multiply_plain_body_asm(
                        num_q, false, false)
                && lowered.operations[3].body_asm
                    == hpu::scheme::ckks::generate_subtract_plain_body_asm(
                        num_q, false, false)
                && lowered.operations[4].body_asm
                    == hpu::scheme::ckks::generate_negate_body_asm(
                        num_q, false, false),
            "basic operation lowering selected an incorrect kernel");

        const auto relocations =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                lowered, image_builder.image(), *bundle.context);
        require(
            relocations.complete() && relocations.expected_dma_count > 1
                && relocations.bindings.front().allocation_id
                    == "constants/modulus_table",
            "basic operation relocation is incomplete");
        for (const auto& step : steps) {
            require(
                std::any_of(
                    relocations.bindings.begin(), relocations.bindings.end(),
                    [&](const hpu::seal_adapter::CkksDmaBinding& binding) {
                        return binding.operation_id == step.id
                            && binding.allocation_id.find(step.output.id)
                                == 0;
                    }),
                "basic operation output has no resolved DMA binding");
        }

        const auto runtime_program =
            hpu::seal_adapter::lower_ckks_runtime_program(
                lowered, relocations);
        require(
            runtime_program.dma.size() == relocations.expected_dma_count
                && runtime_program.spans().size()
                    == relocations.expected_dma_count,
            "basic operation runtime lowering lost DMA spans");

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, image_builder.image());
        executor.add(left, right, added);
        executor.subtract(left, right, subtracted);
        executor.multiply_plain(left, plain, multiplied_plain);
        executor.subtract_plain(left, plain, subtracted_plain);
        executor.negate(left, negated);

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.add(encrypted_left, encrypted_right, expected);
        require_exact(
            expected, added, executor, *bundle.context, "Add");
        evaluator.sub(encrypted_left, encrypted_right, expected);
        require_exact(
            expected, subtracted, executor, *bundle.context, "Subtract");
        evaluator.multiply_plain(encrypted_left, encoded_plain, expected);
        require_exact(
            expected, multiplied_plain, executor,
            *bundle.context, "MultiplyPlain");
        evaluator.sub_plain(encrypted_left, encoded_plain, expected);
        require_exact(
            expected, subtracted_plain, executor,
            *bundle.context, "SubtractPlain");
        evaluator.negate(encrypted_left, expected);
        require_exact(
            expected, negated, executor, *bundle.context, "Negate");

        std::cout
            << "SEAL CKKS basic operation plan/runtime path passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS basic operation plan test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
