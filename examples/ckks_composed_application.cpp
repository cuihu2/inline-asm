#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/operation_runtime.hpp"
#include "hpu/seal/software_executor.hpp"
#include "scheme/ckks/galois.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
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

::seal::Ciphertext import_hpu_ciphertext(
    const hpu::seal_adapter::PreparedRnsObject& object,
    const hpu::seal_adapter::CkksSoftwareExecutor& executor,
    const ::seal::SEALContext& context)
{
    ::seal::Ciphertext result;
    result.resize(context, object.parms_id, object.components.size());
    result.is_ntt_form() = true;
    result.scale() = object.scale;
    for (std::size_t component = 0;
         component < object.components.size(); ++component) {
        const auto words = hpu::seal_adapter::hpu_to_seal_ntt(
            executor.export_component(object, component),
            object.parms_id, context);
        std::copy(
            words.begin(), words.end(), result.data(component));
    }
    return result;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const bool print_asm = argc == 2
            && std::string(argv[1]) == "--print-asm";
        if (argc > 2 || (argc == 2 && !print_asm)) {
            throw std::invalid_argument(
                "usage: hpu_ckks_composed_application_example [--print-asm]");
        }

        // Teaching-sized parameters keep the example fast. The planner and
        // runtime APIs are identical for the deployment degree N=65536.
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const hpu::seal_adapter::CkksLevelChain level_chain(*bundle.context);
        const auto& top = level_chain.top();
        const auto& next = level_chain.next(top.parms_id);

        constexpr int rotation_steps = 1;
        const auto rotation_element =
            hpu::scheme::ckks::rotation_galois_element(
                spec.poly_modulus_degree, rotation_steps);
        const auto conjugation_element =
            hpu::scheme::ckks::conjugation_galois_element(
                spec.poly_modulus_degree);

        // The application needs one public key, one relinearization key, and
        // the two Galois keys referenced by its operation graph.
        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        ::seal::GaloisKeys galois_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{
                rotation_element, conjugation_element},
            galois_keys);

        const std::vector<double> input {0.25, -1.5, 2.0, 0.75};
        constexpr double input_scale = 1048576.0; // 2^20
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_input;
        encoder.encode(input, input_scale, encoded_input);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_input;
        encryptor.encrypt(encoded_input, encrypted_input);

        // Independent SEAL oracle for:
        // y = x * (RotateLeft(x, 1) + Conjugate(x)) + 1.
        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext host_rotated;
        ::seal::Ciphertext host_conjugated;
        ::seal::Ciphertext host_mixed;
        ::seal::Ciphertext host_result;
        evaluator.rotate_vector(
            encrypted_input, rotation_steps, galois_keys, host_rotated);
        evaluator.complex_conjugate(
            encrypted_input, galois_keys, host_conjugated);
        evaluator.add(host_rotated, host_conjugated, host_mixed);
        evaluator.multiply(encrypted_input, host_mixed, host_result);
        evaluator.relinearize_inplace(host_result, relin_keys);
        evaluator.rescale_to_next_inplace(host_result);
        require(
            host_result.parms_id() == next.parms_id,
            "composed SEAL oracle reached the wrong level");
        ::seal::Plaintext encoded_bias;
        encoder.encode(
            std::vector<double>(input.size(), 1.0),
            host_result.parms_id(), host_result.scale(), encoded_bias);
        evaluator.add_plain_inplace(host_result, encoded_bias);

        // Build all immutable data and mutable workspaces in HPU_MEM before
        // constructing the operation plan.
        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 2048);
        image_builder.add_modulus_table();
        const auto canonical_twiddles =
            image_builder.add_canonical_twiddles();
        const auto prepared_input = image_builder.add_ciphertext(
            "input/x", encrypted_input);
        const auto prepared_bias = image_builder.add_plaintext(
            "constant/bias/next", encoded_bias);
        const auto relinearization_key =
            image_builder.add_relinearization_key(
                "key/relinearization/top", relin_keys, top);
        const auto rotation_key = image_builder.add_rotation_key(
            "key/rotate_left_1/top", galois_keys,
            rotation_steps, top);
        const auto conjugation_key = image_builder.add_conjugation_key(
            "key/conjugate/top", galois_keys, top);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants(
                "constants/keyswitch/top", top);
        const auto rescale_constants =
            image_builder.add_rescale_constants(
                "constants/rescale/top_to_next", top);
        const auto rotation_twiddles =
            image_builder.add_rotation_twiddles(
                "rotate_left_1/top", rotation_steps, top);
        const auto conjugation_twiddles =
            image_builder.add_conjugation_twiddles(
                "conjugate/top", top);
        const auto rotation_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_left_1", prepared_input.metadata(), 2,
            hpu::runtime::PolynomialDomain::coefficient,
            rotation_element);
        const auto conjugation_workspace = image_builder.reserve_ciphertext(
            "scratch/conjugate", prepared_input.metadata(), 2,
            hpu::runtime::PolynomialDomain::coefficient,
            conjugation_element);

        // This is the application-facing portion: build an explicit graph and
        // let the planner derive every output's component count, level, scale,
        // representation, and HPU_MEM allocation.
        hpu::seal_adapter::CkksOperationPlan plan(image_builder);
        const auto rotated = plan.append_rotate_slots(
            "rotate_left_1", prepared_input, rotation_steps,
            rotation_key, keyswitch_constants, rotation_twiddles,
            rotation_workspace, "intermediate/rotated/top");
        const auto conjugated = plan.append_conjugate(
            "conjugate", prepared_input, conjugation_key,
            keyswitch_constants, conjugation_twiddles,
            conjugation_workspace, "intermediate/conjugated/top");
        const auto mixed = plan.append_add(
            "mix_branches", rotated, conjugated,
            "intermediate/mixed/top");
        const auto tensor = plan.append_multiply(
            "multiply", prepared_input, mixed,
            "intermediate/product_tensor/top");
        const auto relinearized = plan.append_relinearize(
            "relinearize", tensor, relinearization_key,
            keyswitch_constants, "intermediate/product/top");
        const auto rescaled = plan.append_rescale(
            "rescale", relinearized, rescale_constants,
            "intermediate/product/next");
        const auto output = plan.append_add_plain(
            "add_bias", rescaled, prepared_bias, "output/y/next");

        require(
            plan.steps().size() == 7
                && output.parms_id == next.parms_id,
            "composed planner produced the wrong graph or output level");

        // Host functional execution consumes the same image and planned
        // objects. It does not call seal::Evaluator.
        hpu::seal_adapter::CkksSoftwareExecutor software_executor(
            *bundle.context, image_builder.image());
        software_executor.rotate_slots(
            prepared_input, rotation_steps, rotation_key,
            keyswitch_constants, rotation_twiddles, canonical_twiddles,
            rotation_workspace, rotated);
        software_executor.conjugate(
            prepared_input, conjugation_key, keyswitch_constants,
            conjugation_twiddles, canonical_twiddles,
            conjugation_workspace, conjugated);
        software_executor.add(rotated, conjugated, mixed);
        software_executor.multiply(prepared_input, mixed, tensor);
        software_executor.relinearize(
            tensor, relinearization_key, keyswitch_constants,
            relinearized, canonical_twiddles);
        software_executor.rescale(
            relinearized, rescale_constants, rescaled,
            canonical_twiddles);
        software_executor.add_plain(rescaled, prepared_bias, output);

        const auto imported = import_hpu_ciphertext(
            output, software_executor, *bundle.context);
        for (std::size_t component = 0;
             component < host_result.size(); ++component) {
            require(
                std::equal(
                    imported.data(component),
                    imported.data(component) + imported.poly_modulus_degree()
                        * imported.coeff_modulus_size(),
                    host_result.data(component)),
                "composed HPU result differs from SEAL NTT words");
        }

        ::seal::Decryptor decryptor(
            *bundle.context, key_generator.secret_key());
        ::seal::Plaintext decrypted;
        decryptor.decrypt(imported, decrypted);
        std::vector<double> decoded;
        encoder.decode(decrypted, decoded);
        const std::vector<double> expected {
            0.6875, 0.25, 6.5, 1.5625};
        double maximum_error = 0.0;
        for (std::size_t index = 0; index < expected.size(); ++index) {
            maximum_error = std::max(
                maximum_error,
                std::abs(decoded[index] - expected[index]));
        }
        require(
            maximum_error < 1e-2,
            "composed CKKS application exceeded its decoded tolerance");

        // The same graph now becomes a relocatable encoded program and
        // generated C artifacts. No application-specific DMA code is needed.
        const auto lowered = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context);
        const auto relocation =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                lowered, image_builder.image(), *bundle.context);
        require(
            relocation.complete(),
            "composed application relocation is incomplete");
        const auto runtime = hpu::seal_adapter::lower_ckks_runtime_program(
            lowered, relocation);
        const auto artifacts =
            hpu::seal_adapter::render_ckks_runtime_artifacts(
                "ckks_composed_application", runtime,
                image_builder.image().capacity_lines());

        std::cout << std::setprecision(8)
                  << "y=x*(RotateLeft(x,1)+Conjugate(x))+1\n"
                  << "Plan steps: " << plan.steps().size() << '\n'
                  << "Level: Q" << top.q_moduli.size() << " -> Q"
                  << next.q_moduli.size() << '\n'
                  << "Decoded: [" << decoded[0] << ", " << decoded[1]
                  << ", " << decoded[2] << ", " << decoded[3] << "]\n"
                  << "Maximum decoded error: " << maximum_error << '\n'
                  << "HPU_MEM lines: " << image_builder.image().used_lines()
                  << " / " << image_builder.image().capacity_lines() << '\n'
                  << "DMA relocation: " << relocation.bindings.size()
                  << " / " << relocation.expected_dma_count << '\n'
                  << "Encoded instructions: "
                  << runtime.instructions.size() << '\n'
                  << "Generated artifacts: header=" << artifacts.header.size()
                  << "B, source=" << artifacts.source.size()
                  << "B, manifest="
                  << artifacts.resolved_dma_manifest.size() << "B\n";
        if (print_asm) {
            std::cout << "\n--- generated HPU inline-assembly body ---\n"
                      << lowered.body_asm;
        } else {
            std::cout
                << "Pass --print-asm to print the generated instruction body.\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS composed application example failed: "
                  << error.what() << '\n';
        return 1;
    }
}
