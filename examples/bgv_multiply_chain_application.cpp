#include "hpu/seal/application_delivery.hpp"
#include "delivery_options.hpp"
#include "hpu/seal/bgv_linear_operation_plan.hpp"
#include "hpu/seal/bgv_software_executor.hpp"

#include <seal/seal.h>

#include <iostream>
#include <stdexcept>
#include <string>

int main(int argc, char** argv)
{
    try {
        const auto options = parse_delivery_options(argc, argv, "--print-dma");
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        if (!context.parameters_set()) {
            throw std::runtime_error("BGV multiplication example context is invalid");
        }
        seal::KeyGenerator generator(context);
        seal::RelinKeys relin_keys;
        generator.create_relin_keys(relin_keys);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Ciphertext input;
        seal::Ciphertext multiplier;
        encryptor.encrypt_symmetric(seal::Plaintext("2x^1 + 1"), input);
        encryptor.encrypt_symmetric(seal::Plaintext("3"), multiplier);

        // y = ModSwitch((x + 5) * multiplier) + 7. Only the initial
        // ciphertexts and keys are imported; the product stays in HPU_MEM.
        hpu::seal_adapter::BgvLinearOperationPlan plan(context, input);
        plan.append_add_plain("bias", seal::Plaintext("5"));
        plan.append_multiply("product", multiplier, relin_keys);
        plan.append_modswitch_to_next("drop_level");
        plan.append_add_plain("offset", seal::Plaintext("7"));
        const auto package = plan.lower(8192);
        hpu::seal_adapter::BgvSoftwareExecutor software_executor(
            context, package.image);
        software_executor.execute(plan);
        const auto runtime =
            hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                "bgv_multiply_chain", package);

        // SEAL is an independent metadata oracle, not the execution path.
        seal::Evaluator evaluator(context);
        seal::Ciphertext oracle = input;
        std::vector<seal::Ciphertext> expected_after_step;
        evaluator.add_plain_inplace(oracle, seal::Plaintext("5"));
        expected_after_step.push_back(oracle);
        evaluator.multiply_inplace(oracle, multiplier);
        evaluator.relinearize_inplace(oracle, relin_keys);
        expected_after_step.push_back(oracle);
        evaluator.mod_switch_to_next_inplace(oracle);
        expected_after_step.push_back(oracle);
        evaluator.add_plain_inplace(oracle, seal::Plaintext("7"));
        expected_after_step.push_back(oracle);
        if (package.parms_id != oracle.parms_id() ||
            package.correction_factor != oracle.correction_factor() ||
            package.spans().size() != package.dma.size() ||
            runtime.resolved_dma_manifest.find(
                "steps/product/output/c0/mod0") == std::string::npos ||
            runtime.resolved_dma_manifest.find("output/c1/mod0") ==
                std::string::npos) {
            throw std::runtime_error("BGV multiplication chain metadata or DMA is invalid");
        }
        std::cout << "BGV multiplication-chain example passed: "
                  << package.instructions.size() << " encoded instructions, "
                  << package.dma.size() << " resolved DMA bindings, "
                  << package.image.used_lines() << " HPU_MEM lines\n";
        if (options.print_program) std::cout << runtime.resolved_dma_manifest;
        if (options.emit_directory) {
            auto request = hpu::seal_adapter::make_bgv_application_package(
                "bgv_multiply_chain", context, plan, package,
                expected_after_step, software_executor.memory().words());
            seal::Decryptor decryptor(context, generator.secret_key());
            seal::Plaintext decrypted;
            decryptor.decrypt(expected_after_step.back(), decrypted);
            std::vector<std::uint64_t> decoded;
            seal::BatchEncoder(context).decode(decrypted, decoded);
            request.semantic_report = hpu::seal_adapter::integer_delivery_semantics(decoded);
            hpu::delivery::write_application_package(*options.emit_directory, request);
            std::cout << "Artifacts emitted under: " << *options.emit_directory << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV multiplication-chain example failed: "
                  << error.what() << '\n';
        return 1;
    }
}
