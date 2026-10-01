#include "hpu/seal/bgv_linear_operation_plan.hpp"
#include "scheme/bfv/galois.hpp"

#include <seal/seal.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
    try {
        const bool print_dma = argc == 2 && std::string(argv[1]) == "--print-dma";
        if (argc > 2 || (argc == 2 && !print_dma)) {
            throw std::invalid_argument(
                "usage: hpu_bgv_rotate_chain_example [--print-dma]");
        }
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        if (!context.parameters_set()) {
            throw std::runtime_error("BGV rotation example context is invalid");
        }
        seal::KeyGenerator generator(context);
        seal::GaloisKeys keys;
        constexpr int steps = 1;
        generator.create_galois_keys(
            std::vector<std::uint32_t>{
                hpu::scheme::bfv::row_rotation_galois_element(128, steps)},
            keys);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(seal::Plaintext("2x^3 + 7"), input);
        const seal::Plaintext pre_bias("3");
        const seal::Plaintext post_bias("5");

        // y = RotateRows(x + 3, 1) + 5. The HPU reads the first step's
        // output span directly; no intermediate ciphertext is imported.
        hpu::seal_adapter::BgvLinearOperationPlan plan(context, input);
        plan.append_add_plain("add_before", pre_bias);
        plan.append_rotate_rows("rotate_left_1", steps, keys);
        plan.append_add_plain("add_after", post_bias);
        const auto package = plan.lower(4096);
        const auto runtime =
            hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                "bgv_rotate_chain", package);

        // The independent SEAL calculation documents the intended semantics.
        // It is not used to populate any intermediate HPU_MEM input.
        seal::Evaluator evaluator(context);
        seal::Ciphertext oracle = input;
        evaluator.add_plain_inplace(oracle, pre_bias);
        evaluator.rotate_rows_inplace(oracle, steps, keys);
        evaluator.add_plain_inplace(oracle, post_bias);
        if (package.parms_id != oracle.parms_id() ||
            package.correction_factor != oracle.correction_factor() ||
            package.spans().size() != package.dma.size() ||
            runtime.resolved_dma_manifest.find(
                "steps/add_before/output/c0/mod0") == std::string::npos ||
            runtime.resolved_dma_manifest.find("output/c1/mod0") ==
                std::string::npos) {
            throw std::runtime_error("BGV rotation chain metadata or DMA is invalid");
        }
        std::cout << "BGV rotation-chain example passed: "
                  << package.instructions.size() << " encoded instructions, "
                  << package.dma.size() << " resolved DMA bindings, "
                  << package.image.used_lines() << " HPU_MEM lines\n";
        if (print_dma) std::cout << runtime.resolved_dma_manifest;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV rotation-chain example failed: "
                  << error.what() << '\n';
        return 1;
    }
}
