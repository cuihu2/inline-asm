#include "delivery_options.hpp"
#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/bgv_operation_plan.hpp"
#include "hpu/seal/bgv_software_executor.hpp"
#include "scheme/bfv/galois.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <vector>

int main(int argc, char** argv)
{
    try {
        const auto options = parse_delivery_options(argc, argv, "--print-dma");
        const auto stem = delivery_artifact_stem("bgv_composed_application", options);
        const auto degree = options.poly_modulus_degree.value_or(128);
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(degree);
        parameters.set_coeff_modulus({seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(degree > 32768 ? 786433 : 65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        if (!context.parameters_set()) throw std::runtime_error("invalid BGV composed context");
        seal::KeyGenerator generator(context);
        seal::RelinKeys relin_keys;
        seal::GaloisKeys galois_keys;
        generator.create_relin_keys(relin_keys);
        generator.create_galois_keys(std::vector<std::uint32_t>{
            hpu::scheme::bfv::row_rotation_galois_element(degree, 1),
            hpu::scheme::bfv::column_rotation_galois_element(degree)}, galois_keys);
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> slots(degree), expected(degree);
        for (std::size_t i = 0; i < degree; ++i) slots[i] = i % 3 + 1;
        const auto row_size = degree / 2;
        for (std::size_t i = 0; i < degree; ++i) {
            const auto rotated = slots[(i / row_size) * row_size + (i % row_size + 1) % row_size];
            const auto swapped = slots[(i + row_size) % degree];
            expected[i] = (slots[i] * (rotated + swapped) + 7) % parameters.plain_modulus().value();
        }
        seal::Plaintext encoded_input, bias;
        encoder.encode(slots, encoded_input);
        encoder.encode(std::vector<std::uint64_t>(degree, 7), bias);
        seal::Ciphertext encrypted;
        seal::Encryptor(context, generator.secret_key()).encrypt_symmetric(encoded_input, encrypted);

        // Explicit branching graph. Multiply and Relinearize are separate
        // nodes, so the three-component tensor also has its own IT golden.
        hpu::seal_adapter::BgvOperationPlan plan(context);
        const auto x = plan.add_ciphertext("input/x", encrypted);
        const auto rows = plan.append_rotate_rows("rotate_rows", x, 1, galois_keys);
        const auto columns = plan.append_rotate_columns("rotate_columns", x, galois_keys);
        const auto mixed = plan.append_add("mix", rows, columns);
        const auto tensor = plan.append_multiply("multiply", x, mixed);
        const auto product = plan.append_relinearize("relinearize", tensor, relin_keys);
        const auto switched = plan.append_modswitch_to_next("drop_level", product);
        const auto output = plan.append_add_plain("bias", switched, bias);
        plan.set_output(output);
        const auto application = plan.lower(delivery_construction_limit(degree, 4096));
        hpu::seal_adapter::BgvSoftwareExecutor executor(context, application.image);
        executor.execute(plan);

        // Independent modified-SEAL oracle, one snapshot for every graph node.
        seal::Evaluator evaluator(context);
        seal::Ciphertext host_rows, host_columns, host_mixed, host_tensor, host_product, host_switched, host_output;
        evaluator.rotate_rows(encrypted, 1, galois_keys, host_rows);
        evaluator.rotate_columns(encrypted, galois_keys, host_columns);
        evaluator.add(host_rows, host_columns, host_mixed);
        evaluator.multiply(encrypted, host_mixed, host_tensor);
        evaluator.relinearize(host_tensor, relin_keys, host_product);
        evaluator.mod_switch_to_next(host_product, host_switched);
        evaluator.add_plain(host_switched, bias, host_output);
        auto request = hpu::seal_adapter::make_bgv_application_package(stem, context, plan, application,
            {host_rows, host_columns, host_mixed, host_tensor, host_product, host_switched, host_output},
            executor.memory().words());
        seal::Plaintext decrypted;
        seal::Decryptor(context, generator.secret_key()).decrypt(host_output, decrypted);
        std::vector<std::uint64_t> decoded;
        encoder.decode(decrypted, decoded);
        if (decoded != expected) throw std::runtime_error("BGV composed decoded slots differ from expression");
        request.semantic_report = hpu::seal_adapter::integer_delivery_semantics(decoded);
        if (options.emit_directory) hpu::delivery::write_application_package(*options.emit_directory, request);
        std::cout << "BGV composed application PASS: N=" << degree << ", " << plan.steps().size()
                  << " graph nodes, " << application.instructions.size() << " instructions, "
                  << application.image.used_lines() << " HPU_MEM lines\n";
        if (options.print_program) std::cout << request.program.resolved_dma_manifest;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV composed application failed: " << error.what() << '\n';
        return 1;
    }
}
