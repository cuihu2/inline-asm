#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "scheme/ckks/ciphertext_multiply.hpp"
#include "scheme/ckks/rescale.hpp"
#include "util/hpu_asm.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::size_t count_token(const std::string& text, const std::string& token)
{
    std::size_t count = 0;
    for (std::size_t position = 0;
         (position = text.find(token, position)) != std::string::npos;
         position += token.size()) {
        ++count;
    }
    return count;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const bool print_asm = argc == 2 && std::string(argv[1]) == "--print-asm";
        if (argc > 2 || (argc == 2 && !print_asm)) {
            throw std::invalid_argument("usage: hpu_ckks_polynomial_example [--print-asm]");
        }

        // Five 32-bit primes become Q4 | P1 in SEAL 4.4.4. After one
        // multiply/rescale the result and constant plaintext use Q3.
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 65536;
        spec.coeff_modulus_bits = {32, 32, 32, 32, 32};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const auto levels = hpu::seal_adapter::create_ckks_level_descriptors(
            *bundle.context);
        if (levels.size() < 2) {
            throw std::logic_error("x^2+1 needs one CKKS rescale level");
        }
        const auto& top = levels[0];
        const auto& after_rescale = levels[1];

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);

        const std::vector<double> input {0.25, -1.5, 2.0};
        constexpr double input_scale = 1073741824.0; // 2^30
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_input;
        encoder.encode(input, input_scale, encoded_input);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_input;
        encryptor.encrypt(encoded_input, encrypted_input);

        // Host-only semantic oracle. This verifies f(x)=x^2+1, but does not
        // claim that the generated HPU stream has executed.
        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext host_result;
        evaluator.square(encrypted_input, host_result);
        evaluator.relinearize_inplace(host_result, relin_keys);
        evaluator.rescale_to_next_inplace(host_result);
        if (host_result.parms_id() != after_rescale.parms_id) {
            throw std::logic_error("SEAL rescale did not reach the expected Q3 level");
        }

        ::seal::Plaintext encoded_one;
        encoder.encode(
            std::vector<double>(input.size(), 1.0),
            host_result.parms_id(), host_result.scale(), encoded_one);
        evaluator.add_plain_inplace(host_result, encoded_one);

        ::seal::Decryptor decryptor(*bundle.context, key_generator.secret_key());
        ::seal::Plaintext decrypted;
        decryptor.decrypt(host_result, decrypted);
        std::vector<double> decoded;
        encoder.decode(decrypted, decoded);
        double maximum_error = 0.0;
        for (std::size_t index = 0; index < input.size(); ++index) {
            maximum_error = std::max(
                maximum_error,
                std::abs(decoded[index] - (input[index] * input[index] + 1.0)));
        }
        if (maximum_error > 5e-3) {
            throw std::runtime_error("SEAL x^2+1 semantic oracle exceeded tolerance");
        }

        // Construct the complete application-start DDR image. No SecretKey is
        // accepted by this builder. One million lines is a host-side capacity
        // ceiling; only image.used_lines() is materialized.
        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 1000000);
        const auto modulus_table = image_builder.add_modulus_table();
        image_builder.add_canonical_twiddles();
        image_builder.add_ciphertext("input/x", encrypted_input);
        image_builder.add_relinearization_key(
            "key/relinearization/top", relin_keys, top);
        image_builder.add_plaintext("constant/one/q3", encoded_one);
        image_builder.reserve_ciphertext(
            "intermediate/x_squared/q3", after_rescale, 2, host_result.scale());
        image_builder.reserve_ciphertext(
            "output/x_squared_plus_one/q3", after_rescale, 2, host_result.scale());

        // Compose two kernel bodies under one application-owned modulus-table
        // lifetime and one terminal psync. The generic multiply's left/right
        // DMA operands both bind to input/x for Square. Intermediate
        // dstore/dload remains in this first implementation; the future
        // residency planner may elide it.
        constexpr int modulus_table_object = 4;
        std::string hpu_program = hpu::dload(
            modulus_table_object,
            hpu::DataType::mod_ctx,
            hpu::DloadFlag::small_bank);
        hpu_program +=
            hpu::scheme::ckks::generate_ciphertext_multiply_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                top.rns_layout, false, false);
        hpu_program += hpu::scheme::ckks::generate_add_plain_body_asm(
            static_cast<int>(after_rescale.q_moduli.size()), false, false);
        hpu_program += hpu::pfree(modulus_table_object);
        hpu_program += hpu::psync();

        if (count_token(hpu_program, hpu::psync()) != 1
            || count_token(hpu_program, hpu::dload(
                modulus_table_object,
                hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) != 1) {
            throw std::logic_error("polynomial program lifecycle is not application-scoped");
        }

        const double predicted_scale = hpu::scheme::ckks::rescale_scale(
            hpu::scheme::ckks::multiply_scale(input_scale, input_scale),
            top.q_last);
        std::cout << std::setprecision(8)
                  << "f(x)=x^2+1, N=" << spec.poly_modulus_degree
                  << ", Q" << top.q_moduli.size() << "|P"
                  << top.special_moduli.size() << " -> Q"
                  << after_rescale.q_moduli.size() << '\n'
                  << "HPU_MEM: " << image_builder.image().used_lines()
                  << " / " << image_builder.image().capacity_lines()
                  << " lines; modulus-table source=" << modulus_table.line_count
                  << " line(s)\n"
                  << "Scale: predicted=" << predicted_scale
                  << ", SEAL=" << host_result.scale() << '\n'
                  << "Decoded: [" << decoded[0] << ", " << decoded[1]
                  << ", " << decoded[2] << "]\n"
                  << "Maximum semantic-oracle error: " << maximum_error << '\n'
                  << "Generated HPU body bytes: " << hpu_program.size() << '\n';
        if (print_asm) {
            std::cout << "\n--- generated HPU inline-assembly body ---\n"
                      << hpu_program;
        } else {
            std::cout << "Pass --print-asm to print the generated instruction body.\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS polynomial example failed: " << error.what() << '\n';
        return 1;
    }
}
