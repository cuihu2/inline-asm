#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/software_executor.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void verify_exact(
    const ::seal::Ciphertext& expected,
    const hpu::seal_adapter::PreparedRnsObject& actual,
    const hpu::seal_adapter::CkksSoftwareExecutor& executor,
    const ::seal::SEALContext& context,
    const char* role)
{
    if (expected.parms_id() != actual.parms_id
        || expected.size() != actual.components.size()) {
        throw std::runtime_error(std::string(role) + " output shape mismatch");
    }
    for (std::size_t component = 0; component < expected.size(); ++component) {
        const auto hpu_polynomial = executor.export_component(actual, component);
        const auto seal_words = hpu::seal_adapter::hpu_to_seal_ntt(
            hpu_polynomial, actual.parms_id, context);
        if (!std::equal(
                seal_words.begin(), seal_words.end(), expected.data(component))) {
            throw std::runtime_error(
                std::string(role) + " HPU software output differs from SEAL NTT words");
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
        const auto levels = hpu::seal_adapter::create_ckks_level_descriptors(
            *bundle.context);
        const auto& level = levels.front();

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        key_generator.create_public_key(public_key);
        ::seal::CKKSEncoder encoder(*bundle.context);
        constexpr double scale = 4096.0;
        ::seal::Plaintext plain_a;
        ::seal::Plaintext plain_b;
        encoder.encode(std::vector<double>{0.25, -1.0}, scale, plain_a);
        encoder.encode(std::vector<double>{1.5, 0.5}, scale, plain_b);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext cipher_a;
        ::seal::Ciphertext cipher_b;
        encryptor.encrypt(plain_a, cipher_a);
        encryptor.encrypt(plain_b, cipher_b);

        hpu::seal_adapter::CkksApplicationImageBuilder builder(
            *bundle.context, 256);
        builder.add_modulus_table();
        const auto input_a = builder.add_ciphertext("input/a", cipher_a);
        const auto input_b = builder.add_ciphertext("input/b", cipher_b);
        const auto plaintext = builder.add_plaintext("plain/b", plain_b);
        const auto add_output = builder.reserve_ciphertext(
            "output/add", level, 2, scale);
        const auto subtract_output = builder.reserve_ciphertext(
            "output/subtract", level, 2, scale);
        const auto multiply_plain_output = builder.reserve_ciphertext(
            "output/multiply_plain", level, 2, scale * scale);
        const auto add_plain_output = builder.reserve_ciphertext(
            "output/add_plain", level, 2, scale);
        const auto subtract_plain_output = builder.reserve_ciphertext(
            "output/subtract_plain", level, 2, scale);

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, builder.image());
        executor.add(input_a, input_b, add_output);
        executor.subtract(input_a, input_b, subtract_output);
        executor.multiply_plain(input_a, plaintext, multiply_plain_output);
        executor.add_plain(input_a, plaintext, add_plain_output);
        executor.subtract_plain(input_a, plaintext, subtract_plain_output);

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.add(cipher_a, cipher_b, expected);
        verify_exact(expected, add_output, executor, *bundle.context, "Add");
        evaluator.sub(cipher_a, cipher_b, expected);
        verify_exact(
            expected, subtract_output, executor, *bundle.context, "Subtract");
        evaluator.multiply_plain(cipher_a, plain_b, expected);
        verify_exact(
            expected, multiply_plain_output, executor,
            *bundle.context, "MultiplyPlain");
        evaluator.add_plain(cipher_a, plain_b, expected);
        verify_exact(
            expected, add_plain_output, executor, *bundle.context, "AddPlain");
        evaluator.sub_plain(cipher_a, plain_b, expected);
        verify_exact(
            expected, subtract_plain_output, executor,
            *bundle.context, "SubtractPlain");

        std::cout
            << "CKKS HPU_MEM software executor pointwise operations passed exact SEAL NTT comparison\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS software executor test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
