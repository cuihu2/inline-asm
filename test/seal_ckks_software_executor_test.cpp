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
        || expected.size() != actual.components.size()
        || std::abs(expected.scale() - actual.scale)
            > 1e-12 * std::max(expected.scale(), actual.scale)) {
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
        if (levels.size() < 2) {
            throw std::runtime_error("software executor test needs a Rescale level");
        }
        const auto& level = levels.front();
        const auto& next_level = levels[1];

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        key_generator.create_public_key(public_key);
        ::seal::RelinKeys relinearization_keys;
        key_generator.create_relin_keys(relinearization_keys);
        ::seal::GaloisKeys galois_keys;
        constexpr std::uint32_t galois_element = 3;
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{galois_element}, galois_keys);
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
            *bundle.context, 640);
        builder.add_modulus_table();
        const auto canonical_twiddles = builder.add_canonical_twiddles();
        const auto prepared_relinearization_key =
            builder.add_relinearization_key(
                "key/relinearization", relinearization_keys, level);
        const auto prepared_galois_key = builder.add_galois_key(
            "key/galois3", galois_keys, galois_element, level);
        const auto fused_rotate_tables =
            builder.add_fused_automorphism_twiddles(
                "rotate3", galois_element, level);
        const auto keyswitch_constants = builder.add_keyswitch_constants(
            "constants/keyswitch/q3", level);
        const auto rescale_constants = builder.add_rescale_constants(
            "constants/rescale/q3_to_q2", level);
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
        const auto square_output = builder.reserve_ciphertext(
            "output/square_tensor", level, 3, scale * scale);
        const auto relinearized_output = builder.reserve_ciphertext(
            "output/relinearized", level, 2, scale * scale);
        const auto direct_key_switch_output = builder.reserve_ciphertext(
            "output/direct_key_switch", level, 2, scale * scale);
        const auto rescaled_output = builder.reserve_ciphertext(
            "output/rescaled", next_level, 2,
            scale * scale / static_cast<double>(level.q_last));
        const auto coefficient_scratch = builder.reserve_ciphertext(
            "scratch/a_coefficient", level, 2, scale,
            hpu::runtime::PolynomialDomain::coefficient);
        const auto restored_ntt = builder.reserve_ciphertext(
            "output/a_restored_ntt", level, 2, scale);
        const auto rotate_workspace = builder.reserve_ciphertext(
            "scratch/rotate3_coefficient", level, 2, scale,
            hpu::runtime::PolynomialDomain::coefficient, galois_element);
        const auto rotate_output = builder.reserve_ciphertext(
            "output/rotate3", level, 2, scale);

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, builder.image());
        executor.add(input_a, input_b, add_output);
        executor.subtract(input_a, input_b, subtract_output);
        executor.multiply_plain(input_a, plaintext, multiply_plain_output);
        executor.add_plain(input_a, plaintext, add_plain_output);
        executor.subtract_plain(input_a, plaintext, subtract_plain_output);
        executor.square(input_a, square_output);
        executor.relinearize(
            square_output, prepared_relinearization_key,
            keyswitch_constants, relinearized_output, canonical_twiddles);
        auto key_switch_base = square_output;
        key_switch_base.components.resize(2);
        auto key_switch_target = square_output;
        key_switch_target.components = {square_output.components[2]};
        executor.key_switch(
            key_switch_base, key_switch_target,
            prepared_relinearization_key, keyswitch_constants,
            direct_key_switch_output,
            canonical_twiddles);
        executor.rescale(
            relinearized_output, rescale_constants,
            rescaled_output, canonical_twiddles);
        executor.rotate(
            input_a, galois_element, prepared_galois_key,
            keyswitch_constants, fused_rotate_tables, canonical_twiddles,
            rotate_workspace, rotate_output);
        executor.inverse_ntt(
            input_a, coefficient_scratch, canonical_twiddles);
        executor.forward_ntt(
            coefficient_scratch, restored_ntt, canonical_twiddles);

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
        evaluator.square(cipher_a, expected);
        verify_exact(
            expected, square_output, executor, *bundle.context, "Square");
        evaluator.relinearize_inplace(expected, relinearization_keys);
        verify_exact(
            expected, relinearized_output, executor,
            *bundle.context, "Relinearize");
        verify_exact(
            expected, direct_key_switch_output, executor,
            *bundle.context, "KeySwitch");
        evaluator.rescale_to_next_inplace(expected);
        verify_exact(
            expected, rescaled_output, executor,
            *bundle.context, "Rescale");
        ::seal::Ciphertext expected_rotate;
        evaluator.apply_galois(
            cipher_a, galois_element, galois_keys, expected_rotate);
        verify_exact(
            expected_rotate, rotate_output, executor,
            *bundle.context, "Rotate");
        verify_exact(
            cipher_a, restored_ntt, executor,
            *bundle.context, "HPU NTT/INTT round-trip");

        std::cout
            << "CKKS HPU_MEM software executor pointwise/Square/KeySwitch/Relinearize/Rescale/Rotate and table-driven NTT/INTT passed exact SEAL NTT comparison\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS software executor test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
