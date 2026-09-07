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
        spec.coeff_modulus_bits = {20, 20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const auto levels = hpu::seal_adapter::create_ckks_level_descriptors(
            *bundle.context);
        if (levels.size() < 3) {
            throw std::runtime_error(
                "software executor test needs Q4 -> Q3 -> Q2 levels");
        }
        const auto& level = levels.front();
        const auto& next_level = levels[1];
        const auto& bottom_level = levels[2];

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
        constexpr double scale = 262144.0;
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
            *bundle.context, 1536);
        builder.add_modulus_table();
        const auto canonical_twiddles = builder.add_canonical_twiddles();
        const auto prepared_relinearization_key =
            builder.add_relinearization_key(
                "key/relinearization/q4", relinearization_keys, level);
        const auto prepared_galois_key = builder.add_galois_key(
            "key/galois3/q4", galois_keys, galois_element, level);
        const auto fused_rotate_tables =
            builder.add_fused_automorphism_twiddles(
                "rotate3/q4", galois_element, level);
        const auto keyswitch_constants = builder.add_keyswitch_constants(
            "constants/keyswitch/q4", level);
        const auto rescale_constants = builder.add_rescale_constants(
            "constants/rescale/q4_to_q3", level);
        const auto middle_relinearization_key =
            builder.add_relinearization_key(
                "key/relinearization/q3", relinearization_keys, next_level);
        const auto middle_galois_key = builder.add_galois_key(
            "key/galois3/q3", galois_keys, galois_element, next_level);
        const auto middle_fused_rotate_tables =
            builder.add_fused_automorphism_twiddles(
                "rotate3/q3", galois_element, next_level);
        const auto middle_keyswitch_constants = builder.add_keyswitch_constants(
            "constants/keyswitch/q3", next_level);
        const auto middle_rescale_constants = builder.add_rescale_constants(
            "constants/rescale/q3_to_q2", next_level);
        if (level.rns_layout.p_mod_ids
                != std::vector<int>({4})
            || next_level.rns_layout.p_mod_ids
                != std::vector<int>({4})
            || bottom_level.rns_layout.p_mod_ids
                != std::vector<int>({4})
            || middle_relinearization_key.digits.size() != 3
            || middle_relinearization_key.digits.front().front().modulus_ids
                != std::vector<std::uint8_t>({0, 1, 2, 4})) {
            throw std::runtime_error(
                "multilevel image did not preserve fixed P MOD_ID 4");
        }
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
        const auto multiply_output = builder.reserve_ciphertext(
            "output/multiply_tensor", level, 3, scale * scale);
        const auto multiply_relinearized_output = builder.reserve_ciphertext(
            "output/multiply_relinearized", level, 2, scale * scale);
        const double middle_scale =
            scale * scale / static_cast<double>(level.q_last);
        const double bottom_scale = middle_scale * middle_scale
            / static_cast<double>(next_level.q_last);
        const auto multiply_rescaled_output = builder.reserve_ciphertext(
            "output/multiply_rescaled", next_level, 2,
            middle_scale);
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
        const auto middle_rotate_workspace = builder.reserve_ciphertext(
            "scratch/q3_rotate3_coefficient", next_level, 2, middle_scale,
            hpu::runtime::PolynomialDomain::coefficient, galois_element);
        const auto middle_rotate_output = builder.reserve_ciphertext(
            "output/q3_rotate3", next_level, 2, middle_scale);
        const auto middle_multiply_output = builder.reserve_ciphertext(
            "output/q3_multiply_tensor", next_level, 3,
            middle_scale * middle_scale);
        const auto middle_relinearized_output = builder.reserve_ciphertext(
            "output/q3_multiply_relinearized", next_level, 2,
            middle_scale * middle_scale);
        const auto bottom_rescaled_output = builder.reserve_ciphertext(
            "output/q2_rescaled", bottom_level, 2, bottom_scale);

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, builder.image());
        executor.add(input_a, input_b, add_output);
        executor.subtract(input_a, input_b, subtract_output);
        executor.multiply_plain(input_a, plaintext, multiply_plain_output);
        executor.add_plain(input_a, plaintext, add_plain_output);
        executor.subtract_plain(input_a, plaintext, subtract_plain_output);
        executor.square(input_a, square_output);
        executor.multiply(input_a, input_b, multiply_output);
        executor.relinearize(
            multiply_output, prepared_relinearization_key,
            keyswitch_constants, multiply_relinearized_output,
            canonical_twiddles);
        executor.rescale(
            multiply_relinearized_output, rescale_constants,
            multiply_rescaled_output, canonical_twiddles);
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
        executor.rotate(
            multiply_rescaled_output, galois_element, middle_galois_key,
            middle_keyswitch_constants, middle_fused_rotate_tables,
            canonical_twiddles, middle_rotate_workspace,
            middle_rotate_output);
        executor.multiply(
            multiply_rescaled_output, middle_rotate_output,
            middle_multiply_output);
        executor.relinearize(
            middle_multiply_output, middle_relinearization_key,
            middle_keyswitch_constants, middle_relinearized_output,
            canonical_twiddles);
        executor.rescale(
            middle_relinearized_output, middle_rescale_constants,
            bottom_rescaled_output, canonical_twiddles);
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
        ::seal::Ciphertext expected_multiply;
        evaluator.multiply(cipher_a, cipher_b, expected_multiply);
        verify_exact(
            expected_multiply, multiply_output, executor,
            *bundle.context, "Multiply");
        evaluator.relinearize_inplace(
            expected_multiply, relinearization_keys);
        verify_exact(
            expected_multiply, multiply_relinearized_output, executor,
            *bundle.context, "Multiply/Relinearize");
        evaluator.rescale_to_next_inplace(expected_multiply);
        verify_exact(
            expected_multiply, multiply_rescaled_output, executor,
            *bundle.context, "Multiply/Relinearize/Rescale");
        ::seal::Ciphertext expected_middle_rotate;
        evaluator.apply_galois(
            expected_multiply, galois_element, galois_keys,
            expected_middle_rotate);
        verify_exact(
            expected_middle_rotate, middle_rotate_output, executor,
            *bundle.context, "Q3 Rotate");
        ::seal::Ciphertext expected_middle_multiply;
        evaluator.multiply(
            expected_multiply, expected_middle_rotate,
            expected_middle_multiply);
        verify_exact(
            expected_middle_multiply, middle_multiply_output, executor,
            *bundle.context, "Q3 Multiply");
        evaluator.relinearize_inplace(
            expected_middle_multiply, relinearization_keys);
        verify_exact(
            expected_middle_multiply, middle_relinearized_output, executor,
            *bundle.context, "Q3 Multiply/Relinearize");
        evaluator.rescale_to_next_inplace(expected_middle_multiply);
        verify_exact(
            expected_middle_multiply, bottom_rescaled_output, executor,
            *bundle.context, "Q3 Multiply/Relinearize/Rescale to Q2");
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
            << "CKKS HPU_MEM software executor Q4 -> Q3 -> Q2 pointwise/Multiply/Square/KeySwitch/Relinearize/Rescale/Rotate and table-driven NTT/INTT passed exact SEAL NTT comparison\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "CKKS software executor test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
