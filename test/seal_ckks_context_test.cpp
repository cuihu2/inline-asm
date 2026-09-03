#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/automorphism.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/ckks_level.hpp"
#include "hpu/seal/evaluation_key.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "scheme/ckks/ciphertext_multiply.hpp"
#include "scheme/ckks/relinearize.hpp"
#include "scheme/ckks/rescale.hpp"
#include "scheme/ckks/rotate.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 65536;
        spec.coeff_modulus_bits = {32, 32, 32, 32, 32};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const auto levels = hpu::seal_adapter::create_ckks_level_descriptors(
            *bundle.context);

        if (!bundle.context || bundle.data_moduli.size() != 4
            || bundle.special_moduli.size() != 1 || levels.size() < 3) {
            throw std::runtime_error("unexpected SEALContext Q/P split");
        }
        for (std::size_t level_index = 0; level_index < 3; ++level_index) {
            const auto& level = levels[level_index];
            const std::size_t expected_q = 4 - level_index;
            if (level.q_moduli.size() != expected_q
                || level.rns_layout.q_mod_ids.size() != expected_q
                || level.rns_layout.key_digits.size() != expected_q
                || level.rns_layout.p_mod_ids != std::vector<int>{4}
                || level.evaluation_key_digit_indices.size() != expected_q) {
                throw std::runtime_error(
                    "SEAL level did not preserve the application-global P MOD_ID");
            }
        }
        std::vector<std::uint32_t> all_moduli = bundle.data_moduli;
        all_moduli.insert(
            all_moduli.end(), bundle.special_moduli.begin(), bundle.special_moduli.end());
        for (std::uint32_t modulus : all_moduli) {
            if ((static_cast<std::uint64_t>(modulus) - 1U)
                % (2 * spec.poly_modulus_degree) != 0) {
                throw std::runtime_error("SEAL modulus is not NTT-friendly for N=65536");
            }
        }

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::GaloisKeys galois_keys;
        ::seal::RelinKeys relinearization_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{3}, galois_keys);
        key_generator.create_relin_keys(relinearization_keys);

        ::seal::CKKSEncoder encoder(*bundle.context);
        const std::vector<double> input { 0.125, -1.5, 2.25, 3.0 };
        ::seal::Plaintext plaintext;
        encoder.encode(input, std::pow(2.0, 40), plaintext);
        const auto hpu_plaintext = hpu::seal_adapter::plaintext_to_hpu(
            plaintext, *bundle.context);
        const auto plaintext_round_trip = hpu::seal_adapter::hpu_to_seal_ntt(
            hpu_plaintext, plaintext.parms_id(), *bundle.context);
        if (plaintext_round_trip.size() != plaintext.coeff_count()
            || !std::equal(
                plaintext_round_trip.begin(), plaintext_round_trip.end(),
                plaintext.data())) {
            throw std::runtime_error(
                "SEAL plaintext NTT -> HPU NTT -> SEAL NTT round-trip failed");
        }
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);
        if (!ciphertext.is_ntt_form() || ciphertext.size() != 2
            || relinearization_keys.size() == 0) {
            throw std::runtime_error("SEAL did not produce the expected CKKS artifacts");
        }

        const auto hpu_relinearization_key =
            hpu::seal_adapter::relinearization_key_to_hpu(
                relinearization_keys, *bundle.context, levels.front());
        if (hpu_relinearization_key.empty()
            || hpu_relinearization_key.front().key_component_0.moduli.size()
                != bundle.data_moduli.size() + bundle.special_moduli.size()) {
            throw std::runtime_error("SEAL RelinKeys did not convert from the key context");
        }

        // The first HPU application shape comes from SEALContext/RelinKeys,
        // never from the old P=3,dnum=2 demo profile.
        const std::string application =
            hpu::scheme::ckks::generate_ciphertext_multiply_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                static_cast<int>(bundle.data_moduli.size()),
                static_cast<int>(bundle.special_moduli.size()),
                static_cast<int>(hpu_relinearization_key.size()),
                true);
        if (application.find("Invalid CKKS") != std::string::npos
            || application.find("no input NTT is emitted") == std::string::npos) {
            throw std::runtime_error(
                "SEAL-derived CKKS application shape was not accepted");
        }

        const auto hpu_galois_key = hpu::seal_adapter::galois_key_to_hpu(
            galois_keys, 3, *bundle.context, levels.front());
        const auto fused_tables =
            hpu::seal_adapter::create_fused_inverse_automorphism_tables(
                ciphertext.parms_id(), 3, *bundle.context);
        const auto lower_fused_tables =
            hpu::seal_adapter::create_fused_inverse_automorphism_tables(
                levels[1].parms_id, 3, *bundle.context);
        if (hpu_galois_key.size() != hpu_relinearization_key.size()
            || fused_tables.size() != bundle.data_moduli.size()
            || lower_fused_tables.size() != levels[1].q_moduli.size()) {
            throw std::runtime_error("SEAL Galois key/twiddle conversion shape mismatch");
        }
        const auto lower_relinearization_key =
            hpu::seal_adapter::relinearization_key_to_hpu(
                relinearization_keys, *bundle.context, levels[1]);
        if (lower_relinearization_key.size() != 3
            || lower_relinearization_key.front().key_component_0.modulus_ids
                != std::vector<std::uint8_t>({0, 1, 2, 4})) {
            throw std::runtime_error(
                "Q3 relinearization key did not select Q0,Q1,Q2,P0");
        }
        for (const auto& tables : fused_tables) {
            if (tables.stages.size() != 16
                || tables.post_untwist_scale.size() != spec.poly_modulus_degree
                || hpu::model::pow_mod(
                    tables.modified_psi, 3, tables.modulus)
                    != tables.canonical_psi) {
                throw std::runtime_error("modified-root INTT table invariant failed");
            }
        }
        const std::string rotate_application =
            hpu::scheme::ckks::generate_rotate_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                static_cast<int>(bundle.data_moduli.size()),
                static_cast<int>(bundle.special_moduli.size()),
                static_cast<int>(hpu_galois_key.size()),
                3,
                true);
        if (rotate_application.find("Invalid CKKS") != std::string::npos
            || rotate_application.find("INTT_psi^(1/k)") == std::string::npos) {
            throw std::runtime_error("SEAL-derived CKKS Rotate shape was not accepted");
        }
        const std::string lower_rotate =
            hpu::scheme::ckks::generate_rotate_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                levels[1].rns_layout,
                3,
                true);
        const std::string lower_relinearize =
            hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                levels[1].rns_layout,
                true);
        if (lower_rotate.find("Invalid CKKS") != std::string::npos
            || lower_relinearize.find("Invalid SEAL-facing") != std::string::npos
            || lower_rotate.find(hpu::pmodld(4)) == std::string::npos
            || lower_rotate.find(hpu::pmodld(3)) != std::string::npos) {
            throw std::runtime_error(
                "Q3 CKKS codegen did not keep the fixed special-prime MOD_ID");
        }
        const std::string standalone_relinearize =
            hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                static_cast<int>(bundle.data_moduli.size()),
                static_cast<int>(bundle.special_moduli.size()),
                static_cast<int>(hpu_relinearization_key.size()),
                true);
        const std::string standalone_rescale =
            hpu::scheme::ckks::generate_rescale_ntt_body_asm(
                static_cast<int>(spec.poly_modulus_degree),
                static_cast<int>(bundle.data_moduli.size()),
                true);
        if (standalone_relinearize.find("Invalid SEAL-facing") != std::string::npos
            || standalone_rescale.find("Invalid SEAL-facing") != std::string::npos) {
            throw std::runtime_error(
                "SEAL-derived standalone CKKS kernel shape was not accepted");
        }

        const int num_q = static_cast<int>(bundle.data_moduli.size());
        const std::string pointwise_programs[] {
            hpu::scheme::ckks::generate_add_body_asm(num_q, true),
            hpu::scheme::ckks::generate_subtract_body_asm(num_q, true),
            hpu::scheme::ckks::generate_multiply_plain_body_asm(num_q, true),
            hpu::scheme::ckks::generate_add_plain_body_asm(num_q, true),
            hpu::scheme::ckks::generate_subtract_plain_body_asm(num_q, true),
        };
        for (const auto& program : pointwise_programs) {
            if (program.find("Invalid CKKS") != std::string::npos
                || program.find("pntt ") != std::string::npos
                || program.find("pintt ") != std::string::npos) {
                throw std::runtime_error(
                    "SEAL-derived pointwise kernel emitted an invalid transform");
            }
        }

        for (std::size_t component = 0; component < ciphertext.size(); ++component) {
            const auto hpu_polynomial = hpu::seal_adapter::ciphertext_component_to_hpu(
                ciphertext, component, *bundle.context);
            const auto seal_round_trip = hpu::seal_adapter::hpu_to_seal_ntt(
                hpu_polynomial, ciphertext.parms_id(), *bundle.context);
            const std::uint64_t* expected = ciphertext.data(component);
            if (!std::equal(
                    seal_round_trip.begin(), seal_round_trip.end(), expected)) {
                throw std::runtime_error("SEAL NTT -> HPU NTT -> SEAL NTT round-trip failed");
            }
        }

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext lower_ciphertext;
        evaluator.multiply(ciphertext, ciphertext, lower_ciphertext);
        evaluator.relinearize_inplace(lower_ciphertext, relinearization_keys);
        evaluator.rescale_to_next_inplace(lower_ciphertext);
        if (lower_ciphertext.parms_id() != levels[1].parms_id) {
            throw std::runtime_error("SEAL rescale did not reach the Q3 descriptor");
        }
        for (std::size_t component = 0;
             component < lower_ciphertext.size(); ++component) {
            const auto hpu_polynomial =
                hpu::seal_adapter::ciphertext_component_to_hpu(
                    lower_ciphertext, component, *bundle.context);
            const auto seal_round_trip = hpu::seal_adapter::hpu_to_seal_ntt(
                hpu_polynomial, lower_ciphertext.parms_id(), *bundle.context);
            if (!std::equal(
                    seal_round_trip.begin(), seal_round_trip.end(),
                    lower_ciphertext.data(component))) {
                throw std::runtime_error("Q3 ciphertext NTT bridge round-trip failed");
            }
        }

        ::seal::Decryptor decryptor(*bundle.context, key_generator.secret_key());
        ::seal::Plaintext decrypted;
        decryptor.decrypt(ciphertext, decrypted);
        std::vector<double> decoded;
        encoder.decode(decrypted, decoded);
        for (std::size_t index = 0; index < input.size(); ++index) {
            if (std::abs(decoded[index] - input[index]) > 1e-3) {
                throw std::runtime_error("SEAL CKKS encode/encrypt/decrypt/decode smoke failed");
            }
        }

        std::cout
            << "SEAL CKKS N=65536 multilevel descriptors, bridges, keys, Rotate, and pointwise kernels passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS context test failed: " << error.what() << '\n';
        return 1;
    }
}
