#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/evaluation_key.hpp"
#include "hpu/seal/ntt_bridge.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 65536;
        spec.coeff_modulus_bits = {32, 32, 32, 32, 32};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);

        if (!bundle.context || bundle.data_moduli.size() != 4
            || bundle.special_moduli.size() != 1) {
            throw std::runtime_error("unexpected SEALContext Q/P split");
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
        ::seal::RelinKeys relinearization_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relinearization_keys);

        ::seal::CKKSEncoder encoder(*bundle.context);
        const std::vector<double> input { 0.125, -1.5, 2.25, 3.0 };
        ::seal::Plaintext plaintext;
        encoder.encode(input, std::pow(2.0, 20), plaintext);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);
        if (!ciphertext.is_ntt_form() || ciphertext.size() != 2
            || relinearization_keys.size() == 0) {
            throw std::runtime_error("SEAL did not produce the expected CKKS artifacts");
        }

        const auto hpu_relinearization_key =
            hpu::seal_adapter::relinearization_key_to_hpu(
                relinearization_keys, *bundle.context);
        if (hpu_relinearization_key.empty()
            || hpu_relinearization_key.front().key_component_0.moduli.size()
                != bundle.data_moduli.size() + bundle.special_moduli.size()) {
            throw std::runtime_error("SEAL RelinKeys did not convert from the key context");
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
            << "SEAL CKKS N=65536 host path and exact HPU NTT bridge passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS context test failed: " << error.what() << '\n';
        return 1;
    }
}
