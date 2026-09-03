#include "hpu/runtime/application.hpp"
#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_context.hpp"

#include <seal/seal.h>

#include <cmath>
#include <cstdint>
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

} // namespace

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        ::seal::GaloisKeys galois_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{3}, galois_keys);

        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext plaintext;
        encoder.encode(
            std::vector<double>{0.25, -1.0}, std::pow(2.0, 12), plaintext);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);

        hpu::seal_adapter::CkksApplicationImageBuilder builder(
            *bundle.context, 512);
        const auto modulus_table = builder.add_modulus_table();
        const auto canonical = builder.add_canonical_twiddles();
        const auto prepared_ciphertext = builder.add_ciphertext("input", ciphertext);
        const auto prepared_plaintext = builder.add_plaintext("plain", plaintext);
        const auto& level = builder.levels()[1];
        const auto prepared_relin = builder.add_relinearization_key(
            "relin_q2", relin_keys, level);
        const auto prepared_galois = builder.add_galois_key(
            "galois3_q2", galois_keys, 3, level);
        const auto fused = builder.add_fused_automorphism_twiddles(
            "rotate3_q2", 3, level);
        const auto output = builder.reserve_ciphertext(
            "output_q2", level, 2, std::pow(2.0, 12));

        require(modulus_table.line_count == 1,
                "Q/P modulus table should fit one small-bank source line");
        require(canonical.size() == 4
                    && canonical.front().forward_stages.size() == 7
                    && canonical.front().inverse_stages.size() == 7,
                "canonical Q/P twiddle bundle has the wrong shape");
        require(prepared_ciphertext.components.size() == 2
                    && prepared_plaintext.components.size() == 1
                    && prepared_ciphertext.components.front().limbs.front().line_count == 2,
                "SEAL objects were not split into line-aligned polynomial limbs");
        require(prepared_relin.digits.size() == level.q_moduli.size()
                    && prepared_galois.digits.size() == level.q_moduli.size()
                    && prepared_relin.digits.front().front().modulus_ids
                        == std::vector<std::uint8_t>({0, 1, 3}),
                "level-specific Q/P evaluation-key image is incorrect");
        require(fused.size() == level.q_moduli.size()
                    && fused.front().inverse_stages.size() == 7
                    && output.components.size() == 2,
                "Rotate twiddles or reserved output shape is incorrect");

        const auto& image = builder.image();
        require(image.used_lines() <= image.capacity_lines()
                    && image.words().size()
                        == image.used_lines() * hpu::runtime::kHpuMemLineWords,
                "HPU_MEM image accounting is inconsistent");
        std::uint64_t expected_offset = 0;
        for (const auto& allocation : image.allocations()) {
            require(allocation.span.line_offset == expected_offset,
                    "HPU_MEM allocations overlap or contain an untracked gap");
            require(allocation.id.find("secret") == std::string::npos,
                    "secret-key material appeared in HPU_MEM metadata");
            expected_offset += allocation.span.line_count;
        }

        hpu::runtime::Application application;
        application.load_modulus_table(modulus_table);
        hpu::seal_adapter::register_rns_object(
            application, prepared_ciphertext, false);
        hpu::seal_adapter::register_rns_object(application, output, true);
        const std::string first_input = prepared_ciphertext.components.front().id
            + "/mod" + std::to_string(
                prepared_ciphertext.components.front().modulus_ids.front());
        application.load_object(first_input, 0);
        require(application.object(first_input).resident_slot == 0,
                "prepared SEAL limb did not enter the runtime residency model");

        std::cout << "SEAL CKKS application HPU_MEM image preparation passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS application image test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
