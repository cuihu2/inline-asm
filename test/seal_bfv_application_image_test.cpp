#include "hpu/model/hardware_ntt.hpp"
#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cstddef>
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

template <typename Function> void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

std::uint32_t multiply_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) * right) % modulus);
}

std::uint32_t product_mod(const hpu::seal_adapter::BfvLevelRegistry& registry,
                          const std::vector<int>& factors, std::uint32_t target)
{
    std::uint32_t result = 1;
    for (int factor : factors) {
        result = multiply_mod(
            result, registry.modulus_table[static_cast<std::size_t>(factor)] % target, target);
    }
    return result;
}

std::uint32_t first_word(const hpu::runtime::HpuMemImage& image, const std::string& id)
{
    const auto& allocation = image.allocation(id);
    return image.words()[static_cast<std::size_t>(allocation.span.line_offset) *
                         hpu::runtime::kHpuMemLineWords];
}

std::vector<std::uint32_t> allocation_words(const hpu::runtime::HpuMemImage& image,
                                            const std::string& id)
{
    const auto& allocation = image.allocation(id);
    const auto first =
        image.words().begin() +
        static_cast<std::ptrdiff_t>(allocation.span.line_offset * hpu::runtime::kHpuMemLineWords);
    return {first, first + static_cast<std::ptrdiff_t>(allocation.word_count)};
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        spec.plain_modulus_bits = 17;
        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);

        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t index = 0; index < slots.size(); ++index) {
            slots[index] =
                index % 3 == 0 ? bundle.plain_modulus - 1 : static_cast<std::uint64_t>(index + 1);
        }
        ::seal::Plaintext plaintext;
        encoder.encode(slots, plaintext);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext ciphertext;
        encryptor.encrypt(plaintext, ciphertext);

        hpu::seal_adapter::BfvApplicationImageBuilder builder(*bundle.context, 4096);
        const auto modulus_table = builder.add_modulus_table();
        const auto canonical = builder.add_canonical_twiddles();
        const auto& level = builder.level_chain().top();
        const auto prepared_ciphertext = builder.add_ciphertext("input/ciphertext", ciphertext);
        const auto add_plaintext =
            builder.add_add_subtract_plaintext("plain/add_subtract", plaintext, level);
        const auto multiply_plaintext =
            builder.add_multiply_plaintext("plain/multiply", plaintext, level);
        const auto& next_level = builder.level_chain().next(level.parms_id);
        const auto next_add_plaintext =
            builder.add_add_subtract_plaintext("plain/add_subtract_next", plaintext, next_level);
        const auto output = builder.reserve_ciphertext("output/ciphertext", level);
        const auto prepared_relin = builder.add_relinearization_key("relin/top", relin_keys, level);
        const auto keyswitch = builder.add_keyswitch_constants("constants/keyswitch/top", level);
        const auto multiply = builder.add_multiply_constants("constants/multiply/top", level);

        const auto& registry = builder.registry();
        const std::size_t q_count = level.keyswitch_layout.q_mod_ids.size();
        const std::size_t b_count = level.b_mod_ids.size();
        require(builder.image().allocation("constants/modulus_table").word_count ==
                        registry.modulus_table.size() * 4 &&
                    canonical.size() + 1 == registry.modulus_table.size(),
                "BFV modulus table or canonical twiddle coverage is incomplete");
        require(std::all_of(canonical.begin(), canonical.end(),
                            [](const auto& twiddles) {
                                return twiddles.forward_stages.size() == 7 &&
                                       twiddles.inverse_stages.size() == 7;
                            }),
                "BFV canonical NTT stage count is incorrect");
        require(std::none_of(canonical.begin(), canonical.end(),
                             [&](const auto& twiddles) {
                                 return twiddles.modulus_id ==
                                        static_cast<std::uint8_t>(level.plaintext_mod_id);
                             }),
                "plaintext modulus incorrectly received evaluator NTT twiddles");

        require(prepared_ciphertext.parms_id == level.parms_id &&
                    prepared_ciphertext.chain_index == level.chain_index &&
                    prepared_ciphertext.domain == hpu::runtime::PolynomialDomain::coefficient &&
                    prepared_ciphertext.components.size() == 2 &&
                    add_plaintext.domain == hpu::runtime::PolynomialDomain::coefficient &&
                    multiply_plaintext.domain ==
                        hpu::runtime::PolynomialDomain::canonical_ntt_physical &&
                    next_add_plaintext.parms_id == next_level.parms_id &&
                    next_add_plaintext.components.front().modulus_ids.size() + 1 ==
                        add_plaintext.components.front().modulus_ids.size() &&
                    output.components.size() == 2,
                "BFV ciphertext/plaintext/output object metadata is incorrect");
        for (std::size_t basis = 0; basis < level.q_moduli.size(); ++basis) {
            const std::string suffix = "/mod" + std::to_string(basis);
            const std::vector<std::uint32_t> input_words =
                allocation_words(builder.image(), "input/ciphertext/c0" + suffix);
            std::vector<std::uint32_t> expected_input(spec.poly_modulus_degree);
            for (std::size_t index = 0; index < spec.poly_modulus_degree; ++index) {
                expected_input[index] = static_cast<std::uint32_t>(
                    ciphertext.data(0)[basis * spec.poly_modulus_degree + index]);
            }
            require(input_words == expected_input,
                    "BFV coefficient-domain ciphertext image differs from SEAL");
        }

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected_add = ciphertext;
        evaluator.add_plain_inplace(expected_add, plaintext);
        for (std::size_t basis = 0; basis < level.q_moduli.size(); ++basis) {
            const std::uint32_t q = level.q_moduli[basis];
            std::vector<std::uint32_t> expected_delta(spec.poly_modulus_degree);
            for (std::size_t index = 0; index < spec.poly_modulus_degree; ++index) {
                const std::uint64_t before =
                    ciphertext.data(0)[basis * spec.poly_modulus_degree + index];
                const std::uint64_t after =
                    expected_add.data(0)[basis * spec.poly_modulus_degree + index];
                expected_delta[index] = static_cast<std::uint32_t>((after + q - before) % q);
            }
            require(allocation_words(builder.image(), "plain/add_subtract/c0/mod" +
                                                          std::to_string(basis)) == expected_delta,
                    "prepared BFV Add/Sub plaintext differs from SEAL Delta*m");
        }

        ::seal::Plaintext expected_multiply_plaintext = plaintext;
        evaluator.transform_to_ntt_inplace(expected_multiply_plaintext, level.parms_id);
        const auto expected_multiply_hpu =
            hpu::seal_adapter::plaintext_to_hpu(expected_multiply_plaintext, *bundle.context);
        for (std::size_t basis = 0; basis < level.q_moduli.size(); ++basis) {
            const auto first = expected_multiply_hpu.words.begin() +
                               static_cast<std::ptrdiff_t>(basis * spec.poly_modulus_degree);
            const std::vector<std::uint32_t> expected_limb(first, first + spec.poly_modulus_degree);
            require(allocation_words(builder.image(), "plain/multiply/c0/mod" +
                                                          std::to_string(basis)) == expected_limb,
                    "prepared BFV MultiplyPlain plaintext differs from SEAL");
        }

        std::vector<std::uint8_t> expected_key_ids;
        for (int id : level.keyswitch_layout.q_mod_ids) {
            expected_key_ids.push_back(static_cast<std::uint8_t>(id));
        }
        expected_key_ids.push_back(
            static_cast<std::uint8_t>(level.keyswitch_layout.p_mod_ids.front()));
        require(prepared_relin.data_parms_id == level.parms_id &&
                    prepared_relin.chain_index == level.chain_index &&
                    prepared_relin.digits.size() == q_count &&
                    prepared_relin.digits.front().size() == 2 &&
                    prepared_relin.digits.front().front().modulus_ids == expected_key_ids,
                "BFV level-specific relinearization key has the wrong Q|P shape");

        const std::size_t expected_keyswitch_constants = q_count * q_count + 4 * q_count + 2;
        require(keyswitch.data_parms_id == level.parms_id &&
                    keyswitch.chain_index == level.chain_index &&
                    keyswitch.hardware_constant_polynomial_count == expected_keyswitch_constants &&
                    keyswitch.hardware_workspace_polynomial_count == 4 * q_count + 4 &&
                    first_word(builder.image(), keyswitch.id) == 0x424b5331U,
                "BFV KeySwitch image resources have the wrong shape");
        const int p_id = level.keyswitch_layout.p_mod_ids.front();
        const std::uint32_t p = registry.modulus_table[static_cast<std::size_t>(p_id)];
        for (int q_id : level.keyswitch_layout.q_mod_ids) {
            const std::uint32_t q = registry.modulus_table[static_cast<std::size_t>(q_id)];
            require(first_word(builder.image(), keyswitch.hardware_prefix + "/half/mod" +
                                                    std::to_string(q_id)) == (p >> 1U) % q &&
                        first_word(builder.image(), keyswitch.hardware_prefix +
                                                        "/moddown/p_inverse/mod" +
                                                        std::to_string(q_id)) ==
                            hpu::model::inverse_mod_prime(p % q, q),
                    "BFV rounded single-P ModDown constants are incorrect");
        }

        const std::size_t expected_multiply_constants =
            2 * b_count * q_count + 5 * q_count + 4 * b_count + 4;
        const std::size_t expected_multiply_workspaces =
            13 * q_count + 10 * b_count + 13 + std::max(q_count, b_count);
        require(multiply.data_parms_id == level.parms_id &&
                    multiply.chain_index == level.chain_index &&
                    multiply.q_mod_ids == level.keyswitch_layout.q_mod_ids &&
                    multiply.b_mod_ids == level.b_mod_ids &&
                    multiply.m_sk_mod_id == level.m_sk_mod_id &&
                    multiply.plaintext_mod_id == level.plaintext_mod_id &&
                    multiply.hardware_constant_polynomial_count == expected_multiply_constants &&
                    multiply.hardware_workspace_polynomial_count == expected_multiply_workspaces &&
                    first_word(builder.image(), multiply.id) == 0x42465631U,
                "BFV BEHZ multiply constant image has the wrong shape");

        const int first_q_id = level.keyswitch_layout.q_mod_ids.front();
        const int first_b_id = level.b_mod_ids.front();
        const std::uint32_t first_q = registry.modulus_table[static_cast<std::size_t>(first_q_id)];
        const std::uint32_t first_b = registry.modulus_table[static_cast<std::size_t>(first_b_id)];
        require(first_word(builder.image(),
                           multiply.hardware_prefix + "/t/mod" + std::to_string(first_q_id)) ==
                    level.plaintext_modulus % first_q,
                "BFV plaintext-modulus residues are incorrect");
        require(first_word(builder.image(), multiply.hardware_prefix + "/fast_floor/q_inverse/mod" +
                                                std::to_string(first_b_id)) ==
                    hpu::model::inverse_mod_prime(
                        product_mod(registry, level.keyswitch_layout.q_mod_ids, first_b), first_b),
                "BFV fast-floor Q inverse is incorrect");
        require(first_word(builder.image(), multiply.hardware_prefix + "/branchless/b_inverse/mod" +
                                                std::to_string(level.m_sk_mod_id)) ==
                    hpu::model::inverse_mod_prime(
                        product_mod(registry, level.b_mod_ids, level.m_sk), level.m_sk),
                "BFV branchless B inverse is incorrect");
        const std::uint32_t b_mod_q = product_mod(registry, level.b_mod_ids, first_q);
        require(first_word(builder.image(), multiply.hardware_prefix +
                                                "/branchless/negative_b/mod" +
                                                std::to_string(first_q_id)) ==
                    (b_mod_q == 0 ? 0 : first_q - b_mod_q),
                "BFV branchless negative-B residue is incorrect");

        require_invalid_argument(
            [&] {
                hpu::seal_adapter::BfvLevelDescriptor unknown;
                (void)builder.add_multiply_constants("invalid", unknown);
            },
            "unknown BFV level was accepted by the application image builder");

        const auto& image = builder.image();
        require(image.used_lines() <= image.capacity_lines() &&
                    image.words().size() == image.used_lines() * hpu::runtime::kHpuMemLineWords,
                "BFV HPU_MEM image accounting is inconsistent");
        std::uint64_t expected_offset = 0;
        for (const auto& allocation : image.allocations()) {
            require(allocation.span.line_offset == expected_offset,
                    "BFV HPU_MEM allocations overlap or contain an untracked gap");
            require(allocation.id.find("secret") == std::string::npos,
                    "secret-key material appeared in BFV HPU_MEM metadata");
            expected_offset += allocation.span.line_count;
        }

        hpu::runtime::Application application;
        application.load_modulus_table(modulus_table);
        hpu::seal_adapter::register_bfv_rns_object(application, prepared_ciphertext, false);
        hpu::seal_adapter::register_bfv_rns_object(application, add_plaintext, false);
        hpu::seal_adapter::register_bfv_rns_object(application, multiply_plaintext, false);
        hpu::seal_adapter::register_bfv_rns_object(application, output, true);
        require(application.object("input/ciphertext/c0/mod0").domain ==
                        hpu::runtime::PolynomialDomain::coefficient &&
                    application.object("plain/multiply/c0/mod0").domain ==
                        hpu::runtime::PolynomialDomain::canonical_ntt_physical &&
                    application.object("output/ciphertext/c0/mod0").required_output,
                "BFV runtime object registration lost representation metadata");

        std::cout << "SEAL-derived BFV application image preparation passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL BFV application image test failed: " << error.what() << '\n';
        return 1;
    }
}
