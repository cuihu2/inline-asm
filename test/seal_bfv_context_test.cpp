#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_level.hpp"
#include "operator/rns_layout.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

template <typename Function>
void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

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
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 4096;
        spec.coeff_modulus_bits = {30, 30, 30, 30, 30};
        spec.plain_modulus_bits = 17;

        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);
        const hpu::seal_adapter::BfvLevelChain chain(*bundle.context);
        const auto& registry = chain.registry();
        require(bundle.context && bundle.data_moduli.size() == 4
                    && bundle.special_modulus != 0
                    && bundle.plain_modulus != 0
                    && chain.size() == 4,
                "unexpected BFV SEALContext shape");
        require(registry.poly_modulus_degree == spec.poly_modulus_degree
                    && registry.modulus_table.size()
                        <= static_cast<std::size_t>(hpu::kMaxModContexts),
                "BFV global modulus registry is invalid");

        const auto& top = chain.top();
        require(top.q_moduli == bundle.data_moduli
                    && top.special_modulus == bundle.special_modulus
                    && top.plaintext_modulus == bundle.plain_modulus
                    && top.keyswitch_layout.p_mod_ids == std::vector<int>{4}
                    && top.keyswitch_layout.key_digits
                        == std::vector<std::vector<int>>{{0}, {1}, {2}, {3}}
                    && !top.b_moduli.empty()
                    && top.b_moduli.size() == top.b_mod_ids.size()
                    && top.m_sk_mod_id >= 0
                    && top.plaintext_mod_id >= 0,
                "top BFV level descriptor is incomplete");

        const auto fixed_modulus_end = registry.modulus_table.begin()
            + static_cast<std::ptrdiff_t>(bundle.data_moduli.size() + 1);
        for (std::size_t level_index = 0;
             level_index < chain.levels().size(); ++level_index) {
            const auto& level = chain.levels()[level_index];
            require(level.q_moduli.size() == bundle.data_moduli.size() - level_index
                        && hpu::is_seal_single_p_rns_decomposition_layout(
                            static_cast<int>(spec.poly_modulus_degree),
                            level.keyswitch_layout)
                        && level.evaluation_key_digit_indices.size()
                            == level.q_moduli.size()
                        && registry.modulus_table[
                            static_cast<std::size_t>(level.m_sk_mod_id)]
                            == level.m_sk
                        && registry.modulus_table[
                            static_cast<std::size_t>(level.plaintext_mod_id)]
                            == level.plaintext_modulus,
                    "BFV level chain lost SEAL/global-MOD_ID invariants");
            for (std::uint32_t modulus : level.b_moduli) {
                require(std::find(registry.modulus_table.begin(),
                                  fixed_modulus_end, modulus)
                            == fixed_modulus_end
                            && modulus != level.plaintext_modulus,
                        "BFV B collides with Q/P/t");
            }
            require(std::find(registry.modulus_table.begin(),
                              fixed_modulus_end, level.m_sk)
                        == fixed_modulus_end
                        && level.m_sk != level.plaintext_modulus
                        && std::find(level.b_moduli.begin(),
                                     level.b_moduli.end(), level.m_sk)
                            == level.b_moduli.end(),
                    "BFV m_sk collides with Q/P/B/t");
        }

        require(chain.next(top.parms_id).q_moduli.size() == 3
                    && chain.bottom().q_moduli.size() == 1
                    && !chain.has_next(chain.bottom().parms_id),
                "BFV level navigation is inconsistent");
        require_invalid_argument(
            [&] { (void)chain.require(::seal::parms_id_type{}); },
            "unknown BFV parms_id was accepted");

        auto invalid = spec;
        invalid.coeff_modulus_bits = {32, 30};
        require_invalid_argument(
            [&] { (void)hpu::seal_adapter::create_bfv_context(invalid); },
            "32-bit Q/P was accepted despite the auxiliary-prime reservation");

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);
        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> left(encoder.slot_count(), 2);
        std::vector<std::uint64_t> right(encoder.slot_count(), 3);
        ::seal::Plaintext left_plain;
        ::seal::Plaintext right_plain;
        encoder.encode(left, left_plain);
        encoder.encode(right, right_plain);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Decryptor decryptor(*bundle.context, key_generator.secret_key());
        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext left_cipher;
        ::seal::Ciphertext right_cipher;
        encryptor.encrypt(left_plain, left_cipher);
        encryptor.encrypt(right_plain, right_cipher);
        evaluator.multiply_inplace(left_cipher, right_cipher);
        evaluator.relinearize_inplace(left_cipher, relin_keys);
        evaluator.mod_switch_to_next_inplace(left_cipher);
        ::seal::Plaintext result_plain;
        decryptor.decrypt(left_cipher, result_plain);
        std::vector<std::uint64_t> result_slots;
        encoder.decode(result_plain, result_slots);
        require(result_slots == std::vector<std::uint64_t>(
                    encoder.slot_count(), 6),
                "32-bit-aux modified-SEAL BFV multiply/relinearize/modswitch failed");

        std::cout << "modified-SEAL BFV Q/P/B/m_sk/t level registry tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL BFV context test failed: " << error.what() << '\n';
        return 1;
    }
}
