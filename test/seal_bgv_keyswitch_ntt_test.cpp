#include <seal/seal.h>
#include <seal/util/ntt.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::uint64_t add_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q)
{
    return (a + b) % q;
}

std::uint64_t mul_mod(std::uint64_t a, std::uint64_t b, std::uint64_t q)
{
    return ((a % q) * (b % q)) % q;
}

std::uint64_t inverse_mod(std::uint64_t value, std::uint64_t modulus)
{
    std::int64_t old_r = static_cast<std::int64_t>(modulus);
    std::int64_t r = static_cast<std::int64_t>(value % modulus);
    std::int64_t old_t = 0;
    std::int64_t t = 1;
    while (r != 0) {
        const std::int64_t quotient = old_r / r;
        const std::int64_t next_r = old_r - quotient * r;
        const std::int64_t next_t = old_t - quotient * t;
        old_r = r;
        r = next_r;
        old_t = t;
        t = next_t;
    }
    require(old_r == 1, "special P is not invertible");
    return static_cast<std::uint64_t>(
        (old_t % static_cast<std::int64_t>(modulus) +
         static_cast<std::int64_t>(modulus)) % static_cast<std::int64_t>(modulus));
}

void check_relinearization(const seal::SEALContext& context,
                           seal::Evaluator& evaluator,
                           const seal::RelinKeys& keys,
                           const seal::Ciphertext& product)
{
    const auto level = context.get_context_data(product.parms_id());
    require(level && product.size() == 3 && product.is_ntt_form(),
            "BGV KeySwitch source must be a three-component NTT ciphertext");
    const auto& moduli = level->parms().coeff_modulus();
    const auto& key_moduli = context.key_context_data()->parms().coeff_modulus();
    const std::size_t degree = level->parms().poly_modulus_degree();
    const std::size_t q_count = moduli.size();
    const std::size_t p_index = key_moduli.size() - 1;
    const std::uint64_t p = key_moduli[p_index].value();
    const std::uint64_t t = level->parms().plain_modulus().value();
    require(q_count < key_moduli.size() && keys.has_key(2) &&
                keys.key(2).size() >= q_count,
            "BGV KeySwitch requires all active Q digits and one special P");

    std::vector<std::vector<std::uint64_t>> source_coeff(q_count);
    for (std::size_t j = 0; j < q_count; ++j) {
        const auto* limb = product.data(2) + j * degree;
        source_coeff[j].assign(limb, limb + degree);
        seal::util::inverse_ntt_negacyclic_harvey(
            source_coeff[j].data(), level->small_ntt_tables()[j]);
    }

    // Model exactly the singleton-Q digit products; the key's P limb always
    // occupies the last *key-level* modulus slot, even at a lower data level.
    std::vector<std::vector<std::vector<std::uint64_t>>> accumulator(
        2, std::vector<std::vector<std::uint64_t>>(
               q_count + 1, std::vector<std::uint64_t>(degree, 0)));
    for (std::size_t target = 0; target <= q_count; ++target) {
        const std::size_t key_index = target == q_count ? p_index : target;
        const std::uint64_t modulus = key_moduli[key_index].value();
        for (std::size_t digit = 0; digit < q_count; ++digit) {
            std::vector<std::uint64_t> operand(degree);
            if (target == digit) {
                const auto* limb = product.data(2) + digit * degree;
                operand.assign(limb, limb + degree);
            } else {
                for (std::size_t k = 0; k < degree; ++k) {
                    operand[k] = source_coeff[digit][k] % modulus;
                }
                seal::util::ntt_negacyclic_harvey(
                    operand.data(), context.key_context_data()->small_ntt_tables()[key_index]);
            }
            const auto& key_digit = keys.key(2)[digit].data();
            for (std::size_t component = 0; component < 2; ++component) {
                const auto* key_limb = key_digit.data(component) + key_index * degree;
                for (std::size_t k = 0; k < degree; ++k) {
                    accumulator[component][target][k] = add_mod(
                        accumulator[component][target][k],
                        mul_mod(operand[k], key_limb[k], modulus), modulus);
                }
            }
        }
    }

    seal::Ciphertext expected = product;
    evaluator.relinearize_inplace(expected, keys);
    require(expected.size() == 2 && expected.is_ntt_form() &&
                expected.correction_factor() == product.correction_factor(),
            "modified-SEAL BGV relin metadata changed unexpectedly");

    const std::uint64_t inv_p_t = inverse_mod(p, t);
    for (std::size_t component = 0; component < 2; ++component) {
        auto p_coeff = accumulator[component][q_count];
        seal::util::inverse_ntt_negacyclic_harvey(
            p_coeff.data(), context.key_context_data()->small_ntt_tables()[p_index]);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const std::uint64_t qi = moduli[basis].value();
            std::vector<std::uint64_t> correction(degree);
            const std::uint64_t p_mod_q = p % qi;
            const std::uint64_t inv_p_q = inverse_mod(p_mod_q, qi);
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint64_t u = mul_mod(
                    p_coeff[k], (t - inv_p_t) % t, t);
                correction[k] = add_mod(p_coeff[k] % qi,
                                        mul_mod(u, p_mod_q, qi), qi);
            }
            seal::util::ntt_negacyclic_harvey(
                correction.data(), level->small_ntt_tables()[basis]);
            const auto* base = product.data(component) + basis * degree;
            const auto* actual = expected.data(component) + basis * degree;
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint64_t switched = mul_mod(
                    add_mod(accumulator[component][basis][k],
                            qi - correction[k] % qi, qi), inv_p_q, qi);
                if (add_mod(switched, base[k], qi) != actual[k] % qi) {
                    throw std::runtime_error(
                        "BGV NTT KeySwitch formula differs from modified-SEAL relinearization");
                }
            }
        }
    }
}

} // namespace

int main()
{
    try {
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(), "modified-SEAL rejected BGV test context");
        seal::KeyGenerator key_generator(context);
        seal::RelinKeys keys;
        key_generator.create_relin_keys(keys);
        seal::Encryptor encryptor(context, key_generator.secret_key());
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t k = 0; k < slots.size(); ++k) {
            slots[k] = (k * 53 + 7) % 65537;
        }
        seal::Plaintext plain;
        encoder.encode(slots, plain);
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(plain, input);
        seal::Evaluator evaluator(context);
        seal::Ciphertext product;
        evaluator.multiply(input, input, product);
        check_relinearization(context, evaluator, keys, product);
        evaluator.mod_switch_to_next_inplace(product);
        check_relinearization(context, evaluator, keys, product);
        std::cout << "modified-SEAL BGV NTT KeySwitch differential tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "modified-SEAL BGV NTT KeySwitch test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
