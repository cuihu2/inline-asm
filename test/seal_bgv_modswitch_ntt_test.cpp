#include "hpu/model/hardware_ntt.hpp"
#include "scheme/bgv/modswitch.hpp"

#include <seal/seal.h>
#include <seal/util/ntt.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::uint32_t narrow(std::uint64_t value)
{
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("SEAL BGV modulus exceeds HPU uint32 range");
    }
    return static_cast<std::uint32_t>(value);
}

void check_one_level(const seal::SEALContext& context, seal::Evaluator& evaluator,
                     const seal::Ciphertext& input)
{
    const auto source = context.get_context_data(input.parms_id());
    require(source && source->next_context_data(), "BGV source has no lower level");
    const auto& source_moduli = source->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = source_moduli.size();
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    std::vector<std::uint32_t> q;
    for (const auto& modulus : source_moduli) {
        q.push_back(narrow(modulus.value()));
    }
    const auto constants = hpu::scheme::bgv::prepare_ntt_modswitch_constants(q, t);

    seal::Ciphertext expected = input;
    evaluator.mod_switch_to_next_inplace(expected);
    require(expected.is_ntt_form() && expected.size() == input.size() &&
                expected.parms_id() == source->next_context_data()->parms_id(),
            "modified-SEAL BGV ModSwitch output has the wrong representation");
    require(expected.correction_factor()
                == hpu::scheme::bgv::modswitch_correction_factor(
                    input.correction_factor(), q.back(), t),
            "BGV ModSwitch correction-factor metadata differs from SEAL");

    const auto* tables = source->small_ntt_tables();
    for (std::size_t component = 0; component < input.size(); ++component) {
        const std::uint64_t* input_words = input.data(component);
        const std::uint64_t* expected_words = expected.data(component);
        std::vector<std::uint64_t> c_last(
            input_words + (q_count - 1) * degree,
            input_words + q_count * degree);
        seal::util::inverse_ntt_negacyclic_harvey(c_last.data(), tables[q_count - 1]);

        for (std::size_t basis = 0; basis + 1 < q_count; ++basis) {
            const std::uint32_t qi = q[basis];
            std::vector<std::uint64_t> delta(degree);
            std::vector<std::uint32_t> delta_coefficients(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint64_t u =
                    (c_last[index] * constants.neg_q_last_inverse_mod_t) % t;
                delta[index] = ((c_last[index] % qi) +
                                (u * constants.q_last_mod_q[basis]) % qi) % qi;
                delta_coefficients[index] = static_cast<std::uint32_t>(delta[index]);
            }
            seal::util::ntt_negacyclic_harvey(delta.data(), tables[basis]);

            std::vector<std::uint64_t> input_coefficients(
                input_words + basis * degree,
                input_words + (basis + 1) * degree);
            std::vector<std::uint64_t> expected_coefficients(
                expected_words + basis * degree,
                expected_words + (basis + 1) * degree);
            seal::util::inverse_ntt_negacyclic_harvey(
                input_coefficients.data(), tables[basis]);
            seal::util::inverse_ntt_negacyclic_harvey(
                expected_coefficients.data(), tables[basis]);
            std::vector<std::uint32_t> input_coefficients_u32(degree);
            std::vector<std::uint32_t> expected_coefficients_u32(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                input_coefficients_u32[index] = narrow(input_coefficients[index]);
                expected_coefficients_u32[index] = narrow(expected_coefficients[index]);
            }
            const std::uint32_t psi = narrow(tables[basis].get_root());
            const auto input_hpu_ntt = hpu::model::negacyclic_forward(
                input_coefficients_u32, qi, psi);
            const auto delta_hpu_ntt = hpu::model::negacyclic_forward(
                delta_coefficients, qi, psi);
            const auto expected_hpu_ntt = hpu::model::negacyclic_forward(
                expected_coefficients_u32, qi, psi);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint64_t c_i = input_words[basis * degree + index] % qi;
                const std::uint64_t result =
                    (((c_i + qi - delta[index]) % qi) *
                     constants.q_last_inverse_mod_q[basis]) % qi;
                if (result != expected_words[basis * degree + index] % qi) {
                    throw std::runtime_error(
                        "BGV NTT ModSwitch formula differs from modified-SEAL limb");
                }
                const std::uint64_t hpu_result =
                    (((static_cast<std::uint64_t>(input_hpu_ntt[index]) + qi -
                       delta_hpu_ntt[index]) % qi) *
                     constants.q_last_inverse_mod_q[basis]) % qi;
                if (hpu_result != expected_hpu_ntt[index]) {
                    throw std::runtime_error(
                        "BGV ModSwitch differs in canonical HPU NTT physical layout");
                }
            }
        }
    }
}

} // namespace

int main()
{
    try {
        constexpr std::size_t degree = 128;
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(degree);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set() && context.first_context_data() &&
                    context.first_context_data()->next_context_data(),
                "modified-SEAL rejected the BGV ModSwitch test context");

        seal::KeyGenerator key_generator(context);
        seal::Encryptor encryptor(context, key_generator.secret_key());
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t index = 0; index < slots.size(); ++index) {
            slots[index] = (index * 71 + 5) % 65537;
        }
        seal::Plaintext plain;
        encoder.encode(slots, plain);
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(plain, input);
        require(input.is_ntt_form(), "modified-SEAL BGV ciphertext is not NTT form");
        seal::Evaluator evaluator(context);

        check_one_level(context, evaluator, input);
        evaluator.mod_switch_to_next_inplace(input);
        check_one_level(context, evaluator, input);
        std::cout << "modified-SEAL BGV NTT ModSwitch differential tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "modified-SEAL BGV NTT ModSwitch test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
