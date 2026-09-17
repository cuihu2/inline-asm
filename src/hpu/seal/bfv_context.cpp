#include "hpu/seal/bfv_context.hpp"

#include <seal/seal.h>

#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace hpu::seal_adapter {
namespace {

bool is_power_of_two(std::size_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

std::uint32_t narrow(const ::seal::Modulus& modulus, const char* role)
{
    if (modulus.value() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::logic_error(role);
    }
    return static_cast<std::uint32_t>(modulus.value());
}

} // namespace

BfvContextBundle create_bfv_context(const BfvContextSpec& spec)
{
    if (!is_power_of_two(spec.poly_modulus_degree)
        || spec.poly_modulus_degree < 128
        || spec.poly_modulus_degree > 65536) {
        throw std::invalid_argument(
            "HPU BFV N must be a power of two in [128, 65536]");
    }
    if (spec.coeff_modulus_bits.size() < 2) {
        throw std::invalid_argument(
            "HPU BFV needs at least one data modulus and one special modulus");
    }
    for (int bits : spec.coeff_modulus_bits) {
        if (bits < 2 || bits > 31) {
            throw std::invalid_argument(
                "HPU BFV Q/P moduli must be at most 31 bits; 32-bit primes are reserved for B/m_sk");
        }
    }
    if (spec.plain_modulus_bits < 2 || spec.plain_modulus_bits > 31) {
        throw std::invalid_argument(
            "HPU BFV plaintext modulus must fit the 31-bit prepared-plaintext ABI");
    }

    ::seal::EncryptionParameters parameters(::seal::scheme_type::bfv);
    parameters.set_poly_modulus_degree(spec.poly_modulus_degree);
    parameters.set_coeff_modulus(::seal::CoeffModulus::Create(
        spec.poly_modulus_degree, spec.coeff_modulus_bits));
    parameters.set_plain_modulus(::seal::PlainModulus::Batching(
        spec.poly_modulus_degree, spec.plain_modulus_bits));

    auto context = std::make_shared<::seal::SEALContext>(
        std::move(parameters), true, ::seal::sec_level_type::none);
    if (!context->parameters_set()) {
        throw std::invalid_argument(
            std::string("SEAL rejected the HPU BFV parameters: ")
            + context->parameter_error_message());
    }

    const auto key_data = context->key_context_data();
    const auto first_data = context->first_context_data();
    if (!key_data || !first_data) {
        throw std::logic_error(
            "SEALContext did not create BFV key/data context nodes");
    }
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& data_moduli = first_data->parms().coeff_modulus();
    if (key_moduli.size() != data_moduli.size() + 1) {
        throw std::logic_error(
            "HPU BFV requires exactly one SEAL special key modulus");
    }

    BfvContextBundle result;
    result.context = std::move(context);
    result.data_moduli.reserve(data_moduli.size());
    for (std::size_t index = 0; index < data_moduli.size(); ++index) {
        if (data_moduli[index].value() != key_moduli[index].value()) {
            throw std::logic_error(
                "SEAL BFV data Q is not a key-context prefix");
        }
        result.data_moduli.push_back(narrow(
            data_moduli[index], "SEAL BFV Q exceeds the HPU uint32 ABI"));
    }
    result.special_modulus = narrow(
        key_moduli.back(), "SEAL BFV P exceeds the HPU uint32 ABI");
    result.plain_modulus = narrow(
        first_data->parms().plain_modulus(),
        "SEAL BFV t exceeds the HPU uint32 ABI");
    if (!first_data->qualifiers().using_batching) {
        throw std::logic_error("SEAL BFV context does not support batching");
    }
    return result;
}

} // namespace hpu::seal_adapter
