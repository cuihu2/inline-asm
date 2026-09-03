#include "hpu/seal/ckks_context.hpp"

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

std::vector<std::uint32_t> narrow_moduli(const std::vector<::seal::Modulus>& moduli)
{
    std::vector<std::uint32_t> result;
    result.reserve(moduli.size());
    for (const ::seal::Modulus& modulus : moduli) {
        if (modulus.value() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::logic_error("SEALContext produced a modulus wider than the HPU 32-bit ABI");
        }
        result.push_back(static_cast<std::uint32_t>(modulus.value()));
    }
    return result;
}

} // namespace

CkksContextBundle create_ckks_context(const CkksContextSpec& spec)
{
    if (!is_power_of_two(spec.poly_modulus_degree)
        || spec.poly_modulus_degree < 128
        || spec.poly_modulus_degree > 65536) {
        throw std::invalid_argument("HPU CKKS N must be a power of two in [128, 65536]");
    }
    if (spec.coeff_modulus_bits.size() < 2) {
        throw std::invalid_argument("CKKS needs at least one data and one special modulus");
    }
    for (int bits : spec.coeff_modulus_bits) {
        if (bits < 2 || bits > 32) {
            throw std::invalid_argument("every CKKS q/P modulus must be at most 32 bits");
        }
    }

    ::seal::EncryptionParameters parameters(::seal::scheme_type::ckks);
    parameters.set_poly_modulus_degree(spec.poly_modulus_degree);
    parameters.set_coeff_modulus(::seal::CoeffModulus::Create(
        spec.poly_modulus_degree, spec.coeff_modulus_bits));

    auto context = std::make_shared<::seal::SEALContext>(
        std::move(parameters), true, ::seal::sec_level_type::none);
    if (!context->parameters_set()) {
        throw std::invalid_argument(
            std::string("SEAL rejected the HPU CKKS parameters: ")
            + context->parameter_error_message());
    }

    const auto key_data = context->key_context_data();
    const auto first_data = context->first_context_data();
    if (!key_data || !first_data) {
        throw std::logic_error("SEALContext did not create key/data context nodes");
    }
    const auto key_moduli = narrow_moduli(key_data->parms().coeff_modulus());
    const auto data_moduli = narrow_moduli(first_data->parms().coeff_modulus());
    if (data_moduli.empty() || data_moduli.size() >= key_moduli.size()) {
        throw std::logic_error("SEALContext did not expose a special key modulus");
    }
    for (std::size_t index = 0; index < data_moduli.size(); ++index) {
        if (data_moduli[index] != key_moduli[index]) {
            throw std::logic_error("SEAL key/data modulus chains are not prefix-compatible");
        }
    }

    CkksContextBundle result;
    result.context = std::move(context);
    result.data_moduli = data_moduli;
    result.special_moduli.assign(
        key_moduli.begin() + static_cast<std::ptrdiff_t>(data_moduli.size()),
        key_moduli.end());
    return result;
}

} // namespace hpu::seal_adapter
