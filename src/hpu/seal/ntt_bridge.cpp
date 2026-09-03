#include "hpu/seal/ntt_bridge.hpp"

#include "hpu/model/hardware_ntt.hpp"

#include <seal/util/ntt.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace hpu::seal_adapter {
namespace {

std::shared_ptr<const ::seal::SEALContext::ContextData> require_context_data(
    ::seal::parms_id_type parms_id,
    const ::seal::SEALContext& context)
{
    auto data = context.get_context_data(parms_id);
    if (!data) {
        throw std::invalid_argument("parms_id is not present in SEALContext");
    }
    return data;
}

std::uint32_t narrow(std::uint64_t value, const char* role)
{
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(std::string(role) + " exceeds the HPU uint32 ABI");
    }
    return static_cast<std::uint32_t>(value);
}

} // namespace

HpuRnsPolynomial ciphertext_component_to_hpu(
    const ::seal::Ciphertext& ciphertext,
    std::size_t component,
    const ::seal::SEALContext& context)
{
    if (!ciphertext.is_ntt_form()) {
        throw std::invalid_argument("CKKS ciphertext must be in SEAL NTT form");
    }
    if (component >= ciphertext.size()) {
        throw std::out_of_range("ciphertext component is out of range");
    }
    const auto context_data = require_context_data(ciphertext.parms_id(), context);
    const auto& parameters = context_data->parms();
    const std::size_t degree = parameters.poly_modulus_degree();
    const auto& moduli = parameters.coeff_modulus();
    if (degree > 65536 || ciphertext.poly_modulus_degree() != degree
        || ciphertext.coeff_modulus_size() != moduli.size()) {
        throw std::invalid_argument("ciphertext shape is incompatible with the HPU/SEAL context");
    }

    HpuRnsPolynomial result;
    result.degree = degree;
    result.moduli.reserve(moduli.size());
    result.words.reserve(degree * moduli.size());
    const std::uint64_t* component_data = ciphertext.data(component);
    const ::seal::util::NTTTables* seal_tables = context_data->small_ntt_tables();

    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const std::uint32_t modulus = narrow(moduli[basis].value(), "SEAL modulus");
        const std::uint32_t psi = narrow(seal_tables[basis].get_root(), "SEAL NTT root");
        result.moduli.push_back(modulus);

        std::vector<std::uint64_t> coefficients(
            component_data + basis * degree,
            component_data + (basis + 1) * degree);
        ::seal::util::inverse_ntt_negacyclic_harvey(
            coefficients.data(), seal_tables[basis]);

        std::vector<std::uint32_t> coefficient_words(degree);
        for (std::size_t index = 0; index < degree; ++index) {
            coefficient_words[index] = narrow(coefficients[index], "SEAL coefficient");
        }
        const auto physical = hpu::model::negacyclic_forward(
            coefficient_words, modulus, psi);
        result.words.insert(result.words.end(), physical.begin(), physical.end());
    }
    return result;
}

std::vector<std::uint64_t> hpu_to_seal_ntt(
    const HpuRnsPolynomial& polynomial,
    ::seal::parms_id_type parms_id,
    const ::seal::SEALContext& context)
{
    const auto context_data = require_context_data(parms_id, context);
    const auto& parameters = context_data->parms();
    const std::size_t degree = parameters.poly_modulus_degree();
    const auto& moduli = parameters.coeff_modulus();
    if (polynomial.degree != degree || polynomial.moduli.size() != moduli.size()
        || polynomial.words.size() != degree * moduli.size()) {
        throw std::invalid_argument("HPU RNS polynomial shape does not match parms_id");
    }

    std::vector<std::uint64_t> result(polynomial.words.size());
    const ::seal::util::NTTTables* seal_tables = context_data->small_ntt_tables();
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const std::uint32_t modulus = narrow(moduli[basis].value(), "SEAL modulus");
        if (polynomial.moduli[basis] != modulus) {
            throw std::invalid_argument("HPU modulus order does not match SEALContext");
        }
        const std::uint32_t psi = narrow(seal_tables[basis].get_root(), "SEAL NTT root");
        const auto first = polynomial.words.begin()
            + static_cast<std::ptrdiff_t>(basis * degree);
        const std::vector<std::uint32_t> physical(first, first + degree);
        const auto coefficients = hpu::model::negacyclic_inverse(
            physical, modulus, psi);

        std::uint64_t* destination = result.data() + basis * degree;
        std::copy(coefficients.begin(), coefficients.end(), destination);
        ::seal::util::ntt_negacyclic_harvey(destination, seal_tables[basis]);
    }
    return result;
}

} // namespace hpu::seal_adapter
