#include "hpu/seal/automorphism.hpp"

#include "hpu/model/hardware_ntt.hpp"

#include <seal/util/ntt.h>

#include <limits>
#include <numeric>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint64_t inverse_mod_power_of_two(
    std::uint64_t value,
    std::uint64_t modulus)
{
    if ((value & 1U) == 0 || modulus == 0 || (modulus & (modulus - 1)) != 0) {
        throw std::invalid_argument("Galois element must be odd modulo 2N");
    }
    // Newton iteration doubles the number of correct low bits each step.
    std::uint64_t inverse = value;
    for (int iteration = 0; iteration < 7; ++iteration) {
        inverse *= 2 - value * inverse;
    }
    return inverse & (modulus - 1);
}

std::size_t bit_reverse(std::size_t value, std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t width = degree; width > 1; width >>= 1U) {
        result = (result << 1U) | (value & 1U);
        value >>= 1U;
    }
    return result;
}

std::uint32_t narrow(std::uint64_t value, const char* role)
{
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(role);
    }
    return static_cast<std::uint32_t>(value);
}

std::uint32_t multiply_mod(
    std::uint32_t left,
    std::uint32_t right,
    std::uint32_t modulus)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % modulus);
}

} // namespace

std::vector<FusedInverseAutomorphismTables>
create_fused_inverse_automorphism_tables(
    ::seal::parms_id_type parms_id,
    std::uint32_t galois_element,
    const ::seal::SEALContext& context)
{
    const auto context_data = context.get_context_data(parms_id);
    if (!context_data) {
        throw std::invalid_argument("parms_id is not present in SEALContext");
    }
    const std::size_t degree = context_data->parms().poly_modulus_degree();
    const std::uint64_t ring_order = 2 * degree;
    if (degree < 128 || degree > 65536
        || (degree & (degree - 1)) != 0
        || galois_element >= ring_order
        || std::gcd<std::uint64_t>(galois_element, ring_order) != 1) {
        throw std::invalid_argument("invalid HPU fused-automorphism parameters");
    }

    const std::uint64_t inverse_galois =
        inverse_mod_power_of_two(galois_element, ring_order);
    const auto& moduli = context_data->parms().coeff_modulus();
    const ::seal::util::NTTTables* seal_tables = context_data->small_ntt_tables();
    std::vector<FusedInverseAutomorphismTables> result;
    result.reserve(moduli.size());

    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        FusedInverseAutomorphismTables tables;
        tables.modulus = narrow(moduli[basis].value(), "SEAL modulus exceeds uint32");
        tables.canonical_psi = narrow(
            seal_tables[basis].get_root(), "SEAL NTT root exceeds uint32");
        tables.modified_psi = hpu::model::pow_mod(
            tables.canonical_psi, inverse_galois, tables.modulus);

        hpu::model::HardwareNttModel model(
            degree,
            tables.modulus,
            hpu::model::pow_mod(tables.modified_psi, 2, tables.modulus));
        auto inverse_tables = model.inverse_twiddles();
        tables.stages = std::move(inverse_tables.stages);
        tables.post_untwist_scale.resize(degree);
        const std::uint32_t inverse_modified_psi =
            hpu::model::inverse_mod_prime(tables.modified_psi, tables.modulus);
        for (std::size_t position = 0; position < degree; ++position) {
            const std::uint32_t untwist = hpu::model::pow_mod(
                inverse_modified_psi,
                bit_reverse(position, degree),
                tables.modulus);
            tables.post_untwist_scale[position] = multiply_mod(
                inverse_tables.post_scale[position], untwist, tables.modulus);
        }
        result.push_back(std::move(tables));
    }
    return result;
}

} // namespace hpu::seal_adapter
