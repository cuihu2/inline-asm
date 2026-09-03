#include "hpu/seal/ckks_level.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(const ::seal::Modulus& modulus)
{
    if (modulus.value() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("SEAL modulus exceeds the HPU uint32 ABI");
    }
    return static_cast<std::uint32_t>(modulus.value());
}

} // namespace

std::vector<CkksLevelDescriptor> create_ckks_level_descriptors(
    const ::seal::SEALContext& context)
{
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    if (!key_data || !first_data) {
        throw std::invalid_argument("SEALContext has no CKKS key/data chain");
    }
    if (key_data->parms().scheme() != ::seal::scheme_type::ckks) {
        throw std::invalid_argument("SEALContext is not CKKS");
    }
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& first_moduli = first_data->parms().coeff_modulus();
    if (first_moduli.empty() || first_moduli.size() >= key_moduli.size()) {
        throw std::invalid_argument("SEALContext has no special key modulus");
    }
    const std::size_t initial_q_count = first_moduli.size();
    const std::size_t special_count = key_moduli.size() - initial_q_count;
    if (key_moduli.size() > static_cast<std::size_t>(hpu::kMaxModContexts)) {
        throw std::invalid_argument("SEAL key context exceeds HPU MOD_ID capacity");
    }
    for (std::size_t index = 0; index < initial_q_count; ++index) {
        if (key_moduli[index].value() != first_moduli[index].value()) {
            throw std::invalid_argument("SEAL data Q is not a key-context prefix");
        }
    }

    std::vector<std::uint32_t> special_moduli;
    std::vector<int> p_mod_ids;
    for (std::size_t index = 0; index < special_count; ++index) {
        special_moduli.push_back(narrow(key_moduli[initial_q_count + index]));
        p_mod_ids.push_back(static_cast<int>(initial_q_count + index));
    }

    std::vector<CkksLevelDescriptor> result;
    for (auto data = first_data; data; data = data->next_context_data()) {
        const auto& active_moduli = data->parms().coeff_modulus();
        if (active_moduli.empty() || active_moduli.size() > initial_q_count) {
            throw std::logic_error("invalid SEAL CKKS data-context width");
        }

        CkksLevelDescriptor level;
        level.parms_id = data->parms_id();
        level.chain_index = data->chain_index();
        level.special_moduli = special_moduli;
        level.rns_layout.p_mod_ids = p_mod_ids;
        for (std::size_t index = 0; index < active_moduli.size(); ++index) {
            if (active_moduli[index].value() != key_moduli[index].value()) {
                throw std::logic_error("SEAL level Q is not a key-context prefix");
            }
            level.q_moduli.push_back(narrow(active_moduli[index]));
            level.rns_layout.q_mod_ids.push_back(static_cast<int>(index));
            level.rns_layout.key_digits.push_back(
                {static_cast<int>(index)});
            level.evaluation_key_digit_indices.push_back(index);
        }
        level.q_last = level.q_moduli.back();
        if (!hpu::is_valid_rns_decomposition_layout(
                static_cast<int>(data->parms().poly_modulus_degree()),
                level.rns_layout)) {
            throw std::logic_error("SEAL level produced an invalid HPU RNS layout");
        }
        result.push_back(std::move(level));
    }
    return result;
}

} // namespace hpu::seal_adapter
