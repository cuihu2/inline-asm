#include "hpu/seal/bfv_level.hpp"

#include <seal/util/rns.h>

#include <algorithm>
#include <iterator>
#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(const ::seal::Modulus& modulus, const char* role)
{
    if (modulus.value() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(role);
    }
    return static_cast<std::uint32_t>(modulus.value());
}

std::uint32_t narrow_profile_modulus(
    const ::seal::Modulus& modulus,
    const char* role)
{
    if (modulus.bit_count() > 31) {
        throw std::invalid_argument(role);
    }
    return narrow(modulus, role);
}

int register_modulus(
    std::vector<std::uint32_t>& table,
    std::uint32_t modulus)
{
    const auto found = std::find(table.begin(), table.end(), modulus);
    if (found != table.end()) {
        return static_cast<int>(std::distance(table.begin(), found));
    }
    if (table.size() >= static_cast<std::size_t>(hpu::kMaxModContexts)) {
        throw std::invalid_argument(
            "SEAL BFV Q/P/B/m_sk/t union exceeds the HPU MOD_ID capacity");
    }
    table.push_back(modulus);
    return static_cast<int>(table.size() - 1);
}

struct RawLevel {
    BfvLevelDescriptor descriptor;
};

} // namespace

BfvLevelRegistry create_bfv_level_registry(
    const ::seal::SEALContext& context)
{
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    if (!key_data || !first_data
        || key_data->parms().scheme() != ::seal::scheme_type::bfv) {
        throw std::invalid_argument("SEALContext is not BFV");
    }

    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& first_moduli = first_data->parms().coeff_modulus();
    if (first_moduli.empty() || key_moduli.size() != first_moduli.size() + 1) {
        throw std::invalid_argument(
            "HPU BFV requires exactly one special key modulus");
    }

    BfvLevelRegistry result;
    result.poly_modulus_degree = key_data->parms().poly_modulus_degree();
    for (const ::seal::Modulus& modulus : key_moduli) {
        result.modulus_table.push_back(narrow_profile_modulus(
            modulus,
            "HPU BFV Q/P must be at most 31 bits; 32-bit primes are reserved for B/m_sk"));
    }
    const std::size_t initial_q_count = first_moduli.size();
    const int p_mod_id = static_cast<int>(initial_q_count);
    const std::uint32_t special_modulus = result.modulus_table.back();
    const std::uint32_t plaintext_modulus = narrow_profile_modulus(
        first_data->parms().plain_modulus(),
        "HPU BFV t must be at most 31 bits");

    std::vector<RawLevel> raw_levels;
    for (auto data = first_data; data; data = data->next_context_data()) {
        const auto& active_q = data->parms().coeff_modulus();
        const auto* rns_tool = data->rns_tool();
        if (!rns_tool || !rns_tool->base_B() || rns_tool->m_sk().is_zero()) {
            throw std::logic_error("SEAL BFV level has no BEHZ auxiliary base");
        }

        RawLevel raw;
        auto& level = raw.descriptor;
        level.parms_id = data->parms_id();
        level.chain_index = data->chain_index();
        level.special_modulus = special_modulus;
        level.plaintext_modulus = plaintext_modulus;
        level.keyswitch_layout.p_mod_ids = {p_mod_id};
        for (std::size_t index = 0; index < active_q.size(); ++index) {
            if (active_q[index].value() != key_moduli[index].value()) {
                throw std::logic_error(
                    "SEAL BFV level Q is not a key-context prefix");
            }
            level.q_moduli.push_back(narrow_profile_modulus(
                active_q[index], "HPU BFV active Q must be at most 31 bits"));
            level.keyswitch_layout.q_mod_ids.push_back(
                static_cast<int>(index));
            level.keyswitch_layout.key_digits.push_back(
                {static_cast<int>(index)});
            level.evaluation_key_digit_indices.push_back(index);
        }
        level.q_last = level.q_moduli.back();

        const auto* base_b = rns_tool->base_B();
        level.b_moduli.reserve(base_b->size());
        for (std::size_t index = 0; index < base_b->size(); ++index) {
            level.b_moduli.push_back(narrow(
                (*base_b)[index],
                "modified-SEAL BFV B modulus exceeds the HPU uint32 ABI"));
        }
        level.m_sk = narrow(
            rns_tool->m_sk(),
            "modified-SEAL BFV m_sk exceeds the HPU uint32 ABI");
        for (std::uint32_t modulus : level.b_moduli) {
            if (std::find(result.modulus_table.begin(),
                          result.modulus_table.end(), modulus)
                    != result.modulus_table.end()
                || modulus == plaintext_modulus) {
                throw std::logic_error(
                    "modified-SEAL BFV B collides with Q/P/t");
            }
        }
        if (std::find(result.modulus_table.begin(),
                      result.modulus_table.end(), level.m_sk)
                != result.modulus_table.end()
            || level.m_sk == plaintext_modulus
            || std::find(level.b_moduli.begin(), level.b_moduli.end(), level.m_sk)
                != level.b_moduli.end()) {
            throw std::logic_error(
                "modified-SEAL BFV m_sk collides with Q/P/B/t");
        }
        raw_levels.push_back(std::move(raw));
    }

    // Qmax|P remains the fixed prefix. Append the union of all SEAL-selected
    // auxiliary bases, sharing equal values between levels, and put t last.
    for (const RawLevel& raw : raw_levels) {
        for (std::uint32_t modulus : raw.descriptor.b_moduli) {
            (void)register_modulus(result.modulus_table, modulus);
        }
        (void)register_modulus(result.modulus_table, raw.descriptor.m_sk);
    }
    const int plaintext_mod_id = register_modulus(
        result.modulus_table, plaintext_modulus);

    for (RawLevel& raw : raw_levels) {
        auto& level = raw.descriptor;
        for (std::uint32_t modulus : level.b_moduli) {
            level.b_mod_ids.push_back(register_modulus(
                result.modulus_table, modulus));
        }
        level.m_sk_mod_id = register_modulus(
            result.modulus_table, level.m_sk);
        level.plaintext_mod_id = plaintext_mod_id;
        if (!hpu::is_seal_single_p_rns_decomposition_layout(
                static_cast<int>(result.poly_modulus_degree),
                level.keyswitch_layout)) {
            throw std::logic_error(
                "SEAL BFV level produced an invalid HPU KeySwitch layout");
        }
        result.levels.push_back(std::move(level));
    }
    return result;
}

BfvLevelChain::BfvLevelChain(const ::seal::SEALContext& context)
    : registry_(create_bfv_level_registry(context))
{}

const BfvLevelRegistry& BfvLevelChain::registry() const noexcept
{
    return registry_;
}

std::size_t BfvLevelChain::size() const noexcept
{
    return registry_.levels.size();
}

const std::vector<BfvLevelDescriptor>& BfvLevelChain::levels() const noexcept
{
    return registry_.levels;
}

const BfvLevelDescriptor& BfvLevelChain::top() const noexcept
{
    return registry_.levels.front();
}

const BfvLevelDescriptor& BfvLevelChain::bottom() const noexcept
{
    return registry_.levels.back();
}

const BfvLevelDescriptor& BfvLevelChain::at(std::size_t ordinal) const
{
    return registry_.levels.at(ordinal);
}

std::size_t BfvLevelChain::ordinal(
    const ::seal::parms_id_type& parms_id) const
{
    const auto found = std::find_if(
        registry_.levels.begin(), registry_.levels.end(),
        [&](const BfvLevelDescriptor& level) {
            return level.parms_id == parms_id;
        });
    if (found == registry_.levels.end()) {
        throw std::invalid_argument("parms_id is not a BFV data level");
    }
    return static_cast<std::size_t>(
        std::distance(registry_.levels.begin(), found));
}

const BfvLevelDescriptor& BfvLevelChain::require(
    const ::seal::parms_id_type& parms_id) const
{
    return registry_.levels[ordinal(parms_id)];
}

bool BfvLevelChain::has_next(
    const ::seal::parms_id_type& parms_id) const
{
    return ordinal(parms_id) + 1 < registry_.levels.size();
}

const BfvLevelDescriptor& BfvLevelChain::next(
    const ::seal::parms_id_type& parms_id) const
{
    const std::size_t source = ordinal(parms_id);
    if (source + 1 >= registry_.levels.size()) {
        throw std::invalid_argument("BFV level has no next data level");
    }
    return registry_.levels[source + 1];
}

} // namespace hpu::seal_adapter
