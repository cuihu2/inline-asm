#include "hpu/seal/evaluation_key.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::vector<HpuKeySwitchDigit> key_digits_to_hpu(
    const std::vector<::seal::PublicKey>& seal_digits,
    ::seal::parms_id_type key_parms_id,
    const ::seal::SEALContext& context,
    const char* role)
{
    std::vector<HpuKeySwitchDigit> result;
    result.reserve(seal_digits.size());
    for (const ::seal::PublicKey& public_key : seal_digits) {
        const ::seal::Ciphertext& ciphertext = public_key.data();
        if (!ciphertext.is_ntt_form() || ciphertext.size() != 2
            || ciphertext.parms_id() != key_parms_id) {
            throw std::invalid_argument(std::string(role) + " digit has an invalid shape");
        }
        HpuKeySwitchDigit digit;
        digit.key_component_0 = ciphertext_component_to_hpu(ciphertext, 0, context);
        digit.key_component_1 = ciphertext_component_to_hpu(ciphertext, 1, context);
        result.push_back(std::move(digit));
    }
    return result;
}

std::vector<HpuKeySwitchDigit> key_digits_to_hpu(
    const std::vector<::seal::PublicKey>& seal_digits,
    ::seal::parms_id_type key_parms_id,
    const ::seal::SEALContext& context,
    ::seal::parms_id_type data_parms_id,
    const std::vector<std::size_t>& evaluation_key_digit_indices,
    const std::vector<int>& q_mod_ids,
    const std::vector<int>& p_mod_ids,
    const char* role)
{
    if (!context.get_context_data(data_parms_id)
        || evaluation_key_digit_indices.empty()) {
        throw std::invalid_argument(std::string(role) + " level is not in SEALContext");
    }
    std::vector<std::size_t> modulus_indices;
    for (int id : q_mod_ids) {
        modulus_indices.push_back(static_cast<std::size_t>(id));
    }
    for (int id : p_mod_ids) {
        modulus_indices.push_back(static_cast<std::size_t>(id));
    }

    std::vector<HpuKeySwitchDigit> result;
    result.reserve(evaluation_key_digit_indices.size());
    for (std::size_t digit_index : evaluation_key_digit_indices) {
        if (digit_index >= seal_digits.size()) {
            throw std::invalid_argument(std::string(role) + " lacks an active level digit");
        }
        const ::seal::Ciphertext& ciphertext = seal_digits[digit_index].data();
        if (!ciphertext.is_ntt_form() || ciphertext.size() != 2
            || ciphertext.parms_id() != key_parms_id) {
            throw std::invalid_argument(std::string(role) + " digit has an invalid shape");
        }
        HpuKeySwitchDigit digit;
        digit.key_component_0 = ciphertext_component_to_hpu(
            ciphertext, 0, context, modulus_indices);
        digit.key_component_1 = ciphertext_component_to_hpu(
            ciphertext, 1, context, modulus_indices);
        result.push_back(std::move(digit));
    }
    return result;
}

} // namespace

std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(
    const ::seal::RelinKeys& keys,
    const ::seal::SEALContext& context)
{
    if (!keys.has_key(2)) {
        throw std::invalid_argument("SEAL RelinKeys does not contain the s^2 key");
    }
    return key_digits_to_hpu(
        keys.key(2), keys.parms_id(), context, "SEAL relinearization-key");
}

std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(
    const ::seal::RelinKeys& keys,
    const ::seal::SEALContext& context,
    const CkksLevelDescriptor& level)
{
    if (!keys.has_key(2)) {
        throw std::invalid_argument("SEAL RelinKeys does not contain the s^2 key");
    }
    return key_digits_to_hpu(
        keys.key(2), keys.parms_id(), context, level.parms_id,
        level.evaluation_key_digit_indices,
        level.rns_layout.q_mod_ids, level.rns_layout.p_mod_ids,
        "SEAL level relinearization-key");
}

std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(
    const ::seal::RelinKeys& keys,
    const ::seal::SEALContext& context,
    const BfvLevelDescriptor& level)
{
    if (!keys.has_key(2)) {
        throw std::invalid_argument("SEAL RelinKeys does not contain the s^2 key");
    }
    return key_digits_to_hpu(
        keys.key(2), keys.parms_id(), context, level.parms_id,
        level.evaluation_key_digit_indices,
        level.keyswitch_layout.q_mod_ids,
        level.keyswitch_layout.p_mod_ids,
        "SEAL BFV level relinearization-key");
}

std::vector<HpuKeySwitchDigit> galois_key_to_hpu(
    const ::seal::GaloisKeys& keys,
    std::uint32_t galois_element,
    const ::seal::SEALContext& context)
{
    if (!keys.has_key(galois_element)) {
        throw std::invalid_argument("SEAL GaloisKeys does not contain the requested element");
    }
    return key_digits_to_hpu(
        keys.key(galois_element),
        keys.parms_id(),
        context,
        "SEAL Galois-key");
}

std::vector<HpuKeySwitchDigit> galois_key_to_hpu(
    const ::seal::GaloisKeys& keys,
    std::uint32_t galois_element,
    const ::seal::SEALContext& context,
    const CkksLevelDescriptor& level)
{
    if (!keys.has_key(galois_element)) {
        throw std::invalid_argument("SEAL GaloisKeys does not contain the requested element");
    }
    return key_digits_to_hpu(
        keys.key(galois_element), keys.parms_id(), context, level.parms_id,
        level.evaluation_key_digit_indices,
        level.rns_layout.q_mod_ids, level.rns_layout.p_mod_ids,
        "SEAL level Galois-key");
}

std::vector<HpuKeySwitchDigit> galois_key_to_hpu(
    const ::seal::GaloisKeys& keys,
    std::uint32_t galois_element,
    const ::seal::SEALContext& context,
    const BfvLevelDescriptor& level)
{
    if (!keys.has_key(galois_element)) {
        throw std::invalid_argument("SEAL GaloisKeys does not contain the requested element");
    }
    return key_digits_to_hpu(
        keys.key(galois_element), keys.parms_id(), context, level.parms_id,
        level.evaluation_key_digit_indices, level.keyswitch_layout.q_mod_ids,
        level.keyswitch_layout.p_mod_ids, "SEAL BFV level Galois-key");
}

} // namespace hpu::seal_adapter
