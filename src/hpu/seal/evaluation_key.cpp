#include "hpu/seal/evaluation_key.hpp"

#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {

std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(
    const ::seal::RelinKeys& keys,
    const ::seal::SEALContext& context)
{
    if (!keys.has_key(2)) {
        throw std::invalid_argument("SEAL RelinKeys does not contain the s^2 key");
    }
    const auto& seal_digits = keys.key(2);
    std::vector<HpuKeySwitchDigit> result;
    result.reserve(seal_digits.size());
    for (const ::seal::PublicKey& public_key : seal_digits) {
        const ::seal::Ciphertext& ciphertext = public_key.data();
        if (!ciphertext.is_ntt_form() || ciphertext.size() != 2
            || ciphertext.parms_id() != keys.parms_id()) {
            throw std::invalid_argument("SEAL relinearization-key digit has an invalid shape");
        }
        HpuKeySwitchDigit digit;
        digit.key_component_0 = ciphertext_component_to_hpu(ciphertext, 0, context);
        digit.key_component_1 = ciphertext_component_to_hpu(ciphertext, 1, context);
        result.push_back(std::move(digit));
    }
    return result;
}

} // namespace hpu::seal_adapter
