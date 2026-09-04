#include "scheme/bfv/encode.hpp"

#include "scheme/detail/integer_encode.hpp"

namespace hpu::scheme::bfv {

std::vector<std::uint64_t> encode_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::encode_integer_coefficients(
        signed_coefficients, N, plaintext_modulus, "BFV");
}

std::vector<std::int64_t> decode_coefficients(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::decode_integer_coefficients(
        coefficients, plaintext_modulus, "BFV");
}

std::vector<std::uint64_t> encode_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::encode_integer_slots(
        slots, N, plaintext_modulus, "BFV");
}

std::vector<std::int64_t> decode_slots(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::decode_integer_slots(
        coefficients, plaintext_modulus, "BFV");
}

} // namespace hpu::scheme::bfv
