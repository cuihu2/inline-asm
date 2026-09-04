#ifndef HPU_SCHEME_DETAIL_INTEGER_ENCODE_HPP
#define HPU_SCHEME_DETAIL_INTEGER_ENCODE_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::scheme::detail {

std::vector<std::uint64_t> encode_integer_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    std::uint64_t plaintext_modulus,
    const char* scheme_name);

std::vector<std::int64_t> decode_integer_coefficients(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus,
    const char* scheme_name);

std::vector<std::uint64_t> encode_integer_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    std::uint64_t plaintext_modulus,
    const char* scheme_name);

std::vector<std::int64_t> decode_integer_slots(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus,
    const char* scheme_name);

} // namespace hpu::scheme::detail

#endif // HPU_SCHEME_DETAIL_INTEGER_ENCODE_HPP
