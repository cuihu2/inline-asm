#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::scheme::bfv {

// Host-only codec aligned with the SEAL generator-3 BatchEncoder layout.

std::vector<std::uint64_t> encode_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    std::uint64_t plaintext_modulus);

std::vector<std::int64_t> decode_coefficients(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus);

std::vector<std::uint64_t> encode_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    std::uint64_t plaintext_modulus);

std::vector<std::int64_t> decode_slots(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus);

} // namespace hpu::scheme::bfv
