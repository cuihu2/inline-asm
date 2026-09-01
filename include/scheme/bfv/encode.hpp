#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::scheme::bfv {

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

std::string generate_encode_body_asm(
    int N,
    int num_q,
    std::uint64_t plaintext_modulus,
    bool append_psync = false);

std::string generate_encode_asm(
    int N,
    int num_q,
    std::uint64_t plaintext_modulus,
    bool append_psync = true);

} // namespace hpu::scheme::bfv

