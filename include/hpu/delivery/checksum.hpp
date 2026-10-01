#pragma once

#include <cstdint>
#include <vector>

namespace hpu::delivery {

std::uint64_t fnv1a64_bytes(
    const std::vector<std::uint8_t>& bytes) noexcept;

std::uint64_t fnv1a64_words32_le(
    const std::vector<std::uint32_t>& words) noexcept;
std::uint64_t fnv1a64_words64_le(
    const std::vector<std::uint64_t>& words) noexcept;

} // namespace hpu::delivery
