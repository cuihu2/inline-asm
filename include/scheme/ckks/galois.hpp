#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace hpu::scheme::ckks {

inline std::uint32_t conjugation_galois_element(std::size_t degree)
{
    if (degree < 2 || (degree & (degree - 1)) != 0
        || degree > std::numeric_limits<std::uint32_t>::max() / 2U) {
        throw std::invalid_argument(
            "CKKS Galois mapping requires a power-of-two degree");
    }
    return static_cast<std::uint32_t>(2 * degree - 1);
}

// Matches SEAL's generator-3 CKKS slot convention. Positive steps rotate
// left; negative steps rotate right. Zero is deliberately rejected because
// it is a no-op at the slot API, while SEAL's low-level step mapper reserves
// step zero for conjugation.
inline std::uint32_t rotation_galois_element(
    std::size_t degree,
    int steps)
{
    const std::uint32_t conjugation = conjugation_galois_element(degree);
    if (steps == 0) {
        throw std::invalid_argument("zero-step CKKS rotation is a no-op");
    }
    const std::uint64_t magnitude = steps < 0
        ? 0U - static_cast<std::uint64_t>(steps)
        : static_cast<std::uint64_t>(steps);
    const std::uint64_t slot_count = degree >> 1U;
    if (magnitude >= slot_count) {
        throw std::invalid_argument("CKKS rotation step count is too large");
    }
    const std::uint64_t exponent = steps < 0
        ? slot_count - magnitude
        : magnitude;
    const std::uint64_t mask = conjugation;
    std::uint64_t element = 1;
    for (std::uint64_t index = 0; index < exponent; ++index) {
        element = (element * 3U) & mask;
    }
    return static_cast<std::uint32_t>(element);
}

} // namespace hpu::scheme::ckks
