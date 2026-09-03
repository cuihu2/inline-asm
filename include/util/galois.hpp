#pragma once

#include "util/validation.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <optional>
#include <stdexcept>

namespace hpu {

struct NegacyclicAutomorphismTarget {
    std::size_t index;
    bool negate;
};

inline constexpr bool is_valid_galois_element(
    std::size_t N,
    std::uint64_t galois_element)
{
    if (!is_power_of_two(N)
        || N > std::numeric_limits<std::uint64_t>::max() / 2) {
        return false;
    }
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(N);
    return galois_element > 0
        && galois_element < two_n
        && std::gcd(galois_element, two_n) == 1;
}

inline std::uint64_t galois_element_from_rotation_step(
    std::size_t N,
    std::int64_t step)
{
    if (!is_power_of_two(N) || N < 2
        || N / 2 > static_cast<std::size_t>(
            std::numeric_limits<std::int64_t>::max())) {
        throw std::invalid_argument(
            "rotation requires a power-of-two N of at least 2");
    }

    const std::int64_t row_size = static_cast<std::int64_t>(N / 2);
    std::int64_t normalized_step = step % row_size;
    if (normalized_step < 0) {
        normalized_step += row_size;
    }

    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(N);
    std::uint64_t result = 1;
    std::uint64_t base = 3;
    std::uint64_t exponent = static_cast<std::uint64_t>(normalized_step);
    while (exponent != 0) {
        if ((exponent & 1U) != 0U) {
            result = static_cast<std::uint64_t>(
                (static_cast<unsigned __int128>(result) * base) % two_n);
        }
        base = static_cast<std::uint64_t>(
            (static_cast<unsigned __int128>(base) * base) % two_n);
        exponent >>= 1U;
    }
    return result;
}

inline std::optional<std::size_t> rotation_step_from_galois_element(
    std::size_t N,
    std::uint64_t galois_element)
{
    if (!is_valid_galois_element(N, galois_element)) {
        throw std::invalid_argument("invalid Galois element for Z_(2N)^*");
    }

    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(N);
    std::uint64_t current = 1;
    for (std::size_t step = 0; step < N / 2; ++step) {
        if (current == galois_element) {
            return step;
        }
        current = static_cast<std::uint64_t>(
            (static_cast<unsigned __int128>(current) * 3) % two_n);
    }
    return std::nullopt;
}

inline std::uint64_t conjugation_galois_element(std::size_t N)
{
    if (!is_power_of_two(N) || N < 2
        || N > std::numeric_limits<std::uint64_t>::max() / 2) {
        throw std::invalid_argument(
            "conjugation requires a power-of-two N of at least 2");
    }
    return 2 * static_cast<std::uint64_t>(N) - 1;
}

inline NegacyclicAutomorphismTarget map_negacyclic_automorphism_index(
    std::size_t N,
    std::size_t source_index,
    std::uint64_t galois_element)
{
    if (!is_valid_galois_element(N, galois_element)
        || source_index >= N) {
        throw std::invalid_argument(
            "automorphism index requires source < N and g in Z_(2N)^*");
    }
    const std::uint64_t two_n = 2 * static_cast<std::uint64_t>(N);
    const std::uint64_t exponent = static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(source_index) * galois_element)
        % two_n);
    return {
        static_cast<std::size_t>(exponent % N),
        exponent >= N,
    };
}

static_assert(is_valid_galois_element(4096, 3));
static_assert(!is_valid_galois_element(4096, 2));
static_assert(!is_valid_galois_element(4096, 8193));

} // namespace hpu
