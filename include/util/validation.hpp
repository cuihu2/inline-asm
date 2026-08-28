#pragma once

#include "util/hpu_asm.hpp"

#include <cstddef>
#include <cstdint>

namespace hpu {

inline constexpr bool is_power_of_two(std::size_t value)
{
    return value > 0 && (value & (value - 1)) == 0;
}

inline constexpr bool is_power_of_two(int value)
{
    return value > 0 && is_power_of_two(static_cast<std::size_t>(value));
}

inline constexpr bool is_valid_ntt_size(int N)
{
    return is_power_of_two(N) && fits_ntt_object(N);
}

inline constexpr bool has_mod_context_capacity(
    std::size_t num_q,
    std::size_t num_p = 0,
    std::size_t reserved_contexts = 0)
{
    const auto capacity = static_cast<std::size_t>(kMaxModContexts);
    return num_q > 0
        && reserved_contexts <= capacity
        && num_q <= capacity - reserved_contexts
        && num_p <= capacity - reserved_contexts - num_q;
}

inline constexpr bool has_mod_context_capacity(
    int num_q,
    int num_p = 0,
    int reserved_contexts = 0)
{
    return num_q > 0 && num_p >= 0 && reserved_contexts >= 0
        && has_mod_context_capacity(
            static_cast<std::size_t>(num_q),
            static_cast<std::size_t>(num_p),
            static_cast<std::size_t>(reserved_contexts));
}

inline constexpr bool is_prime(std::uint64_t value)
{
    if (value < 2) {
        return false;
    }
    if ((value & 1U) == 0) {
        return value == 2;
    }
    for (std::uint64_t divisor = 3;
         divisor <= value / divisor;
         divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }
    return true;
}

inline constexpr bool is_valid_plaintext_ntt_config(int N, int num_q)
{
    return is_valid_ntt_size(N) && has_mod_context_capacity(num_q);
}

inline constexpr bool is_valid_rns_decomposition_config(
    int N,
    int num_q,
    int num_p,
    int dnum,
    int reserved_contexts = 0)
{
    return is_valid_ntt_size(N)
        && num_p > 0
        && dnum > 0
        && num_q % dnum == 0
        && has_mod_context_capacity(num_q, num_p, reserved_contexts);
}

static_assert(is_power_of_two(4096));
static_assert(!is_power_of_two(4095));
static_assert(is_valid_ntt_size(128));
static_assert(!is_valid_ntt_size(64));
static_assert(has_mod_context_capacity(4, 3, 1));
static_assert(!has_mod_context_capacity(252, 4, 1));
static_assert(is_prime(65537));
static_assert(!is_prime(81921));

} // namespace hpu
