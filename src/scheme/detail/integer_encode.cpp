#include "scheme/detail/integer_encode.hpp"

#include "util/validation.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace hpu::scheme::detail {
namespace {

using U64 = std::uint64_t;
using U128 = unsigned __int128;

std::string error_prefix(const char* scheme_name)
{
    return std::string(scheme_name) + ' ';
}

U64 add_mod(U64 left, U64 right, U64 modulus)
{
    return static_cast<U64>((static_cast<U128>(left) + right) % modulus);
}

U64 sub_mod(U64 left, U64 right, U64 modulus)
{
    return left >= right ? left - right : modulus - (right - left);
}

U64 mul_mod(U64 left, U64 right, U64 modulus)
{
    return static_cast<U64>((static_cast<U128>(left) * right) % modulus);
}

U64 pow_mod(U64 base, U64 exponent, U64 modulus)
{
    U64 result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1U;
    }
    return result;
}

U64 inverse_mod(U64 value, U64 modulus, const char* scheme_name)
{
    if (value == 0) {
        throw std::invalid_argument(
            error_prefix(scheme_name) + "modular inverse does not exist");
    }
    return pow_mod(value, modulus - 2, modulus);
}

void validate_plaintext_modulus(
    std::size_t N, U64 modulus, bool batching, const char* scheme_name)
{
    const std::string prefix = error_prefix(scheme_name);
    if (N < 2 || !hpu::is_power_of_two(N)) {
        throw std::invalid_argument(
            prefix + "N must be a power of two and at least 2");
    }
    if (modulus < 2 || modulus > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(
            prefix + "plaintext modulus must fit uint32 and be at least 2");
    }
    if (batching
        && (!hpu::is_prime(modulus) || (modulus - 1) % (2 * N) != 0)) {
        throw std::invalid_argument(
            prefix + "batching requires prime t and 2N to divide t-1");
    }
}

U64 encode_signed_value(U64 modulus, std::int64_t value, const char* scheme_name)
{
    const std::int64_t bound = static_cast<std::int64_t>(modulus / 2);
    if (value < -bound || value > bound) {
        throw std::invalid_argument(
            error_prefix(scheme_name)
            + "signed value is outside the centered t range");
    }
    return value >= 0
        ? static_cast<U64>(value)
        : modulus - static_cast<U64>(-value);
}

std::int64_t decode_signed_value(U64 value, U64 modulus)
{
    value %= modulus;
    return value > modulus / 2
        ? -static_cast<std::int64_t>(modulus - value)
        : static_cast<std::int64_t>(value);
}

U64 find_primitive_2n_root(U64 modulus, std::size_t N, const char* scheme_name)
{
    const U64 order = static_cast<U64>(2 * N);
    for (U64 base = 2; base < modulus; ++base) {
        const U64 candidate = pow_mod(base, (modulus - 1) / order, modulus);
        if (pow_mod(candidate, static_cast<U64>(N), modulus) == modulus - 1) {
            // Match SEAL's batching ABI by selecting the smallest odd power
            // from this primitive-root conjugacy class.
            const U64 generator_squared = mul_mod(candidate, candidate, modulus);
            U64 minimal = candidate;
            U64 current = candidate;
            for (std::size_t index = 0; index < N; ++index) {
                minimal = std::min(minimal, current);
                current = mul_mod(current, generator_squared, modulus);
            }
            return minimal;
        }
    }
    throw std::runtime_error(
        "failed to find " + error_prefix(scheme_name) + "primitive 2N-th root");
}

void cyclic_ntt(
    std::vector<U64>& values,
    U64 omega,
    U64 modulus,
    bool inverse,
    const char* scheme_name)
{
    const std::size_t N = values.size();
    for (std::size_t i = 1, j = 0; i < N; ++i) {
        std::size_t bit = N >> 1U;
        while ((j & bit) != 0) {
            j ^= bit;
            bit >>= 1U;
        }
        j ^= bit;
        if (i < j) {
            std::swap(values[i], values[j]);
        }
    }
    const U64 root = inverse ? inverse_mod(omega, modulus, scheme_name) : omega;
    for (std::size_t length = 2; length <= N; length <<= 1U) {
        const U64 step = pow_mod(root, static_cast<U64>(N / length), modulus);
        for (std::size_t begin = 0; begin < N; begin += length) {
            U64 twiddle = 1;
            for (std::size_t j = 0; j < length / 2; ++j) {
                const U64 even = values[begin + j];
                const U64 odd = mul_mod(
                    values[begin + j + length / 2], twiddle, modulus);
                values[begin + j] = add_mod(even, odd, modulus);
                values[begin + j + length / 2] = sub_mod(even, odd, modulus);
                twiddle = mul_mod(twiddle, step, modulus);
            }
        }
    }
    if (inverse) {
        const U64 n_inverse = inverse_mod(static_cast<U64>(N), modulus, scheme_name);
        for (U64& value : values) {
            value = mul_mod(value, n_inverse, modulus);
        }
    }
}

void negacyclic_ntt(
    std::vector<U64>& values,
    U64 psi,
    U64 modulus,
    bool inverse,
    const char* scheme_name)
{
    const U64 omega = mul_mod(psi, psi, modulus);
    if (!inverse) {
        U64 twist = 1;
        for (U64& value : values) {
            value = mul_mod(value, twist, modulus);
            twist = mul_mod(twist, psi, modulus);
        }
        cyclic_ntt(values, omega, modulus, false, scheme_name);
        return;
    }
    cyclic_ntt(values, omega, modulus, true, scheme_name);
    const U64 psi_inverse = inverse_mod(psi, modulus, scheme_name);
    U64 twist = 1;
    for (U64& value : values) {
        value = mul_mod(value, twist, modulus);
        twist = mul_mod(twist, psi_inverse, modulus);
    }
}

std::vector<std::size_t> generator3_slot_roots(std::size_t N)
{
    const std::size_t m = 2 * N;
    std::vector<std::size_t> roots(N);
    std::size_t position = 1;
    for (std::size_t slot = 0; slot < N / 2; ++slot) {
        roots[slot] = (position - 1) / 2;
        roots[N / 2 + slot] = (m - position - 1) / 2;
        position = (position * 3) & (m - 1);
    }
    return roots;
}

} // namespace

std::vector<U64> encode_integer_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    U64 plaintext_modulus,
    const char* scheme_name)
{
    validate_plaintext_modulus(N, plaintext_modulus, false, scheme_name);
    if (signed_coefficients.size() > N) {
        throw std::invalid_argument(
            error_prefix(scheme_name) + "coefficient count exceeds N");
    }
    std::vector<U64> coefficients(N, 0);
    for (std::size_t i = 0; i < signed_coefficients.size(); ++i) {
        coefficients[i] = encode_signed_value(
            plaintext_modulus, signed_coefficients[i], scheme_name);
    }
    return coefficients;
}

std::vector<std::int64_t> decode_integer_coefficients(
    const std::vector<U64>& coefficients,
    U64 plaintext_modulus,
    const char* scheme_name)
{
    validate_plaintext_modulus(
        coefficients.size(), plaintext_modulus, false, scheme_name);
    std::vector<std::int64_t> decoded(coefficients.size());
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        decoded[i] = decode_signed_value(coefficients[i], plaintext_modulus);
    }
    return decoded;
}

std::vector<U64> encode_integer_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    U64 plaintext_modulus,
    const char* scheme_name)
{
    validate_plaintext_modulus(N, plaintext_modulus, true, scheme_name);
    if (slots.size() > N) {
        throw std::invalid_argument(
            error_prefix(scheme_name) + "slot count exceeds N");
    }
    const auto roots = generator3_slot_roots(N);
    std::vector<U64> evaluations(N, 0);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        evaluations[roots[slot]] = encode_signed_value(
            plaintext_modulus, slots[slot], scheme_name);
    }
    negacyclic_ntt(
        evaluations,
        find_primitive_2n_root(plaintext_modulus, N, scheme_name),
        plaintext_modulus,
        true,
        scheme_name);
    return evaluations;
}

std::vector<std::int64_t> decode_integer_slots(
    const std::vector<U64>& coefficients,
    U64 plaintext_modulus,
    const char* scheme_name)
{
    const std::size_t N = coefficients.size();
    validate_plaintext_modulus(N, plaintext_modulus, true, scheme_name);
    std::vector<U64> evaluations = coefficients;
    negacyclic_ntt(
        evaluations,
        find_primitive_2n_root(plaintext_modulus, N, scheme_name),
        plaintext_modulus,
        false,
        scheme_name);
    const auto roots = generator3_slot_roots(N);
    std::vector<std::int64_t> slots(N);
    for (std::size_t slot = 0; slot < N; ++slot) {
        slots[slot] = decode_signed_value(
            evaluations[roots[slot]], plaintext_modulus);
    }
    return slots;
}

} // namespace hpu::scheme::detail
