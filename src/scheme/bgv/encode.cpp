#include "scheme/bgv/encode.hpp"

#include "operator/plaintext_ntt.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <algorithm>
#include <limits>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::bgv {
namespace {

using U64 = std::uint64_t;
using U128 = unsigned __int128;

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

U64 inverse_mod(U64 value, U64 modulus)
{
    if (value == 0) {
        throw std::invalid_argument("BGV modular inverse does not exist");
    }
    return pow_mod(value, modulus - 2, modulus);
}

void validate_plaintext_modulus(std::size_t N, U64 modulus, bool batching)
{
    if (N < 2 || !hpu::is_power_of_two(N)) {
        throw std::invalid_argument("BGV N must be a power of two and at least 2");
    }
    if (modulus < 2 || modulus > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("BGV plaintext modulus must fit uint32 and be at least 2");
    }
    if (batching
        && (!hpu::is_prime(modulus) || (modulus - 1) % (2 * N) != 0)) {
        throw std::invalid_argument(
            "BGV batching requires prime t and 2N to divide t-1");
    }
}

U64 encode_signed_value(std::int64_t value, U64 modulus)
{
    const std::int64_t bound = static_cast<std::int64_t>(modulus / 2);
    if (value < -bound || value > bound) {
        throw std::invalid_argument("BGV signed value is outside the centered t range");
    }
    if (value >= 0) {
        return static_cast<U64>(value);
    }
    return modulus - static_cast<U64>(-value);
}

std::int64_t decode_signed_value(U64 value, U64 modulus)
{
    value %= modulus;
    return value > modulus / 2
        ? -static_cast<std::int64_t>(modulus - value)
        : static_cast<std::int64_t>(value);
}

U64 find_primitive_2n_root(U64 modulus, std::size_t N)
{
    const U64 order = static_cast<U64>(2 * N);
    for (U64 base = 2; base < modulus; ++base) {
        const U64 candidate = pow_mod(base, (modulus - 1) / order, modulus);
        if (pow_mod(candidate, static_cast<U64>(N), modulus) == modulus - 1) {
            return candidate;
        }
    }
    throw std::runtime_error("failed to find BGV primitive 2N-th root");
}

void cyclic_ntt(std::vector<U64>& values, U64 omega, U64 modulus, bool inverse)
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
    const U64 root = inverse ? inverse_mod(omega, modulus) : omega;
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
        const U64 n_inverse = inverse_mod(static_cast<U64>(N), modulus);
        for (U64& value : values) {
            value = mul_mod(value, n_inverse, modulus);
        }
    }
}

void negacyclic_ntt(std::vector<U64>& values, U64 psi, U64 modulus, bool inverse)
{
    const U64 omega = mul_mod(psi, psi, modulus);
    if (!inverse) {
        U64 twist = 1;
        for (U64& value : values) {
            value = mul_mod(value, twist, modulus);
            twist = mul_mod(twist, psi, modulus);
        }
        cyclic_ntt(values, omega, modulus, false);
        return;
    }
    cyclic_ntt(values, omega, modulus, true);
    const U64 psi_inverse = inverse_mod(psi, modulus);
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

bool valid_codegen_config(int N, int num_q, U64 modulus)
{
    if (!hpu::is_valid_plaintext_ntt_config(N, num_q)) {
        return false;
    }
    try {
        validate_plaintext_modulus(static_cast<std::size_t>(N), modulus, true);
        return true;
    } catch (const std::invalid_argument&) {
        return false;
    }
}

} // namespace

std::vector<U64> encode_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    U64 plaintext_modulus)
{
    validate_plaintext_modulus(N, plaintext_modulus, false);
    if (signed_coefficients.size() > N) {
        throw std::invalid_argument("BGV coefficient count exceeds N");
    }
    std::vector<U64> coefficients(N, 0);
    for (std::size_t i = 0; i < signed_coefficients.size(); ++i) {
        coefficients[i] = encode_signed_value(signed_coefficients[i], plaintext_modulus);
    }
    return coefficients;
}

std::vector<std::int64_t> decode_coefficients(
    const std::vector<U64>& coefficients,
    U64 plaintext_modulus)
{
    validate_plaintext_modulus(coefficients.size(), plaintext_modulus, false);
    std::vector<std::int64_t> decoded(coefficients.size());
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        decoded[i] = decode_signed_value(coefficients[i], plaintext_modulus);
    }
    return decoded;
}

std::vector<U64> encode_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    U64 plaintext_modulus)
{
    validate_plaintext_modulus(N, plaintext_modulus, true);
    if (slots.size() > N) {
        throw std::invalid_argument("BGV slot count exceeds N");
    }
    const auto roots = generator3_slot_roots(N);
    std::vector<U64> evaluations(N, 0);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        evaluations[roots[slot]] = encode_signed_value(slots[slot], plaintext_modulus);
    }
    negacyclic_ntt(
        evaluations, find_primitive_2n_root(plaintext_modulus, N),
        plaintext_modulus, true);
    return evaluations;
}

std::vector<std::int64_t> decode_slots(
    const std::vector<U64>& coefficients,
    U64 plaintext_modulus)
{
    const std::size_t N = coefficients.size();
    validate_plaintext_modulus(N, plaintext_modulus, true);
    std::vector<U64> evaluations = coefficients;
    negacyclic_ntt(
        evaluations, find_primitive_2n_root(plaintext_modulus, N),
        plaintext_modulus, false);
    const auto roots = generator3_slot_roots(N);
    std::vector<std::int64_t> slots(N);
    for (std::size_t slot = 0; slot < N; ++slot) {
        slots[slot] = decode_signed_value(evaluations[roots[slot]], plaintext_modulus);
    }
    return slots;
}

std::string generate_encode_body_asm(
    int N, int num_q, U64 plaintext_modulus, bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_codegen_config(N, num_q, plaintext_modulus)) {
        asm_code << "        // Invalid BGV Encode config: batching requires prime t and 2N | (t-1)\n";
        return asm_code.str();
    }
    asm_code << "        /* BGV ENCODE: host coefficient/batching map -> HPU NTT-Q */\n";
    asm_code << generate_plaintext_ntt_body_asm(N, num_q, append_psync);
    return asm_code.str();
}

std::string generate_encode_asm(
    int N, int num_q, U64 plaintext_modulus, bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bgv_encode_N" << N << "_Q" << num_q << "(void) {\n";
    if (!valid_codegen_config(N, num_q, plaintext_modulus)) {
        asm_code << "    // Invalid BGV Encode config\n}\n";
        return asm_code.str();
    }
    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_encode_body_asm(
        N, num_q, plaintext_modulus, append_psync);
    asm_code << "        : \n        : \n        : \"memory\"\n    );\n}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::bgv
