#include <algorithm>
#include <array>
#include <cmath>
#include <complex>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "config/fhe_test_config.hpp"
#include "scheme/bgv/encode.hpp"
#include "scheme/bfv/encode.hpp"
#include "scheme/ckks/encode.hpp"

namespace {

using U64 = std::uint64_t;
using U32 = std::uint32_t;
using U128 = unsigned __int128;
using I128 = __int128;
using Poly = std::vector<U64>;
using BasisPoly = std::vector<Poly>;
using Ciphertext = std::array<BasisPoly, 2>;
using TensorCiphertext = std::array<BasisPoly, 3>;
using EvaluationKey = std::vector<std::array<BasisPoly, 2>>;
using BigInt = U128;

std::size_t g_n = 0;
std::size_t g_num_q = 0;
std::size_t g_num_p = 0;
std::size_t g_bfv_num_b = 0;
std::size_t g_dnum = 0;
std::size_t g_auto_index = 0;
U64 g_plaintext_modulus = 0;
U64 g_seed = 0;
U64 g_hpu_mem_max_lines = 0;
constexpr U64 kFnv1a64OffsetBasis = 14695981039346656037ULL;
constexpr std::size_t kHpuWordsPerLine = 64;
constexpr U64 kHpuLineBytes = kHpuWordsPerLine * sizeof(U32);
constexpr U64 kHpuMemBase = 0x10000000ULL;
constexpr std::size_t kModContextWords = 4;
constexpr U64 kMinPeModulus = 65537;
constexpr U64 kMaxPeModulus = std::numeric_limits<U32>::max();
constexpr unsigned kBarrettMuBits = 48;
constexpr std::size_t kRegularBankCount = 5;
constexpr std::size_t kRegularBankLines = 1024;
constexpr std::size_t kSmallBankId = 5;
constexpr std::size_t kSmallBankLines = 32;
constexpr std::size_t kModTableBaseLine =
    kRegularBankCount * kRegularBankLines;
constexpr std::size_t kModContextsPerLine =
    kHpuWordsPerLine / kModContextWords;
constexpr std::size_t kPhysicalModContexts =
    kSmallBankLines * kModContextsPerLine;
constexpr std::size_t kModIdBits = 8;
constexpr std::size_t kMaxModContexts =
    std::min(kPhysicalModContexts, std::size_t{1} << kModIdBits);

enum class HardwareDomain {
    kCoefficient,
    kNtt,
};

enum class TwiddleRequirement {
    kNone,
    kRequired,
};

struct Artifact {
    std::string path;
    std::string role;
    std::vector<std::size_t> shape;
    std::vector<U64> words;
    std::vector<std::string> axes;
    HardwareDomain hardware_domain = HardwareDomain::kCoefficient;
    bool hardware_visible = true;
    U64 checksum = 0;
};

struct HardwareImage {
    std::string path;
    std::string role;
    std::vector<std::size_t> shape;
    std::vector<U32> payload_words;
    std::vector<U32> padded_words;
    U64 line_offset = 0;
    U64 payload_checksum = 0;
    U64 image_checksum = 0;
};

struct TwiddleMapEntry {
    std::string direction;
    std::size_t basis = 0;
    U64 modulus = 0;
    std::string phase;
    int stage = -1;
    std::size_t value_count = 0;
    std::size_t group_count = 0;
    std::size_t twiddles_per_group = 0;
    U64 first_value = 0;
    U64 step = 0;
    std::size_t image_index = 0;
};

U64 add_mod(U64 a, U64 b, U64 modulus)
{
    return static_cast<U64>((static_cast<U128>(a) + b) % modulus);
}

U64 sub_mod(U64 a, U64 b, U64 modulus)
{
    return a >= b ? a - b : modulus - (b - a);
}

U64 mul_mod(U64 a, U64 b, U64 modulus)
{
    return static_cast<U64>((static_cast<U128>(a) * b) % modulus);
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
    I128 t = 0;
    I128 new_t = 1;
    I128 r = static_cast<I128>(modulus);
    I128 new_r = static_cast<I128>(value % modulus);
    while (new_r != 0) {
        const I128 quotient = r / new_r;
        const I128 old_t = t;
        t = new_t;
        new_t = old_t - quotient * new_t;
        const I128 old_r = r;
        r = new_r;
        new_r = old_r - quotient * new_r;
    }
    if (r != 1) {
        throw std::runtime_error("modular inverse does not exist");
    }
    t %= static_cast<I128>(modulus);
    if (t < 0) {
        t += static_cast<I128>(modulus);
    }
    return static_cast<U64>(t);
}

bool is_prime(U64 value)
{
    if (value < 2) {
        return false;
    }
    if ((value & 1U) == 0) {
        return value == 2;
    }
    for (U64 divisor = 3; divisor * divisor <= value; divisor += 2) {
        if (value % divisor == 0) {
            return false;
        }
    }
    return true;
}

U64 find_ntt_prime(U64 start, U64 order)
{
    U64 candidate = start;
    const U64 remainder = candidate % order;
    candidate += remainder <= 1 ? 1 - remainder : order + 1 - remainder;
    while (!is_prime(candidate)) {
        candidate += order;
    }
    return candidate;
}

U64 find_primitive_2n_root(U64 modulus, std::size_t n)
{
    const U64 order = static_cast<U64>(2 * n);
    for (U64 base = 2; base < modulus; ++base) {
        const U64 candidate = pow_mod(base, (modulus - 1) / order, modulus);
        if (pow_mod(candidate, static_cast<U64>(n), modulus) == modulus - 1) {
            return candidate;
        }
    }
    throw std::runtime_error("failed to find primitive 2N-th root");
}

void cyclic_ntt(Poly& values, U64 omega, U64 modulus, bool inverse)
{
    const std::size_t n = values.size();
    for (std::size_t i = 1, j = 0; i < n; ++i) {
        std::size_t bit = n >> 1U;
        while ((j & bit) != 0) {
            j ^= bit;
            bit >>= 1U;
        }
        j ^= bit;
        if (i < j) {
            std::swap(values[i], values[j]);
        }
    }

    const U64 active_root = inverse ? inverse_mod(omega, modulus) : omega;
    for (std::size_t length = 2; length <= n; length <<= 1U) {
        const U64 step = pow_mod(active_root, static_cast<U64>(n / length), modulus);
        for (std::size_t begin = 0; begin < n; begin += length) {
            U64 twiddle = 1;
            for (std::size_t j = 0; j < length / 2; ++j) {
                const U64 even = values[begin + j];
                const U64 odd = mul_mod(values[begin + j + length / 2], twiddle, modulus);
                values[begin + j] = add_mod(even, odd, modulus);
                values[begin + j + length / 2] = sub_mod(even, odd, modulus);
                twiddle = mul_mod(twiddle, step, modulus);
            }
        }
    }

    if (inverse) {
        const U64 n_inverse = inverse_mod(static_cast<U64>(n), modulus);
        for (U64& value : values) {
            value = mul_mod(value, n_inverse, modulus);
        }
    }
}

void negacyclic_ntt(Poly& values, U64 psi, U64 modulus, bool inverse)
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

Poly add_poly(const Poly& left, const Poly& right, U64 modulus)
{
    Poly out(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        out[i] = add_mod(left[i], right[i], modulus);
    }
    return out;
}

Poly sub_poly(const Poly& left, const Poly& right, U64 modulus)
{
    Poly out(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        out[i] = sub_mod(left[i], right[i], modulus);
    }
    return out;
}

Poly scalar_poly(const Poly& input, U64 scalar, U64 modulus)
{
    Poly out(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        out[i] = mul_mod(input[i], scalar, modulus);
    }
    return out;
}

Poly pointwise_mul(const Poly& left, const Poly& right, U64 modulus)
{
    Poly out(left.size());
    for (std::size_t i = 0; i < left.size(); ++i) {
        out[i] = mul_mod(left[i], right[i], modulus);
    }
    return out;
}

Poly scalar_mul_poly(const Poly& input, U64 scalar, U64 modulus)
{
    Poly output(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        output[i] = mul_mod(input[i], scalar % modulus, modulus);
    }
    return output;
}

Poly negacyclic_mul(const Poly& left, const Poly& right, U64 modulus, U64 psi)
{
    Poly left_ntt = left;
    Poly right_ntt = right;
    negacyclic_ntt(left_ntt, psi, modulus, false);
    negacyclic_ntt(right_ntt, psi, modulus, false);
    Poly out = pointwise_mul(left_ntt, right_ntt, modulus);
    negacyclic_ntt(out, psi, modulus, true);
    return out;
}

Poly encode_signed(const std::vector<std::int64_t>& input, U64 modulus)
{
    Poly out(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const std::int64_t value = input[i];
        out[i] = value >= 0
            ? static_cast<U64>(value) % modulus
            : sub_mod(0, static_cast<U64>(-value) % modulus, modulus);
    }
    return out;
}

BasisPoly encode_basis(const std::vector<std::int64_t>& input,
                       const std::vector<U64>& moduli)
{
    BasisPoly out;
    out.reserve(moduli.size());
    for (U64 modulus : moduli) {
        out.push_back(encode_signed(input, modulus));
    }
    return out;
}

BasisPoly lift_basis(const Poly& input, const std::vector<U64>& moduli)
{
    BasisPoly output(moduli.size(), Poly(input.size()));
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        for (std::size_t coefficient = 0; coefficient < input.size(); ++coefficient) {
            output[basis][coefficient] = input[coefficient] % moduli[basis];
        }
    }
    return output;
}

BasisPoly transform_basis(const BasisPoly& input,
                          const std::vector<U64>& moduli,
                          const std::vector<U64>& roots,
                          bool inverse)
{
    BasisPoly out = input;
    for (std::size_t i = 0; i < out.size(); ++i) {
        negacyclic_ntt(out[i], roots[i], moduli[i], inverse);
    }
    return out;
}

Ciphertext encrypt_test_message(const std::vector<std::int64_t>& message,
                                const BasisPoly& secret,
                                const std::vector<U64>& moduli,
                                const std::vector<U64>& roots,
                                std::mt19937_64& rng)
{
    Ciphertext ciphertext;
    ciphertext[0].resize(moduli.size());
    ciphertext[1].resize(moduli.size());
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const U64 modulus = moduli[basis];
        Poly a(g_n);
        for (U64& value : a) {
            value = rng() % modulus;
        }
        const Poly product = negacyclic_mul(a, secret[basis], modulus, roots[basis]);
        const Poly encoded = encode_signed(message, modulus);
        ciphertext[0][basis] = sub_poly(encoded, product, modulus);
        ciphertext[1][basis] = std::move(a);
    }
    return ciphertext;
}

Ciphertext encrypt_bgv_test_message(
    const Poly& plaintext_coefficients,
    U64 correction_factor,
    U64 plaintext_modulus,
    const BasisPoly& secret,
    const std::vector<U64>& moduli,
    const std::vector<U64>& roots,
    std::mt19937_64& rng)
{
    Ciphertext ciphertext;
    ciphertext[0].resize(moduli.size());
    ciphertext[1].resize(moduli.size());
    if (plaintext_coefficients.size() != g_n) {
        throw std::runtime_error("BGV plaintext must contain N coefficients");
    }
    Poly encoded_t(plaintext_coefficients.size());
    for (std::size_t i = 0; i < plaintext_coefficients.size(); ++i) {
        encoded_t[i] = mul_mod(
            plaintext_coefficients[i] % plaintext_modulus,
            correction_factor,
            plaintext_modulus);
    }
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const U64 modulus = moduli[basis];
        Poly a(g_n);
        for (U64& value : a) {
            value = rng() % modulus;
        }
        const Poly product = negacyclic_mul(
            a, secret[basis], modulus, roots[basis]);
        Poly encoded_q(g_n);
        for (std::size_t i = 0; i < g_n; ++i) {
            encoded_q[i] = encoded_t[i] % modulus;
        }
        ciphertext[0][basis] = sub_poly(encoded_q, product, modulus);
        ciphertext[1][basis] = std::move(a);
    }
    return ciphertext;
}

Poly bconv_to_target(const BasisPoly& source,
                     const std::vector<U64>& source_moduli,
                     U64 target_modulus)
{
    if (source.empty() || source.size() != source_moduli.size()) {
        throw std::runtime_error("invalid BConv source");
    }
    Poly out(source.front().size(), 0);
    for (std::size_t j = 0; j < source.size(); ++j) {
        U64 qhat = 1;
        for (std::size_t k = 0; k < source_moduli.size(); ++k) {
            if (k == j) {
                continue;
            }
            if (qhat > UINT64_MAX / source_moduli[k]) {
                throw std::runtime_error("BConv basis-hat exceeds uint64_t");
            }
            qhat *= source_moduli[k];
        }
        const U64 qhat_inverse = inverse_mod(qhat % source_moduli[j], source_moduli[j]);
        const U64 qhat_target = qhat % target_modulus;
        for (std::size_t i = 0; i < out.size(); ++i) {
            const U64 normalized = mul_mod(source[j][i], qhat_inverse, source_moduli[j]);
            out[i] = add_mod(out[i], mul_mod(normalized, qhat_target, target_modulus), target_modulus);
        }
    }
    return out;
}

U64 product_mod(const std::vector<U64>& values, U64 modulus);

Poly fast_bconv_to_target(const BasisPoly& source,
                          const std::vector<U64>& source_moduli,
                          U64 target_modulus)
{
    if (source.empty() || source.size() != source_moduli.size()) {
        throw std::runtime_error("invalid fast BConv source");
    }
    Poly out(source.front().size(), 0);
    for (std::size_t j = 0; j < source.size(); ++j) {
        U64 qhat_source = 1;
        U64 qhat_target = 1;
        for (std::size_t k = 0; k < source_moduli.size(); ++k) {
            if (k == j) {
                continue;
            }
            qhat_source = mul_mod(
                qhat_source, source_moduli[k] % source_moduli[j],
                source_moduli[j]);
            qhat_target = mul_mod(
                qhat_target, source_moduli[k] % target_modulus,
                target_modulus);
        }
        const U64 qhat_inverse = inverse_mod(
            qhat_source, source_moduli[j]);
        for (std::size_t coefficient = 0;
             coefficient < out.size(); ++coefficient) {
            const U64 normalized = mul_mod(
                source[j][coefficient], qhat_inverse, source_moduli[j]);
            out[coefficient] = add_mod(
                out[coefficient],
                mul_mod(normalized, qhat_target, target_modulus),
                target_modulus);
        }
    }
    return out;
}

BasisPoly fast_bconv(const BasisPoly& source,
                     const std::vector<U64>& source_moduli,
                     const std::vector<U64>& target_moduli)
{
    BasisPoly output;
    output.reserve(target_moduli.size());
    for (U64 modulus : target_moduli) {
        output.push_back(fast_bconv_to_target(
            source, source_moduli, modulus));
    }
    return output;
}

BigInt big_product(const std::vector<U64>& values)
{
    BigInt product = 1;
    for (U64 value : values) {
        if (value != 0 && product > static_cast<BigInt>(-1) / value) {
            throw std::runtime_error(
                "reference Q product exceeds the self-contained 128-bit path");
        }
        product *= value;
    }
    return product;
}

unsigned big_bit_length(const BigInt& value)
{
    if (value <= 0) {
        return 0;
    }
    unsigned bits = 0;
    BigInt remaining = value;
    while (remaining != 0) {
        ++bits;
        remaining >>= 1U;
    }
    return bits;
}

unsigned u64_bit_length(U64 value)
{
    unsigned bits = 0;
    while (value != 0) {
        ++bits;
        value >>= 1U;
    }
    return bits;
}

U64 big_mod_u64(const BigInt& value, U64 modulus)
{
    return static_cast<U64>(value % modulus);
}

unsigned product_bit_length(const std::vector<U64>& values)
{
    std::vector<U32> limbs(1, 1);
    for (U64 value : values) {
        U64 carry = 0;
        for (U32& limb : limbs) {
            const U128 wide = static_cast<U128>(limb) * value + carry;
            limb = static_cast<U32>(wide);
            carry = static_cast<U64>(wide >> 32U);
        }
        while (carry != 0) {
            limbs.push_back(static_cast<U32>(carry));
            carry >>= 32U;
        }
    }
    while (limbs.size() > 1 && limbs.back() == 0) {
        limbs.pop_back();
    }
    return static_cast<unsigned>((limbs.size() - 1) * 32)
        + u64_bit_length(limbs.back());
}

struct FastBconvConstants {
    BasisPoly source_hat_inverse;
    std::vector<BasisPoly> source_hat_mod_target;
};

FastBconvConstants make_fast_bconv_constants(
    const std::vector<U64>& source_moduli,
    const std::vector<U64>& target_moduli)
{
    FastBconvConstants constants;
    constants.source_hat_inverse.resize(source_moduli.size());
    for (std::size_t source = 0; source < source_moduli.size(); ++source) {
        U64 source_hat = 1;
        for (std::size_t other = 0; other < source_moduli.size(); ++other) {
            if (other != source) {
                source_hat = mul_mod(
                    source_hat,
                    source_moduli[other] % source_moduli[source],
                    source_moduli[source]);
            }
        }
        constants.source_hat_inverse[source] = Poly(
            g_n, inverse_mod(source_hat, source_moduli[source]));
    }

    constants.source_hat_mod_target.resize(target_moduli.size());
    for (std::size_t target = 0; target < target_moduli.size(); ++target) {
        constants.source_hat_mod_target[target].resize(source_moduli.size());
        for (std::size_t source = 0; source < source_moduli.size(); ++source) {
            U64 source_hat = 1;
            for (std::size_t other = 0; other < source_moduli.size(); ++other) {
                if (other != source) {
                    source_hat = mul_mod(
                        source_hat,
                        source_moduli[other] % target_moduli[target],
                        target_moduli[target]);
                }
            }
            constants.source_hat_mod_target[target][source] = Poly(
                g_n, source_hat);
        }
    }
    return constants;
}

struct BfvBehzTrace {
    Ciphertext left_bsk;
    Ciphertext right_bsk;
    Ciphertext left_q_ntt;
    Ciphertext right_q_ntt;
    Ciphertext left_bsk_ntt;
    Ciphertext right_bsk_ntt;
    TensorCiphertext tensor_q_ntt;
    TensorCiphertext tensor_bsk_ntt;
    TensorCiphertext tensor_q_coeff;
    TensorCiphertext tensor_bsk_coeff;
    TensorCiphertext scaled_q;
    TensorCiphertext scaled_bsk;
    TensorCiphertext fast_floor_bsk;
    TensorCiphertext output_q;
    std::array<Poly, 3> alpha_msk;
};

Ciphertext encrypt_bfv_test_message(
    const Poly& encoded_t,
    const std::vector<std::int64_t>& error,
    const BasisPoly& secret,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& q_roots,
    std::mt19937_64& rng)
{
    if (encoded_t.size() != g_n || error.size() != g_n) {
        throw std::runtime_error("invalid BFV plaintext or error size");
    }
    const BigInt delta = big_product(q_moduli) / g_plaintext_modulus;
    Ciphertext ciphertext;
    ciphertext[0].resize(q_moduli.size());
    ciphertext[1].resize(q_moduli.size());
    for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
        const U64 modulus = q_moduli[basis];
        Poly random_a(g_n);
        for (U64& value : random_a) {
            value = rng() % modulus;
        }
        const Poly product = negacyclic_mul(
            random_a, secret[basis], modulus, q_roots[basis]);
        const U64 delta_mod_q = big_mod_u64(delta, modulus);
        ciphertext[0][basis].resize(g_n);
        for (std::size_t coefficient = 0;
             coefficient < g_n; ++coefficient) {
            U64 scaled = mul_mod(
                encoded_t[coefficient] % modulus, delta_mod_q, modulus);
            const std::int64_t signed_error = error[coefficient];
            const U64 error_mod = signed_error >= 0
                ? static_cast<U64>(signed_error) % modulus
                : sub_mod(0, static_cast<U64>(-signed_error) % modulus, modulus);
            scaled = add_mod(scaled, error_mod, modulus);
            ciphertext[0][basis][coefficient] = sub_mod(
                scaled, product[coefficient], modulus);
        }
        ciphertext[1][basis] = std::move(random_a);
    }
    return ciphertext;
}

TensorCiphertext tensor_product_ntt(
    const Ciphertext& left_ntt,
    const Ciphertext& right_ntt,
    const std::vector<U64>& moduli)
{
    TensorCiphertext tensor;
    for (BasisPoly& component : tensor) {
        component.resize(moduli.size());
    }
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const U64 modulus = moduli[basis];
        tensor[0][basis] = pointwise_mul(
            left_ntt[0][basis], right_ntt[0][basis], modulus);
        tensor[1][basis] = add_poly(
            pointwise_mul(left_ntt[0][basis], right_ntt[1][basis], modulus),
            pointwise_mul(left_ntt[1][basis], right_ntt[0][basis], modulus),
            modulus);
        tensor[2][basis] = pointwise_mul(
            left_ntt[1][basis], right_ntt[1][basis], modulus);
    }
    return tensor;
}

TensorCiphertext bfv_behz_multiply(
    const Ciphertext& left,
    const Ciphertext& right,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& b_moduli,
    U64 m_sk,
    const std::vector<U64>& q_roots,
    const std::vector<U64>& bsk_roots,
    BfvBehzTrace* trace)
{
    std::vector<U64> bsk_moduli = b_moduli;
    bsk_moduli.push_back(m_sk);

    Ciphertext left_bsk;
    Ciphertext right_bsk;
    Ciphertext left_q_ntt;
    Ciphertext right_q_ntt;
    Ciphertext left_bsk_ntt;
    Ciphertext right_bsk_ntt;
    for (std::size_t component = 0; component < 2; ++component) {
        left_bsk[component] = fast_bconv(
            left[component], q_moduli, bsk_moduli);
        right_bsk[component] = fast_bconv(
            right[component], q_moduli, bsk_moduli);
        left_q_ntt[component] = transform_basis(
            left[component], q_moduli, q_roots, false);
        right_q_ntt[component] = transform_basis(
            right[component], q_moduli, q_roots, false);
        left_bsk_ntt[component] = transform_basis(
            left_bsk[component], bsk_moduli, bsk_roots, false);
        right_bsk_ntt[component] = transform_basis(
            right_bsk[component], bsk_moduli, bsk_roots, false);
    }

    TensorCiphertext tensor_q_ntt = tensor_product_ntt(
        left_q_ntt, right_q_ntt, q_moduli);
    TensorCiphertext tensor_bsk_ntt = tensor_product_ntt(
        left_bsk_ntt, right_bsk_ntt, bsk_moduli);
    TensorCiphertext tensor_q_coeff;
    TensorCiphertext tensor_bsk_coeff;
    TensorCiphertext scaled_q;
    TensorCiphertext scaled_bsk;
    TensorCiphertext fast_floor_bsk;
    TensorCiphertext output_q;
    std::array<Poly, 3> alpha_msk;

    const U64 b_inverse_msk = inverse_mod(
        product_mod(b_moduli, m_sk), m_sk);
    for (std::size_t component = 0; component < 3; ++component) {
        tensor_q_coeff[component] = transform_basis(
            tensor_q_ntt[component], q_moduli, q_roots, true);
        tensor_bsk_coeff[component] = transform_basis(
            tensor_bsk_ntt[component], bsk_moduli, bsk_roots, true);
        scaled_q[component].resize(q_moduli.size());
        scaled_bsk[component].resize(bsk_moduli.size());
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            scaled_q[component][basis] = scalar_mul_poly(
                tensor_q_coeff[component][basis],
                g_plaintext_modulus, q_moduli[basis]);
        }
        for (std::size_t basis = 0; basis < bsk_moduli.size(); ++basis) {
            scaled_bsk[component][basis] = scalar_mul_poly(
                tensor_bsk_coeff[component][basis],
                g_plaintext_modulus, bsk_moduli[basis]);
        }

        const BasisPoly converted_q = fast_bconv(
            scaled_q[component], q_moduli, bsk_moduli);
        fast_floor_bsk[component].resize(bsk_moduli.size());
        for (std::size_t basis = 0; basis < bsk_moduli.size(); ++basis) {
            const U64 modulus = bsk_moduli[basis];
            const U64 q_inverse = inverse_mod(
                product_mod(q_moduli, modulus), modulus);
            fast_floor_bsk[component][basis].resize(g_n);
            for (std::size_t coefficient = 0;
                 coefficient < g_n; ++coefficient) {
                fast_floor_bsk[component][basis][coefficient] = mul_mod(
                    sub_mod(
                        scaled_bsk[component][basis][coefficient],
                        converted_q[basis][coefficient], modulus),
                    q_inverse, modulus);
            }
        }

        const BasisPoly z_b(
            fast_floor_bsk[component].begin(),
            fast_floor_bsk[component].begin()
                + static_cast<std::ptrdiff_t>(b_moduli.size()));
        const BasisPoly y_q = fast_bconv(z_b, b_moduli, q_moduli);
        const Poly temp_msk = fast_bconv_to_target(
            z_b, b_moduli, m_sk);
        alpha_msk[component].resize(g_n);
        for (std::size_t coefficient = 0;
             coefficient < g_n; ++coefficient) {
            alpha_msk[component][coefficient] = mul_mod(
                sub_mod(
                    temp_msk[coefficient],
                    fast_floor_bsk[component].back()[coefficient],
                    m_sk),
                b_inverse_msk, m_sk);
            if (alpha_msk[component][coefficient] > b_moduli.size()
                || alpha_msk[component][coefficient] > m_sk / 2) {
                throw std::runtime_error(
                    "branchless SK alpha exceeds the proven lower-half range");
            }
        }

        output_q[component].resize(q_moduli.size());
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            const U64 modulus = q_moduli[basis];
            const U64 b_mod_q = product_mod(b_moduli, modulus);
            const U64 neg_b_mod_q = b_mod_q == 0 ? 0 : modulus - b_mod_q;
            output_q[component][basis].resize(g_n);
            for (std::size_t coefficient = 0;
                 coefficient < g_n; ++coefficient) {
                output_q[component][basis][coefficient] = add_mod(
                    y_q[basis][coefficient],
                    mul_mod(alpha_msk[component][coefficient],
                            neg_b_mod_q, modulus),
                    modulus);
            }
        }
    }

    if (trace != nullptr) {
        trace->left_bsk = std::move(left_bsk);
        trace->right_bsk = std::move(right_bsk);
        trace->left_q_ntt = std::move(left_q_ntt);
        trace->right_q_ntt = std::move(right_q_ntt);
        trace->left_bsk_ntt = std::move(left_bsk_ntt);
        trace->right_bsk_ntt = std::move(right_bsk_ntt);
        trace->tensor_q_ntt = std::move(tensor_q_ntt);
        trace->tensor_bsk_ntt = std::move(tensor_bsk_ntt);
        trace->tensor_q_coeff = std::move(tensor_q_coeff);
        trace->tensor_bsk_coeff = std::move(tensor_bsk_coeff);
        trace->scaled_q = std::move(scaled_q);
        trace->scaled_bsk = std::move(scaled_bsk);
        trace->fast_floor_bsk = std::move(fast_floor_bsk);
        trace->output_q = output_q;
        trace->alpha_msk = std::move(alpha_msk);
    }
    return output_q;
}

BasisPoly modup(const BasisPoly& input_q,
                const std::vector<U64>& q_moduli,
                const std::vector<U64>& all_moduli,
                std::size_t offset,
                std::size_t digit_size)
{
    BasisPoly source;
    std::vector<U64> source_moduli;
    for (std::size_t i = 0; i < digit_size; ++i) {
        source.push_back(input_q[offset + i]);
        source_moduli.push_back(q_moduli[offset + i]);
    }

    BasisPoly out(all_moduli.size());
    for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
        if (basis >= offset && basis < offset + digit_size) {
            out[basis] = input_q[basis];
        } else {
            out[basis] = bconv_to_target(source, source_moduli, all_moduli[basis]);
        }
    }
    return out;
}

U64 product_mod(const std::vector<U64>& values, U64 modulus)
{
    U64 result = 1;
    for (U64 value : values) {
        result = mul_mod(result, value % modulus, modulus);
    }
    return result;
}

std::vector<U64> crt_digit_factors(const std::vector<U64>& q_moduli,
                                   std::size_t offset,
                                   std::size_t digit_size,
                                   const std::vector<U64>& all_moduli)
{
    U64 q_digit = 1;
    U64 q_other = 1;
    for (std::size_t i = 0; i < q_moduli.size(); ++i) {
        U64& product = (i >= offset && i < offset + digit_size) ? q_digit : q_other;
        if (product > UINT64_MAX / q_moduli[i]) {
            throw std::runtime_error("CRT digit product exceeds uint64_t");
        }
        product *= q_moduli[i];
    }
    const U64 inverse = inverse_mod(q_other % q_digit, q_digit);
    std::vector<U64> out;
    out.reserve(all_moduli.size());
    for (U64 modulus : all_moduli) {
        out.push_back(mul_mod(q_other % modulus, inverse % modulus, modulus));
    }
    return out;
}

BasisPoly moddown(const BasisPoly& input_qp,
                  const std::vector<U64>& q_moduli,
                  const std::vector<U64>& p_moduli)
{
    BasisPoly source_p(input_qp.begin() + static_cast<std::ptrdiff_t>(q_moduli.size()),
                       input_qp.end());
    BasisPoly out(q_moduli.size());
    for (std::size_t i = 0; i < q_moduli.size(); ++i) {
        const U64 modulus = q_moduli[i];
        const Poly correction = bconv_to_target(source_p, p_moduli, modulus);
        const U64 p_inverse = inverse_mod(product_mod(p_moduli, modulus), modulus);
        out[i].resize(g_n);
        for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
            out[i][coefficient] = mul_mod(
                sub_mod(input_qp[i][coefficient], correction[coefficient], modulus),
                p_inverse,
                modulus);
        }
    }
    return out;
}

BasisPoly rescale_drop_last(const BasisPoly& input_q,
                            const std::vector<U64>& q_moduli)
{
    if (q_moduli.size() < 2 || input_q.size() != q_moduli.size()) {
        throw std::runtime_error("rescale requires matching Q basis with at least two limbs");
    }

    const U64 dropped_modulus = q_moduli.back();
    const U64 half = dropped_modulus / 2;
    BasisPoly rounded_numerator = input_q;
    for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
        const U64 modulus = q_moduli[basis];
        for (U64& coefficient : rounded_numerator[basis]) {
            coefficient = add_mod(coefficient, half % modulus, modulus);
        }
    }

    const std::vector<U64> retained_moduli(q_moduli.begin(), q_moduli.end() - 1);
    return moddown(rounded_numerator, retained_moduli, {dropped_modulus});
}

BasisPoly direct_rounded_divide_last(const BasisPoly& input_q,
                                     const std::vector<U64>& q_moduli)
{
    if (q_moduli.size() < 2 || input_q.size() != q_moduli.size()) {
        throw std::runtime_error("direct rescale check requires a matching Q basis");
    }

    BasisPoly out(q_moduli.size() - 1, Poly(g_n));
    const U64 dropped_modulus = q_moduli.back();
    for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
        U128 value = 0;
        U128 product = 1;
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            const U64 modulus = q_moduli[basis];
            const U64 value_mod = static_cast<U64>(value % modulus);
            const U64 delta = sub_mod(
                input_q[basis][coefficient], value_mod, modulus);
            const U64 product_inverse = inverse_mod(
                static_cast<U64>(product % modulus), modulus);
            const U64 digit = mul_mod(delta, product_inverse, modulus);
            value += product * digit;
            product *= modulus;
        }

        const U128 rounded =
            (value + dropped_modulus / 2) / dropped_modulus;
        for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
            out[basis][coefficient] =
                static_cast<U64>(rounded % q_moduli[basis]);
        }
    }
    return out;
}

Poly apply_negacyclic_automorphism(const Poly& input,
                                   U64 galois_element,
                                   U64 modulus)
{
    if ((galois_element & 1U) == 0U || input.empty()) {
        throw std::runtime_error("automorphism requires a non-empty polynomial and odd Galois element");
    }
    const U64 two_n = static_cast<U64>(input.size()) * 2U;
    Poly output(input.size(), 0U);
    for (std::size_t coefficient = 0; coefficient < input.size(); ++coefficient) {
        const U64 exponent =
            (static_cast<U64>(coefficient) * galois_element) % two_n;
        const std::size_t target =
            static_cast<std::size_t>(exponent % input.size());
        output[target] = exponent < input.size()
            ? input[coefficient]
            : (input[coefficient] == 0U ? 0U : modulus - input[coefficient]);
    }
    return output;
}

BasisPoly apply_negacyclic_automorphism(
    const BasisPoly& input,
    U64 galois_element,
    const std::vector<U64>& moduli)
{
    if (input.size() != moduli.size()) {
        throw std::runtime_error("automorphism basis/modulus size mismatch");
    }
    BasisPoly output(input.size());
    for (std::size_t basis = 0; basis < input.size(); ++basis) {
        output[basis] = apply_negacyclic_automorphism(
            input[basis], galois_element, moduli[basis]);
    }
    return output;
}

BasisPoly decrypt_ciphertext(const Ciphertext& ciphertext,
                             const BasisPoly& secret,
                             const std::vector<U64>& moduli,
                             const std::vector<U64>& roots)
{
    BasisPoly out(moduli.size());
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        out[basis] = add_poly(
            ciphertext[0][basis],
            negacyclic_mul(ciphertext[1][basis], secret[basis], moduli[basis], roots[basis]),
            moduli[basis]);
    }
    return out;
}

BasisPoly decrypt_tensor(const TensorCiphertext& tensor,
                         const BasisPoly& secret,
                         const std::vector<U64>& moduli,
                         const std::vector<U64>& roots)
{
    BasisPoly out(moduli.size());
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const Poly secret_squared = negacyclic_mul(
            secret[basis], secret[basis], moduli[basis], roots[basis]);
        const Poly linear = negacyclic_mul(
            tensor[1][basis], secret[basis], moduli[basis], roots[basis]);
        const Poly quadratic = negacyclic_mul(
            tensor[2][basis], secret_squared, moduli[basis], roots[basis]);
        out[basis] = add_poly(add_poly(tensor[0][basis], linear, moduli[basis]),
                              quadratic,
                              moduli[basis]);
    }
    return out;
}

void verify_equal(
    const BasisPoly& left,
    const BasisPoly& right,
    const std::string& label);

struct SchemeMultiplyTrace {
    Ciphertext left_ntt;
    Ciphertext right_ntt;
    TensorCiphertext tensor_ntt;
    TensorCiphertext tensor_coeff;
    std::vector<BasisPoly> modup_coeff;
    std::vector<BasisPoly> modup_ntt;
    std::array<BasisPoly, 2> keyswitch_accum_ntt;
    std::array<BasisPoly, 2> keyswitch_accum_coeff;
    std::array<BasisPoly, 2> keyswitch_q;
};

Ciphertext multiply_and_relinearize(
    const Ciphertext& left,
    const Ciphertext& right,
    const BasisPoly& secret_q,
    const EvaluationKey& rlk_ntt,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& p_moduli,
    const std::vector<U64>& all_moduli,
    const std::vector<U64>& q_roots,
    const std::vector<U64>& all_roots,
    SchemeMultiplyTrace* trace = nullptr)
{
    if (rlk_ntt.size() != g_dnum || g_num_q % g_dnum != 0) {
        throw std::runtime_error("invalid evaluation key for scheme multiply");
    }

    Ciphertext left_ntt;
    Ciphertext right_ntt;
    for (std::size_t component = 0; component < 2; ++component) {
        left_ntt[component] = transform_basis(left[component], q_moduli, q_roots, false);
        right_ntt[component] = transform_basis(right[component], q_moduli, q_roots, false);
    }

    TensorCiphertext tensor_ntt;
    for (BasisPoly& component : tensor_ntt) {
        component.resize(g_num_q);
    }
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        const U64 modulus = q_moduli[basis];
        tensor_ntt[0][basis] = pointwise_mul(
            left_ntt[0][basis], right_ntt[0][basis], modulus);
        tensor_ntt[1][basis] = add_poly(
            pointwise_mul(left_ntt[0][basis], right_ntt[1][basis], modulus),
            pointwise_mul(left_ntt[1][basis], right_ntt[0][basis], modulus),
            modulus);
        tensor_ntt[2][basis] = pointwise_mul(
            left_ntt[1][basis], right_ntt[1][basis], modulus);
    }

    TensorCiphertext tensor;
    for (std::size_t component = 0; component < 3; ++component) {
        tensor[component] = transform_basis(
            tensor_ntt[component], q_moduli, q_roots, true);
    }

    const std::size_t digit_size = g_num_q / g_dnum;
    std::vector<BasisPoly> modup_coeff(g_dnum);
    std::vector<BasisPoly> modup_ntt(g_dnum);
    std::array<BasisPoly, 2> accum_ntt;
    for (BasisPoly& component : accum_ntt) {
        component.assign(all_moduli.size(), Poly(g_n, 0));
    }
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        modup_coeff[digit] = modup(
            tensor[2], q_moduli, all_moduli, digit * digit_size, digit_size);
        modup_ntt[digit] = transform_basis(
            modup_coeff[digit], all_moduli, all_roots, false);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
                accum_ntt[component][basis] = add_poly(
                    accum_ntt[component][basis],
                    pointwise_mul(modup_ntt[digit][basis],
                                  rlk_ntt[digit][component][basis],
                                  all_moduli[basis]),
                    all_moduli[basis]);
            }
        }
    }

    std::array<BasisPoly, 2> accum_coeff;
    std::array<BasisPoly, 2> keyswitch_q;
    for (std::size_t component = 0; component < 2; ++component) {
        accum_coeff[component] = transform_basis(
            accum_ntt[component], all_moduli, all_roots, true);
        keyswitch_q[component] = moddown(
            accum_coeff[component], q_moduli, p_moduli);
    }

    Ciphertext output;
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        output[0].push_back(add_poly(
            tensor[0][basis], keyswitch_q[0][basis], q_moduli[basis]));
        output[1].push_back(add_poly(
            tensor[1][basis], keyswitch_q[1][basis], q_moduli[basis]));
    }
    verify_equal(
        decrypt_tensor(tensor, secret_q, q_moduli, q_roots),
        decrypt_ciphertext(output, secret_q, q_moduli, q_roots),
        "scheme multiply relinearization");
    if (trace != nullptr) {
        trace->left_ntt = std::move(left_ntt);
        trace->right_ntt = std::move(right_ntt);
        trace->tensor_ntt = std::move(tensor_ntt);
        trace->tensor_coeff = std::move(tensor);
        trace->modup_coeff = std::move(modup_coeff);
        trace->modup_ntt = std::move(modup_ntt);
        trace->keyswitch_accum_ntt = std::move(accum_ntt);
        trace->keyswitch_accum_coeff = std::move(accum_coeff);
        trace->keyswitch_q = std::move(keyswitch_q);
    }
    return output;
}

Ciphertext relinearize_tensor(
    const TensorCiphertext& tensor,
    const BasisPoly& secret_q,
    const EvaluationKey& rlk_ntt,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& p_moduli,
    const std::vector<U64>& all_moduli,
    const std::vector<U64>& q_roots,
    const std::vector<U64>& all_roots,
    SchemeMultiplyTrace* trace)
{
    const std::size_t digit_size = g_num_q / g_dnum;
    std::vector<BasisPoly> modup_coeff(g_dnum);
    std::vector<BasisPoly> modup_ntt(g_dnum);
    std::array<BasisPoly, 2> accum_ntt;
    for (BasisPoly& component : accum_ntt) {
        component.assign(all_moduli.size(), Poly(g_n, 0));
    }
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        modup_coeff[digit] = modup(
            tensor[2], q_moduli, all_moduli,
            digit * digit_size, digit_size);
        modup_ntt[digit] = transform_basis(
            modup_coeff[digit], all_moduli, all_roots, false);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
                accum_ntt[component][basis] = add_poly(
                    accum_ntt[component][basis],
                    pointwise_mul(
                        modup_ntt[digit][basis],
                        rlk_ntt[digit][component][basis],
                        all_moduli[basis]),
                    all_moduli[basis]);
            }
        }
    }

    std::array<BasisPoly, 2> accum_coeff;
    std::array<BasisPoly, 2> keyswitch_q;
    for (std::size_t component = 0; component < 2; ++component) {
        accum_coeff[component] = transform_basis(
            accum_ntt[component], all_moduli, all_roots, true);
        keyswitch_q[component] = moddown(
            accum_coeff[component], q_moduli, p_moduli);
    }

    Ciphertext output;
    for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
        output[0].push_back(add_poly(
            tensor[0][basis], keyswitch_q[0][basis], q_moduli[basis]));
        output[1].push_back(add_poly(
            tensor[1][basis], keyswitch_q[1][basis], q_moduli[basis]));
    }
    verify_equal(
        decrypt_tensor(tensor, secret_q, q_moduli, q_roots),
        decrypt_ciphertext(output, secret_q, q_moduli, q_roots),
        "BFV relinearization");
    if (trace != nullptr) {
        trace->tensor_coeff = tensor;
        trace->modup_coeff = std::move(modup_coeff);
        trace->modup_ntt = std::move(modup_ntt);
        trace->keyswitch_accum_ntt = std::move(accum_ntt);
        trace->keyswitch_accum_coeff = std::move(accum_coeff);
        trace->keyswitch_q = std::move(keyswitch_q);
    }
    return output;
}

BigInt crt_reconstruct(
    const BasisPoly& input,
    const std::vector<U64>& moduli,
    std::size_t coefficient)
{
    BigInt value = 0;
    BigInt product = 1;
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const U64 modulus = moduli[basis];
        const U64 current = big_mod_u64(value, modulus);
        const U64 product_modulus = big_mod_u64(product, modulus);
        const U64 digit = mul_mod(
            sub_mod(input[basis][coefficient], current, modulus),
            inverse_mod(product_modulus, modulus), modulus);
        value += product * digit;
        product *= modulus;
    }
    return value;
}

Poly decrypt_bfv_scale_and_round(
    const Ciphertext& ciphertext,
    const BasisPoly& secret_q,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& q_roots)
{
    const BasisPoly phase = decrypt_ciphertext(
        ciphertext, secret_q, q_moduli, q_roots);
    const BigInt Q = big_product(q_moduli);
    Poly plaintext(g_n);
    for (std::size_t coefficient = 0;
         coefficient < g_n; ++coefficient) {
        const BigInt value = crt_reconstruct(
            phase, q_moduli, coefficient);
        const BigInt rounded =
            (value * g_plaintext_modulus + Q / 2) / Q;
        plaintext[coefficient] = big_mod_u64(
            rounded, g_plaintext_modulus);
    }
    return plaintext;
}

Ciphertext automorphism_and_keyswitch(
    const Ciphertext& input,
    U64 galois_element,
    const BasisPoly& secret_q,
    const EvaluationKey& galois_key_ntt,
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& p_moduli,
    const std::vector<U64>& all_moduli,
    const std::vector<U64>& q_roots,
    const std::vector<U64>& all_roots)
{
    if (galois_key_ntt.size() != g_dnum || g_num_q % g_dnum != 0) {
        throw std::runtime_error("invalid Galois key for automorphism");
    }
    Ciphertext rotated;
    for (std::size_t component = 0; component < 2; ++component) {
        rotated[component] = apply_negacyclic_automorphism(
            input[component], galois_element, q_moduli);
    }

    const std::size_t digit_size = g_num_q / g_dnum;
    std::array<BasisPoly, 2> accum_ntt;
    for (BasisPoly& component : accum_ntt) {
        component.assign(all_moduli.size(), Poly(g_n, 0));
    }
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        const BasisPoly raised = modup(
            rotated[1], q_moduli, all_moduli,
            digit * digit_size, digit_size);
        const BasisPoly raised_ntt = transform_basis(
            raised, all_moduli, all_roots, false);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
                accum_ntt[component][basis] = add_poly(
                    accum_ntt[component][basis],
                    pointwise_mul(
                        raised_ntt[basis],
                        galois_key_ntt[digit][component][basis],
                        all_moduli[basis]),
                    all_moduli[basis]);
            }
        }
    }

    std::array<BasisPoly, 2> switched_q;
    for (std::size_t component = 0; component < 2; ++component) {
        switched_q[component] = moddown(
            transform_basis(accum_ntt[component], all_moduli, all_roots, true),
            q_moduli, p_moduli);
    }
    Ciphertext output;
    for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
        output[0].push_back(add_poly(
            rotated[0][basis], switched_q[0][basis], q_moduli[basis]));
        output[1].push_back(switched_q[1][basis]);
    }
    verify_equal(
        apply_negacyclic_automorphism(
            decrypt_ciphertext(input, secret_q, q_moduli, q_roots),
            galois_element, q_moduli),
        decrypt_ciphertext(output, secret_q, q_moduli, q_roots),
        "scheme automorphism plus Galois key switch");
    return output;
}

struct BgvModswitchTrace {
    BasisPoly output;
    Poly c_last_mod_t;
    Poly u_mod_t;
    BasisPoly c_last_mod_qprime;
    BasisPoly u_mod_qprime;
};

BgvModswitchTrace bgv_modswitch_drop_last(
    const BasisPoly& input_q,
    const std::vector<U64>& q_moduli,
    U64 plaintext_modulus)
{
    if (q_moduli.size() < 2 || input_q.size() != q_moduli.size()) {
        throw std::runtime_error("BGV ModSwitch requires matching Q with at least two limbs");
    }
    const U64 q_last = q_moduli.back();
    const U64 q_last_inverse_t = inverse_mod(q_last % plaintext_modulus, plaintext_modulus);
    BgvModswitchTrace trace;
    trace.c_last_mod_t.resize(g_n);
    trace.u_mod_t.resize(g_n);
    trace.output.assign(q_moduli.size() - 1, Poly(g_n));
    trace.c_last_mod_qprime.assign(q_moduli.size() - 1, Poly(g_n));
    trace.u_mod_qprime.assign(q_moduli.size() - 1, Poly(g_n));

    for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
        trace.c_last_mod_t[coefficient] =
            input_q.back()[coefficient] % plaintext_modulus;
        trace.u_mod_t[coefficient] = mul_mod(
            sub_mod(0, trace.c_last_mod_t[coefficient], plaintext_modulus),
            q_last_inverse_t,
            plaintext_modulus);
    }
    for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
        const U64 modulus = q_moduli[basis];
        const U64 q_last_mod_qi = q_last % modulus;
        const U64 q_last_inverse_qi = inverse_mod(q_last_mod_qi, modulus);
        for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
            const U64 c_last_qi = input_q.back()[coefficient] % modulus;
            const U64 u_qi = trace.u_mod_t[coefficient] % modulus;
            trace.c_last_mod_qprime[basis][coefficient] = c_last_qi;
            trace.u_mod_qprime[basis][coefficient] = u_qi;
            const U64 delta = add_mod(
                c_last_qi, mul_mod(q_last_mod_qi, u_qi, modulus), modulus);
            trace.output[basis][coefficient] = mul_mod(
                sub_mod(input_q[basis][coefficient], delta, modulus),
                q_last_inverse_qi,
                modulus);
        }
    }
    return trace;
}

std::vector<I128> exact_rns_to_centered(const BasisPoly& input,
                                        const std::vector<U64>& moduli)
{
    if (input.empty() || input.size() != moduli.size()) {
        throw std::runtime_error("centered RNS reconstruction requires a matching basis");
    }
    U128 basis_product = 1;
    for (U64 modulus : moduli) {
        if (basis_product > std::numeric_limits<U128>::max() / modulus) {
            throw std::runtime_error("centered RNS basis product exceeds uint128");
        }
        basis_product *= modulus;
    }

    std::vector<I128> output(g_n);
    for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
        U128 value = 0;
        U128 product = 1;
        for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
            const U64 modulus = moduli[basis];
            const U64 digit = mul_mod(
                sub_mod(input[basis][coefficient],
                        static_cast<U64>(value % modulus),
                        modulus),
                inverse_mod(static_cast<U64>(product % modulus), modulus),
                modulus);
            value += product * digit;
            product *= modulus;
        }
        output[coefficient] = value > basis_product / 2
            ? static_cast<I128>(value - basis_product)
            : static_cast<I128>(value);
    }
    return output;
}

std::vector<std::int64_t> centered_to_int64(
    const std::vector<I128>& coefficients,
    const std::string& label)
{
    std::vector<std::int64_t> output(coefficients.size());
    for (std::size_t i = 0; i < coefficients.size(); ++i) {
        if (coefficients[i] < std::numeric_limits<std::int64_t>::min()
            || coefficients[i] > std::numeric_limits<std::int64_t>::max()) {
            throw std::runtime_error(label + " coefficient exceeds int64");
        }
        output[i] = static_cast<std::int64_t>(coefficients[i]);
    }
    return output;
}

Poly centered_rns_to_modulus(const BasisPoly& input,
                             const std::vector<U64>& moduli,
                             U64 target_modulus)
{
    const auto centered = exact_rns_to_centered(input, moduli);
    Poly output(centered.size());
    for (std::size_t i = 0; i < centered.size(); ++i) {
        I128 reduced = centered[i] % static_cast<I128>(target_modulus);
        if (reduced < 0) {
            reduced += static_cast<I128>(target_modulus);
        }
        output[i] = static_cast<U64>(reduced);
    }
    return output;
}

std::vector<std::int64_t> scale_signed_message(
    const std::vector<std::int64_t>& input,
    U64 factor)
{
    std::vector<std::int64_t> output(input.size());
    for (std::size_t i = 0; i < input.size(); ++i) {
        const I128 scaled = static_cast<I128>(input[i]) * factor;
        if (scaled < std::numeric_limits<std::int64_t>::min()
            || scaled > std::numeric_limits<std::int64_t>::max()) {
            throw std::runtime_error("scaled test message exceeds int64");
        }
        output[i] = static_cast<std::int64_t>(scaled);
    }
    return output;
}

std::vector<std::int64_t> plaintext_product(const std::vector<std::int64_t>& left,
                                            const std::vector<std::int64_t>& right)
{
    std::vector<std::int64_t> out(g_n, 0);
    for (std::size_t i = 0; i < g_n; ++i) {
        for (std::size_t j = 0; j < g_n; ++j) {
            const std::int64_t term = left[i] * right[j];
            const std::size_t index = i + j;
            if (index < g_n) {
                out[index] += term;
            } else {
                out[index - g_n] -= term;
            }
        }
    }
    return out;
}

U64 fnv1a_words(const std::vector<U64>& words)
{
    U64 hash = kFnv1a64OffsetBasis;
    for (U64 word : words) {
        for (int byte = 0; byte < 8; ++byte) {
            hash ^= (word >> (8 * byte)) & 0xffU;
            hash *= 1099511628211ULL;
        }
    }
    return hash;
}

U64 fnv1a_words32(const std::vector<U32>& words)
{
    U64 hash = kFnv1a64OffsetBasis;
    for (U32 word : words) {
        for (int byte = 0; byte < 4; ++byte) {
            hash ^= (word >> (8 * byte)) & 0xffU;
            hash *= 1099511628211ULL;
        }
    }
    return hash;
}

U32 checked_u32(U64 value, const std::string& label)
{
    if (value > std::numeric_limits<U32>::max()) {
        throw std::runtime_error(label + " does not fit the 32-bit HPU coefficient ABI");
    }
    return static_cast<U32>(value);
}

std::vector<U32> to_u32_words(const std::vector<U64>& words, const std::string& label)
{
    std::vector<U32> out;
    out.reserve(words.size());
    for (U64 word : words) {
        out.push_back(checked_u32(word, label));
    }
    return out;
}

struct NttBatch {
    bool interleaved = false;
    std::size_t first = 0;
    std::size_t second = 0;
};

std::size_t bit_reverse_index(std::size_t value, std::size_t n)
{
    std::size_t reversed = 0;
    for (std::size_t bits = n; bits > 1; bits >>= 1U) {
        reversed = (reversed << 1U) | (value & 1U);
        value >>= 1U;
    }
    return reversed;
}

std::vector<NttBatch> ntt_stage_batches(std::size_t n, std::size_t stage)
{
    constexpr std::size_t kArrayWidth = 128;
    constexpr std::size_t kHalfArray = 64;
    const std::size_t m = std::size_t{1} << stage;
    std::vector<NttBatch> batches;
    batches.reserve(n / kArrayWidth);
    if (m < kArrayWidth) {
        for (std::size_t base = 0; base < n; base += kArrayWidth) {
            batches.push_back({false, base, base + kHalfArray});
        }
    } else {
        for (std::size_t group = 0; group < n; group += 2 * m) {
            for (std::size_t offset = 0; offset < m; offset += kHalfArray) {
                batches.push_back({true, group + offset, group + m + offset});
            }
        }
    }
    return batches;
}

template <typename T>
std::pair<std::array<T, 128>, std::array<std::size_t, 128>>
load_ntt_batch(const std::vector<T>& values, const NttBatch& batch)
{
    std::array<T, 128> registers {};
    std::array<std::size_t, 128> positions {};
    if (!batch.interleaved) {
        for (std::size_t i = 0; i < registers.size(); ++i) {
            positions[i] = batch.first + i;
            registers[i] = values[positions[i]];
        }
    } else {
        for (std::size_t i = 0; i < registers.size() / 2; ++i) {
            positions[2 * i] = batch.first + i;
            positions[2 * i + 1] = batch.second + i;
            registers[2 * i] = values[positions[2 * i]];
            registers[2 * i + 1] = values[positions[2 * i + 1]];
        }
    }
    return {registers, positions};
}

template <typename T>
void store_ntt_batch(std::vector<T>& values,
                     const std::array<T, 128>& registers,
                     const std::array<std::size_t, 128>& positions)
{
    for (std::size_t i = 0; i < registers.size(); ++i) {
        values[positions[i]] = registers[i];
    }
}

template <typename T>
std::array<T, 128> apply_p_network(std::array<T, 128> registers,
                                   std::size_t count = 1)
{
    for (std::size_t rotation = 0; rotation < count % 7; ++rotation) {
        std::array<T, 128> shifted {};
        for (std::size_t old_position = 0; old_position < registers.size(); ++old_position) {
            const std::size_t new_position =
                (old_position >> 1U) | ((old_position & 1U) << 6U);
            shifted[new_position] = registers[old_position];
        }
        registers = shifted;
    }
    return registers;
}

std::vector<std::size_t> hardware_ntt_layout(std::size_t n)
{
    if (n < 128 || (n & (n - 1)) != 0 || n % 128 != 0) {
        throw std::runtime_error("hardware NTT layout requires power-of-two N >= 128");
    }
    std::vector<std::size_t> labels(n);
    std::iota(labels.begin(), labels.end(), 0);
    const std::size_t log_n = static_cast<std::size_t>(std::log2(static_cast<double>(n)));
    for (std::size_t stage = 0; stage < log_n; ++stage) {
        for (const NttBatch& batch : ntt_stage_batches(n, stage)) {
            auto loaded = load_ntt_batch(labels, batch);
            loaded.first = apply_p_network(loaded.first);
            store_ntt_batch(labels, loaded.first, loaded.second);
        }
    }
    return labels;
}

std::vector<U32> to_hardware_words(const Artifact& artifact)
{
    if (artifact.shape.empty() || artifact.shape.back() != g_n
        || artifact.words.size() % g_n != 0) {
        throw std::runtime_error(
            artifact.path + " does not have a complete polynomial as its innermost axis");
    }

    const std::vector<U32> logical = to_u32_words(artifact.words, artifact.path);
    std::vector<U32> physical(logical.size());
    const std::vector<std::size_t> ntt_layout = hardware_ntt_layout(g_n);
    for (std::size_t block = 0; block < logical.size() / g_n; ++block) {
        const std::size_t base = block * g_n;
        for (std::size_t position = 0; position < g_n; ++position) {
            const std::size_t logical_index =
                artifact.hardware_domain == HardwareDomain::kNtt
                ? ntt_layout[position]
                : bit_reverse_index(position, g_n);
            physical[base + position] = logical[base + logical_index];
        }
    }
    return physical;
}

void append_words(std::vector<U64>& out, const Poly& poly)
{
    out.insert(out.end(), poly.begin(), poly.end());
}

void append_words(std::vector<U64>& out, const BasisPoly& basis)
{
    for (const Poly& poly : basis) {
        append_words(out, poly);
    }
}

void write_binary(const std::filesystem::path& path, const std::vector<U64>& words)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to create " + path.string());
    }
    for (U64 word : words) {
        for (int byte = 0; byte < 8; ++byte) {
            output.put(static_cast<char>((word >> (8 * byte)) & 0xffU));
        }
    }
}

void write_binary32(const std::filesystem::path& path, const std::vector<U32>& words)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to create " + path.string());
    }
    for (U32 word : words) {
        for (int byte = 0; byte < 4; ++byte) {
            output.put(static_cast<char>((word >> (8 * byte)) & 0xffU));
        }
    }
}

void write_text(const std::filesystem::path& path, const std::string& text)
{
    std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path);
    if (!output) {
        throw std::runtime_error("failed to create " + path.string());
    }
    output << text;
}

std::string hex64(U64 value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

std::string hex32(U32 value)
{
    std::ostringstream out;
    out << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
    return out.str();
}

std::string shape_string(const std::vector<std::size_t>& shape)
{
    std::ostringstream out;
    for (std::size_t i = 0; i < shape.size(); ++i) {
        if (i != 0) {
            out << 'x';
        }
        out << shape[i];
    }
    return out.str();
}

std::string csv_field(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (char ch : value) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

struct HostArtifact {
    std::string path;
    std::string role;
    std::string contents;
};

struct DmaSpan {
    std::string logical_object;
    std::string artifact;
    U64 line_offset = 0;
    U64 line_count = 0;
};

struct PlannedDma {
    std::string direction;
    int object_slot = 0;
    DmaSpan span;
};

std::vector<std::string> parse_csv_row(const std::string& row)
{
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (std::size_t i = 0; i < row.size(); ++i) {
        const char ch = row[i];
        if (ch == '"') {
            if (quoted && i + 1 < row.size() && row[i + 1] == '"') {
                field.push_back('"');
                ++i;
            } else {
                quoted = !quoted;
            }
        } else if (ch == ',' && !quoted) {
            fields.push_back(field);
            field.clear();
        } else {
            field.push_back(ch);
        }
    }
    fields.push_back(field);
    return fields;
}

std::map<std::string, std::pair<U64, U64>> read_line_catalog(
    const std::filesystem::path& line_map_path)
{
    std::ifstream input(line_map_path);
    if (!input) {
        throw std::runtime_error("failed to open " + line_map_path.string());
    }
    std::map<std::string, std::pair<U64, U64>> catalog;
    std::string row;
    std::getline(input, row);
    while (std::getline(input, row)) {
        const auto fields = parse_csv_row(row);
        if (fields.size() < 6) {
            throw std::runtime_error("invalid hardware line_map row");
        }
        catalog.emplace(
            fields[0], std::make_pair(
                static_cast<U64>(std::stoull(fields[4])),
                static_cast<U64>(std::stoull(fields[5]))));
    }
    return catalog;
}

class DmaPlanBuilder {
public:
    explicit DmaPlanBuilder(
        std::map<std::string, std::pair<U64, U64>> catalog)
        : catalog_(std::move(catalog)), poly_lines_(g_n / kHpuWordsPerLine)
    {
        if (poly_lines_ == 0) {
            throw std::runtime_error("invalid zero-line polynomial span");
        }
    }

    DmaSpan poly(
        const std::string& artifact,
        std::size_t poly_index,
        const std::string& logical_object) const
    {
        const auto found = catalog_.find(artifact);
        if (found == catalog_.end()) {
            throw std::runtime_error("DMA plan artifact is absent from line_map: " + artifact);
        }
        const U64 sub_offset = static_cast<U64>(poly_index) * poly_lines_;
        if (sub_offset + poly_lines_ > found->second.second) {
            throw std::runtime_error("DMA polynomial subspan exceeds artifact: " + artifact);
        }
        return {logical_object, artifact, found->second.first + sub_offset, poly_lines_};
    }

    DmaSpan whole(
        const std::string& artifact,
        const std::string& logical_object) const
    {
        const auto found = catalog_.find(artifact);
        if (found == catalog_.end()) {
            throw std::runtime_error("DMA plan artifact is absent from line_map: " + artifact);
        }
        return {logical_object, artifact, found->second.first, found->second.second};
    }

    void load(int object_slot, const DmaSpan& span)
    {
        records_.push_back({"dload", object_slot, span});
    }

    void store(int object_slot, const DmaSpan& span)
    {
        records_.push_back({"dstore", object_slot, span});
    }

    void load_mod_context()
    {
        load(4, whole("constants/mod_ctx.u32.bin", "mod_context_table"));
    }

    void bconv(
        const std::vector<DmaSpan>& source,
        const std::vector<DmaSpan>& source_hat_inverse,
        const std::vector<std::vector<DmaSpan>>& source_hat_mod_target,
        const std::vector<DmaSpan>& normalized_scratch,
        const std::vector<DmaSpan>& target)
    {
        if (source.empty() || source.size() != source_hat_inverse.size()
            || source.size() != normalized_scratch.size()
            || target.size() != source_hat_mod_target.size()) {
            throw std::runtime_error("invalid planned BConv dimensions");
        }
        load_mod_context();
        for (std::size_t source_index = 0; source_index < source.size(); ++source_index) {
            load(0, source[source_index]);
            load(1, source_hat_inverse[source_index]);
            store(0, normalized_scratch[source_index]);
        }
        for (std::size_t target_index = 0; target_index < target.size(); ++target_index) {
            if (source_hat_mod_target[target_index].size() != source.size()) {
                throw std::runtime_error("invalid planned BConv target matrix");
            }
            for (std::size_t source_index = 0; source_index < source.size(); ++source_index) {
                load(0, normalized_scratch[source_index]);
                load(1, source_hat_mod_target[target_index][source_index]);
            }
            store(2, target[target_index]);
        }
    }

    void transform(
        const std::vector<std::vector<DmaSpan>>& components,
        const std::vector<int>& contexts,
        bool inverse)
    {
        transform_between(components, components, contexts, inverse);
    }

    void transform_between(
        const std::vector<std::vector<DmaSpan>>& input_components,
        const std::vector<std::vector<DmaSpan>>& output_components,
        const std::vector<int>& contexts,
        bool inverse)
    {
        if (input_components.empty()) {
            return;
        }
        if (input_components.size() != output_components.size()) {
            throw std::runtime_error("invalid planned transform component count");
        }
        load_mod_context();
        const std::size_t stages = u64_bit_length(g_n) - 1;
        for (std::size_t component_index = 0;
             component_index < input_components.size(); ++component_index) {
            const auto& input = input_components[component_index];
            const auto& output = output_components[component_index];
            if (input.size() != contexts.size()
                || output.size() != contexts.size()) {
                throw std::runtime_error("invalid planned transform dimensions");
            }
            for (std::size_t basis = 0; basis < contexts.size(); ++basis) {
                load(0, input[basis]);
                if (!inverse) {
                    load(3, twiddle("ntt", contexts[basis], "pre_twist", -1));
                }
                for (std::size_t stage = 0; stage < stages; ++stage) {
                    load(3, twiddle(
                        inverse ? "intt" : "ntt", contexts[basis],
                        "stage", static_cast<int>(stage)));
                }
                if (inverse) {
                    load(3, twiddle(
                        "intt", contexts[basis], "post_untwist_scale", -1));
                }
                store(0, output[basis]);
            }
        }
    }

    void tensor(
        const std::array<std::vector<DmaSpan>, 4>& input,
        const std::array<std::vector<DmaSpan>, 3>& output)
    {
        load_mod_context();
        for (std::size_t basis = 0; basis < input[0].size(); ++basis) {
            load(0, input[0][basis]); load(1, input[2][basis]);
            store(2, output[0][basis]);
            load(0, input[0][basis]); load(1, input[3][basis]);
            load(0, input[1][basis]); load(1, input[2][basis]);
            store(2, output[1][basis]);
            load(0, input[1][basis]); load(1, input[3][basis]);
            store(2, output[2][basis]);
        }
    }

    void scalar_multiply(
        const std::vector<std::vector<DmaSpan>>& components,
        const std::vector<DmaSpan>& scalar)
    {
        load_mod_context();
        for (const auto& component : components) {
            for (std::size_t basis = 0; basis < component.size(); ++basis) {
                load(0, component[basis]);
                load(1, scalar[basis]);
                store(0, component[basis]);
            }
        }
    }

    const std::vector<PlannedDma>& records() const { return records_; }

private:
    DmaSpan twiddle(
        const std::string& direction,
        int basis,
        const std::string& phase,
        int stage) const
    {
        std::ostringstream path;
        path << "constants/twiddle/" << direction << "/basis_"
             << std::setw(2) << std::setfill('0') << basis << '/';
        if (phase == "stage") {
            path << "stage_" << std::setw(2) << std::setfill('0') << stage;
        } else {
            path << phase;
        }
        path << ".u32.bin";
        return whole(path.str(), direction + "_twiddle_ctx_" + std::to_string(basis));
    }

    std::map<std::string, std::pair<U64, U64>> catalog_;
    U64 poly_lines_;
    std::vector<PlannedDma> records_;
};

std::vector<PlannedDma> rebase_dma_records(
    const std::vector<PlannedDma>& planned,
    const std::map<std::string, std::pair<U64, U64>>& old_catalog,
    const std::map<std::string, std::pair<U64, U64>>& new_catalog)
{
    std::vector<PlannedDma> rebased = planned;
    for (PlannedDma& entry : rebased) {
        const auto old_span = old_catalog.find(entry.span.artifact);
        const auto new_span = new_catalog.find(entry.span.artifact);
        if (old_span == old_catalog.end() || new_span == new_catalog.end()) {
            throw std::runtime_error(
                "cannot rebase DMA artifact: " + entry.span.artifact);
        }
        if (entry.span.line_offset < old_span->second.first) {
            throw std::runtime_error(
                "DMA subspan precedes its artifact: " + entry.span.artifact);
        }
        const U64 relative_offset =
            entry.span.line_offset - old_span->second.first;
        if (relative_offset + entry.span.line_count > new_span->second.second) {
            throw std::runtime_error(
                "rebased DMA subspan exceeds artifact: " + entry.span.artifact);
        }
        entry.span.line_offset = new_span->second.first + relative_offset;
    }
    return rebased;
}

void write_resolved_dma_plan(
    const std::filesystem::path& suite_root,
    const std::string& case_name,
    const std::vector<PlannedDma>& planned)
{
    const auto manifest_path = suite_root / case_name / "dma_relocation_manifest.csv";
    std::ifstream manifest(manifest_path);
    if (!manifest) {
        throw std::runtime_error("missing DMA relocation manifest: " + manifest_path.string());
    }
    std::string header;
    std::getline(manifest, header);
    std::vector<std::vector<std::string>> relocation;
    std::string row;
    while (std::getline(manifest, row)) {
        relocation.push_back(parse_csv_row(row));
    }
    if (relocation.size() != planned.size()) {
        throw std::runtime_error(
            case_name + " resolved DMA plan count differs from encoded relocation manifest");
    }

    std::ostringstream output;
    output << "instruction_index,dma_index,direction,object_slot,logical_object,artifact,line_offset,line_count,status\n";
    for (std::size_t index = 0; index < planned.size(); ++index) {
        if (relocation[index].size() < 4) {
            throw std::runtime_error("invalid DMA relocation manifest row");
        }
        const auto& entry = planned[index];
        if (relocation[index][2] != entry.direction
            || std::stoi(relocation[index][3]) != entry.object_slot) {
            throw std::runtime_error(
                case_name + " planned DMA direction/object differs at index "
                + std::to_string(index));
        }
        output << relocation[index][0] << ',' << relocation[index][1] << ','
               << entry.direction << ',' << entry.object_slot << ','
               << csv_field(entry.span.logical_object) << ','
               << csv_field(entry.span.artifact) << ','
               << entry.span.line_offset << ',' << entry.span.line_count
               << ",RESOLVED\n";
    }
    write_text(
        suite_root / case_name / "test_data" / "dma_plan.csv",
        output.str());
}

U64 fnv1a_text(const std::string& text)
{
    U64 hash = kFnv1a64OffsetBasis;
    for (unsigned char byte : text) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

void write_host_package(
    const std::filesystem::path& test_data_root,
    const std::vector<HostArtifact>& artifacts)
{
    const auto host_root = test_data_root / "host";
    std::filesystem::remove_all(host_root);
    std::ostringstream manifest;
    manifest << "path,role,bytes,fnv1a64\n";
    for (const HostArtifact& artifact : artifacts) {
        write_text(host_root / artifact.path, artifact.contents);
        manifest << csv_field(artifact.path) << ','
                 << csv_field(artifact.role) << ','
                 << artifact.contents.size() << ','
                 << hex64(fnv1a_text(artifact.contents)) << '\n';
    }
    write_text(host_root / "host_manifest.csv", manifest.str());
}

std::string complex_slots_csv(
    const std::vector<std::complex<double>>& values,
    const std::string& value_name)
{
    std::ostringstream output;
    output << "slot," << value_name << "_real," << value_name << "_imag\n";
    output << std::setprecision(17);
    for (std::size_t slot = 0; slot < values.size(); ++slot) {
        output << slot << ',' << values[slot].real() << ','
               << values[slot].imag() << '\n';
    }
    return output.str();
}

std::string signed_values_csv(
    const std::vector<std::int64_t>& values,
    const std::string& value_name)
{
    std::ostringstream output;
    output << "index," << value_name << '\n';
    for (std::size_t index = 0; index < values.size(); ++index) {
        output << index << ',' << values[index] << '\n';
    }
    return output.str();
}

template <typename T>
std::vector<T> rotate_slots_left(const std::vector<T>& values)
{
    if (values.empty()) {
        return {};
    }
    std::vector<T> rotated(values.size());
    for (std::size_t index = 0; index < values.size(); ++index) {
        rotated[index] = values[(index + 1) % values.size()];
    }
    return rotated;
}

std::string seal_oracle_parameters_csv(
    const std::vector<U64>& q_moduli,
    const std::vector<U64>& p_moduli,
    double ckks_input_scale,
    double ckks_output_scale,
    double ckks_roundtrip_error_bound,
    double ckks_multiply_error_bound,
    double ckks_rotation_error_bound)
{
    if (p_moduli.empty()) {
        throw std::runtime_error("SEAL oracle requires at least one special modulus");
    }

    std::ostringstream output;
    output << "name,index,value\n";
    output << "poly_modulus_degree,," << g_n << '\n';
    for (std::size_t index = 0; index < q_moduli.size(); ++index) {
        output << "coeff_modulus_q," << index << ',' << q_moduli[index] << '\n';
    }
    output << "special_modulus_p,0," << p_moduli.front() << '\n';
    output << "plain_modulus,," << g_plaintext_modulus << '\n';
    output << "seed,," << g_seed << '\n';
    output << std::setprecision(17);
    output << "ckks_input_scale,," << ckks_input_scale << '\n';
    output << "ckks_output_scale,," << ckks_output_scale << '\n';
    output << "ckks_roundtrip_error_bound,,"
           << ckks_roundtrip_error_bound << '\n';
    output << "ckks_multiply_error_bound,,"
           << ckks_multiply_error_bound << '\n';
    output << "ckks_rotation_error_bound,,"
           << ckks_rotation_error_bound << '\n';
    output << "rotation_step,,1\n";
    return output.str();
}

std::string residues_csv(const Poly& values, const std::string& value_name)
{
    std::ostringstream output;
    output << "index," << value_name << '\n';
    for (std::size_t index = 0; index < values.size(); ++index) {
        output << index << ',' << values[index] << '\n';
    }
    return output.str();
}

std::string complex_comparison_csv(
    const std::vector<std::complex<double>>& expected,
    const std::vector<std::complex<double>>& actual)
{
    if (expected.size() != actual.size()) {
        throw std::runtime_error("complex comparison size mismatch");
    }
    std::ostringstream output;
    output << "slot,expected_real,expected_imag,actual_real,actual_imag,abs_error\n";
    output << std::setprecision(17);
    for (std::size_t slot = 0; slot < expected.size(); ++slot) {
        output << slot << ',' << expected[slot].real() << ','
               << expected[slot].imag() << ',' << actual[slot].real() << ','
               << actual[slot].imag() << ','
               << std::abs(actual[slot] - expected[slot]) << '\n';
    }
    return output.str();
}

std::string signed_comparison_csv(
    const std::vector<std::int64_t>& expected,
    const std::vector<std::int64_t>& actual)
{
    if (expected.size() != actual.size()) {
        throw std::runtime_error("signed comparison size mismatch");
    }
    std::ostringstream output;
    output << "slot,expected,actual,equal\n";
    for (std::size_t slot = 0; slot < expected.size(); ++slot) {
        output << slot << ',' << expected[slot] << ',' << actual[slot] << ','
               << (expected[slot] == actual[slot] ? 1 : 0) << '\n';
    }
    return output.str();
}

std::string residues_comparison_csv(
    const Poly& expected,
    const Poly& actual)
{
    if (expected.size() != actual.size()) {
        throw std::runtime_error("residue comparison size mismatch");
    }
    std::ostringstream output;
    output << "index,expected,actual,equal\n";
    for (std::size_t index = 0; index < expected.size(); ++index) {
        output << index << ',' << expected[index] << ',' << actual[index] << ','
               << (expected[index] == actual[index] ? 1 : 0) << '\n';
    }
    return output.str();
}

void add_artifact(std::vector<Artifact>& artifacts,
                  std::string path,
                  std::string role,
                  std::vector<std::size_t> shape,
                  std::vector<U64> words,
                  std::vector<std::string> axes = {},
                  HardwareDomain hardware_domain = HardwareDomain::kCoefficient,
                  bool hardware_visible = true)
{
    Artifact artifact{
        std::move(path),
        std::move(role),
        std::move(shape),
        std::move(words),
        std::move(axes),
        hardware_domain,
        hardware_visible,
        0};
    artifact.checksum = fnv1a_words(artifact.words);
    artifacts.push_back(std::move(artifact));
}

void add_scheme_multiply_artifacts(
    std::vector<Artifact>& artifacts,
    const Ciphertext& left,
    const Ciphertext& right,
    const SchemeMultiplyTrace& trace,
    const EvaluationKey& rlk_ntt,
    const Ciphertext& output)
{
    std::vector<U64> words;
    append_words(words, left[0]);
    append_words(words, left[1]);
    add_artifact(artifacts, "input/ct_a_q.bin", "left ciphertext, coefficient domain",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
    words.clear();
    append_words(words, right[0]);
    append_words(words, right[1]);
    add_artifact(artifacts, "input/ct_b_q.bin", "right ciphertext, coefficient domain",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
    words.clear();
    for (const auto& digit : rlk_ntt) {
        append_words(words, digit[0]);
        append_words(words, digit[1]);
    }
    add_artifact(artifacts, "constants/relinearization_key_ntt_qp.bin",
                 "relinearization key",
                 {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    append_words(words, trace.left_ntt[0]);
    append_words(words, trace.left_ntt[1]);
    append_words(words, trace.right_ntt[0]);
    append_words(words, trace.right_ntt[1]);
    add_artifact(artifacts, "expected/inputs_ntt_q.bin", "NTT inputs A0,A1,B0,B1",
                 {4, g_num_q, g_n}, std::move(words),
                 {"input_component[A0,A1,B0,B1]", "basis_q", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    for (const BasisPoly& component : trace.tensor_ntt) {
        append_words(words, component);
    }
    add_artifact(artifacts, "expected/tensor_ntt_q.bin", "tensor t0,t1,t2, NTT domain",
                 {3, g_num_q, g_n}, std::move(words),
                 {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    for (const BasisPoly& component : trace.tensor_coeff) {
        append_words(words, component);
    }
    add_artifact(artifacts, "expected/tensor_coeff_q.bin", "tensor t0,t1,t2, coefficient domain",
                 {3, g_num_q, g_n}, std::move(words),
                 {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"});
    words.clear();
    for (const BasisPoly& digit : trace.modup_coeff) {
        append_words(words, digit);
    }
    add_artifact(artifacts, "expected/modup_t2_coeff_qp.bin", "digit ModUp output",
                 {g_dnum, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "basis_q_then_p", "coefficient"});
    words.clear();
    for (const BasisPoly& digit : trace.modup_ntt) {
        append_words(words, digit);
    }
    add_artifact(artifacts, "expected/modup_t2_ntt_qp.bin", "digit ModUp output, NTT domain",
                 {g_dnum, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "basis_q_then_p", "coefficient"}, HardwareDomain::kNtt);
    words.clear();
    append_words(words, trace.keyswitch_accum_ntt[0]);
    append_words(words, trace.keyswitch_accum_ntt[1]);
    add_artifact(artifacts, "expected/keyswitch_accum_ntt_qp.bin", "key-switch accumulators",
                 {2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    append_words(words, trace.keyswitch_accum_coeff[0]);
    append_words(words, trace.keyswitch_accum_coeff[1]);
    add_artifact(artifacts, "expected/keyswitch_accum_coeff_qp.bin",
                 "key-switch accumulators, coefficient domain",
                 {2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q_then_p", "coefficient"});
    words.clear();
    append_words(words, trace.keyswitch_q[0]);
    append_words(words, trace.keyswitch_q[1]);
    add_artifact(artifacts, "expected/keyswitch_moddown_q.bin", "ModDown key-switch result",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q", "coefficient"});
    words.clear();
    append_words(words, output[0]);
    append_words(words, output[1]);
    add_artifact(artifacts, "expected/ciphertext_out_q.bin", "relinearized ciphertext",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
}

std::filesystem::path readable_path(const std::filesystem::path& binary_path)
{
    std::filesystem::path path = binary_path;
    path.replace_extension(".dec.txt");
    return path;
}

std::vector<std::string> artifact_axes(const Artifact& artifact)
{
    if (artifact.axes.size() == artifact.shape.size()) {
        return artifact.axes;
    }
    std::vector<std::string> axes;
    axes.reserve(artifact.shape.size());
    for (std::size_t i = 0; i < artifact.shape.size(); ++i) {
        axes.push_back(i + 1 == artifact.shape.size()
            ? "coefficient"
            : "dimension_" + std::to_string(i));
    }
    return axes;
}

void write_readable_artifact(const std::filesystem::path& root,
                             const Artifact& artifact)
{
    const std::vector<std::string> axes = artifact_axes(artifact);
    std::ostringstream output;
    output << "# HPU golden data readable view\n"
           << "# source_binary: " << artifact.path << "\n"
           << "# role: " << artifact.role << "\n"
           << "# shape: " << shape_string(artifact.shape) << "\n"
           << "# encoding: canonical residue, uint64, little-endian in the binary file\n"
           << "# text_values: unsigned decimal\n"
           << "# axes: ";
    for (std::size_t i = 0; i < axes.size(); ++i) {
        output << (i ? ", " : "") << axes[i] << '=' << artifact.shape[i];
    }
    output << "\n# The last axis is stored contiguously; outer axes use row-major order.\n";

    const std::size_t coefficients = artifact.shape.empty() ? artifact.words.size() : artifact.shape.back();
    const std::size_t blocks = coefficients == 0 ? 0 : artifact.words.size() / coefficients;
    for (std::size_t block = 0; block < blocks; ++block) {
        if (artifact.shape.size() > 1) {
            output << "\n# block ";
            std::size_t remaining = block;
            std::vector<std::size_t> coordinates(artifact.shape.size() - 1);
            for (std::size_t reverse = artifact.shape.size() - 1; reverse > 0; --reverse) {
                const std::size_t dimension = reverse - 1;
                coordinates[dimension] = remaining % artifact.shape[dimension];
                remaining /= artifact.shape[dimension];
            }
            for (std::size_t dimension = 0; dimension < coordinates.size(); ++dimension) {
                output << (dimension ? ", " : "") << axes[dimension]
                       << '=' << coordinates[dimension];
            }
            output << "\n";
        }

        for (std::size_t offset = 0; offset < coefficients; offset += 8) {
            const std::size_t end = std::min(offset + 8, coefficients);
            output << std::dec << std::setw(6) << std::setfill('0') << offset
                   << '-' << std::setw(6) << (end - 1) << ":";
            for (std::size_t coefficient = offset; coefficient < end; ++coefficient) {
                const U64 value = artifact.words[block * coefficients + coefficient];
                output << ' ' << std::dec << value;
            }
            output << '\n';
        }
    }

    write_text(root / readable_path(artifact.path), output.str());
}

std::filesystem::path hardware_image_path(const std::filesystem::path& golden_path)
{
    std::filesystem::path path = std::filesystem::path("images") / golden_path;
    path.replace_extension(".u32.bin");
    return path;
}

std::size_t add_hardware_image(std::vector<HardwareImage>& images,
                               std::string path,
                               std::string role,
                               std::vector<std::size_t> shape,
                               std::vector<U32> payload_words)
{
    if (payload_words.empty()) {
        throw std::runtime_error("hardware image payload is empty: " + path);
    }
    HardwareImage image;
    image.path = std::move(path);
    image.role = std::move(role);
    image.shape = std::move(shape);
    image.payload_words = std::move(payload_words);
    image.padded_words = image.payload_words;
    const std::size_t padded_size =
        (image.padded_words.size() + kHpuWordsPerLine - 1) / kHpuWordsPerLine * kHpuWordsPerLine;
    image.padded_words.resize(padded_size, 0);
    image.payload_checksum = fnv1a_words32(image.payload_words);
    image.image_checksum = fnv1a_words32(image.padded_words);
    images.push_back(std::move(image));
    return images.size() - 1;
}

void write_readable_hardware_image(const std::filesystem::path& hardware_root,
                                   const HardwareImage& image)
{
    std::ostringstream output;
    output << "# HPU uint32 hardware image\n"
           << "# source_binary: " << image.path << "\n"
           << "# role: " << image.role << "\n"
           << "# logical_shape: " << shape_string(image.shape) << "\n"
           << "# encoding: uint32 little-endian canonical residue or ABI field\n"
           << "# text_values: unsigned decimal\n"
           << "# payload_words: " << image.payload_words.size() << "\n"
           << "# padded_words: " << image.padded_words.size() << "\n"
           << "# hpu_line_offset: " << image.line_offset << "\n"
           << "# hpu_line_count: " << image.padded_words.size() / kHpuWordsPerLine << "\n"
           << "# one HPU line is 64 uint32 words (256 bytes); zero words after payload are padding.\n";

    for (std::size_t line = 0; line < image.padded_words.size() / kHpuWordsPerLine; ++line) {
        output << "\n# line " << line << " (HPU_MEM line " << image.line_offset + line << ")\n";
        for (std::size_t offset = 0; offset < kHpuWordsPerLine; offset += 8) {
            const std::size_t word_index = line * kHpuWordsPerLine + offset;
            output << std::dec << std::setw(8) << std::setfill('0') << word_index << ":";
            for (std::size_t lane = 0; lane < 8; ++lane) {
                output << ' ' << std::dec << image.padded_words[word_index + lane];
            }
            if (word_index >= image.payload_words.size()) {
                output << "  # padding";
            } else if (word_index + 8 > image.payload_words.size()) {
                output << "  # payload then padding";
            }
            output << '\n';
        }
    }
    write_text(hardware_root / readable_path(image.path), output.str());
}

U64 barrett_mu64(U64 modulus)
{
    if (modulus <= 1) {
        throw std::runtime_error("Barrett modulus must be greater than one");
    }
    return static_cast<U64>((static_cast<U128>(1) << 64U) / modulus);
}

std::vector<std::vector<U32>> hardware_ntt_twiddle_tables(U64 omega, U64 modulus)
{
    const std::size_t log_n = static_cast<std::size_t>(
        std::log2(static_cast<double>(g_n)));
    std::vector<std::size_t> labels(g_n);
    std::iota(labels.begin(), labels.end(), 0);
    std::vector<std::vector<U32>> tables;
    tables.reserve(log_n);

    for (std::size_t stage = 0; stage < log_n; ++stage) {
        const std::size_t m = std::size_t{1} << stage;
        std::vector<U32> words;
        words.reserve(g_n / 2);
        for (const NttBatch& batch : ntt_stage_batches(g_n, stage)) {
            auto loaded = load_ntt_batch(labels, batch);
            for (std::size_t lane = 0; lane < 64; ++lane) {
                const std::size_t lower = loaded.first[2 * lane];
                const std::size_t upper = loaded.first[2 * lane + 1];
                if (upper != lower + m) {
                    throw std::runtime_error("forward NTT physical lane pairing mismatch");
                }
                const U64 exponent = static_cast<U64>((lower % m) * g_n / (2 * m));
                words.push_back(checked_u32(
                    pow_mod(omega, exponent, modulus), "forward stage twiddle"));
            }
            loaded.first = apply_p_network(loaded.first);
            store_ntt_batch(labels, loaded.first, loaded.second);
        }
        if (words.size() != g_n / 2) {
            throw std::runtime_error("forward NTT stage twiddle count is not N/2");
        }
        tables.push_back(std::move(words));
    }
    return tables;
}

std::vector<std::vector<U32>> hardware_intt_twiddle_tables(U64 omega, U64 modulus)
{
    const std::size_t log_n = static_cast<std::size_t>(
        std::log2(static_cast<double>(g_n)));
    std::vector<std::size_t> labels = hardware_ntt_layout(g_n);
    std::vector<U64> scales(g_n, 1);
    std::vector<std::vector<U32>> tables;
    tables.reserve(log_n);

    for (std::size_t inverse_stage = 0; inverse_stage < log_n; ++inverse_stage) {
        const std::size_t forward_stage = log_n - 1 - inverse_stage;
        const std::size_t m = std::size_t{1} << forward_stage;
        std::vector<U32> words;
        words.reserve(g_n / 2);
        for (const NttBatch& batch : ntt_stage_batches(g_n, forward_stage)) {
            auto loaded_labels = load_ntt_batch(labels, batch);
            auto loaded_scales = load_ntt_batch(scales, batch);
            loaded_labels.first = apply_p_network(loaded_labels.first, 6);
            loaded_scales.first = apply_p_network(loaded_scales.first, 6);

            for (std::size_t lane = 0; lane < 64; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const std::size_t lower = loaded_labels.first[even];
                const std::size_t upper = loaded_labels.first[odd];
                if (upper != lower + m) {
                    throw std::runtime_error("inverse NTT physical lane pairing mismatch");
                }
                const U64 alpha = loaded_scales.first[even];
                const U64 beta = loaded_scales.first[odd];
                const U64 exponent = static_cast<U64>((lower % m) * g_n / (2 * m));
                const U64 forward_twiddle = pow_mod(omega, exponent, modulus);
                words.push_back(checked_u32(
                    mul_mod(alpha, inverse_mod(beta, modulus), modulus),
                    "inverse BF twiddle"));
                loaded_scales.first[even] = alpha;
                loaded_scales.first[odd] = mul_mod(alpha, forward_twiddle, modulus);
            }
            store_ntt_batch(labels, loaded_labels.first, loaded_labels.second);
            store_ntt_batch(scales, loaded_scales.first, loaded_scales.second);
        }
        if (words.size() != g_n / 2) {
            throw std::runtime_error("inverse NTT stage twiddle count is not N/2");
        }
        tables.push_back(std::move(words));
    }

    for (std::size_t position = 0; position < g_n; ++position) {
        if (labels[position] != position || scales[position] != 1) {
            throw std::runtime_error("inverse NTT dual schedule does not restore layout/scale");
        }
    }
    return tables;
}

Poly hardware_forward_cyclic(const Poly& logical,
                             const std::vector<std::vector<U32>>& tables,
                             U64 modulus)
{
    Poly physical(g_n);
    for (std::size_t position = 0; position < g_n; ++position) {
        physical[position] = logical[bit_reverse_index(position, g_n)];
    }
    for (std::size_t stage = 0; stage < tables.size(); ++stage) {
        std::size_t twiddle_index = 0;
        for (const NttBatch& batch : ntt_stage_batches(g_n, stage)) {
            auto loaded = load_ntt_batch(physical, batch);
            for (std::size_t lane = 0; lane < 64; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const U64 a = loaded.first[even];
                const U64 product = mul_mod(
                    loaded.first[odd], tables[stage][twiddle_index++], modulus);
                loaded.first[even] = add_mod(a, product, modulus);
                loaded.first[odd] = sub_mod(a, product, modulus);
            }
            loaded.first = apply_p_network(loaded.first);
            store_ntt_batch(physical, loaded.first, loaded.second);
        }
    }
    return physical;
}

Poly hardware_inverse_cyclic(const Poly& physical_input,
                             const std::vector<std::vector<U32>>& tables,
                             U64 modulus)
{
    Poly physical = physical_input;
    const std::size_t log_n = tables.size();
    for (std::size_t inverse_stage = 0; inverse_stage < log_n; ++inverse_stage) {
        const std::size_t forward_stage = log_n - 1 - inverse_stage;
        std::size_t twiddle_index = 0;
        for (const NttBatch& batch : ntt_stage_batches(g_n, forward_stage)) {
            auto loaded = load_ntt_batch(physical, batch);
            loaded.first = apply_p_network(loaded.first, 6);
            for (std::size_t lane = 0; lane < 64; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const U64 a = loaded.first[even];
                const U64 product = mul_mod(
                    loaded.first[odd], tables[inverse_stage][twiddle_index++], modulus);
                loaded.first[even] = add_mod(a, product, modulus);
                loaded.first[odd] = sub_mod(a, product, modulus);
            }
            store_ntt_batch(physical, loaded.first, loaded.second);
        }
    }
    return physical;
}

void validate_hardware_ntt_model(U64 omega,
                                 U64 modulus,
                                 const std::vector<std::vector<U32>>& ntt_tables,
                                 const std::vector<std::vector<U32>>& intt_tables)
{
    Poly a(g_n);
    Poly b(g_n);
    for (std::size_t i = 0; i < g_n; ++i) {
        a[i] = static_cast<U64>((17 * i + 3) % modulus);
        b[i] = static_cast<U64>((29 * i + 5) % modulus);
    }

    Poly a_ntt = a;
    Poly b_ntt = b;
    cyclic_ntt(a_ntt, omega, modulus, false);
    cyclic_ntt(b_ntt, omega, modulus, false);
    const Poly a_physical = hardware_forward_cyclic(a, ntt_tables, modulus);
    const Poly b_physical = hardware_forward_cyclic(b, ntt_tables, modulus);
    const std::vector<std::size_t> layout = hardware_ntt_layout(g_n);
    for (std::size_t position = 0; position < g_n; ++position) {
        if (a_physical[position] != a_ntt[layout[position]]) {
            throw std::runtime_error("hardware PNTT model disagrees with mathematical NTT");
        }
    }

    Poly product_physical(g_n);
    Poly product_logical(g_n);
    for (std::size_t position = 0; position < g_n; ++position) {
        product_physical[position] = mul_mod(
            a_physical[position], b_physical[position], modulus);
    }
    for (std::size_t i = 0; i < g_n; ++i) {
        product_logical[i] = mul_mod(a_ntt[i], b_ntt[i], modulus);
    }
    cyclic_ntt(product_logical, omega, modulus, true);

    Poly inverse_physical = hardware_inverse_cyclic(
        product_physical, intt_tables, modulus);
    const U64 n_inverse = inverse_mod(static_cast<U64>(g_n), modulus);
    for (std::size_t position = 0; position < g_n; ++position) {
        inverse_physical[position] = mul_mod(
            inverse_physical[position], n_inverse, modulus);
        if (inverse_physical[position]
            != product_logical[bit_reverse_index(position, g_n)]) {
            throw std::runtime_error(
                "hardware PNTT/pointwise/PINTT path violates convolution semantics");
        }
    }
}

void write_hardware_package(const std::filesystem::path& test_data_root,
                            const std::vector<Artifact>& artifacts,
                            const std::vector<U64>& moduli,
                            const std::vector<U64>& roots)
{
    if (moduli.empty() || moduli.size() != roots.size()) {
        throw std::runtime_error(
            "hardware package requires one root entry per modulus; zero marks no NTT tables");
    }
    if (moduli.size() > kMaxModContexts) {
        throw std::runtime_error("mod contexts exceed the 8-bit MOD_ID address space");
    }
    const bool includes_twiddles = std::any_of(
        roots.begin(), roots.end(), [](U64 root) { return root != 0; });
    if (g_n < 128 || (g_n & (g_n - 1)) != 0) {
        throw std::runtime_error(
            "hardware stage twiddles require power-of-two N >= 128");
    }

    const std::filesystem::path hardware_root = test_data_root / "hardware";
    std::filesystem::remove_all(hardware_root);
    std::vector<HardwareImage> images;
    for (const Artifact& artifact : artifacts) {
        if (!artifact.hardware_visible) {
            continue;
        }
        add_hardware_image(images,
                           hardware_image_path(artifact.path).string(),
                           "uint32 hardware form of " + artifact.role,
                           artifact.shape,
                           to_hardware_words(artifact));
    }

    std::vector<U32> mod_context_words;
    mod_context_words.reserve(moduli.size() * 4);
    for (U64 modulus : moduli) {
        if (modulus < kMinPeModulus || modulus > kMaxPeModulus) {
            throw std::runtime_error(
                "PE modulus must satisfy 65537 <= q <= 2^32 - 1");
        }
        const U64 mu = barrett_mu64(modulus);
        if ((mu >> kBarrettMuBits) != 0) {
            throw std::runtime_error("Barrett mu does not fit the PE 48-bit ABI");
        }
        mod_context_words.push_back(checked_u32(modulus, "modulus"));
        mod_context_words.push_back(static_cast<U32>(mu));
        mod_context_words.push_back(static_cast<U32>((mu >> 32U) & 0xffffU));
        mod_context_words.push_back(0);
    }
    const std::size_t mod_context_image = add_hardware_image(
        images,
        "constants/mod_ctx.u32.bin",
        "128-bit mod_ctx records: q32, Barrett mu48, reserved48",
        {moduli.size(), 4},
        std::move(mod_context_words));

    std::vector<TwiddleMapEntry> twiddle_entries;
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const U64 modulus = moduli[basis];
        const U64 psi = roots[basis];
        if (psi == 0) {
            continue;
        }
        if (pow_mod(psi, static_cast<U64>(g_n), modulus) != modulus - 1) {
            throw std::runtime_error("root is not a primitive 2N-th root for hardware twiddles");
        }
        const std::string basis_dir = "basis_" +
            (basis < 10 ? std::string("0") : std::string()) + std::to_string(basis);

        std::vector<U32> pre_twist(g_n);
        for (std::size_t position = 0; position < g_n; ++position) {
            pre_twist[position] = checked_u32(
                pow_mod(psi, static_cast<U64>(bit_reverse_index(position, g_n)), modulus),
                "physical pre-twist");
        }
        std::size_t image_index = add_hardware_image(
            images,
            "constants/twiddle/ntt/" + basis_dir + "/pre_twist.u32.bin",
            "forward negacyclic pre-twist in bit-reversed coefficient order",
            {g_n},
            std::move(pre_twist));
        twiddle_entries.push_back({"ntt", basis, modulus, "pre_twist", -1,
                                    g_n, 1, g_n, 1, psi, image_index});

        const U64 omega = mul_mod(psi, psi, modulus);
        const auto ntt_tables = hardware_ntt_twiddle_tables(omega, modulus);
        std::size_t stage = 0;
        for (; stage < ntt_tables.size(); ++stage) {
            const std::string stage_name = "stage_" +
                (stage < 10 ? std::string("0") : std::string()) + std::to_string(stage);
            image_index = add_hardware_image(
                images,
                "constants/twiddle/ntt/" + basis_dir + "/" + stage_name + ".u32.bin",
                "forward DIT stage twiddles in hardware batch/lane consumption order",
                {g_n / 2},
                ntt_tables[stage]);
            twiddle_entries.push_back({"ntt", basis, modulus, "butterfly", static_cast<int>(stage),
                                        g_n / 2, g_n / 128, 64,
                                        ntt_tables[stage].front(), 0, image_index});
        }

        const auto intt_tables = hardware_intt_twiddle_tables(omega, modulus);
        validate_hardware_ntt_model(
            omega, modulus, ntt_tables, intt_tables);
        stage = 0;
        for (; stage < intt_tables.size(); ++stage) {
            const std::string stage_name = "stage_" +
                (stage < 10 ? std::string("0") : std::string()) + std::to_string(stage);
            image_index = add_hardware_image(
                images,
                "constants/twiddle/intt/" + basis_dir + "/" + stage_name + ".u32.bin",
                "inverse DIF lazy-scale BF twiddles in dual-loader batch/lane order",
                {g_n / 2},
                intt_tables[stage]);
            twiddle_entries.push_back({"intt", basis, modulus, "butterfly", static_cast<int>(stage),
                                        g_n / 2, g_n / 128, 64,
                                        intt_tables[stage].front(), 0, image_index});
        }

        const U64 n_inverse = inverse_mod(static_cast<U64>(g_n), modulus);
        const U64 psi_inverse = inverse_mod(psi, modulus);
        std::vector<U32> post_untwist(g_n);
        for (std::size_t position = 0; position < g_n; ++position) {
            const U64 logical_index = static_cast<U64>(bit_reverse_index(position, g_n));
            post_untwist[position] = checked_u32(
                mul_mod(n_inverse, pow_mod(psi_inverse, logical_index, modulus), modulus),
                "physical post-untwist");
        }
        image_index = add_hardware_image(
            images,
            "constants/twiddle/intt/" + basis_dir + "/post_untwist_scale.u32.bin",
            "inverse negacyclic post-factor in bit-reversed coefficient order",
            {g_n},
            std::move(post_untwist));
        twiddle_entries.push_back({"intt", basis, modulus, "post_untwist_scale", -1,
                                    g_n, 1, g_n, n_inverse, psi_inverse, image_index});
    }

    U64 next_line = 0;
    std::vector<U32> hpu_mem_words;
    for (HardwareImage& image : images) {
        image.line_offset = next_line;
        const U64 line_count = image.padded_words.size() / kHpuWordsPerLine;
        next_line += line_count;
        hpu_mem_words.insert(hpu_mem_words.end(), image.padded_words.begin(), image.padded_words.end());
        write_binary32(hardware_root / image.path, image.padded_words);
    }
    if (next_line > g_hpu_mem_max_lines) {
        throw std::runtime_error(
            "hardware package exceeds configured hpu_mem_max_lines="
            + std::to_string(g_hpu_mem_max_lines));
    }
    if (hpu_mem_words.size() != next_line * kHpuWordsPerLine) {
        throw std::runtime_error("HPU_MEM image line accounting mismatch");
    }
    for (const HardwareImage& image : images) {
        write_readable_hardware_image(hardware_root, image);
    }
    write_binary32(hardware_root / "hpu_mem_image.u32.bin", hpu_mem_words);

    std::ostringstream line_map;
    line_map << "path,role,shape,address_byte,line_offset,line_count,payload_words,payload_bytes,"
                "padded_words,padded_bytes\n";
    for (const HardwareImage& image : images) {
        const U64 line_count = image.padded_words.size() / kHpuWordsPerLine;
        line_map << csv_field(image.path) << ',' << csv_field(image.role) << ','
                 << csv_field(shape_string(image.shape)) << ','
                 << hex64(kHpuMemBase + image.line_offset * kHpuLineBytes) << ','
                 << image.line_offset << ',' << line_count << ','
                 << image.payload_words.size() << ',' << image.payload_words.size() * sizeof(U32) << ','
                 << image.padded_words.size() << ',' << image.padded_words.size() * sizeof(U32) << '\n';
    }
    write_text(hardware_root / "line_map.csv", line_map.str());

    std::ostringstream manifest;
    manifest << "path,readable_path,role,shape,payload_words,padded_words,line_offset,line_count,"
                "payload_fnv1a64,image_fnv1a64\n";
    for (const HardwareImage& image : images) {
        manifest << csv_field(image.path) << ','
                 << csv_field(readable_path(image.path).string()) << ','
                 << csv_field(image.role) << ',' << csv_field(shape_string(image.shape)) << ','
                 << image.payload_words.size() << ',' << image.padded_words.size() << ','
                 << image.line_offset << ',' << image.padded_words.size() / kHpuWordsPerLine << ','
                 << hex64(image.payload_checksum) << ',' << hex64(image.image_checksum) << '\n';
    }
    manifest << csv_field("hpu_mem_image.u32.bin") << ',' << csv_field("") << ','
             << csv_field("complete contiguous HPU_MEM window image") << ',' << csv_field("") << ','
             << hpu_mem_words.size() << ',' << hpu_mem_words.size() << ",0," << next_line << ','
             << hex64(fnv1a_words32(hpu_mem_words)) << ',' << hex64(fnv1a_words32(hpu_mem_words)) << '\n';
    write_text(hardware_root / "hardware_manifest.csv", manifest.str());

    const HardwareImage& mod_image = images[mod_context_image];
    std::ostringstream mod_map;
    mod_map << "context_index,modulus,modulus_hex,barrett_mu48_hex,record_word_offset,"
               "line_offset,line_word_offset,record_words\n";
    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        const std::size_t record_word = basis * 4;
        mod_map << basis << ',' << moduli[basis] << ',' << hex32(checked_u32(moduli[basis], "modulus"))
                << ',' << hex64(barrett_mu64(moduli[basis])) << ',' << record_word << ','
                << mod_image.line_offset + record_word / kHpuWordsPerLine << ','
                << record_word % kHpuWordsPerLine << ",4\n";
    }
    write_text(hardware_root / "mod_ctx_map.csv", mod_map.str());

    if (includes_twiddles) {
        std::ostringstream twiddle_map;
        twiddle_map << "direction,basis_index,modulus,phase,stage,value_count,batch_count,"
                       "twiddles_per_batch,first_value,recurrence_step,path,line_offset,line_count\n";
        for (const TwiddleMapEntry& entry : twiddle_entries) {
            const HardwareImage& image = images[entry.image_index];
            twiddle_map << entry.direction << ',' << entry.basis << ',' << entry.modulus << ','
                        << entry.phase << ',' << entry.stage << ',' << entry.value_count << ','
                        << entry.group_count << ',' << entry.twiddles_per_group << ','
                        << hex32(checked_u32(entry.first_value, "twiddle first value")) << ','
                        << hex32(checked_u32(entry.step, "twiddle step")) << ','
                        << csv_field(image.path) << ',' << image.line_offset << ','
                        << image.padded_words.size() / kHpuWordsPerLine << '\n';
        }
        write_text(hardware_root / "twiddle_map.csv", twiddle_map.str());
    }

    const U64 window_bytes = next_line * kHpuLineBytes;
    const U32 size_lines_lo = static_cast<U32>(next_line);
    const U32 size_lines_hi = static_cast<U32>((next_line >> 32U) & 0x1U);
    std::ostringstream hpu_mem_config;
    hpu_mem_config << "{\n"
                   << "  \"format_version\": 1,\n"
                   << "  \"status\": \"HOST_WINDOW_AND_CSR_ABI_READY\",\n"
                   << "  \"image\": \"hpu_mem_image.u32.bin\",\n"
                   << "  \"base_address\": \"" << hex64(kHpuMemBase) << "\",\n"
                   << "  \"base_lo\": \"" << hex32(static_cast<U32>(kHpuMemBase)) << "\",\n"
                   << "  \"base_hi\": \"" << hex32(static_cast<U32>(kHpuMemBase >> 32U)) << "\",\n"
                   << "  \"line_bytes\": " << kHpuLineBytes << ",\n"
                   << "  \"words_per_line\": " << kHpuWordsPerLine << ",\n"
                   << "  \"size_lines\": " << next_line << ",\n"
                   << "  \"configured_max_lines\": "
                   << g_hpu_mem_max_lines << ",\n"
                   << "  \"size_bytes\": " << window_bytes << ",\n"
                   << "  \"end_address_exclusive\": \"" << hex64(kHpuMemBase + window_bytes) << "\",\n"
                   << "  \"image_fnv1a64\": \"" << hex64(fnv1a_words32(hpu_mem_words)) << "\",\n"
                   << "  \"csr_offsets\": [\n"
                   << "    {\"offset\": \"0x00\", \"name\": \"HPU_MEM_BASE_LO\", \"access\": \"RW\", \"field\": \"base[31:0]\"},\n"
                   << "    {\"offset\": \"0x04\", \"name\": \"HPU_MEM_BASE_HI\", \"access\": \"RW\", \"field\": \"base[39:32]\"},\n"
                   << "    {\"offset\": \"0x08\", \"name\": \"HPU_MEM_SIZE_LINES_LO\", \"access\": \"RW\", \"field\": \"size_lines[31:0]\"},\n"
                   << "    {\"offset\": \"0x0c\", \"name\": \"HPU_MEM_SIZE_LINES_HI\", \"access\": \"RW\", \"field\": \"size_lines[32]\"},\n"
                   << "    {\"offset\": \"0x10\", \"name\": \"HPU_MEM_COMMIT\", \"access\": \"W1\", \"field\": \"commit[0]\"},\n"
                   << "    {\"offset\": \"0x14\", \"name\": \"HPU_STATUS\", \"access\": \"RO\", \"field\": \"window_valid[0],hpu_busy[1],fault_valid[2]\"},\n"
                   << "    {\"offset\": \"0x18\", \"name\": \"HPU_FAULT_STATUS\", \"access\": \"RO/W1C\", \"field\": \"fault_valid[0],is_load[1],obj_id[6:4]\"}\n"
                   << "  ],\n"
                   << "  \"programming_sequence\": [\n"
                   << "    {\"offset\": \"0x00\", \"csr\": \"HPU_MEM_BASE_LO\", \"value\": \""
                   << hex32(static_cast<U32>(kHpuMemBase)) << "\"},\n"
                   << "    {\"offset\": \"0x04\", \"csr\": \"HPU_MEM_BASE_HI\", \"value\": \""
                   << hex32(static_cast<U32>(kHpuMemBase >> 32U)) << "\"},\n"
                   << "    {\"offset\": \"0x08\", \"csr\": \"HPU_MEM_SIZE_LINES_LO\", \"value\": "
                   << size_lines_lo << "},\n"
                   << "    {\"offset\": \"0x0c\", \"csr\": \"HPU_MEM_SIZE_LINES_HI\", \"value\": "
                   << size_lines_hi << "},\n"
                   << "    {\"offset\": \"0x10\", \"csr\": \"HPU_MEM_COMMIT\", \"value\": 1},\n"
                   << "    {\"offset\": \"0x14\", \"csr\": \"HPU_STATUS\", \"action\": \"read_and_require_window_valid_and_no_fault\"}\n"
                   << "  ]\n}\n";
    write_text(hardware_root / "hpu_mem_config.json", hpu_mem_config.str());

    std::ostringstream abi;
    abi << "{\n"
        << "  \"format_version\": 1,\n"
        << "  \"N\": " << g_n << ",\n"
        << "  \"modulus_count\": " << moduli.size() << ",\n"
        << "  \"coefficient_bits\": 32,\n"
        << "  \"byte_order\": \"little-endian\",\n"
        << "  \"line_bytes\": " << kHpuLineBytes << ",\n"
        << "  \"line_words\": " << kHpuWordsPerLine << ",\n"
        << "  \"line_offset_origin\": \"HPU_MEM base address\",\n"
        << "  \"custom1_sideband\": {\n"
        << "    \"rs1_value\": \"HPU_MEM line offset\",\n"
        << "    \"rs2_value\": \"line count\",\n"
        << "    \"unit_bytes\": " << kHpuLineBytes << ",\n"
        << "    \"line_count_must_be_nonzero\": true,\n"
        << "    \"bounds_rule\": \"offset + count <= HPU_MEM_SIZE_LINES\"\n"
        << "  },\n"
        << "  \"local_sram\": {\n"
        << "    \"regular_bank_count\": " << kRegularBankCount << ",\n"
        << "    \"regular_bank_lines\": " << kRegularBankLines << ",\n"
        << "    \"regular_line_range\": \"0x0000..0x13ff\",\n"
        << "    \"small_bank_id\": " << kSmallBankId << ",\n"
        << "    \"small_bank_lines\": " << kSmallBankLines << ",\n"
        << "    \"small_bank_line_range\": \"0x1400..0x141f\"\n"
        << "  },\n"
        << "  \"mod_ctx\": {\n"
        << "    \"record_words\": " << kModContextWords << ",\n"
        << "    \"dload_type\": 2,\n"
        << "    \"dload_flag0_small_bank\": 1,\n"
        << "    \"small_bank_id\": " << kSmallBankId << ",\n"
        << "    \"small_bank_lines\": " << kSmallBankLines << ",\n"
        << "    \"mod_table_base_line\": \""
        << hex32(static_cast<U32>(kModTableBaseLine)) << "\",\n"
        << "    \"contexts_per_line\": " << kModContextsPerLine << ",\n"
        << "    \"physical_context_capacity\": " << kPhysicalModContexts << ",\n"
        << "    \"mod_id_bits\": " << kModIdBits << ",\n"
        << "    \"mod_id_addressable_lines\": "
        << kMaxModContexts / kModContextsPerLine << ",\n"
        << "    \"max_contexts\": " << kMaxModContexts << ",\n"
        << "    \"q_min\": " << kMinPeModulus << ",\n"
        << "    \"q_max\": " << kMaxPeModulus << ",\n"
        << "    \"mu_bits\": " << kBarrettMuBits << ",\n"
        << "    \"reserved_bits\": 48,\n"
        << "    \"record_layout_lsb_to_msb\": \"q[31:0], mu[47:0], reserved[47:0]\",\n"
        << "    \"word_0\": \"q (uint32)\",\n"
        << "    \"word_1\": \"floor(2^64/q)[31:0]\",\n"
        << "    \"word_2\": \"bits[15:0]=floor(2^64/q)[47:32], bits[31:16]=reserved zero\",\n"
        << "    \"word_3\": \"reserved[47:16], zero\"\n"
        << "  },\n"
        << "  \"twiddle_images_included\": "
        << (includes_twiddles ? "true" : "false");
    if (includes_twiddles) {
        abi << ",\n"
            << "  \"twiddle\": {\n"
            << "    \"convention\": \"autotest dual schedule: 128 registers, 64 BF lanes, P after PNTT and P^-1 before PINTT\",\n"
            << "    \"coefficient_physical_order\": \"memory[position] = coefficient[bit_reverse(position)]\",\n"
            << "    \"ntt_physical_order\": \"memory[position] = logical_ntt[forward_layout[position]]\",\n"
            << "    \"pre_twist_execution\": \"explicit PMUL by psi^bit_reverse(position) before PNTT stage 0\",\n"
            << "    \"stage_payload_words\": " << g_n / 2 << ",\n"
            << "    \"stage_payload_lines\": "
            << (g_n / 2 + kHpuWordsPerLine - 1) / kHpuWordsPerLine << ",\n"
            << "    \"stage_payload\": \"N/2 physical values in loader-batch then BF-lane consumption order\",\n"
            << "    \"batch_rule\": \"N/128 batches, 64 lane twiddles per batch; labels follow every preceding P network\",\n"
            << "    \"intt_rule\": \"reverse forward stage order, P^-1 before BF, lazy-scale w_bf=alpha/beta\",\n"
            << "    \"stage_alignment\": \"each stage image starts at a 256-byte line\",\n"
            << "    \"stage_pairing\": \"stream_ctrl address generation and PE lane transpose; no standalone bit-reversal command\",\n"
            << "    \"physical_update\": \"out-of-place per stage; controller commits a new base to the same logical object id\",\n"
            << "    \"intt_post_factor\": \"at physical position p: N^-1 * psi^-bit_reverse(p)\",\n"
            << "    \"intt_post_execution\": \"explicit PMUL after the final PINTT stage\"\n"
            << "  }";
    }
    abi << "\n}\n";
    write_text(hardware_root / "abi.json", abi.str());

    std::ostringstream memory_map;
    memory_map << "{\n"
               << "  \"status\": \"UINT32_256B_LINE_LAYOUT_GENERATED\",\n"
               << "  \"base_address\": \"" << hex64(kHpuMemBase) << "\",\n"
               << "  \"line_bytes\": " << kHpuLineBytes << ",\n"
               << "  \"line_count\": " << next_line << ",\n"
               << "  \"hardware_image\": \"hardware/hpu_mem_image.u32.bin\",\n"
               << "  \"line_map\": \"hardware/line_map.csv\",\n"
               << "  \"hpu_mem_config\": \"hardware/hpu_mem_config.json\",\n"
               << "  \"custom1_sideband\": \"GPR[rs1]=line_offset, GPR[rs2]=line_count, both in 256-byte line units\",\n"
               << "  \"runtime_binding\": \"pass the resolved DMA span array to the generated hpu_program_* entry; Nexus-AM materializes auditable resolved manifests\",\n"
               << "  \"qualification_pending\": [\"target RTL execution evidence\"]\n}\n";
    write_text(test_data_root / "memory_map.json", memory_map.str());

    std::ostringstream hardware_readme;
    hardware_readme
        << "# HPU uint32 Hardware Package\n\n"
        << "`hpu_mem_image.u32.bin` is the complete contiguous HPU_MEM window image. "
        << "All words are little-endian uint32 and every object starts on a 256-byte "
        << "line. Program the frozen CSR offsets in `hpu_mem_config.json`, then use "
        << "`line_map.csv` for `cmd_mem_line_offset` and `cmd_mem_len_lines`.\n\n"
        << "`images/` contains independently loadable, line-padded hardware forms of the "
        << "uint64 mathematical golden. Coefficient-domain images use bit-reversed coefficient "
        << "order; NTT-domain images use the final P-network physical layout. `mod_ctx_map.csv` "
        << "documents q and Barrett mu records. "
        << "Load that image with dload type=2 and flag[0]=1 so the object allocator "
        << "places it in 32-line small Bank 5 at MOD_TABLE_BASE_LINE=0x1400; "
        << "hardware maintains DMA consistency, so pmodld needs no software psync. ";
    if (includes_twiddles) {
        hardware_readme
            << "`twiddle_map.csv` gives each modulus, direction, phase, stage, loader-batch/lane "
            << "order, line offset, and line count. ";
    } else {
        hardware_readme
            << "This operator has no PNTT/PINTT stage, so the package intentionally omits "
            << "twiddle images and `twiddle_map.csv`. ";
    }
    hardware_readme
        << "Every individual binary has an annotated decimal view.\n\n"
        << "The physical host-memory ABI in `abi.json` is complete. "
        << "Custom1 sideband semantics and CSR offsets are frozen in `abi.json` and "
        << "`hpu_mem_config.json`. DMA relocation/GPR loading, SRAM scratch allocation, "
        << "and terminal psync completion handling still require runtime integration.\n";
    write_text(hardware_root / "README.md", hardware_readme.str());
}

void write_case_package(const std::filesystem::path& suite_root,
                        const std::string& case_name,
                        const std::string& params,
                        std::vector<Artifact> artifacts,
                        const std::vector<U64>& moduli,
                        const std::vector<U64>& roots,
                        TwiddleRequirement twiddle_requirement)
{
    const std::filesystem::path root = suite_root / case_name / "test_data";
    // Case packages are generated artifacts. Recreate the directory so renamed
    // inputs/outputs from an older schema cannot survive and confuse consumers.
    std::filesystem::remove_all(root);
    for (Artifact& artifact : artifacts) {
        write_binary(root / artifact.path, artifact.words);
        write_readable_artifact(root, artifact);
    }

    std::ostringstream manifest;
    manifest << "path,readable_path,role,shape,elements,bytes,hardware_visible,fnv1a64\n";
    for (const Artifact& artifact : artifacts) {
        manifest << csv_field(artifact.path) << ','
                 << csv_field(readable_path(artifact.path).string()) << ','
                 << csv_field(artifact.role) << ','
                 << csv_field(shape_string(artifact.shape)) << ',' << artifact.words.size()
                 << ',' << artifact.words.size() * sizeof(U64) << ','
                 << (artifact.hardware_visible ? 1 : 0) << ','
                 << hex64(artifact.checksum) << '\n';
    }
    write_text(root / "params.json", params);
    write_text(root / "artifact_manifest.csv", manifest.str());
    std::vector<U64> hardware_roots = roots;
    if (twiddle_requirement == TwiddleRequirement::kNone) {
        std::fill(hardware_roots.begin(), hardware_roots.end(), 0);
    }
    write_hardware_package(root, artifacts, moduli, hardware_roots);
    std::ostringstream readme;
    readme << "This UT package is generated from the same deterministic N=" << g_n
           << " FHE reference used by ciphertext_multiply. Binary values are little-endian "
           << "uint64 canonical residues. Every binary has a complete annotated `.dec.txt` "
           << "view with block coordinates. Shape and checksum information is in "
           << "artifact_manifest.csv. The independent `hardware/` tree contains uint32, "
           << "256-byte-line-padded images, q/Barrett contexts, line offsets, and HPU_MEM "
           << "window configuration. ";
    if (twiddle_requirement == TwiddleRequirement::kRequired) {
        readme << "Because this operator executes PNTT/PINTT, it also contains the required "
               << "stage twiddle images and map.\n";
    } else {
        readme << "Because this operator executes no PNTT/PINTT, twiddle data is intentionally "
               << "omitted.\n";
    }
    write_text(root / "README.md", readme.str());
}

void verify_equal(const BasisPoly& left, const BasisPoly& right, const std::string& label)
{
    if (left != right) {
        throw std::runtime_error(label + " mismatch");
    }
}

void generate(const std::filesystem::path& output_root,
              const std::filesystem::path* suite_root)
{
    const U64 order = static_cast<U64>(2 * g_n);
    std::vector<U64> q_moduli;
    std::vector<U64> p_moduli;
    U64 next = 50000000;
    for (std::size_t i = 0; i < g_num_q; ++i) {
        const U64 prime = find_ntt_prime(next, order);
        q_moduli.push_back(prime);
        next = prime + order;
    }
    next = 90000000;
    for (std::size_t i = 0; i < g_num_p; ++i) {
        const U64 prime = find_ntt_prime(next, order);
        p_moduli.push_back(prime);
        next = prime + order;
    }

    std::vector<U64> b_moduli;
    next = 3000000000ULL;
    for (std::size_t i = 0; i < g_bfv_num_b; ++i) {
        const U64 prime = find_ntt_prime(next, order);
        if (prime > UINT32_MAX) {
            throw std::runtime_error("BFV B basis exceeds the 32-bit PE modulus ABI");
        }
        b_moduli.push_back(prime);
        next = prime + order;
    }
    const U64 m_sk = find_ntt_prime(next, order);
    if (m_sk > UINT32_MAX || m_sk <= 2 * g_bfv_num_b) {
        throw std::runtime_error("BFV m_sk violates the branchless-SK range gate");
    }

    const BigInt q_product = big_product(q_moduli);
    const unsigned no_smrq_extra_bits = u64_bit_length(
        static_cast<U64>(g_num_q * g_num_q - 1));
    const unsigned required_b_bits = 33
        + u64_bit_length(g_plaintext_modulus)
        + big_bit_length(q_product)
        + no_smrq_extra_bits;
    if (product_bit_length(b_moduli) <= required_b_bits) {
        throw std::runtime_error(
            "BFV B basis is too small for the no-SMRQ error bound");
    }

    std::vector<U64> all_moduli = q_moduli;
    all_moduli.insert(all_moduli.end(), p_moduli.begin(), p_moduli.end());
    for (U64 modulus : all_moduli) {
        if (std::gcd(modulus, g_plaintext_modulus) != 1) {
            throw std::runtime_error(
                "plaintext modulus must be coprime with every Q/P modulus");
        }
    }
    std::vector<U64> all_roots;
    for (U64 modulus : all_moduli) {
        all_roots.push_back(find_primitive_2n_root(modulus, g_n));
    }
    const std::vector<U64> q_roots(all_roots.begin(), all_roots.begin() + g_num_q);
    std::vector<U64> bsk_moduli = b_moduli;
    bsk_moduli.push_back(m_sk);
    std::vector<U64> bsk_roots;
    for (U64 modulus : bsk_moduli) {
        bsk_roots.push_back(find_primitive_2n_root(modulus, g_n));
    }
    std::vector<U64> bfv_context_moduli = all_moduli;
    bfv_context_moduli.insert(
        bfv_context_moduli.end(), bsk_moduli.begin(), bsk_moduli.end());
    bfv_context_moduli.push_back(g_plaintext_modulus);
    std::vector<U64> bfv_multiply_roots = all_roots;
    bfv_multiply_roots.insert(
        bfv_multiply_roots.end(), bsk_roots.begin(), bsk_roots.end());
    bfv_multiply_roots.push_back(0);

    std::vector<U64> unique_contexts = bfv_context_moduli;
    std::sort(unique_contexts.begin(), unique_contexts.end());
    if (std::adjacent_find(unique_contexts.begin(), unique_contexts.end())
        != unique_contexts.end()) {
        throw std::runtime_error("BFV Q/P/B/m_sk/t contexts must be pairwise distinct");
    }
    std::vector<U64> bgv_moduli = all_moduli;
    bgv_moduli.push_back(g_plaintext_modulus);
    std::vector<U64> bgv_roots = all_roots;
    // BGV ModSwitch uses t only for coefficient-wise modular arithmetic.
    bgv_roots.push_back(0);

    std::mt19937_64 rng(g_seed);
    std::vector<std::int64_t> secret_small(g_n);
    std::vector<std::int64_t> message_a(g_n);
    std::vector<std::int64_t> message_b(g_n);
    for (std::size_t i = 0; i < g_n; ++i) {
        secret_small[i] = static_cast<std::int64_t>(rng() % 3) - 1;
        message_a[i] = static_cast<std::int64_t>((3 * i + 1) % 7) - 3;
        message_b[i] = static_cast<std::int64_t>((5 * i + 2) % 7) - 3;
    }

    const BasisPoly secret_q = encode_basis(secret_small, q_moduli);
    const BasisPoly secret_qp = encode_basis(secret_small, all_moduli);
    Ciphertext ct_a = encrypt_test_message(message_a, secret_q, q_moduli, q_roots, rng);
    Ciphertext ct_b = encrypt_test_message(message_b, secret_q, q_moduli, q_roots, rng);

    Ciphertext ct_a_ntt;
    Ciphertext ct_b_ntt;
    for (std::size_t component = 0; component < 2; ++component) {
        ct_a_ntt[component] = transform_basis(ct_a[component], q_moduli, q_roots, false);
        ct_b_ntt[component] = transform_basis(ct_b[component], q_moduli, q_roots, false);
    }
    const BasisPoly plaintext_b_q = encode_basis(message_b, q_moduli);
    const BasisPoly plaintext_b_ntt = transform_basis(
        plaintext_b_q, q_moduli, q_roots, false);
    Ciphertext rescaled_ct_a;
    for (std::size_t component = 0; component < 2; ++component) {
        rescaled_ct_a[component] = rescale_drop_last(ct_a[component], q_moduli);
        verify_equal(rescaled_ct_a[component],
                     direct_rounded_divide_last(ct_a[component], q_moduli),
                     "rounded rescale direct CRT check");
    }
    Ciphertext pmult_ntt;
    for (std::size_t component = 0; component < 2; ++component) {
        pmult_ntt[component].resize(g_num_q);
        for (std::size_t basis = 0; basis < g_num_q; ++basis) {
            pmult_ntt[component][basis] = pointwise_mul(
                ct_a_ntt[component][basis], plaintext_b_ntt[basis], q_moduli[basis]);
        }
    }

    TensorCiphertext tensor_ntt;
    for (BasisPoly& component : tensor_ntt) {
        component.resize(g_num_q);
    }
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        const U64 modulus = q_moduli[basis];
        tensor_ntt[0][basis] = pointwise_mul(ct_a_ntt[0][basis], ct_b_ntt[0][basis], modulus);
        tensor_ntt[2][basis] = pointwise_mul(ct_a_ntt[1][basis], ct_b_ntt[1][basis], modulus);
        tensor_ntt[1][basis] = add_poly(
            pointwise_mul(ct_a_ntt[0][basis], ct_b_ntt[1][basis], modulus),
            pointwise_mul(ct_a_ntt[1][basis], ct_b_ntt[0][basis], modulus),
            modulus);
    }

    TensorCiphertext tensor;
    for (std::size_t component = 0; component < 3; ++component) {
        tensor[component] = transform_basis(tensor_ntt[component], q_moduli, q_roots, true);
    }

    const std::size_t digit_size = g_num_q / g_dnum;
    std::vector<std::array<BasisPoly, 2>> rlk(g_dnum);
    std::vector<std::array<BasisPoly, 2>> rlk_ntt(g_dnum);
    BasisPoly secret_squared_qp(all_moduli.size());
    for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
        secret_squared_qp[basis] = negacyclic_mul(
            secret_qp[basis], secret_qp[basis], all_moduli[basis], all_roots[basis]);
    }

    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        const std::vector<U64> gadget = crt_digit_factors(
            q_moduli, digit * digit_size, digit_size, all_moduli);
        std::vector<std::int64_t> r_small(g_n);
        for (std::int64_t& value : r_small) {
            value = static_cast<std::int64_t>(rng() % 7) - 3;
        }
        for (BasisPoly& component : rlk[digit]) {
            component.resize(all_moduli.size());
        }
        for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
            const U64 modulus = all_moduli[basis];
            const U64 p_modulus = product_mod(p_moduli, modulus);
            Poly a = scalar_poly(encode_signed(r_small, modulus), p_modulus, modulus);
            const Poly a_times_s = negacyclic_mul(a, secret_qp[basis], modulus, all_roots[basis]);
            const Poly target = scalar_poly(
                secret_squared_qp[basis], mul_mod(p_modulus, gadget[basis], modulus), modulus);
            rlk[digit][0][basis] = sub_poly(target, a_times_s, modulus);
            rlk[digit][1][basis] = std::move(a);
        }
        for (std::size_t component = 0; component < 2; ++component) {
            rlk_ntt[digit][component] = transform_basis(
                rlk[digit][component], all_moduli, all_roots, false);
        }
    }

    // AUTO index 1 is frozen to the standard odd Galois element 3.  The CPU
    // applies x -> x^3 in the negacyclic coefficient layout; the HPU then
    // performs a normal key switch from sigma_3(s) back to s.
    constexpr U64 kAutoGaloisElement = 3;
    Ciphertext auto_rotated;
    for (std::size_t component = 0; component < 2; ++component) {
        auto_rotated[component] = apply_negacyclic_automorphism(
            ct_a[component], kAutoGaloisElement, q_moduli);
    }
    const BasisPoly auto_secret_qp = apply_negacyclic_automorphism(
        secret_qp, kAutoGaloisElement, all_moduli);
    std::vector<std::array<BasisPoly, 2>> galois_key(g_dnum);
    std::vector<std::array<BasisPoly, 2>> galois_key_ntt(g_dnum);
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        const std::vector<U64> gadget = crt_digit_factors(
            q_moduli, digit * digit_size, digit_size, all_moduli);
        std::vector<std::int64_t> r_small(g_n);
        for (std::int64_t& value : r_small) {
            value = static_cast<std::int64_t>(rng() % 7) - 3;
        }
        for (BasisPoly& component : galois_key[digit]) {
            component.resize(all_moduli.size());
        }
        for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
            const U64 modulus = all_moduli[basis];
            const U64 p_modulus = product_mod(p_moduli, modulus);
            Poly a = scalar_poly(
                encode_signed(r_small, modulus), p_modulus, modulus);
            const Poly a_times_s = negacyclic_mul(
                a, secret_qp[basis], modulus, all_roots[basis]);
            const Poly target = scalar_poly(
                auto_secret_qp[basis],
                mul_mod(p_modulus, gadget[basis], modulus), modulus);
            galois_key[digit][0][basis] =
                sub_poly(target, a_times_s, modulus);
            galois_key[digit][1][basis] = std::move(a);
        }
        for (std::size_t component = 0; component < 2; ++component) {
            galois_key_ntt[digit][component] = transform_basis(
                galois_key[digit][component], all_moduli, all_roots, false);
        }
    }

    std::vector<BasisPoly> modup_coeff(g_dnum);
    std::vector<BasisPoly> modup_ntt(g_dnum);
    std::array<BasisPoly, 2> keyswitch_ntt;
    for (BasisPoly& component : keyswitch_ntt) {
        component.assign(all_moduli.size(), Poly(g_n, 0));
    }
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        modup_coeff[digit] = modup(
            tensor[2], q_moduli, all_moduli, digit * digit_size, digit_size);
        modup_ntt[digit] = transform_basis(modup_coeff[digit], all_moduli, all_roots, false);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
                keyswitch_ntt[component][basis] = add_poly(
                    keyswitch_ntt[component][basis],
                    pointwise_mul(modup_ntt[digit][basis],
                                  rlk_ntt[digit][component][basis],
                                  all_moduli[basis]),
                    all_moduli[basis]);
            }
        }
    }

    std::array<BasisPoly, 2> keyswitch_qp;
    std::array<BasisPoly, 2> keyswitch_q;
    for (std::size_t component = 0; component < 2; ++component) {
        keyswitch_qp[component] = transform_basis(
            keyswitch_ntt[component], all_moduli, all_roots, true);
        keyswitch_q[component] = moddown(keyswitch_qp[component], q_moduli, p_moduli);
    }

    std::array<BasisPoly, 2> auto_keyswitch_ntt;
    for (BasisPoly& component : auto_keyswitch_ntt) {
        component.assign(all_moduli.size(), Poly(g_n, 0));
    }
    for (std::size_t digit = 0; digit < g_dnum; ++digit) {
        const BasisPoly raised = modup(
            auto_rotated[1], q_moduli, all_moduli,
            digit * digit_size, digit_size);
        const BasisPoly raised_ntt = transform_basis(
            raised, all_moduli, all_roots, false);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < all_moduli.size(); ++basis) {
                auto_keyswitch_ntt[component][basis] = add_poly(
                    auto_keyswitch_ntt[component][basis],
                    pointwise_mul(raised_ntt[basis],
                                  galois_key_ntt[digit][component][basis],
                                  all_moduli[basis]),
                    all_moduli[basis]);
            }
        }
    }
    std::array<BasisPoly, 2> auto_keyswitch_q;
    for (std::size_t component = 0; component < 2; ++component) {
        const BasisPoly coeff_qp = transform_basis(
            auto_keyswitch_ntt[component], all_moduli, all_roots, true);
        auto_keyswitch_q[component] = moddown(
            coeff_qp, q_moduli, p_moduli);
    }
    Ciphertext auto_output;
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        auto_output[0].push_back(add_poly(
            auto_rotated[0][basis], auto_keyswitch_q[0][basis],
            q_moduli[basis]));
        auto_output[1].push_back(auto_keyswitch_q[1][basis]);
    }
    const BasisPoly auto_decrypted = decrypt_ciphertext(
        auto_output, secret_q, q_moduli, q_roots);
    const BasisPoly auto_expected = apply_negacyclic_automorphism(
        decrypt_ciphertext(ct_a, secret_q, q_moduli, q_roots),
        kAutoGaloisElement, q_moduli);
    verify_equal(auto_expected, auto_decrypted,
                 "automorphism plus Galois key switch decryption");

    Ciphertext keyswitch_output;
    Ciphertext output;
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        keyswitch_output[0].push_back(
            add_poly(tensor[0][basis], keyswitch_q[0][basis], q_moduli[basis]));
        keyswitch_output[1].push_back(keyswitch_q[1][basis]);
        output[0].push_back(keyswitch_output[0][basis]);
        output[1].push_back(add_poly(tensor[1][basis], keyswitch_q[1][basis], q_moduli[basis]));
    }

    BasisPoly keyswitch_expected(g_num_q);
    for (std::size_t basis = 0; basis < g_num_q; ++basis) {
        keyswitch_expected[basis] = add_poly(
            tensor[0][basis],
            negacyclic_mul(
                tensor[2][basis],
                secret_squared_qp[basis],
                q_moduli[basis],
                q_roots[basis]),
            q_moduli[basis]);
    }
    const BasisPoly keyswitch_output_decrypted = decrypt_ciphertext(
        keyswitch_output, secret_q, q_moduli, q_roots);
    verify_equal(
        keyswitch_expected,
        keyswitch_output_decrypted,
        "complete key-switch output decryption");

    const BasisPoly tensor_decrypted = decrypt_tensor(tensor, secret_q, q_moduli, q_roots);
    const BasisPoly output_decrypted = decrypt_ciphertext(output, secret_q, q_moduli, q_roots);
    verify_equal(tensor_decrypted, output_decrypted, "relinearized ciphertext decryption");

    const std::vector<std::int64_t> expected_plain = plaintext_product(message_a, message_b);
    std::vector<U64> expected_plain_mod_t(g_n);
    std::vector<U64> decrypted_plain_mod_t(g_n);
    for (std::size_t i = 0; i < g_n; ++i) {
        const std::int64_t expected = expected_plain[i];
        const std::int64_t expected_mod = ((expected % static_cast<std::int64_t>(g_plaintext_modulus))
            + static_cast<std::int64_t>(g_plaintext_modulus)) % static_cast<std::int64_t>(g_plaintext_modulus);
        expected_plain_mod_t[i] = static_cast<U64>(expected_mod);

        const U64 residue = output_decrypted[0][i];
        const std::int64_t centered = residue > q_moduli[0] / 2
            ? static_cast<std::int64_t>(residue) - static_cast<std::int64_t>(q_moduli[0])
            : static_cast<std::int64_t>(residue);
        const std::int64_t decoded = ((centered % static_cast<std::int64_t>(g_plaintext_modulus))
            + static_cast<std::int64_t>(g_plaintext_modulus)) % static_cast<std::int64_t>(g_plaintext_modulus);
        decrypted_plain_mod_t[i] = static_cast<U64>(decoded);
    }
    if (decrypted_plain_mod_t != expected_plain_mod_t) {
        throw std::runtime_error("plaintext multiplication check failed");
    }

    const std::vector<U64> retained_q_moduli(
        q_moduli.begin(), q_moduli.end() - 1);
    const std::vector<U64> retained_q_roots(
        q_roots.begin(), q_roots.end() - 1);

    // CKKS fixture: host canonical embedding, functional encryption,
    // multiply/relinearize, rounded Rescale, decrypt, and slot Decode.
    const double ckks_input_scale = static_cast<double>(q_moduli.back());
    const double ckks_product_scale = ckks_input_scale * ckks_input_scale;
    const double ckks_output_scale =
        ckks_product_scale / static_cast<double>(q_moduli.back());
    std::vector<std::complex<double>> ckks_slots_a(g_n / 2);
    std::vector<std::complex<double>> ckks_slots_b(g_n / 2);
    for (std::size_t slot = 0; slot < g_n / 2; ++slot) {
        ckks_slots_a[slot] = {
            (static_cast<double>((3 * slot + 1) % 11) - 5.0) / 8.0,
            (static_cast<double>((5 * slot + 2) % 9) - 4.0) / 16.0};
        ckks_slots_b[slot] = {
            (static_cast<double>((7 * slot + 3) % 13) - 6.0) / 8.0,
            (static_cast<double>((2 * slot + 1) % 7) - 3.0) / 16.0};
    }
    const auto ckks_rotated_slots_a = rotate_slots_left(ckks_slots_a);
    const auto ckks_encoded_a = hpu::scheme::ckks::encode_slots(
        ckks_slots_a, g_n, ckks_input_scale);
    const auto ckks_encoded_b = hpu::scheme::ckks::encode_slots(
        ckks_slots_b, g_n, ckks_input_scale);
    const auto ckks_roundtrip_a = hpu::scheme::ckks::decode_slots(
        ckks_encoded_a.coefficients, ckks_input_scale);
    const auto ckks_roundtrip_b = hpu::scheme::ckks::decode_slots(
        ckks_encoded_b.coefficients, ckks_input_scale);
    const double ckks_encode_bound = std::max(
        1e-6, 8.0 * static_cast<double>(g_n) / ckks_input_scale);
    double ckks_encode_max_error_a = 0.0;
    double ckks_encode_max_error_b = 0.0;
    for (std::size_t slot = 0; slot < g_n / 2; ++slot) {
        ckks_encode_max_error_a = std::max(
            ckks_encode_max_error_a,
            std::abs(ckks_roundtrip_a[slot] - ckks_slots_a[slot]));
        ckks_encode_max_error_b = std::max(
            ckks_encode_max_error_b,
            std::abs(ckks_roundtrip_b[slot] - ckks_slots_b[slot]));
        if (ckks_encode_max_error_a > ckks_encode_bound
            || ckks_encode_max_error_b > ckks_encode_bound) {
            throw std::runtime_error("CKKS Encode/Decode round-trip failed");
        }
    }
    const Ciphertext ckks_ct_a = encrypt_test_message(
        ckks_encoded_a.coefficients, secret_q, q_moduli, q_roots, rng);
    const Ciphertext ckks_ct_b = encrypt_test_message(
        ckks_encoded_b.coefficients, secret_q, q_moduli, q_roots, rng);
    SchemeMultiplyTrace ckks_multiply_trace;
    const Ciphertext ckks_product_q = multiply_and_relinearize(
        ckks_ct_a, ckks_ct_b, secret_q, rlk_ntt,
        q_moduli, p_moduli, all_moduli, q_roots, all_roots,
        &ckks_multiply_trace);
    Ciphertext ckks_product_qprime;
    for (std::size_t component = 0; component < 2; ++component) {
        ckks_product_qprime[component] = rescale_drop_last(
            ckks_product_q[component], q_moduli);
        verify_equal(
            ckks_product_qprime[component],
            direct_rounded_divide_last(ckks_product_q[component], q_moduli),
            "CKKS multiply Rescale direct CRT check");
    }
    const BasisPoly secret_qprime(secret_q.begin(), secret_q.end() - 1);
    const BasisPoly ckks_decrypted_qprime = decrypt_ciphertext(
        ckks_product_qprime, secret_qprime, retained_q_moduli, retained_q_roots);
    const auto ckks_centered = centered_to_int64(
        exact_rns_to_centered(ckks_decrypted_qprime, retained_q_moduli),
        "CKKS decrypted");
    const auto ckks_decoded_product = hpu::scheme::ckks::decode_slots(
        ckks_centered, ckks_output_scale);
    std::vector<std::complex<double>> ckks_expected_slots(g_n / 2);
    double ckks_max_abs_error = 0.0;
    for (std::size_t slot = 0; slot < g_n / 2; ++slot) {
        ckks_expected_slots[slot] = ckks_slots_a[slot] * ckks_slots_b[slot];
        ckks_max_abs_error = std::max(
            ckks_max_abs_error,
            std::abs(ckks_decoded_product[slot] - ckks_expected_slots[slot]));
    }
    const double ckks_error_bound = std::max(
        1e-6, 64.0 * static_cast<double>(g_n) / ckks_input_scale);
    const double ckks_rotation_error_bound = std::max(
        1e-6, 128.0 * static_cast<double>(g_n) / ckks_input_scale);
    if (ckks_max_abs_error > ckks_error_bound) {
        throw std::runtime_error("CKKS slot product exceeds functional error bound");
    }
    const auto ckks_ideal = hpu::scheme::ckks::encode_slots(
        ckks_expected_slots, g_n, ckks_output_scale).coefficients;
    const BasisPoly ckks_ideal_qprime = encode_basis(
        ckks_ideal, retained_q_moduli);

    // BGV fixture: batch Encode, non-trivial correction factors, multiply,
    // ModSwitch, factor removal, and exact slot Decode.
    std::vector<std::int64_t> bgv_slots_a(g_n);
    std::vector<std::int64_t> bgv_slots_b(g_n);
    for (std::size_t slot = 0; slot < g_n; ++slot) {
        bgv_slots_a[slot] = static_cast<std::int64_t>((3 * slot + 1) % 17) - 8;
        bgv_slots_b[slot] = static_cast<std::int64_t>((5 * slot + 2) % 19) - 9;
    }
    const Poly bgv_plain_a = hpu::scheme::bgv::encode_slots(
        bgv_slots_a, g_n, g_plaintext_modulus);
    const Poly bgv_plain_b = hpu::scheme::bgv::encode_slots(
        bgv_slots_b, g_n, g_plaintext_modulus);
    if (hpu::scheme::bgv::decode_slots(bgv_plain_a, g_plaintext_modulus)
            != bgv_slots_a
        || hpu::scheme::bgv::decode_slots(bgv_plain_b, g_plaintext_modulus)
            != bgv_slots_b) {
        throw std::runtime_error("BGV batch Encode/Decode round-trip failed");
    }
    std::vector<std::int64_t> bgv_expected_slots(g_n);
    for (std::size_t slot = 0; slot < g_n; ++slot) {
        I128 product = static_cast<I128>(bgv_slots_a[slot]) * bgv_slots_b[slot];
        product %= static_cast<I128>(g_plaintext_modulus);
        if (product > static_cast<I128>(g_plaintext_modulus / 2)) {
            product -= static_cast<I128>(g_plaintext_modulus);
        } else if (product < -static_cast<I128>(g_plaintext_modulus / 2)) {
            product += static_cast<I128>(g_plaintext_modulus);
        }
        bgv_expected_slots[slot] = static_cast<std::int64_t>(product);
    }
    const Poly bgv_expected_coeff_t = hpu::scheme::bgv::encode_slots(
        bgv_expected_slots, g_n, g_plaintext_modulus);

    const Poly bgv_auto_coeff_t = apply_negacyclic_automorphism(
        bgv_plain_a, 3, g_plaintext_modulus);
    const auto bgv_expected_auto_slots = hpu::scheme::bgv::decode_slots(
        bgv_auto_coeff_t, g_plaintext_modulus);
    for (std::size_t row = 0; row < 2; ++row) {
        for (std::size_t column = 0; column < g_n / 2; ++column) {
            const auto expected = bgv_slots_a[
                row * (g_n / 2) + (column + 1) % (g_n / 2)];
            if (bgv_expected_auto_slots[row * (g_n / 2) + column] != expected) {
                throw std::runtime_error("BGV X->X^3 slot rotation check failed");
            }
        }
    }

    constexpr U64 kBgvFactorA = 3;
    constexpr U64 kBgvFactorB = 5;
    const U64 bgv_multiply_factor = mul_mod(
        kBgvFactorA, kBgvFactorB, g_plaintext_modulus);
    const Ciphertext bgv_ct_a = encrypt_bgv_test_message(
        bgv_plain_a, kBgvFactorA, g_plaintext_modulus,
        secret_q, q_moduli, q_roots, rng);
    const Ciphertext bgv_ct_b = encrypt_bgv_test_message(
        bgv_plain_b, kBgvFactorB, g_plaintext_modulus,
        secret_q, q_moduli, q_roots, rng);
    const Ciphertext bgv_auto_ct = automorphism_and_keyswitch(
        bgv_ct_a, 3, secret_q, galois_key_ntt,
        q_moduli, p_moduli, all_moduli, q_roots, all_roots);
    const Poly bgv_auto_phase_t = centered_rns_to_modulus(
        decrypt_ciphertext(bgv_auto_ct, secret_q, q_moduli, q_roots),
        q_moduli, g_plaintext_modulus);
    const U64 bgv_factor_a_inverse = inverse_mod(
        kBgvFactorA, g_plaintext_modulus);
    Poly bgv_auto_decoded_coeff_t(g_n);
    for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
        bgv_auto_decoded_coeff_t[coefficient] = mul_mod(
            bgv_auto_phase_t[coefficient], bgv_factor_a_inverse,
            g_plaintext_modulus);
    }
    const auto bgv_auto_decoded_slots = hpu::scheme::bgv::decode_slots(
        bgv_auto_decoded_coeff_t, g_plaintext_modulus);
    if (bgv_auto_decoded_slots != bgv_expected_auto_slots) {
        throw std::runtime_error("BGV ciphertext Auto slot rotation failed");
    }
    SchemeMultiplyTrace bgv_multiply_trace;
    const Ciphertext bgv_product_q = multiply_and_relinearize(
        bgv_ct_a, bgv_ct_b, secret_q, rlk_ntt,
        q_moduli, p_moduli, all_moduli, q_roots, all_roots,
        &bgv_multiply_trace);
    const BasisPoly bgv_decrypted_q = decrypt_ciphertext(
        bgv_product_q, secret_q, q_moduli, q_roots);
    const Poly bgv_phase_mod_t = centered_rns_to_modulus(
        bgv_decrypted_q, q_moduli, g_plaintext_modulus);
    const U64 bgv_multiply_factor_inverse = inverse_mod(
        bgv_multiply_factor, g_plaintext_modulus);
    Poly bgv_decoded_coeff_t(g_n);
    for (std::size_t i = 0; i < g_n; ++i) {
        bgv_decoded_coeff_t[i] = mul_mod(
            bgv_phase_mod_t[i], bgv_multiply_factor_inverse,
            g_plaintext_modulus);
        if (bgv_decoded_coeff_t[i] != bgv_expected_coeff_t[i]) {
            throw std::runtime_error("BGV multiply correction-factor decode failed");
        }
    }
    const auto bgv_decoded_slots = hpu::scheme::bgv::decode_slots(
        bgv_decoded_coeff_t, g_plaintext_modulus);
    if (bgv_decoded_slots != bgv_expected_slots) {
        throw std::runtime_error("BGV multiply slot Decode failed");
    }

    std::array<BgvModswitchTrace, 2> bgv_modswitch_trace;
    Ciphertext bgv_product_qprime;
    for (std::size_t component = 0; component < 2; ++component) {
        bgv_modswitch_trace[component] = bgv_modswitch_drop_last(
            bgv_product_q[component], q_moduli, g_plaintext_modulus);
        bgv_product_qprime[component] = bgv_modswitch_trace[component].output;
    }
    const U64 q_last_inverse_t = inverse_mod(
        q_moduli.back() % g_plaintext_modulus, g_plaintext_modulus);
    const U64 bgv_modswitch_factor = mul_mod(
        bgv_multiply_factor, q_last_inverse_t, g_plaintext_modulus);
    const U64 bgv_modswitch_factor_inverse = inverse_mod(
        bgv_modswitch_factor, g_plaintext_modulus);
    const BasisPoly bgv_decrypted_qprime = decrypt_ciphertext(
        bgv_product_qprime, secret_qprime, retained_q_moduli, retained_q_roots);
    const Poly bgv_switched_phase_mod_t = centered_rns_to_modulus(
        bgv_decrypted_qprime, retained_q_moduli, g_plaintext_modulus);
    Poly bgv_switched_coeff_t(g_n);
    for (std::size_t i = 0; i < g_n; ++i) {
        bgv_switched_coeff_t[i] = mul_mod(
            bgv_switched_phase_mod_t[i], bgv_modswitch_factor_inverse,
            g_plaintext_modulus);
        if (bgv_switched_coeff_t[i] != bgv_expected_coeff_t[i]) {
            throw std::runtime_error("BGV ModSwitch correction-factor decode failed");
        }
    }
    const auto bgv_switched_slots = hpu::scheme::bgv::decode_slots(
        bgv_switched_coeff_t, g_plaintext_modulus);
    if (bgv_switched_slots != bgv_expected_slots) {
        throw std::runtime_error("BGV ModSwitch slot Decode failed");
    }

    // BFV fixture: batch Encode, no-SMRQ BEHZ tensor product, branchless-SK,
    // independent Q/P relinearization kernel, rounded ModSwitch, and Decode.
    const std::vector<std::int64_t> bfv_slots_a = bgv_slots_a;
    const std::vector<std::int64_t> bfv_slots_b = bgv_slots_b;
    const Poly bfv_plain_a = hpu::scheme::bfv::encode_slots(
        bfv_slots_a, g_n, g_plaintext_modulus);
    const Poly bfv_plain_b = hpu::scheme::bfv::encode_slots(
        bfv_slots_b, g_n, g_plaintext_modulus);
    if (hpu::scheme::bfv::decode_slots(bfv_plain_a, g_plaintext_modulus)
            != bfv_slots_a
        || hpu::scheme::bfv::decode_slots(bfv_plain_b, g_plaintext_modulus)
            != bfv_slots_b) {
        throw std::runtime_error("BFV batch Encode/Decode round-trip failed");
    }
    std::vector<std::int64_t> bfv_expected_slots(g_n);
    for (std::size_t slot = 0; slot < g_n; ++slot) {
        I128 product = static_cast<I128>(bfv_slots_a[slot]) * bfv_slots_b[slot];
        product %= static_cast<I128>(g_plaintext_modulus);
        if (product > static_cast<I128>(g_plaintext_modulus / 2)) {
            product -= static_cast<I128>(g_plaintext_modulus);
        } else if (product < -static_cast<I128>(g_plaintext_modulus / 2)) {
            product += static_cast<I128>(g_plaintext_modulus);
        }
        bfv_expected_slots[slot] = static_cast<std::int64_t>(product);
    }
    const Poly bfv_expected_coeff_t = hpu::scheme::bfv::encode_slots(
        bfv_expected_slots, g_n, g_plaintext_modulus);

    const std::vector<std::int64_t> zero_error(g_n, 0);
    const Ciphertext bfv_ct_a = encrypt_bfv_test_message(
        bfv_plain_a, zero_error, secret_q, q_moduli, q_roots, rng);
    const Ciphertext bfv_ct_b = encrypt_bfv_test_message(
        bfv_plain_b, zero_error, secret_q, q_moduli, q_roots, rng);
    BfvBehzTrace bfv_behz_trace;
    const TensorCiphertext bfv_tensor_q = bfv_behz_multiply(
        bfv_ct_a, bfv_ct_b, q_moduli, b_moduli, m_sk,
        q_roots, bsk_roots, &bfv_behz_trace);
    SchemeMultiplyTrace bfv_relinearization_trace;
    const Ciphertext bfv_product_q = relinearize_tensor(
        bfv_tensor_q, secret_q, rlk_ntt,
        q_moduli, p_moduli, all_moduli, q_roots, all_roots,
        &bfv_relinearization_trace);
    const Poly bfv_decrypted_coeff_t = decrypt_bfv_scale_and_round(
        bfv_product_q, secret_q, q_moduli, q_roots);
    const auto bfv_decoded_slots = hpu::scheme::bfv::decode_slots(
        bfv_decrypted_coeff_t, g_plaintext_modulus);
    if (bfv_decrypted_coeff_t != bfv_expected_coeff_t
        || bfv_decoded_slots != bfv_expected_slots) {
        throw std::runtime_error("BFV BEHZ multiply/relinearize Decode failed");
    }

    Ciphertext bfv_product_qprime;
    for (std::size_t component = 0; component < 2; ++component) {
        bfv_product_qprime[component] = rescale_drop_last(
            bfv_product_q[component], q_moduli);
        verify_equal(
            bfv_product_qprime[component],
            direct_rounded_divide_last(bfv_product_q[component], q_moduli),
            "BFV ModSwitch direct rounded CRT check");
    }
    const Poly bfv_switched_coeff_t = decrypt_bfv_scale_and_round(
        bfv_product_qprime, secret_qprime,
        retained_q_moduli, retained_q_roots);
    if (bfv_switched_coeff_t != bfv_expected_coeff_t
        || hpu::scheme::bfv::decode_slots(
               bfv_switched_coeff_t, g_plaintext_modulus)
            != bfv_expected_slots) {
        throw std::runtime_error("BFV ModSwitch Decode failed");
    }

    std::vector<std::int64_t> bfv_noise_a(g_n);
    std::vector<std::int64_t> bfv_noise_b(g_n);
    for (std::size_t coefficient = 0; coefficient < g_n; ++coefficient) {
        bfv_noise_a[coefficient] = static_cast<std::int64_t>(coefficient % 3) - 1;
        bfv_noise_b[coefficient] = static_cast<std::int64_t>((2 * coefficient + 1) % 3) - 1;
    }
    const Ciphertext bfv_noise_ct_a = encrypt_bfv_test_message(
        bfv_plain_a, bfv_noise_a, secret_q, q_moduli, q_roots, rng);
    const Ciphertext bfv_noise_ct_b = encrypt_bfv_test_message(
        bfv_plain_b, bfv_noise_b, secret_q, q_moduli, q_roots, rng);
    const TensorCiphertext bfv_noise_tensor = bfv_behz_multiply(
        bfv_noise_ct_a, bfv_noise_ct_b, q_moduli, b_moduli, m_sk,
        q_roots, bsk_roots, nullptr);
    const Ciphertext bfv_noise_product = relinearize_tensor(
        bfv_noise_tensor, secret_q, rlk_ntt,
        q_moduli, p_moduli, all_moduli, q_roots, all_roots, nullptr);
    Ciphertext bfv_noise_switched;
    for (std::size_t component = 0; component < 2; ++component) {
        bfv_noise_switched[component] = rescale_drop_last(
            bfv_noise_product[component], q_moduli);
    }
    const Poly bfv_noise_result = decrypt_bfv_scale_and_round(
        bfv_noise_switched, secret_qprime,
        retained_q_moduli, retained_q_roots);
    if (bfv_noise_result != bfv_expected_coeff_t) {
        throw std::runtime_error("BFV nonzero-noise smoke Decode failed");
    }

    std::vector<Artifact> artifacts;
    std::vector<U64> words;
    append_words(words, ct_a[0]); append_words(words, ct_a[1]);
    add_artifact(artifacts, "input/ct_a_q.bin", "ciphertext A, coefficient domain",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
    words.clear(); append_words(words, ct_b[0]); append_words(words, ct_b[1]);
    add_artifact(artifacts, "input/ct_b_q.bin", "ciphertext B, coefficient domain",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
    words.clear(); append_words(words, secret_q);
    add_artifact(artifacts, "input/secret_key_q.bin", "test-only secret key",
                 {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"});
    add_artifact(artifacts, "input/message_a_mod_t.bin", "plaintext A",
                 {g_n}, encode_signed(message_a, g_plaintext_modulus));
    add_artifact(artifacts, "input/message_b_mod_t.bin", "plaintext B",
                 {g_n}, encode_signed(message_b, g_plaintext_modulus));

    words.clear();
    for (const auto& digit : rlk_ntt) {
        append_words(words, digit[0]); append_words(words, digit[1]);
    }
    add_artifact(artifacts, "constants/relinearization_key_ntt_qp.bin",
                 "rlk[digit][component][Q then P][coefficient]",
                 {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                 HardwareDomain::kNtt);

    words.clear(); append_words(words, ct_a_ntt[0]); append_words(words, ct_a_ntt[1]);
    append_words(words, ct_b_ntt[0]); append_words(words, ct_b_ntt[1]);
    add_artifact(artifacts, "expected/inputs_ntt_q.bin", "NTT(A0,A1,B0,B1)",
                 {4, g_num_q, g_n}, std::move(words),
                 {"input_component[A0,A1,B0,B1]", "basis_q", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    for (const BasisPoly& component : tensor_ntt) append_words(words, component);
    add_artifact(artifacts, "expected/tensor_ntt_q.bin", "t0,t1,t2 in NTT domain",
                 {3, g_num_q, g_n}, std::move(words),
                 {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear();
    for (const BasisPoly& component : tensor) append_words(words, component);
    add_artifact(artifacts, "expected/tensor_coeff_q.bin", "t0,t1,t2 in coefficient domain",
                 {3, g_num_q, g_n}, std::move(words),
                 {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"});
    words.clear(); for (const BasisPoly& digit : modup_coeff) append_words(words, digit);
    add_artifact(artifacts, "expected/modup_t2_coeff_qp.bin", "ModUp(t2 digit) coefficient domain",
                 {g_dnum, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "basis_q_then_p", "coefficient"});
    words.clear(); for (const BasisPoly& digit : modup_ntt) append_words(words, digit);
    add_artifact(artifacts, "expected/modup_t2_ntt_qp.bin", "ModUp(t2 digit) NTT domain",
                 {g_dnum, g_num_q + g_num_p, g_n}, std::move(words),
                 {"digit", "basis_q_then_p", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear(); append_words(words, keyswitch_ntt[0]); append_words(words, keyswitch_ntt[1]);
    add_artifact(artifacts, "expected/keyswitch_accum_ntt_qp.bin", "key-switch accumulators, NTT domain",
                 {2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                 HardwareDomain::kNtt);
    words.clear(); append_words(words, keyswitch_qp[0]); append_words(words, keyswitch_qp[1]);
    add_artifact(artifacts, "expected/keyswitch_coeff_qp.bin", "key-switch accumulators, coefficient domain",
                 {2, g_num_q + g_num_p, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q_then_p", "coefficient"});
    words.clear(); append_words(words, keyswitch_q[0]); append_words(words, keyswitch_q[1]);
    add_artifact(artifacts, "expected/keyswitch_moddown_q.bin", "ModDown key-switch result",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[ks0,ks1]", "basis_q", "coefficient"});
    words.clear(); append_words(words, output[0]); append_words(words, output[1]);
    add_artifact(artifacts, "expected/ciphertext_out_q.bin", "relinearized ciphertext output",
                 {2, g_num_q, g_n}, std::move(words),
                 {"component[c0,c1]", "basis_q", "coefficient"});
    words.clear(); append_words(words, output_decrypted);
    add_artifact(artifacts, "expected/decrypted_ring_q.bin", "test-only decrypted ring product",
                 {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"});
    add_artifact(artifacts, "expected/plaintext_product_mod_t.bin", "expected plaintext product",
                 {g_n}, expected_plain_mod_t);

    // The main package is generated output just like each standalone UT case.
    // Recreate it so files from an older readable-view schema cannot survive.
    std::filesystem::remove_all(output_root);
    for (Artifact& artifact : artifacts) {
        write_binary(output_root / artifact.path, artifact.words);
        write_readable_artifact(output_root, artifact);
    }
    write_hardware_package(output_root, artifacts, all_moduli, all_roots);

    std::ostringstream params;
    params << "{\n"
           << "  \"format_version\": 1,\n"
           << "  \"algorithm\": \"RLWE-RNS hybrid relinearization\",\n"
           << "  \"ring\": \"Z_m[x]/(x^N+1)\",\n"
           << "  \"N\": " << g_n << ",\n"
           << "  \"num_q\": " << g_num_q << ",\n"
           << "  \"num_p\": " << g_num_p << ",\n"
           << "  \"bfv_num_b\": " << g_bfv_num_b << ",\n"
           << "  \"hpu_mem_max_lines\": " << g_hpu_mem_max_lines << ",\n"
           << "  \"dnum\": " << g_dnum << ",\n"
           << "  \"plaintext_modulus\": " << g_plaintext_modulus << ",\n"
           << "  \"seed\": \"" << hex64(g_seed) << "\",\n"
           << "  \"basis_order\": \"Q[0.." << (g_num_q - 1)
           << "],P[0.." << (g_num_p - 1) << "]\",\n"
           << "  \"coefficient_encoding\": \"uint64 little-endian canonical residue\",\n"
           << "  \"hardware_coefficient_encoding\": \"uint32 little-endian, 64 words per 256-byte line\",\n"
           << "  \"hardware_package\": \"hardware/\",\n"
           << "  \"ntt_convention\": \"negacyclic twist, DIT cyclic NTT, natural-order output\",\n"
           << "  \"evaluation_key_noise\": 0,\n"
           << "  \"evaluation_key_fixture\": \"P-divisible exact functional key\",\n"
           << "  \"security_status\": \"FUNCTIONAL_TEST_ONLY\",\n"
           << "  \"q\": [";
    for (std::size_t i = 0; i < q_moduli.size(); ++i) params << (i ? ", " : "") << q_moduli[i];
    params << "],\n  \"p\": [";
    for (std::size_t i = 0; i < p_moduli.size(); ++i) params << (i ? ", " : "") << p_moduli[i];
    params << "],\n  \"psi_2n\": [";
    for (std::size_t i = 0; i < all_roots.size(); ++i) params << (i ? ", " : "") << all_roots[i];
    params << "]\n}\n";
    write_text(output_root / "params.json", params.str());

    std::ostringstream manifest;
    manifest << "path,readable_path,role,shape,elements,bytes,fnv1a64\n";
    for (const Artifact& artifact : artifacts) {
        manifest << csv_field(artifact.path) << ','
                 << csv_field(readable_path(artifact.path).string()) << ','
                 << csv_field(artifact.role) << ','
                 << csv_field(shape_string(artifact.shape))
                 << ',' << artifact.words.size() << ',' << artifact.words.size() * sizeof(U64)
                 << ',' << hex64(artifact.checksum) << '\n';
    }
    write_text(output_root / "artifact_manifest.csv", manifest.str());

    const std::string dma_plan =
        "phase,operation,logical_object,domain,basis,status\n"
        "input,dload,ct_a_q,coefficient,Q,READY\n"
        "input,dload,ct_b_q,coefficient,Q,READY\n"
        "transform,pmul_pre_twist,ct_a_and_ct_b,coefficient,Q,READY_UINT32_LINE_LAYOUT\n"
        "transform,pntt,ct_a_and_ct_b,NTT,Q,READY_UINT32_LINE_LAYOUT\n"
        "tensor,pmul_pmac,t0_t1_t2,NTT,Q,READY\n"
        "transform,pintt,t0_t1_t2,cyclic_inverse,Q,READY_UINT32_LINE_LAYOUT\n"
        "transform,pmul_post_untwist_scale,t0_t1_t2,coefficient,Q,READY_UINT32_LINE_LAYOUT\n"
        "relinearize,bconv,t2_digits,coefficient,Q_to_QP,READY\n"
        "relinearize,pmul_pre_twist,t2_digits,coefficient,QP,READY_UINT32_LINE_LAYOUT\n"
        "relinearize,pntt,t2_digits,NTT,QP,READY_UINT32_LINE_LAYOUT\n"
        "relinearize,pmul_pmac,rlk_and_t2_digits,NTT,QP,READY\n"
        "relinearize,pintt,keyswitch_accum,coefficient,QP,READY_UINT32_LINE_LAYOUT\n"
        "relinearize,pmul_post_untwist_scale,keyswitch_accum,coefficient,QP,READY_UINT32_LINE_LAYOUT\n"
        "relinearize,moddown,keyswitch_accum,coefficient,QP_to_Q,READY\n"
        "output,dstore,ciphertext_out_q,coefficient,Q,READY\n";
    write_text(output_root / "dma_plan.csv", dma_plan);

    std::ostringstream readme;
    readme
        << "# Ciphertext Multiply Golden Package\n\n"
        << "This directory is generated by `hpu_reference_vectors`. It is a deterministic, "
        << "algorithm-level RLWE/RNS multiplication and hybrid relinearization fixture for "
        << "`N=" << g_n << ", Q=" << g_num_q << ", P=" << g_num_p
        << ", dnum=" << g_dnum << "`.\n\n"
        << "Top-level binary files contain mathematical golden residues as little-endian uint64 values. Every binary "
        << "has a complete annotated `.dec.txt` view. Dimensions, readable paths, and checksums "
        << "are listed in `artifact_manifest.csv`; basis order is Q followed by P.\n\n"
        << "The independent `hardware/` tree contains uint32 hardware images, q/Barrett contexts, "
        << "physical per-stage twiddles, 256-byte line offsets/counts, and a complete HPU_MEM image/config.\n\n"
        << "The validation path is: encrypt two test messages, NTT, three-component tensor "
        << "product, INTT, digit ModUp to Q union P, NTT, multiply by the relinearization key, "
        << "INTT, ModDown by P, compose the two-component ciphertext, decrypt, and compare with "
        << "negacyclic plaintext multiplication modulo t.\n\n"
        << "The key and ciphertext use zero test noise and a P-divisible functional evaluation "
        << "key so failures are bit-exact and easy to localize. They are not security test vectors. "
        << "`memory_map.json` points to the generated uint32/256-byte host-memory layout. "
        << "Custom1 line sideband semantics, CSR offsets, Bank 5/mod-table mapping, and physical "
        << "NTT/INTT out-of-place behavior are frozen. The generated hpu_program_* C entry "
        << "accepts one concrete line offset/count span per DMA; the Nexus-AM hpu-it runtime "
        << "resolves the full layout, configures cache/CSR/fault/interrupt handling, and emits "
        << "a row-by-row relocation manifest. Target RTL evidence remains a qualification step.\n";
    write_text(output_root / "README.md", readme.str());

    std::ostringstream validation;
    validation << "PASS\nrelinearized_decryption == tensor_decryption\n"
               << "rescale_moddown == direct_rounded_CRT_division\n"
               << "decoded_plaintext == negacyclic(message_a * message_b) mod "
               << g_plaintext_modulus << '\n';
    write_text(output_root / "VALIDATION.txt", validation.str());

    if (suite_root != nullptr) {
        std::filesystem::remove_all(*suite_root / "bfv_behz_multiply");
        std::filesystem::remove_all(*suite_root / "bfv_relinearization");
        std::filesystem::remove(
            *suite_root / "bfv_ciphertext_multiply" / "pipeline.json");
        const auto common_params = [&](const std::string& operation,
                                       const std::string& input_domain,
                                       const std::string& output_domain,
                                       const std::vector<U64>& moduli) {
            std::ostringstream out;
            out << "{\n  \"format_version\": 1,\n  \"operation\": \"" << operation
                << "\",\n  \"N\": " << g_n << ",\n  \"input_domain\": \""
                << input_domain << "\",\n  \"output_domain\": \"" << output_domain
                << "\",\n  \"layout\": \"row-major, coefficient last, little-endian uint64\",\n"
                << "  \"hardware_layout\": \"hardware/: little-endian uint32; coefficient domain bit-reversed, NTT domain P-network physical; 64 words per 256-byte line\",\n"
                << "  \"moduli\": [";
            for (std::size_t i = 0; i < moduli.size(); ++i) {
                out << (i ? ", " : "") << moduli[i];
            }
            out << "]\n}\n";
            return out.str();
        };

        const auto scheme_params = [&](const std::string& scheme,
                                       const std::string& operation,
                                       const std::string& input_domain,
                                       const std::string& output_domain,
                                       const std::vector<U64>& moduli,
                                       const std::string& metadata_fields) {
            std::ostringstream out;
            out << "{\n  \"format_version\": 2,\n  \"scheme\": \"" << scheme
                << "\",\n  \"operation\": \"" << operation
                << "\",\n  \"N\": " << g_n << ",\n  \"input_domain\": \""
                << input_domain << "\",\n  \"output_domain\": \"" << output_domain
                << "\",\n  \"layout\": \"row-major, coefficient last, little-endian uint64\",\n"
                << "  \"hardware_layout\": \"hardware/: little-endian uint32; coefficient domain bit-reversed; 64 words per 256-byte line\",\n"
                << "  \"moduli\": [";
            for (std::size_t i = 0; i < moduli.size(); ++i) {
                out << (i ? ", " : "") << moduli[i];
            }
            out << "],\n" << metadata_fields << "\n}\n";
            return out.str();
        };

        std::vector<Artifact> case_artifacts;
        add_artifact(case_artifacts, "input.bin", "NTT input, coefficient domain",
                     {g_n}, ct_a[0][0]);
        add_artifact(case_artifacts, "expected.bin", "NTT expected output, NTT domain",
                     {g_n}, ct_a_ntt[0][0], {}, HardwareDomain::kNtt);
        write_case_package(*suite_root, "ntt",
                           common_params("ntt", "coefficient", "NTT", {q_moduli[0]}),
                           std::move(case_artifacts),
                           {q_moduli[0]}, {q_roots[0]},
                           TwiddleRequirement::kRequired);

        case_artifacts.clear();
        add_artifact(case_artifacts, "input.bin", "INTT input, NTT domain",
                     {g_n}, ct_a_ntt[0][0], {}, HardwareDomain::kNtt);
        add_artifact(case_artifacts, "expected.bin", "INTT expected output, coefficient domain",
                     {g_n}, ct_a[0][0]);
        write_case_package(*suite_root, "intt",
                           common_params("intt", "NTT", "coefficient", {q_moduli[0]}),
                           std::move(case_artifacts),
                           {q_moduli[0]}, {q_roots[0]},
                           TwiddleRequirement::kRequired);

        const BasisPoly ckks_encode_a_q = encode_basis(
            ckks_encoded_a.coefficients, q_moduli);
        const BasisPoly ckks_encode_b_q = encode_basis(
            ckks_encoded_b.coefficients, q_moduli);
        const BasisPoly ckks_encode_a_ntt = transform_basis(
            ckks_encode_a_q, q_moduli, q_roots, false);
        const BasisPoly ckks_encode_b_ntt = transform_basis(
            ckks_encode_b_q, q_moduli, q_roots, false);
        case_artifacts.clear();
        words.clear(); append_words(words, ckks_encode_a_q);
        add_artifact(case_artifacts, "input/plaintext_a_coeff_q.bin",
                     "CKKS host-encoded plaintext A, coefficient RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        words.clear(); append_words(words, ckks_encode_b_q);
        add_artifact(case_artifacts, "input/plaintext_b_coeff_q.bin",
                     "CKKS host-encoded plaintext B, coefficient RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        words.clear(); append_words(words, ckks_encode_a_ntt);
        add_artifact(case_artifacts, "expected/plaintext_a_ntt_q.bin",
                     "CKKS plaintext A ready for PMult, NTT RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"}, HardwareDomain::kNtt);
        words.clear(); append_words(words, ckks_encode_b_ntt);
        add_artifact(case_artifacts, "expected/plaintext_b_ntt_q.bin",
                     "CKKS plaintext B ready for PMult, NTT RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"}, HardwareDomain::kNtt);
        write_case_package(
            *suite_root, "ckks_encode",
            scheme_params(
                "CKKS", "encode",
                "host complex slots -> signed coefficients -> coefficient/RNS-Q",
                "plaintext/NTT/Q", q_moduli,
                "  \"slot_count\": " + std::to_string(g_n / 2) + ",\n"
                "  \"slot_layout\": \"generator-3 canonical embedding with conjugate half\",\n"
                "  \"scale\": " + std::to_string(ckks_input_scale) + ",\n"
                "  \"level\": " + std::to_string(g_num_q - 1) + ",\n"
                "  \"roundtrip_error_bound\": "
                    + std::to_string(ckks_encode_bound) + ",\n"
                "  \"decode_location\": \"host_only\",\n"
                "  \"hpu_operation\": \"per-Q-limb negacyclic NTT\""),
            std::move(case_artifacts), q_moduli, q_roots,
            TwiddleRequirement::kRequired);
        write_host_package(
            *suite_root / "ckks_encode" / "test_data",
            {
                {"slots_a.csv", "input complex slots A",
                 complex_slots_csv(ckks_slots_a, "input")},
                {"slots_b.csv", "input complex slots B",
                 complex_slots_csv(ckks_slots_b, "input")},
                {"decoded_a.csv", "decoded slots A after host round-trip",
                 complex_slots_csv(ckks_roundtrip_a, "decoded")},
                {"decoded_b.csv", "decoded slots B after host round-trip",
                 complex_slots_csv(ckks_roundtrip_b, "decoded")},
                {"coefficients_a.csv", "signed scaled CKKS coefficients A",
                 signed_values_csv(ckks_encoded_a.coefficients, "coefficient")},
                {"coefficients_b.csv", "signed scaled CKKS coefficients B",
                 signed_values_csv(ckks_encoded_b.coefficients, "coefficient")},
                {"rotate_left_1_expected_slots.csv",
                 "expected CKKS vector rotation left by one slot",
                 complex_slots_csv(ckks_rotated_slots_a, "expected")},
                {"error_stats.csv", "CKKS Encode/Decode error summary",
                 "vector,max_abs_error,error_bound,pass\nA,"
                    + std::to_string(ckks_encode_max_error_a) + ","
                    + std::to_string(ckks_encode_bound) + ",1\nB,"
                    + std::to_string(ckks_encode_max_error_b) + ","
                    + std::to_string(ckks_encode_bound) + ",1\n"},
                {"validation.txt", "host Encode/Decode status",
                 "PASS\nslot_layout=generator-3\nzero_fill=PASS\n"
                 "roundtrip_error_within_bound=PASS\n"},
            });
        write_text(
            *suite_root / "ckks_encode" / "test_data" / "dma_plan.csv",
            "vector,phase,operation,logical_object,domain,basis,status\n"
            "A,input,dload,plaintext_a_coeff_q,coefficient,Q,READY\n"
            "A,transform,pntt,plaintext_a,NTT,Q,READY\n"
            "A,output,dstore,plaintext_a_ntt_q,NTT,Q,READY\n"
            "B,input,dload,plaintext_b_coeff_q,coefficient,Q,READY\n"
            "B,transform,pntt,plaintext_b,NTT,Q,READY\n"
            "B,output,dstore,plaintext_b_ntt_q,NTT,Q,READY\n");

        std::vector<std::int64_t> bgv_coefficient_sample(g_n, 0);
        const std::vector<std::int64_t> bgv_coefficient_prefix{
            0, 1, -1, 7, -7,
            static_cast<std::int64_t>(g_plaintext_modulus / 2),
            -static_cast<std::int64_t>(g_plaintext_modulus / 2)};
        std::copy(bgv_coefficient_prefix.begin(), bgv_coefficient_prefix.end(),
                  bgv_coefficient_sample.begin());
        const Poly bgv_coefficient_t = hpu::scheme::bgv::encode_coefficients(
            bgv_coefficient_sample, g_n, g_plaintext_modulus);
        const auto bgv_coefficient_decoded = hpu::scheme::bgv::decode_coefficients(
            bgv_coefficient_t, g_plaintext_modulus);
        const BasisPoly bgv_coefficient_q = lift_basis(
            bgv_coefficient_t, q_moduli);
        const BasisPoly bgv_batch_q = lift_basis(bgv_plain_a, q_moduli);
        const BasisPoly bgv_coefficient_ntt = transform_basis(
            bgv_coefficient_q, q_moduli, q_roots, false);
        const BasisPoly bgv_batch_ntt = transform_basis(
            bgv_batch_q, q_moduli, q_roots, false);
        case_artifacts.clear();
        words.clear(); append_words(words, bgv_coefficient_q);
        add_artifact(case_artifacts, "input/coefficient_plaintext_q.bin",
                     "BGV coefficient-encoded plaintext, coefficient RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        words.clear(); append_words(words, bgv_batch_q);
        add_artifact(case_artifacts, "input/batch_plaintext_q.bin",
                     "BGV generator-3 batched plaintext, coefficient RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        words.clear(); append_words(words, bgv_coefficient_ntt);
        add_artifact(case_artifacts, "expected/coefficient_plaintext_ntt_q.bin",
                     "BGV coefficient plaintext ready for PMult, NTT RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"}, HardwareDomain::kNtt);
        words.clear(); append_words(words, bgv_batch_ntt);
        add_artifact(case_artifacts, "expected/batch_plaintext_ntt_q.bin",
                     "BGV batched plaintext ready for PMult, NTT RNS-Q",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"}, HardwareDomain::kNtt);
        write_case_package(
            *suite_root, "bgv_encode",
            scheme_params(
                "BGV", "coefficient_encode_and_batch_encode",
                "host signed coefficients or N slots -> coefficient/RNS-Q",
                "plaintext/NTT/Q", q_moduli,
                "  \"plaintext_modulus\": "
                    + std::to_string(g_plaintext_modulus) + ",\n"
                "  \"slot_count\": " + std::to_string(g_n) + ",\n"
                "  \"slot_layout\": \"generator-3, two rows of N/2\",\n"
                "  \"batching_condition\": \"t prime and 2N divides t-1\",\n"
                "  \"decode_location\": \"host_only\",\n"
                "  \"hpu_operation\": \"per-Q-limb negacyclic NTT\""),
            std::move(case_artifacts), q_moduli, q_roots,
            TwiddleRequirement::kRequired);
        write_host_package(
            *suite_root / "bgv_encode" / "test_data",
            {
                {"coefficient_input.csv", "signed coefficient input",
                 signed_values_csv(bgv_coefficient_sample, "input")},
                {"coefficient_encoded_mod_t.csv", "coefficient encoding modulo t",
                 residues_csv(bgv_coefficient_t, "coefficient_mod_t")},
                {"coefficient_decoded.csv", "decoded signed coefficients",
                 signed_values_csv(bgv_coefficient_decoded, "decoded")},
                {"batch_slots.csv", "two-row generator-3 input slots",
                 signed_values_csv(bgv_slots_a, "input")},
                {"batch_coefficients_mod_t.csv", "batched polynomial modulo t",
                 residues_csv(bgv_plain_a, "coefficient_mod_t")},
                {"batch_decoded_slots.csv", "decoded batch slots",
                 signed_values_csv(
                     hpu::scheme::bgv::decode_slots(
                         bgv_plain_a, g_plaintext_modulus),
                     "decoded")},
                {"auto_x3_expected_slots.csv", "expected X->X^3 row rotations",
                 signed_values_csv(bgv_expected_auto_slots, "expected")},
                {"auto_x3_decoded_slots.csv", "ciphertext Auto decoded row rotations",
                 signed_values_csv(bgv_auto_decoded_slots, "rotated")},
                {"validation.txt", "host Encode/Decode and Auto status",
                 "PASS\ncoefficient_roundtrip=PASS\nbatch_roundtrip=PASS\n"
                 "auto_x_to_x3_ciphertext_keyswitch_two_rows_left_rotate=PASS\n"},
            });
        write_text(
            *suite_root / "bgv_encode" / "test_data" / "dma_plan.csv",
            "vector,phase,operation,logical_object,domain,basis,status\n"
            "coefficient,input,dload,coefficient_plaintext_q,coefficient,Q,READY\n"
            "coefficient,transform,pntt,coefficient_plaintext,NTT,Q,READY\n"
            "coefficient,output,dstore,coefficient_plaintext_ntt_q,NTT,Q,READY\n"
            "batch,input,dload,batch_plaintext_q,coefficient,Q,READY\n"
            "batch,transform,pntt,batch_plaintext,NTT,Q,READY\n"
            "batch,output,dstore,batch_plaintext_ntt_q,NTT,Q,READY\n");

        case_artifacts.clear();
        words.clear(); append_words(words, ct_a[0]); append_words(words, ct_a[1]);
        add_artifact(case_artifacts, "input_q.bin",
                     "two-component ciphertext before rounded level drop",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"});

        BasisPoly half_constants(g_num_q, Poly(g_n));
        const U64 dropped_modulus = q_moduli.back();
        const U64 half = dropped_modulus / 2;
        for (std::size_t basis = 0; basis < g_num_q; ++basis) {
            std::fill(half_constants[basis].begin(), half_constants[basis].end(),
                      half % q_moduli[basis]);
        }
        words.clear(); append_words(words, half_constants);
        add_artifact(case_artifacts, "constants/q_last_half_mod_q.bin",
                     "floor(q_last/2) reduced in every Q context",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});

        add_artifact(case_artifacts, "constants/qhat_inv_drop.bin",
                     "single-source BConv qhat inverse (all ones)",
                     {1, g_n}, Poly(g_n, 1),
                     {"source_basis", "coefficient"});
        BasisPoly qhat_mod_qprime(g_num_q - 1, Poly(g_n, 1));
        words.clear(); append_words(words, qhat_mod_qprime);
        add_artifact(case_artifacts, "constants/qhat_mod_qprime.bin",
                     "single-source BConv qhat residues (all ones)",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"target_basis_qprime", "coefficient"});

        BasisPoly dropped_inverse(g_num_q - 1, Poly(g_n));
        for (std::size_t basis = 0; basis + 1 < g_num_q; ++basis) {
            std::fill(dropped_inverse[basis].begin(), dropped_inverse[basis].end(),
                      inverse_mod(dropped_modulus % q_moduli[basis], q_moduli[basis]));
        }
        words.clear(); append_words(words, dropped_inverse);
        add_artifact(case_artifacts, "constants/q_last_inv_mod_qprime.bin",
                     "q_last inverse in every retained Q context",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});

        words.clear();
        append_words(words, rescaled_ct_a[0]);
        append_words(words, rescaled_ct_a[1]);
        add_artifact(case_artifacts, "expected_qprime.bin",
                     "rounded ciphertext after dropping q_last",
                     {2, g_num_q - 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_qprime", "coefficient"});
        write_case_package(*suite_root, "ckks_rescale",
                           scheme_params(
                               "CKKS",
                               "rescale",
                               "ciphertext/coefficient/Q",
                               "ciphertext/coefficient/Q_without_last",
                               q_moduli,
                               "  \"level_delta\": -1,\n"
                               "  \"scale_rule\": \"scale_out=scale_in/q_last\",\n"
                               "  \"metadata_test_input_scale\": "
                                   + std::to_string(ckks_product_scale) + ",\n"
                               "  \"metadata_test_output_scale\": "
                                   + std::to_string(ckks_output_scale)),
                           std::move(case_artifacts), q_moduli, q_roots,
                           TwiddleRequirement::kNone);
        write_text(
            *suite_root / "ckks_rescale" / "test_data" / "dma_plan.csv",
            "phase,operation,logical_object,domain,basis,status\n"
            "input,dload,ciphertext_component,coefficient,Q,READY\n"
            "round,padd,ciphertext_component_and_q_last_half,coefficient,Q,READY\n"
            "scratch,dstore,rounded_numerator,coefficient,Q,READY\n"
            "drop,bconv,rounded_q_last,coefficient,q_last_to_Qprime,READY\n"
            "divide,psub_pmul,rounded_numerator,coefficient,Qprime,READY\n"
            "output,dstore,ciphertext_component_out,coefficient,Qprime,READY\n");

        case_artifacts.clear();
        add_scheme_multiply_artifacts(
            case_artifacts, ckks_ct_a, ckks_ct_b,
            ckks_multiply_trace, rlk_ntt, ckks_product_q);
        words.clear(); append_words(words, half_constants);
        add_artifact(case_artifacts, "constants/q_last_half_mod_q.bin",
                     "floor(q_last/2) reduced in every Q context",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        add_artifact(case_artifacts, "constants/rescale_qhat_inv.bin",
                     "single-source Rescale BConv qhat inverse",
                     {1, g_n}, Poly(g_n, 1));
        words.clear(); append_words(words, qhat_mod_qprime);
        add_artifact(case_artifacts, "constants/rescale_qhat_mod_qprime.bin",
                     "single-source Rescale BConv target residues",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        words.clear(); append_words(words, dropped_inverse);
        add_artifact(case_artifacts, "constants/q_last_inv_mod_qprime.bin",
                     "q_last inverse in every retained Q context",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        words.clear();
        append_words(words, ckks_product_qprime[0]);
        append_words(words, ckks_product_qprime[1]);
        add_artifact(case_artifacts, "expected/ciphertext_out_qprime.bin",
                     "CKKS multiply/relinearize/Rescale output",
                     {2, g_num_q - 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_qprime", "coefficient"});
        words.clear(); append_words(words, ckks_decrypted_qprime);
        add_artifact(case_artifacts, "expected/decrypted_scaled_qprime.bin",
                     "decrypted approximate scaled product",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        words.clear(); append_words(words, ckks_ideal_qprime);
        add_artifact(case_artifacts, "expected/ideal_scaled_product_qprime.bin",
                     "ideal plaintext product at output scale",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        write_case_package(
            *suite_root,
            "ckks_ciphertext_multiply",
            scheme_params(
                "CKKS",
                "ciphertext_multiply_relinearize_rescale",
                "two ciphertexts/coefficient/Q + rlk/NTT/QP",
                "ciphertext/coefficient/Q_without_last",
                all_moduli,
                "  \"context_order\": \"Q|P\",\n"
                "  \"level_delta\": -1,\n"
                "  \"q_last\": " + std::to_string(q_moduli.back()) + ",\n"
                "  \"input_scale_a\": " + std::to_string(ckks_input_scale) + ",\n"
                "  \"input_scale_b\": " + std::to_string(ckks_input_scale) + ",\n"
                "  \"product_scale\": " + std::to_string(ckks_product_scale) + ",\n"
                "  \"output_scale\": " + std::to_string(ckks_output_scale) + ",\n"
                "  \"max_abs_decode_error\": " + std::to_string(ckks_max_abs_error) + ",\n"
                "  \"decode_error_bound\": " + std::to_string(ckks_error_bound)),
            std::move(case_artifacts), all_moduli, all_roots,
            TwiddleRequirement::kRequired);
        write_text(
            *suite_root / "ckks_ciphertext_multiply" / "test_data" / "SCHEME_VALIDATION.txt",
            "PASS\ncommon_multiply_and_relinearize=PASS\n"
            "rescale_direct_rounded_crt=PASS\n"
            "scale_out=scale_a*scale_b/q_last\n"
            "decoded_error_within_bound=PASS\n");
        write_host_package(
            *suite_root / "ckks_ciphertext_multiply" / "test_data",
            {
                {"input_slots_a.csv", "CKKS input slots A",
                 complex_slots_csv(ckks_slots_a, "input")},
                {"input_slots_b.csv", "CKKS input slots B",
                 complex_slots_csv(ckks_slots_b, "input")},
                {"decoded_product.csv", "expected and decoded CKKS slot product",
                 complex_comparison_csv(
                     ckks_expected_slots, ckks_decoded_product)},
                {"validation.txt", "end-to-end CKKS slot validation",
                 "PASS\nencode=PASS\nencrypt=PASS\nmultiply=PASS\n"
                 "relinearize=PASS\nrescale=PASS\ndecrypt=PASS\ndecode=PASS\n"},
            });
        write_text(
            *suite_root / "ckks_ciphertext_multiply" / "test_data" / "dma_plan.csv",
            "phase,operation,logical_object,domain,basis,status\n"
            "input,dload,ct_a_q_and_ct_b_q,coefficient,Q,READY\n"
            "multiply,ntt_tensor_intt,t0_t1_t2,coefficient,Q,READY\n"
            "relinearize,keyswitch_moddown,t2_and_rlk,coefficient,Q|P_to_Q,READY\n"
            "rescale,padd_bconv_psub_pmul,c0_and_c1,coefficient,Q_to_Qprime,READY\n"
            "output,dstore,ciphertext_out_qprime,coefficient,Qprime,READY\n");

        case_artifacts.clear();
        add_scheme_multiply_artifacts(
            case_artifacts, bgv_ct_a, bgv_ct_b,
            bgv_multiply_trace, rlk_ntt, bgv_product_q);
        words.clear(); append_words(words, bgv_decrypted_q);
        add_artifact(case_artifacts, "expected/decrypted_ring_q.bin",
                     "BGV decrypted phase before correction-factor removal",
                     {g_num_q, g_n}, std::move(words),
                     {"basis_q", "coefficient"});
        add_artifact(case_artifacts, "expected/decrypted_phase_mod_t.bin",
                     "centered CRT phase reduced modulo t",
                     {g_n}, bgv_phase_mod_t);
        add_artifact(case_artifacts, "expected/plaintext_product_mod_t.bin",
                     "decoded BGV batched plaintext product coefficients",
                     {g_n}, bgv_expected_coeff_t);
        write_case_package(
            *suite_root,
            "bgv_ciphertext_multiply",
            scheme_params(
                "BGV",
                "ciphertext_multiply_relinearize",
                "two ciphertexts/coefficient/Q + rlk/NTT/QP",
                "ciphertext/coefficient/Q",
                bgv_moduli,
                "  \"context_order\": \"Q|P|t\",\n"
                "  \"t_mod_id\": " + std::to_string(g_num_q + g_num_p) + ",\n"
                "  \"plaintext_modulus\": " + std::to_string(g_plaintext_modulus) + ",\n"
                "  \"correction_factor_a\": " + std::to_string(kBgvFactorA) + ",\n"
                "  \"correction_factor_b\": " + std::to_string(kBgvFactorB) + ",\n"
                "  \"correction_factor_out\": " + std::to_string(bgv_multiply_factor)),
            std::move(case_artifacts), bgv_moduli, bgv_roots,
            TwiddleRequirement::kRequired);
        write_text(
            *suite_root / "bgv_ciphertext_multiply" / "test_data" / "SCHEME_VALIDATION.txt",
            "PASS\ncommon_multiply_and_relinearize=PASS\n"
            "correction_factor_out=factor_a*factor_b_mod_t\n"
            "decoded_plaintext_product_mod_t=PASS\n");
        write_host_package(
            *suite_root / "bgv_ciphertext_multiply" / "test_data",
            {
                {"input_slots_a.csv", "BGV batched input slots A",
                 signed_values_csv(bgv_slots_a, "input")},
                {"input_slots_b.csv", "BGV batched input slots B",
                 signed_values_csv(bgv_slots_b, "input")},
                {"decoded_product.csv", "expected and decoded BGV slot product",
                 signed_comparison_csv(
                     bgv_expected_slots, bgv_decoded_slots)},
                {"validation.txt", "end-to-end BGV multiply validation",
                 "PASS\nencode=PASS\nencrypt=PASS\nmultiply=PASS\n"
                 "relinearize=PASS\ndecrypt=PASS\nremove_factor=PASS\ndecode=PASS\n"},
            });
        write_text(
            *suite_root / "bgv_ciphertext_multiply" / "test_data" / "dma_plan.csv",
            "phase,operation,logical_object,domain,basis,status\n"
            "input,dload,ct_a_q_and_ct_b_q,coefficient,Q,READY\n"
            "multiply,ntt_tensor_intt,t0_t1_t2,coefficient,Q,READY\n"
            "relinearize,keyswitch_moddown,t2_and_rlk,coefficient,Q|P_to_Q,READY\n"
            "metadata,host_update,correction_factor,scalar,t,READY\n"
            "output,dstore,ciphertext_out_q,coefficient,Q,READY\n");

        case_artifacts.clear();
        words.clear();
        append_words(words, bgv_product_q[0]);
        append_words(words, bgv_product_q[1]);
        add_artifact(case_artifacts, "input_q.bin",
                     "two-component BGV ciphertext before ModSwitch",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"});
        BasisPoly bgv_c_last_mod_t(2);
        BasisPoly bgv_u_mod_t(2);
        std::vector<BasisPoly> bgv_c_last_mod_qprime(2);
        std::vector<BasisPoly> bgv_u_mod_qprime(2);
        for (std::size_t component = 0; component < 2; ++component) {
            bgv_c_last_mod_t[component] = bgv_modswitch_trace[component].c_last_mod_t;
            bgv_u_mod_t[component] = bgv_modswitch_trace[component].u_mod_t;
            bgv_c_last_mod_qprime[component] =
                bgv_modswitch_trace[component].c_last_mod_qprime;
            bgv_u_mod_qprime[component] =
                bgv_modswitch_trace[component].u_mod_qprime;
        }
        words.clear(); append_words(words, bgv_c_last_mod_t);
        add_artifact(case_artifacts, "intermediate/c_last_mod_t.bin",
                     "single-source BConv q_last to t",
                     {2, 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_t", "coefficient"});
        words.clear(); append_words(words, bgv_u_mod_t);
        add_artifact(case_artifacts, "intermediate/u_mod_t.bin",
                     "u=-c_last*q_last^-1 mod t",
                     {2, 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_t", "coefficient"});
        words.clear();
        for (const BasisPoly& component : bgv_c_last_mod_qprime) {
            append_words(words, component);
        }
        add_artifact(case_artifacts, "intermediate/c_last_mod_qprime.bin",
                     "single-source BConv q_last to retained Q",
                     {2, g_num_q - 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_qprime", "coefficient"});
        words.clear();
        for (const BasisPoly& component : bgv_u_mod_qprime) {
            append_words(words, component);
        }
        add_artifact(case_artifacts, "intermediate/u_mod_qprime.bin",
                     "single-source BConv t to retained Q",
                     {2, g_num_q - 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_qprime", "coefficient"});
        add_artifact(case_artifacts, "constants/zero_mod_t.bin",
                     "zero polynomial for modular negation under t",
                     {g_n}, Poly(g_n, 0));
        add_artifact(case_artifacts, "constants/q_last_inv_mod_t.bin",
                     "q_last inverse modulo t",
                     {g_n}, Poly(g_n, q_last_inverse_t));
        add_artifact(case_artifacts, "constants/bconv_qhat_inv.bin",
                     "single-source BConv qhat inverse, reused by all three conversions",
                     {g_n}, Poly(g_n, 1));
        add_artifact(case_artifacts, "constants/bconv_qhat_target_t.bin",
                     "single-source BConv target residue for q_last to t",
                     {1, g_n}, Poly(g_n, 1),
                     {"basis_t", "coefficient"});
        BasisPoly bgv_bconv_target_ones(g_num_q - 1, Poly(g_n, 1));
        words.clear(); append_words(words, bgv_bconv_target_ones);
        add_artifact(case_artifacts, "constants/bconv_qhat_target.bin",
                     "single-source BConv target residues",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        BasisPoly q_last_mod_qprime(g_num_q - 1, Poly(g_n));
        BasisPoly q_last_inv_qprime(g_num_q - 1, Poly(g_n));
        for (std::size_t basis = 0; basis + 1 < g_num_q; ++basis) {
            std::fill(q_last_mod_qprime[basis].begin(),
                      q_last_mod_qprime[basis].end(),
                      q_moduli.back() % q_moduli[basis]);
            std::fill(q_last_inv_qprime[basis].begin(),
                      q_last_inv_qprime[basis].end(),
                      inverse_mod(q_moduli.back() % q_moduli[basis], q_moduli[basis]));
        }
        words.clear(); append_words(words, q_last_mod_qprime);
        add_artifact(case_artifacts, "constants/q_last_mod_qprime.bin",
                     "q_last reduced in every retained Q context",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        words.clear(); append_words(words, q_last_inv_qprime);
        add_artifact(case_artifacts, "constants/q_last_inv_mod_qprime.bin",
                     "q_last inverse in every retained Q context",
                     {g_num_q - 1, g_n}, std::move(words),
                     {"basis_qprime", "coefficient"});
        words.clear();
        append_words(words, bgv_product_qprime[0]);
        append_words(words, bgv_product_qprime[1]);
        add_artifact(case_artifacts, "expected_qprime.bin",
                     "BGV ciphertext after dropping q_last",
                     {2, g_num_q - 1, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_qprime", "coefficient"});
        add_artifact(case_artifacts, "expected/decrypted_phase_mod_t.bin",
                     "switched BGV phase reduced modulo t",
                     {g_n}, bgv_switched_phase_mod_t);
        add_artifact(case_artifacts, "expected/plaintext_product_mod_t.bin",
                     "decoded plaintext after correction-factor removal",
                     {g_n}, bgv_expected_coeff_t);
        write_case_package(
            *suite_root,
            "bgv_modswitch",
            scheme_params(
                "BGV",
                "modswitch_drop_last",
                "ciphertext/coefficient/Q",
                "ciphertext/coefficient/Q_without_last",
                bgv_moduli,
                "  \"context_order\": \"Q|P|t\",\n"
                "  \"t_mod_id\": " + std::to_string(g_num_q + g_num_p) + ",\n"
                "  \"plaintext_modulus\": " + std::to_string(g_plaintext_modulus) + ",\n"
                "  \"q_last\": " + std::to_string(q_moduli.back()) + ",\n"
                "  \"correction_factor_in\": " + std::to_string(bgv_multiply_factor) + ",\n"
                "  \"correction_factor_out\": " + std::to_string(bgv_modswitch_factor) + ",\n"
                "  \"correction_factor_rule\": \"cf_out=cf_in*q_last^-1 mod t\",\n"
                "  \"level_delta\": -1"),
            std::move(case_artifacts), bgv_moduli, bgv_roots,
            TwiddleRequirement::kNone);
        write_text(
            *suite_root / "bgv_modswitch" / "test_data" / "SCHEME_VALIDATION.txt",
            "PASS\nq_last_to_t_bconv=PASS\n"
            "u=-c_last*q_last^-1_mod_t=PASS\n"
            "coefficient_modswitch_formula=PASS\n"
            "correction_factor_update=PASS\n"
            "decoded_plaintext_preserved=PASS\n");
        write_host_package(
            *suite_root / "bgv_modswitch" / "test_data",
            {
                {"decoded_product_after_modswitch.csv",
                 "expected and decoded BGV slots after ModSwitch",
                 signed_comparison_csv(
                     bgv_expected_slots, bgv_switched_slots)},
                {"validation.txt", "end-to-end BGV ModSwitch validation",
                 "PASS\nmodswitch=PASS\ncorrection_factor_update=PASS\n"
                 "decrypt=PASS\nremove_factor=PASS\ndecode=PASS\n"},
            });
        write_text(
            *suite_root / "bgv_modswitch" / "test_data" / "dma_plan.csv",
            "phase,operation,logical_object,domain,basis,status\n"
            "input,dload,ciphertext_component,coefficient,Q,READY\n"
            "convert,bconv,c_last,coefficient,q_last_to_t,READY\n"
            "correction,psub_pmul,u,coefficient,t,READY\n"
            "scratch,dstore,u,coefficient,t,READY\n"
            "convert,bconv,c_last,coefficient,q_last_to_Qprime,READY\n"
            "convert,bconv,u,coefficient,t_to_Qprime,READY\n"
            "switch,pmul_padd_psub,ciphertext_component,coefficient,Qprime,READY\n"
            "metadata,host_update,correction_factor,scalar,t,READY\n"
            "output,dstore,ciphertext_component_out,coefficient,Qprime,READY\n");

        const Poly bfv_coefficient_t = hpu::scheme::bfv::encode_coefficients(
            bgv_coefficient_sample, g_n, g_plaintext_modulus);
        const BasisPoly bfv_coefficient_q = lift_basis(
            bfv_coefficient_t, q_moduli);
        const BasisPoly bfv_batch_q = lift_basis(bfv_plain_a, q_moduli);
        const BasisPoly bfv_batch_ntt = transform_basis(
            bfv_batch_q, q_moduli, q_roots, false);
        case_artifacts.clear();
        words.clear(); append_words(words, bfv_coefficient_q);
        add_artifact(
            case_artifacts, "host/coefficient_plaintext_q.bin",
            "BFV coefficient encoding example, coefficient RNS-Q",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"}, HardwareDomain::kCoefficient, false);
        words.clear(); append_words(words, bfv_batch_q);
        add_artifact(
            case_artifacts, "input/batch_plaintext_q.bin",
            "BFV generator-3 batched plaintext, coefficient RNS-Q",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"});
        add_artifact(
            case_artifacts, "runtime/output_ntt_q.bin",
            "zero-initialized destination for the BFV Encode kernel",
            {g_num_q, g_n}, Poly(g_num_q * g_n, 0),
            {"basis_q", "coefficient"}, HardwareDomain::kNtt);
        words.clear(); append_words(words, bfv_batch_ntt);
        add_artifact(
            case_artifacts, "expected/batch_plaintext_ntt_q.bin",
            "golden BFV plaintext ready for PMult, NTT RNS-Q",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"}, HardwareDomain::kNtt, false);
        write_case_package(
            *suite_root, "bfv_encode",
            scheme_params(
                "BFV", "coefficient_encode_and_batch_encode",
                "host signed coefficients or N slots -> coefficient/RNS-Q",
                "plaintext/NTT/Q", q_moduli,
                "  \"plaintext_modulus\": "
                    + std::to_string(g_plaintext_modulus) + ",\n"
                "  \"slot_count\": " + std::to_string(g_n) + ",\n"
                "  \"slot_layout\": \"generator-3, two rows of N/2\",\n"
                "  \"batching_condition\": \"t prime and 2N divides t-1\",\n"
                "  \"decode_location\": \"host_only\",\n"
                "  \"hpu_operation\": \"per-Q-limb negacyclic NTT\""),
            std::move(case_artifacts), q_moduli, q_roots,
            TwiddleRequirement::kRequired);
        write_host_package(
            *suite_root / "bfv_encode" / "test_data",
            {
                {"coefficient_input.csv", "signed BFV coefficient input",
                 signed_values_csv(bgv_coefficient_sample, "input")},
                {"coefficient_encoded_mod_t.csv", "BFV coefficient encoding modulo t",
                 residues_csv(bfv_coefficient_t, "coefficient_mod_t")},
                {"batch_slots.csv", "two-row generator-3 input slots",
                 signed_values_csv(bfv_slots_a, "input")},
                {"batch_coefficients_mod_t.csv", "BFV batched polynomial modulo t",
                 residues_csv(bfv_plain_a, "coefficient_mod_t")},
                {"batch_decoded_slots.csv", "decoded BFV batch slots",
                 signed_values_csv(
                     hpu::scheme::bfv::decode_slots(
                         bfv_plain_a, g_plaintext_modulus),
                     "decoded")},
                {"rotate_left_1_expected_slots.csv",
                 "expected BFV two-row rotation left by one slot",
                 signed_values_csv(bgv_expected_auto_slots, "expected")},
                {"validation.txt", "BFV host Encode/Decode status",
                 "PASS\ncoefficient_roundtrip=PASS\nbatch_roundtrip=PASS\n"},
            });
        DmaPlanBuilder bfv_encode_dma(read_line_catalog(
            *suite_root / "bfv_encode" / "test_data" /
            "hardware" / "line_map.csv"));
        std::vector<DmaSpan> bfv_encode_input;
        std::vector<DmaSpan> bfv_encode_output;
        std::vector<int> bfv_encode_contexts;
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            bfv_encode_input.push_back(bfv_encode_dma.poly(
                "images/input/batch_plaintext_q.u32.bin", basis,
                "bfv_batch_plaintext_q[" + std::to_string(basis) + "]"));
            bfv_encode_output.push_back(bfv_encode_dma.poly(
                "images/runtime/output_ntt_q.u32.bin", basis,
                "bfv_batch_plaintext_ntt_q[" + std::to_string(basis) + "]"));
            bfv_encode_contexts.push_back(static_cast<int>(basis));
        }
        bfv_encode_dma.transform_between(
            {bfv_encode_input}, {bfv_encode_output},
            bfv_encode_contexts, false);
        write_resolved_dma_plan(
            *suite_root, "bfv_encode", bfv_encode_dma.records());

        const FastBconvConstants q_to_bsk_constants =
            make_fast_bconv_constants(q_moduli, bsk_moduli);
        const FastBconvConstants b_to_q_constants =
            make_fast_bconv_constants(b_moduli, q_moduli);
        const FastBconvConstants b_to_msk_constants =
            make_fast_bconv_constants(b_moduli, {m_sk});
        const FastBconvConstants msk_to_q_constants =
            make_fast_bconv_constants({m_sk}, q_moduli);

        case_artifacts.clear();
        words.clear(); append_words(words, bfv_ct_a[0]); append_words(words, bfv_ct_a[1]);
        add_artifact(
            case_artifacts, "input/ct_a_q.bin",
            "zero-noise BFV ciphertext A, coefficient Q",
            {2, g_num_q, g_n}, std::move(words),
            {"component[c0,c1]", "basis_q", "coefficient"});
        words.clear(); append_words(words, bfv_ct_b[0]); append_words(words, bfv_ct_b[1]);
        add_artifact(
            case_artifacts, "input/ct_b_q.bin",
            "zero-noise BFV ciphertext B, coefficient Q",
            {2, g_num_q, g_n}, std::move(words),
            {"component[c0,c1]", "basis_q", "coefficient"});

        words.clear(); append_words(words, q_to_bsk_constants.source_hat_inverse);
        add_artifact(
            case_artifacts, "constants/q_to_bsk_qhat_inv.bin",
            "FastBConv Q source-hat inverses",
            {g_num_q, g_n}, std::move(words),
            {"source_basis_q", "coefficient"});
        words.clear();
        for (const BasisPoly& target : q_to_bsk_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/q_to_bsk_qhat_mod.bin",
            "FastBConv Q source hats reduced in every Bsk target",
            {bsk_moduli.size(), g_num_q, g_n}, std::move(words),
            {"target_basis_bsk", "source_basis_q", "coefficient"});

        BasisPoly t_mod_q_bsk;
        std::vector<U64> q_bsk_moduli = q_moduli;
        q_bsk_moduli.insert(
            q_bsk_moduli.end(), bsk_moduli.begin(), bsk_moduli.end());
        for (U64 modulus : q_bsk_moduli) {
            t_mod_q_bsk.push_back(Poly(
                g_n, g_plaintext_modulus % modulus));
        }
        words.clear(); append_words(words, t_mod_q_bsk);
        add_artifact(
            case_artifacts, "constants/t_mod_q_bsk.bin",
            "plaintext modulus t reduced in every Q and Bsk context",
            {q_bsk_moduli.size(), g_n}, std::move(words),
            {"basis_q_then_bsk", "coefficient"});

        BasisPoly q_inverse_bsk;
        for (U64 modulus : bsk_moduli) {
            q_inverse_bsk.push_back(Poly(
                g_n, inverse_mod(product_mod(q_moduli, modulus), modulus)));
        }
        words.clear(); append_words(words, q_inverse_bsk);
        add_artifact(
            case_artifacts, "constants/q_inverse_mod_bsk.bin",
            "Q inverse in every Bsk context for FastFloor",
            {bsk_moduli.size(), g_n}, std::move(words),
            {"basis_bsk", "coefficient"});

        words.clear(); append_words(words, b_to_q_constants.source_hat_inverse);
        add_artifact(
            case_artifacts, "constants/b_qhat_inv.bin",
            "FastBConv B source-hat inverses shared by B-to-Q and B-to-m_sk",
            {b_moduli.size(), g_n}, std::move(words),
            {"source_basis_b", "coefficient"});
        words.clear();
        for (const BasisPoly& target : b_to_q_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/b_qhat_mod_q.bin",
            "FastBConv B source hats reduced in Q",
            {g_num_q, b_moduli.size(), g_n}, std::move(words),
            {"target_basis_q", "source_basis_b", "coefficient"});
        words.clear();
        for (const BasisPoly& target : b_to_msk_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/b_qhat_mod_msk.bin",
            "FastBConv B source hats reduced in m_sk",
            {1, b_moduli.size(), g_n}, std::move(words),
            {"target_basis_msk", "source_basis_b", "coefficient"});
        add_artifact(
            case_artifacts, "constants/b_inverse_mod_msk.bin",
            "B inverse modulo m_sk for branchless alpha",
            {g_n}, Poly(g_n, inverse_mod(product_mod(b_moduli, m_sk), m_sk)));
        words.clear(); append_words(words, msk_to_q_constants.source_hat_inverse);
        add_artifact(
            case_artifacts, "constants/msk_qhat_inv.bin",
            "single-source m_sk BConv inverse",
            {1, g_n}, std::move(words),
            {"source_basis_msk", "coefficient"});
        words.clear();
        for (const BasisPoly& target : msk_to_q_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/msk_qhat_mod_q.bin",
            "single-source m_sk BConv target residues",
            {g_num_q, 1, g_n}, std::move(words),
            {"target_basis_q", "source_basis_msk", "coefficient"});
        BasisPoly neg_b_q;
        for (U64 modulus : q_moduli) {
            const U64 reduced = product_mod(b_moduli, modulus);
            neg_b_q.push_back(Poly(
                g_n, reduced == 0 ? 0 : modulus - reduced));
        }
        words.clear(); append_words(words, neg_b_q);
        add_artifact(
            case_artifacts, "constants/negative_b_mod_q.bin",
            "-B reduced in every Q context",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"});
        const std::size_t bfv_behz_workspace_polys =
            4 * bsk_moduli.size() + q_moduli.size();
        add_artifact(
            case_artifacts, "runtime/behz_workspace.bin",
            "BFV BEHZ workspace with lifetime reuse",
            {bfv_behz_workspace_polys, g_n},
            Poly(bfv_behz_workspace_polys * g_n, 0),
            {"workspace_polynomial", "coefficient"});

        const auto add_hidden_tensor = [&case_artifacts](
            const std::string& path, const std::string& role,
            const TensorCiphertext& value, std::size_t bases,
            HardwareDomain domain = HardwareDomain::kCoefficient) {
            std::vector<U64> flattened;
            for (const BasisPoly& component : value) {
                append_words(flattened, component);
            }
            add_artifact(
                case_artifacts, path, role,
                {3, bases, g_n}, std::move(flattened),
                {"tensor_component[t0,t1,t2]", "basis", "coefficient"},
                domain, false);
        };
        words.clear(); append_words(words, bfv_behz_trace.left_bsk[0]);
        append_words(words, bfv_behz_trace.left_bsk[1]);
        append_words(words, bfv_behz_trace.right_bsk[0]);
        append_words(words, bfv_behz_trace.right_bsk[1]);
        add_artifact(
            case_artifacts, "expected/inputs_bsk.bin",
            "no-SMRQ FastBConv of four input components to Bsk",
            {4, bsk_moduli.size(), g_n}, std::move(words),
            {"input_component[A0,A1,B0,B1]", "basis_bsk", "coefficient"},
            HardwareDomain::kCoefficient, false);
        add_hidden_tensor(
            "expected/tensor_q_ntt.bin", "BFV tensor product under Q, NTT",
            bfv_behz_trace.tensor_q_ntt, q_moduli.size(), HardwareDomain::kNtt);
        add_hidden_tensor(
            "expected/tensor_bsk_ntt.bin", "BFV tensor product under Bsk, NTT",
            bfv_behz_trace.tensor_bsk_ntt, bsk_moduli.size(), HardwareDomain::kNtt);
        add_hidden_tensor(
            "expected/tensor_q_coeff.bin", "BFV tensor product under Q, coefficient",
            bfv_behz_trace.tensor_q_coeff, q_moduli.size());
        add_hidden_tensor(
            "expected/tensor_bsk_coeff.bin", "BFV tensor product under Bsk, coefficient",
            bfv_behz_trace.tensor_bsk_coeff, bsk_moduli.size());
        add_hidden_tensor(
            "expected/scaled_q.bin", "BFV t-times tensor under Q",
            bfv_behz_trace.scaled_q, q_moduli.size());
        add_hidden_tensor(
            "expected/scaled_bsk.bin", "BFV t-times tensor under Bsk",
            bfv_behz_trace.scaled_bsk, bsk_moduli.size());
        add_hidden_tensor(
            "expected/fast_floor_bsk.bin", "BFV FastFloor result under Bsk",
            bfv_behz_trace.fast_floor_bsk, bsk_moduli.size());
        words.clear();
        for (const Poly& alpha : bfv_behz_trace.alpha_msk) {
            append_words(words, alpha);
        }
        add_artifact(
            case_artifacts, "expected/alpha_msk.bin",
            "branchless-SK alpha in [0,|B|]",
            {3, 1, g_n}, std::move(words),
            {"tensor_component[t0,t1,t2]", "basis_msk", "coefficient"},
            HardwareDomain::kCoefficient, false);
        add_hidden_tensor(
            "expected/ciphertext_tensor_q.bin",
            "phase-0 three-component BFV ciphertext output",
            bfv_tensor_q, q_moduli.size());

        write_case_package(
            *suite_root, "bfv_ciphertext_multiply",
            scheme_params(
                "BFV", "ciphertext_multiply_no_smrq_branchless_sk_relinearization",
                "two ciphertexts/coefficient/Q",
                "two-component ciphertext/coefficient/Q",
                bfv_context_moduli,
                "  \"context_order\": \"Q|Pks|B|m_sk|t\",\n"
                "  \"num_b\": " + std::to_string(g_bfv_num_b) + ",\n"
                "  \"m_sk_mod_id\": "
                    + std::to_string(g_num_q + g_num_p + g_bfv_num_b) + ",\n"
                "  \"t_mod_id\": "
                    + std::to_string(g_num_q + g_num_p + g_bfv_num_b + 1) + ",\n"
                "  \"q_bits\": " + std::to_string(big_bit_length(q_product)) + ",\n"
                "  \"b_bits\": " + std::to_string(product_bit_length(b_moduli)) + ",\n"
                "  \"required_b_bits_exclusive\": "
                    + std::to_string(required_b_bits) + ",\n"
                "  \"smrq\": false,\n"
                "  \"branchless_sk\": true,\n"
                "  \"single_kernel\": true,\n"
                "  \"terminal_psync_count\": 1,\n"
                "  \"hpu_mem_max_lines\": "
                    + std::to_string(g_hpu_mem_max_lines)),
            case_artifacts, bfv_context_moduli, bfv_multiply_roots,
            TwiddleRequirement::kRequired);

        const auto bfv_behz_catalog = read_line_catalog(
            *suite_root / "bfv_ciphertext_multiply" / "test_data" /
            "hardware" / "line_map.csv");
        DmaPlanBuilder bfv_behz_dma(bfv_behz_catalog);
        const auto make_polys = [&bfv_behz_dma](
            const std::string& artifact,
            std::size_t first,
            std::size_t count,
            const std::string& label) {
            std::vector<DmaSpan> spans;
            for (std::size_t index = 0; index < count; ++index) {
                spans.push_back(bfv_behz_dma.poly(
                    artifact, first + index,
                    label + "[" + std::to_string(index) + "]"));
            }
            return spans;
        };
        const std::string ct_a_image = "images/input/ct_a_q.u32.bin";
        const std::string ct_b_image = "images/input/ct_b_q.u32.bin";
        const std::string workspace_image =
            "images/runtime/behz_workspace.u32.bin";
        std::array<std::vector<DmaSpan>, 4> bfv_q_input{
            make_polys(ct_a_image, 0, g_num_q, "ct_a.c0.q"),
            make_polys(ct_a_image, g_num_q, g_num_q, "ct_a.c1.q"),
            make_polys(ct_b_image, 0, g_num_q, "ct_b.c0.q"),
            make_polys(ct_b_image, g_num_q, g_num_q, "ct_b.c1.q")};
        std::array<std::vector<DmaSpan>, 4> bfv_bsk_input{
            make_polys(workspace_image, 0, bsk_moduli.size(), "ct_a.c0.bsk"),
            make_polys(workspace_image, bsk_moduli.size(), bsk_moduli.size(), "ct_a.c1.bsk"),
            make_polys(workspace_image, 2 * bsk_moduli.size(), bsk_moduli.size(), "ct_b.c0.bsk"),
            make_polys(workspace_image, 3 * bsk_moduli.size(), bsk_moduli.size(), "ct_b.c1.bsk")};
        const auto q_bconv_inverse = make_polys(
            "images/constants/q_to_bsk_qhat_inv.u32.bin",
            0, g_num_q, "q_to_bsk.qhat_inv");
        std::vector<std::vector<DmaSpan>> q_bconv_target;
        for (std::size_t target = 0; target < bsk_moduli.size(); ++target) {
            q_bconv_target.push_back(make_polys(
                "images/constants/q_to_bsk_qhat_mod.u32.bin",
                target * g_num_q, g_num_q,
                "q_to_bsk.qhat_mod.target" + std::to_string(target)));
        }
        const auto q_normalized_scratch = make_polys(
            workspace_image, 4 * bsk_moduli.size(), g_num_q,
            "q_to_bsk.normalized");
        for (std::size_t component = 0; component < 4; ++component) {
            bfv_behz_dma.bconv(
                bfv_q_input[component], q_bconv_inverse,
                q_bconv_target, q_normalized_scratch,
                bfv_bsk_input[component]);
        }

        std::vector<int> q_contexts;
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            q_contexts.push_back(static_cast<int>(basis));
        }
        std::vector<int> bsk_contexts;
        for (std::size_t basis = 0; basis < bsk_moduli.size(); ++basis) {
            bsk_contexts.push_back(
                static_cast<int>(g_num_q + g_num_p + basis));
        }
        bfv_behz_dma.transform(
            {bfv_q_input[0], bfv_q_input[1],
             bfv_q_input[2], bfv_q_input[3]},
            q_contexts, false);
        bfv_behz_dma.transform(
            {bfv_bsk_input[0], bfv_bsk_input[1],
             bfv_bsk_input[2], bfv_bsk_input[3]},
            bsk_contexts, false);

        std::array<std::vector<DmaSpan>, 3> bfv_q_tensor{
            bfv_q_input[0], bfv_q_input[1], bfv_q_input[2]};
        std::array<std::vector<DmaSpan>, 3> bfv_bsk_tensor{
            bfv_bsk_input[0], bfv_bsk_input[1], bfv_bsk_input[2]};
        bfv_behz_dma.tensor(bfv_q_input, bfv_q_tensor);
        bfv_behz_dma.tensor(bfv_bsk_input, bfv_bsk_tensor);
        bfv_behz_dma.transform(
            {bfv_q_tensor[0], bfv_q_tensor[1], bfv_q_tensor[2]},
            q_contexts, true);
        bfv_behz_dma.transform(
            {bfv_bsk_tensor[0], bfv_bsk_tensor[1], bfv_bsk_tensor[2]},
            bsk_contexts, true);

        const auto t_scalar = make_polys(
            "images/constants/t_mod_q_bsk.u32.bin", 0,
            q_bsk_moduli.size(), "t_mod_q_bsk");
        std::vector<std::vector<DmaSpan>> q_bsk_tensor;
        for (std::size_t component = 0; component < 3; ++component) {
            std::vector<DmaSpan> joined = bfv_q_tensor[component];
            joined.insert(
                joined.end(), bfv_bsk_tensor[component].begin(),
                bfv_bsk_tensor[component].end());
            q_bsk_tensor.push_back(std::move(joined));
        }
        bfv_behz_dma.scalar_multiply(q_bsk_tensor, t_scalar);

        const auto q_inverse_spans = make_polys(
            "images/constants/q_inverse_mod_bsk.u32.bin", 0,
            bsk_moduli.size(), "q_inverse_mod_bsk");
        const auto converted_bsk = make_polys(
            workspace_image, 3 * bsk_moduli.size(), bsk_moduli.size(),
            "fastfloor.converted_q");
        for (std::size_t component = 0; component < 3; ++component) {
            bfv_behz_dma.bconv(
                bfv_q_tensor[component], q_bconv_inverse,
                q_bconv_target, q_normalized_scratch, converted_bsk);
            bfv_behz_dma.load_mod_context();
            for (std::size_t basis = 0; basis < bsk_moduli.size(); ++basis) {
                bfv_behz_dma.load(0, bfv_bsk_tensor[component][basis]);
                bfv_behz_dma.load(1, converted_bsk[basis]);
                bfv_behz_dma.load(2, q_inverse_spans[basis]);
                bfv_behz_dma.store(0, bfv_bsk_tensor[component][basis]);
            }
        }

        const auto b_inverse_spans = make_polys(
            "images/constants/b_qhat_inv.u32.bin", 0,
            b_moduli.size(), "b_qhat_inverse");
        std::vector<std::vector<DmaSpan>> b_target_q;
        for (std::size_t target = 0; target < q_moduli.size(); ++target) {
            b_target_q.push_back(make_polys(
                "images/constants/b_qhat_mod_q.u32.bin",
                target * b_moduli.size(), b_moduli.size(),
                "b_qhat_mod_q.target" + std::to_string(target)));
        }
        std::vector<std::vector<DmaSpan>> b_target_msk{
            make_polys(
                "images/constants/b_qhat_mod_msk.u32.bin", 0,
                b_moduli.size(), "b_qhat_mod_msk")};
        const auto b_normalized_scratch = make_polys(
            workspace_image, 3 * bsk_moduli.size(), b_moduli.size(),
            "branchless_sk.b_normalized");
        const std::vector<DmaSpan> temp_msk{
            bfv_behz_dma.poly(
                workspace_image, 3 * bsk_moduli.size() + b_moduli.size(),
                "branchless_sk.temp_msk")};
        const std::vector<DmaSpan> alpha_msk{
            bfv_behz_dma.poly(
                workspace_image, 3 * bsk_moduli.size() + b_moduli.size(),
                "branchless_sk.alpha_msk")};
        const auto msk_inverse = make_polys(
            "images/constants/msk_qhat_inv.u32.bin", 0, 1,
            "msk_qhat_inverse");
        std::vector<std::vector<DmaSpan>> msk_target_q;
        for (std::size_t target = 0; target < q_moduli.size(); ++target) {
            msk_target_q.push_back(make_polys(
                "images/constants/msk_qhat_mod_q.u32.bin", target, 1,
                "msk_qhat_mod_q.target" + std::to_string(target)));
        }
        const std::vector<DmaSpan> msk_normalized{
            bfv_behz_dma.poly(
                workspace_image, 4 * bsk_moduli.size(),
                "alpha.normalized_msk")};
        const auto alpha_q = bfv_q_input[3];
        const auto b_inverse_msk_span = bfv_behz_dma.poly(
            "images/constants/b_inverse_mod_msk.u32.bin", 0,
            "b_inverse_mod_msk");
        const auto negative_b_spans = make_polys(
            "images/constants/negative_b_mod_q.u32.bin", 0,
            g_num_q, "negative_b_mod_q");
        for (std::size_t component = 0; component < 3; ++component) {
            const std::vector<DmaSpan> source_b(
                bfv_bsk_tensor[component].begin(),
                bfv_bsk_tensor[component].begin()
                    + static_cast<std::ptrdiff_t>(b_moduli.size()));
            bfv_behz_dma.bconv(
                source_b, b_inverse_spans, b_target_q,
                b_normalized_scratch, bfv_q_tensor[component]);
            bfv_behz_dma.bconv(
                source_b, b_inverse_spans, b_target_msk,
                b_normalized_scratch, temp_msk);
            bfv_behz_dma.load_mod_context();
            bfv_behz_dma.load(0, temp_msk[0]);
            bfv_behz_dma.load(1, bfv_bsk_tensor[component].back());
            bfv_behz_dma.load(2, b_inverse_msk_span);
            bfv_behz_dma.store(0, alpha_msk[0]);
            bfv_behz_dma.bconv(
                alpha_msk, msk_inverse, msk_target_q,
                msk_normalized, alpha_q);
            bfv_behz_dma.load_mod_context();
            for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
                bfv_behz_dma.load(2, bfv_q_tensor[component][basis]);
                bfv_behz_dma.load(0, alpha_q[basis]);
                bfv_behz_dma.load(1, negative_b_spans[basis]);
                bfv_behz_dma.store(2, bfv_q_tensor[component][basis]);
            }
        }
        words.clear();
        for (const auto& digit : rlk_ntt) {
            append_words(words, digit[0]);
            append_words(words, digit[1]);
        }
        add_artifact(
            case_artifacts, "constants/relinearization_key_ntt_qp.bin",
            "zero-noise exact functional BFV relinearization key",
            {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
            {"digit", "component[ks0,ks1]", "basis_q_then_p", "coefficient"},
            HardwareDomain::kNtt);

        std::vector<BasisPoly> modup_source_inverse;
        std::vector<std::vector<BasisPoly>> modup_target_hat;
        for (std::size_t digit = 0; digit < g_dnum; ++digit) {
            const std::vector<U64> digit_moduli(
                q_moduli.begin() + static_cast<std::ptrdiff_t>(digit * digit_size),
                q_moduli.begin() + static_cast<std::ptrdiff_t>((digit + 1) * digit_size));
            const FastBconvConstants constants = make_fast_bconv_constants(
                digit_moduli, all_moduli);
            modup_source_inverse.push_back(constants.source_hat_inverse);
            modup_target_hat.push_back(constants.source_hat_mod_target);
        }
        words.clear();
        for (const BasisPoly& digit : modup_source_inverse) {
            append_words(words, digit);
        }
        add_artifact(
            case_artifacts, "constants/modup_digit_qhat_inv.bin",
            "per-digit ModUp source-hat inverses",
            {g_dnum, digit_size, g_n}, std::move(words),
            {"digit", "source_basis_q", "coefficient"});
        words.clear();
        for (const auto& digit : modup_target_hat) {
            for (const BasisPoly& target : digit) {
                append_words(words, target);
            }
        }
        add_artifact(
            case_artifacts, "constants/modup_digit_qhat_mod_qp.bin",
            "per-digit ModUp source hats in every QP target",
            {g_dnum, all_moduli.size(), digit_size, g_n}, std::move(words),
            {"digit", "target_basis_qp", "source_basis_q", "coefficient"});

        const FastBconvConstants p_to_q_constants =
            make_fast_bconv_constants(p_moduli, q_moduli);
        words.clear(); append_words(words, p_to_q_constants.source_hat_inverse);
        add_artifact(
            case_artifacts, "constants/moddown_p_qhat_inv.bin",
            "ModDown P source-hat inverses",
            {g_num_p, g_n}, std::move(words),
            {"source_basis_p", "coefficient"});
        words.clear();
        for (const BasisPoly& target : p_to_q_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/moddown_p_qhat_mod_q.bin",
            "ModDown P source hats reduced in Q",
            {g_num_q, g_num_p, g_n}, std::move(words),
            {"target_basis_q", "source_basis_p", "coefficient"});
        BasisPoly p_inverse_q;
        for (U64 modulus : q_moduli) {
            p_inverse_q.push_back(Poly(
                g_n, inverse_mod(product_mod(p_moduli, modulus), modulus)));
        }
        words.clear(); append_words(words, p_inverse_q);
        add_artifact(
            case_artifacts, "constants/p_inverse_mod_q.bin",
            "P inverse in every Q context for ModDown",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"});
        add_artifact(
            case_artifacts, "runtime/relinearization_workspace.bin",
            "64-polynomial BFV KeySwitch workspace",
            {64, g_n}, Poly(64 * g_n, 0),
            {"workspace_polynomial", "coefficient"});

        const auto add_hidden_basis = [&case_artifacts](
            const std::string& path, const std::string& role,
            const BasisPoly& value, std::vector<std::size_t> shape,
            HardwareDomain domain = HardwareDomain::kCoefficient) {
            std::vector<U64> flattened;
            append_words(flattened, value);
            add_artifact(
                case_artifacts, path, role, std::move(shape),
                std::move(flattened), {}, domain, false);
        };
        words.clear();
        for (const BasisPoly& digit : bfv_relinearization_trace.modup_coeff) {
            append_words(words, digit);
        }
        add_artifact(
            case_artifacts, "expected/modup_t2_coeff_qp.bin",
            "BFV t2 digit ModUp outputs",
            {g_dnum, all_moduli.size(), g_n}, std::move(words),
            {"digit", "basis_qp", "coefficient"},
            HardwareDomain::kCoefficient, false);
        add_hidden_basis(
            "expected/keyswitch_accum_ntt_0_qp.bin",
            "BFV KeySwitch accumulator 0, NTT",
            bfv_relinearization_trace.keyswitch_accum_ntt[0],
            {all_moduli.size(), g_n}, HardwareDomain::kNtt);
        add_hidden_basis(
            "expected/keyswitch_accum_ntt_1_qp.bin",
            "BFV KeySwitch accumulator 1, NTT",
            bfv_relinearization_trace.keyswitch_accum_ntt[1],
            {all_moduli.size(), g_n}, HardwareDomain::kNtt);
        words.clear(); append_words(words, bfv_product_q[0]); append_words(words, bfv_product_q[1]);
        add_artifact(
            case_artifacts, "expected/ciphertext_out_q.bin",
            "phase-1 relinearized two-component BFV ciphertext",
            {2, g_num_q, g_n}, std::move(words),
            {"component[c0,c1]", "basis_q", "coefficient"},
            HardwareDomain::kCoefficient, false);
        add_artifact(
            case_artifacts, "expected/plaintext_product_mod_t.bin",
            "BFV scale-and-round decrypted plaintext product",
            {g_n}, bfv_decrypted_coeff_t, {},
            HardwareDomain::kCoefficient, false);
        write_case_package(
            *suite_root, "bfv_ciphertext_multiply",
            scheme_params(
                "BFV", "ciphertext_multiply_no_smrq_branchless_sk_relinearization",
                "two ciphertexts/coefficient/Q",
                "two-component ciphertext/coefficient/Q",
                bfv_context_moduli,
                "  \"context_order\": \"Q|Pks|B|m_sk|t\",\n"
                "  \"num_b\": " + std::to_string(g_bfv_num_b) + ",\n"
                "  \"m_sk_mod_id\": "
                    + std::to_string(g_num_q + g_num_p + g_bfv_num_b) + ",\n"
                "  \"t_mod_id\": "
                    + std::to_string(g_num_q + g_num_p + g_bfv_num_b + 1) + ",\n"
                "  \"q_bits\": " + std::to_string(big_bit_length(q_product)) + ",\n"
                "  \"b_bits\": " + std::to_string(product_bit_length(b_moduli)) + ",\n"
                "  \"required_b_bits_exclusive\": "
                    + std::to_string(required_b_bits) + ",\n"
                "  \"smrq\": false,\n"
                "  \"branchless_sk\": true,\n"
                "  \"single_kernel\": true,\n"
                "  \"terminal_psync_count\": 1,\n"
                "  \"hpu_mem_max_lines\": "
                    + std::to_string(g_hpu_mem_max_lines)),
            std::move(case_artifacts), bfv_context_moduli,
            bfv_multiply_roots,
            TwiddleRequirement::kRequired);
        const auto bfv_multiply_catalog = read_line_catalog(
            *suite_root / "bfv_ciphertext_multiply" / "test_data" /
            "hardware" / "line_map.csv");
        DmaPlanBuilder bfv_relin_dma(bfv_multiply_catalog);
        const auto make_relin_polys = [&bfv_relin_dma](
            const std::string& artifact,
            std::size_t first,
            std::size_t count,
            const std::string& label) {
            std::vector<DmaSpan> spans;
            for (std::size_t index = 0; index < count; ++index) {
                spans.push_back(bfv_relin_dma.poly(
                    artifact, first + index,
                    label + "[" + std::to_string(index) + "]"));
            }
            return spans;
        };
        const std::string bfv_relin_workspace =
            "images/runtime/relinearization_workspace.u32.bin";
        const auto& bfv_relin_tensor = bfv_q_tensor;
        const std::size_t total_qp = all_moduli.size();
        const auto modup_workspace = make_relin_polys(
            bfv_relin_workspace, 0, total_qp, "modup.current_qp");
        std::array<std::vector<DmaSpan>, 2> keyswitch_accumulator{
            make_relin_polys(
                bfv_relin_workspace, total_qp, total_qp,
                "keyswitch.accum0.qp"),
            make_relin_polys(
                bfv_relin_workspace, 2 * total_qp, total_qp,
                "keyswitch.accum1.qp")};
        const auto moddown_normalized = make_relin_polys(
            bfv_relin_workspace, 3 * total_qp,
            std::max(digit_size, p_moduli.size()),
            "keyswitch.bconv_normalized");
        const auto moddown_correction = make_relin_polys(
            bfv_relin_workspace,
            3 * total_qp + std::max(digit_size, p_moduli.size()),
            q_moduli.size(), "keyswitch.moddown_correction_q");
        std::vector<int> qp_contexts;
        for (std::size_t basis = 0; basis < total_qp; ++basis) {
            qp_contexts.push_back(static_cast<int>(basis));
        }

        for (std::size_t digit = 0; digit < g_dnum; ++digit) {
            const std::size_t q_offset = digit * digit_size;
            std::vector<DmaSpan> digit_source;
            std::vector<DmaSpan> digit_inverse;
            std::vector<DmaSpan> digit_normalized;
            for (std::size_t source = 0; source < digit_size; ++source) {
                digit_source.push_back(bfv_relin_tensor[2][q_offset + source]);
                digit_inverse.push_back(bfv_relin_dma.poly(
                    "images/constants/modup_digit_qhat_inv.u32.bin",
                    digit * digit_size + source,
                    "modup.d" + std::to_string(digit)
                        + ".qhat_inv" + std::to_string(source)));
                digit_normalized.push_back(moddown_normalized[source]);
                bfv_relin_dma.load(0, digit_source.back());
                bfv_relin_dma.store(0, modup_workspace[q_offset + source]);
            }
            std::vector<std::vector<DmaSpan>> digit_target_constants;
            std::vector<DmaSpan> digit_targets;
            for (std::size_t target = 0; target < total_qp; ++target) {
                if (target >= q_offset && target < q_offset + digit_size) {
                    continue;
                }
                std::vector<DmaSpan> target_row;
                for (std::size_t source = 0; source < digit_size; ++source) {
                    target_row.push_back(bfv_relin_dma.poly(
                        "images/constants/modup_digit_qhat_mod_qp.u32.bin",
                        (digit * total_qp + target) * digit_size + source,
                        "modup.d" + std::to_string(digit)
                            + ".target" + std::to_string(target)
                            + ".source" + std::to_string(source)));
                }
                digit_target_constants.push_back(std::move(target_row));
                digit_targets.push_back(modup_workspace[target]);
            }
            bfv_relin_dma.bconv(
                digit_source, digit_inverse, digit_target_constants,
                digit_normalized, digit_targets);
            bfv_relin_dma.transform(
                {modup_workspace}, qp_contexts, false);

            for (std::size_t component = 0; component < 2; ++component) {
                for (std::size_t basis = 0; basis < total_qp; ++basis) {
                    const std::size_t key_index =
                        (digit * 2 + component) * total_qp + basis;
                    const DmaSpan key_span = bfv_relin_dma.poly(
                        "images/constants/relinearization_key_ntt_qp.u32.bin",
                        key_index,
                        "rlk.d" + std::to_string(digit)
                            + ".c" + std::to_string(component)
                            + ".basis" + std::to_string(basis));
                    bfv_relin_dma.load(0, modup_workspace[basis]);
                    bfv_relin_dma.load(1, key_span);
                    if (digit != 0) {
                        bfv_relin_dma.load(
                            2, keyswitch_accumulator[component][basis]);
                    }
                    bfv_relin_dma.store(
                        2, keyswitch_accumulator[component][basis]);
                }
            }
        }

        bfv_relin_dma.transform(
            {keyswitch_accumulator[0], keyswitch_accumulator[1]},
            qp_contexts, true);
        const auto p_source_inverse = make_relin_polys(
            "images/constants/moddown_p_qhat_inv.u32.bin", 0,
            p_moduli.size(), "moddown.p_qhat_inverse");
        std::vector<std::vector<DmaSpan>> p_target_q;
        for (std::size_t target = 0; target < q_moduli.size(); ++target) {
            p_target_q.push_back(make_relin_polys(
                "images/constants/moddown_p_qhat_mod_q.u32.bin",
                target * p_moduli.size(), p_moduli.size(),
                "moddown.p_qhat_mod_q.target" + std::to_string(target)));
        }
        const auto p_inverse_q_spans = make_relin_polys(
            "images/constants/p_inverse_mod_q.u32.bin", 0,
            q_moduli.size(), "moddown.p_inverse_mod_q");
        for (std::size_t component = 0; component < 2; ++component) {
            const std::vector<DmaSpan> source_p(
                keyswitch_accumulator[component].begin()
                    + static_cast<std::ptrdiff_t>(g_num_q),
                keyswitch_accumulator[component].end());
            const std::vector<DmaSpan> normalized_p(
                moddown_normalized.begin(),
                moddown_normalized.begin()
                    + static_cast<std::ptrdiff_t>(p_moduli.size()));
            bfv_relin_dma.bconv(
                source_p, p_source_inverse, p_target_q,
                normalized_p, moddown_correction);
            bfv_relin_dma.load_mod_context();
            for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
                bfv_relin_dma.load(
                    0, keyswitch_accumulator[component][basis]);
                bfv_relin_dma.load(1, moddown_correction[basis]);
                bfv_relin_dma.load(2, p_inverse_q_spans[basis]);
                bfv_relin_dma.store(
                    0, keyswitch_accumulator[component][basis]);
            }
        }
        bfv_relin_dma.load_mod_context();
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            bfv_relin_dma.load(0, keyswitch_accumulator[0][basis]);
            bfv_relin_dma.load(1, bfv_relin_tensor[0][basis]);
            bfv_relin_dma.store(2, bfv_relin_tensor[0][basis]);
        }
        bfv_relin_dma.load_mod_context();
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            bfv_relin_dma.load(0, bfv_relin_tensor[1][basis]);
            bfv_relin_dma.load(1, keyswitch_accumulator[1][basis]);
            bfv_relin_dma.store(2, bfv_relin_tensor[1][basis]);
        }
        std::vector<PlannedDma> bfv_multiply_dma = rebase_dma_records(
            bfv_behz_dma.records(), bfv_behz_catalog, bfv_multiply_catalog);
        bfv_multiply_dma.insert(
            bfv_multiply_dma.end(),
            bfv_relin_dma.records().begin(), bfv_relin_dma.records().end());
        write_resolved_dma_plan(
            *suite_root, "bfv_ciphertext_multiply", bfv_multiply_dma);
        write_text(
            *suite_root / "bfv_ciphertext_multiply" / "test_data" /
                "SCHEME_VALIDATION.txt",
            "PASS\nsingle_kernel=PASS\nno_host_tensor_copy=PASS\n"
            "no_smrq_q_to_bsk=PASS\nntt_tensor_product=PASS\n"
            "fast_floor=PASS\nbranchless_sk=PASS\nalpha_range=PASS\n"
            "m_tilde_absent=PASS\ncomparison_instruction_absent=PASS\n"
            "modup=PASS\n"
            "evaluation_key_product=PASS\nmoddown=PASS\n"
            "three_to_two_components=PASS\ndecryption_preserved=PASS\n");
        write_text(
            *suite_root / "bfv_ciphertext_multiply" / "test_data" /
                "memory_lifetime.csv",
            "phase,live_data,released_or_reused_after_phase\n"
            "q_to_bsk,ct_q+ct_bsk+conversion_constants,none\n"
            "ntt,ct_q_ntt+ct_bsk_ntt+twiddles,coefficient_input_regions\n"
            "tensor,tensor_q_ntt+tensor_bsk_ntt,consumed_input_component_regions\n"
            "intt_scale,tensor_q+tensor_bsk,NTT input regions\n"
            "fastfloor,z_bsk,Q_to_Bsk temporary and consumed scaled-Q regions\n"
            "branchless_sk,tensor_q,BEHZ workspace and Bsk data are dead\n"
            "relinearization,ciphertext_out_q,t2 and KeySwitch workspace are dead\n");

        case_artifacts.clear();
        words.clear(); append_words(words, bfv_product_q[0]); append_words(words, bfv_product_q[1]);
        add_artifact(
            case_artifacts, "input/ciphertext_q.bin",
            "two-component BFV ciphertext before rounded ModSwitch",
            {2, g_num_q, g_n}, std::move(words),
            {"component[c0,c1]", "basis_q", "coefficient"});
        words.clear(); append_words(words, half_constants);
        add_artifact(
            case_artifacts, "constants/q_last_half_mod_q.bin",
            "floor(q_last/2) reduced in every Q context",
            {g_num_q, g_n}, std::move(words),
            {"basis_q", "coefficient"});
        add_artifact(
            case_artifacts, "constants/qhat_inv_drop.bin",
            "single-source drop-last BConv inverse",
            {1, g_n}, Poly(g_n, 1));
        words.clear(); append_words(words, qhat_mod_qprime);
        add_artifact(
            case_artifacts, "constants/qhat_mod_qprime.bin",
            "single-source drop-last target residues",
            {g_num_q - 1, g_n}, std::move(words),
            {"basis_qprime", "coefficient"});
        words.clear(); append_words(words, dropped_inverse);
        add_artifact(
            case_artifacts, "constants/q_last_inverse_mod_qprime.bin",
            "q_last inverse in every retained Q context",
            {g_num_q - 1, g_n}, std::move(words),
            {"basis_qprime", "coefficient"});
        add_artifact(
            case_artifacts, "runtime/output_qprime.bin",
            "zero-initialized BFV ModSwitch destination",
            {2, g_num_q - 1, g_n}, Poly(2 * (g_num_q - 1) * g_n, 0),
            {"component[c0,c1]", "basis_qprime", "coefficient"});
        words.clear(); append_words(words, bfv_product_qprime[0]);
        append_words(words, bfv_product_qprime[1]);
        add_artifact(
            case_artifacts, "expected/ciphertext_qprime.bin",
            "golden rounded BFV ciphertext after dropping q_last",
            {2, g_num_q - 1, g_n}, std::move(words),
            {"component[c0,c1]", "basis_qprime", "coefficient"},
            HardwareDomain::kCoefficient, false);
        add_artifact(
            case_artifacts, "expected/plaintext_product_mod_t.bin",
            "BFV scale-and-round plaintext after ModSwitch",
            {g_n}, bfv_switched_coeff_t, {},
            HardwareDomain::kCoefficient, false);
        write_case_package(
            *suite_root, "bfv_modswitch",
            scheme_params(
                "BFV", "rounded_modswitch_drop_last",
                "ciphertext/coefficient/Q",
                "ciphertext/coefficient/Q_without_last",
                q_moduli,
                "  \"q_last\": " + std::to_string(q_moduli.back()) + ",\n"
                "  \"level_delta\": -1,\n"
                "  \"scale_metadata\": null,\n"
                "  \"correction_factor_metadata\": null"),
            std::move(case_artifacts), q_moduli, q_roots,
            TwiddleRequirement::kNone);
        DmaPlanBuilder bfv_modswitch_dma(read_line_catalog(
            *suite_root / "bfv_modswitch" / "test_data" /
            "hardware" / "line_map.csv"));
        std::vector<DmaSpan> bfv_half_spans;
        std::vector<DmaSpan> bfv_drop_targets;
        std::vector<DmaSpan> bfv_drop_inverse;
        for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
            bfv_half_spans.push_back(bfv_modswitch_dma.poly(
                "images/constants/q_last_half_mod_q.u32.bin", basis,
                "q_last_half_mod_q[" + std::to_string(basis) + "]"));
            if (basis + 1 < q_moduli.size()) {
                bfv_drop_targets.push_back(bfv_modswitch_dma.poly(
                    "images/constants/qhat_mod_qprime.u32.bin", basis,
                    "drop_qhat_mod_qprime[" + std::to_string(basis) + "]"));
                bfv_drop_inverse.push_back(bfv_modswitch_dma.poly(
                    "images/constants/q_last_inverse_mod_qprime.u32.bin", basis,
                    "q_last_inverse_mod_qprime[" + std::to_string(basis) + "]"));
            }
        }
        const DmaSpan bfv_drop_source_inverse = bfv_modswitch_dma.poly(
            "images/constants/qhat_inv_drop.u32.bin", 0,
            "drop_qhat_inverse");
        for (std::size_t component = 0; component < 2; ++component) {
            std::vector<DmaSpan> rounded_q;
            std::vector<DmaSpan> output_qprime;
            for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
                rounded_q.push_back(bfv_modswitch_dma.poly(
                    "images/input/ciphertext_q.u32.bin",
                    component * q_moduli.size() + basis,
                    "rounded_ciphertext.c" + std::to_string(component)
                        + ".q" + std::to_string(basis)));
                if (basis + 1 < q_moduli.size()) {
                    output_qprime.push_back(bfv_modswitch_dma.poly(
                        "images/runtime/output_qprime.u32.bin",
                        component * (q_moduli.size() - 1) + basis,
                        "bfv_modswitch_out.c" + std::to_string(component)
                            + ".q" + std::to_string(basis)));
                }
            }
            bfv_modswitch_dma.load_mod_context();
            for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
                bfv_modswitch_dma.load(0, rounded_q[basis]);
                bfv_modswitch_dma.load(1, bfv_half_spans[basis]);
                bfv_modswitch_dma.store(0, rounded_q[basis]);
            }
            std::vector<std::vector<DmaSpan>> target_matrix;
            for (const DmaSpan& target : bfv_drop_targets) {
                target_matrix.push_back({target});
            }
            bfv_modswitch_dma.bconv(
                {rounded_q.back()}, {bfv_drop_source_inverse},
                target_matrix, {rounded_q.back()}, output_qprime);
            bfv_modswitch_dma.load_mod_context();
            for (std::size_t basis = 0; basis + 1 < q_moduli.size(); ++basis) {
                bfv_modswitch_dma.load(0, rounded_q[basis]);
                bfv_modswitch_dma.load(1, output_qprime[basis]);
                bfv_modswitch_dma.load(2, bfv_drop_inverse[basis]);
                bfv_modswitch_dma.store(0, output_qprime[basis]);
            }
        }
        write_resolved_dma_plan(
            *suite_root, "bfv_modswitch", bfv_modswitch_dma.records());
        write_text(
            *suite_root / "bfv_modswitch" / "test_data" / "SCHEME_VALIDATION.txt",
            "PASS\nrounded_drop_last=PASS\ndirect_crt_check=PASS\n"
            "decrypt_scale_and_round=PASS\nplaintext_preserved=PASS\n");

        write_host_package(
            *suite_root / "bfv_ciphertext_multiply" / "test_data",
            {
                {"input_slots_a.csv", "BFV batched input slots A",
                 signed_values_csv(bfv_slots_a, "input")},
                {"input_slots_b.csv", "BFV batched input slots B",
                 signed_values_csv(bfv_slots_b, "input")},
                {"decoded_product.csv", "expected and decoded BFV slot product",
                 signed_comparison_csv(
                     bfv_expected_slots, bfv_decoded_slots)},
                {"noise_smoke/input_error_a.csv", "deterministic nonzero BFV error A",
                 signed_values_csv(bfv_noise_a, "error")},
                {"noise_smoke/input_error_b.csv", "deterministic nonzero BFV error B",
                 signed_values_csv(bfv_noise_b, "error")},
                {"noise_smoke/decoded_product.csv", "nonzero-noise expected and decoded coefficients",
                 residues_comparison_csv(
                     bfv_expected_coeff_t, bfv_noise_result)},
                {"noise_smoke/validation.txt", "nonzero-noise end-to-end status",
                 "PASS\nencode=PASS\nencrypt_nonzero_error=PASS\n"
                 "behz_multiply=PASS\nrelinearize=PASS\nmodswitch=PASS\n"
                 "decrypt_scale_and_round=PASS\ndecode=PASS\n"
                 "security_status=FUNCTIONAL_TEST_ONLY\n"},
            });

        write_text(
            *suite_root / "seal_oracle" / "parameters.csv",
            seal_oracle_parameters_csv(
                q_moduli, p_moduli, ckks_input_scale, ckks_output_scale,
                ckks_encode_bound, ckks_error_bound,
                ckks_rotation_error_bound));

        case_artifacts.clear();
        add_artifact(case_artifacts, "input_a.bin", "left polynomial", {g_n},
                     ct_a_ntt[0][0], {}, HardwareDomain::kNtt);
        add_artifact(case_artifacts, "input_b.bin", "right polynomial", {g_n},
                     ct_b_ntt[0][0], {}, HardwareDomain::kNtt);
        add_artifact(case_artifacts, "expected.bin", "pointwise product", {g_n},
                     tensor_ntt[0][0], {}, HardwareDomain::kNtt);
        write_case_package(*suite_root, "mm",
                           common_params("mm", "NTT", "NTT", {q_moduli[0]}),
                           std::move(case_artifacts),
                           {q_moduli[0]}, {q_roots[0]},
                           TwiddleRequirement::kNone);

        case_artifacts.clear();
        const BasisPoly& bconv_source = tensor[2];
        const std::vector<U64>& bconv_source_moduli = q_moduli;
        words.clear(); append_words(words, bconv_source);
        add_artifact(
            case_artifacts, "input_q.bin", "complete Q-basis source limbs",
            {g_num_q, g_n}, std::move(words),
            {"source_basis_q", "coefficient"});

        const FastBconvConstants bconv_constants =
            make_fast_bconv_constants(bconv_source_moduli, p_moduli);
        words.clear(); append_words(words, bconv_constants.source_hat_inverse);
        add_artifact(
            case_artifacts, "constants/qhat_inv_q.bin",
            "Q source-hat inverses in each source context",
            {g_num_q, g_n}, std::move(words),
            {"source_basis_q", "coefficient"});
        words.clear();
        for (const BasisPoly& target : bconv_constants.source_hat_mod_target) {
            append_words(words, target);
        }
        add_artifact(
            case_artifacts, "constants/qhat_mod_p.bin",
            "Q source hats reduced in every P target context",
            {g_num_p, g_num_q, g_n}, std::move(words),
            {"target_basis_p", "source_basis_q", "coefficient"});
        add_artifact(
            case_artifacts, "runtime/normalized_q.bin",
            "zero-initialized normalized source scratch",
            {g_num_q, g_n}, Poly(g_num_q * g_n, 0),
            {"source_basis_q", "coefficient"});
        add_artifact(
            case_artifacts, "runtime/output_p.bin",
            "zero-initialized BConv destination",
            {g_num_p, g_n}, Poly(g_num_p * g_n, 0),
            {"target_basis_p", "coefficient"});

        const BasisPoly bconv_expected_p = fast_bconv(
            bconv_source, bconv_source_moduli, p_moduli);
        for (const Poly& source_limb : bconv_source) {
            if (bconv_expected_p.front() == source_limb) {
                throw std::runtime_error(
                    "standalone BConv fixture degenerated to an identity mapping");
            }
        }
        words.clear(); append_words(words, bconv_expected_p);
        add_artifact(
            case_artifacts, "expected_p.bin",
            "non-trivial complete-Q to P basis conversion",
            {g_num_p, g_n}, std::move(words),
            {"target_basis_p", "coefficient"},
            HardwareDomain::kCoefficient, false);

        write_case_package(*suite_root, "bconv",
                           common_params("bconv", "coefficient/Q", "coefficient/P",
                                         all_moduli),
                           std::move(case_artifacts),
                           all_moduli, all_roots,
                           TwiddleRequirement::kNone);
        DmaPlanBuilder bconv_dma(read_line_catalog(
            *suite_root / "bconv" / "test_data" / "hardware" / "line_map.csv"));
        std::vector<DmaSpan> bconv_inputs;
        std::vector<DmaSpan> bconv_inverses;
        std::vector<DmaSpan> bconv_scratch;
        for (std::size_t source = 0; source < g_num_q; ++source) {
            bconv_inputs.push_back(bconv_dma.poly(
                "images/input_q.u32.bin", source,
                "bconv.input_q[" + std::to_string(source) + "]"));
            bconv_inverses.push_back(bconv_dma.poly(
                "images/constants/qhat_inv_q.u32.bin", source,
                "bconv.qhat_inv[" + std::to_string(source) + "]"));
            bconv_scratch.push_back(bconv_dma.poly(
                "images/runtime/normalized_q.u32.bin", source,
                "bconv.normalized_q[" + std::to_string(source) + "]"));
        }
        std::vector<std::vector<DmaSpan>> bconv_target_constants;
        std::vector<DmaSpan> bconv_outputs;
        for (std::size_t target = 0; target < g_num_p; ++target) {
            std::vector<DmaSpan> target_constants;
            for (std::size_t source = 0; source < g_num_q; ++source) {
                target_constants.push_back(bconv_dma.poly(
                    "images/constants/qhat_mod_p.u32.bin",
                    target * g_num_q + source,
                    "bconv.qhat_mod_p[" + std::to_string(target) + "]["
                        + std::to_string(source) + "]"));
            }
            bconv_target_constants.push_back(std::move(target_constants));
            bconv_outputs.push_back(bconv_dma.poly(
                "images/runtime/output_p.u32.bin", target,
                "bconv.output_p[" + std::to_string(target) + "]"));
        }
        bconv_dma.bconv(
            bconv_inputs, bconv_inverses, bconv_target_constants,
            bconv_scratch, bconv_outputs);
        write_resolved_dma_plan(*suite_root, "bconv", bconv_dma.records());

        case_artifacts.clear();
        words.clear();
        for (std::size_t i = 0; i < digit_size; ++i) {
            append_words(words, tensor[2][i]);
        }
        add_artifact(case_artifacts, "input_digit_q.bin", "Q digit input for ModUp",
                     {digit_size, g_n}, std::move(words),
                     {"basis_q_digit", "coefficient"});
        words.clear(); append_words(words, modup_coeff[0]);
        add_artifact(case_artifacts, "expected_qp.bin", "complete Q union P ModUp output",
                     {g_num_q + g_num_p, g_n}, std::move(words),
                     {"basis_q_then_p", "coefficient"});
        write_case_package(*suite_root, "modup",
                           common_params("modup", "coefficient/Q_digit0", "coefficient/QP",
                                         all_moduli),
                           std::move(case_artifacts),
                           all_moduli, all_roots,
                           TwiddleRequirement::kNone);

        case_artifacts.clear();
        words.clear(); append_words(words, ct_a_ntt[0]); append_words(words, ct_a_ntt[1]);
        add_artifact(case_artifacts, "ciphertext_ntt_q.bin", "input ciphertext",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"},
                     HardwareDomain::kNtt);
        words.clear(); append_words(words, plaintext_b_ntt);
        add_artifact(case_artifacts, "plaintext_ntt_q.bin", "input plaintext",
                     {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"},
                     HardwareDomain::kNtt);
        words.clear(); append_words(words, pmult_ntt[0]); append_words(words, pmult_ntt[1]);
        add_artifact(case_artifacts, "expected_ntt_q.bin", "plaintext-ciphertext product",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"},
                     HardwareDomain::kNtt);
        write_case_package(*suite_root, "pmult",
                           common_params("pmult", "NTT/Q", "NTT/Q", q_moduli),
                           std::move(case_artifacts),
                           q_moduli, q_roots,
                           TwiddleRequirement::kNone);

        case_artifacts.clear();
        words.clear(); append_words(words, ct_a_ntt[0]); append_words(words, ct_a_ntt[1]);
        append_words(words, ct_b_ntt[0]); append_words(words, ct_b_ntt[1]);
        add_artifact(case_artifacts, "input_ntt_q.bin", "A0,A1,B0,B1",
                     {4, g_num_q, g_n}, std::move(words),
                     {"input_component[A0,A1,B0,B1]", "basis_q", "coefficient"},
                     HardwareDomain::kNtt);
        words.clear(); for (const BasisPoly& component : tensor_ntt) append_words(words, component);
        add_artifact(case_artifacts, "expected_ntt_q.bin", "t0,t1,t2",
                     {3, g_num_q, g_n}, std::move(words),
                     {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"},
                     HardwareDomain::kNtt);
        write_case_package(*suite_root, "cmult",
                           common_params("cmult", "NTT/Q", "NTT/Q", q_moduli),
                           std::move(case_artifacts),
                           q_moduli, q_roots,
                           TwiddleRequirement::kNone);

        case_artifacts.clear();
        words.clear(); append_words(words, keyswitch_qp[0]);
        add_artifact(case_artifacts, "input_qp.bin", "key-switch component before ModDown",
                     {g_num_q + g_num_p, g_n}, std::move(words),
                     {"basis_q_then_p", "coefficient"});
        words.clear(); append_words(words, keyswitch_q[0]);
        add_artifact(case_artifacts, "expected_q.bin", "key-switch component after ModDown",
                     {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"});
        write_case_package(*suite_root, "moddown",
                           common_params("moddown", "coefficient/QP", "coefficient/Q", all_moduli),
                           std::move(case_artifacts),
                           all_moduli, all_roots,
                           TwiddleRequirement::kNone);

        case_artifacts.clear();
        words.clear(); append_words(words, tensor[0]);
        add_artifact(case_artifacts, "input_base_q.bin", "KeySwitch base component t0",
                     {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"});
        words.clear(); append_words(words, tensor[2]);
        add_artifact(case_artifacts, "input_t2_q.bin", "KeySwitch switching component t2",
                     {g_num_q, g_n}, std::move(words), {"basis_q", "coefficient"});
        words.clear();
        for (const auto& digit : rlk_ntt) { append_words(words, digit[0]); append_words(words, digit[1]); }
        add_artifact(case_artifacts, "rlk_ntt_qp.bin", "relinearization key",
                     {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
                     {"digit", "component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                     HardwareDomain::kNtt);
        words.clear(); append_words(words, keyswitch_output[0]); append_words(words, keyswitch_output[1]);
        add_artifact(case_artifacts, "expected_q.bin", "KeySwitch(t0, t2) output",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[t0_plus_ks0,ks1]", "basis_q", "coefficient"});
        write_case_package(*suite_root, "keyswitch",
                           common_params("keyswitch", "base/Q + switching_component/Q + rlk/NTT/QP",
                                         "coefficient/Q", all_moduli),
                           std::move(case_artifacts),
                           all_moduli, all_roots,
                           TwiddleRequirement::kRequired);

        case_artifacts.clear();
        words.clear();
        for (const BasisPoly& component : tensor) append_words(words, component);
        add_artifact(case_artifacts, "input_tensor_q.bin", "tensor ciphertext t0,t1,t2",
                     {3, g_num_q, g_n}, std::move(words),
                     {"tensor_component[t0,t1,t2]", "basis_q", "coefficient"});
        words.clear();
        for (const auto& digit : rlk_ntt) { append_words(words, digit[0]); append_words(words, digit[1]); }
        add_artifact(case_artifacts, "rlk_ntt_qp.bin", "relinearization key",
                     {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
                     {"digit", "component[ks0,ks1]", "basis_q_then_p", "coefficient"},
                     HardwareDomain::kNtt);
        words.clear(); append_words(words, output[0]); append_words(words, output[1]);
        add_artifact(case_artifacts, "expected_q.bin", "relinearized ciphertext",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[t0_plus_ks0,t1_plus_ks1]", "basis_q", "coefficient"});
        write_case_package(*suite_root, "relinearization",
                           common_params("relinearization",
                                         "tensor/coefficient/Q + rlk/NTT/QP",
                                         "ciphertext/coefficient/Q", all_moduli),
                           std::move(case_artifacts),
                           all_moduli, all_roots,
                           TwiddleRequirement::kRequired);

        case_artifacts.clear();
        words.clear();
        append_words(words, auto_rotated[0]);
        append_words(words, auto_rotated[1]);
        add_artifact(case_artifacts, "input_rotated_q.bin",
                     "CPU-applied negacyclic x->x^3 ciphertext",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"});
        words.clear();
        for (const auto& digit : galois_key_ntt) {
            append_words(words, digit[0]);
            append_words(words, digit[1]);
        }
        add_artifact(case_artifacts, "galois_key_ntt_qp.bin",
                     "Galois key switching sigma_3(s) back to s",
                     {g_dnum, 2, g_num_q + g_num_p, g_n}, std::move(words),
                     {"digit", "component[ks0,ks1]", "basis_q_then_p",
                      "coefficient"}, HardwareDomain::kNtt);
        words.clear();
        append_words(words, auto_output[0]);
        append_words(words, auto_output[1]);
        add_artifact(case_artifacts, "expected_q.bin",
                     "automorphed and Galois-key-switched ciphertext",
                     {2, g_num_q, g_n}, std::move(words),
                     {"component[c0,c1]", "basis_q", "coefficient"});
        write_case_package(*suite_root, "auto",
                           common_params("auto",
                                         "CPU coefficient automorphism/Q + Galois key/NTT/QP",
                                         "ciphertext/coefficient/Q", all_moduli),
                           std::move(case_artifacts), all_moduli, all_roots,
                           TwiddleRequirement::kRequired);
        write_text(*suite_root / "auto" / "test_data" / "AUTO_LAYOUT.json",
                   "{\n"
                   "  \"auto_index\": " + std::to_string(g_auto_index) + ",\n"
                   "  \"galois_element\": " + std::to_string(kAutoGaloisElement) + ",\n"
                   "  \"coefficient_map\": \"dst=(src*galois_element) mod 2N; negate when dst>=N\",\n"
                   "  \"cpu_preprocess\": true,\n"
                   "  \"hpu_stage\": \"Galois KeySwitch only\"\n"
                   "}\n");
        write_text(*suite_root / "auto" / "test_data" / "STATUS.md",
                   "PASS: auto index 1 is frozen to negacyclic x->x^3. The CPU performs the "
                   "coefficient permutation because the frozen 11-instruction HPU ISA has no "
                   "shuffle opcode; the generated HPU program performs the complete Galois "
                   "KeySwitch with bit-exact input/key/output artifacts.\n");
    }

    std::cout << "Generated " << artifacts.size() << " binary artifacts in " << output_root << '\n';
    std::cout << "FHE reference validation: PASS\n";
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        std::filesystem::path config_path = hpu::test::default_fhe_test_config_path();
        std::vector<std::filesystem::path> positional;
        for (int index = 1; index < argc; ++index) {
            const std::string argument = argv[index];
            if (argument == "--config") {
                if (++index >= argc) {
                    throw std::runtime_error("--config requires a path");
                }
                config_path = argv[index];
            } else if (argument.rfind("--", 0) == 0) {
                throw std::runtime_error("unknown argument: " + argument);
            } else {
                positional.emplace_back(argument);
            }
        }
        if (positional.size() > 2) {
            throw std::runtime_error(
                "usage: hpu_reference_vectors [output-root] [suite-root] [--config path]");
        }

        const hpu::test::FheTestConfig config =
            hpu::test::load_fhe_test_config(config_path);
        g_n = config.N;
        g_num_q = config.num_q;
        g_num_p = config.num_p;
        g_bfv_num_b = config.bfv_num_b;
        g_dnum = config.dnum;
        g_auto_index = config.auto_index;
        g_plaintext_modulus = config.plaintext_modulus;
        g_seed = config.seed;
        g_hpu_mem_max_lines = config.hpu_mem_max_lines;

        const std::filesystem::path output = !positional.empty()
            ? positional[0]
            : std::filesystem::path("outputs/ciphertext_multiply/test_data");
        const std::filesystem::path suite = positional.size() > 1
            ? positional[1]
            : std::filesystem::path();
        std::cout << "Loaded shared FHE config from " << config_path
                  << " (N=" << g_n << ", Q=" << g_num_q
                  << ", P=" << g_num_p << ", B=" << g_bfv_num_b
                  << ", dnum=" << g_dnum
                  << ", HPU_MEM_MAX=" << g_hpu_mem_max_lines << ")\n";
        generate(output, positional.size() > 1 ? &suite : nullptr);
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Reference generation failed: " << exception.what() << '\n';
        return 1;
    }
}
