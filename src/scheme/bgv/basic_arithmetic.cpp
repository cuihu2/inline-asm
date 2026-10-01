#include "scheme/bgv/basic_arithmetic.hpp"

#include "scheme/ckks/basic_arithmetic.hpp"
#include "util/hpu_asm.hpp"

#include <numeric>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::bgv {
namespace {

std::uint32_t inverse_mod(std::uint32_t value, std::uint32_t modulus)
{
    std::int64_t old_r = modulus;
    std::int64_t r = value % modulus;
    std::int64_t old_s = 0;
    std::int64_t s = 1;
    while (r != 0) {
        const std::int64_t quotient = old_r / r;
        const std::int64_t next_r = old_r - quotient * r;
        const std::int64_t next_s = old_s - quotient * s;
        old_r = r;
        r = next_r;
        old_s = s;
        s = next_s;
    }
    if (old_r != 1) {
        throw std::invalid_argument("BGV correction factor is not invertible modulo t");
    }
    const std::int64_t signed_modulus = modulus;
    return static_cast<std::uint32_t>(
        (old_s % signed_modulus + signed_modulus) % signed_modulus);
}

std::uint32_t signed_residue(__int128 value, std::uint32_t modulus)
{
    value %= modulus;
    if (value < 0) value += modulus;
    return static_cast<std::uint32_t>(value);
}

std::uint64_t balanced_magnitude(std::uint32_t value, std::uint32_t modulus)
{
    return value > modulus / 2
        ? static_cast<std::uint64_t>(modulus) - value : value;
}

std::uint64_t balance_cost(std::uint32_t left, std::uint32_t right,
                           std::uint32_t modulus)
{
    return balanced_magnitude(left, modulus) +
           balanced_magnitude(right, modulus);
}

std::string generate_binary_body(
    int num_q, const CorrectionBalance& balance, bool subtract,
    bool append_psync, bool manage_modulus_table)
{
    if (num_q <= 0 || num_q >= hpu::kMaxModContexts ||
        balance.output_factor == 0 || balance.left_scalar == 0 ||
        balance.right_scalar == 0) {
        return "        /* Invalid BGV NTT Add/Subtract config */\n";
    }
    std::ostringstream code;
    code << "        /* BGV NTT " << (subtract ? "SUB" : "ADD")
         << ": balance correction factors on HPU, then pointwise op */\n";
    if (manage_modulus_table) {
        code << hpu::dload(4, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    }
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            code << "        /* component " << component << ", Q MOD_ID "
                 << basis << " */\n";
            code << hpu::pmodld(basis);
            code << hpu::dload(0, hpu::DataType::poly);
            if (balance.left_scalar != 1) {
                code << "        // prepared left balancing scalar splat\n";
                code << hpu::dload(3, hpu::DataType::poly);
                code << hpu::pmul(0, 0, 3);
                code << hpu::pfree(3);
            }
            code << hpu::dload(1, hpu::DataType::poly);
            if (balance.right_scalar != 1) {
                code << "        // prepared right balancing scalar splat\n";
                code << hpu::dload(3, hpu::DataType::poly);
                code << hpu::pmul(1, 1, 3);
                code << hpu::pfree(3);
            }
            code << (subtract ? hpu::psub(2, 0, 1) : hpu::padd(2, 0, 1));
            code << hpu::pfree(0) << hpu::pfree(1);
            code << hpu::dstore(2, 1);
        }
    }
    if (manage_modulus_table) code << hpu::pfree(4);
    if (append_psync) code << hpu::psync();
    return code.str();
}

} // namespace

CorrectionBalance balance_correction_factors(
    std::uint32_t left_factor, std::uint32_t right_factor,
    std::uint32_t plaintext_modulus)
{
    if (plaintext_modulus < 65537 || left_factor == 0 || right_factor == 0 ||
        left_factor >= plaintext_modulus || right_factor >= plaintext_modulus) {
        throw std::invalid_argument("BGV correction factors or plaintext modulus are invalid");
    }
    if (left_factor == right_factor) {
        return {left_factor, 1, 1};
    }
    const std::uint32_t inverse = inverse_mod(left_factor, plaintext_modulus);
    const std::uint32_t ratio = static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(inverse) * right_factor) % plaintext_modulus);
    std::uint32_t left_scalar = ratio;
    std::uint32_t right_scalar = 1;
    std::uint64_t best_cost = balance_cost(ratio, 1, plaintext_modulus);

    __int128 previous_a = plaintext_modulus;
    __int128 previous_b = 0;
    __int128 a = ratio;
    __int128 b = 1;
    while (a != 0) {
        const __int128 quotient = previous_a / a;
        const __int128 next_a = previous_a % a;
        previous_a = a;
        a = next_a;
        const __int128 next_b = previous_b - b * quotient;
        previous_b = b;
        b = next_b;
        const auto candidate_left = signed_residue(a, plaintext_modulus);
        const auto candidate_right = signed_residue(b, plaintext_modulus);
        if (candidate_left != 0 &&
            std::gcd(candidate_left, plaintext_modulus) == 1) {
            const std::uint64_t cost = balance_cost(
                candidate_left, candidate_right, plaintext_modulus);
            if (cost < best_cost) {
                best_cost = cost;
                left_scalar = candidate_left;
                right_scalar = candidate_right;
            }
        }
    }
    return {
        static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(left_scalar) * left_factor) % plaintext_modulus),
        left_scalar, right_scalar};
}

std::string generate_add_body_asm(
    int num_q, const CorrectionBalance& balance,
    bool append_psync, bool manage_modulus_table)
{
    return generate_binary_body(
        num_q, balance, false, append_psync, manage_modulus_table);
}

std::string generate_subtract_body_asm(
    int num_q, const CorrectionBalance& balance,
    bool append_psync, bool manage_modulus_table)
{
    return generate_binary_body(
        num_q, balance, true, append_psync, manage_modulus_table);
}

std::string generate_negate_body_asm(
    int num_q, bool append_psync, bool manage_modulus_table)
{
    return hpu::scheme::ckks::generate_negate_body_asm(
        num_q, append_psync, manage_modulus_table);
}

} // namespace hpu::scheme::bgv
