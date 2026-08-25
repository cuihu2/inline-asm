#include "scheme/bgv/ciphertext_multiply.hpp"

#include "operator/ciphertext_multiply.hpp"
#include "util/hpu_asm.hpp"

#include <sstream>
#include <stdexcept>

namespace hpu::scheme::bgv {
namespace {

bool is_power_of_two(int value)
{
    return value > 0 && (value & (value - 1)) == 0;
}

bool valid_config(int N, int num_q, int num_p, int dnum)
{
    return is_power_of_two(N) && hpu::fits_ntt_object(N)
        && num_q >= 2 && num_p > 0 && dnum > 0
        && num_q % dnum == 0
        && num_q + num_p + 1 <= hpu::kMaxModContexts;
}

} // namespace

std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "        // Invalid BGV multiply config: reserve Q|P|t contexts and require a valid common multiply configuration\n";
        return asm_code.str();
    }

    asm_code << "        /* BGV MULTIPLY: common tensor product and relinearization */\n";
    asm_code << "        /* Software metadata: correction_factor_out = factor_a * factor_b mod t. */\n";
    asm_code << ::generate_hpu_ciphertext_multiply_body_asm(
        N, num_q, num_p, dnum, false);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bgv_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid BGV multiply config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_ciphertext_multiply_body_asm(
        N, num_q, num_p, dnum, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}

std::uint64_t multiply_correction_factor(
    std::uint64_t factor_a,
    std::uint64_t factor_b,
    std::uint64_t plaintext_modulus)
{
    if (plaintext_modulus < 2) {
        throw std::invalid_argument("BGV plaintext modulus must be at least 2");
    }
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(factor_a % plaintext_modulus)
         * (factor_b % plaintext_modulus))
        % plaintext_modulus);
}

} // namespace hpu::scheme::bgv
