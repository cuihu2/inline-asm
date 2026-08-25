#include "scheme/ckks/ciphertext_multiply.hpp"

#include "operator/ciphertext_multiply.hpp"
#include "scheme/ckks/rescale.hpp"
#include "util/hpu_asm.hpp"

#include <cmath>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::ckks {
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
        && num_q + num_p <= hpu::kMaxModContexts;
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
        asm_code << "        // Invalid CKKS multiply config: require N fitting one bank, num_q >= 2, divisible digits, and <= 256 contexts\n";
        return asm_code.str();
    }

    asm_code << "        /* CKKS MULTIPLY: common tensor/relinearization followed by rounded Rescale */\n";
    asm_code << ::generate_hpu_ciphertext_multiply_body_asm(
        N, num_q, num_p, dnum, false);
    asm_code << generate_rescale_body_asm(num_q, 2, false);
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
    asm_code << "void hpu_ckks_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid CKKS multiply config\n}\n";
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

double multiply_scale(double scale_a, double scale_b)
{
    if (!std::isfinite(scale_a) || !std::isfinite(scale_b)
        || scale_a <= 0.0 || scale_b <= 0.0) {
        throw std::invalid_argument("CKKS input scales must be positive");
    }
    const double result = scale_a * scale_b;
    if (!std::isfinite(result)) {
        throw std::overflow_error("CKKS multiplied scale is not finite");
    }
    return result;
}

} // namespace hpu::scheme::ckks
