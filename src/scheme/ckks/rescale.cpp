#include "scheme/ckks/rescale.hpp"

#include "operator/rounded_drop_last.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <cmath>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::ckks {
namespace {

bool valid_rescale_config(int num_q, int num_components)
{
    return num_q >= 2 && num_components > 0
        && hpu::has_mod_context_capacity(num_q);
}

} // namespace

std::string generate_rescale_body_asm(
    int num_q,
    int num_components,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_rescale_config(num_q, num_components)) {
        asm_code << "        // Invalid CKKS Rescale config: require 2 <= num_q <= 256 and num_components > 0\n";
        return asm_code.str();
    }

    asm_code << "        /* CKKS RESCALE: rounded drop-last q_" << (num_q - 1)
             << " for " << num_components << " component(s) */\n";
    asm_code << ::generate_hpu_rounded_drop_last_body_asm(
        num_q, num_components, append_psync, manage_modulus_table);
    return asm_code.str();
}

std::string generate_rescale_asm(
    int num_q,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_rescale_Q" << num_q << "_C" << num_components
             << "(void) {\n";

    if (!valid_rescale_config(num_q, num_components)) {
        asm_code << "    // Invalid CKKS Rescale config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_rescale_body_asm(
        num_q, num_components, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}

double rescale_scale(double scale, std::uint64_t q_last)
{
    if (!std::isfinite(scale) || scale <= 0.0 || q_last == 0) {
        throw std::invalid_argument("CKKS scale and q_last must be positive");
    }
    return scale / static_cast<double>(q_last);
}

} // namespace hpu::scheme::ckks
