#include "scheme/ckks/rescale.hpp"

#include "poly/moddown.hpp"
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
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_rescale_config(num_q, num_components)) {
        asm_code << "        // Invalid CKKS Rescale config: require 2 <= num_q <= 256 and num_components > 0\n";
        return asm_code.str();
    }

    const int POBJ_VALUE = 0;
    const int POBJ_HALF = 1;
    const int POBJ_MOD_CTX = 4;
    const int dropped_context = num_q - 1;

    asm_code << "        /* CKKS RESCALE: rounded drop-last q_" << dropped_context
             << " for " << num_components << " component(s) */\n";
    asm_code << "        /* Formula: round(x/q_last) = ModDown(x + floor(q_last/2), q_last). */\n";

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* CKKS RESCALE component " << component
                 << " stage-1: add floor(q_last/2) in every Q context */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        for (int i = 0; i < num_q; ++i) {
            asm_code << "        /* component " << component << ", q_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << "        // dload input limb and floor(q_last/2) mod q_i\n";
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_HALF, hpu::DataType::poly);
            asm_code << hpu::padd(POBJ_VALUE, POBJ_VALUE, POBJ_HALF);
            asm_code << hpu::pfree(POBJ_HALF);
            asm_code << "        // dstore rounded numerator limb to scratch\n";
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
        asm_code << hpu::pfree(POBJ_MOD_CTX);

        asm_code << "        /* CKKS RESCALE component " << component
                 << " stage-2: reuse ModDown with Q'=q_0..q_"
                 << (dropped_context - 1) << " and P={q_" << dropped_context
                 << "} */\n";
        asm_code << ::generate_hpu_moddown_body_asm(
            dropped_context, 1, false);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }
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
