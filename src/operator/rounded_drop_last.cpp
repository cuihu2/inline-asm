#include "operator/rounded_drop_last.hpp"

#include "poly/moddown.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <sstream>

std::string generate_hpu_rounded_drop_last_body_asm(
    int num_q,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (num_q < 2 || num_components <= 0
        || !hpu::has_mod_context_capacity(num_q)) {
        asm_code << "        // Invalid rounded drop-last config: require 2 <= num_q <= 256 and components > 0\n";
        return asm_code.str();
    }

    const int POBJ_VALUE = 0;
    const int POBJ_HALF = 1;
    const int POBJ_MOD_CTX = 4;
    const int dropped_context = num_q - 1;

    asm_code << "        /* ROUNDED DROP-LAST: round(x/q_" << dropped_context
             << ") for " << num_components << " component(s) */\n";
    asm_code << "        /* Formula: ModDown(x + floor(q_last/2), P={q_last}). */\n";

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* component " << component
                 << " stage-1: add floor(q_last/2) in every Q context */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        for (int i = 0; i < num_q; ++i) {
            asm_code << "        /* component " << component << ", q_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_HALF, hpu::DataType::poly);
            asm_code << hpu::padd(POBJ_VALUE, POBJ_VALUE, POBJ_HALF);
            asm_code << hpu::pfree(POBJ_HALF);
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
        asm_code << hpu::pfree(POBJ_MOD_CTX);
        asm_code << ::generate_hpu_moddown_body_asm(
            dropped_context, 1, false);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}
