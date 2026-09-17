#include "operator/rounded_drop_last.hpp"

#include "operator/rns_layout.hpp"
#include "poly/moddown.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <algorithm>
#include <sstream>
#include <vector>

std::string generate_hpu_rounded_single_p_moddown_contexts_body_asm(
    const std::vector<int>& q_contexts,
    int p_context,
    int num_components,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!hpu::valid_mod_id_list(q_contexts)
        || p_context < 0 || p_context >= hpu::kMaxModContexts
        || std::find(q_contexts.begin(), q_contexts.end(), p_context)
            != q_contexts.end()
        || num_components <= 0) {
        asm_code << "        // Invalid rounded single-P ModDown context layout\n";
        return asm_code.str();
    }

    constexpr int POBJ_VALUE = 0;
    constexpr int POBJ_HALF = 1;
    constexpr int POBJ_MOD_CTX = 4;

    std::vector<int> full_contexts = q_contexts;
    full_contexts.push_back(p_context);

    asm_code << "        /* ROUNDED SINGLE-P MODDOWN: coefficient/QP -> coefficient/Q */\n";
    asm_code << "        /* Formula: round(x/P) = ModDown(x + floor(P/2), P={P}). */\n";
    asm_code << "        /* No coefficient comparison: half-P residues are preloaded constants. */\n";

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* component " << component
                 << " stage-1: add floor(P/2) in Q union P */\n";
        if (manage_modulus_table) {
            asm_code << hpu::dload(
                POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank);
        }
        for (int context : full_contexts) {
            asm_code << "        /* component " << component
                     << ", MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_HALF, hpu::DataType::poly);
            asm_code << hpu::padd(POBJ_VALUE, POBJ_VALUE, POBJ_HALF);
            asm_code << hpu::pfree(POBJ_HALF);
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
        if (manage_modulus_table) {
            asm_code << hpu::pfree(POBJ_MOD_CTX);
        }
        asm_code << ::generate_hpu_moddown_contexts_body_asm(
            q_contexts, {p_context}, false, manage_modulus_table);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_hpu_rounded_drop_last_body_asm(
    int num_q,
    int num_components,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (num_q < 2 || num_components <= 0
        || !hpu::has_mod_context_capacity(num_q)) {
        asm_code << "        // Invalid rounded drop-last config: require 2 <= num_q <= 64 and components > 0\n";
        return asm_code.str();
    }

    const int dropped_context = num_q - 1;

    asm_code << "        /* ROUNDED DROP-LAST: round(x/q_" << dropped_context
             << ") for " << num_components << " component(s) */\n";
    std::vector<int> retained_contexts;
    retained_contexts.reserve(static_cast<std::size_t>(dropped_context));
    for (int context = 0; context < dropped_context; ++context) {
        retained_contexts.push_back(context);
    }
    asm_code << generate_hpu_rounded_single_p_moddown_contexts_body_asm(
        retained_contexts,
        dropped_context,
        num_components,
        append_psync,
        manage_modulus_table);
    return asm_code.str();
}
