#include "poly/moddown.hpp"

#include "util/bconv.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <string>
#include <vector>

namespace {

bool valid_moddown_config(int num_q, int num_p)
{
    return num_p > 0 && hpu::has_mod_context_capacity(num_q, num_p);
}

} // namespace
// Coefficient domain.
std::string generate_hpu_moddown_body_asm(
    int num_q,
    int num_p,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;

    if (!valid_moddown_config(num_q, num_p)) {
        asm_code << "        // Invalid config: require positive bases within the 8-bit MOD_ID capacity\n";
        return asm_code.str();
    }

    // 复用 HPU 硬件槽位
    const int POBJ_MOD_CTX = 4;
    const int POBJ_Q = 0;
    const int POBJ_CORR = 1;
    const int POBJ_P_INV = 2; //用于存放 P^{-1} mod q_i

    asm_code << "        /* MODDOWN stage-1: BConv P -> Q (correction term) */\n";
    // Global context order is Q followed by P.
    std::vector<int> source_contexts;
    std::vector<int> target_contexts;
    for (int i = 0; i < num_p; ++i) {
        source_contexts.push_back(num_q + i);
    }
    for (int i = 0; i < num_q; ++i) {
        target_contexts.push_back(i);
    }
    asm_code << generate_hpu_bconv_contexts_body_asm(
        source_contexts,
        target_contexts,
        false,
        manage_modulus_table);

    if (manage_modulus_table) {
        asm_code << "        // dload the runtime-relocated complete modulus table\n";
        asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }

    asm_code << "        /* MODDOWN stage-2: q <- q - correction (mod q_i) */\n";
    for (int i = 0; i < num_q; ++i) {
        asm_code << "        /* q_" << i << " */\n";
        asm_code << hpu::pmodld(i);

        asm_code << hpu::dload(POBJ_Q, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_CORR, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_P_INV, hpu::DataType::poly);
        
        asm_code << hpu::psub(POBJ_Q, POBJ_Q, POBJ_CORR);
        asm_code << hpu::pmul(POBJ_Q, POBJ_Q, POBJ_P_INV);
        asm_code << hpu::pfree(POBJ_CORR);
        asm_code << hpu::pfree(POBJ_P_INV);
        asm_code << hpu::dstore(POBJ_Q, 1);
    }

    if (manage_modulus_table) {
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_moddown_asm(
    int num_q,
    int num_p,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_moddown_Q" << num_q << "_P" << num_p << "(void) {\n";

    if (!valid_moddown_config(num_q, num_p)) {
        asm_code << "    // Invalid config: require positive bases within the 8-bit MOD_ID capacity\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_moddown_body_asm(
        num_q,
        num_p,
        append_psync);

    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}
