#include "operator/relinearization.hpp"

#include "operator/keyswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <string>

namespace {

std::string generate_add_second_component_body_asm(
    const std::vector<int>& q_contexts,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;

    const int POBJ_T1 = 0;
    const int POBJ_KS1 = 1;
    const int POBJ_OUT1 = 2;
    const int POBJ_MOD_CTX = 4;

    asm_code << "        /* --- Relinearization final merge: out1 = t1 + ks1 --- */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int context : q_contexts) {
        asm_code << "        /* q MOD_ID " << context << " */\n";
        asm_code << hpu::pmodld(context);
        asm_code << hpu::dload(POBJ_T1, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_KS1, hpu::DataType::poly);
        asm_code << hpu::padd(POBJ_OUT1, POBJ_T1, POBJ_KS1);
        asm_code << hpu::pfree(POBJ_T1);
        asm_code << hpu::pfree(POBJ_KS1);
        asm_code << hpu::dstore(POBJ_OUT1, 1);
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }

    return asm_code.str();
}

} // namespace

std::string generate_hpu_relinearization_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;

    if (!hpu::is_valid_rns_decomposition_layout(N, layout)) {
        asm_code << "        // Invalid explicit Relinearization RNS layout\n";
        return asm_code.str();
    }

    asm_code << "        /* --- Relinearization: KeySwitch(t2, rlk) with base=t0 --- */\n";
    asm_code << "        /* KeySwitch(base=t0, switching_component=t2) -> (t0 + ks0, ks1) */\n";
    asm_code << generate_hpu_keyswitch_body_asm(
        N, layout, false, manage_modulus_table);
    asm_code << "        /* --- Compose final ciphertext: out0=t0+ks0, out1=t1+ks1 --- */\n";
    asm_code << generate_add_second_component_body_asm(
        layout.q_mod_ids, manage_modulus_table);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_relinearization_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync,
    bool manage_modulus_table)
{
    if (!hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum)) {
        return "        // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
    }
    return generate_hpu_relinearization_body_asm(
        N,
        hpu::make_contiguous_rns_decomposition_layout(num_q, num_p, dnum),
        append_psync,
        manage_modulus_table);
}

std::string generate_hpu_relinearization_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_relinearization_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";

    if (!hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_relinearization_body_asm(
        N,
        num_q,
        num_p,
        dnum,
        append_psync);
    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}
