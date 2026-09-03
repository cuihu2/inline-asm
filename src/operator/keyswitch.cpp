#include "operator/keyswitch.hpp"

#include "poly/modup.hpp"
#include "poly/moddown.hpp"
#include "util/hpu_asm.hpp"
#include "util/mm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <string>

std::string generate_hpu_keyswitch_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;

    if (!hpu::is_valid_rns_decomposition_layout(N, layout)) {
        asm_code << "        // Invalid explicit KeySwitch RNS layout\n";
        return asm_code.str();
    }

    const auto& q_contexts = layout.q_mod_ids;
    const auto& p_contexts = layout.p_mod_ids;
    std::vector<int> full_contexts = q_contexts;
    full_contexts.insert(
        full_contexts.end(), p_contexts.begin(), p_contexts.end());
    const int dnum = static_cast<int>(layout.key_digits.size());

    const int POBJ_MOD_CTX = 4;
    const int TWIDDLE = 3;
    const int POBJ_TMP_A = 0;

    asm_code << "        /* KEYSWITCH BODY: (base, switching_component) -> (base + ks0, ks1) */\n";
    asm_code << "        /* Application-global MOD_IDs; fixed P survives Q level drops. */\n";
    asm_code << "        /* --- Active SEAL key digits loop (dnum = " << dnum << ") --- */\n";
    for (int d = 0; d < dnum; ++d) {
        asm_code << "        /* --- Digit " << d << " --- */\n";

        // 1. ModUp (Q digit -> full Q union P)
        asm_code << "        /* --- Step 1: ModUp --- */\n";
        asm_code << generate_hpu_modup_contexts_body_asm(
            q_contexts,
            p_contexts,
            layout.key_digits[static_cast<std::size_t>(d)],
            false,
            manage_modulus_table);

        // 2. NTT
        asm_code << "        /* --- Step 2: NTT on Q and P bases --- */\n";
        if (manage_modulus_table) {
            asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                                   hpu::DloadFlag::small_bank);
        }

        for (int context : full_contexts) {
            asm_code << "        /* NTT MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
            asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, TWIDDLE, false);
            asm_code << hpu::dstore(POBJ_TMP_A, 1);
        }

        // 3. Multiplication with Evk
        asm_code << "        /* --- Step 3: Multiply with Evaluation Key --- */\n";
        const int POBJ_CT = 0;
        const int POBJ_EVK = 1;
        const int POBJ_OUT = 2;

        for (int v = 0; v < 2; ++v) {
            asm_code << "        /* evk" << v << " mult for all bases */\n";
            for (int context : full_contexts) {
                asm_code << "        /* base MOD_ID " << context << " */\n";
                asm_code << hpu::pmodld(context);
                // IF first digit, just mul. If subsequent digits, multiply and accumulate (pmac)
                asm_code << hpu::dload(POBJ_CT, hpu::DataType::poly);
                asm_code << hpu::dload(POBJ_EVK, hpu::DataType::poly);
                if (d == 0) {
                    asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_CT, POBJ_EVK);
                } else {
                    asm_code << hpu::dload(POBJ_OUT, hpu::DataType::poly); // Load accumulated result
                    asm_code << hpu::pmac(POBJ_OUT, POBJ_CT, POBJ_EVK);
                }
                asm_code << hpu::pfree(POBJ_CT);
                asm_code << hpu::pfree(POBJ_EVK);
                asm_code << hpu::dstore(POBJ_OUT, 1);
            }
        }
        if (manage_modulus_table) {
            asm_code << hpu::pfree(POBJ_MOD_CTX);
        }
    }

    // 4. INTT
    asm_code << "        /* --- Step 4: INTT on Q and P bases --- */\n";
    const int POBJ_MOD_CTX2 = 4;
    const int TWIDDLE2 = 3;
    const int POBJ_TMP_A2 = 0;
    if (manage_modulus_table) {
        asm_code << hpu::dload(POBJ_MOD_CTX2, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int v = 0; v < 2; ++v) {
        asm_code << "        /* INTT for out" << v << " */\n";
        for (int context : full_contexts) {
            asm_code << "        /* INTT MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_TMP_A2, hpu::DataType::poly);
            asm_code << generate_hpu_intt_body_asm(N, POBJ_TMP_A2, TWIDDLE2, false);
            asm_code << hpu::dstore(POBJ_TMP_A2, 1);
        }
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(POBJ_MOD_CTX2);
    }

    // 5. ModDown
    asm_code << "        /* --- Step 5: ModDown for both parts --- */\n";
    for (int v = 0; v < 2; ++v) {
        asm_code << "        /* ModDown for out" << v << " */\n";
        asm_code << generate_hpu_moddown_contexts_body_asm(
            q_contexts, p_contexts, false, manage_modulus_table);
    }
    asm_code << "        /* --- Step 6: Add base component to out0 --- */\n";
    const int POBJ_MOD_CTX_S6 = 4;
    const int POBJ_OUT0 = 0;
    const int POBJ_BASE = 1;
    const int POBJ_FINAL_OUT0 = 2;

    if (manage_modulus_table) {
        asm_code << hpu::dload(POBJ_MOD_CTX_S6, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    
    for (int context : q_contexts) {
        asm_code << hpu::pmodld(context);
        // 1. 加载刚才 ModDown 生成的 out0
        asm_code << hpu::dload(POBJ_OUT0, hpu::DataType::poly);
        // 2. 加载不参与分解、需要并入第一输出分量的 base（普通 KeySwitch 为 c0）
        asm_code << hpu::dload(POBJ_BASE, hpu::DataType::poly);
        // 3. 在片上直接相加
        asm_code << hpu::padd(POBJ_FINAL_OUT0, POBJ_OUT0, POBJ_BASE);
        asm_code << hpu::pfree(POBJ_OUT0);
        asm_code << hpu::pfree(POBJ_BASE);
        // 4. 写回主存
        asm_code << hpu::dstore(POBJ_FINAL_OUT0, 1);
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(POBJ_MOD_CTX_S6);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_keyswitch_body_asm(
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
    return generate_hpu_keyswitch_body_asm(
        N,
        hpu::make_contiguous_rns_decomposition_layout(num_q, num_p, dnum),
        append_psync,
        manage_modulus_table);
}

std::string generate_hpu_keyswitch_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_keyswitch_N" << N << "_Q" << num_q << "_P" << num_p << "_D" << dnum << "(void) {\n";

    if (!hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << "        /* KEYSWITCH: (base, switching_component) -> (base + ks0, ks1) */\n";

    asm_code << generate_hpu_keyswitch_body_asm(N, num_q, num_p, dnum, append_psync);

    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}
