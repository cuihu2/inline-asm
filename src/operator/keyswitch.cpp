#include "operator/keyswitch.hpp"

#include "poly/modup.hpp"
#include "poly/moddown.hpp"
#include "util/hpu_asm.hpp"
#include "util/mm.hpp"
#include "util/ntt.hpp"

#include <sstream>
#include <string>

namespace {

bool is_power_of_two(int x)
{
    return x > 0 && (x & (x - 1)) == 0;
}

} // namespace

std::string generate_hpu_keyswitch_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (num_q <= 0 || num_p <= 0 || dnum <= 0 || !is_power_of_two(N)
        || !hpu::fits_ntt_object(N)
        || num_q % dnum != 0 || num_q + num_p > hpu::kMaxModContexts) {
        asm_code << "        // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
        return asm_code.str();
    }

    int total_bases = num_q + num_p;
    int digit_size = num_q / dnum;

    const int POBJ_MOD_CTX = 4;
    const int TWIDDLE = 3;
    const int POBJ_TMP_A = 0;

    asm_code << "        /* KEYSWITCH BODY: (base, switching_component) -> (base + ks0, ks1) */\n";
    asm_code << "        /* --- Decomposed digits loop (dnum = " << dnum << ") --- */\n";
    for (int d = 0; d < dnum; ++d) {
        int q_offset = d * digit_size;
        asm_code << "        /* --- Digit " << d << " --- */\n";

        // 1. ModUp (Q digit -> full Q union P)
        asm_code << "        /* --- Step 1: ModUp --- */\n";
        asm_code << generate_hpu_modup_body_asm(
            num_q,
            num_p,
            digit_size,
            q_offset,
            false);

        // 2. NTT
        asm_code << "        /* --- Step 2: NTT on Q and P bases --- */\n";
        asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);

        for (int i = 0; i < total_bases; ++i) {
            asm_code << "        /* NTT ctx_" << i << " */\n";
            asm_code << hpu::pmodld(i);
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
            for (int i = 0; i < total_bases; ++i) {
                asm_code << "        /* base_" << i << " */\n";
                asm_code << hpu::pmodld(i);
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
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }

    // 4. INTT
    asm_code << "        /* --- Step 4: INTT on Q and P bases --- */\n";
    const int POBJ_MOD_CTX2 = 4;
    const int TWIDDLE2 = 3;
    const int POBJ_TMP_A2 = 0;
    asm_code << hpu::dload(POBJ_MOD_CTX2, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int v = 0; v < 2; ++v) {
        asm_code << "        /* INTT for out" << v << " */\n";
        for (int i = 0; i < total_bases; ++i) {
            asm_code << "        /* INTT ctx_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << hpu::dload(POBJ_TMP_A2, hpu::DataType::poly);
            asm_code << generate_hpu_intt_body_asm(N, POBJ_TMP_A2, TWIDDLE2, false);
            asm_code << hpu::dstore(POBJ_TMP_A2, 1);
        }
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX2);

    // 5. ModDown
    asm_code << "        /* --- Step 5: ModDown for both parts --- */\n";
    for (int v = 0; v < 2; ++v) {
        asm_code << "        /* ModDown for out" << v << " */\n";
        asm_code << generate_hpu_moddown_body_asm(num_q, num_p, false);
    }
    asm_code << "        /* --- Step 6: Add base component to out0 --- */\n";
    const int POBJ_MOD_CTX_S6 = 4;
    const int POBJ_OUT0 = 0;
    const int POBJ_BASE = 1;
    const int POBJ_FINAL_OUT0 = 2;

    asm_code << hpu::dload(POBJ_MOD_CTX_S6, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    
    for (int i = 0; i < num_q; ++i) { // 降模后只有 num_q 个基了
        asm_code << hpu::pmodld(i); // 切换固定模表中的 MOD_ID
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
    asm_code << hpu::pfree(POBJ_MOD_CTX_S6);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
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

    if (num_q <= 0 || num_p <= 0 || !is_power_of_two(N) || dnum <= 0
        || !hpu::fits_ntt_object(N)
        || num_q % dnum != 0 || num_q + num_p > hpu::kMaxModContexts) {
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
