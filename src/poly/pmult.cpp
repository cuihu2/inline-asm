#include "poly/pmult.hpp"

#include "util/hpu_asm.hpp"
#include "util/mm.hpp"
#include <sstream>
#include <string>

std::string generate_hpu_pmult_body_asm(
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (num_q <= 0) {
        asm_code << "        // Invalid config: require num_q > 0\n";
        return asm_code.str();
    }

    asm_code << "        /* PMULT: (ct0, ct1) * pt over RNS basis Q */\n";

    const int POBJ_MOD_CTX = 4;
    const int POBJ_CT = 0;
    const int POBJ_PT = 1;
    const int POBJ_OUT = 2;

    asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int i = 0; i < num_q; ++i) {
        asm_code << "        /* q_" << i << " */\n";
        asm_code << hpu::pmodld(i);

        asm_code << hpu::dload(POBJ_CT, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_PT, hpu::DataType::poly);
        asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_CT, POBJ_PT);
        asm_code << hpu::pfree(POBJ_CT);
        asm_code << hpu::dstore(POBJ_OUT, 1);

        asm_code << hpu::dload(POBJ_CT, hpu::DataType::poly);
        asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_CT, POBJ_PT);
        asm_code << hpu::pfree(POBJ_CT);
        asm_code << hpu::pfree(POBJ_PT);
        asm_code << hpu::dstore(POBJ_OUT, 1);
    }

    asm_code << hpu::pfree(POBJ_MOD_CTX);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_pmult_asm(
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_pmult_Q" << num_q << "(void) {\n";

    if (num_q <= 0) {
        asm_code << "    // Invalid config: require num_q > 0\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_pmult_body_asm(num_q, append_psync);

    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}

// std::string generate_hpu_pmult_ntt_asm(
//     int N,
//     int num_q,
//     bool append_psync)
// {
//     std::ostringstream asm_code;
//     asm_code << "void hpu_pmult_ntt_N" << N << "_Q" << num_q << "(void) {\n";

//     if (num_q <= 0 || !is_power_of_two(N)) {
//         asm_code << "    // Invalid config: require num_q > 0 and power-of-two N\n";
//         asm_code << "}\n";
//         return asm_code.str();
//     }

//     asm_code << "    __asm__ volatile(\n";
//     asm_code << "        /* PMULT+NTT: NTT(ct0,ct1,pt) then point-wise multiply */\n";

//     const int POBJ_MOD_CTX = 4;
//     const int POBJ_SHF = 0; // Dummy
//     const int POBJ_TMP_A = 0;
//     const int POBJ_TMP_B = 1;
//     const int POBJ_PT_NTT = 2;
//     const int POBJ_CT_NTT = 0; // Reusing slot A for CT result

//     asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx);

//     for (int i = 0; i < num_q; ++i) {
//         asm_code << "        /* q_" << i << " */\n";
//         asm_code << hpu::pmodld(i);
//         // Pre-NTT PT
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, POBJ_SHF, false);
//         int pt_ntt_slot = POBJ_TMP_A;
//         // Move to POBJ_PT_NTT if it's not already there
//         if (pt_ntt_slot != POBJ_PT_NTT) {
//             // we will just dstore and reload or use alias, we can dstore then reload to POBJ_PT_NTT
//             asm_code << hpu::dstore(pt_ntt_slot, 0);
//             asm_code << hpu::dload(POBJ_PT_NTT, hpu::DataType::poly);
//         }

//         // Pre-NTT CT0
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, POBJ_SHF, false);
//         int ct0_ntt_slot = POBJ_TMP_A;
//         asm_code << generate_hpu_mm_body_asm(POBJ_TMP_A, ct0_ntt_slot, POBJ_PT_NTT);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);

//         // Pre-NTT CT1
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, POBJ_SHF, false);
//         int ct1_ntt_slot = POBJ_TMP_A;
//         asm_code << generate_hpu_mm_body_asm(POBJ_TMP_A, ct1_ntt_slot, POBJ_PT_NTT);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);
//     }

//     if (append_psync) {
//         asm_code << hpu::psync();
//     }

//     asm_code << "        : \n";
//     asm_code << "        : \n";
//     asm_code << "        : \"memory\"\n";
//     asm_code << "    );\n";
//     asm_code << "}\n";

//     return asm_code.str();
// }
