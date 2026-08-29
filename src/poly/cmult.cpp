#include "poly/cmult.hpp"

#include "util/hpu_asm.hpp"
#include "util/mm.hpp"
#include <sstream>
#include <string>
// eval domain
std::string generate_hpu_cmult_body_asm(
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (num_q <= 0) {
        asm_code << "        // Invalid config: require num_q > 0\n";
        return asm_code.str();
    }

    asm_code << "        /* CMULT: (a0,a1)*(b0,b1)->(out0,out1,out2) over basis Q */\n";

    const int POBJ_MOD_CTX = 4;
    const int POBJ_A = 0;
    const int POBJ_B = 1;
    const int POBJ_OUT = 2;

    asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int i = 0; i < num_q; ++i) {
        asm_code << "        /* q_" << i << " */\n";

        asm_code << hpu::pmodld(i);

        asm_code << "        /* --- CMULT out0 = a0 * b0 --- */\n";
        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly); // a0
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly); // b0
        asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A);
        asm_code << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1); // store out0

        asm_code << "        /* --- CMULT out1 = a0 * b1 + a1 * b0 --- */\n";
        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly); // a0
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly); // b1
        asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A);
        asm_code << hpu::pfree(POBJ_B);
        // temp result is in POBJ_OUT
        // Now compute a1 * b0 and ADD
        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly); // a1
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly); // b0
        asm_code << hpu::pmac(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A);
        asm_code << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1); // store out1

        asm_code << "        /* --- CMULT out2 = a1 * b1 --- */\n";
        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly); // a1
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly); // b1
        asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A);
        asm_code << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1); // store out2
    }

    asm_code << hpu::pfree(POBJ_MOD_CTX);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_cmult_asm(
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_cmult_Q" << num_q << "(void) {\n";

    if (num_q <= 0) {
        asm_code << "    // Invalid config: require num_q > 0\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_cmult_body_asm(num_q, append_psync);

    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}

// std::string generate_hpu_cmult_ntt_asm(
//     int N,
//     int num_q,
//     bool append_psync)
// {
//     std::ostringstream asm_code;
//     asm_code << "void hpu_cmult_ntt_N" << N << "_Q" << num_q << "(void) {\n";

//     if (num_q <= 0 || !is_power_of_two(N)) {
//         asm_code << "    // Invalid config: require num_q > 0 and power-of-two N\n";
//         asm_code << "}\n";
//         return asm_code.str();
//     }

//     asm_code << "    __asm__ volatile(\n";
//     asm_code << "        /* CMULT+NTT: NTT(a0,a1,b0,b1) then point-wise multiply-accumulate */\n";

//     const int POBJ_MOD_CTX = 6;
//     const int POBJ_TMP_A = 3;
//     const int POBJ_TMP_B = 4;
//     const int TWIDDLE = 5;
//     const int POBJ_A0 = 0;
//     const int POBJ_B0 = 1;
//     const int POBJ_OUT = 2; // For output accumulator

//     // Just DMA load sequences and run NTT, then store to DMA
//     // We cannot hold a0, a1, b0, b1 NTT forms all at once.
//     // Load un-NTT'd one by one, do NTT, and store the NTT'd back to memory.
//     for (int i = 0; i < num_q; ++i) {
//         asm_code << "        /* q_" << i << " */\n";

//         // Convert a0
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, TWIDDLE, false);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);

//         // Convert a1
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, TWIDDLE, false);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);

//         // Convert b0
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, TWIDDLE, false);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);

//         // Convert b1
//         asm_code << hpu::dload(POBJ_TMP_A, hpu::DataType::poly);
//         asm_code << generate_hpu_ntt_body_asm(N, POBJ_TMP_A, TWIDDLE, false);
//         asm_code << hpu::dstore(POBJ_TMP_A, 0);

//         // Now compute out0 = a0*b0
//         asm_code << hpu::dload(POBJ_A0, hpu::DataType::poly);
//         asm_code << hpu::dload(POBJ_B0, hpu::DataType::poly);
//         asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A0, POBJ_B0);
//         asm_code << hpu::dstore(POBJ_OUT, 0);

//         // out2 = a1*b1
//         asm_code << hpu::dload(POBJ_A0, hpu::DataType::poly);
//         asm_code << hpu::dload(POBJ_B0, hpu::DataType::poly);
//         asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A0, POBJ_B0);
//         asm_code << hpu::dstore(POBJ_OUT, 0);

//         // out1 = a0*b1 + a1*b0
//         asm_code << hpu::dload(POBJ_A0, hpu::DataType::poly);
//         asm_code << hpu::dload(POBJ_B0, hpu::DataType::poly);
//         asm_code << generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A0, POBJ_B0);
//         asm_code << hpu::dload(POBJ_A0, hpu::DataType::poly);
//         asm_code << hpu::dload(POBJ_B0, hpu::DataType::poly);
//         asm_code << hpu::pmac(POBJ_OUT, POBJ_A0, POBJ_B0);
//         asm_code << hpu::dstore(POBJ_OUT, 0);
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
