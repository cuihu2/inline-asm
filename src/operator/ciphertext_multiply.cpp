#include "operator/ciphertext_multiply.hpp"

#include "operator/relinearization.hpp"
#include "poly/cmult.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"

#include <cmath>
#include <sstream>
#include <string>

namespace {

bool is_power_of_two(int x)
{
    return x > 0 && (x & (x - 1)) == 0;
}

bool is_valid_config(int N, int num_q, int num_p, int dnum)
{
    return is_power_of_two(N) && hpu::fits_ntt_object(N)
        && num_q > 0 && num_p > 0 && dnum > 0
        && num_q % dnum == 0 && num_q + num_p <= hpu::kMaxModContexts;
}

std::string generate_basis_ntt_body_asm(
    int N,
    int num_q,
    int num_components,
    const std::string& label)
{
    std::ostringstream asm_code;

    const int POBJ_POLY = 0;
    const int POBJ_TWIDDLE = 3;
    const int POBJ_MOD_CTX = 4;

    asm_code << "        /* --- " << label << ": coefficient -> NTT domain --- */\n";
    asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* " << label << " component_" << component << " */\n";
        for (int i = 0; i < num_q; ++i) {
            asm_code << "        /* q_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << hpu::dload(POBJ_POLY, hpu::DataType::poly);
            asm_code << generate_hpu_ntt_body_asm(N, POBJ_POLY, POBJ_TWIDDLE, false);
            asm_code << hpu::dstore(POBJ_POLY, 1);
        }
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX);

    return asm_code.str();
}

std::string generate_basis_intt_body_asm(
    int N,
    int num_q,
    int num_components,
    const std::string& label)
{
    std::ostringstream asm_code;

    const int POBJ_POLY = 0;
    const int POBJ_TWIDDLE = 3;
    const int POBJ_MOD_CTX = 4;

    asm_code << "        /* --- " << label << ": NTT -> coefficient domain --- */\n";
    asm_code << hpu::dload(POBJ_MOD_CTX, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* " << label << " component_" << component << " */\n";
        for (int i = 0; i < num_q; ++i) {
            asm_code << "        /* q_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << hpu::dload(POBJ_POLY, hpu::DataType::poly);
            asm_code << generate_hpu_intt_body_asm(N, POBJ_POLY, POBJ_TWIDDLE, false);
            asm_code << hpu::dstore(POBJ_POLY, 1);
        }
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX);

    return asm_code.str();
}

} // namespace

std::string generate_hpu_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!is_valid_config(N, num_q, num_p, dnum)) {
        asm_code << "        // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
        return asm_code.str();
    }

    asm_code << "        /* CIPHERTEXT MULTIPLY: ctA(2) * ctB(2) -> ctOut(2) with relinearization */\n";
    asm_code << generate_basis_ntt_body_asm(N, num_q, 2, "ctA");
    asm_code << generate_basis_ntt_body_asm(N, num_q, 2, "ctB");
    asm_code << "        /* --- Tensor product in NTT domain: (a0,a1)*(b0,b1)->(t0,t1,t2) --- */\n";
    asm_code << generate_hpu_cmult_body_asm(num_q, false);
    asm_code << generate_basis_intt_body_asm(N, num_q, 3, "tensor product");
    asm_code << generate_hpu_relinearization_body_asm(
        N,
        num_q,
        num_p,
        dnum,
        false);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    return asm_code.str();
}

std::string generate_hpu_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";

    if (!is_valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid config: require power-of-two N fitting 1024 lines, divisible digits, and at most 256 mod contexts\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_ciphertext_multiply_body_asm(
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
