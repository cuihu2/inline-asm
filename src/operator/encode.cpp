#include "operator/encode.hpp"

#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"

#include <sstream>
#include <string>

namespace {

bool is_power_of_two(int value)
{
    return value > 0 && (value & (value - 1)) == 0;
}

bool valid_encode_config(int N, int num_q)
{
    return is_power_of_two(N)
        && hpu::fits_ntt_object(N)
        && num_q > 0
        && num_q <= hpu::kMaxModContexts;
}

} // namespace

std::string generate_hpu_encode_body_asm(
    int N,
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_encode_config(N, num_q)) {
        asm_code << "        // Invalid Encode config: require supported power-of-two N and 1 <= num_q <= 256\n";
        return asm_code.str();
    }

    const int POBJ_PLAINTEXT = 0;
    const int POBJ_TWIDDLE = 3;
    const int POBJ_MOD_CTX = 4;

    asm_code << "        /* ENCODE: host signed-to-RNS input -> NTT plaintext */\n";
    asm_code << "        /* The host supplies one coefficient-domain plaintext limb per q_i. */\n";
    asm_code << hpu::dload(
        POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);

    for (int i = 0; i < num_q; ++i) {
        asm_code << "        /* Encode q_" << i
                 << ": load embedded coefficient limb, then negacyclic NTT */\n";
        asm_code << hpu::pmodld(i);
        asm_code << hpu::dload(POBJ_PLAINTEXT, hpu::DataType::poly);
        asm_code << generate_hpu_ntt_body_asm(
            N, POBJ_PLAINTEXT, POBJ_TWIDDLE, false);
        asm_code << hpu::dstore(POBJ_PLAINTEXT, 1);
    }

    asm_code << hpu::pfree(POBJ_MOD_CTX);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_hpu_encode_asm(
    int N,
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_encode_N" << N << "_Q" << num_q << "(void) {\n";

    if (!valid_encode_config(N, num_q)) {
        asm_code << "    // Invalid Encode config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_encode_body_asm(N, num_q, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}
