#include "operator/plaintext_ntt.hpp"

#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"

#include <sstream>

namespace {

bool is_power_of_two(int value)
{
    return value > 0 && (value & (value - 1)) == 0;
}

bool valid_plaintext_ntt_config(int N, int num_q)
{
    return is_power_of_two(N)
        && hpu::fits_ntt_object(N)
        && num_q > 0
        && num_q <= hpu::kMaxModContexts;
}

} // namespace

std::string generate_plaintext_ntt_body_asm(
    int N,
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_plaintext_ntt_config(N, num_q)) {
        asm_code << "        // Invalid plaintext NTT config: require supported power-of-two N and 1 <= num_q <= 256\n";
        return asm_code.str();
    }

    constexpr int kPlaintextObject = 0;
    constexpr int kTwiddleObject = 3;
    constexpr int kModContextObject = 4;

    asm_code << "        /* PLAINTEXT NTT BACKEND: coefficient RNS-Q -> NTT RNS-Q */\n";
    asm_code << hpu::dload(
        kModContextObject, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);

    for (int basis = 0; basis < num_q; ++basis) {
        asm_code << "        /* q_" << basis
                 << ": load host-encoded coefficient limb and run negacyclic NTT */\n";
        asm_code << hpu::pmodld(basis);
        asm_code << hpu::dload(kPlaintextObject, hpu::DataType::poly);
        asm_code << generate_hpu_ntt_body_asm(
            N, kPlaintextObject, kTwiddleObject, false);
        asm_code << hpu::dstore(kPlaintextObject, 1);
    }

    asm_code << hpu::pfree(kModContextObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

