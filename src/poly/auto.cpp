#include "poly/auto.hpp"
#include "operator/keyswitch.hpp"
#include "util/galois.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <string>

std::string generate_hpu_auto_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    std::uint64_t galois_element,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum)) {
        return "";
    }

    if (!hpu::is_valid_galois_element(
            static_cast<std::size_t>(N), galois_element)) {
        asm_code << "        // Invalid AUTO Galois element: require 1 <= g < 2N and gcd(g, 2N) = 1\n";
        return asm_code.str();
    }

    constexpr int kDataObject = 0;
    constexpr int kTwiddleObject = 3;
    constexpr int kModContextObject = 4;

    asm_code << "        /* AUTO g=" << galois_element
             << ": HPU applies sigma_g with an INTT profile rooted at psi^(g^-1). */\n";
    asm_code << "        /* Step 0: sigma_g(ci) = INTT_(psi^(g^-1))(NTT_psi(ci)), i=0,1. */\n";
    asm_code << hpu::dload(kModContextObject, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            asm_code << "        /* Transform c" << component
                     << " in Q context " << basis << ". */\n";
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(kDataObject, hpu::DataType::poly);
            asm_code << "        /* Forward loads use the standard ntt profile. */\n";
            asm_code << generate_hpu_ntt_body_asm(
                N, kDataObject, kTwiddleObject, false);
            asm_code << "        /* Runtime binds inverse loads to auto_intt_g"
                     << galois_element << ". */\n";
            asm_code << generate_hpu_intt_body_asm(
                N, kDataObject, kTwiddleObject, false);
            asm_code << hpu::dstore(kDataObject, 1);
        }
    }
    asm_code << hpu::pfree(kModContextObject);

    asm_code << "        /* Steps 1..6: ordinary hybrid KeySwitch of sigma_g(c1). */\n";
    asm_code << "        /* All KeySwitch NTT/INTT loads below use standard profiles. */\n";
    asm_code << generate_hpu_keyswitch_body_asm(
        N, num_q, num_p, dnum, append_psync);

    return asm_code.str();
}

std::string generate_hpu_auto_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    std::uint64_t galois_element,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_auto_N" << N << "_Q" << num_q << "_P" << num_p
             << "_D" << dnum << "_G" << galois_element << "(void) {\n";

    if (!hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum)
        || !hpu::is_valid_galois_element(
            static_cast<std::size_t>(N), galois_element)) {
        asm_code << "    // Invalid config: require valid RNS decomposition and g in Z_(2N)^*\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << "        /* AUTO: HPU fused automorphism NTT followed by Galois KeySwitch */\n";
    asm_code << generate_hpu_auto_body_asm(
        N, num_q, num_p, dnum, galois_element, append_psync);
    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}
