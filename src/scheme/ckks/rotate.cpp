#include "scheme/ckks/rotate.hpp"

#include "operator/keyswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <numeric>
#include <sstream>

namespace hpu::scheme::ckks {
namespace {

constexpr int kPolynomialObject = 0;
constexpr int kTwiddleObject = 3;
constexpr int kModulusTableObject = 4;

bool valid_config(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    std::uint32_t galois_element)
{
    const std::uint64_t ring_order = 2ULL * static_cast<std::uint64_t>(N);
    return hpu::is_valid_rns_decomposition_layout(N, layout)
        && galois_element < ring_order
        && std::gcd<std::uint64_t>(galois_element, ring_order) == 1;
}

std::string generate_fused_inverse_body_asm(
    int N,
    const std::vector<int>& q_contexts,
    std::uint32_t galois_element)
{
    std::ostringstream asm_code;
    asm_code
        << "        /* --- FUSED AUTO: NTT_psi -> INTT_psi^(1/k) -> sigma_k(coeff) --- */\n"
        << "        /* p3 binds modified-root INTT tables; k="
        << galois_element << ". */\n";
    for (int component = 0; component < 2; ++component) {
        for (int context : q_contexts) {
            asm_code << "        /* fused component_" << component
                     << ", q MOD_ID " << context << ", key_domain="
                     << galois_element << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(kPolynomialObject, hpu::DataType::poly);
            asm_code << generate_hpu_intt_body_asm(
                N, kPolynomialObject, kTwiddleObject, false);
            asm_code << hpu::dstore(kPolynomialObject, 1);
        }
    }
    return asm_code.str();
}

std::string generate_output_ntt_body_asm(
    int N,
    const std::vector<int>& q_contexts)
{
    std::ostringstream asm_code;
    asm_code
        << "        /* --- Canonical output NTT after Galois KeySwitch --- */\n";
    for (int component = 0; component < 2; ++component) {
        for (int context : q_contexts) {
            asm_code << "        /* output component_" << component
                     << ", q MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(kPolynomialObject, hpu::DataType::poly);
            asm_code << generate_hpu_ntt_body_asm(
                N, kPolynomialObject, kTwiddleObject, false);
            asm_code << hpu::dstore(kPolynomialObject, 1);
        }
    }
    return asm_code.str();
}

} // namespace

std::string generate_rotate_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    std::uint32_t galois_element,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(N, layout, galois_element)) {
        asm_code << "        /* Invalid CKKS Rotate config */\n";
        return asm_code.str();
    }

    asm_code
        << "        /* CKKS ROTATE: fused automorphism + Galois KeySwitch */\n"
        << "        /* Input/output: canonical HPU NTT; no coefficient permutation. */\n";
    asm_code << hpu::dload(
        kModulusTableObject,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);

    // Completing the modified-root INTT leaves ordinary coefficient data in
    // key domain sigma_k(s). Only {domain=coefficient,key_domain=k} needs to
    // cross a kernel boundary if the two phases are scheduled separately.
    asm_code << generate_fused_inverse_body_asm(
        N, layout.q_mod_ids, galois_element);
    asm_code
        << "        /* --- Galois KeySwitch: key_domain k -> canonical secret-key domain --- */\n";
    asm_code << ::generate_hpu_keyswitch_body_asm(
        N, layout, false, false);
    asm_code << generate_output_ntt_body_asm(N, layout.q_mod_ids);

    asm_code << hpu::pfree(kModulusTableObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_rotate_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    std::uint32_t galois_element,
    bool append_psync)
{
    const auto layout = hpu::make_contiguous_rns_decomposition_layout(
        num_q, num_p, dnum);
    if (!valid_config(N, layout, galois_element)) {
        return "        /* Invalid CKKS Rotate config */\n";
    }
    return generate_rotate_body_asm(
        N, layout, galois_element, append_psync);
}

std::string generate_rotate_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    std::uint32_t galois_element,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_rotate_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "_K"
             << galois_element << "(void) {\n";
    if (!valid_config(
            N,
            hpu::make_contiguous_rns_decomposition_layout(
                num_q, num_p, dnum),
            galois_element)) {
        asm_code << "    /* Invalid CKKS Rotate config */\n}\n";
        return asm_code.str();
    }
    asm_code
        << "    __asm__ volatile(\n"
        << generate_rotate_body_asm(
            N, num_q, num_p, dnum, galois_element, append_psync)
        << "        : \n"
        << "        : \n"
        << "        : \"memory\"\n"
        << "    );\n"
        << "}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::ckks
