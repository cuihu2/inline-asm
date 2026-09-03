#include "scheme/ckks/relinearize.hpp"

#include "operator/relinearization.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <sstream>

namespace hpu::scheme::ckks {
namespace {

constexpr int kPolynomialObject = 0;
constexpr int kTwiddleObject = 3;
constexpr int kModulusTableObject = 4;

std::string transform(
    int N,
    const std::vector<int>& q_contexts,
    int components,
    bool inverse,
    const char* label)
{
    std::ostringstream asm_code;
    asm_code << "        /* --- " << label << " --- */\n";
    for (int component = 0; component < components; ++component) {
        for (int context : q_contexts) {
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(kPolynomialObject, hpu::DataType::poly);
            asm_code << (inverse
                ? generate_hpu_intt_body_asm(
                    N, kPolynomialObject, kTwiddleObject, false)
                : generate_hpu_ntt_body_asm(
                    N, kPolynomialObject, kTwiddleObject, false));
            asm_code << hpu::dstore(kPolynomialObject, 1);
        }
    }
    return asm_code.str();
}

bool valid_config(int N, int num_q, int num_p, int dnum)
{
    return hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum);
}

} // namespace

std::string generate_relinearize_ntt_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!hpu::is_valid_rns_decomposition_layout(N, layout)) {
        asm_code << "        /* Invalid SEAL-facing CKKS Relinearize config */\n";
        return asm_code.str();
    }

    asm_code
        << "        /* CKKS RELINEARIZE NTT: tensor NTT/Q -> ciphertext NTT/Q */\n";
    asm_code << hpu::dload(
        kModulusTableObject,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);
    asm_code << transform(
        N, layout.q_mod_ids, 3, true,
        "Tensor t0/t1/t2: canonical HPU NTT -> coefficient domain");
    asm_code << ::generate_hpu_relinearization_body_asm(
        N, layout, false, false);
    asm_code << transform(
        N, layout.q_mod_ids, 2, false,
        "Relinearized c0/c1: coefficient domain -> canonical HPU NTT");
    asm_code << hpu::pfree(kModulusTableObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_relinearize_ntt_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    if (!valid_config(N, num_q, num_p, dnum)) {
        return "        /* Invalid SEAL-facing CKKS Relinearize config */\n";
    }
    return generate_relinearize_ntt_body_asm(
        N,
        hpu::make_contiguous_rns_decomposition_layout(num_q, num_p, dnum),
        append_psync);
}

std::string generate_relinearize_ntt_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_relinearize_ntt_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    /* Invalid SEAL-facing CKKS Relinearize config */\n}\n";
        return asm_code.str();
    }
    asm_code
        << "    __asm__ volatile(\n"
        << generate_relinearize_ntt_body_asm(
            N, num_q, num_p, dnum, append_psync)
        << "        : \n"
        << "        : \n"
        << "        : \"memory\"\n"
        << "    );\n"
        << "}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::ckks
