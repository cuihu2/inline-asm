#include "scheme/bfv/ciphertext_multiply.hpp"

#include "operator/relinearization.hpp"
#include "util/bconv.hpp"
#include "util/hpu_asm.hpp"
#include "util/mm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace hpu::scheme::bfv {
namespace {

bool valid_behz_config(
    int N, int num_q, int num_p, int num_b, std::uint64_t t)
{
    return hpu::is_valid_ntt_size(N)
        && num_q >= 2 && num_p > 0 && num_b >= num_q
        && t >= 65537 && t <= std::numeric_limits<std::uint32_t>::max()
        && hpu::is_prime(t)
        && (t - 1) % static_cast<std::uint64_t>(2 * N) == 0
        && hpu::has_mod_context_capacity(num_q, num_p + num_b, 2);
}

bool valid_ciphertext_multiply_config(
    int N,
    int num_q,
    int num_p,
    int num_b,
    int dnum,
    std::uint64_t t)
{
    return valid_behz_config(N, num_q, num_p, num_b, t)
        && hpu::is_valid_rns_decomposition_config(
            N, num_q, num_p, dnum);
}

std::vector<int> make_contexts(int begin, int count)
{
    std::vector<int> contexts;
    contexts.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        contexts.push_back(begin + i);
    }
    return contexts;
}

std::string generate_basis_transform_body_asm(
    int N,
    const std::vector<int>& contexts,
    int num_components,
    bool inverse,
    const std::string& label)
{
    std::ostringstream asm_code;
    constexpr int POBJ_POLY = 0;
    constexpr int POBJ_TWIDDLE = 3;
    constexpr int POBJ_MOD_CTX = 4;

    asm_code << "        /* " << label << (inverse ? ": INTT */\n" : ": NTT */\n");
    asm_code << hpu::dload(
        POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    for (int component = 0; component < num_components; ++component) {
        for (int context : contexts) {
            asm_code << "        /* component " << component
                     << ", MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_POLY, hpu::DataType::poly);
            asm_code << (inverse
                ? ::generate_hpu_intt_body_asm(
                      N, POBJ_POLY, POBJ_TWIDDLE, false)
                : ::generate_hpu_ntt_body_asm(
                      N, POBJ_POLY, POBJ_TWIDDLE, false));
            asm_code << hpu::dstore(POBJ_POLY, 1);
        }
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX);
    return asm_code.str();
}

std::string generate_tensor_body_asm(
    const std::vector<int>& contexts,
    const std::string& label)
{
    std::ostringstream asm_code;
    constexpr int POBJ_A = 0;
    constexpr int POBJ_B = 1;
    constexpr int POBJ_OUT = 2;
    constexpr int POBJ_MOD_CTX = 4;

    asm_code << "        /* " << label
             << ": (a0,a1)*(b0,b1) -> (t0,t1,t2) */\n";
    asm_code << hpu::dload(
        POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    for (int context : contexts) {
        asm_code << hpu::pmodld(context);

        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly);
        asm_code << ::generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A) << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1);

        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly);
        asm_code << ::generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A) << hpu::pfree(POBJ_B);
        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly);
        asm_code << hpu::pmac(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A) << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1);

        asm_code << hpu::dload(POBJ_A, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_B, hpu::DataType::poly);
        asm_code << ::generate_hpu_mm_body_asm(POBJ_OUT, POBJ_A, POBJ_B);
        asm_code << hpu::pfree(POBJ_A) << hpu::pfree(POBJ_B);
        asm_code << hpu::dstore(POBJ_OUT, 1);
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX);
    return asm_code.str();
}

std::string generate_scalar_multiply_body_asm(
    const std::vector<int>& contexts,
    int num_components,
    const std::string& label)
{
    std::ostringstream asm_code;
    constexpr int POBJ_VALUE = 0;
    constexpr int POBJ_SCALAR = 1;
    constexpr int POBJ_MOD_CTX = 4;

    asm_code << "        /* " << label << " */\n";
    asm_code << hpu::dload(
        POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    for (int component = 0; component < num_components; ++component) {
        for (int context : contexts) {
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_SCALAR, hpu::DataType::poly);
            asm_code << hpu::pmul(POBJ_VALUE, POBJ_VALUE, POBJ_SCALAR);
            asm_code << hpu::pfree(POBJ_SCALAR);
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
    }
    asm_code << hpu::pfree(POBJ_MOD_CTX);
    return asm_code.str();
}

std::string generate_fast_floor_body_asm(
    const std::vector<int>& q_contexts,
    const std::vector<int>& bsk_contexts,
    int num_components)
{
    std::ostringstream asm_code;
    constexpr int POBJ_VALUE = 0;
    constexpr int POBJ_CONVERTED = 1;
    constexpr int POBJ_Q_INV = 2;
    constexpr int POBJ_MOD_CTX = 4;

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* FastFloor component " << component
                 << ": FastConv(Q->Bsk), subtract, multiply Q^-1 */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            q_contexts, bsk_contexts, false);
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        for (int context : bsk_contexts) {
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_CONVERTED, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_Q_INV, hpu::DataType::poly);
            asm_code << hpu::psub(
                POBJ_VALUE, POBJ_VALUE, POBJ_CONVERTED);
            asm_code << hpu::pfree(POBJ_CONVERTED);
            asm_code << hpu::pmul(POBJ_VALUE, POBJ_VALUE, POBJ_Q_INV);
            asm_code << hpu::pfree(POBJ_Q_INV);
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }
    return asm_code.str();
}

std::string generate_branchless_sk_body_asm(
    const std::vector<int>& q_contexts,
    const std::vector<int>& b_contexts,
    int msk_context,
    int num_components)
{
    std::ostringstream asm_code;
    constexpr int POBJ_ALPHA = 0;
    constexpr int POBJ_FACTOR = 1;
    constexpr int POBJ_DEST = 2;
    constexpr int POBJ_MOD_CTX = 4;

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* branchless SK component " << component << " */\n";
        asm_code << "        /* y = FastConv(B->Q) */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            b_contexts, q_contexts, false);
        asm_code << "        /* temp = FastConv(B->m_sk) */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            b_contexts, {msk_context}, false);

        asm_code << "        /* alpha=(temp-z_msk)*B^-1 mod m_sk */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        asm_code << hpu::pmodld(msk_context);
        asm_code << hpu::dload(POBJ_ALPHA, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_FACTOR, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_DEST, hpu::DataType::poly);
        asm_code << hpu::psub(POBJ_ALPHA, POBJ_ALPHA, POBJ_FACTOR);
        asm_code << hpu::pfree(POBJ_FACTOR);
        asm_code << hpu::pmul(POBJ_ALPHA, POBJ_ALPHA, POBJ_DEST);
        asm_code << hpu::pfree(POBJ_DEST);
        asm_code << hpu::dstore(POBJ_ALPHA, 1);
        asm_code << hpu::pfree(POBJ_MOD_CTX);

        asm_code << "        /* broadcast alpha: {m_sk}->Q */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            {msk_context}, q_contexts, false);

        asm_code << "        /* out_i=y_i+alpha*(-B mod q_i) */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        for (int context : q_contexts) {
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(POBJ_DEST, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_ALPHA, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_FACTOR, hpu::DataType::poly);
            asm_code << hpu::pmac(POBJ_DEST, POBJ_ALPHA, POBJ_FACTOR);
            asm_code << hpu::pfree(POBJ_ALPHA);
            asm_code << hpu::pfree(POBJ_FACTOR);
            asm_code << hpu::dstore(POBJ_DEST, 1);
        }
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }
    return asm_code.str();
}

} // namespace

std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int num_b,
    int dnum,
    std::uint64_t plaintext_modulus,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_ciphertext_multiply_config(
            N, num_q, num_p, num_b, dnum, plaintext_modulus)) {
        asm_code << "        // Invalid BFV ciphertext multiply config: require valid N, Q/P/B/dnum, batching t, and MOD_ID capacity\n";
        return asm_code.str();
    }

    const std::vector<int> q_contexts = make_contexts(0, num_q);
    const std::vector<int> b_contexts = make_contexts(
        num_q + num_p, num_b);
    std::vector<int> bsk_contexts = b_contexts;
    const int msk_context = num_q + num_p + num_b;
    const int t_context = msk_context + 1;
    bsk_contexts.push_back(msk_context);

    asm_code << "        /* BFV BEHZ MULTIPLY: comparison-free no-SMRQ + branchless-SK */\n";
    asm_code << "        /* MOD_ID: Q[0.." << (num_q - 1) << "], Pks["
             << num_q << ".." << (num_q + num_p - 1) << "], B["
             << (num_q + num_p) << ".." << (msk_context - 1)
             << "], m_sk=" << msk_context << ", t=" << t_context << ". */\n";

    for (int component = 0; component < 4; ++component) {
        asm_code << "        /* input component " << component
                 << ": unreduced FastBConv Q->Bsk; no m_tilde/SmMRq */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            q_contexts, bsk_contexts, false);
    }
    asm_code << generate_basis_transform_body_asm(
        N, q_contexts, 4, false, "input Q");
    asm_code << generate_basis_transform_body_asm(
        N, bsk_contexts, 4, false, "input Bsk");
    asm_code << generate_tensor_body_asm(q_contexts, "tensor Q");
    asm_code << generate_tensor_body_asm(bsk_contexts, "tensor Bsk");
    asm_code << generate_basis_transform_body_asm(
        N, q_contexts, 3, true, "tensor Q");
    asm_code << generate_basis_transform_body_asm(
        N, bsk_contexts, 3, true, "tensor Bsk");

    std::vector<int> q_bsk_contexts = q_contexts;
    q_bsk_contexts.insert(
        q_bsk_contexts.end(), bsk_contexts.begin(), bsk_contexts.end());
    asm_code << generate_scalar_multiply_body_asm(
        q_bsk_contexts, 3, "multiply every Q union Bsk limb by plaintext modulus t");
    asm_code << generate_fast_floor_body_asm(
        q_contexts, bsk_contexts, 3);
    asm_code << generate_branchless_sk_body_asm(
        q_contexts, b_contexts, msk_context, 3);

    asm_code << "        /* BFV RELINEARIZATION: consume phase-local (t0,t1,t2)_Q without host synchronization */\n";
    asm_code << ::generate_hpu_relinearization_body_asm(
        N, num_q, num_p, dnum, false);

    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int num_b,
    int dnum,
    std::uint64_t plaintext_modulus,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bfv_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_B" << num_b << "_D" << dnum
             << "(void) {\n";
    if (!valid_ciphertext_multiply_config(
            N, num_q, num_p, num_b, dnum, plaintext_modulus)) {
        asm_code << "    // Invalid BFV ciphertext multiply config\n}\n";
        return asm_code.str();
    }
    asm_code << "    __asm__ volatile(\n"
             << generate_ciphertext_multiply_body_asm(
                    N, num_q, num_p, num_b,
                    dnum, plaintext_modulus, append_psync)
             << "        : \n        : \n        : \"memory\"\n    );\n}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::bfv
