#include "scheme/ckks/ciphertext_multiply.hpp"

#include "operator/relinearization.hpp"
#include "poly/cmult.hpp"
#include "scheme/ckks/rescale.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <cmath>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::ckks {
namespace {

bool valid_config(int N, int num_q, int num_p, int dnum)
{
    return num_q >= 2
        && hpu::is_valid_rns_decomposition_config(N, num_q, num_p, dnum);
}

std::string generate_basis_transform_body_asm(
    int N,
    const std::vector<int>& contexts,
    int component_count,
    bool inverse,
    const char* label)
{
    constexpr int poly_object = 0;
    constexpr int twiddle_object = 3;

    std::ostringstream asm_code;
    asm_code << "        /* --- " << label << " --- */\n";
    for (int component = 0; component < component_count; ++component) {
        for (int context : contexts) {
            asm_code << "        /* component_" << component
                     << ", MOD_ID " << context << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(poly_object, hpu::DataType::poly);
            asm_code << (inverse
                ? generate_hpu_intt_body_asm(
                    N, poly_object, twiddle_object, false)
                : generate_hpu_ntt_body_asm(
                    N, poly_object, twiddle_object, false));
            asm_code << hpu::dstore(poly_object, 1);
        }
    }
    return asm_code.str();
}

} // namespace

std::string generate_ciphertext_multiply_body_asm(
    int N,
    const hpu::RnsDecompositionLayout& layout,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    bool prefix_q = true;
    for (std::size_t index = 0; index < layout.q_mod_ids.size(); ++index) {
        prefix_q = prefix_q
            && layout.q_mod_ids[index] == static_cast<int>(index);
    }
    if (!hpu::is_valid_rns_decomposition_layout(N, layout)
        || layout.q_mod_ids.size() < 2 || !prefix_q) {
        asm_code << "        // Invalid CKKS multiply config: require N fitting one bank, num_q >= 2, divisible digits, and <= 256 contexts\n";
        return asm_code.str();
    }

    constexpr int modulus_table_object = 4;
    const int num_q = static_cast<int>(layout.q_mod_ids.size());

    asm_code
        << "        /* CKKS MULTIPLY: canonical HPU NTT inputs -> multiply, relinearize, rescale */\n"
        << "        /* Inputs are already canonical HPU NTT; no input NTT is emitted. */\n";

    // The modulus and mu table is application-lifetime state in the small
    // bank. Every nested body is told not to reload or release it.
    if (manage_modulus_table) {
        asm_code << hpu::dload(
            modulus_table_object,
            hpu::DataType::mod_ctx,
            hpu::DloadFlag::small_bank);
    }

    asm_code
        << "        /* --- Tensor product stays in the input NTT domain --- */\n";
    asm_code << ::generate_hpu_cmult_body_asm(num_q, false, false);

    // The first implementation deliberately reuses the already verified
    // coefficient-domain KeySwitch/ModDown and Rescale bodies. Therefore the
    // three tensor components cross the domain boundary exactly once here.
    asm_code << generate_basis_transform_body_asm(
        N, layout.q_mod_ids, 3, true,
        "Tensor t0/t1/t2: canonical HPU NTT -> coefficient domain");
    asm_code << ::generate_hpu_relinearization_body_asm(
        N, layout, false, false);

    // Keep Rescale independent in the generated stream. It consumes the two
    // coefficient-domain relinearization results and drops q_last.
    asm_code << "        /* --- Independent CKKS Rescale --- */\n";
    asm_code << generate_rescale_body_asm(num_q, 2, false, false);

    // SEAL CKKS ciphertexts are NTT-form objects. Only the final two outputs
    // need a forward transform, now over Q without the dropped modulus.
    std::vector<int> retained_q(
        layout.q_mod_ids.begin(), layout.q_mod_ids.end() - 1);
    asm_code << generate_basis_transform_body_asm(
        N, retained_q, 2, false,
        "Rescaled c0/c1: coefficient domain -> canonical HPU NTT");

    if (manage_modulus_table) {
        asm_code << hpu::pfree(modulus_table_object);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync,
    bool manage_modulus_table)
{
    if (!valid_config(N, num_q, num_p, dnum)) {
        return "        // Invalid CKKS multiply config: require N fitting one bank, num_q >= 2, divisible digits, and <= 256 contexts\n";
    }
    return generate_ciphertext_multiply_body_asm(
        N,
        hpu::make_contiguous_rns_decomposition_layout(num_q, num_p, dnum),
        append_psync,
        manage_modulus_table);
}

std::string generate_ciphertext_multiply_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid CKKS multiply config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_ciphertext_multiply_body_asm(
        N, num_q, num_p, dnum, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}

double multiply_scale(double scale_a, double scale_b)
{
    if (!std::isfinite(scale_a) || !std::isfinite(scale_b)
        || scale_a <= 0.0 || scale_b <= 0.0) {
        throw std::invalid_argument("CKKS input scales must be positive");
    }
    const double result = scale_a * scale_b;
    if (!std::isfinite(result)) {
        throw std::overflow_error("CKKS multiplied scale is not finite");
    }
    return result;
}

} // namespace hpu::scheme::ckks
