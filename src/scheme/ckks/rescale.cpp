#include "scheme/ckks/rescale.hpp"

#include "operator/rounded_drop_last.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <cmath>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::ckks {
namespace {

bool valid_rescale_config(int num_q, int num_components)
{
    return num_q >= 2 && num_components > 0
        && hpu::has_mod_context_capacity(num_q);
}

std::string transform_components(
    int N,
    int basis_count,
    int component_count,
    bool inverse,
    const char* label)
{
    constexpr int polynomial_object = 0;
    constexpr int twiddle_object = 3;
    std::ostringstream asm_code;
    asm_code << "        /* --- " << label << " --- */\n";
    for (int component = 0; component < component_count; ++component) {
        for (int basis = 0; basis < basis_count; ++basis) {
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(polynomial_object, hpu::DataType::poly);
            asm_code << (inverse
                ? generate_hpu_intt_body_asm(
                    N, polynomial_object, twiddle_object, false)
                : generate_hpu_ntt_body_asm(
                    N, polynomial_object, twiddle_object, false));
            asm_code << hpu::dstore(polynomial_object, 1);
        }
    }
    return asm_code.str();
}

} // namespace

std::string generate_rescale_body_asm(
    int num_q,
    int num_components,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_rescale_config(num_q, num_components)) {
        asm_code << "        // Invalid CKKS Rescale config: require 2 <= num_q <= 256 and num_components > 0\n";
        return asm_code.str();
    }

    asm_code << "        /* CKKS RESCALE: rounded drop-last q_" << (num_q - 1)
             << " for " << num_components << " component(s) */\n";
    asm_code << ::generate_hpu_rounded_drop_last_body_asm(
        num_q, num_components, append_psync, manage_modulus_table);
    return asm_code.str();
}

std::string generate_rescale_asm(
    int num_q,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_rescale_Q" << num_q << "_C" << num_components
             << "(void) {\n";

    if (!valid_rescale_config(num_q, num_components)) {
        asm_code << "    // Invalid CKKS Rescale config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_rescale_body_asm(
        num_q, num_components, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}

std::string generate_rescale_ntt_body_asm(
    int N,
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_rescale_config(num_q, 2) || !hpu::is_valid_ntt_size(N)) {
        asm_code << "        /* Invalid SEAL-facing CKKS Rescale config */\n";
        return asm_code.str();
    }

    constexpr int modulus_table_object = 4;
    asm_code
        << "        /* CKKS RESCALE NTT: canonical input -> rounded drop-last -> canonical output */\n";
    asm_code << hpu::dload(
        modulus_table_object,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);
    asm_code << transform_components(
        N, num_q, 2, true,
        "Input c0/c1: canonical HPU NTT -> coefficient domain");
    asm_code << generate_rescale_body_asm(num_q, 2, false, false);
    asm_code << transform_components(
        N, num_q - 1, 2, false,
        "Rescaled c0/c1: coefficient domain -> canonical HPU NTT");
    asm_code << hpu::pfree(modulus_table_object);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_rescale_ntt_asm(
    int N,
    int num_q,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_ckks_rescale_ntt_N" << N << "_Q" << num_q
             << "(void) {\n";
    if (!valid_rescale_config(num_q, 2) || !hpu::is_valid_ntt_size(N)) {
        asm_code << "    /* Invalid SEAL-facing CKKS Rescale config */\n}\n";
        return asm_code.str();
    }
    asm_code
        << "    __asm__ volatile(\n"
        << generate_rescale_ntt_body_asm(N, num_q, append_psync)
        << "        : \n"
        << "        : \n"
        << "        : \"memory\"\n"
        << "    );\n"
        << "}\n";
    return asm_code.str();
}

double rescale_scale(double scale, std::uint64_t q_last)
{
    if (!std::isfinite(scale) || scale <= 0.0 || q_last == 0) {
        throw std::invalid_argument("CKKS scale and q_last must be positive");
    }
    return scale / static_cast<double>(q_last);
}

} // namespace hpu::scheme::ckks
