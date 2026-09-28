#include "scheme/bgv/ciphertext_multiply.hpp"

#include "operator/ciphertext_multiply.hpp"
#include "poly/cmult.hpp"
#include "scheme/bgv/keyswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <stdexcept>

namespace hpu::scheme::bgv {
namespace {

bool valid_config(int N, int num_q, int num_p, int dnum)
{
    return num_q >= 2
        && hpu::is_valid_rns_decomposition_config(
            N, num_q, num_p, dnum, 1);
}

} // namespace

std::string generate_ciphertext_multiply_ntt_body_asm(
    int N, const hpu::RnsDecompositionLayout& layout, int plaintext_mod_id,
    bool append_psync, bool manage_modulus_table)
{
    bool prefix_q = true;
    for (std::size_t index = 0; index < layout.q_mod_ids.size(); ++index) {
        prefix_q = prefix_q && layout.q_mod_ids[index] == static_cast<int>(index);
    }
    if (!hpu::is_seal_single_p_rns_decomposition_layout(N, layout) ||
        !prefix_q || plaintext_mod_id < 0 ||
        plaintext_mod_id >= hpu::kMaxModContexts ||
        plaintext_mod_id == layout.p_mod_ids.front()) {
        return "        /* Invalid SEAL-facing BGV NTT Multiply layout */\n";
    }
    for (int q_id : layout.q_mod_ids) {
        if (q_id == plaintext_mod_id) {
            return "        /* Invalid SEAL-facing BGV NTT Multiply t MOD_ID */\n";
        }
    }
    std::ostringstream asm_code;
    asm_code << "        /* BGV MULTIPLY NTT: tensor -> BGV special-P KeySwitch */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(4, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    asm_code << ::generate_hpu_cmult_body_asm(
        static_cast<int>(layout.q_mod_ids.size()), false, false);
    asm_code << generate_keyswitch_ntt_body_asm(
        N, layout, plaintext_mod_id, false, false);
    if (manage_modulus_table) asm_code << hpu::pfree(4);
    if (append_psync) asm_code << hpu::psync();
    return asm_code.str();
}

std::string generate_ciphertext_multiply_body_asm(
    int N,
    int num_q,
    int num_p,
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "        // Invalid BGV multiply config: reserve Q|P|t contexts and require a valid common multiply configuration\n";
        return asm_code.str();
    }

    asm_code << "        /* BGV MULTIPLY: common tensor product and relinearization */\n";
    asm_code << "        /* Software metadata: correction_factor_out = factor_a * factor_b mod t. */\n";
    asm_code << ::generate_hpu_ciphertext_multiply_body_asm(
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
    int dnum,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bgv_ciphertext_multiply_N" << N << "_Q" << num_q
             << "_P" << num_p << "_D" << dnum << "(void) {\n";
    if (!valid_config(N, num_q, num_p, dnum)) {
        asm_code << "    // Invalid BGV multiply config\n}\n";
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

std::uint64_t multiply_correction_factor(
    std::uint64_t factor_a,
    std::uint64_t factor_b,
    std::uint64_t plaintext_modulus)
{
    if (plaintext_modulus < 2) {
        throw std::invalid_argument("BGV plaintext modulus must be at least 2");
    }
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(factor_a % plaintext_modulus)
         * (factor_b % plaintext_modulus))
        % plaintext_modulus);
}

} // namespace hpu::scheme::bgv
