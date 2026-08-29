#include "scheme/bgv/modswitch.hpp"

#include "util/bconv.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <sstream>
#include <stdexcept>
#include <vector>

namespace hpu::scheme::bgv {
namespace {

bool valid_config(int num_q, int num_p, int num_components)
{
    return num_q >= 2 && num_components > 0
        && hpu::has_mod_context_capacity(num_q, num_p, 1);
}

std::uint64_t inverse_mod(std::uint64_t value, std::uint64_t modulus)
{
    using I128 = __int128;
    I128 t = 0;
    I128 new_t = 1;
    I128 r = static_cast<I128>(modulus);
    I128 new_r = static_cast<I128>(value % modulus);
    while (new_r != 0) {
        const I128 quotient = r / new_r;
        const I128 old_t = t;
        t = new_t;
        new_t = old_t - quotient * new_t;
        const I128 old_r = r;
        r = new_r;
        new_r = old_r - quotient * new_r;
    }
    if (r != 1) {
        throw std::invalid_argument("BGV q_last is not invertible modulo t");
    }
    t %= static_cast<I128>(modulus);
    if (t < 0) {
        t += static_cast<I128>(modulus);
    }
    return static_cast<std::uint64_t>(t);
}

} // namespace

std::string generate_modswitch_body_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q, num_p, num_components)) {
        asm_code << "        // Invalid BGV ModSwitch config: require num_q >= 2, components > 0, and Q|P|t within 256 contexts\n";
        return asm_code.str();
    }

    const int dropped_context = num_q - 1;
    const int t_context = num_q + num_p;
    std::vector<int> retained_contexts;
    retained_contexts.reserve(static_cast<std::size_t>(num_q - 1));
    for (int i = 0; i < dropped_context; ++i) {
        retained_contexts.push_back(i);
    }

    const int POBJ_VALUE = 0;
    const int POBJ_CORRECTION = 1;
    const int POBJ_U = 2;
    const int POBJ_SCALAR = 3;
    const int POBJ_MOD_CTX = 4;

    asm_code << "        /* BGV MODSWITCH: coefficient/Q -> coefficient/Q_without_last */\n";
    asm_code << "        /* MOD_ID layout: Q[0.." << dropped_context << "], P["
             << num_q << ".." << (num_q + num_p - 1) << "], t=" << t_context << ". */\n";
    asm_code << "        /* Formula: u=-c_last*q_last^-1 mod t; c_i'=(c_i-c_last-q_last*u)*q_last^-1 mod q_i. */\n";

    for (int component = 0; component < num_components; ++component) {
        asm_code << "        /* BGV MODSWITCH component " << component << " */\n";

        asm_code << "        /* stage-1: exact single-source BConv q_last -> t */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            {dropped_context}, {t_context}, false);

        asm_code << "        /* stage-2: u = -c_last * q_last^-1 mod t */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        asm_code << hpu::pmodld(t_context);
        asm_code << "        // dload zero, BConv(c_last mod t), and q_last^-1 mod t\n";
        asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_CORRECTION, hpu::DataType::poly);
        asm_code << hpu::dload(POBJ_SCALAR, hpu::DataType::poly);
        asm_code << hpu::psub(POBJ_VALUE, POBJ_VALUE, POBJ_CORRECTION);
        asm_code << hpu::pfree(POBJ_CORRECTION);
        asm_code << hpu::pmul(POBJ_VALUE, POBJ_VALUE, POBJ_SCALAR);
        asm_code << hpu::pfree(POBJ_SCALAR);
        asm_code << hpu::dstore(POBJ_VALUE, 1);
        asm_code << hpu::pfree(POBJ_MOD_CTX);

        asm_code << "        /* stage-3a: exact single-source BConv c_last: q_last -> Q' */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            {dropped_context}, retained_contexts, false);
        asm_code << "        /* stage-3b: exact single-source BConv u: t -> Q' */\n";
        asm_code << ::generate_hpu_bconv_contexts_body_asm(
            {t_context}, retained_contexts, false);

        asm_code << "        /* stage-4: subtract correction and divide by q_last in Q' */\n";
        asm_code << hpu::dload(
            POBJ_MOD_CTX, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        for (int i = 0; i < dropped_context; ++i) {
            asm_code << "        /* component " << component << ", q_" << i << " */\n";
            asm_code << hpu::pmodld(i);
            asm_code << "        // dload c_i, c_last mod q_i, u mod q_i, q_last mod q_i\n";
            asm_code << hpu::dload(POBJ_VALUE, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_CORRECTION, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_U, hpu::DataType::poly);
            asm_code << hpu::dload(POBJ_SCALAR, hpu::DataType::poly);
            asm_code << hpu::pmul(POBJ_U, POBJ_U, POBJ_SCALAR);
            asm_code << hpu::pfree(POBJ_SCALAR);
            asm_code << hpu::padd(POBJ_CORRECTION, POBJ_CORRECTION, POBJ_U);
            asm_code << hpu::pfree(POBJ_U);
            asm_code << hpu::psub(POBJ_VALUE, POBJ_VALUE, POBJ_CORRECTION);
            asm_code << hpu::pfree(POBJ_CORRECTION);
            asm_code << "        // dload q_last^-1 mod q_i and write c_i'\n";
            asm_code << hpu::dload(POBJ_SCALAR, hpu::DataType::poly);
            asm_code << hpu::pmul(POBJ_VALUE, POBJ_VALUE, POBJ_SCALAR);
            asm_code << hpu::pfree(POBJ_SCALAR);
            asm_code << hpu::dstore(POBJ_VALUE, 1);
        }
        asm_code << hpu::pfree(POBJ_MOD_CTX);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_modswitch_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bgv_modswitch_Q" << num_q << "_P" << num_p
             << "_C" << num_components << "(void) {\n";
    if (!valid_config(num_q, num_p, num_components)) {
        asm_code << "    // Invalid BGV ModSwitch config\n}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_modswitch_body_asm(
        num_q, num_p, num_components, append_psync);
    asm_code << "        : \n"
             << "        : \n"
             << "        : \"memory\"\n"
             << "    );\n"
             << "}\n";
    return asm_code.str();
}

std::uint64_t modswitch_correction_factor(
    std::uint64_t factor,
    std::uint64_t q_last,
    std::uint64_t plaintext_modulus)
{
    if (plaintext_modulus < 2) {
        throw std::invalid_argument("BGV plaintext modulus must be at least 2");
    }
    const std::uint64_t inverse = inverse_mod(q_last, plaintext_modulus);
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(factor % plaintext_modulus) * inverse)
        % plaintext_modulus);
}

} // namespace hpu::scheme::bgv
