#include "scheme/bfv/basic_arithmetic.hpp"

#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <sstream>

namespace hpu::scheme::bfv {
namespace {

constexpr int kLeftObject = 0;
constexpr int kRightObject = 1;
constexpr int kOutputObject = 2;
constexpr int kModulusTableObject = 4;

bool valid_config(int num_q)
{
    return num_q > 0 && hpu::has_mod_context_capacity(num_q);
}

std::string generate_ciphertext_binary_body(int num_q, bool subtract, bool append_psync,
                                            bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid BFV ciphertext binary config */\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV " << (subtract ? "SUB" : "ADD")
             << ": coefficient-domain Q ciphertext operation */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            asm_code << "        /* component_" << component << ", q_" << basis << " */\n";
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
            asm_code << hpu::dload(kRightObject, hpu::DataType::poly);
            asm_code << (subtract ? hpu::psub(kOutputObject, kLeftObject, kRightObject)
                                  : hpu::padd(kOutputObject, kLeftObject, kRightObject));
            asm_code << hpu::pfree(kLeftObject);
            asm_code << hpu::pfree(kRightObject);
            asm_code << hpu::dstore(kOutputObject, 1);
        }
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_plain_binary_body(int num_q, bool subtract, bool append_psync,
                                       bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid BFV plaintext binary config */\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV " << (subtract ? "SUB_PLAIN" : "ADD_PLAIN")
             << ": update coefficient-domain c0 with prepared Delta*m; copy c1 */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int basis = 0; basis < num_q; ++basis) {
        asm_code << "        /* q_" << basis << ": out0=c0 op prepared_plaintext */\n";
        asm_code << hpu::pmodld(basis);
        asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
        asm_code << hpu::dload(kRightObject, hpu::DataType::poly);
        asm_code << (subtract ? hpu::psub(kOutputObject, kLeftObject, kRightObject)
                              : hpu::padd(kOutputObject, kLeftObject, kRightObject));
        asm_code << hpu::pfree(kLeftObject);
        asm_code << hpu::pfree(kRightObject);
        asm_code << hpu::dstore(kOutputObject, 1);

        asm_code << "        /* q_" << basis << ": out1=c1 */\n";
        asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
        asm_code << hpu::dstore(kLeftObject, 1);
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

} // namespace

std::string generate_add_body_asm(int num_q, bool append_psync, bool manage_modulus_table)
{
    return generate_ciphertext_binary_body(num_q, false, append_psync, manage_modulus_table);
}

std::string generate_subtract_body_asm(int num_q, bool append_psync, bool manage_modulus_table)
{
    return generate_ciphertext_binary_body(num_q, true, append_psync, manage_modulus_table);
}

std::string generate_add_plain_body_asm(int num_q, bool append_psync, bool manage_modulus_table)
{
    return generate_plain_binary_body(num_q, false, append_psync, manage_modulus_table);
}

std::string generate_subtract_plain_body_asm(int num_q, bool append_psync,
                                             bool manage_modulus_table)
{
    return generate_plain_binary_body(num_q, true, append_psync, manage_modulus_table);
}

std::string generate_multiply_plain_body_asm(int N, int num_q, bool append_psync,
                                             bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q) || !hpu::is_valid_ntt_size(N)) {
        asm_code << "        /* Invalid BFV MultiplyPlain config */\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV MULTIPLY_PLAIN: coefficient ciphertext -> canonical HPU "
                "NTT -> pointwise multiply -> coefficient output */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            asm_code << "        /* component_" << component << ", q_" << basis << " */\n";
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
            asm_code << ::generate_hpu_ntt_body_asm(N, kLeftObject, 3, false);
            asm_code << hpu::dload(kRightObject, hpu::DataType::poly);
            asm_code << hpu::pmul(kLeftObject, kLeftObject, kRightObject);
            asm_code << hpu::pfree(kRightObject);
            asm_code << ::generate_hpu_intt_body_asm(N, kLeftObject, 3, false);
            asm_code << hpu::dstore(kLeftObject, 1);
        }
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_negate_body_asm(int num_q, bool append_psync, bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid BFV Negate config */\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV NEGATE: coefficient-domain out=(c-c)-c */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            asm_code << "        /* component_" << component << ", q_" << basis << " */\n";
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
            asm_code << hpu::psub(kOutputObject, kLeftObject, kLeftObject);
            asm_code << hpu::psub(kOutputObject, kOutputObject, kLeftObject);
            asm_code << hpu::pfree(kLeftObject);
            asm_code << hpu::dstore(kOutputObject, 1);
        }
    }
    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

} // namespace hpu::scheme::bfv
