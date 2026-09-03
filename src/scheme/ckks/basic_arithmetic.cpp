#include "scheme/ckks/basic_arithmetic.hpp"

#include "poly/pmult.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>

namespace hpu::scheme::ckks {
namespace {

constexpr int kLeftObject = 0;
constexpr int kRightObject = 1;
constexpr int kOutputObject = 2;
constexpr int kModulusTableObject = 4;

bool valid_config(int num_q)
{
    return num_q > 0 && hpu::has_mod_context_capacity(num_q);
}

std::string generate_ciphertext_binary_body(
    int num_q,
    bool subtract,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid CKKS ciphertext binary config */\n";
        return asm_code.str();
    }
    asm_code << "        /* CKKS " << (subtract ? "SUB" : "ADD")
             << ": canonical HPU NTT/Q pointwise ciphertext operation */\n";
    asm_code << hpu::dload(
        kModulusTableObject,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);
    for (int component = 0; component < 2; ++component) {
        for (int basis = 0; basis < num_q; ++basis) {
            asm_code << "        /* component_" << component
                     << ", q_" << basis << " */\n";
            asm_code << hpu::pmodld(basis);
            asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
            asm_code << hpu::dload(kRightObject, hpu::DataType::poly);
            asm_code << (subtract
                ? hpu::psub(kOutputObject, kLeftObject, kRightObject)
                : hpu::padd(kOutputObject, kLeftObject, kRightObject));
            asm_code << hpu::pfree(kLeftObject);
            asm_code << hpu::pfree(kRightObject);
            asm_code << hpu::dstore(kOutputObject, 1);
        }
    }
    asm_code << hpu::pfree(kModulusTableObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_plain_binary_body(
    int num_q,
    bool subtract,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid CKKS plaintext binary config */\n";
        return asm_code.str();
    }
    asm_code << "        /* CKKS " << (subtract ? "SUB_PLAIN" : "ADD_PLAIN")
             << ": update c0 in canonical HPU NTT/Q; copy c1 */\n";
    asm_code << hpu::dload(
        kModulusTableObject,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);
    for (int basis = 0; basis < num_q; ++basis) {
        asm_code << "        /* q_" << basis << ": out0=c0 op plaintext */\n";
        asm_code << hpu::pmodld(basis);
        asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
        asm_code << hpu::dload(kRightObject, hpu::DataType::poly);
        asm_code << (subtract
            ? hpu::psub(kOutputObject, kLeftObject, kRightObject)
            : hpu::padd(kOutputObject, kLeftObject, kRightObject));
        asm_code << hpu::pfree(kLeftObject);
        asm_code << hpu::pfree(kRightObject);
        asm_code << hpu::dstore(kOutputObject, 1);

        // The standalone ABI materializes both output components. A runtime
        // implementing an in-place operation may alias c1 and omit this copy.
        asm_code << "        /* q_" << basis << ": out1=c1 */\n";
        asm_code << hpu::dload(kLeftObject, hpu::DataType::poly);
        asm_code << hpu::dstore(kLeftObject, 1);
    }
    asm_code << hpu::pfree(kModulusTableObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string wrap(
    const char* function,
    int num_q,
    const std::string& body,
    bool valid)
{
    std::ostringstream asm_code;
    asm_code << "void " << function << "_Q" << num_q << "(void) {\n";
    if (!valid) {
        asm_code << "    /* Invalid CKKS pointwise config */\n}\n";
        return asm_code.str();
    }
    asm_code
        << "    __asm__ volatile(\n"
        << body
        << "        : \n"
        << "        : \n"
        << "        : \"memory\"\n"
        << "    );\n"
        << "}\n";
    return asm_code.str();
}

} // namespace

std::string generate_add_body_asm(int num_q, bool append_psync)
{
    return generate_ciphertext_binary_body(num_q, false, append_psync);
}

std::string generate_subtract_body_asm(int num_q, bool append_psync)
{
    return generate_ciphertext_binary_body(num_q, true, append_psync);
}

std::string generate_multiply_plain_body_asm(int num_q, bool append_psync)
{
    std::ostringstream asm_code;
    if (!valid_config(num_q)) {
        asm_code << "        /* Invalid CKKS MultiplyPlain config */\n";
        return asm_code.str();
    }
    asm_code
        << "        /* CKKS MULTIPLY_PLAIN: canonical HPU NTT/Q pointwise multiply */\n";
    asm_code << hpu::dload(
        kModulusTableObject,
        hpu::DataType::mod_ctx,
        hpu::DloadFlag::small_bank);
    asm_code << ::generate_hpu_pmult_body_asm(num_q, false, false);
    asm_code << hpu::pfree(kModulusTableObject);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_add_plain_body_asm(int num_q, bool append_psync)
{
    return generate_plain_binary_body(num_q, false, append_psync);
}

std::string generate_subtract_plain_body_asm(int num_q, bool append_psync)
{
    return generate_plain_binary_body(num_q, true, append_psync);
}

std::string generate_add_asm(int num_q, bool append_psync)
{
    return wrap("hpu_ckks_add", num_q,
                generate_add_body_asm(num_q, append_psync), valid_config(num_q));
}

std::string generate_subtract_asm(int num_q, bool append_psync)
{
    return wrap("hpu_ckks_subtract", num_q,
                generate_subtract_body_asm(num_q, append_psync), valid_config(num_q));
}

std::string generate_multiply_plain_asm(int num_q, bool append_psync)
{
    return wrap("hpu_ckks_multiply_plain", num_q,
                generate_multiply_plain_body_asm(num_q, append_psync),
                valid_config(num_q));
}

std::string generate_add_plain_asm(int num_q, bool append_psync)
{
    return wrap("hpu_ckks_add_plain", num_q,
                generate_add_plain_body_asm(num_q, append_psync), valid_config(num_q));
}

std::string generate_subtract_plain_asm(int num_q, bool append_psync)
{
    return wrap("hpu_ckks_subtract_plain", num_q,
                generate_subtract_plain_body_asm(num_q, append_psync),
                valid_config(num_q));
}

bool compatible_add_scales(
    double left_scale,
    double right_scale,
    double relative_tolerance)
{
    if (!std::isfinite(left_scale) || !std::isfinite(right_scale)
        || !std::isfinite(relative_tolerance) || left_scale <= 0.0
        || right_scale <= 0.0 || relative_tolerance < 0.0) {
        return false;
    }
    return std::abs(left_scale - right_scale)
        <= relative_tolerance * std::max(left_scale, right_scale);
}

double multiply_plain_scale(double ciphertext_scale, double plaintext_scale)
{
    if (!std::isfinite(ciphertext_scale) || !std::isfinite(plaintext_scale)
        || ciphertext_scale <= 0.0 || plaintext_scale <= 0.0) {
        throw std::invalid_argument("CKKS MultiplyPlain scales must be positive");
    }
    const double result = ciphertext_scale * plaintext_scale;
    if (!std::isfinite(result)) {
        throw std::overflow_error("CKKS MultiplyPlain scale is not finite");
    }
    return result;
}

} // namespace hpu::scheme::ckks
