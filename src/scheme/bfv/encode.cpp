#include "scheme/bfv/encode.hpp"

#include "operator/plaintext_ntt.hpp"
#include "scheme/detail/integer_encode.hpp"

#include <sstream>

namespace hpu::scheme::bfv {

std::vector<std::uint64_t> encode_coefficients(
    const std::vector<std::int64_t>& signed_coefficients,
    std::size_t N,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::encode_integer_coefficients(
        signed_coefficients, N, plaintext_modulus, "BFV");
}

std::vector<std::int64_t> decode_coefficients(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::decode_integer_coefficients(
        coefficients, plaintext_modulus, "BFV");
}

std::vector<std::uint64_t> encode_slots(
    const std::vector<std::int64_t>& slots,
    std::size_t N,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::encode_integer_slots(
        slots, N, plaintext_modulus, "BFV");
}

std::vector<std::int64_t> decode_slots(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t plaintext_modulus)
{
    return hpu::scheme::detail::decode_integer_slots(
        coefficients, plaintext_modulus, "BFV");
}

std::string generate_encode_body_asm(
    int N,
    int num_q,
    std::uint64_t plaintext_modulus,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (!hpu::scheme::detail::is_valid_integer_encode_config(
            N, num_q, plaintext_modulus)) {
        asm_code << "        // Invalid BFV Encode config: batching requires prime t and 2N | (t-1)\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV ENCODE: host coefficient/batching map -> HPU NTT-Q */\n";
    asm_code << generate_plaintext_ntt_body_asm(N, num_q, append_psync);
    return asm_code.str();
}

std::string generate_encode_asm(
    int N,
    int num_q,
    std::uint64_t plaintext_modulus,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bfv_encode_N" << N << "_Q" << num_q << "(void) {\n";
    if (!hpu::scheme::detail::is_valid_integer_encode_config(
            N, num_q, plaintext_modulus)) {
        asm_code << "    // Invalid BFV Encode config\n}\n";
        return asm_code.str();
    }
    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_encode_body_asm(
        N, num_q, plaintext_modulus, append_psync);
    asm_code << "        : \n        : \n        : \"memory\"\n    );\n}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::bfv
