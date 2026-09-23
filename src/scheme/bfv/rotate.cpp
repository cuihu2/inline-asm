#include "scheme/bfv/rotate.hpp"

#include "operator/keyswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include <numeric>
#include <sstream>

namespace hpu::scheme::bfv {
namespace {

constexpr int kPolynomialObject = 0;
constexpr int kTwiddleObject = 3;
constexpr int kModulusTableObject = 4;

bool valid_config(int N, const hpu::RnsDecompositionLayout& layout,
                  std::uint32_t galois_element)
{
    const std::uint64_t ring_order = 2ULL * static_cast<std::uint64_t>(N);
    return hpu::is_seal_single_p_rns_decomposition_layout(N, layout) &&
           galois_element < ring_order &&
           std::gcd<std::uint64_t>(galois_element, ring_order) == 1;
}

} // namespace

std::string generate_rotate_body_asm(int N, const hpu::RnsDecompositionLayout& layout,
                                     std::uint32_t galois_element, bool append_psync,
                                     bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_config(N, layout, galois_element)) {
        return "        /* Invalid BFV Rotate config */\n";
    }

    asm_code << "        /* BFV ROTATE: coefficient automorphism + rounded Galois KeySwitch */\n"
             << "        /* Canonical NTT followed by modified-root INTT implements sigma_k; k="
             << galois_element << ". */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTableObject, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }
    for (int component = 0; component < 2; ++component) {
        for (int context : layout.q_mod_ids) {
            asm_code << "        /* automorphism component_" << component << ", q MOD_ID "
                     << context << ", key_domain=" << galois_element << " */\n";
            asm_code << hpu::pmodld(context);
            asm_code << hpu::dload(kPolynomialObject, hpu::DataType::poly);
            asm_code << generate_hpu_ntt_body_asm(N, kPolynomialObject, kTwiddleObject, false);
            asm_code << generate_hpu_intt_body_asm(N, kPolynomialObject, kTwiddleObject, false);
            asm_code << hpu::dstore(kPolynomialObject, 1);
        }
    }
    asm_code << "        /* Galois KeySwitch: key_domain k -> canonical secret-key domain. */\n";
    asm_code << ::generate_hpu_bfv_keyswitch_body_asm(N, layout, false, false);
    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTableObject);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

} // namespace hpu::scheme::bfv
