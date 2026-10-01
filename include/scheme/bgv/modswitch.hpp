#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hpu::scheme::bgv {

// Coefficient-domain BGV modulus switch from Q to Q without its final limb.
// The global context order is Q followed by P followed by plaintext modulus t.
std::string generate_modswitch_body_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync = false);

std::string generate_modswitch_asm(
    int num_q,
    int num_p,
    int num_components,
    bool append_psync = true);

std::uint64_t modswitch_correction_factor(
    std::uint64_t factor,
    std::uint64_t q_last,
    std::uint64_t plaintext_modulus);

// SEAL-facing BGV uses canonical HPU NTT ciphertexts. Active Q MOD_IDs are
// supplied explicitly so the plaintext MOD_ID stays fixed across level drops.
struct NttModSwitchLayout {
    std::vector<int> q_mod_ids;
    int plaintext_mod_id = -1;
};

struct NttModSwitchConstants {
    std::uint32_t neg_q_last_inverse_mod_t = 0;
    std::vector<std::uint32_t> q_last_mod_q;
    std::vector<std::uint32_t> q_last_inverse_mod_q;
};

NttModSwitchConstants prepare_ntt_modswitch_constants(
    const std::vector<std::uint32_t>& q_moduli,
    std::uint32_t plaintext_modulus);

// Input/output are canonical HPU NTT at adjacent Q levels. For each component,
// the caller binds DMA loads/stores in the order documented in the generated
// stream: dropped limb -> coefficient scratch -> u_t scratch -> retained limbs.
// Constants are N-word splats of the values returned above. The modulus table
// belongs to the application when manage_modulus_table=false.
std::string generate_modswitch_ntt_body_asm(
    int N,
    const NttModSwitchLayout& layout,
    int num_components,
    bool append_psync = false,
    bool manage_modulus_table = false);

} // namespace hpu::scheme::bgv
