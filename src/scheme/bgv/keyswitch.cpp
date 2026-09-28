#include "scheme/bgv/keyswitch.hpp"

#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"

#include <algorithm>
#include <sstream>
#include <vector>

namespace hpu::scheme::bgv {
namespace {

constexpr int kValue = 0;
constexpr int kAuxiliary = 1;
constexpr int kAccumulator = 2;
constexpr int kTwiddle = 3;
constexpr int kModulusTable = 4;

bool valid_config(int N, const hpu::RnsDecompositionLayout& layout, int t_id)
{
    return hpu::is_seal_single_p_rns_decomposition_layout(N, layout) &&
           t_id >= 0 && t_id < hpu::kMaxModContexts &&
           std::find(layout.q_mod_ids.begin(), layout.q_mod_ids.end(), t_id) ==
               layout.q_mod_ids.end() &&
           t_id != layout.p_mod_ids.front();
}

} // namespace

std::string generate_keyswitch_ntt_body_asm(
    int N, const hpu::RnsDecompositionLayout& layout, int plaintext_mod_id,
    bool append_psync, bool manage_modulus_table)
{
    if (!valid_config(N, layout, plaintext_mod_id)) {
        return "        /* Invalid SEAL-facing BGV NTT KeySwitch layout */\n";
    }
    const int p_id = layout.p_mod_ids.front();
    std::vector<int> target_ids = layout.q_mod_ids;
    target_ids.push_back(p_id);
    std::ostringstream asm_code;
    asm_code << "        /* BGV KEYSWITCH NTT: singleton Q digits, mod-t special-P ModDown */\n";
    asm_code << "        /* Two canonical NTT base limbs plus one switching component -> two NTT outputs. */\n";
    if (manage_modulus_table) {
        asm_code << hpu::dload(kModulusTable, hpu::DataType::mod_ctx,
                               hpu::DloadFlag::small_bank);
    }

    for (std::size_t digit = 0; digit < layout.q_mod_ids.size(); ++digit) {
        const int source_id = layout.q_mod_ids[digit];
        asm_code << "        /* digit " << digit << ": switching limb NTT -> coefficient scratch */\n";
        asm_code << hpu::pmodld(source_id);
        asm_code << "        // dload switching component, q_j canonical HPU NTT\n";
        asm_code << hpu::dload(kValue, hpu::DataType::poly);
        asm_code << generate_hpu_intt_body_asm(N, kValue, kTwiddle, false);
        asm_code << "        // dstore switching q_j coefficient scratch\n";
        asm_code << hpu::dstore(kValue, 1);

        for (int target_id : target_ids) {
            asm_code << "        /* digit " << digit << ", target MOD_ID " << target_id << " */\n";
            asm_code << hpu::pmodld(target_id);
            if (target_id == source_id) {
                asm_code << "        // same modulus: dload original canonical NTT limb\n";
                asm_code << hpu::dload(kValue, hpu::DataType::poly);
            } else {
                asm_code << "        // cross-base dload q_j coefficients; canonicalize before PNTT\n";
                asm_code << hpu::dload(kValue, hpu::DataType::poly);
                asm_code << hpu::pmul_imm(kValue, kValue, 1);
                asm_code << generate_hpu_ntt_body_asm(N, kValue, kTwiddle, false);
            }
            for (int key_component = 0; key_component < 2; ++key_component) {
                asm_code << "        /* evaluation-key component " << key_component << " */\n";
                asm_code << "        // dload key digit at target MOD_ID\n";
                asm_code << hpu::dload(kAuxiliary, hpu::DataType::poly);
                if (digit == 0) {
                    asm_code << hpu::pmul(kAccumulator, kValue, kAuxiliary);
                } else {
                    asm_code << "        // dload prior canonical NTT accumulator\n";
                    asm_code << hpu::dload(kAccumulator, hpu::DataType::poly);
                    asm_code << hpu::pmac(kAccumulator, kValue, kAuxiliary);
                }
                asm_code << hpu::pfree(kAuxiliary);
                asm_code << "        // dstore canonical NTT accumulator\n";
                asm_code << hpu::dstore(kAccumulator, 1);
            }
            asm_code << hpu::pfree(kValue);
        }
    }

    for (int key_component = 0; key_component < 2; ++key_component) {
        asm_code << "        /* key component " << key_component
                 << ": special-P NTT accumulator -> coefficient correction */\n";
        asm_code << hpu::pmodld(p_id);
        asm_code << "        // dload special-P NTT accumulator\n";
        asm_code << hpu::dload(kValue, hpu::DataType::poly);
        asm_code << generate_hpu_intt_body_asm(N, kValue, kTwiddle, false);
        asm_code << "        // dstore special-P coefficient scratch\n";
        asm_code << hpu::dstore(kValue, 1);

        asm_code << "        /* u_t = -c_P * P^-1 mod t; wide PMUL input is legal */\n";
        asm_code << hpu::pmodld(plaintext_mod_id);
        asm_code << "        // dload c_P coefficients and prepared -P^-1 mod t\n";
        asm_code << hpu::dload(kValue, hpu::DataType::poly);
        asm_code << hpu::dload(kAuxiliary, hpu::DataType::poly);
        asm_code << hpu::pmul(kValue, kValue, kAuxiliary);
        asm_code << hpu::pfree(kAuxiliary);
        asm_code << "        // dstore canonical u_t coefficient scratch\n";
        asm_code << hpu::dstore(kValue, 1);

        for (int q_id : layout.q_mod_ids) {
            asm_code << "        /* BGV P ModDown, key component " << key_component
                     << ", q MOD_ID " << q_id << " */\n";
            asm_code << hpu::pmodld(q_id);
            asm_code << "        // dload u_t and prepared P mod q_i\n";
            asm_code << hpu::dload(kValue, hpu::DataType::poly);
            asm_code << hpu::dload(kAuxiliary, hpu::DataType::poly);
            asm_code << hpu::pmul(kValue, kValue, kAuxiliary);
            asm_code << hpu::pfree(kAuxiliary);
            asm_code << "        // dload c_P coefficients and canonicalize before PADD\n";
            asm_code << hpu::dload(kAuxiliary, hpu::DataType::poly);
            asm_code << hpu::pmul_imm(kAuxiliary, kAuxiliary, 1);
            asm_code << hpu::padd(kValue, kValue, kAuxiliary);
            asm_code << hpu::pfree(kAuxiliary);
            asm_code << generate_hpu_ntt_body_asm(N, kValue, kTwiddle, false);
            asm_code << "        // dload Q NTT accumulator and subtract correction NTT\n";
            asm_code << hpu::dload(kAuxiliary, hpu::DataType::poly);
            asm_code << hpu::psub(kAuxiliary, kAuxiliary, kValue);
            asm_code << hpu::pfree(kValue);
            asm_code << "        // dload prepared P^-1 mod q_i\n";
            asm_code << hpu::dload(kValue, hpu::DataType::poly);
            asm_code << hpu::pmul(kAuxiliary, kAuxiliary, kValue);
            asm_code << hpu::pfree(kValue);
            asm_code << "        // dload base component in canonical HPU NTT and add\n";
            asm_code << hpu::dload(kValue, hpu::DataType::poly);
            asm_code << hpu::padd(kAuxiliary, kAuxiliary, kValue);
            asm_code << hpu::pfree(kValue);
            asm_code << "        // dstore final canonical HPU NTT output\n";
            asm_code << hpu::dstore(kAuxiliary, 1);
        }
    }

    if (manage_modulus_table) {
        asm_code << hpu::pfree(kModulusTable);
    }
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

} // namespace hpu::scheme::bgv
