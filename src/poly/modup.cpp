#include "poly/modup.hpp"

#include "operator/rns_layout.hpp"
#include "util/bconv.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace {

bool valid_modup_config(
    int num_q,
    int num_p,
    int num_q_digit,
    int q_offset)
{
    return num_p > 0 && num_q_digit > 0 && q_offset >= 0
        && q_offset <= num_q
        && num_q_digit <= num_q - q_offset
        && hpu::has_mod_context_capacity(num_q, num_p);
}

bool valid_contexts(
    const std::vector<int>& q_contexts,
    const std::vector<int>& p_contexts,
    const std::vector<int>& source_contexts)
{
    if (!hpu::valid_mod_id_list(q_contexts)
        || !hpu::valid_mod_id_list(p_contexts)
        || !hpu::valid_mod_id_list(source_contexts)) {
        return false;
    }
    for (int source : source_contexts) {
        if (std::find(q_contexts.begin(), q_contexts.end(), source)
            == q_contexts.end()) {
            return false;
        }
    }
    for (int p : p_contexts) {
        if (std::find(q_contexts.begin(), q_contexts.end(), p)
            != q_contexts.end()) {
            return false;
        }
    }
    return true;
}

} // namespace

std::string generate_hpu_modup_contexts_body_asm(
    const std::vector<int>& q_contexts,
    const std::vector<int>& p_contexts,
    const std::vector<int>& source_contexts,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_contexts(q_contexts, p_contexts, source_contexts)) {
        asm_code << "        // Invalid explicit ModUp context layout\n";
        return asm_code.str();
    }

    std::vector<int> target_contexts;
    for (int q : q_contexts) {
        if (std::find(source_contexts.begin(), source_contexts.end(), q)
            == source_contexts.end()) {
            target_contexts.push_back(q);
        }
    }
    target_contexts.insert(
        target_contexts.end(), p_contexts.begin(), p_contexts.end());

    asm_code << "        /* MODUP: Q_digit -> full Q union P (explicit global MOD_ID layout) */\n";
    asm_code << "        /* Retain source digit limbs in full-basis workspace */\n";
    for (int context : source_contexts) {
        asm_code << "        /* Copy Q context " << context
                 << " (global MOD_ID " << context << ") */\n";
        asm_code << hpu::dload(0, hpu::DataType::poly);
        asm_code << hpu::dstore(0, 1);
    }
    asm_code << generate_hpu_bconv_contexts_body_asm(
        source_contexts, target_contexts, false, manage_modulus_table);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
}

std::string generate_hpu_modup_body_asm(
    int num_q,
    int num_p,
    int num_q_digit,
    int q_offset,
    bool append_psync,
    bool manage_modulus_table)
{
    std::ostringstream asm_code;
    if (!valid_modup_config(num_q, num_p, num_q_digit, q_offset)) {
        asm_code << "        // Invalid ModUp config\n";
        return asm_code.str();
    }

    std::vector<int> q_contexts;
    std::vector<int> p_contexts;
    std::vector<int> source_contexts;
    for (int i = 0; i < num_q; ++i) {
        q_contexts.push_back(i);
    }
    for (int i = 0; i < num_p; ++i) {
        p_contexts.push_back(num_q + i);
    }
    for (int i = 0; i < num_q_digit; ++i) {
        source_contexts.push_back(q_offset + i);
    }
    return generate_hpu_modup_contexts_body_asm(
        q_contexts, p_contexts, source_contexts,
        append_psync, manage_modulus_table);
}

std::string generate_hpu_modup_asm(
    int num_q,
    int num_p,
    int num_q_digit,
    int q_offset,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_modup_Q" << num_q << "_P" << num_p
             << "_D" << num_q_digit << "_O" << q_offset << "(void) {\n";

    if (!valid_modup_config(num_q, num_p, num_q_digit, q_offset)) {
        asm_code << "    // Invalid config: require a Q digit within the complete Q union P basis\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << generate_hpu_modup_body_asm(
        num_q,
        num_p,
        num_q_digit,
        q_offset,
        append_psync);

    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";

    return asm_code.str();
}
