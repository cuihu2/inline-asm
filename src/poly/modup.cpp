#include "poly/modup.hpp"

#include "util/bconv.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

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

} // namespace

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

    std::vector<int> source_contexts;
    std::vector<int> target_contexts;
    for (int i = 0; i < num_q_digit; ++i) {
        source_contexts.push_back(q_offset + i);
    }
    for (int i = 0; i < num_q; ++i) {
        if (i < q_offset || i >= q_offset + num_q_digit) {
            target_contexts.push_back(i);
        }
    }
    for (int i = 0; i < num_p; ++i) {
        target_contexts.push_back(num_q + i);
    }

    asm_code << "        /* MODUP: Q_digit -> full Q union P */\n";
    asm_code << "        /* Retain source digit limbs in full-basis workspace */\n";
    for (int i = 0; i < num_q_digit; ++i) {
        asm_code << "        /* Copy Q context " << (q_offset + i) << " */\n";
        asm_code << hpu::dload(0, hpu::DataType::poly);
        asm_code << hpu::dstore(0, 1);
    }
    asm_code << generate_hpu_bconv_contexts_body_asm(
        source_contexts,
        target_contexts,
        false,
        manage_modulus_table);

    if (append_psync) {
        asm_code << hpu::psync();
    }
    return asm_code.str();
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
