#include "scheme/bfv/modswitch.hpp"

#include "operator/rounded_drop_last.hpp"
#include "util/validation.hpp"

#include <sstream>

namespace hpu::scheme::bfv {

std::string generate_modswitch_body_asm(
    int num_q,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    if (num_q < 2 || num_components <= 0
        || !hpu::has_mod_context_capacity(num_q)) {
        asm_code << "        // Invalid BFV ModSwitch config\n";
        return asm_code.str();
    }
    asm_code << "        /* BFV MODSWITCH: coefficient/Q -> rounded coefficient/Q_without_last */\n";
    asm_code << ::generate_hpu_rounded_drop_last_body_asm(
        num_q, num_components, append_psync);
    return asm_code.str();
}

std::string generate_modswitch_asm(
    int num_q,
    int num_components,
    bool append_psync)
{
    std::ostringstream asm_code;
    asm_code << "void hpu_bfv_modswitch_Q" << num_q << "_C"
             << num_components << "(void) {\n";
    if (num_q < 2 || num_components <= 0
        || !hpu::has_mod_context_capacity(num_q)) {
        asm_code << "    // Invalid BFV ModSwitch config\n}\n";
        return asm_code.str();
    }
    asm_code << "    __asm__ volatile(\n"
             << generate_modswitch_body_asm(
                    num_q, num_components, append_psync)
             << "        : \n        : \n        : \"memory\"\n    );\n}\n";
    return asm_code.str();
}

} // namespace hpu::scheme::bfv
