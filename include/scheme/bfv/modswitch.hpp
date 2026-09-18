#pragma once

#include <string>

namespace hpu::scheme::bfv {

std::string generate_modswitch_body_asm(int num_q, int num_components, bool append_psync = false,
                                        bool manage_modulus_table = true);

std::string generate_modswitch_asm(int num_q, int num_components, bool append_psync = true);

} // namespace hpu::scheme::bfv
