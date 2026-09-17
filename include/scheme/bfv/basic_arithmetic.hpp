#pragma once

#include <string>

namespace hpu::scheme::bfv {

// BFV ciphertexts and Add/SubPlain operands use coefficient-domain Q limbs.
// A composed application passes manage_modulus_table=false so the outer
// program owns the single application-lifetime modulus-table load/free pair.
std::string generate_add_body_asm(int num_q, bool append_psync = true,
                                  bool manage_modulus_table = true);
std::string generate_subtract_body_asm(int num_q, bool append_psync = true,
                                       bool manage_modulus_table = true);
std::string generate_add_plain_body_asm(int num_q, bool append_psync = true,
                                        bool manage_modulus_table = true);
std::string generate_subtract_plain_body_asm(int num_q, bool append_psync = true,
                                             bool manage_modulus_table = true);
std::string generate_negate_body_asm(int num_q, bool append_psync = true,
                                     bool manage_modulus_table = true);

} // namespace hpu::scheme::bfv
