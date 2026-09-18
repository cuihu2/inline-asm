#pragma once

#include "operator/rns_layout.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace hpu::scheme::bfv {

struct BfvCiphertextMultiplyLayout {
    hpu::RnsDecompositionLayout keyswitch_layout;
    std::vector<int> b_mod_ids;
    int m_sk_mod_id = -1;
    int plaintext_mod_id = -1;
};

bool is_valid_ciphertext_multiply_layout(int N, const BfvCiphertextMultiplyLayout& layout,
                                         std::uint64_t plaintext_modulus);

// SEAL-facing fused BEHZ multiply + comparison-free single-P
// relinearization. Explicit MOD_IDs allow Q to shrink without renumbering P or
// the per-level B/m_sk resources.
std::string generate_ciphertext_multiply_body_asm(int N, const BfvCiphertextMultiplyLayout& layout,
                                                  std::uint64_t plaintext_modulus,
                                                  bool append_psync = false,
                                                  bool manage_modulus_table = true);

std::string generate_ciphertext_multiply_body_asm(int N, int num_q, int num_p, int num_b, int dnum,
                                                  std::uint64_t plaintext_modulus,
                                                  bool append_psync = false);

std::string generate_ciphertext_multiply_asm(int N, int num_q, int num_p, int num_b, int dnum,
                                             std::uint64_t plaintext_modulus,
                                             bool append_psync = true);

} // namespace hpu::scheme::bfv
