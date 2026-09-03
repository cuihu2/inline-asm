#pragma once

#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <algorithm>
#include <cstddef>
#include <utility>
#include <vector>

namespace hpu {

// Application-global MOD_ID layout for hybrid key switching. Q may shrink as
// the SEAL chain advances, while P keeps its original key-context MOD_ID.
// key_digits is an ordered partition of the active Q MOD_IDs.
struct RnsDecompositionLayout {
    std::vector<int> q_mod_ids;
    std::vector<int> p_mod_ids;
    std::vector<std::vector<int>> key_digits;
};

inline bool valid_mod_id_list(const std::vector<int>& ids)
{
    if (ids.empty()) {
        return false;
    }
    std::vector<bool> seen(static_cast<std::size_t>(kMaxModContexts), false);
    for (int id : ids) {
        if (id < 0 || id >= kMaxModContexts || seen[static_cast<std::size_t>(id)]) {
            return false;
        }
        seen[static_cast<std::size_t>(id)] = true;
    }
    return true;
}

inline bool is_valid_rns_decomposition_layout(
    int N,
    const RnsDecompositionLayout& layout)
{
    if (!is_valid_ntt_size(N) || !valid_mod_id_list(layout.q_mod_ids)
        || !valid_mod_id_list(layout.p_mod_ids) || layout.key_digits.empty()) {
        return false;
    }
    std::vector<bool> q_seen(layout.q_mod_ids.size(), false);
    for (const auto& digit : layout.key_digits) {
        if (digit.empty()) {
            return false;
        }
        for (int id : digit) {
            const auto found = std::find(
                layout.q_mod_ids.begin(), layout.q_mod_ids.end(), id);
            if (found == layout.q_mod_ids.end()) {
                return false;
            }
            const std::size_t index = static_cast<std::size_t>(
                found - layout.q_mod_ids.begin());
            if (q_seen[index]) {
                return false;
            }
            q_seen[index] = true;
        }
    }
    if (std::find(q_seen.begin(), q_seen.end(), false) != q_seen.end()) {
        return false;
    }
    for (int p_id : layout.p_mod_ids) {
        if (std::find(layout.q_mod_ids.begin(), layout.q_mod_ids.end(), p_id)
            != layout.q_mod_ids.end()) {
            return false;
        }
    }
    return true;
}

inline RnsDecompositionLayout make_contiguous_rns_decomposition_layout(
    int num_q,
    int num_p,
    int dnum)
{
    RnsDecompositionLayout layout;
    if (num_q <= 0 || num_p <= 0 || dnum <= 0 || num_q % dnum != 0) {
        return layout;
    }
    for (int i = 0; i < num_q; ++i) {
        layout.q_mod_ids.push_back(i);
    }
    for (int i = 0; i < num_p; ++i) {
        layout.p_mod_ids.push_back(num_q + i);
    }
    const int digit_size = num_q / dnum;
    for (int digit = 0; digit < dnum; ++digit) {
        std::vector<int> contexts;
        for (int i = 0; i < digit_size; ++i) {
            contexts.push_back(digit * digit_size + i);
        }
        layout.key_digits.push_back(std::move(contexts));
    }
    return layout;
}

} // namespace hpu
