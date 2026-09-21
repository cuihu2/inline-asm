#pragma once

#include "scheme/ckks/galois.hpp"

#include <cstddef>
#include <cstdint>

namespace hpu::scheme::bfv {

// BFV batching and CKKS slots use the same SEAL generator-3 action on the
// 2N-th cyclotomic ring. Positive steps rotate both BFV batching rows left;
// negative steps rotate them right.
inline std::uint32_t row_rotation_galois_element(std::size_t degree, int steps)
{
    return hpu::scheme::ckks::rotation_galois_element(degree, steps);
}

// SEAL rotate_columns swaps the two BFV batching rows with X -> X^(2N-1).
inline std::uint32_t column_rotation_galois_element(std::size_t degree)
{
    return hpu::scheme::ckks::conjugation_galois_element(degree);
}

} // namespace hpu::scheme::bfv
