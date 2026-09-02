#pragma once

#include <complex>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::scheme::ckks {

// Host-only codec. These APIs perform no HPU instruction generation.

struct EncodedPlaintext {
    std::vector<std::int64_t> coefficients;
    double scale = 0.0;
    std::size_t slot_count = 0;
};

// Generator-3 CKKS canonical embedding. Missing slots are zero-filled up to
// N/2; coefficients are rounded after multiplication by scale.
EncodedPlaintext encode_slots(
    const std::vector<std::complex<double>>& complex_slots,
    std::size_t N,
    double scale);

std::vector<std::complex<double>> decode_slots(
    const std::vector<std::int64_t>& centered_coefficients,
    double scale);

} // namespace hpu::scheme::ckks
