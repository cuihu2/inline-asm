#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace seal {
class SEALContext;
}

namespace hpu::seal_adapter {

struct BfvContextSpec {
    std::size_t poly_modulus_degree = 65536;

    // Complete key-context list: data Q followed by exactly one special P.
    // The current HPU BFV profile reserves 32-bit primes for SEAL's auxiliary
    // B/m_sk base, so Q/P are restricted to at most 31 bits.
    std::vector<int> coeff_modulus_bits;
    int plain_modulus_bits = 17;
};

struct BfvContextBundle {
    std::shared_ptr<::seal::SEALContext> context;
    std::vector<std::uint32_t> data_moduli;
    std::uint32_t special_modulus = 0;
    std::uint32_t plain_modulus = 0;
};

// Creates the modified-SEAL BFV context used by the HPU adapter. Batching is
// required so host-prepared plaintexts have one stable N-slot ABI.
BfvContextBundle create_bfv_context(const BfvContextSpec& spec);

} // namespace hpu::seal_adapter
