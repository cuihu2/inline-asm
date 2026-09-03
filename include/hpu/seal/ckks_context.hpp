#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace seal {
class SEALContext;
}

namespace hpu::seal_adapter {

struct CkksContextSpec {
    std::size_t poly_modulus_degree = 65536;

    // Complete SEAL key-context modulus list. The adapter does not freeze Q/P
    // counts: it asks SEALContext which suffix is special-key modulus data.
    std::vector<int> coeff_modulus_bits;
};

struct CkksContextBundle {
    std::shared_ptr<::seal::SEALContext> context;
    std::vector<std::uint32_t> data_moduli;
    std::vector<std::uint32_t> special_moduli;
};

// Creates a CKKS SEALContext under the HPU ABI. Every q/P prime must fit one
// uint32 word. sec_level_type::none is intentional for the initial N=65536
// functional path; security qualification is a separate milestone.
CkksContextBundle create_ckks_context(const CkksContextSpec& spec);

} // namespace hpu::seal_adapter
