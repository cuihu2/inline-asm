#pragma once

#include <seal/seal.h>

#include <cstdint>
#include <vector>

namespace hpu::seal_adapter {

// HPU_MEM payloads for one modulus of toy_fhe_auto.py's INTT-fused form:
// NTT_psi(a) -> INTT_{psi^(1/k)} -> a(X^k) in coefficient order.
struct FusedInverseAutomorphismTables {
    std::uint32_t modulus = 0;
    std::uint32_t canonical_psi = 0;
    std::uint32_t modified_psi = 0;
    std::vector<std::vector<std::uint32_t>> stages;
    std::vector<std::uint32_t> post_untwist_scale;
};

// Builds the modified-root tables for every active data modulus at parms_id.
// The caller preloads these payloads in HPU_MEM and binds the fused INTT p3
// dloads to them. No modified-root representation crosses the completed INTT.
std::vector<FusedInverseAutomorphismTables>
create_fused_inverse_automorphism_tables(
    ::seal::parms_id_type parms_id,
    std::uint32_t galois_element,
    const ::seal::SEALContext& context);

} // namespace hpu::seal_adapter
