#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::model {

struct NttBatch {
    bool interleaved = false;
    std::size_t first = 0;
    std::size_t second = 0;
};

struct InverseNttTables {
    // One N/2-entry table per inverse stage, in loader-batch/BF-lane order.
    std::vector<std::vector<std::uint32_t>> stages;

    // Per physical coefficient position after the last inverse stage.
    // Includes lazy-scale cancellation and N^-1 normalization.
    std::vector<std::uint32_t> post_scale;
};

// Bit-accurate software model of hw_ntt_intt_complete.py. This class models
// the cyclic transform. CKKS negacyclic transforms are exposed by the free
// functions below and add the required psi twist/untwist.
class HardwareNttModel {
public:
    HardwareNttModel(
        std::size_t degree,
        std::uint32_t modulus,
        std::uint32_t omega);

    std::size_t degree() const noexcept;
    std::uint32_t modulus() const noexcept;
    std::uint32_t omega() const noexcept;
    std::size_t log_degree() const noexcept;

    std::vector<NttBatch> stage_batches(std::size_t forward_stage) const;
    std::vector<std::size_t> forward_layout() const;
    std::vector<std::vector<std::uint32_t>> forward_twiddles() const;
    InverseNttTables inverse_twiddles() const;

    // Forward consumes logical coefficient order and returns HPU physical NTT
    // order. Inverse consumes that physical order and returns logical order.
    std::vector<std::uint32_t> forward(
        const std::vector<std::uint32_t>& coefficients) const;
    std::vector<std::uint32_t> inverse(
        const std::vector<std::uint32_t>& physical_ntt) const;

private:
    std::size_t degree_;
    std::uint32_t modulus_;
    std::uint32_t omega_;
    std::size_t log_degree_;
};

std::uint32_t pow_mod(
    std::uint32_t base,
    std::uint64_t exponent,
    std::uint32_t modulus);

std::uint32_t inverse_mod_prime(
    std::uint32_t value,
    std::uint32_t modulus);

std::vector<std::uint32_t> negacyclic_forward(
    const std::vector<std::uint32_t>& coefficients,
    std::uint32_t modulus,
    std::uint32_t psi);

std::vector<std::uint32_t> negacyclic_inverse(
    const std::vector<std::uint32_t>& physical_ntt,
    std::uint32_t modulus,
    std::uint32_t psi);

std::vector<std::uint32_t> automorphism_coefficients(
    const std::vector<std::uint32_t>& coefficients,
    std::uint64_t galois_element,
    std::uint32_t modulus);

// Implements toy_fhe_auto.py's two fused forms. Both return the canonical HPU
// NTT physical domain, so no modified-root state must survive a kernel boundary.
std::vector<std::uint32_t> automorphism_fused_inverse(
    const std::vector<std::uint32_t>& canonical_physical_ntt,
    std::uint64_t galois_element,
    std::uint32_t modulus,
    std::uint32_t psi);

std::vector<std::uint32_t> automorphism_fused_forward(
    const std::vector<std::uint32_t>& canonical_physical_ntt,
    std::uint64_t galois_element,
    std::uint32_t modulus,
    std::uint32_t psi);

} // namespace hpu::model
