#pragma once

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::seal_adapter {

struct HpuRnsPolynomial {
    std::size_t degree = 0;
    std::vector<std::uint32_t> moduli;
    std::vector<std::uint8_t> modulus_ids;

    // Logical shape [modulus][coefficient]. The owning prepared object records
    // whether words use coefficient order or HPU canonical physical NTT order.
    std::vector<std::uint32_t> words;
};

// Copies one coefficient-domain BFV ciphertext component into the HPU uint32
// ABI without changing its RNS-Q coefficient order.
HpuRnsPolynomial bfv_ciphertext_component_to_hpu(
    const ::seal::Ciphertext& ciphertext,
    std::size_t component,
    const ::seal::SEALContext& context);

// Prepares the two distinct BFV plaintext representations. Add/Sub uses the
// exact SEAL scaling-variant Delta*m residues in coefficient order. Multiply
// uses centered plaintext lift followed by canonical HPU NTT physical order.
HpuRnsPolynomial bfv_add_subtract_plaintext_to_hpu(
    const ::seal::Plaintext& plaintext,
    ::seal::parms_id_type parms_id,
    const ::seal::SEALContext& context);

HpuRnsPolynomial bfv_multiply_plaintext_to_hpu(
    const ::seal::Plaintext& plaintext,
    ::seal::parms_id_type parms_id,
    const ::seal::SEALContext& context);

// Converts one CKKS ciphertext component from SEAL's NTT representation to the
// HPU canonical physical NTT representation. Conversion intentionally goes via
// coefficients so it is correct even when the two NTT orders differ.
HpuRnsPolynomial ciphertext_component_to_hpu(
    const ::seal::Ciphertext& ciphertext,
    std::size_t component,
    const ::seal::SEALContext& context);

// Evaluation-key form: extracts selected key-context modulus limbs while
// preserving their application-global MOD_IDs in the returned polynomial.
HpuRnsPolynomial ciphertext_component_to_hpu(
    const ::seal::Ciphertext& ciphertext,
    std::size_t component,
    const ::seal::SEALContext& context,
    const std::vector<std::size_t>& modulus_indices);

// Converts an encoded CKKS plaintext at its current parms_id. CKKS plaintexts
// are already in SEAL NTT form; conversion still goes through coefficients so
// the result uses canonical HPU physical order.
HpuRnsPolynomial plaintext_to_hpu(
    const ::seal::Plaintext& plaintext,
    const ::seal::SEALContext& context);

// Inverse bridge used for differential tests and eventual HPU result import.
// Returns SEAL NTT words in [modulus][coefficient] order.
std::vector<std::uint64_t> hpu_to_seal_ntt(
    const HpuRnsPolynomial& polynomial,
    ::seal::parms_id_type parms_id,
    const ::seal::SEALContext& context);

} // namespace hpu::seal_adapter
