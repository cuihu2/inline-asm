#pragma once

#include "hpu/seal/ntt_bridge.hpp"

#include <seal/seal.h>

#include <vector>

namespace hpu::seal_adapter {

struct HpuKeySwitchDigit {
    HpuRnsPolynomial key_component_0;
    HpuRnsPolynomial key_component_1;
};

// Converts SEAL's s^2 relinearization key directly from the key context. The
// returned Q/P and digit count are whatever SEAL generated; no P=3 or dnum=2
// assumption is made. SecretKey is neither accepted nor copied.
std::vector<HpuKeySwitchDigit> relinearization_key_to_hpu(
    const ::seal::RelinKeys& keys,
    const ::seal::SEALContext& context);

} // namespace hpu::seal_adapter
