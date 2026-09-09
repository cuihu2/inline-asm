#pragma once

#include "hpu/seal/ckks_level.hpp"

#include <seal/seal.h>

#include <cstddef>

namespace hpu::seal_adapter {

// Operation-visible CKKS metadata. Data-domain and key-domain representation
// are deliberately tracked separately by PreparedRnsObject.
struct CkksValueMetadata {
    ::seal::parms_id_type parms_id{};
    std::size_t chain_index = 0;
    double scale = 1.0;
};

bool ckks_scales_compatible(
    double left,
    double right,
    double relative_tolerance = 1e-6) noexcept;

void validate_ckks_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& metadata,
    const char* role);

CkksValueMetadata infer_ckks_preserving_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& input);

CkksValueMetadata infer_ckks_add_sub_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& left,
    const CkksValueMetadata& right);

CkksValueMetadata infer_ckks_multiply_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& left,
    const CkksValueMetadata& right);

CkksValueMetadata infer_ckks_rescale_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& input);

void require_ckks_metadata_matches(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& expected,
    const CkksValueMetadata& actual,
    const char* role);

} // namespace hpu::seal_adapter
