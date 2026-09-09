#include "hpu/seal/ckks_metadata.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>

namespace hpu::seal_adapter {
namespace {

std::string metadata_error(const char* role, const char* detail)
{
    return std::string(role) + " " + detail;
}

void require_same_level(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& left,
    const CkksValueMetadata& right,
    const char* role)
{
    validate_ckks_metadata(level_chain, left, role);
    validate_ckks_metadata(level_chain, right, role);
    if (left.parms_id != right.parms_id
        || left.chain_index != right.chain_index) {
        throw std::invalid_argument(
            metadata_error(role, "requires operands at the same CKKS level"));
    }
}

} // namespace

bool ckks_scales_compatible(
    double left,
    double right,
    double relative_tolerance) noexcept
{
    return std::isfinite(left) && std::isfinite(right)
        && left > 0.0 && right > 0.0
        && std::isfinite(relative_tolerance) && relative_tolerance >= 0.0
        && std::abs(left - right)
            <= relative_tolerance * std::max(left, right);
}

void validate_ckks_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& metadata,
    const char* role)
{
    const auto& level = level_chain.require(metadata.parms_id);
    if (metadata.chain_index != level.chain_index) {
        throw std::invalid_argument(
            metadata_error(role, "has a chain_index inconsistent with parms_id"));
    }
    if (!std::isfinite(metadata.scale) || metadata.scale <= 0.0) {
        throw std::invalid_argument(
            metadata_error(role, "has a non-positive or non-finite scale"));
    }
}

CkksValueMetadata infer_ckks_preserving_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& input)
{
    validate_ckks_metadata(level_chain, input, "CKKS preserving operation input");
    return input;
}

CkksValueMetadata infer_ckks_add_sub_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& left,
    const CkksValueMetadata& right)
{
    require_same_level(level_chain, left, right, "CKKS Add/Sub");
    if (!ckks_scales_compatible(left.scale, right.scale)) {
        throw std::invalid_argument("CKKS Add/Sub requires matching scales");
    }
    return left;
}

CkksValueMetadata infer_ckks_multiply_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& left,
    const CkksValueMetadata& right)
{
    require_same_level(level_chain, left, right, "CKKS Multiply");
    CkksValueMetadata result = left;
    result.scale = left.scale * right.scale;
    if (!std::isfinite(result.scale) || result.scale <= 0.0) {
        throw std::invalid_argument("CKKS Multiply produced an invalid scale");
    }
    return result;
}

CkksValueMetadata infer_ckks_rescale_metadata(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& input)
{
    validate_ckks_metadata(level_chain, input, "CKKS Rescale input");
    const auto& source = level_chain.require(input.parms_id);
    const auto& destination = level_chain.next(input.parms_id);
    if (source.q_last == 0) {
        throw std::invalid_argument("CKKS Rescale source has no q_last modulus");
    }
    CkksValueMetadata result;
    result.parms_id = destination.parms_id;
    result.chain_index = destination.chain_index;
    result.scale = input.scale / static_cast<double>(source.q_last);
    if (!std::isfinite(result.scale) || result.scale <= 0.0) {
        throw std::invalid_argument("CKKS Rescale produced an invalid scale");
    }
    return result;
}

void require_ckks_metadata_matches(
    const CkksLevelChain& level_chain,
    const CkksValueMetadata& expected,
    const CkksValueMetadata& actual,
    const char* role)
{
    validate_ckks_metadata(level_chain, expected, role);
    validate_ckks_metadata(level_chain, actual, role);
    if (expected.parms_id != actual.parms_id
        || expected.chain_index != actual.chain_index
        || !ckks_scales_compatible(expected.scale, actual.scale)) {
        throw std::invalid_argument(
            metadata_error(role, "has incompatible level or scale metadata"));
    }
}

} // namespace hpu::seal_adapter
