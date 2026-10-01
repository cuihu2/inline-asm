#pragma once

#include "hpu/delivery/application_package.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "hpu/seal/bgv_linear_operation_plan.hpp"
#include "hpu/seal/operation_runtime.hpp"

namespace hpu::seal_adapter {

// One independent SEAL Evaluator snapshot per lowered operation, in plan order.
// Every output limb is checked against the executor's final HPU_MEM words.
// Returned requests borrow image; keep it alive until write_application_package.
hpu::delivery::ApplicationPackageRequest make_ckks_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const CkksLoweredProgram& lowered, const CkksRuntimeProgram& runtime,
    const CkksRuntimeArtifacts& artifacts, const hpu::runtime::HpuMemImage& image,
    const std::vector<::seal::Ciphertext>& oracle_after_step,
    const std::vector<std::uint32_t>& executed_image_words);

hpu::delivery::ApplicationPackageRequest make_bfv_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const BfvLoweredProgram& lowered, const BfvRuntimeProgram& runtime,
    const BfvRuntimeArtifacts& artifacts, const hpu::runtime::HpuMemImage& image,
    const std::vector<::seal::Ciphertext>& oracle_after_step,
    const std::vector<std::uint32_t>& executed_image_words);

// BGV goldens come from independent SEAL snapshots and every output limb is
// checked against BgvSoftwareExecutor's HPU_MEM result.
hpu::delivery::ApplicationPackageRequest make_bgv_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const BgvLinearOperationPlan& plan, const BgvKeySwitchApplication& application,
    const std::vector<::seal::Ciphertext>& oracle_after_step,
    const std::vector<std::uint32_t>& executed_image_words);

// Convenience overload that executes BgvSoftwareExecutor internally.
hpu::delivery::ApplicationPackageRequest make_bgv_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const BgvLinearOperationPlan& plan, const BgvKeySwitchApplication& application,
    const std::vector<::seal::Ciphertext>& oracle_after_step);

// Optional decoded data, supplied by the caller after its semantic assertions.
hpu::delivery::SemanticReport ckks_delivery_semantics(
    const std::vector<double>& decoded, std::size_t count,
    double maximum_absolute_error, double tolerance);
hpu::delivery::SemanticReport integer_delivery_semantics(
    const std::vector<std::uint64_t>& decoded);

} // namespace hpu::seal_adapter
