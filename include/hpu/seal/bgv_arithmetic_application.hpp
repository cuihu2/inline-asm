#pragma once

#include "hpu/seal/bgv_keyswitch_application.hpp"

namespace hpu::seal_adapter {

// Shares the validated single-operation HPU_MEM/DMA/runtime container.
using BgvArithmeticApplication = BgvKeySwitchApplication;
using BgvArithmeticRuntimeArtifacts = BgvKeySwitchRuntimeArtifacts;

BgvArithmeticApplication build_bgv_add_application(
    const ::seal::SEALContext& context,
    const ::seal::Ciphertext& left,
    const ::seal::Ciphertext& right,
    std::uint64_t capacity_lines);

BgvArithmeticApplication build_bgv_subtract_application(
    const ::seal::SEALContext& context,
    const ::seal::Ciphertext& left,
    const ::seal::Ciphertext& right,
    std::uint64_t capacity_lines);

BgvArithmeticApplication build_bgv_negate_application(
    const ::seal::SEALContext& context,
    const ::seal::Ciphertext& input,
    std::uint64_t capacity_lines);

// Plaintext is prepared into canonical HPU NTT limbs before execution.
// Add/Sub apply the ciphertext correction factor modulo t during preparation.
BgvArithmeticApplication build_bgv_add_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines);
BgvArithmeticApplication build_bgv_subtract_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines);
BgvArithmeticApplication build_bgv_multiply_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines);

BgvArithmeticRuntimeArtifacts render_bgv_arithmetic_runtime_artifacts(
    const std::string& stem,
    const BgvArithmeticApplication& application);

} // namespace hpu::seal_adapter
