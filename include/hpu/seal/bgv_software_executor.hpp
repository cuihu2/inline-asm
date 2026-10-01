#pragma once

#include "hpu/runtime/software_executor.hpp"
#include "hpu/seal/bgv_linear_operation_plan.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace hpu::seal_adapter {

// Functional execution of a lowered BGV linear plan over the same HPU_MEM
// image consumed by codegen and relocation. The executor reads prepared
// plaintexts, ciphertexts, keys, constants, and twiddles from the image and
// never calls seal::Evaluator; modified-SEAL remains an independent oracle.
class BgvSoftwareExecutor {
public:
    BgvSoftwareExecutor(
        const ::seal::SEALContext& context,
        const hpu::runtime::HpuMemImage& image);

    void execute(const BgvLinearOperationPlan& plan);

    const hpu::runtime::HpuSoftwareExecutor& memory() const noexcept;

private:
    using Limb = std::vector<std::uint32_t>;

    bool has(const std::string& id) const noexcept;
    const hpu::runtime::HpuMemAllocation& allocation(
        const std::string& id) const;
    Limb read(const std::string& id) const;
    void write(const std::string& id, const Limb& words);
    std::size_t limb_count(const std::string& prefix) const;
    std::uint32_t constant(
        const std::string& id, std::uint32_t modulus) const;

    Limb inverse_ntt(
        const Limb& words, std::size_t modulus_id,
        const std::string& twiddle_prefix) const;
    Limb forward_ntt(
        const Limb& coefficients, std::size_t modulus_id,
        const std::string& twiddle_prefix) const;

    void execute_plain(
        const BgvPlainOperationStep& step,
        const std::string& input_prefix,
        const std::string& output_prefix,
        std::size_t q_count);
    void execute_binary(
        const BgvPlainOperationStep& step,
        const std::string& input_prefix,
        const std::string& output_prefix,
        std::size_t q_count);
    void execute_multiply(
        const BgvPlainOperationStep& step,
        const std::string& input_prefix,
        const std::string& output_prefix,
        std::size_t q_count);
    void execute_rotation(
        const BgvPlainOperationStep& step,
        const std::string& input_prefix,
        const std::string& output_prefix,
        std::size_t q_count);
    void execute_modswitch(
        const BgvPlainOperationStep& step,
        const std::string& input_prefix,
        const std::string& output_prefix,
        std::size_t q_count);
    void execute_keyswitch(
        const std::string& resource_prefix,
        const std::string& output_prefix,
        std::size_t q_count);

    const ::seal::SEALContext& context_;
    const hpu::runtime::HpuMemImage& image_;
    std::size_t degree_ = 0;
    std::size_t key_modulus_count_ = 0;
    std::unordered_map<std::string, const hpu::runtime::HpuMemAllocation*>
        allocations_;
    hpu::runtime::HpuSoftwareExecutor memory_;
};

} // namespace hpu::seal_adapter
