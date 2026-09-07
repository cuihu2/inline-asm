#pragma once

#include "hpu/runtime/memory_image.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace hpu::runtime {

enum class PointwiseOperation {
    add,
    subtract,
    multiply
};

// Functional executor for the HPU-visible DDR image. It models DMA payloads,
// the application-lifetime modulus table, and exact uint32 modular pointwise
// instructions. Regular-bank scheduling is tracked separately by Application.
class HpuSoftwareExecutor {
public:
    explicit HpuSoftwareExecutor(const HpuMemImage& image);

    void load_modulus_table(HpuMemSpan span, std::size_t modulus_count);
    std::uint32_t modulus(std::uint8_t modulus_id) const;

    std::vector<std::uint32_t> read(
        HpuMemSpan span,
        std::size_t word_count) const;
    void write(HpuMemSpan span, const std::vector<std::uint32_t>& words);
    void copy(HpuMemSpan destination, HpuMemSpan source, std::size_t word_count);
    void pointwise(
        HpuMemSpan destination,
        HpuMemSpan left,
        HpuMemSpan right,
        std::size_t word_count,
        std::uint8_t modulus_id,
        PointwiseOperation operation);
    void multiply_accumulate(
        HpuMemSpan accumulator,
        HpuMemSpan left,
        HpuMemSpan right,
        std::size_t word_count,
        std::uint8_t modulus_id);

    const std::vector<std::uint32_t>& words() const noexcept;

private:
    std::size_t checked_word_offset(
        HpuMemSpan span,
        std::size_t word_count) const;

    std::vector<std::uint32_t> words_;
    std::vector<std::uint32_t> moduli_;
    bool modulus_table_loaded_ = false;
};

} // namespace hpu::runtime
