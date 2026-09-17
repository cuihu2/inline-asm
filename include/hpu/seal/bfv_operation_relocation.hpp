#pragma once

#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "util/hpu_asm.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

enum class BfvDmaDirection { load, store };

struct BfvDmaBinding {
    std::size_t program_dma_index = 0;
    std::optional<std::size_t> operation_index;
    std::size_t operation_dma_index = 0;
    std::string operation_id;
    BfvDmaDirection direction = BfvDmaDirection::load;
    int object_slot = 0;
    hpu::DataType load_type = hpu::DataType::poly;
    hpu::DloadFlag load_flag = hpu::DloadFlag::regular_bank;
    int store_release = 0;
    std::string allocation_id;
    hpu::runtime::HpuMemSpan span;
};

struct BfvRelocationSchedule {
    std::size_t expected_dma_count = 0;
    std::vector<BfvDmaBinding> bindings;

    bool complete() const noexcept
    {
        return bindings.size() == expected_dma_count;
    }
};

BfvRelocationSchedule build_bfv_relocation_schedule(const BfvLoweredProgram& program,
                                                    const hpu::runtime::HpuMemImage& image,
                                                    const ::seal::SEALContext& context);

} // namespace hpu::seal_adapter
