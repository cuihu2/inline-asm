#pragma once

#include "hpu/seal/bfv_operation_relocation.hpp"
#include "instruction.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct BfvRuntimeDma {
    std::size_t instruction_index = 0;
    BfvDmaBinding binding;
};

struct BfvRuntimeProgram {
    std::vector<hpu::EncodedInstruction> instructions;
    std::vector<BfvRuntimeDma> dma;

    std::vector<hpu::runtime::HpuMemSpan> spans() const;
};

struct BfvRuntimeArtifacts {
    std::string header;
    std::string source;
    std::string resolved_dma_manifest;
};

// Assembles a fully relocated BFV plan and verifies that every encoded custom1
// DMA instruction agrees with its concrete HPU_MEM binding.
BfvRuntimeProgram lower_bfv_runtime_program(const BfvLoweredProgram& lowered,
                                            const BfvRelocationSchedule& relocation);

// Emits a span-driven hpu_program_* implementation, a fixed resolved span
// table, a zero-argument hpu_run_* wrapper, and the resolved DMA CSV.
BfvRuntimeArtifacts render_bfv_runtime_artifacts(const std::string& stem,
                                                 const BfvRuntimeProgram& program,
                                                 std::uint64_t hpu_mem_line_count);

} // namespace hpu::seal_adapter
