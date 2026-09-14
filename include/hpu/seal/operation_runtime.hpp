#pragma once

#include "hpu/seal/operation_relocation.hpp"
#include "instruction.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct CkksRuntimeDma {
    std::size_t instruction_index = 0;
    CkksDmaBinding binding;
};

struct CkksRuntimeProgram {
    std::vector<hpu::EncodedInstruction> instructions;
    std::vector<CkksRuntimeDma> dma;

    std::vector<hpu::runtime::HpuMemSpan> spans() const;
};

struct CkksRuntimeArtifacts {
    std::string header;
    std::string source;
    std::string resolved_dma_manifest;
};

// Assembles the lowered body, validates executable object lifetimes, then
// matches every encoded custom1 instruction against the complete relocation
// schedule. The result is ordered exactly as the runtime consumes DMA spans.
CkksRuntimeProgram lower_ckks_runtime_program(
    const CkksLoweredProgram& lowered,
    const CkksRelocationSchedule& relocation);

// Emits the existing span-driven hpu_program_* function plus a fixed resolved
// span table and zero-argument hpu_run_* wrapper. The CSV retains both encoded
// instruction metadata and SEAL operation/allocation provenance.
CkksRuntimeArtifacts render_ckks_runtime_artifacts(
    const std::string& stem,
    const CkksRuntimeProgram& program,
    std::uint64_t hpu_mem_line_count);

} // namespace hpu::seal_adapter
