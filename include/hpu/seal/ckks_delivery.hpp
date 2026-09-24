#pragma once

#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_runtime.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

// Writes one self-contained CKKS application package. The initial image is the
// exact uint32 DDR contents consumed by the generated program. When
// expected_image_words is provided, every dstore destination is also exported
// as a software-executor golden for hardware comparison.
void write_ckks_delivery_package(
    const std::filesystem::path& directory,
    const std::string& stem,
    const CkksLoweredProgram& lowered,
    const CkksRuntimeProgram& runtime,
    const CkksRuntimeArtifacts& artifacts,
    const hpu::runtime::HpuMemImage& image,
    const std::vector<std::uint32_t>* expected_image_words = nullptr);

} // namespace hpu::seal_adapter
