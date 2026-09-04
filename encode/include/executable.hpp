#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "instruction.hpp"

namespace hpu {

inline constexpr std::uint32_t kSmallBankLineCount = 32;

struct DmaRelocation {
    std::size_t instruction_index = 0;
    std::size_t dma_index = 0;
    Mnemonic direction = Mnemonic::kDload;
    std::uint8_t object_id = 0;
    std::uint8_t type_or_release = 0;
    std::uint8_t flag = 0;
};

std::string c_identifier(std::string value);
std::vector<DmaRelocation> collect_dma_relocations(
    const std::vector<EncodedInstruction>& encoded);
void validate_executable_program(
    const std::vector<EncodedInstruction>& encoded);
std::string render_executable_header(
    const std::string& stem,
    std::size_t dma_count);
std::string render_executable_source(
    const std::string& stem,
    const std::vector<EncodedInstruction>& encoded,
    std::uint64_t hpu_mem_line_count);
std::string render_dma_manifest(
    const std::vector<EncodedInstruction>& encoded);

}  // namespace hpu
