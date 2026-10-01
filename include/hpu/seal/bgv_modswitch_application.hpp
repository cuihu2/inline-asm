#pragma once

#include "hpu/runtime/memory_image.hpp"
#include "instruction.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct BgvModSwitchDmaBinding {
    std::size_t dma_index = 0;
    std::size_t instruction_index = 0;
    hpu::Mnemonic direction = hpu::Mnemonic::kDload;
    std::uint8_t object_slot = 0;
    std::uint8_t type_or_release = 0;
    std::uint8_t flag = 0;
    std::string allocation_id;
    hpu::runtime::HpuMemSpan span;
};

// A single SEAL-facing BGV ModSwitch with fully prepared HPU_MEM and resolved
// custom1 DMA spans. No SecretKey or CPU coefficient arithmetic enters image.
struct BgvModSwitchApplication {
    hpu::runtime::HpuMemImage image;
    ::seal::parms_id_type source_parms_id{};
    ::seal::parms_id_type destination_parms_id{};
    std::uint64_t correction_factor = 1;
    std::vector<hpu::EncodedInstruction> instructions;
    std::vector<BgvModSwitchDmaBinding> dma;

    std::vector<hpu::runtime::HpuMemSpan> spans() const;
};

struct BgvModSwitchRuntimeArtifacts {
    std::string header;
    std::string source;
    std::string resolved_dma_manifest;
};

BgvModSwitchApplication build_bgv_modswitch_application(
    const ::seal::SEALContext& context,
    const ::seal::Ciphertext& input,
    std::uint64_t capacity_lines);

BgvModSwitchRuntimeArtifacts render_bgv_modswitch_runtime_artifacts(
    const std::string& stem,
    const BgvModSwitchApplication& application);

} // namespace hpu::seal_adapter
