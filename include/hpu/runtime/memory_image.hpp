#pragma once

#include "hpu/runtime/application.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace hpu::runtime {

constexpr std::size_t kHpuMemLineWords = 64;

enum class AllocationKind {
    modulus_table,
    ciphertext,
    plaintext,
    evaluation_key,
    twiddle,
    workspace,
    output
};

struct HpuMemAllocation {
    std::string id;
    HpuMemSpan span;
    std::size_t word_count = 0;
    AllocationKind kind = AllocationKind::workspace;
    bool read_only = false;
};

// Line-aligned, deterministic image of the DDR window visible to the HPU.
// Payloads are padded to complete 256-byte lines so each recorded span can be
// used directly by dload/dstore. The image owns no secret-key material.
class HpuMemImage {
public:
    explicit HpuMemImage(std::uint64_t capacity_lines);

    HpuMemAllocation add(
        std::string id,
        const std::vector<std::uint32_t>& words,
        AllocationKind kind,
        bool read_only = true);
    HpuMemAllocation reserve(
        std::string id,
        std::size_t word_count,
        AllocationKind kind);

    const HpuMemAllocation& allocation(const std::string& id) const;
    const std::vector<HpuMemAllocation>& allocations() const noexcept;
    const std::vector<std::uint32_t>& words() const noexcept;
    std::uint64_t capacity_lines() const noexcept;
    std::uint64_t used_lines() const noexcept;

private:
    HpuMemAllocation append(
        std::string id,
        const std::vector<std::uint32_t>* words,
        std::size_t word_count,
        AllocationKind kind,
        bool read_only);

    std::uint64_t capacity_lines_;
    std::vector<std::uint32_t> words_;
    std::vector<HpuMemAllocation> allocations_;
    std::unordered_map<std::string, std::size_t> allocation_indices_;
};

} // namespace hpu::runtime
