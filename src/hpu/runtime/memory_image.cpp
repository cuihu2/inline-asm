#include "hpu/runtime/memory_image.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::runtime {

HpuMemImage::HpuMemImage(std::uint64_t capacity_lines)
    : capacity_lines_(capacity_lines)
{
    if (capacity_lines == 0
        || capacity_lines > std::numeric_limits<std::size_t>::max() / kHpuMemLineWords) {
        throw std::invalid_argument("HPU_MEM capacity is zero or too large for this host");
    }
}

HpuMemAllocation HpuMemImage::add(
    std::string id,
    const std::vector<std::uint32_t>& words,
    AllocationKind kind,
    bool read_only)
{
    return append(std::move(id), &words, words.size(), kind, read_only);
}

HpuMemAllocation HpuMemImage::reserve(
    std::string id,
    std::size_t word_count,
    AllocationKind kind)
{
    return append(std::move(id), nullptr, word_count, kind, false);
}

HpuMemAllocation HpuMemImage::append(
    std::string id,
    const std::vector<std::uint32_t>* words,
    std::size_t word_count,
    AllocationKind kind,
    bool read_only)
{
    if (id.empty() || word_count == 0) {
        throw std::invalid_argument("HPU_MEM allocation needs a name and nonzero payload");
    }
    if (allocation_indices_.count(id) != 0) {
        throw std::invalid_argument("duplicate HPU_MEM allocation: " + id);
    }
    if (word_count > std::numeric_limits<std::size_t>::max()
            - (kHpuMemLineWords - 1)) {
        throw std::overflow_error("HPU_MEM allocation size overflow");
    }
    const std::uint64_t line_count = static_cast<std::uint64_t>(
        (word_count + kHpuMemLineWords - 1) / kHpuMemLineWords);
    const std::uint64_t line_offset = used_lines();
    if (line_count > capacity_lines_ - line_offset) {
        throw std::overflow_error("HPU_MEM DDR window capacity exceeded");
    }

    HpuMemAllocation allocation;
    allocation.id = std::move(id);
    allocation.span = {line_offset, line_count};
    allocation.word_count = word_count;
    allocation.kind = kind;
    allocation.read_only = read_only;
    allocation_indices_.emplace(allocation.id, allocations_.size());
    allocations_.push_back(std::move(allocation));

    const std::size_t padded_words = static_cast<std::size_t>(line_count)
        * kHpuMemLineWords;
    if (words) {
        words_.insert(words_.end(), words->begin(), words->end());
        words_.resize(words_.size() + padded_words - word_count, 0);
    } else {
        words_.resize(words_.size() + padded_words, 0);
    }
    return allocations_.back();
}

const HpuMemAllocation& HpuMemImage::allocation(const std::string& id) const
{
    const auto found = allocation_indices_.find(id);
    if (found == allocation_indices_.end()) {
        throw std::out_of_range("unknown HPU_MEM allocation: " + id);
    }
    return allocations_[found->second];
}

const std::vector<HpuMemAllocation>& HpuMemImage::allocations() const noexcept
{
    return allocations_;
}

const std::vector<std::uint32_t>& HpuMemImage::words() const noexcept
{
    return words_;
}

std::uint64_t HpuMemImage::capacity_lines() const noexcept
{
    return capacity_lines_;
}

std::uint64_t HpuMemImage::used_lines() const noexcept
{
    return static_cast<std::uint64_t>(words_.size() / kHpuMemLineWords);
}

} // namespace hpu::runtime
