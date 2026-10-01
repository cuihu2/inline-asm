#include "hpu/delivery/checksum.hpp"

namespace hpu::delivery {
namespace {

constexpr std::uint64_t kFnv1a64OffsetBasis = 14695981039346656037ULL;
constexpr std::uint64_t kFnv1a64Prime = 1099511628211ULL;

void add_byte(std::uint64_t& hash, std::uint8_t byte) noexcept
{
    hash ^= byte;
    hash *= kFnv1a64Prime;
}

} // namespace

std::uint64_t fnv1a64_bytes(
    const std::vector<std::uint8_t>& bytes) noexcept
{
    std::uint64_t hash = kFnv1a64OffsetBasis;
    for (const std::uint8_t byte : bytes) {
        add_byte(hash, byte);
    }
    return hash;
}

std::uint64_t fnv1a64_words32_le(
    const std::vector<std::uint32_t>& words) noexcept
{
    std::uint64_t hash = kFnv1a64OffsetBasis;
    for (const std::uint32_t word : words) {
        for (unsigned int byte = 0; byte < 4; ++byte) {
            add_byte(
                hash,
                static_cast<std::uint8_t>((word >> (byte * 8U)) & 0xffU));
        }
    }
    return hash;
}

std::uint64_t fnv1a64_words64_le(
    const std::vector<std::uint64_t>& words) noexcept
{
    std::uint64_t hash = kFnv1a64OffsetBasis;
    for (const std::uint64_t word : words) {
        for (unsigned int byte = 0; byte < 8; ++byte) {
            add_byte(
                hash,
                static_cast<std::uint8_t>((word >> (byte * 8U)) & 0xffU));
        }
    }
    return hash;
}

} // namespace hpu::delivery
