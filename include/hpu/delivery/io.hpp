#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace hpu::delivery {

std::string render_u32_le(const std::vector<std::uint32_t>& words);
std::string render_u64_le(const std::vector<std::uint64_t>& words);

void validate_package_relative_path(const std::filesystem::path& path);

// Resolves a validated relative path below an existing package root and rejects
// destinations that escape through resolvable symlinks at call time. Dangling
// symlinks may remain lexical, so package writers must consume this result only
// with write_file_atomic() inside a private staging root. The root must exist
// and be a directory. This function does not eliminate concurrent TOCTOU risk.
std::filesystem::path resolve_package_destination(
    const std::filesystem::path& root,
    const std::filesystem::path& relative);

void write_file_atomic(
    const std::filesystem::path& path,
    const std::string& bytes);

// Atomically publish a staged directory only if the destination name is absent.
// Fails closed on platforms without a no-replace directory rename primitive.
void publish_directory_noreplace(
    const std::filesystem::path& staging,
    const std::filesystem::path& destination);

void write_text_atomic(
    const std::filesystem::path& path,
    const std::string& text);

} // namespace hpu::delivery
