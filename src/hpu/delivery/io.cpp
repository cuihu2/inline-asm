#include "hpu/delivery/io.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <system_error>

#include <unistd.h>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#elif defined(__APPLE__)
#include <sys/stdio.h>
#endif

namespace hpu::delivery {
namespace {

std::string path_for_error(const std::filesystem::path& path)
{
    return path.empty() ? "<empty path>" : path.string();
}

std::runtime_error write_error(
    const std::filesystem::path& path,
    const std::string& detail)
{
    return std::runtime_error(
        "Failed to atomically write path '" + path_for_error(path)
        + "': " + detail);
}

class TemporaryFileCleanup {
public:
    ~TemporaryFileCleanup()
    {
        if (path_ != nullptr) {
            ::unlink(path_);
        }
    }

    TemporaryFileCleanup() = default;
    TemporaryFileCleanup(const TemporaryFileCleanup&) = delete;
    TemporaryFileCleanup& operator=(const TemporaryFileCleanup&) = delete;
    TemporaryFileCleanup(TemporaryFileCleanup&&) = delete;
    TemporaryFileCleanup& operator=(TemporaryFileCleanup&&) = delete;

    void adopt(const char* path) noexcept
    {
        path_ = path;
    }

    void release() noexcept
    {
        path_ = nullptr;
    }

private:
    const char* path_ = nullptr;
};

class FileDescriptor {
public:
    explicit FileDescriptor(int descriptor) noexcept
        : descriptor_(descriptor)
    {}

    ~FileDescriptor()
    {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
    }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&&) = delete;
    FileDescriptor& operator=(FileDescriptor&&) = delete;

    int get() const noexcept
    {
        return descriptor_;
    }

    int close() noexcept
    {
        const int descriptor = descriptor_;
        descriptor_ = -1;
        return ::close(descriptor);
    }

private:
    int descriptor_;
};

std::invalid_argument package_destination_error(
    const std::filesystem::path& root,
    const std::filesystem::path& relative,
    const std::string& detail)
{
    return std::invalid_argument(
        "Invalid package destination for root '" + path_for_error(root)
        + "' and relative path '" + path_for_error(relative) + "': "
        + detail);
}

bool has_component_prefix(
    const std::filesystem::path& path,
    const std::filesystem::path& prefix)
{
    auto path_component = path.begin();
    for (auto prefix_component = prefix.begin();
         prefix_component != prefix.end();
         ++prefix_component, ++path_component) {
        if (path_component == path.end()
            || *path_component != *prefix_component) {
            return false;
        }
    }
    return true;
}

} // namespace

std::string render_u32_le(const std::vector<std::uint32_t>& words)
{
    if (words.size() > std::string().max_size() / 4U) {
        throw std::runtime_error(
            "Cannot render uint32 words as little-endian bytes: size overflow");
    }

    std::string bytes;
    bytes.reserve(words.size() * 4U);
    for (const std::uint32_t word : words) {
        for (unsigned int byte = 0; byte < 4; ++byte) {
            bytes.push_back(static_cast<char>((word >> (byte * 8U)) & 0xffU));
        }
    }
    return bytes;
}

std::string render_u64_le(const std::vector<std::uint64_t>& words)
{
    if (words.size() > std::string().max_size() / 8U) {
        throw std::runtime_error(
            "Cannot render uint64 words as little-endian bytes: size overflow");
    }
    std::string bytes;
    bytes.reserve(words.size() * 8U);
    for (const std::uint64_t word : words) {
        for (unsigned int byte = 0; byte < 8; ++byte) {
            bytes.push_back(static_cast<char>((word >> (byte * 8U)) & 0xffU));
        }
    }
    return bytes;
}

void validate_package_relative_path(const std::filesystem::path& path)
{
    if (path.empty()) {
        throw std::invalid_argument(
            "Invalid package relative path '<empty path>': path must not be empty");
    }
    if (path.is_absolute() || path.has_root_path()
        || path.has_root_name() || path.has_root_directory()) {
        throw std::invalid_argument(
            "Invalid package relative path '" + path_for_error(path)
            + "': root path, root name, and root directory are forbidden");
    }

    for (const auto& component : path) {
        if (component == "..") {
            throw std::invalid_argument(
                "Invalid package relative path '" + path_for_error(path)
                + "': path must not contain a '..' component");
        }
    }
}

std::filesystem::path resolve_package_destination(
    const std::filesystem::path& root,
    const std::filesystem::path& relative)
{
    try {
        validate_package_relative_path(relative);
    } catch (const std::invalid_argument& error) {
        throw package_destination_error(root, relative, error.what());
    }

    std::error_code error;
    if (!std::filesystem::is_directory(root, error)) {
        const std::string detail = error
            ? "failed to inspect package root: " + error.message()
            : "package root does not exist or is not a directory";
        throw package_destination_error(root, relative, detail);
    }

    const std::filesystem::path canonical_root =
        std::filesystem::weakly_canonical(root, error);
    if (error) {
        throw package_destination_error(
            root,
            relative,
            "failed to canonicalize package root: " + error.message());
    }

    const std::filesystem::path destination =
        std::filesystem::weakly_canonical(canonical_root / relative, error);
    if (error) {
        throw package_destination_error(
            root,
            relative,
            "failed to canonicalize destination: " + error.message());
    }
    if (!has_component_prefix(destination, canonical_root)) {
        throw package_destination_error(
            root,
            relative,
            "destination resolves outside the package root");
    }
    return destination;
}

void write_file_atomic(
    const std::filesystem::path& path,
    const std::string& bytes)
{
    if (path.empty() || path.filename().empty()) {
        throw std::invalid_argument(
            "Invalid atomic write path '" + path_for_error(path)
            + "': a file name is required");
    }

    const std::filesystem::path parent = path.parent_path();
    if (!parent.empty()) {
        std::error_code error;
        std::filesystem::create_directories(parent, error);
        if (error) {
            throw write_error(
                path,
                "failed to create parent directory '" + parent.string()
                    + "': " + error.message());
        }
    }

    std::string temporary_template =
        (parent / ("." + path.filename().string() + ".tmp.XXXXXX")).string();
    TemporaryFileCleanup cleanup;
    const int descriptor = ::mkstemp(temporary_template.data());
    if (descriptor < 0) {
        const int error_number = errno;
        throw write_error(
            path,
            "failed to create unique temporary file '" + temporary_template
                + "': "
                + std::error_code(error_number, std::generic_category()).message());
    }
    cleanup.adopt(temporary_template.c_str());
    FileDescriptor output(descriptor);

    std::size_t written = 0;
    while (written < bytes.size()) {
        const std::size_t remaining = bytes.size() - written;
        const std::size_t chunk = std::min(
            remaining,
            static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t result =
            ::write(output.get(), bytes.data() + written, chunk);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int error_number = errno;
            throw write_error(
                path,
                "failed while writing temporary file '" + temporary_template
                    + "': "
                    + std::error_code(
                          error_number, std::generic_category()).message());
        }
        if (result == 0) {
            throw write_error(
                path,
                "write made no progress for temporary file '"
                    + temporary_template + "'");
        }
        written += static_cast<std::size_t>(result);
    }

    if (output.close() != 0) {
        const int error_number = errno;
        throw write_error(
            path,
            "failed to close temporary file '" + temporary_template + "': "
                + std::error_code(
                      error_number, std::generic_category()).message());
    }

    if (::rename(temporary_template.c_str(), path.c_str()) != 0) {
        const int error_number = errno;
        throw write_error(
            path,
            "failed to replace destination from temporary file '"
                + temporary_template + "': "
                + std::error_code(
                      error_number, std::generic_category()).message());
    }
    cleanup.release();
}

void publish_directory_noreplace(
    const std::filesystem::path& staging,
    const std::filesystem::path& destination)
{
#if defined(__linux__)
    const int result = static_cast<int>(::syscall(
        SYS_renameat2, AT_FDCWD, staging.c_str(),
        AT_FDCWD, destination.c_str(), RENAME_NOREPLACE));
#elif defined(__APPLE__)
    const int result = ::renamex_np(
        staging.c_str(), destination.c_str(), RENAME_EXCL);
#else
    throw std::runtime_error(
        "no supported atomic no-replace directory publication primitive");
#endif
#if defined(__linux__) || defined(__APPLE__)
    if (result != 0) {
        const int error = errno;
        throw std::runtime_error(
            "Failed to publish directory '" + path_for_error(staging)
            + "' to '" + path_for_error(destination) + "': "
            + std::error_code(error, std::generic_category()).message());
    }
#endif
}

void write_text_atomic(
    const std::filesystem::path& path,
    const std::string& text)
{
    write_file_atomic(path, text);
}

} // namespace hpu::delivery
