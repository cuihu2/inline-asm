#include "hpu/delivery/checksum.hpp"
#include "hpu/delivery/io.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h> // mkdtemp on macOS

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Exception, typename Function>
void require_throws_with_path(
    Function function,
    const std::string& path_fragment,
    const char* message)
{
    try {
        function();
    } catch (const Exception& error) {
        require(
            std::string(error.what()).find(path_fragment) != std::string::npos,
            "exception did not include path context");
        return;
    }
    throw std::runtime_error(message);
}

template <typename Exception, typename Function>
void require_throws_with_context(
    Function function,
    const std::string& first_fragment,
    const std::string& second_fragment,
    const char* message)
{
    try {
        function();
    } catch (const Exception& error) {
        const std::string detail = error.what();
        require(
            detail.find(first_fragment) != std::string::npos,
            "exception did not include the first path context");
        require(
            detail.find(second_fragment) != std::string::npos,
            "exception did not include the second path context");
        return;
    }
    throw std::runtime_error(message);
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("failed to read test file: " + path.string());
    }
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

class ScratchDirectory {
public:
    ScratchDirectory()
    {
        const std::string path_template =
            (std::filesystem::temp_directory_path()
             / "hpu_delivery_io_test_slice1.XXXXXX")
                .string();
        std::vector<char> mutable_template(
            path_template.begin(), path_template.end());
        mutable_template.push_back('\0');
        const char* const created = ::mkdtemp(mutable_template.data());
        if (created == nullptr) {
            throw std::runtime_error(
                "failed to create unique delivery IO test directory");
        }
        path_ = created;
    }

    ~ScratchDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const noexcept
    {
        return path_;
    }

    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;
    ScratchDirectory(ScratchDirectory&&) = delete;
    ScratchDirectory& operator=(ScratchDirectory&&) = delete;

private:
    std::filesystem::path path_;
};

void test_checksums_and_little_endian_rendering()
{
    require(
        hpu::delivery::fnv1a64_bytes({}) == 0xcbf29ce484222325ULL,
        "empty bytes did not produce the FNV-1a offset basis");
    require(
        hpu::delivery::fnv1a64_words32_le({}) == 0xcbf29ce484222325ULL,
        "empty words did not produce the FNV-1a offset basis");
    require(
        hpu::delivery::render_u32_le({}).empty(),
        "empty words did not render as empty bytes");

    const std::vector<std::uint8_t> hello = {'h', 'e', 'l', 'l', 'o'};
    require(
        hpu::delivery::fnv1a64_bytes(hello) == 0xa430d84680aabd0bULL,
        "FNV-1a bytes did not match the known hello vector");

    const std::vector<std::uint32_t> words = {0x01234567U, 0x89abcdefU};
    const std::string expected(
        "\x67\x45\x23\x01\xef\xcd\xab\x89", 8);
    require(
        hpu::delivery::render_u32_le(words) == expected,
        "uint32 words were not rendered as explicit little-endian bytes");
    require(
        hpu::delivery::fnv1a64_words32_le(words) == 0x5850c19868425c15ULL,
        "FNV-1a words did not hash their little-endian byte representation");

    const std::vector<std::uint64_t> wide_words = {0x0123456789abcdefULL};
    require(
        hpu::delivery::render_u64_le(wide_words)
            == std::string("\xef\xcd\xab\x89\x67\x45\x23\x01", 8),
        "uint64 words were not rendered as explicit little-endian bytes");
    require(
        hpu::delivery::fnv1a64_words64_le(wide_words)
            == 0x37eb3f3347761c55ULL,
        "FNV-1a uint64 words did not hash their little-endian byte representation");
}

void test_package_relative_paths()
{
    hpu::delivery::validate_package_relative_path("program/app.inst32");
    hpu::delivery::validate_package_relative_path("program/./app.inst32");

    require_throws_with_path<std::invalid_argument>(
        [] { hpu::delivery::validate_package_relative_path({}); },
        "path",
        "empty package path was accepted");
    require_throws_with_path<std::invalid_argument>(
        [] { hpu::delivery::validate_package_relative_path("/root/injected"); },
        "/root/injected",
        "absolute package path was accepted");
    require_throws_with_path<std::invalid_argument>(
        [] { hpu::delivery::validate_package_relative_path("../outside"); },
        "../outside",
        "parent directory escape was accepted");
    require_throws_with_path<std::invalid_argument>(
        [] {
            hpu::delivery::validate_package_relative_path(
                "program/../../outside");
        },
        "program/../../outside",
        "nested parent directory escape was accepted");
    require_throws_with_path<std::invalid_argument>(
        [] {
            hpu::delivery::validate_package_relative_path(
                "program/../outside");
        },
        "program/../outside",
        "parent directory alias was accepted");
}

void test_package_destination_resolution()
{
    ScratchDirectory scratch;
    const auto root = scratch.path() / "package-root";
    const auto outside = scratch.path() / "outside";
    std::filesystem::create_directories(root / "program");
    std::filesystem::create_directories(outside);

    const auto relative = std::filesystem::path("program/app.bin");
    const auto resolved =
        hpu::delivery::resolve_package_destination(root, relative);
    require(
        resolved == std::filesystem::weakly_canonical(root / relative),
        "ordinary package destination did not resolve inside its root");

    std::filesystem::create_directory_symlink(outside, root / "link");
    require_throws_with_context<std::invalid_argument>(
        [&] {
            hpu::delivery::resolve_package_destination(
                root, "link/evil.bin");
        },
        root.string(),
        "link/evil.bin",
        "package destination followed a symlink outside its root");

    require_throws_with_context<std::invalid_argument>(
        [&] { hpu::delivery::resolve_package_destination(root, {}); },
        root.string(),
        "<empty path>",
        "empty package destination was accepted");
    require_throws_with_context<std::invalid_argument>(
        [&] {
            hpu::delivery::resolve_package_destination(
                root, "/absolute/evil.bin");
        },
        root.string(),
        "/absolute/evil.bin",
        "absolute package destination was accepted");
    require_throws_with_context<std::invalid_argument>(
        [&] {
            hpu::delivery::resolve_package_destination(
                root, "program/../outside.bin");
        },
        root.string(),
        "program/../outside.bin",
        "package destination containing a parent component was accepted");

    const auto missing_root = scratch.path() / "missing-root";
    require_throws_with_context<std::invalid_argument>(
        [&] {
            hpu::delivery::resolve_package_destination(
                missing_root, "program/app.bin");
        },
        missing_root.string(),
        "program/app.bin",
        "missing package root was accepted");

    const auto file_root = scratch.path() / "root-is-file";
    std::ofstream(file_root) << "not a directory";
    require_throws_with_context<std::invalid_argument>(
        [&] {
            hpu::delivery::resolve_package_destination(
                file_root, "program/app.bin");
        },
        file_root.string(),
        "program/app.bin",
        "non-directory package root was accepted");
}

void test_atomic_writes()
{
    ScratchDirectory scratch;
    const auto root = scratch.path();

    const auto text_path = root / "text" / "nested" / "report.txt";
    const std::string text = "line one\nline two\n";
    hpu::delivery::write_text_atomic(text_path, text);
    require(
        read_file(text_path) == text,
        "atomic text write changed the requested bytes");

    const auto binary_path = root / "binary" / "payload.bin";
    const std::string binary("\x00\x01\x7f\x80\xff", 5);
    hpu::delivery::write_file_atomic(binary_path, binary);
    require(
        read_file(binary_path) == binary,
        "atomic binary write changed the requested bytes");

    const auto overwrite_path = root / "overwrite" / "artifact.bin";
    hpu::delivery::write_file_atomic(overwrite_path, "old trailing bytes");
    hpu::delivery::write_file_atomic(overwrite_path, "new");
    require(
        read_file(overwrite_path) == "new",
        "atomic write did not replace an existing file exactly");

    const auto repeat_path = root / "repeat" / "artifact.bin";
    hpu::delivery::write_file_atomic(repeat_path, binary);
    const std::string first = read_file(repeat_path);
    hpu::delivery::write_file_atomic(repeat_path, binary);
    require(
        read_file(repeat_path) == first,
        "repeated atomic writes were not byte-for-byte deterministic");

    const auto blocked_path = root / "blocked-target";
    std::filesystem::create_directory(blocked_path);
    std::ofstream(blocked_path / "keep") << "keep";
    require_throws_with_path<std::runtime_error>(
        [&] { hpu::delivery::write_file_atomic(blocked_path, "cannot replace"); },
        blocked_path.string(),
        "atomic writer accepted a directory as its target");

    const auto parent_file = root / "parent-is-file";
    std::ofstream(parent_file) << "keep";
    const auto child_of_file = parent_file / "artifact.bin";
    require_throws_with_path<std::runtime_error>(
        [&] { hpu::delivery::write_file_atomic(child_of_file, "cannot write"); },
        child_of_file.string(),
        "atomic writer accepted a regular file as its parent directory");

    std::vector<std::string> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            files.push_back(
                std::filesystem::relative(entry.path(), root).generic_string());
        }
    }
    std::sort(files.begin(), files.end());
    require(
        files == std::vector<std::string>{
            "binary/payload.bin",
            "blocked-target/keep",
            "overwrite/artifact.bin",
            "parent-is-file",
            "repeat/artifact.bin",
            "text/nested/report.txt"},
        "atomic writer left a temporary file behind");
}

void test_atomic_write_does_not_follow_foreign_temporary_symlink()
{
    ScratchDirectory scratch;
    const auto root = scratch.path();
    const auto destination = root / "publish" / "artifact.bin";
    std::filesystem::create_directories(destination.parent_path());

    const auto sentinel = root / "external-sentinel.bin";
    const std::string sentinel_contents = "must remain unchanged";
    std::ofstream(sentinel, std::ios::binary) << sentinel_contents;

    const auto foreign_temporary =
        destination.parent_path() / ".artifact.bin.tmp";
    std::filesystem::create_symlink(sentinel, foreign_temporary);

    const std::string published = "new package contents";
    hpu::delivery::write_file_atomic(destination, published);

    require(
        read_file(sentinel) == sentinel_contents,
        "atomic writer followed the foreign temporary symlink");
    require(
        std::filesystem::is_regular_file(
            std::filesystem::symlink_status(destination)),
        "atomic writer published a symlink instead of a regular file");
    require(
        read_file(destination) == published,
        "atomic writer published incorrect bytes beside a foreign symlink");
    require(
        std::filesystem::is_symlink(
            std::filesystem::symlink_status(foreign_temporary)),
        "atomic writer removed or replaced a foreign temporary symlink");
    require(
        std::filesystem::read_symlink(foreign_temporary) == sentinel,
        "atomic writer rewrote a foreign temporary symlink");
}

void test_directory_publication_never_replaces_empty_existing_target()
{
    ScratchDirectory scratch;
    const auto staging = scratch.path() / "staging";
    const auto target = scratch.path() / "target";
    std::filesystem::create_directory(staging);
    std::ofstream(staging / "marker", std::ios::binary) << "ours";
    std::filesystem::create_directory(target);
    require_throws_with_path<std::runtime_error>(
        [&] { hpu::delivery::publish_directory_noreplace(staging, target); },
        target.string(),
        "directory publisher replaced an existing empty target");
    require(
        std::filesystem::is_directory(target)
            && std::filesystem::is_empty(target),
        "directory publisher modified the existing empty target");
    require(read_file(staging / "marker") == "ours",
            "failed publication lost its staging directory");

    const auto new_target = scratch.path() / "new_target";
    hpu::delivery::publish_directory_noreplace(staging, new_target);
    require(read_file(new_target / "marker") == "ours",
            "directory publisher did not atomically publish to absent target");
    require(!std::filesystem::exists(staging),
            "successful publication retained the staging directory");
}

void test_concurrent_atomic_writes_publish_their_own_complete_content()
{
    ScratchDirectory scratch;
    const auto destination = scratch.path() / "concurrent" / "artifact.bin";
    std::filesystem::create_directories(destination.parent_path());

    const std::string first(512U * 1024U, 'A');
    const std::string second(512U * 1024U, 'B');
    for (int round = 0; round < 40; ++round) {
        std::atomic<int> ready{0};
        std::atomic<bool> start{false};
        std::array<std::string, 2> errors;

        const auto writer = [&](std::size_t index, const std::string& bytes) {
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            try {
                hpu::delivery::write_file_atomic(destination, bytes);
            } catch (const std::exception& error) {
                errors[index] = error.what();
            } catch (...) {
                errors[index] = "non-standard exception";
            }
        };

        std::thread first_writer(writer, 0U, std::cref(first));
        std::thread second_writer(writer, 1U, std::cref(second));
        while (ready.load(std::memory_order_acquire) != 2) {
            std::this_thread::yield();
        }
        start.store(true, std::memory_order_release);
        first_writer.join();
        second_writer.join();

        if (!errors[0].empty() || !errors[1].empty()) {
            throw std::runtime_error(
                "concurrent atomic write failed in round "
                + std::to_string(round) + ": first='" + errors[0]
                + "', second='" + errors[1] + "'");
        }
        const std::string actual = read_file(destination);
        require(
            actual == first || actual == second,
            "concurrent atomic writes published mixed or incorrect bytes");
    }
}

template <typename Function>
void run_test(
    const char* name,
    Function function,
    std::vector<std::string>& failures)
{
    try {
        function();
    } catch (const std::exception& error) {
        failures.push_back(std::string(name) + ": " + error.what());
    } catch (...) {
        failures.push_back(std::string(name) + ": non-standard exception");
    }
}

} // namespace

int main()
{
    std::vector<std::string> failures;
    run_test(
        "checksums and little-endian rendering",
        test_checksums_and_little_endian_rendering,
        failures);
    run_test(
        "package relative paths", test_package_relative_paths, failures);
    run_test(
        "package destination resolution",
        test_package_destination_resolution,
        failures);
    run_test("atomic writes", test_atomic_writes, failures);
    run_test(
        "foreign temporary symlink",
        test_atomic_write_does_not_follow_foreign_temporary_symlink,
        failures);
    run_test(
        "directory publication never replaces an existing target",
        test_directory_publication_never_replaces_empty_existing_target,
        failures);
    run_test(
        "concurrent atomic writes",
        test_concurrent_atomic_writes_publish_their_own_complete_content,
        failures);

    if (failures.empty()) {
        std::cout << "HPU delivery IO tests passed\n";
        return 0;
    }
    for (const auto& failure : failures) {
        std::cerr << "HPU delivery IO test failed: " << failure << '\n';
    }
    return 1;
}
