#include "assembler.hpp"
#include "executable.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

std::size_t occurrences(const std::string& value, const std::string& needle)
{
    std::size_t count = 0;
    for (std::size_t at = 0; (at = value.find(needle, at)) != std::string::npos;
         at += needle.size()) ++count;
    return count;
}

struct Fixture {
    const std::string stem = "execution_profile_fixture";
    const std::vector<hpu::EncodedInstruction> instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\n"
        "pmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\n"
        "dload x10, x11, p1, 0, 0, 0\n"
        "psync\n"
        "pmul p2, p0, p1\n"
        "dstore x10, x11, p2, 0, 0\n"
        "pfree p0\n"
        "dload x10, x11, p0, 0, 0, 0\n"
        "psync\n" // An existing barrier does not split the timer.
        "padd p2, p2, p0\n"
        "pfree p0\n"
        "pfree p1\n"
        "psync\n"
        "dstore x10, x11, p2, 1, 0\n"
        "pfree p4\n"
        "psync\n");
    const std::vector<hpu::ExecutableDmaSpan> spans = {
        {0, 1}, {2, 2}, {4, 2}, {6, 2}, {8, 2}, {10, 2}};
    const hpu::ExecutionProfileWindow window{5, 13};
};

void expect_rejected(const std::vector<hpu::EncodedInstruction>& instructions,
                     const hpu::ExecutionProfileWindow& window,
                     const std::string& reason)
{
    try {
        hpu::validate_execution_profile_window(instructions, window);
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("execution profiling accepted " + reason);
}

void test_invalid_windows(const Fixture& fixture)
{
    expect_rejected(fixture.instructions, {0, 13}, "missing initial PSYNC");
    expect_rejected(fixture.instructions, {5, 5}, "empty window");
    expect_rejected(fixture.instructions, {6, 13}, "unbounded beginning");
    expect_rejected(fixture.instructions, {5, 12}, "unbounded end");
    expect_rejected(fixture.instructions, {5, 17}, "out-of-bounds end");
    expect_rejected(fixture.instructions, {5, 9}, "omitted later arithmetic");
    expect_rejected(fixture.instructions, {10, 13}, "omitted earlier arithmetic");
    expect_rejected(hpu::assemble_source(
        "dload x10, x11, p0, 0, 0, 0\npsync\npfree p0\npsync\n"),
        {2, 3}, "window without arithmetic");
    try {
        (void)hpu::render_profiled_executable_header("invalid", fixture.instructions,
                                                   fixture.spans.size() - 1, fixture.window);
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error("profile header accepted mismatched DMA count");
}

void test_source(const Fixture& fixture)
{
    const auto source = hpu::render_profiled_executable_source(
        fixture.stem, fixture.instructions, 64, fixture.spans, fixture.window);
    const auto header = hpu::render_profiled_executable_header(
        fixture.stem, fixture.instructions, fixture.spans.size(), fixture.window);
    require(header.find("hpu_execution_profile_sample_t *sample") != std::string::npos,
            "profile API must expose one sample");
    require(occurrences(source, "hooks->read_cycles(hooks->user)") == 2,
            "the whole program must have exactly one timestamp pair");
    require(occurrences(source, "__asm__ volatile(") == 4,
            "existing and boundary PSYNCs must be preserved");
    require(occurrences(source, "hooks->wait_complete(hooks->user,") == 4,
            "every PSYNC must wait for completion");
    require(occurrences(source, "li x10, ") == fixture.spans.size(),
            "x10 must be initialized for every DMA");
    require(occurrences(source, "li x11, ") == 4,
            "x11 must reset after callbacks and cache within indivisible asm");
    require(occurrences(source, "return -5;") == 2,
            "ordinary entries must reject profiling artifacts");
    const auto start = source.find("sample->start_cycles = hooks->read_cycles");
    const auto end = source.find("sample->end_cycles = hooks->read_cycles");
    const auto valid = source.find("sample->valid = 1;");
    require(source.find("hooks->wait_complete(hooks->user, 0)") < start &&
            start < source.find("hooks->wait_complete(hooks->user, 1)") &&
            source.find("hooks->wait_complete(hooks->user, 2)") < end &&
            end < source.find("hooks->wait_complete(hooks->user, 3)") &&
            source.find("hooks->wait_complete(hooks->user, 3)") < valid,
            "timing must exclude preload/drain and include existing internal wait");
    const std::regex word(R"(\.word (0x[0-9A-Fa-f]+))");
    std::size_t i = 0;
    for (auto it = std::sregex_iterator(source.begin(), source.end(), word);
         it != std::sregex_iterator(); ++it) {
        require(i < fixture.instructions.size() &&
                    std::stoul((*it)[1].str(), nullptr, 16) == fixture.instructions[i++].word,
                "profiling changed HPU instruction order or encoding");
    }
    require(i == fixture.instructions.size(), "profiling omitted instructions");
    require(hpu::render_execution_profile_manifest(fixture.instructions, fixture.window) ==
        "begin_instruction,end_instruction,arithmetic_instruction_count,dload_count,dstore_count\n"
        "5,13,2,1,1\n", "manifest must truthfully report DMA inside the continuous window");
}

void write_file(const std::filesystem::path& path, const std::string& contents)
{
    std::ofstream output(path, std::ios::binary);
    output << contents;
    require(static_cast<bool>(output), "cannot write " + path.string());
}

void write_fixture(const Fixture& fixture, const std::filesystem::path& root)
{
    std::filesystem::create_directories(root);
    write_file(root / (fixture.stem + ".h"), hpu::render_profiled_executable_header(
        fixture.stem, fixture.instructions, fixture.spans.size(), fixture.window));
    write_file(root / (fixture.stem + ".c"), hpu::render_profiled_executable_source(
        fixture.stem, fixture.instructions, 64, fixture.spans, fixture.window));
    write_file(root / "other_profile.h", hpu::render_profiled_executable_header(
        "other_profile", fixture.instructions, fixture.spans.size(), fixture.window));
    std::string words;
    for (const auto& item : fixture.instructions)
        words += std::to_string(item.word) + '\n';
    write_file(root / "words.txt", words);
    std::string dma;
    for (const auto& span : fixture.spans)
        dma += std::to_string(span.line_offset) + ',' + std::to_string(span.line_count) + '\n';
    write_file(root / "dma.csv", dma);
}

} // namespace

int main(int argc, char** argv)
{
    try {
        require(argc == 1 || argc == 3, "usage: hpu_execution_profile_codegen_test [--emit-fixtures DIR]");
        if (argc == 3) require(std::string(argv[1]) == "--emit-fixtures", "unknown option");
        const Fixture fixture;
        test_invalid_windows(fixture);
        test_source(fixture);
        if (argc == 3) write_fixture(fixture, argv[2]);
        std::cout << "Continuous execution profile codegen tests: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Continuous execution profile codegen tests failed: " << error.what() << '\n';
        return 1;
    }
}
