#include "hpu/delivery/application_package.hpp"
#include "hpu/delivery/checksum.hpp"

#include "assembler.hpp"
#include "executable.hpp"
#include "hpu/runtime/memory_image.hpp"

#include <algorithm>
#include <cstdlib>
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Function>
void require_throws_with_fragments(
    Function function,
    const std::vector<std::string>& fragments,
    const char* message)
{
    try {
        function();
    } catch (const std::exception& error) {
        const std::string detail = error.what();
        for (const auto& fragment : fragments) {
            require(
                detail.find(fragment) != std::string::npos,
                "exception omitted required error context");
        }
        return;
    }
    throw std::runtime_error(message);
}

class ScratchDirectory {
public:
    ScratchDirectory()
    {
        const std::string path_template =
            (std::filesystem::temp_directory_path()
             / "hpu_application_package_test.XXXXXX")
                .string();
        std::vector<char> mutable_template(
            path_template.begin(), path_template.end());
        mutable_template.push_back('\0');
        const char* const created = ::mkdtemp(mutable_template.data());
        if (created == nullptr) {
            throw std::runtime_error(
                "failed to create application package test directory");
        }
        path_ = created;
    }

    ~ScratchDirectory()
    {
        std::error_code error;
        std::filesystem::remove_all(path_, error);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

    ScratchDirectory(const ScratchDirectory&) = delete;
    ScratchDirectory& operator=(const ScratchDirectory&) = delete;

private:
    std::filesystem::path path_;
};

struct Fixture {
    hpu::runtime::HpuMemImage image;
    hpu::delivery::ApplicationPackageRequest request;

    explicit Fixture(
        bool legacy_transform = false, unsigned cp = 0,
        hpu::runtime::AllocationKind input_kind = hpu::runtime::AllocationKind::plaintext,
        std::optional<unsigned> store_cp = std::nullopt,
        bool profile_execution = false)
        : image(legacy_transform ? 8 : 4)
    {
        std::string assembly;
        std::vector<hpu::runtime::HpuMemSpan> prefix_spans;
        std::vector<std::string> allocation_ids;
        if (legacy_transform) {
            const auto data = image.add(
                "legacy/data", std::vector<std::uint32_t>(128, 1),
                hpu::runtime::AllocationKind::ciphertext, true);
            const auto twiddle = image.add(
                "legacy/twiddle", std::vector<std::uint32_t>(64, 1),
                hpu::runtime::AllocationKind::twiddle, true);
            prefix_spans = {data.span, twiddle.span};
            allocation_ids = {"legacy/data", "legacy/twiddle"};
            assembly = "dload x10, x11, p1, 0, 0, 0\n"
                       "dload x10, x11, p2, 0, 0, 0\n"
                       "pntt p1, p2, 0, 0, 0\n"
                       "pfree p1\npfree p2\n";
        }
        const auto input = image.add(
            "input", {9, 8, 7, 6},
            input_kind, true);
        const auto output = image.reserve(
            "result", 4, hpu::runtime::AllocationKind::output);
        assembly += "dload x10, x11, p0, 0, " + std::to_string(cp) + ", 0\n";
        if (profile_execution) {
            require(!legacy_transform, "profile fixture cannot use legacy transforms");
            assembly += "psync\npadd p0, p0, p0\n"
                        "dstore x10, x11, p0, 0, 0\n"
                        "dload x10, x11, p1, 0, 0, 0\n"
                        "padd p0, p0, p1\npfree p1\npsync\n";
        }
        assembly += "dstore x10, x11, p0, 0, " + std::to_string(store_cp.value_or(cp)) + "\n"
                    "psync\n";
        const auto instructions = hpu::assemble_source(assembly);

        request.scheme = hpu::delivery::SchemeKind::ckks;
        request.case_name = "minimal_case";
        request.producer = {"inline-asm", "473f6ec", "clean"};
        request.initial_image = &image;
        request.program.stem = "minimal_app";
        request.program.assembly = assembly;
        request.program.instructions = instructions;
        request.program.header = hpu::render_executable_header(
            request.program.stem,
            hpu::collect_dma_relocations(instructions).size());
        request.program.source = hpu::render_executable_source(
            request.program.stem, instructions, image.capacity_lines());
        request.program.ordered_dma_spans = prefix_spans;
        request.program.ordered_dma_spans.insert(
            request.program.ordered_dma_spans.end(), {input.span});
        allocation_ids.push_back("input");
        if (profile_execution) {
            request.program.ordered_dma_spans.insert(
                request.program.ordered_dma_spans.end(), {output.span, output.span});
            allocation_ids.insert(allocation_ids.end(), {"result", "result"});
        }
        request.program.ordered_dma_spans.push_back(output.span);
        allocation_ids.push_back("result");
        if (profile_execution) {
            request.program.profile_execution = true;
            request.program.execution_profile = hpu::ExecutionProfileWindow{2, 7};
            request.program.header = hpu::render_profiled_executable_header(
                request.program.stem, instructions,
                request.program.ordered_dma_spans.size(), *request.program.execution_profile);
            std::vector<hpu::ExecutableDmaSpan> spans;
            for (const auto& span : request.program.ordered_dma_spans)
                spans.push_back({span.line_offset, span.line_count});
            request.program.source = hpu::render_profiled_executable_source(
                request.program.stem, instructions, image.capacity_lines(),
                spans, *request.program.execution_profile);
        }
        const auto relocations = hpu::collect_dma_relocations(instructions);
        std::ostringstream resolved;
        resolved << "instruction_index,dma_index,operation_index,operation_id,"
                    "operation_dma_index,direction,object_slot,type_or_release,flag,"
                    "allocation_id,line_offset,line_count,word_hex,normalized_asm,cp\n";
        for (std::size_t index = 0; index < relocations.size(); ++index) {
            const auto& dma = relocations[index];
            const auto& span = request.program.ordered_dma_spans[index];
            const auto& instruction = instructions[dma.instruction_index];
            resolved << dma.instruction_index << ',' << dma.dma_index << ",,copy,"
                     << index << ',' << hpu::to_string(dma.direction) << ','
                     << static_cast<unsigned>(dma.object_id) << ','
                     << static_cast<unsigned>(dma.type_or_release) << ','
                     << static_cast<unsigned>(dma.flag) << ','
                     << allocation_ids[index] << ','
                     << span.line_offset << ',' << span.line_count << ','
                     << hpu::format_word_hex(instruction.word) << ",\""
                     << instruction.normalized_asm << "\"," << unsigned(dma.cp) << "\n";
        }
        request.program.resolved_dma_manifest = resolved.str();
        request.outputs.push_back({
            "result", 0, 3, 17,
            hpu::delivery::OutputDomain::canonical_ntt_physical,
            output.span, 4, {1, 2, 3, 4}});
        request.parameters_json = "{\"poly_modulus_degree\":128}\n";
        request.operation_graph_json = "{\"operation\":\"copy\"}\n";
        request.oracle_report_json = "{\"status\":\"verified\"}\n";
        request.semantic_report = hpu::delivery::SemanticReport{
            "application/json", "{\"decoded\":[1,2,3,4]}\n"};
    }
};

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

void write_file(
    const std::filesystem::path& path,
    const std::string& contents)
{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(
        contents.data(),
        static_cast<std::streamsize>(contents.size()));
    output.close();
    require(static_cast<bool>(output), "failed to write test file");
}

std::vector<std::string> split_csv_row(const std::string& row)
{
    std::vector<std::string> fields;
    std::size_t begin = 0;
    for (;;) {
        const std::size_t comma = row.find(',', begin);
        fields.push_back(row.substr(begin, comma - begin));
        if (comma == std::string::npos) {
            return fields;
        }
        begin = comma + 1U;
    }
}

std::string join_csv_row(const std::vector<std::string>& fields)
{
    std::ostringstream output;
    for (std::size_t index = 0; index < fields.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << fields[index];
    }
    return output.str();
}

std::string hex64(std::uint64_t value)
{
    std::ostringstream output;
    output << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return output.str();
}

void update_csv_row(
    const std::filesystem::path& path,
    const std::string& row_id,
    const std::map<std::size_t, std::string>& replacements)
{
    std::istringstream input(read_file(path));
    std::ostringstream output;
    std::string line;
    bool replaced = false;
    while (std::getline(input, line)) {
        auto fields = split_csv_row(line);
        if (!fields.empty() && fields.front() == row_id) {
            for (const auto& replacement : replacements) {
                require(
                    replacement.first < fields.size(),
                    "CSV replacement field index is out of range");
                fields[replacement.first] = replacement.second;
            }
            line = join_csv_row(fields);
            replaced = true;
        }
        output << line << '\n';
    }
    require(replaced, "CSV row to update was not found");
    write_file(path, output.str());
}

void remove_csv_row(
    const std::filesystem::path& path,
    const std::string& row_id)
{
    std::istringstream input(read_file(path));
    std::ostringstream output;
    std::string line;
    bool removed = false;
    while (std::getline(input, line)) {
        const auto fields = split_csv_row(line);
        if (!fields.empty() && fields.front() == row_id) {
            removed = true;
            continue;
        }
        output << line << '\n';
    }
    require(removed, "CSV row to remove was not found");
    write_file(path, output.str());
}

void refresh_files_manifest_entry(
    const std::filesystem::path& package,
    const std::string& relative)
{
    const std::string contents = read_file(package / relative);
    const std::vector<std::uint8_t> hash_input(
        contents.begin(), contents.end());
    update_csv_row(
        package / "provenance/files.csv",
        relative,
        {{2, std::to_string(contents.size())},
         {3, hex64(hpu::delivery::fnv1a64_bytes(hash_input))}});
}

void store_u32_le(
    std::string& bytes,
    std::size_t word_index,
    std::uint32_t value)
{
    require(
        word_index < bytes.size() / sizeof(std::uint32_t),
        "test word index is outside binary file");
    const std::size_t offset = word_index * sizeof(std::uint32_t);
    for (unsigned byte = 0; byte < sizeof(std::uint32_t); ++byte) {
        bytes[offset + byte] = static_cast<char>(value >> (8U * byte));
    }
}

std::map<std::string, std::string> read_regular_tree(
    const std::filesystem::path& root)
{
    std::map<std::string, std::string> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
        if (entry.is_regular_file()) {
            const std::string relative =
                std::filesystem::relative(entry.path(), root).generic_string();
            files.emplace(relative, read_file(entry.path()));
        }
    }
    return files;
}

std::vector<std::uint32_t> decode_u32_le(const std::string& bytes)
{
    require(bytes.size() % 4U == 0U, "u32 file has a partial word");
    std::vector<std::uint32_t> words;
    words.reserve(bytes.size() / 4U);
    for (std::size_t index = 0; index < bytes.size(); index += 4U) {
        std::uint32_t word = 0;
        for (unsigned byte = 0; byte < 4U; ++byte) {
            word |= static_cast<std::uint32_t>(
                        static_cast<unsigned char>(bytes[index + byte]))
                << (8U * byte);
        }
        words.push_back(word);
    }
    return words;
}

std::string expected_bits(std::uint32_t value, unsigned width)
{
    std::string result;
    for (unsigned bit = width; bit != 0; --bit) {
        result.push_back(((value >> (bit - 1U)) & 1U) != 0U ? '1' : '0');
    }
    result.push_back('\n');
    return result;
}

void test_happy_path_package()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const std::filesystem::path package = scratch.path() / "minimal_case";

    const auto report = hpu::delivery::write_application_package(
        package, fixture.request);
    require(report.root == package, "package report root mismatch");
    require(!report.files.empty(), "package report omitted files");

    const std::vector<std::filesystem::path> required{
        "package.json",
        "metadata/parameters.json",
        "metadata/operation_graph.json",
        "program/minimal_app.c",
        "program/minimal_app.h",
        "program/minimal_app.asm",
        "program/minimal_app.inst32",
        "program/minimal_app.cmd26",
        "program/dma_relocation_manifest.csv",
        "memory/hpu_mem_image.u32.bin",
        "memory/line_map.csv",
        "memory/memory_manifest.csv",
        "memory/abi.json",
        "memory/hpu_mem_config.json",
        "golden/golden_manifest.csv",
        "golden/objects/result/c0/mod3.u32.bin",
        "oracle/report.json",
        "semantic/decoded.json",
        "provenance/build.json",
        "provenance/files.csv",
    };
    for (const auto& relative : required) {
        require(
            std::filesystem::is_regular_file(package / relative),
            ("missing required package file: " + relative.string()).c_str());
    }
    const auto abi = read_file(package / "memory/abi.json");
    require(abi.find("\"stage_twiddle_format\": \"hpu-twiddle-k8-v1\"") != std::string::npos
                && abi.find("\"twiddle_chains\": 8") != std::string::npos
                && abi.find("\"stage_parameter_lines\": 2") != std::string::npos,
            "package omitted the K=8 target twiddle ABI");
    hpu::delivery::validate_application_package_on_disk(package);
}

void test_cp_manifest_roundtrip_and_tampering()
{
    ScratchDirectory scratch;
    Fixture fixture(false, 1);
    const auto package = hpu::delivery::write_application_package(
        scratch.path() / "cp_allocating", fixture.request);
    hpu::delivery::validate_application_package_on_disk(package.root);
    for (const auto& dma : hpu::collect_dma_relocations(fixture.request.program.instructions))
        require(dma.cp == 1, "CP=1 was lost by assembly/relocation");

    const std::string relative = "program/dma_relocation_manifest.csv";
    update_csv_row(package.root / relative, "0", {{14, "0"}});
    refresh_files_manifest_entry(package.root, relative);
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
        {"DMA", "disagrees with the encoded program"},
        "validator accepted a re-signed cache policy unlike the instruction");
}

void test_twiddle_cache_policy_contract()
{
    using hpu::compiler::DmaCachePolicy;
    Fixture table(false, 1, hpu::runtime::AllocationKind::twiddle, 0);
    table.request.program.dma_cache_policy = DmaCachePolicy::twiddle_loads_only;
    ScratchDirectory scratch;
    const auto package = hpu::delivery::write_application_package(
        scratch.path() / "twiddle", table.request);
    hpu::delivery::validate_application_package_on_disk(package.root);
    require(read_file(package.root / "memory/abi.json").find(
                "\"dma_cache_policy\": \"twiddle_loads_only\"") != std::string::npos,
            "package omitted the declared DMA cache policy");

    Fixture missing_hint(false, 0, hpu::runtime::AllocationKind::twiddle);
    missing_hint.request.program.dma_cache_policy = DmaCachePolicy::twiddle_loads_only;
    Fixture bad_load(false, 1, hpu::runtime::AllocationKind::plaintext, 0);
    bad_load.request.program.dma_cache_policy = DmaCachePolicy::twiddle_loads_only;
    Fixture bad_store(false, 1, hpu::runtime::AllocationKind::twiddle, 1);
    bad_store.request.program.dma_cache_policy = DmaCachePolicy::twiddle_loads_only;
    for (const auto* fixture : {&missing_hint, &bad_load, &bad_store}) {
        require_throws_with_fragments(
            [&] { hpu::delivery::validate_application_package_request(fixture->request); },
            {"DMA cache policy mismatch"},
            "request validator accepted a DMA incompatible with its declared policy");
    }

    // Re-signing consistent instructions and CSV must not bypass data-kind validation.
    Fixture preserved(false, 1);
    const auto other = hpu::delivery::write_application_package(
        scratch.path() / "preserved", preserved.request);
    const auto abi_path = other.root / "memory/abi.json";
    const auto original_abi = read_file(abi_path);
    const std::string declaration = "  \"dma_cache_policy\": \"preserve\",\n";
    const auto position = original_abi.find(declaration);
    require(position != std::string::npos, "low-level package omitted preserve policy");
    for (const auto* policy : {"twiddle_loads_only", "unknown", ""}) {
        auto abi = original_abi;
        abi.replace(position, declaration.size(),
                    "  \"dma_cache_policy\": \"" + std::string(policy) + "\",\n");
        write_file(abi_path, abi);
        refresh_files_manifest_entry(other.root, "memory/abi.json");
        require_throws_with_fragments(
            [&] { hpu::delivery::validate_application_package_on_disk(other.root); },
            {"DMA cache policy"},
            "on-disk validator accepted a false or unknown cache policy declaration");
    }
    auto legacy_abi = original_abi;
    legacy_abi.erase(position, declaration.size());
    write_file(abi_path, legacy_abi);
    refresh_files_manifest_entry(other.root, "memory/abi.json");
    hpu::delivery::validate_application_package_on_disk(other.root);
}

void test_deterministic_generation()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto first = hpu::delivery::write_application_package(
        scratch.path() / "first", fixture.request);
    const auto second = hpu::delivery::write_application_package(
        scratch.path() / "second", fixture.request);

    require(
        read_regular_tree(first.root) == read_regular_tree(second.root),
        "same request produced different relative files or bytes");
    require(
        first.files == second.files,
        "same request produced different report file order");
    auto sorted = first.files;
    std::sort(sorted.begin(), sorted.end());
    require(
        first.files == sorted,
        "application package report files are not path-byte sorted");
}

void test_program_and_separate_golden_image()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "separation", fixture.request);

    std::string expected_inst32;
    std::string expected_cmd26;
    for (const auto& instruction : fixture.request.program.instructions) {
        expected_inst32 += expected_bits(instruction.word, 32);
        expected_cmd26 += expected_bits(instruction.command26, 26);
    }
    require(
        read_file(report.root / "program/minimal_app.inst32")
            == expected_inst32,
        ".inst32 did not exactly match fixture instruction words");
    require(
        read_file(report.root / "program/minimal_app.cmd26")
            == expected_cmd26,
        ".cmd26 did not exactly match fixture command26 values");

    const auto image_words = decode_u32_le(
        read_file(report.root / "memory/hpu_mem_image.u32.bin"));
    const auto& output = fixture.request.outputs.front();
    const std::size_t output_begin = static_cast<std::size_t>(
        output.destination.line_offset)
        * hpu::runtime::kHpuMemLineWords;
    require(
        image_words.size() == fixture.image.words().size(),
        "initial image did not contain exactly used line-padded words");
    require(
        std::all_of(
            image_words.begin()
                + static_cast<std::vector<std::uint32_t>::difference_type>(
                    output_begin),
            image_words.begin()
                + static_cast<std::vector<std::uint32_t>::difference_type>(
                    output_begin + output.word_count),
            [](std::uint32_t word) { return word == 0; }),
        "initial image output payload was backfilled with golden words");

    const auto golden_words = decode_u32_le(read_file(
        report.root / "golden/objects/result/c0/mod3.u32.bin"));
    require(
        golden_words.size()
            == output.destination.line_count
                * hpu::runtime::kHpuMemLineWords,
        "golden limb was not padded to its destination line span");
    require(
        std::equal(
            output.golden_words.begin(), output.golden_words.end(),
            golden_words.begin()),
        "golden limb payload did not contain the verified raw words");
    require(
        std::all_of(
            golden_words.begin()
                + static_cast<std::vector<std::uint32_t>::difference_type>(
                    output.word_count),
            golden_words.end(),
            [](std::uint32_t word) { return word == 0; }),
        "golden limb padding was not zero");
}

void test_scheme_neutral_writer_supports_bfv_and_bgv()
{
    ScratchDirectory scratch;
    const std::vector<std::pair<hpu::delivery::SchemeKind, std::string>> schemes{
        {hpu::delivery::SchemeKind::bfv, "bfv"},
        {hpu::delivery::SchemeKind::bgv, "bgv"},
    };
    for (const auto& scheme : schemes) {
        Fixture fixture;
        fixture.request.scheme = scheme.first;
        const auto report = hpu::delivery::write_application_package(
            scratch.path() / scheme.second, fixture.request);
        require(
            read_file(report.root / "package.json").find(
                "\"scheme\": \"" + scheme.second + "\"") != std::string::npos,
            "scheme-neutral descriptor did not preserve its scheme");
        hpu::delivery::validate_application_package_on_disk(report.root);
    }
}

void test_request_rejects_nonzero_initial_output()
{
    Fixture fixture;
    hpu::runtime::HpuMemImage nonzero_image(4);
    (void)nonzero_image.add(
        "input", {9, 8, 7, 6},
        hpu::runtime::AllocationKind::plaintext, true);
    (void)nonzero_image.add(
        "result", {5, 0, 0, 0},
        hpu::runtime::AllocationKind::output, false);
    fixture.request.initial_image = &nonzero_image;

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(
                fixture.request);
        },
        {"minimal_case", "result", "initial", "zero"},
        "nonzero initial output payload was accepted");
}

void test_request_rejects_wrong_golden_size()
{
    Fixture fixture;
    fixture.request.outputs.front().golden_words.pop_back();
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(
                fixture.request);
        },
        {"minimal_case", "result", "component 0", "MOD_ID 3", "word_count"},
        "wrong golden size was accepted");
}

void test_request_rejects_program_assembly_mismatch()
{
    Fixture fixture;
    fixture.request.program.assembly = "psync\n";
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(fixture.request);
        },
        {"minimal_case", "assembly", "instructions"},
        "request accepted instructions unrelated to assembly");
}

void test_request_rejects_dma_outside_used_image()
{
    Fixture fixture;
    fixture.request.program.ordered_dma_spans.front() = {3, 1};
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(fixture.request);
        },
        {"minimal_case", "DMA span 0", "used_lines"},
        "request accepted a DMA span beyond the serialized image");
}

void test_request_rejects_incorrect_dma_manifest()
{
    Fixture fixture;
    fixture.request.program.resolved_dma_manifest =
        "instruction_index,dma_index,operation_index,operation_id,"
        "operation_dma_index,direction,object_slot,type_or_release,flag,"
        "allocation_id,line_offset,line_count,word_hex,normalized_asm,cp\n";
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(fixture.request);
        },
        {"DMA", "manifest"},
        "request accepted a DMA manifest missing both relocations");
}

void test_validator_rejects_resigned_incorrect_dma_manifest()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "bad_dma_manifest", fixture.request);
    const std::string relative = "program/dma_relocation_manifest.csv";
    write_file(report.root / relative, "missing relocations\n");
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"DMA", "manifest"},
        "validator accepted a re-signed DMA manifest unrelated to the program");
}

void test_validator_rejects_resigned_dma_span_outside_named_allocation()
{
    ScratchDirectory scratch;
    Fixture fixture;
    fixture.image.reserve(
        "filler", 4, hpu::runtime::AllocationKind::workspace);
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "bad_dma_allocation", fixture.request);
    const std::string relative = "program/dma_relocation_manifest.csv";
    std::string manifest = read_file(report.root / relative);
    const std::string old_span = ",input,0,1,";
    const auto position = manifest.find(old_span);
    require(position != std::string::npos, "DMA fixture input span not found");
    manifest.replace(position, old_span.size(), ",input,2,1,");
    write_file(report.root / relative, manifest);
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"DMA", "allocation_id"},
        "validator accepted a DMA span outside its claimed input allocation");
}

void test_request_rejects_program_source_mismatch()
{
    Fixture fixture;
    fixture.request.program.source = "int unexpected(void) { return 0; }\n";
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(fixture.request);
        },
        {"program", "source"},
        "request accepted C source unrelated to encoded instructions");
}

void test_validator_rejects_resigned_program_source_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "bad_source", fixture.request);
    const std::string relative = "program/minimal_app.c";
    write_file(report.root / relative, "int unexpected(void) { return 0; }\n");
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"program", "source"},
        "validator accepted re-signed C source unrelated to encoded instructions");
}

void test_request_rejects_program_header_mismatch()
{
    Fixture fixture;
    fixture.request.program.header = "#define HPU_PROGRAM_MINIMAL_APP_DMA_COUNT 0\n";
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(fixture.request);
        },
        {"program", "header"},
        "request accepted a C header with a false DMA count");
}

void test_fixed_entry_compatibility_and_sideband_integrity()
{
    ScratchDirectory scratch;
    Fixture fixture;
    auto& program = fixture.request.program;
    const auto dynamic_source = program.source;
    const std::string marker = "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    program.header.insert(program.header.find(marker), "int hpu_run_minimal_app(void);\n\n");
    std::vector<hpu::ExecutableDmaSpan> spans;
    for (const auto& span : program.ordered_dma_spans)
        spans.push_back({span.line_offset, span.line_count});
    program.source = hpu::render_fixed_executable_source(
        program.stem, program.instructions, fixture.image.capacity_lines(), spans);
    const auto package = hpu::delivery::write_application_package(scratch.path() / "fixed", fixture.request);
    hpu::delivery::validate_application_package_on_disk(package.root);

    auto corrupt = program.source;
    const auto position = corrupt.find("li x11, 1");
    require(position != std::string::npos, "fixed fixture has no x11 setup");
    corrupt.replace(position, std::string("li x11, 1").size(), "li x11, 2");
    write_file(package.root / "program/minimal_app.c", corrupt);
    refresh_files_manifest_entry(package.root, "program/minimal_app.c");
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
        {"program", "source"}, "validator accepted re-signed incorrect fixed DMA operands");

    // Frozen example of the fixed-table wrapper emitted by earlier V1 tools.
    program.source = dynamic_source +
        "\nstatic const hpu_dma_span_t hpu_program_minimal_app_resolved_spans[] = {\n"
        "    { UINT32_C(0), UINT32_C(1) },\n"
        "    { UINT32_C(1), UINT32_C(1) },\n"
        "};\n\nint hpu_run_minimal_app(void) {\n"
        "    return hpu_program_minimal_app(\n"
        "        hpu_program_minimal_app_resolved_spans,\n"
        "        HPU_PROGRAM_MINIMAL_APP_DMA_COUNT);\n}\n";
    const auto legacy = hpu::delivery::write_application_package(scratch.path() / "legacy", fixture.request);
    hpu::delivery::validate_application_package_on_disk(legacy.root);
}

void test_rejects_incompatible_isa_and_stage_shape()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto package = hpu::delivery::write_application_package(
        scratch.path() / "target_abi", fixture.request);
    auto abi = read_file(package.root / "memory/abi.json");
    const std::string current = "hpu-objects64-v1.2";
    const auto position = abi.find(current);
    require(position != std::string::npos, "package omitted target instruction ISA");
    abi.replace(position, current.size(), "hpu-objects8-legacy");
    write_file(package.root / "memory/abi.json", abi);
    refresh_files_manifest_entry(package.root, "memory/abi.json");
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
        {"incompatible instruction ISA", "regenerate"},
        "validator accepted a re-signed package for an incompatible target ISA");

    // A consumer must not reinterpret REL0 according to incompatible metadata.
    abi = read_file(package.root / "memory/abi.json");
    const auto old_isa = abi.find("hpu-objects8-legacy");
    abi.replace(old_isa, std::string("hpu-objects8-legacy").size(), current);
    const auto rel = abi.find("\"dstore_rel0_retains\": true");
    require(rel != std::string::npos, "fixture omitted REL0 target metadata");
    abi.replace(rel, std::string("\"dstore_rel0_retains\": true").size(),
                "\"dstore_rel0_retains\": false");
    write_file(package.root / "memory/abi.json", abi);
    refresh_files_manifest_entry(package.root, "memory/abi.json");
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
        {"incompatible instruction ISA"},
        "validator accepted incompatible REL0 semantics");

    // Dynamic entry points must validate concrete stage shapes as strictly
    // as fixed entry points; a historical one-line N=128 table is invalid.
    Fixture wrong_stage(true);
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_request(wrong_stage.request); },
        {"fixed executable", "twiddles", "format"},
        "dynamic entry accepted a historical one-line stage table");
}

void test_validator_rejects_resigned_program_header_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "bad_header", fixture.request);
    const std::string relative = "program/minimal_app.h";
    write_file(report.root / relative,
               "#define HPU_PROGRAM_MINIMAL_APP_DMA_COUNT 0\n");
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"program", "header"},
        "validator accepted a re-signed C header with a false DMA count");
}

void test_validator_rejects_resigned_instruction_stream_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "instruction_mismatch", fixture.request);
    const std::string relative = "program/minimal_app.inst32";
    std::string stream = read_file(report.root / relative);
    require(!stream.empty(), "instruction fixture has no bits");
    stream[0] = stream[0] == '0' ? '1' : '0';
    write_file(report.root / relative, stream);
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"program", "inst32", "assembly"},
        "validator accepted an instruction stream unrelated to assembly");
}

void test_validator_rejects_resigned_invalid_json_descriptor()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "invalid_json", fixture.request);
    const std::string relative = "package.json";
    write_file(report.root / relative,
               "not-json\n" + read_file(report.root / relative));
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"package.json", "JSON"},
        "validator accepted an invalid JSON descriptor with matching file hash");
}

void test_validator_rejects_resigned_unknown_scheme()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "unknown_scheme", fixture.request);
    const std::string relative = "package.json";
    std::string descriptor = read_file(report.root / relative);
    const std::string original = "\"scheme\": \"ckks\"";
    const auto pos = descriptor.find(original);
    require(pos != std::string::npos,
            "package descriptor lacks expected scheme field");
    descriptor.replace(pos, original.size(), "\"scheme\": \"unrecognized\"");
    write_file(report.root / relative, descriptor);
    refresh_files_manifest_entry(report.root, relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"scheme", "unsupported"},
        "validator accepted a re-signed package with unknown scheme");
}

void test_validator_rejects_wrong_manifest_role()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "wrong_role", fixture.request);
    update_csv_row(
        report.root / "provenance/files.csv",
        "memory/hpu_mem_image.u32.bin", {{1, "golden"}});
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"memory/hpu_mem_image.u32.bin", "role"},
        "validator accepted an image mislabeled as a golden artifact");
}

void test_validator_rejects_resigned_invalid_utf8_json()
{
    ScratchDirectory scratch;
    const std::vector<std::string> invalid_bytes{
        std::string(1, static_cast<char>(0x80)),
        std::string("\xe0\x80\xaf", 3), // overlong slash
        std::string("\xed\xa0\x80", 3), // UTF-8 surrogate
        std::string("\xf4\x90\x80\x80", 4), // beyond U+10FFFF
    };
    const auto append_note = [&](
        const std::filesystem::path& package,
        const std::string& note) {
        const std::string relative = "package.json";
        std::string descriptor = read_file(package / relative);
        const auto closing = descriptor.rfind('}');
        require(closing != std::string::npos,
                "JSON descriptor does not have an object terminator");
        descriptor.insert(closing, ",\n  \"note\": \"" + note + "\"\n");
        write_file(package / relative, descriptor);
        refresh_files_manifest_entry(package, relative);
    };
    for (std::size_t index = 0; index < invalid_bytes.size(); ++index) {
        Fixture fixture;
        const auto report = hpu::delivery::write_application_package(
            scratch.path() / ("invalid_utf8_" + std::to_string(index)),
            fixture.request);
        append_note(report.root, invalid_bytes[index]);
        require_throws_with_fragments(
            [&] {
                hpu::delivery::validate_application_package_on_disk(
                    report.root);
            },
            {"package.json", "UTF-8"},
            "validator accepted invalid UTF-8 JSON after re-signing");
    }
    Fixture valid_fixture;
    const auto valid = hpu::delivery::write_application_package(
        scratch.path() / "valid_utf8", valid_fixture.request);
    append_note(valid.root, std::string("\xe4\xb8\xad", 3)); // 中
    hpu::delivery::validate_application_package_on_disk(valid.root);
}

void test_validator_rejects_tampered_golden()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "tampered", fixture.request);
    const std::filesystem::path golden =
        report.root / "golden/objects/result/c0/mod3.u32.bin";
    std::fstream file(golden, std::ios::in | std::ios::out | std::ios::binary);
    require(static_cast<bool>(file), "failed to open golden for corruption");
    char byte = 0;
    file.read(&byte, 1);
    require(file.gcount() == 1, "golden file was unexpectedly empty");
    byte = static_cast<char>(static_cast<unsigned char>(byte) ^ 0x01U);
    file.seekp(0);
    file.write(&byte, 1);
    file.close();

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"golden/objects/result/c0/mod3.u32.bin", "fnv1a64"},
        "validator accepted a one-byte golden corruption");
}

void test_validator_rejects_resigned_nonzero_initial_output()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_nonzero_output", fixture.request);
    const std::string image_relative = "memory/hpu_mem_image.u32.bin";
    std::string image = read_file(report.root / image_relative);
    const auto& output = fixture.request.outputs.front();
    const std::size_t word_index = static_cast<std::size_t>(
        output.destination.line_offset)
        * hpu::runtime::kHpuMemLineWords;
    store_u32_le(image, word_index, output.golden_words.front());
    write_file(report.root / image_relative, image);
    refresh_files_manifest_entry(report.root, image_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"output allocation", "result", "word 0", "zero"},
        "validator accepted a re-signed nonzero initial output word");
}

void test_validator_rejects_resigned_golden_span_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_golden_span", fixture.request);
    const std::string manifest_relative = "golden/golden_manifest.csv";
    const auto& output = fixture.request.outputs.front();
    update_csv_row(
        report.root / manifest_relative,
        output.object_id,
        {{6, std::to_string(output.destination.line_offset + 1U)}});
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"golden object", "result", "line_offset", "allocation"},
        "validator accepted a re-signed golden/allocation span mismatch");
}

void test_validator_rejects_resigned_noncanonical_golden_residue()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_noncanonical_golden", fixture.request);
    const std::string golden_relative =
        "golden/objects/result/c0/mod3.u32.bin";
    const std::string manifest_relative = "golden/golden_manifest.csv";
    const auto& output = fixture.request.outputs.front();
    std::string golden = read_file(report.root / golden_relative);
    store_u32_le(golden, 0, output.modulus);
    write_file(report.root / golden_relative, golden);

    const auto padded_words = decode_u32_le(golden);
    const std::vector<std::uint32_t> payload_words(
        padded_words.begin(),
        padded_words.begin()
            + static_cast<std::vector<std::uint32_t>::difference_type>(
                output.word_count));
    update_csv_row(
        report.root / manifest_relative,
        output.object_id,
        {{10, hex64(hpu::delivery::fnv1a64_words32_le(payload_words))},
         {11, hex64(hpu::delivery::fnv1a64_words32_le(padded_words))}});
    refresh_files_manifest_entry(report.root, golden_relative);
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"golden object", "result", "MOD_ID 3", "word 0", "modulus 17"},
        "validator accepted a re-signed noncanonical golden residue");
}

void test_validator_rejects_resigned_memory_manifest_hash_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_memory_hash", fixture.request);
    const std::string manifest_relative = "memory/memory_manifest.csv";
    update_csv_row(
        report.root / manifest_relative,
        "result",
        {{8, "0x0000000000000000"}});
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"memory manifest", "result", "payload_fnv1a64", "image"},
        "validator accepted a re-signed memory manifest/image hash mismatch");
}

void test_validator_rejects_resigned_line_map_span_mismatch()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_line_map_span", fixture.request);
    const std::string line_map_relative = "memory/line_map.csv";
    const auto& output = fixture.request.outputs.front();
    update_csv_row(
        report.root / line_map_relative,
        "result",
        {{3, std::to_string(output.destination.line_offset + 1U)}});
    refresh_files_manifest_entry(report.root, line_map_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"line_map", "result", "line_offset", "memory manifest"},
        "validator accepted a re-signed line_map/memory manifest span mismatch");
}

void test_validator_rejects_resigned_nonzero_output_padding()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_output_padding", fixture.request);
    const std::string image_relative = "memory/hpu_mem_image.u32.bin";
    const std::string manifest_relative = "memory/memory_manifest.csv";
    const auto& output = fixture.request.outputs.front();
    std::string image = read_file(report.root / image_relative);
    const std::size_t allocation_begin = static_cast<std::size_t>(
        output.destination.line_offset)
        * hpu::runtime::kHpuMemLineWords;
    store_u32_le(image, allocation_begin + output.word_count, 9);
    write_file(report.root / image_relative, image);

    const auto image_words = decode_u32_le(image);
    const auto padded_begin = image_words.begin()
        + static_cast<std::vector<std::uint32_t>::difference_type>(
            allocation_begin);
    const std::vector<std::uint32_t> padded_words(
        padded_begin,
        padded_begin
            + static_cast<std::vector<std::uint32_t>::difference_type>(
                output.destination.line_count
                * hpu::runtime::kHpuMemLineWords));
    update_csv_row(
        report.root / manifest_relative,
        "result",
        {{9, hex64(hpu::delivery::fnv1a64_words32_le(padded_words))}});
    refresh_files_manifest_entry(report.root, image_relative);
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"output allocation", "result", "word 4", "zero"},
        "validator accepted nonzero output padding with synchronized hashes");
}

void test_validator_rejects_resigned_nonzero_golden_padding()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "resigned_golden_padding", fixture.request);
    const std::string golden_relative =
        "golden/objects/result/c0/mod3.u32.bin";
    const std::string manifest_relative = "golden/golden_manifest.csv";
    const auto& output = fixture.request.outputs.front();
    std::string golden = read_file(report.root / golden_relative);
    store_u32_le(golden, output.word_count, 9);
    write_file(report.root / golden_relative, golden);
    const auto padded_words = decode_u32_le(golden);
    update_csv_row(
        report.root / manifest_relative,
        output.object_id,
        {{11, hex64(hpu::delivery::fnv1a64_words32_le(padded_words))}});
    refresh_files_manifest_entry(report.root, golden_relative);
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"golden object", "result", "padding word 4", "zero"},
        "validator accepted nonzero golden padding with synchronized hashes");
}

void test_validator_rejects_resigned_invalid_golden_domain_and_modulus()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto domain_report = hpu::delivery::write_application_package(
        scratch.path() / "invalid_golden_domain", fixture.request);
    const std::string manifest_relative = "golden/golden_manifest.csv";
    update_csv_row(
        domain_report.root / manifest_relative,
        "result",
        {{4, "unknown_domain"}});
    refresh_files_manifest_entry(domain_report.root, manifest_relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(
                domain_report.root);
        },
        {"golden object", "result", "domain"},
        "validator accepted an invalid re-signed golden domain");

    const auto modulus_report = hpu::delivery::write_application_package(
        scratch.path() / "invalid_golden_modulus", fixture.request);
    update_csv_row(
        modulus_report.root / manifest_relative,
        "result",
        {{3, "0"}});
    refresh_files_manifest_entry(modulus_report.root, manifest_relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(
                modulus_report.root);
        },
        {"golden object", "result", "modulus", "nonzero"},
        "validator accepted a zero re-signed golden modulus");
}

void test_validator_rejects_resigned_negative_u64()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "negative_line_offset", fixture.request);
    const std::string line_map_relative = "memory/line_map.csv";
    const std::string manifest_relative = "memory/memory_manifest.csv";
    update_csv_row(report.root / line_map_relative, "result", {{3, "-1"}});
    update_csv_row(report.root / manifest_relative, "result", {{3, "-1"}});
    refresh_files_manifest_entry(report.root, line_map_relative);
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"line_map", "line_offset", "-1"},
        "validator accepted a negative re-signed u64 field");
}

void test_validator_rejects_resigned_duplicate_allocation_id_and_span()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const std::string line_map_relative = "memory/line_map.csv";
    const std::string manifest_relative = "memory/memory_manifest.csv";
    const auto id_report = hpu::delivery::write_application_package(
        scratch.path() / "duplicate_allocation_id", fixture.request);
    update_csv_row(id_report.root / line_map_relative, "input", {{0, "result"}});
    update_csv_row(id_report.root / manifest_relative, "input", {{0, "result"}});
    refresh_files_manifest_entry(id_report.root, line_map_relative);
    refresh_files_manifest_entry(id_report.root, manifest_relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(id_report.root);
        },
        {"duplicate", "allocation_id", "result"},
        "validator accepted duplicate re-signed allocation IDs");

    const auto span_report = hpu::delivery::write_application_package(
        scratch.path() / "duplicate_allocation_span", fixture.request);
    update_csv_row(span_report.root / line_map_relative, "input", {{3, "1"}});
    update_csv_row(span_report.root / manifest_relative, "input", {{3, "1"}});
    refresh_files_manifest_entry(span_report.root, line_map_relative);
    refresh_files_manifest_entry(span_report.root, manifest_relative);
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(span_report.root);
        },
        {"allocation", "input", "overlaps", "result"},
        "validator accepted duplicate re-signed allocation spans");
}

void test_validator_rejects_resigned_empty_golden_set()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "empty_golden_set", fixture.request);
    const std::string golden_relative =
        "golden/objects/result/c0/mod3.u32.bin";
    const std::string manifest_relative = "golden/golden_manifest.csv";
    remove_csv_row(report.root / manifest_relative, "result");
    require(
        std::filesystem::remove(report.root / golden_relative),
        "failed to remove golden file for empty-set test");
    remove_csv_row(report.root / "provenance/files.csv", golden_relative);
    refresh_files_manifest_entry(report.root, manifest_relative);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"golden manifest", "at least one"},
        "validator accepted an empty re-signed golden set");
}

void test_validator_rejects_missing_required_file()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "missing", fixture.request);
    const std::filesystem::path required =
        report.root / "memory/abi.json";
    require(std::filesystem::remove(required), "failed to remove required file");
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"memory/abi.json", "required"},
        "validator accepted a missing required file");
}

void test_validator_rejects_extra_regular_file()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "extra", fixture.request);
    const std::string extra_bytes = "not declared";
    const std::filesystem::path extra = report.root / "unexpected.bin";
    std::ofstream output(extra, std::ios::binary);
    output << extra_bytes;
    output.close();
    require(static_cast<bool>(output), "failed to create extra regular file");
    const std::vector<std::uint8_t> hash_input(
        extra_bytes.begin(), extra_bytes.end());
    std::ostringstream manifest_row;
    manifest_row << "unexpected.bin,artifact," << extra_bytes.size()
                 << ",0x" << std::hex << std::setw(16) << std::setfill('0')
                 << hpu::delivery::fnv1a64_bytes(hash_input) << '\n';
    std::ofstream manifest(
        report.root / "provenance/files.csv",
        std::ios::binary | std::ios::app);
    manifest << manifest_row.str();
    manifest.close();
    require(static_cast<bool>(manifest), "failed to declare extra regular file");

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"unexpected.bin", "extra"},
        "validator accepted an extra regular file");
}

void test_validator_rejects_symlink()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "symlink", fixture.request);
    const std::filesystem::path link = report.root / "unexpected_link";
    std::filesystem::create_symlink("package.json", link);

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"unexpected_link", "symlink"},
        "validator accepted a package-tree symlink");
}

void test_writer_rejects_existing_target_without_removal()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const std::filesystem::path target = scratch.path() / "existing";
    std::filesystem::create_directory(target);
    const std::filesystem::path sentinel = target / "sentinel.txt";
    {
        std::ofstream output(sentinel, std::ios::binary);
        output << "keep me";
    }

    require_throws_with_fragments(
        [&] {
            (void)hpu::delivery::write_application_package(
                target, fixture.request);
        },
        {target.string(), "already exists"},
        "writer accepted an existing target root");
    require(
        read_file(sentinel) == "keep me",
        "writer modified or removed the existing target sentinel");

    const std::string staging_prefix = ".existing.staging.";
    for (const auto& entry : std::filesystem::directory_iterator(scratch.path())) {
        require(
            entry.path().filename().string().rfind(staging_prefix, 0) != 0,
            "writer left a private staging directory after rejection");
    }
}

void test_package_descriptor_contract()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "descriptor", fixture.request);
    const std::string descriptor = read_file(report.root / "package.json");
    const std::vector<std::string> required_fragments{
        "\"schema\": \"hpu-application-package\"",
        "\"schema_version\": 1",
        "\"scheme\": \"ckks\"",
        "\"case_name\": \"minimal_case\"",
        "\"word_bits\": 32",
        "\"line_words\": 64",
        "\"line_bytes\": 256",
        "\"byte_order\": \"little-endian\"",
        "\"parameters\": \"metadata/parameters.json\"",
        "\"operation_graph\": \"metadata/operation_graph.json\"",
        "\"program_source\": \"program/minimal_app.c\"",
        "\"program_header\": \"program/minimal_app.h\"",
        "\"program_asm\": \"program/minimal_app.asm\"",
        "\"program_inst32\": \"program/minimal_app.inst32\"",
        "\"program_cmd26\": \"program/minimal_app.cmd26\"",
        "\"dma_relocation_manifest\": "
            "\"program/dma_relocation_manifest.csv\"",
        "\"image\": \"memory/hpu_mem_image.u32.bin\"",
        "\"line_map\": \"memory/line_map.csv\"",
        "\"golden_manifest\": \"golden/golden_manifest.csv\"",
        "\"oracle_report\": \"oracle/report.json\"",
        "\"semantic_report\": \"semantic/decoded.json\"",
        "\"semantic_media_type\": \"application/json\"",
    };
    for (const auto& fragment : required_fragments) {
        require(
            descriptor.find(fragment) != std::string::npos,
            ("package descriptor omitted contract fragment: " + fragment).c_str());
    }
}

void test_validator_rejects_unknown_schema_version()
{
    ScratchDirectory scratch;
    Fixture fixture;
    const auto report = hpu::delivery::write_application_package(
        scratch.path() / "schema", fixture.request);
    const std::filesystem::path descriptor_path = report.root / "package.json";
    std::string descriptor = read_file(descriptor_path);
    const std::string current = "\"schema_version\": 1";
    const std::size_t position = descriptor.find(current);
    require(position != std::string::npos, "fixture schema_version was missing");
    descriptor.replace(position, current.size(), "\"schema_version\": 10");
    {
        std::ofstream output(descriptor_path, std::ios::binary | std::ios::trunc);
        output << descriptor;
    }
    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_on_disk(report.root);
        },
        {"package.json", "schema_version"},
        "validator accepted an unknown schema version");
}

void test_request_rejects_partial_dstore_to_read_only_allocation()
{
    Fixture fixture;
    hpu::runtime::HpuMemImage image(5);
    const std::vector<std::uint32_t> input_words(65, 1);
    const auto input = image.add(
        "wide_input", input_words,
        hpu::runtime::AllocationKind::plaintext, true);
    const auto output = image.reserve(
        "result", 4, hpu::runtime::AllocationKind::output);
    fixture.request.initial_image = &image;
    fixture.request.program.ordered_dma_spans = {
        input.span,
        {input.span.line_offset + 1, 1},
    };
    fixture.request.outputs.front().destination = output.span;

    require_throws_with_fragments(
        [&] {
            hpu::delivery::validate_application_package_request(
                fixture.request);
        },
        {"minimal_case", "DSTORE", "read_only", "wide_input"},
        "partial DSTORE into a read_only allocation was accepted");
}

void test_execution_profile_package_roundtrip_and_resigned_tampering()
{
    ScratchDirectory scratch;
    Fixture fixture(false, 0, hpu::runtime::AllocationKind::plaintext,
                    std::nullopt, true);
    const auto package = hpu::delivery::write_application_package(
        scratch.path() / "profile", fixture.request);
    const std::string relative = "profiling/execution_window.csv";
    const auto canonical = read_file(package.root / relative);
    require(canonical ==
        "begin_instruction,end_instruction,arithmetic_instruction_count,dload_count,dstore_count\n"
        "2,7,2,1,1\n", "profile package emitted wrong continuous window counts");
    require(read_file(package.root / "package.json").find(
        "\"execution_profile_manifest\": \"profiling/execution_window.csv\"")
        != std::string::npos, "profile package did not declare execution window");
    hpu::delivery::validate_application_package_on_disk(package.root);

    for (const std::string row : {"2,7,3,1,1\n", "2,7,2,0,1\n",
                                  "2,7,2,1,0\n", "0,7,2,1,1\n",
                                  "2,8,2,1,1\n", "02,7,2,1,1\n",
                                  "2,7,2,1,1\n2,7,2,1,1\n", ""}) {
        const auto header_end = canonical.find('\n') + 1;
        write_file(package.root / relative, canonical.substr(0, header_end) + row);
        refresh_files_manifest_entry(package.root, relative);
        require_throws_with_fragments(
            [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
            {}, "profile package accepted a re-signed incorrect execution window");
    }
    write_file(package.root / relative, canonical);
    refresh_files_manifest_entry(package.root, relative);

    const auto source_path = "program/minimal_app.c";
    auto unsafe_source = fixture.request.program.source;
    const std::string completion_wait = "hooks->wait_complete(hooks->user, 0)";
    const auto wait_position = unsafe_source.find(completion_wait);
    require(wait_position != std::string::npos,
            "profile source did not emit the preload completion wait");
    unsafe_source.replace(wait_position, completion_wait.size(), "0");
    write_file(package.root / source_path, unsafe_source);
    refresh_files_manifest_entry(package.root, source_path);
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_on_disk(package.root); },
        {"profiled", "source"},
        "profile package accepted a re-signed source inconsistent with its completion hooks");
    write_file(package.root / source_path, fixture.request.program.source);
    refresh_files_manifest_entry(package.root, source_path);
    hpu::delivery::validate_application_package_on_disk(package.root);

    fixture.request.program.profile_execution = false;
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_request(fixture.request); },
        {"execution window", "profile_execution"},
        "request accepted an execution window with profiling disabled");
    fixture.request.program.profile_execution = true;
    fixture.request.program.execution_profile.reset();
    require_throws_with_fragments(
        [&] { hpu::delivery::validate_application_package_request(fixture.request); },
        {"execution window", "profile_execution"},
        "request accepted profiling without an execution window");

    Fixture ordinary;
    const auto ordinary_package = hpu::delivery::write_application_package(
        scratch.path() / "ordinary", ordinary.request);
    require(!std::filesystem::exists(ordinary_package.root / relative),
            "default package unexpectedly acquired a profiling manifest");
    require(read_file(ordinary_package.root / "package.json").find("execution_profile_manifest")
            == std::string::npos,
            "default package unexpectedly declares profiling");
}

void test_native_writer_honors_execution_profile_option()
{
    namespace r = hpu::resource;
    using hpu::runtime::AllocationKind;
    hpu::runtime::HpuMemImage image(32);
    constexpr std::uint32_t modulus = 65537;
    constexpr std::uint64_t maximum = ~std::uint64_t{0};
    const std::uint64_t mu = maximum / modulus
        + ((maximum % modulus) + 1 >= modulus ? 1 : 0);
    std::vector<std::uint32_t> modulus_words(256, 0);
    modulus_words[0] = modulus;
    modulus_words[1] = static_cast<std::uint32_t>(mu);
    modulus_words[2] = static_cast<std::uint32_t>(mu >> 32U);
    const auto moduli = image.add("moduli", modulus_words, AllocationKind::modulus_table, true);
    const auto input = image.add("input", std::vector<std::uint32_t>(128, 3),
                                 AllocationKind::constant, true);
    const auto output = image.reserve("result", 128, AllocationKind::output);
    const auto table = r::make_operand("moduli"), data = r::make_operand("data");
    r::Recording recording;
    r::input(table, {0, "moduli", moduli.span}, hpu::DataType::mod_ctx,
             hpu::DloadFlag::small_bank);
    r::select_modulus(0);
    r::input(data, {0, "input", input.span}, hpu::DataType::seg);
    r::multiply_immediate(data, data, 2);
    r::output(data, {0, "result", output.span});
    r::finish_program();
    Fixture fixture;
    auto& request = fixture.request;
    request.initial_image = &image;
    request.program = {};
    request.program.stem = "automatic_profile";
    request.program.profile_execution = true;
    request.program.operator_program = std::make_shared<r::OperatorProgram>(recording.finish());
    request.outputs = {{"result", 0, 0, modulus,
        hpu::delivery::OutputDomain::canonical_ntt_physical, output.span, 128,
        std::vector<std::uint32_t>(128, 6)}};
    request.semantic_report.reset();
    const auto original_words = image.words();
    ScratchDirectory directory;
    const auto destination = directory.path() / "automatic_profile";
    hpu::delivery::write_application_package(destination, request);
    hpu::delivery::validate_application_package_on_disk(destination);
    require(std::filesystem::exists(destination / "profiling/execution_window.csv"),
            "native package writer silently ignored the execution profiling option");
    const auto report = read_file(destination / "oracle/report.json");
    require(report.find("\"timing_measured\":false") != std::string::npos
                && report.find("\"host_instruction_model_verified\":true") != std::string::npos,
            "native writer did not separate verified instructions from measured timing");
    require(image.words() == original_words && !request.program.resources_compiled
                && request.program.profile_execution && !request.program.execution_profile,
            "automatic profiling changed caller-owned memory or request");
}

void test_native_writer_preserves_caller()
{
    Fixture fixture;
    fixture.request.outputs.front().golden_words = {9, 8, 7, 6};
    const auto original_words = fixture.image.words();
    const auto original_spans = fixture.request.program.ordered_dma_spans;
    hpu::resource::Recording recording;
    hpu::resource::read(hpu::resource::value, hpu::DataType::seg);
    hpu::resource::publish(hpu::resource::value, 0);
    hpu::resource::finish_program();
    fixture.request.program.operator_program =
        std::make_shared<hpu::resource::OperatorProgram>(recording.finish());
    fixture.request.program.resource_dma = {
        {0, "input", original_spans[0], {}, "copy", 0},
        {1, "result", original_spans[1], {}, "copy", 1}};
    ScratchDirectory directory;
    const auto destination = directory.path() / "compiled";
    hpu::delivery::write_application_package(destination, fixture.request);
    hpu::delivery::validate_application_package_on_disk(destination);
    require(fixture.image.words() == original_words && !fixture.request.program.resources_compiled,
            "resource writer changed caller-owned memory or request");
    const auto report = read_file(destination / "oracle/report.json");
    require(report.find("\"ir_source\": \"operator\"") != std::string::npos &&
            report.find("\"host_instruction_model_verified\":true") != std::string::npos,
            "writer omitted native resource compilation or strict verification");
    require(read_file(destination / "memory/abi.json").find(
                "\"dma_cache_policy\": \"twiddle_loads_only\"") != std::string::npos,
            "native writer did not apply the default application cache policy");
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
    run_test("execution profile package roundtrip and re-signed tampering",
             test_execution_profile_package_roundtrip_and_resigned_tampering, failures);
    run_test("native writer honors execution profiling option",
             test_native_writer_honors_execution_profile_option, failures);
    run_test("native writer preserves caller", test_native_writer_preserves_caller, failures);
    run_test("twiddle cache policy contract", test_twiddle_cache_policy_contract, failures);
    run_test("happy path package", test_happy_path_package, failures);
    run_test(
        "deterministic generation", test_deterministic_generation, failures);
    run_test(
        "program and separate golden/image",
        test_program_and_separate_golden_image,
        failures);
    run_test(
        "scheme-neutral BFV/BGV package serialization",
        test_scheme_neutral_writer_supports_bfv_and_bgv,
        failures);
    run_test(
        "reject nonzero initial output",
        test_request_rejects_nonzero_initial_output,
        failures);
    run_test(
        "reject wrong golden size",
        test_request_rejects_wrong_golden_size,
        failures);
    run_test(
        "reject assembly mismatch",
        test_request_rejects_program_assembly_mismatch,
        failures);
    run_test(
        "reject DMA beyond used image",
        test_request_rejects_dma_outside_used_image,
        failures);
    run_test("CP manifest roundtrip and tampering", test_cp_manifest_roundtrip_and_tampering, failures);
    run_test(
        "reject incorrect DMA manifest at request boundary",
        test_request_rejects_incorrect_dma_manifest,
        failures);
    run_test(
        "reject re-signed incorrect DMA manifest",
        test_validator_rejects_resigned_incorrect_dma_manifest,
        failures);
    run_test(
        "reject re-signed DMA span outside named allocation",
        test_validator_rejects_resigned_dma_span_outside_named_allocation,
        failures);
    run_test(
        "reject mismatched C program source at request boundary",
        test_request_rejects_program_source_mismatch,
        failures);
    run_test(
        "reject re-signed mismatched C program source",
        test_validator_rejects_resigned_program_source_mismatch,
        failures);
    run_test(
        "reject mismatched C program header at request boundary",
        test_request_rejects_program_header_mismatch,
        failures);
    run_test(
        "fixed entry compatibility and DMA sideband integrity",
        test_fixed_entry_compatibility_and_sideband_integrity,
        failures);
    run_test(
        "reject incompatible target ISA and stage shapes",
        test_rejects_incompatible_isa_and_stage_shape,
        failures);
    run_test(
        "reject re-signed mismatched C program header",
        test_validator_rejects_resigned_program_header_mismatch,
        failures);
    run_test(
        "reject re-signed instruction stream mismatch",
        test_validator_rejects_resigned_instruction_stream_mismatch,
        failures);
    run_test(
        "reject re-signed invalid JSON descriptor",
        test_validator_rejects_resigned_invalid_json_descriptor,
        failures);
    run_test(
        "reject re-signed unknown scheme",
        test_validator_rejects_resigned_unknown_scheme,
        failures);
    run_test(
        "reject wrong role in file manifest",
        test_validator_rejects_wrong_manifest_role,
        failures);
    run_test(
        "reject re-signed invalid UTF-8 JSON",
        test_validator_rejects_resigned_invalid_utf8_json,
        failures);
    run_test(
        "reject tampered golden",
        test_validator_rejects_tampered_golden,
        failures);
    run_test(
        "reject re-signed nonzero initial output",
        test_validator_rejects_resigned_nonzero_initial_output,
        failures);
    run_test(
        "reject re-signed golden span mismatch",
        test_validator_rejects_resigned_golden_span_mismatch,
        failures);
    run_test(
        "reject re-signed noncanonical golden residue",
        test_validator_rejects_resigned_noncanonical_golden_residue,
        failures);
    run_test(
        "reject re-signed memory manifest hash mismatch",
        test_validator_rejects_resigned_memory_manifest_hash_mismatch,
        failures);
    run_test(
        "reject re-signed line_map span mismatch",
        test_validator_rejects_resigned_line_map_span_mismatch,
        failures);
    run_test(
        "reject re-signed nonzero output padding",
        test_validator_rejects_resigned_nonzero_output_padding,
        failures);
    run_test(
        "reject re-signed nonzero golden padding",
        test_validator_rejects_resigned_nonzero_golden_padding,
        failures);
    run_test(
        "reject invalid golden domain/modulus",
        test_validator_rejects_resigned_invalid_golden_domain_and_modulus,
        failures);
    run_test(
        "reject negative u64",
        test_validator_rejects_resigned_negative_u64,
        failures);
    run_test(
        "reject duplicate allocation ID/span",
        test_validator_rejects_resigned_duplicate_allocation_id_and_span,
        failures);
    run_test(
        "reject empty golden set",
        test_validator_rejects_resigned_empty_golden_set,
        failures);
    run_test(
        "reject missing required file",
        test_validator_rejects_missing_required_file,
        failures);
    run_test(
        "reject extra regular file",
        test_validator_rejects_extra_regular_file,
        failures);
    run_test("reject symlink", test_validator_rejects_symlink, failures);
    run_test(
        "reject existing target",
        test_writer_rejects_existing_target_without_removal,
        failures);
    run_test(
        "package descriptor contract",
        test_package_descriptor_contract,
        failures);
    run_test(
        "reject unknown schema version",
        test_validator_rejects_unknown_schema_version,
        failures);
    run_test(
        "reject partial DSTORE to read-only allocation",
        test_request_rejects_partial_dstore_to_read_only_allocation,
        failures);

    if (failures.empty()) {
        std::cout << "Application package tests: PASS\n";
        return 0;
    }
    for (const auto& failure : failures) {
        std::cerr << "Application package test failed: " << failure << '\n';
    }
    return 1;
}
