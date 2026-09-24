#include "hpu/seal/ckks_delivery.hpp"

#include "executable.hpp"

#include <bitset>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace hpu::seal_adapter {
namespace {

constexpr const char* kHardwareDirectory = "test_data/hardware";

std::string csv_field(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (char character : value) {
        if (character == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(character);
    }
    escaped.push_back('"');
    return escaped;
}

std::string json_string(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (unsigned char character : value) {
        switch (character) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (character < 0x20U) {
                throw std::invalid_argument(
                    "CKKS delivery metadata contains a control character");
            }
            escaped.push_back(static_cast<char>(character));
        }
    }
    escaped.push_back('"');
    return escaped;
}

const char* allocation_kind_name(hpu::runtime::AllocationKind kind)
{
    switch (kind) {
    case hpu::runtime::AllocationKind::modulus_table: return "modulus_table";
    case hpu::runtime::AllocationKind::constant: return "constant";
    case hpu::runtime::AllocationKind::ciphertext: return "ciphertext";
    case hpu::runtime::AllocationKind::plaintext: return "plaintext";
    case hpu::runtime::AllocationKind::evaluation_key: return "evaluation_key";
    case hpu::runtime::AllocationKind::twiddle: return "twiddle";
    case hpu::runtime::AllocationKind::workspace: return "workspace";
    case hpu::runtime::AllocationKind::output: return "output";
    }
    throw std::invalid_argument("unknown HPU_MEM allocation kind");
}

void write_text(
    const std::filesystem::path& path,
    const std::string& contents)
{
    std::ofstream output(path, std::ios::binary);
    if (!output || !(output << contents)) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

void write_u32_le(
    const std::filesystem::path& path,
    const std::uint32_t* words,
    std::size_t word_count)
{
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("failed to open " + path.string());
    }
    for (std::size_t index = 0; index < word_count; ++index) {
        const std::uint32_t word = words[index];
        const char bytes[4] {
            static_cast<char>(word & 0xffU),
            static_cast<char>((word >> 8U) & 0xffU),
            static_cast<char>((word >> 16U) & 0xffU),
            static_cast<char>((word >> 24U) & 0xffU)
        };
        output.write(bytes, sizeof(bytes));
    }
    if (!output) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

void write_u32_le(
    const std::filesystem::path& path,
    const std::vector<std::uint32_t>& words)
{
    write_u32_le(path, words.data(), words.size());
}

std::string render_line_map(const hpu::runtime::HpuMemImage& image)
{
    std::ostringstream output;
    output
        << "allocation_id,kind,read_only,line_offset,line_count,word_count,"
           "byte_offset,payload_bytes,padded_bytes\n";
    for (const auto& allocation : image.allocations()) {
        const std::uint64_t byte_offset = allocation.span.line_offset
            * hpu::runtime::kHpuMemLineWords * sizeof(std::uint32_t);
        const std::uint64_t padded_bytes = allocation.span.line_count
            * hpu::runtime::kHpuMemLineWords * sizeof(std::uint32_t);
        output << csv_field(allocation.id) << ','
               << allocation_kind_name(allocation.kind) << ','
               << (allocation.read_only ? 1 : 0) << ','
               << allocation.span.line_offset << ','
               << allocation.span.line_count << ','
               << allocation.word_count << ','
               << byte_offset << ','
               << allocation.word_count * sizeof(std::uint32_t) << ','
               << padded_bytes << '\n';
    }
    return output.str();
}

std::string render_memory_config(
    const std::string& stem,
    const hpu::runtime::HpuMemImage& image,
    const CkksRuntimeProgram& runtime)
{
    std::ostringstream output;
    output
        << "{\n"
        << "  \"format_version\": 1,\n"
        << "  \"scheme\": \"CKKS\",\n"
        << "  \"program_stem\": " << json_string(stem) << ",\n"
        << "  \"entry_point\": "
        << json_string("hpu_run_" + hpu::c_identifier(stem)) << ",\n"
        << "  \"image\": \"hpu_mem_image.u32.bin\",\n"
        << "  \"line_map\": \"line_map.csv\",\n"
        << "  \"byte_order\": \"little-endian\",\n"
        << "  \"word_bytes\": 4,\n"
        << "  \"line_words\": " << hpu::runtime::kHpuMemLineWords << ",\n"
        << "  \"line_bytes\": "
        << hpu::runtime::kHpuMemLineWords * sizeof(std::uint32_t) << ",\n"
        << "  \"image_used_lines\": " << image.used_lines() << ",\n"
        << "  \"hpu_mem_capacity_lines\": " << image.capacity_lines() << ",\n"
        << "  \"instruction_count\": " << runtime.instructions.size() << ",\n"
        << "  \"dma_count\": " << runtime.dma.size() << ",\n"
        << "  \"dma_offset_register\": \"x10\",\n"
        << "  \"dma_length_register\": \"x11\",\n"
        << "  \"dma_address_unit\": \"256-byte-line\"\n"
        << "}\n";
    return output.str();
}

std::string render_readme(const std::string& stem, bool has_expected_outputs)
{
    const std::string entry = "hpu_run_" + hpu::c_identifier(stem);
    std::ostringstream output;
    output
        << "# CKKS HPU application delivery\n\n"
        << "This directory is generated. `" << stem
        << ".c` contains fixed HPU instruction words and a resolved DMA span "
           "table. Compile it as part of a Nexus AM application and call `"
        << entry << "()` after loading `test_data/hardware/hpu_mem_image.u32.bin` "
           "into the configured HPU memory window.\n\n"
        << "DMA offsets and lengths use 256-byte lines. `x10` carries the line "
           "offset and `x11` carries the line count. See `dma_relocation_manifest.csv` "
           "and `test_data/hardware/line_map.csv` for the resolved mapping.\n";
    if (has_expected_outputs) {
        output
            << "\n`test_data/hardware/expected_outputs.csv` maps software-executor "
               "goldens to the HPU output spans. Each expected binary includes the "
               "complete line-padded span in little-endian uint32 format.\n";
    }
    return output.str();
}

} // namespace

void write_ckks_delivery_package(
    const std::filesystem::path& directory,
    const std::string& stem,
    const CkksLoweredProgram& lowered,
    const CkksRuntimeProgram& runtime,
    const CkksRuntimeArtifacts& artifacts,
    const hpu::runtime::HpuMemImage& image,
    const std::vector<std::uint32_t>* expected_image_words)
{
    if (directory.empty() || stem.empty()
        || std::filesystem::path(stem).filename().string() != stem
        || lowered.body_asm.empty() || runtime.instructions.empty()
        || artifacts.header.empty() || artifacts.source.empty()
        || artifacts.resolved_dma_manifest.empty()
        || image.words().empty()
        || image.words().size()
            != image.used_lines() * hpu::runtime::kHpuMemLineWords) {
        throw std::invalid_argument("incomplete CKKS delivery package");
    }
    if (expected_image_words
        && expected_image_words->size() != image.words().size()) {
        throw std::invalid_argument(
            "CKKS expected image differs in size from the initial HPU_MEM image");
    }

    std::filesystem::create_directories(directory);
    const std::filesystem::path hardware = directory / kHardwareDirectory;
    const std::filesystem::path expected_directory = hardware / "images";
    std::filesystem::create_directories(hardware);
    std::filesystem::remove_all(expected_directory);
    if (expected_image_words) {
        std::filesystem::create_directories(expected_directory);
    }

    const std::filesystem::path prefix = directory / stem;
    write_text(prefix.string() + ".asm", lowered.body_asm);

    std::string inst32;
    std::string command26;
    inst32.reserve(runtime.instructions.size() * 33);
    command26.reserve(runtime.instructions.size() * 27);
    for (const auto& instruction : runtime.instructions) {
        inst32 += std::bitset<32>(instruction.word).to_string() + '\n';
        command26 += std::bitset<26>(instruction.command26).to_string() + '\n';
    }
    write_text(prefix.string() + ".inst32", inst32);
    write_text(prefix.string() + ".cmd26", command26);
    write_text(prefix.string() + ".h", artifacts.header);
    write_text(prefix.string() + ".c", artifacts.source);
    write_text(
        directory / "dma_relocation_manifest.csv",
        artifacts.resolved_dma_manifest);

    write_u32_le(hardware / "hpu_mem_image.u32.bin", image.words());
    write_text(hardware / "line_map.csv", render_line_map(image));
    write_text(
        hardware / "hpu_mem_config.json",
        render_memory_config(stem, image, runtime));

    std::vector<std::filesystem::path> generated {
        prefix.filename().string() + ".asm",
        prefix.filename().string() + ".inst32",
        prefix.filename().string() + ".cmd26",
        prefix.filename().string() + ".h",
        prefix.filename().string() + ".c",
        "dma_relocation_manifest.csv",
        std::filesystem::path{kHardwareDirectory} / "hpu_mem_image.u32.bin",
        std::filesystem::path{kHardwareDirectory} / "line_map.csv",
        std::filesystem::path{kHardwareDirectory} / "hpu_mem_config.json"
    };

    if (expected_image_words) {
        std::ostringstream expected_map;
        expected_map
            << "path,allocation_id,line_offset,line_count,word_count,"
               "padded_words,byte_order\n";
        std::size_t output_index = 0;
        std::unordered_set<std::string> emitted_allocations;
        for (const auto& dma : runtime.dma) {
            if (dma.binding.direction != CkksDmaDirection::store
                || !emitted_allocations.insert(
                    dma.binding.allocation_id).second) {
                continue;
            }
            const auto& allocation = image.allocation(
                dma.binding.allocation_id);
            if (allocation.span.line_offset != dma.binding.span.line_offset
                || allocation.span.line_count != dma.binding.span.line_count) {
                throw std::logic_error(
                    "CKKS dstore binding differs from its HPU_MEM allocation");
            }
            const std::string filename = "expected_output_"
                + std::to_string(output_index++) + ".u32.bin";
            const std::size_t word_offset = static_cast<std::size_t>(
                allocation.span.line_offset * hpu::runtime::kHpuMemLineWords);
            const std::size_t padded_words = static_cast<std::size_t>(
                allocation.span.line_count * hpu::runtime::kHpuMemLineWords);
            if (word_offset > expected_image_words->size()
                || padded_words > expected_image_words->size() - word_offset) {
                throw std::logic_error(
                    "CKKS output allocation exceeds the expected image");
            }
            write_u32_le(
                expected_directory / filename,
                expected_image_words->data() + word_offset,
                padded_words);
            const auto relative = std::filesystem::path{kHardwareDirectory}
                / "images" / filename;
            generated.push_back(relative);
            expected_map << csv_field((std::filesystem::path{"images"}
                                      / filename).generic_string())
                         << ',' << csv_field(allocation.id) << ','
                         << allocation.span.line_offset << ','
                         << allocation.span.line_count << ','
                         << allocation.word_count << ','
                         << padded_words << ",little-endian\n";
        }
        if (output_index == 0) {
            throw std::invalid_argument(
                "CKKS expected image contains no output allocations");
        }
        write_text(hardware / "expected_outputs.csv", expected_map.str());
        generated.push_back(
            std::filesystem::path{kHardwareDirectory} / "expected_outputs.csv");
    }

    write_text(directory / "README.md", render_readme(stem, expected_image_words));
    generated.push_back("README.md");

    std::ostringstream manifest;
    manifest << "path,role,byte_count\n";
    for (const auto& relative : generated) {
        const auto path = directory / relative;
        std::string role = "artifact";
        if (relative.extension() == ".c" || relative.extension() == ".h") {
            role = "nexus_am_source";
        } else if (relative.filename() == "hpu_mem_image.u32.bin") {
            role = "initial_hpu_mem_image";
        } else if (relative.string().find("expected_output_") != std::string::npos) {
            role = "expected_output";
        }
        manifest << csv_field(relative.generic_string()) << ','
                 << role << ',' << std::filesystem::file_size(path) << '\n';
    }
    write_text(directory / "artifact_manifest.csv", manifest.str());
}

} // namespace hpu::seal_adapter
