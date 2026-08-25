#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "assembler.hpp"
#include "executable.hpp"

namespace {

const std::vector<std::string> kEncodableOutputs{
    "ntt",
    "intt",
    "encode",
    "ckks_rescale",
    "ckks_ciphertext_multiply",
    "bgv_ciphertext_multiply",
    "bgv_modswitch",
    "mm",
    "bconv",
    "pmult",
    "cmult",
    "modup",
    "moddown",
    "keyswitch",
    "relinearization",
    "ciphertext_multiply",
    "auto",
};

const std::vector<std::string> kAllOutputs{
    "ntt",
    "intt",
    "encode",
    "ckks_rescale",
    "ckks_ciphertext_multiply",
    "bgv_ciphertext_multiply",
    "bgv_modswitch",
    "mm",
    "bconv",
    "pmult",
    "cmult",
    "modup",
    "moddown",
    "auto",
    "keyswitch",
    "relinearization",
    "ciphertext_multiply",
};

const std::vector<std::string> kSkippedOutputs{};

std::string read_all(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("failed to open input file: " + path.string());
    }
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

std::string format_word_bits(std::uint32_t word) {
    std::string bits;
    bits.reserve(32);
    for (int bit = 31; bit >= 0; --bit) {
        bits.push_back(((word >> bit) & 1U) ? '1' : '0');
    }
    return bits;
}

std::string format_command_bits(std::uint32_t command) {
    std::string bits;
    bits.reserve(26);
    for (int bit = 25; bit >= 0; --bit) {
        bits.push_back(((command >> bit) & 1U) ? '1' : '0');
    }
    return bits;
}

std::string csv_field(std::string value) {
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (char ch : value) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

void write_inst32(const std::filesystem::path& path,
                  const std::vector<hpu::EncodedInstruction>& encoded) {
    std::ofstream output(path);
    if (!output) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }

    for (const auto& item : encoded) {
        output << format_word_bits(item.word) << '\n';
    }
}

void write_cmd26(const std::filesystem::path& path,
                 const std::vector<hpu::EncodedInstruction>& encoded) {
    std::ofstream output(path);
    if (!output) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }

    for (const auto& item : encoded) {
        output << format_command_bits(item.command26) << '\n';
    }
}

void write_text(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream output(path);
    if (!output) {
        throw std::runtime_error("failed to open output file: " + path.string());
    }
    output << contents;
}

void package_case(const std::filesystem::path& source_root,
                  const std::filesystem::path& outputs_root,
                  const std::string& stem) {
    const auto case_dir = outputs_root / stem;
    std::filesystem::create_directories(case_dir / "test_data");

    for (const auto* extension : {".cpp", ".asm"}) {
        const auto source_path = source_root / (stem + extension);
        const auto target_path = case_dir / (stem + extension);
        if (!std::filesystem::exists(source_path)) {
            std::cout << "Skipped packaging " << source_path
                      << " (source file not generated)\n";
            continue;
        }

        std::filesystem::copy_file(
            source_path,
            target_path,
            std::filesystem::copy_options::overwrite_existing);
        std::cout << "Packaged " << source_path << " -> " << target_path << '\n';
    }
}

void encode_output(const std::filesystem::path& outputs_root,
                   const std::string& stem) {
    const auto case_dir = outputs_root / stem;
    const auto input_path = case_dir / (stem + ".asm");
    const auto output_path = case_dir / (stem + ".inst32");
    const auto command_path = case_dir / (stem + ".cmd26");
    const auto encoded = hpu::assemble_source(read_all(input_path));
    write_inst32(output_path, encoded);
    write_cmd26(command_path, encoded);
    const auto executable = hpu::render_executable_source(stem, encoded);
    const auto header = hpu::render_executable_header(
        stem, hpu::collect_dma_relocations(encoded).size());
    const auto manifest = hpu::render_dma_manifest(encoded);
    write_text(case_dir / (stem + ".cpp"), executable);
    write_text(case_dir / (stem + ".c"), executable);
    write_text(case_dir / (stem + ".h"), header);
    write_text(case_dir / "dma_relocation_manifest.csv", manifest);
    write_text(std::filesystem::path{"output"} / (stem + ".cpp"), executable);
    std::cout << "Encoded " << input_path << " -> " << output_path
              << ", " << command_path << " and executable .cpp ("
              << encoded.size() << " instructions, "
              << hpu::collect_dma_relocations(encoded).size() << " DMA relocations)\n";
}

void write_rv_interface_smoke(const std::filesystem::path& outputs_root) {
    const std::string source =
        "dload x10, x11, p0, 0, 0\n"
        "dload x10, x11, p1, 1, 0\n"
        "dload x10, x11, p4, 2, 1\n"
        "pmodld 255\n"
        "padd p2, p0, p1\n"
        "psub p2, p0, p1\n"
        "pmul p2, p0, p1\n"
        "pmul p2, p0, 255\n"
        "pmac p2, p0, p1\n"
        "pmac p2, p0, 255\n"
        "pntt p0, p3, 0, 0, 0\n"
        "pntt p0, p3, 15, 3, 1\n"
        "pintt p0, p3, 0, 0, 0\n"
        "pfree p5\n"
        "dstore x10, x11, p2, 0\n"
        "dstore x10, x11, p2, 1\n"
        "psync\n";

    const auto case_dir = outputs_root / "rv_interface_smoke";
    const auto test_data_dir = case_dir / "test_data";
    std::filesystem::create_directories(test_data_dir);
    {
        std::ofstream output(case_dir / "rv_interface_smoke.asm");
        output << source;
    }

    const auto encoded = hpu::assemble_source(source);
    write_inst32(case_dir / "rv_interface_smoke.inst32", encoded);
    write_cmd26(case_dir / "rv_interface_smoke.cmd26", encoded);

    std::ofstream decode(test_data_dir / "expected_decode.csv");
    decode << "index,word_hex,command26_hex,opcode_class,normalized_asm\n";
    std::ofstream command_decode(test_data_dir / "expected_cmd26.csv");
    command_decode
        << "index,command26_hex,custom_kind,command_payload25_hex,"
           "source_inst31_7_hex,normalized_asm\n";
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        const auto opcode = encoded[i].word & 0x7fU;
        const auto custom_kind = opcode == 0x2bU ? 1U : 0U;
        decode << i << ',' << hpu::format_word_hex(encoded[i].word) << ','
               << hpu::format_command26_hex(encoded[i].command26) << ','
               << (opcode == 0x0bU ? "custom0" : "custom1") << ','
               << csv_field(encoded[i].normalized_asm) << '\n';
        command_decode << i << ','
                       << hpu::format_command26_hex(encoded[i].command26) << ','
                       << custom_kind << ','
                       << hpu::format_command26_hex(
                              encoded[i].command26 & 0x1FFFFFFU) << ','
                       << hpu::format_command26_hex(encoded[i].word >> 7U) << ','
                       << csv_field(encoded[i].normalized_asm) << '\n';
    }

    std::ofstream negative(test_data_dir / "negative_cases.asm.txt");
    negative << "# Each line must be rejected by the assembler/verifier.\n"
             << "padd p8, p0, p1\n"
             << "padd p0, p1, 1\n"
             << "pmul p0, p1, 256\n"
             << "pntt p0, p1, 16, 0, 0\n"
             << "pntt p0, p1, 0, 4, 0\n"
             << "pntt p0, p1, 0, 0, 2\n"
             << "pmodld 256\n"
             << "pmodld -1\n"
             << "pmodld p0, 0, 0\n"
             << "pfree p8\n"
             << "pfree p0, 0, 0\n"
             << "pshcfg p0, 0, 0\n"
             << "pshuf p0, p1, 0, 0, 0\n"
             << "pseed 0\n"
             << "psample p0, p1, 0, 0, 0\n"
             << "psync 0, 0\n"
             << "dload x32, x0, p0, 0, 0\n"
             << "dload x0, x0, p0, 4, 0\n"
             << "dload x0, x0, p0, 3, 0\n"
             << "dload x0, x0, p0, 0\n"
             << "dload x0, x0, p0, 2, 2\n"
             << "dstore x0, x0, p0, 2\n"
             << "dstore x0, x0, p0, 1, 1\n";

    std::cout << "Generated RV interface smoke stream (" << encoded.size()
              << " instructions) in " << case_dir << '\n';
}

}  // namespace

int main() {
    try {
        const std::filesystem::path source_root{"output"};
        const std::filesystem::path outputs_root{"outputs"};
        std::filesystem::remove_all(outputs_root / "rescale");

        for (const auto& stem : kAllOutputs) {
            package_case(source_root, outputs_root, stem);
        }

        for (const auto& stem : kEncodableOutputs) {
            encode_output(outputs_root, stem);
        }

        for (const auto& stem : kSkippedOutputs) {
            std::cout << "Skipped " << outputs_root / stem / (stem + ".asm")
                      << " (contains symbolic DMA register placeholders)\n";
        }

        write_rv_interface_smoke(outputs_root);

        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << '\n';
        return 1;
    }
}
