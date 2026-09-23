#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "hpu/seal/bfv_software_executor.hpp"
#include "scheme/bfv/galois.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* kArtifactStem = "bfv_rotation_application";
constexpr int kRowSteps = 2;

struct Options {
    bool print_asm = false;
    std::optional<std::filesystem::path> emit_directory;
};

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Options parse_options(int argc, char** argv)
{
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--print-asm") {
            options.print_asm = true;
        } else if (argument == "--emit-dir" && index + 1 < argc) {
            options.emit_directory = std::filesystem::path(argv[++index]);
        } else {
            throw std::invalid_argument("usage: hpu_bfv_rotation_example "
                                        "[--print-asm] [--emit-dir PATH]");
        }
    }
    return options;
}

void write_text(const std::filesystem::path& path, const std::string& contents)
{
    std::ofstream output(path);
    if (!output || !(output << contents)) {
        throw std::runtime_error("failed to write " + path.string());
    }
}

void emit_artifacts(const std::filesystem::path& directory,
                    const hpu::seal_adapter::BfvLoweredProgram& lowered,
                    const hpu::seal_adapter::BfvRuntimeProgram& runtime,
                    const hpu::seal_adapter::BfvRuntimeArtifacts& artifacts,
                    const hpu::runtime::HpuMemImage& image)
{
    std::filesystem::create_directories(directory);
    const std::filesystem::path prefix = directory / kArtifactStem;
    write_text(prefix.string() + ".asm", lowered.body_asm);

    std::string inst32;
    std::string command26;
    for (const auto& instruction : runtime.instructions) {
        inst32 += std::bitset<32>(instruction.word).to_string() + '\n';
        command26 += std::bitset<26>(instruction.command26).to_string() + '\n';
    }
    write_text(prefix.string() + ".inst32", inst32);
    write_text(prefix.string() + ".cmd26", command26);
    write_text(prefix.string() + ".h", artifacts.header);
    write_text(prefix.string() + ".c", artifacts.source);
    write_text(prefix.string() + ".resolved_dma.csv", artifacts.resolved_dma_manifest);

    const auto image_path = prefix.string() + ".hpu_mem.u32.bin";
    std::ofstream image_output(image_path, std::ios::binary);
    const auto& words = image.words();
    image_output.write(reinterpret_cast<const char*>(words.data()),
                       static_cast<std::streamsize>(words.size() * sizeof(std::uint32_t)));
    if (!image_output) {
        throw std::runtime_error("failed to write " + image_path);
    }
}

void require_exact(const ::seal::Ciphertext& oracle,
                   const hpu::seal_adapter::PreparedBfvRnsObject& output,
                   const hpu::seal_adapter::BfvSoftwareExecutor& executor)
{
    require(oracle.parms_id() == output.parms_id && oracle.size() == output.components.size(),
            "BFV rotation example produced incorrect output metadata");
    for (std::size_t component = 0; component < oracle.size(); ++component) {
        const auto actual = executor.export_component(output, component);
        require(std::equal(actual.words.begin(), actual.words.end(), oracle.data(component)),
                "BFV rotation example differs from modified-SEAL coefficients");
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const Options options = parse_options(argc, argv);

        // Teaching-sized parameters; the application API is independent of N.
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        spec.plain_modulus_bits = 17;
        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);
        const auto row_element = hpu::scheme::bfv::row_rotation_galois_element(
            spec.poly_modulus_degree, kRowSteps);
        const auto column_element = hpu::scheme::bfv::column_rotation_galois_element(
            spec.poly_modulus_degree);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::GaloisKeys galois_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{row_element, column_element}, galois_keys);

        ::seal::BatchEncoder encoder(*bundle.context);
        const std::size_t slot_count = encoder.slot_count();
        const std::size_t row_size = slot_count / 2;
        std::vector<std::uint64_t> slots(slot_count);
        std::vector<std::uint64_t> expected_slots(slot_count);
        for (std::size_t index = 0; index < slot_count; ++index) {
            slots[index] = (3 * index + 1) % bundle.plain_modulus;
        }
        for (std::size_t index = 0; index < slot_count; ++index) {
            const std::size_t row = index / row_size;
            const std::size_t column = index % row_size;
            const auto rotated = slots[row * row_size + (column + kRowSteps) % row_size];
            const auto swapped = slots[(1 - row) * row_size + column];
            expected_slots[index] = (rotated + swapped) % bundle.plain_modulus;
        }

        ::seal::Plaintext plaintext;
        encoder.encode(slots, plaintext);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted;
        encryptor.encrypt(plaintext, encrypted);

        // Independent modified-SEAL oracle for the complete expression.
        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext row_oracle;
        ::seal::Ciphertext column_oracle;
        ::seal::Ciphertext oracle;
        evaluator.rotate_rows(encrypted, kRowSteps, galois_keys, row_oracle);
        evaluator.rotate_columns(encrypted, galois_keys, column_oracle);
        evaluator.add(row_oracle, column_oracle, oracle);
        ::seal::Decryptor decryptor(*bundle.context, key_generator.secret_key());
        ::seal::Plaintext decrypted;
        decryptor.decrypt(oracle, decrypted);
        std::vector<std::uint64_t> oracle_slots;
        encoder.decode(decrypted, oracle_slots);
        require(oracle_slots == expected_slots,
                "modified-SEAL rotation oracle produced incorrect batching slots");

        // All Galois keys, twiddles, constants, and key-domain workspaces are
        // prepared before planning. SecretKey never enters HPU_MEM.
        hpu::seal_adapter::BfvApplicationImageBuilder image_builder(*bundle.context, 8192);
        image_builder.add_modulus_table();
        const auto canonical_twiddles = image_builder.add_canonical_twiddles();
        const auto& level = image_builder.level_chain().top();
        const auto input = image_builder.add_ciphertext("input/x", encrypted);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants("constants/keyswitch/top", level);
        const auto row_key = image_builder.add_row_rotation_key(
            "key/rotate_rows_2/top", galois_keys, kRowSteps, level);
        const auto column_key = image_builder.add_column_rotation_key(
            "key/rotate_columns/top", galois_keys, level);
        const auto row_twiddles = image_builder.add_row_rotation_twiddles(
            "rotate_rows_2/top", kRowSteps, level);
        const auto column_twiddles = image_builder.add_column_rotation_twiddles(
            "rotate_columns/top", level);
        const auto row_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_rows_2", level, 2,
            hpu::runtime::PolynomialDomain::coefficient, row_element);
        const auto column_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_columns", level, 2,
            hpu::runtime::PolynomialDomain::coefficient, column_element);

        // Two independent branches return coefficient-domain ciphertexts at
        // the same level, so ordinary BFV Add can join them directly.
        hpu::seal_adapter::BfvOperationPlan plan(image_builder);
        const auto row_output = plan.append_rotate_rows(
            "rotate_rows_2", input, kRowSteps, row_key, keyswitch_constants,
            row_twiddles, row_workspace, "intermediate/rows");
        const auto column_output = plan.append_rotate_columns(
            "rotate_columns", input, column_key, keyswitch_constants,
            column_twiddles, column_workspace, "intermediate/columns");
        const auto output = plan.append_add("add", row_output, column_output, "output/y");
        require(plan.steps().size() == 3 && output.parms_id == level.parms_id &&
                    output.key_domain == 1,
                "BFV rotation example planner produced the wrong graph");

        // Functional execution consumes exactly the prepared HPU_MEM image.
        hpu::seal_adapter::BfvSoftwareExecutor executor(*bundle.context, image_builder.image());
        executor.rotate_rows(input, kRowSteps, row_key, keyswitch_constants, row_twiddles,
                             canonical_twiddles, row_workspace, row_output);
        executor.rotate_columns(input, column_key, keyswitch_constants, column_twiddles,
                                canonical_twiddles, column_workspace, column_output);
        executor.add(row_output, column_output, output);
        require_exact(oracle, output, executor);

        const auto lowered = hpu::seal_adapter::lower_bfv_operation_plan(plan, *bundle.context);
        const auto relocation = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, image_builder.image(), *bundle.context);
        require(relocation.complete(), "BFV rotation example relocation is incomplete");
        const auto runtime = hpu::seal_adapter::lower_bfv_runtime_program(lowered, relocation);
        const auto artifacts = hpu::seal_adapter::render_bfv_runtime_artifacts(
            kArtifactStem, runtime, image_builder.image().capacity_lines());
        require(runtime.dma.size() == relocation.expected_dma_count &&
                    artifacts.header.find("hpu_run_bfv_rotation_application") !=
                        std::string::npos,
                "BFV rotation example runtime artifacts are incomplete");

        if (options.emit_directory) {
            emit_artifacts(*options.emit_directory, lowered, runtime, artifacts,
                           image_builder.image());
        }
        std::cout << "y=RotateRows(x,2)+RotateColumns(x)\n"
                  << "Plan: RotateRows -> RotateColumns -> Add\n"
                  << "Level: Q" << level.q_moduli.size() << " throughout\n"
                  << "Decoded first slots: [" << expected_slots[0] << ", "
                  << expected_slots[1] << ", " << expected_slots[2] << ", "
                  << expected_slots[3] << "]\n"
                  << "HPU_MEM lines: " << image_builder.image().used_lines() << " / "
                  << image_builder.image().capacity_lines() << '\n'
                  << "DMA relocation: " << relocation.bindings.size() << " / "
                  << relocation.expected_dma_count << '\n'
                  << "Encoded instructions: " << runtime.instructions.size() << '\n';
        if (options.emit_directory) {
            std::cout << "Artifacts emitted under: " << options.emit_directory->string() << '\n';
        } else {
            std::cout << "Pass --emit-dir PATH to write deployment artifacts.\n";
        }
        if (options.print_asm) {
            std::cout << "\n--- generated HPU inline-assembly body ---\n" << lowered.body_asm;
        } else {
            std::cout << "Pass --print-asm to print the generated instruction body.\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BFV rotation application example failed: " << error.what() << '\n';
        return 1;
    }
}
