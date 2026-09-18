#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "hpu/seal/bfv_software_executor.hpp"

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

constexpr const char* kArtifactStem = "bfv_multiply_modswitch_application";

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
            throw std::invalid_argument("usage: hpu_bfv_multiply_modswitch_example "
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

::seal::Ciphertext import_hpu_ciphertext(const hpu::seal_adapter::PreparedBfvRnsObject& object,
                                         const hpu::seal_adapter::BfvSoftwareExecutor& executor,
                                         const ::seal::SEALContext& context)
{
    ::seal::Ciphertext result;
    result.resize(context, object.parms_id, object.components.size());
    result.is_ntt_form() = false;
    result.scale() = 1.0;
    result.correction_factor() = 1;
    for (std::size_t component = 0; component < object.components.size(); ++component) {
        const auto polynomial = executor.export_component(object, component);
        std::copy(polynomial.words.begin(), polynomial.words.end(), result.data(component));
    }
    return result;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const Options options = parse_options(argc, argv);

        // Teaching-sized parameters keep the example quick. Application code,
        // planner calls, and runtime artifact APIs are unchanged at deployment N.
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        spec.plain_modulus_bits = 17;
        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relinearization_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relinearization_keys);

        ::seal::BatchEncoder encoder(*bundle.context);
        const std::size_t slot_count = encoder.slot_count();
        std::vector<std::uint64_t> left_slots(slot_count);
        std::vector<std::uint64_t> right_slots(slot_count);
        std::vector<std::uint64_t> bias_slots(slot_count, 3);
        std::vector<std::uint64_t> expected_slots(slot_count);
        for (std::size_t index = 0; index < slot_count; ++index) {
            left_slots[index] = index % 7 + 1;
            right_slots[index] = index % 5 + 2;
            expected_slots[index] =
                (left_slots[index] * right_slots[index] + bias_slots[index]) % bundle.plain_modulus;
        }

        ::seal::Plaintext left_plaintext;
        ::seal::Plaintext right_plaintext;
        ::seal::Plaintext bias_plaintext;
        encoder.encode(left_slots, left_plaintext);
        encoder.encode(right_slots, right_plaintext);
        encoder.encode(bias_slots, bias_plaintext);

        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(left_plaintext, encrypted_left);
        encryptor.encrypt(right_plaintext, encrypted_right);

        // Independent modified-SEAL semantic oracle. It verifies the application
        // expression; the HPU program generated below does not call Evaluator.
        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext oracle;
        evaluator.multiply(encrypted_left, encrypted_right, oracle);
        evaluator.relinearize_inplace(oracle, relinearization_keys);
        evaluator.mod_switch_to_next_inplace(oracle);
        evaluator.add_plain_inplace(oracle, bias_plaintext);
        ::seal::Decryptor decryptor(*bundle.context, key_generator.secret_key());
        ::seal::Plaintext decrypted;
        decryptor.decrypt(oracle, decrypted);
        std::vector<std::uint64_t> oracle_decoded;
        encoder.decode(decrypted, oracle_decoded);
        require(
            oracle_decoded.size() >= expected_slots.size() &&
                std::equal(expected_slots.begin(), expected_slots.end(), oracle_decoded.begin()),
            "modified-SEAL BFV application oracle produced incorrect slots");

        // All runtime inputs, plaintext representations, keys, constants, and
        // workspaces are prepared before the operation plan is constructed.
        hpu::seal_adapter::BfvApplicationImageBuilder image_builder(*bundle.context, 16384);
        image_builder.add_modulus_table();
        const auto canonical_twiddles = image_builder.add_canonical_twiddles();
        const auto& top = image_builder.level_chain().top();
        const auto& next = image_builder.level_chain().next(top.parms_id);
        const auto left = image_builder.add_ciphertext("input/left", encrypted_left);
        const auto right = image_builder.add_ciphertext("input/right", encrypted_right);
        const auto bias =
            image_builder.add_add_subtract_plaintext("constant/bias/next", bias_plaintext, next);
        const auto relinearization_key = image_builder.add_relinearization_key(
            "key/relinearization/top", relinearization_keys, top);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants("constants/keyswitch/top", top);
        const auto multiply_constants =
            image_builder.add_multiply_constants("constants/multiply/top", top);
        const auto mod_switch_constants =
            image_builder.add_mod_switch_constants("constants/mod_switch/top_to_next", top);

        // Application-facing graph:
        // y = ModSwitch(Relinearize(left * right)) + prepared_bias.
        // append_multiply owns the fused BFV Multiply + Relinearize kernel;
        // append_mod_switch is the only explicit level transition.
        hpu::seal_adapter::BfvOperationPlan plan(image_builder);
        const auto product =
            plan.append_multiply("multiply", left, right, relinearization_key, keyswitch_constants,
                                 multiply_constants, "intermediate/product/top");
        const auto switched = plan.append_mod_switch("mod_switch", product, mod_switch_constants,
                                                     "intermediate/product/next");
        const auto output = plan.append_add_plain("add_bias", switched, bias, "output/y/next");
        require(plan.steps().size() == 3 && product.parms_id == top.parms_id &&
                    switched.parms_id == next.parms_id && output.parms_id == next.parms_id,
                "BFV example planner produced the wrong operation graph or level transition");

        // Execute the planned BFV path from the same HPU_MEM image. This
        // reproduces comparison-free BEHZ, rounded KeySwitch, rounded
        // ModSwitch, and AddPlain without calling seal::Evaluator.
        hpu::seal_adapter::BfvSoftwareExecutor software_executor(*bundle.context,
                                                                 image_builder.image());
        software_executor.multiply(left, right, relinearization_key, keyswitch_constants,
                                   multiply_constants, canonical_twiddles, product);
        software_executor.mod_switch(product, mod_switch_constants, switched);
        software_executor.add_plain(switched, bias, output);
        const auto imported = import_hpu_ciphertext(output, software_executor, *bundle.context);
        require(imported.parms_id() == oracle.parms_id() && imported.size() == oracle.size(),
                "BFV software executor produced incorrect output metadata");
        for (std::size_t component = 0; component < oracle.size(); ++component) {
            require(std::equal(imported.data(component),
                               imported.data(component) +
                                   imported.poly_modulus_degree() * imported.coeff_modulus_size(),
                               oracle.data(component)),
                    "BFV software executor output differs from modified-SEAL coefficients");
        }
        decryptor.decrypt(imported, decrypted);
        std::vector<std::uint64_t> decoded;
        encoder.decode(decrypted, decoded);
        require(decoded.size() >= expected_slots.size() &&
                    std::equal(expected_slots.begin(), expected_slots.end(), decoded.begin()),
                "BFV software executor application produced incorrect slots");

        // The same plan becomes one encoded program with one modulus-table
        // lifetime, one terminal psync, and a concrete span for every DMA.
        const auto lowered = hpu::seal_adapter::lower_bfv_operation_plan(plan, *bundle.context);
        const auto relocation = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, image_builder.image(), *bundle.context);
        require(relocation.complete(), "BFV example relocation schedule is incomplete");
        const auto runtime = hpu::seal_adapter::lower_bfv_runtime_program(lowered, relocation);
        const auto artifacts = hpu::seal_adapter::render_bfv_runtime_artifacts(
            kArtifactStem, runtime, image_builder.image().capacity_lines());
        require(runtime.dma.size() == relocation.expected_dma_count &&
                    artifacts.header.find("hpu_run_bfv_multiply_modswitch_application") !=
                        std::string::npos,
                "BFV example runtime artifacts are incomplete");

        if (options.emit_directory) {
            emit_artifacts(*options.emit_directory, lowered, runtime, artifacts,
                           image_builder.image());
        }

        std::cout << "y=ModSwitch(left*right)+3\n"
                  << "Plan: Multiply+Relinearize -> ModSwitch -> AddPlain\n"
                  << "Level: Q" << top.q_moduli.size() << " -> Q" << next.q_moduli.size() << '\n'
                  << "Decoded first slots: [" << decoded[0] << ", " << decoded[1] << ", "
                  << decoded[2] << ", " << decoded[3] << "]\n"
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
        std::cerr << "BFV Multiply/ModSwitch application example failed: " << error.what() << '\n';
        return 1;
    }
}
