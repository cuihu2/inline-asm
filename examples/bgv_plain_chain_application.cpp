#include "hpu/seal/bgv_plain_operation_plan.hpp"
#include "hpu/seal/ntt_bridge.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

std::vector<std::uint32_t> words(const hpu::runtime::HpuMemImage& image,
                                 const std::string& id)
{
    const auto& allocation = image.allocation(id);
    const std::size_t first = allocation.span.line_offset *
        hpu::runtime::kHpuMemLineWords;
    return {image.words().begin() + static_cast<std::ptrdiff_t>(first),
            image.words().begin() + static_cast<std::ptrdiff_t>(first + allocation.word_count)};
}

std::vector<std::uint32_t> apply(
    const std::vector<std::uint32_t>& ciphertext,
    const std::vector<std::uint32_t>& plaintext,
    std::uint32_t q, hpu::seal_adapter::BgvPlainOperationKind kind)
{
    std::vector<std::uint32_t> output(ciphertext.size());
    for (std::size_t index = 0; index < ciphertext.size(); ++index) {
        switch (kind) {
        case hpu::seal_adapter::BgvPlainOperationKind::add:
            output[index] = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(ciphertext[index]) + plaintext[index]) % q);
            break;
        case hpu::seal_adapter::BgvPlainOperationKind::subtract:
            output[index] = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(ciphertext[index]) + q - plaintext[index]) % q);
            break;
        case hpu::seal_adapter::BgvPlainOperationKind::multiply:
            output[index] = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(ciphertext[index]) * plaintext[index]) % q);
            break;
        }
    }
    return output;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const bool print_manifest = argc == 2 &&
            std::string(argv[1]) == "--print-dma";
        if (argc > 2 || (argc == 2 && !print_manifest)) {
            throw std::invalid_argument(
                "usage: hpu_bgv_plain_chain_example [--print-dma]");
        }
        // Small parameters make the example quick; the API also accepts
        // N=65536 when the HPU_MEM window has enough lines.
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(), "BGV example context is invalid");
        seal::KeyGenerator generator(context);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Evaluator evaluator(context);
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(seal::Plaintext("2x^3 + 7"), input);

        // y = ((x + 3) * (2x + 1)) - 5. Plaintexts are known in advance.
        const seal::Plaintext bias("3");
        const seal::Plaintext multiplier("2x^1 + 1");
        const seal::Plaintext offset("5");
        hpu::seal_adapter::BgvPlainOperationPlan plan(context, input);
        plan.append_add_plain("add_bias", bias);
        plan.append_multiply_plain("multiply_polynomial", multiplier);
        plan.append_subtract_plain("subtract_offset", offset);
        auto package = plan.lower(512);
        const auto runtime =
            hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                "bgv_plain_chain", package);

        // Independent SEAL oracle. This is validation code, not part of the
        // generated runtime and does not prepare intermediate HPU inputs.
        seal::Ciphertext expected = input;
        std::vector<seal::Ciphertext> expected_after_step;
        evaluator.add_plain_inplace(expected, bias);
        expected_after_step.push_back(expected);
        evaluator.multiply_plain_inplace(expected, multiplier);
        expected_after_step.push_back(expected);
        evaluator.sub_plain_inplace(expected, offset);
        expected_after_step.push_back(expected);
        const auto source = context.get_context_data(input.parms_id());
        const auto& q_moduli = source->parms().coeff_modulus();
        require(package.correction_factor == expected.correction_factor() &&
                    package.parms_id == expected.parms_id() &&
                    package.spans().size() == package.dma.size(),
                "BGV plain-chain metadata or DMA shape differs from SEAL");
        std::size_t psync_count = 0;
        for (const auto& instruction : package.instructions) {
            psync_count += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
        }
        require(psync_count == 1,
                "BGV plain-chain must contain one final psync");

        for (std::size_t step_index = 0; step_index < plan.steps().size(); ++step_index) {
            const auto& step = plan.steps()[step_index];
            const std::string input_prefix = step_index == 0
                ? "input" : "steps/" + plan.steps()[step_index - 1].id + "/output";
            const std::string output_prefix = step_index + 1 == plan.steps().size()
                ? "output" : "steps/" + step.id + "/output";
            for (std::size_t basis = 0; basis < q_moduli.size(); ++basis) {
                const auto q = static_cast<std::uint32_t>(q_moduli[basis].value());
                const std::string suffix = "/mod" + std::to_string(basis);
                const auto plain_words = words(package.image,
                    "steps/" + step.id + "/plain" + suffix);
                for (std::size_t component = 0; component < 2; ++component) {
                    const auto input_id = input_prefix + "/c" +
                        std::to_string(component) + suffix;
                    std::vector<std::uint32_t> current;
                    if (step_index == 0) {
                        current = words(package.image, input_id);
                    } else {
                        const auto prior = hpu::seal_adapter::ciphertext_component_to_hpu(
                            expected_after_step[step_index - 1], component, context);
                        const auto first = prior.words.begin() +
                            static_cast<std::ptrdiff_t>(basis * source->parms().poly_modulus_degree());
                        current.assign(first, first + source->parms().poly_modulus_degree());
                    }
                    const auto actual = component == 1 &&
                        step.kind != hpu::seal_adapter::BgvPlainOperationKind::multiply
                        ? current : apply(current, plain_words, q, step.kind);
                    const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
                        expected_after_step[step_index], component, context);
                    const auto first = expected_hpu.words.begin() +
                        static_cast<std::ptrdiff_t>(basis * source->parms().poly_modulus_degree());
                    require(std::equal(actual.begin(), actual.end(), first),
                            "BGV plain-chain step differs from modified-SEAL");
                    // Only the first input is preloaded. All later loads must
                    // resolve to the preceding step's HPU-written output.
                    if (step_index != 0) {
                        bool bound = false;
                        for (const auto& dma : package.dma) {
                            bound |= dma.direction == hpu::Mnemonic::kDload &&
                                dma.allocation_id == input_id;
                        }
                        require(bound, "BGV plain-chain lost an intermediate DMA edge");
                    }
                    require(package.image.allocation(
                                output_prefix + "/c" +
                                std::to_string(component) + suffix).read_only == false,
                            "BGV plain-chain output is not HPU-writable");
                }
            }
        }
        require(runtime.resolved_dma_manifest.find("output/c1/mod0") !=
                    std::string::npos,
                "BGV plain-chain runtime lacks the final output");
        std::cout << "BGV plain-chain example passed: " << plan.steps().size()
                  << " steps, " << package.instructions.size() << " encoded instructions, "
                  << package.dma.size() << " resolved DMA bindings, "
                  << package.image.used_lines() << " HPU_MEM lines\n";
        if (print_manifest) std::cout << runtime.resolved_dma_manifest;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV plain-chain example failed: " << error.what() << '\n';
        return 1;
    }
}
