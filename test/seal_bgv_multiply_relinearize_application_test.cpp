#include "hpu/seal/bgv_keyswitch_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"

#include <seal/seal.h>

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

std::string mod_id(const std::string& prefix, std::size_t basis)
{
    return prefix + "/mod" + std::to_string(basis);
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

std::uint32_t mul_mod(std::uint32_t left, std::uint32_t right, std::uint32_t q)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) * right) % q);
}

void check_small(const seal::SEALContext& context, seal::Evaluator& evaluator,
                 const seal::RelinKeys& keys, const seal::Ciphertext& left,
                 const seal::Ciphertext& right)
{
    const auto source = context.get_context_data(left.parms_id());
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = source->parms().coeff_modulus().size();
    const std::size_t key_count =
        context.key_context_data()->parms().coeff_modulus().size();
    const std::uint64_t capacity =
        hpu::seal_adapter::estimate_bgv_multiply_relinearize_image_lines(
            degree, q_count, key_count);
    auto package = hpu::seal_adapter::build_bgv_multiply_relinearize_application(
        context, left, right, keys, capacity);
    require(package.image.used_lines() == capacity &&
                package.parms_id == left.parms_id() &&
                package.spans().size() == package.dma.size() &&
                package.dma.size() > 11 * q_count,
            "BGV combined image, metadata, or DMA shape is wrong");
    std::size_t psync_count = 0;
    std::size_t modulus_load_count = 0;
    for (const auto& encoded : package.instructions) {
        psync_count += encoded.instruction.mnemonic == hpu::Mnemonic::kPsync;
        modulus_load_count += encoded.instruction.mnemonic == hpu::Mnemonic::kDload &&
                              encoded.instruction.obj_id == 4 &&
                              encoded.instruction.type == 2;
    }
    require(psync_count == 1 && modulus_load_count == 1 &&
                package.instructions.back().instruction.mnemonic == hpu::Mnemonic::kPsync,
            "BGV combined program has a duplicate table load or intermediate psync");

    // SEAL multiplication is test-only oracle work. The builder above accepts
    // only the two original ciphertexts; its tensor spans start uninitialized.
    seal::Ciphertext tensor;
    evaluator.multiply(left, right, tensor);
    require(package.correction_factor == tensor.correction_factor(),
            "BGV combined correction factor differs from modified-SEAL");
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const std::uint32_t q = static_cast<std::uint32_t>(
            source->parms().coeff_modulus()[basis].value());
        const auto a0 = words(package.image, mod_id("input/left/c0", basis));
        const auto a1 = words(package.image, mod_id("input/left/c1", basis));
        const auto b0 = words(package.image, mod_id("input/right/c0", basis));
        const auto b1 = words(package.image, mod_id("input/right/c1", basis));
        std::vector<std::vector<std::uint32_t>> expected_tensor(3,
            std::vector<std::uint32_t>(degree));
        for (std::size_t k = 0; k < degree; ++k) {
            expected_tensor[0][k] = mul_mod(a0[k], b0[k], q);
            expected_tensor[1][k] = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(mul_mod(a0[k], b1[k], q)) +
                 mul_mod(a1[k], b0[k], q)) % q);
            expected_tensor[2][k] = mul_mod(a1[k], b1[k], q);
        }
        for (std::size_t component = 0; component < 3; ++component) {
            const auto oracle = hpu::seal_adapter::ciphertext_component_to_hpu(
                tensor, component, context);
            const auto& tensor_span = package.image.allocation(
                mod_id("input/c" + std::to_string(component), basis));
            require(!tensor_span.read_only &&
                        words(package.image, tensor_span.id) ==
                            std::vector<std::uint32_t>(degree, 0),
                    "BGV tensor intermediate was precomputed on CPU");
            bool saw_store = false;
            bool saw_later_load = false;
            for (const auto& binding : package.dma) {
                if (binding.allocation_id != tensor_span.id) continue;
                if (binding.direction == hpu::Mnemonic::kDstore) saw_store = true;
                if (binding.direction == hpu::Mnemonic::kDload && saw_store) {
                    saw_later_load = true;
                }
                require(binding.span.line_offset == tensor_span.span.line_offset &&
                            binding.span.line_count == tensor_span.span.line_count,
                        "BGV tensor store/load does not share one HPU_MEM span");
            }
            require(saw_store && saw_later_load,
                    "BGV KeySwitch did not consume HPU-produced tensor output");
            for (std::size_t k = 0; k < degree; ++k) {
                if (expected_tensor[component][k] !=
                    oracle.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV HPU tensor formula differs from modified-SEAL");
                }
            }
        }
    }

    auto standalone = hpu::seal_adapter::build_bgv_keyswitch_application(
        context, tensor, keys,
        hpu::seal_adapter::estimate_bgv_keyswitch_image_lines(
            degree, q_count, key_count));
    const std::size_t key_phase_first = 1 + 11 * q_count;
    require(package.dma.size() == key_phase_first + standalone.dma.size() - 1,
            "BGV combined KeySwitch DMA suffix has a different length");
    for (std::size_t index = 1; index < standalone.dma.size(); ++index) {
        const auto& combined = package.dma[key_phase_first + index - 1];
        const auto& separate = standalone.dma[index];
        require(combined.allocation_id == separate.allocation_id &&
                    combined.direction == separate.direction &&
                    combined.object_slot == separate.object_slot &&
                    combined.span.line_offset == separate.span.line_offset &&
                    combined.span.line_count == separate.span.line_count,
                "BGV combined KeySwitch no longer matches its verified standalone phase");
    }
    for (const auto& allocation : standalone.image.allocations()) {
        if (allocation.id.rfind("keys/", 0) == 0 ||
            allocation.id.rfind("constants/", 0) == 0) {
            require(words(package.image, allocation.id) ==
                        words(standalone.image, allocation.id),
                    "BGV combined key or constant payload differs from standalone KeySwitch");
        }
    }
    seal::Ciphertext expected = tensor;
    evaluator.relinearize_inplace(expected, keys);
    require(expected.correction_factor() == package.correction_factor &&
                expected.size() == 2 && expected.is_ntt_form(),
            "BGV combined output metadata differs from modified-SEAL");
    const auto artifacts = hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
        "bgv_multiply_relin", package);
    require(artifacts.resolved_dma_manifest.find("input/left/c0/mod0") !=
                std::string::npos &&
                artifacts.resolved_dma_manifest.find("output/c1/mod0") !=
                std::string::npos,
            "BGV combined runtime manifest lacks input or output binding");
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const bool target_degree = argc == 2 &&
            std::string(argv[1]) == "--target-degree";
        require(argc == 1 || target_degree, "unknown BGV combined test argument");
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(target_degree ? 65536 : 128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(), "modified-SEAL rejected BGV context");
        seal::KeyGenerator generator(context);
        seal::RelinKeys keys;
        generator.create_relin_keys(keys);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Plaintext left_plain("3");
        seal::Plaintext right_plain("5");
        seal::Ciphertext left;
        seal::Ciphertext right;
        encryptor.encrypt_symmetric(left_plain, left);
        encryptor.encrypt_symmetric(right_plain, right);
        seal::Evaluator evaluator(context);
        if (target_degree) {
            const std::uint64_t required =
                hpu::seal_adapter::estimate_bgv_multiply_relinearize_image_lines(
                    65536, 3, 4);
            auto package = hpu::seal_adapter::build_bgv_multiply_relinearize_application(
                context, left, right, keys, required);
            require(required == 148481 && package.image.used_lines() == required &&
                        !package.dma.empty(),
                    "N=65536 BGV combined image exceeds estimated window");
            std::cout << "N=65536 BGV Multiply+Relinearize image passed: "
                      << required << " lines, " << package.dma.size()
                      << " DMA bindings\n";
        } else {
            const auto first_source = context.get_context_data(left.parms_id());
            const std::uint64_t minimum_lines =
                hpu::seal_adapter::estimate_bgv_multiply_relinearize_image_lines(
                    first_source->parms().poly_modulus_degree(),
                    first_source->parms().coeff_modulus().size(),
                    context.key_context_data()->parms().coeff_modulus().size());
            bool rejected = false;
            try {
                (void)hpu::seal_adapter::build_bgv_multiply_relinearize_application(
                    context, left, right, keys, minimum_lines - 1);
            } catch (const std::overflow_error&) {
                rejected = true;
            }
            require(rejected, "BGV combined builder accepted an undersized window");
            check_small(context, evaluator, keys, left, right);
            evaluator.mod_switch_to_next_inplace(right);
            rejected = false;
            try {
                (void)hpu::seal_adapter::build_bgv_multiply_relinearize_application(
                    context, left, right, keys, minimum_lines);
            } catch (const std::invalid_argument&) {
                rejected = true;
            }
            require(rejected, "BGV combined builder accepted mixed ciphertext levels");
            evaluator.mod_switch_to_next_inplace(left);
            check_small(context, evaluator, keys, left, right);
            std::cout << "BGV Multiply+Relinearize application tests passed\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV Multiply+Relinearize test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
