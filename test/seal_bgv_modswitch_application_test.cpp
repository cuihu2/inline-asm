#include "hpu/model/hardware_ntt.hpp"
#include "hpu/runtime/software_executor.hpp"
#include "hpu/seal/bgv_modswitch_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/modswitch.hpp"

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
    if (!condition) {
        throw std::runtime_error(message);
    }
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

std::string mod_id(const std::string& prefix, std::size_t id)
{
    return prefix + "/mod" + std::to_string(id);
}

void check_package(const seal::SEALContext& context, seal::Evaluator& evaluator,
                   const seal::Ciphertext& input)
{
    const auto source = context.get_context_data(input.parms_id());
    require(source && source->next_context_data(), "BGV test input has no next level");
    const auto& moduli = source->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t last = moduli.size() - 1;
    const std::uint32_t q_last = static_cast<std::uint32_t>(moduli[last].value());
    const std::uint32_t t = static_cast<std::uint32_t>(
        source->parms().plain_modulus().value());
    const auto package = hpu::seal_adapter::build_bgv_modswitch_application(
        context, input, 512);
    require(package.source_parms_id == input.parms_id() &&
                package.destination_parms_id == source->next_context_data()->parms_id() &&
                !package.dma.empty() && package.spans().size() == package.dma.size(),
            "BGV application metadata or DMA shape is wrong");
    const auto table = words(package.image, "constants/modulus_table");
    const auto key_moduli = context.key_context_data()->parms().coeff_modulus();
    require(table.size() == 4 * (key_moduli.size() + 1) &&
                table[4 * key_moduli.size()] == t &&
                package.dma.front().allocation_id == "constants/modulus_table" &&
                package.dma.front().span.line_offset ==
                    package.image.allocation("constants/modulus_table").span.line_offset,
            "BGV application did not keep the fixed Qmax|P|t modulus table");
    hpu::runtime::HpuSoftwareExecutor memory(package.image);
    memory.load_modulus_table(
        package.image.allocation("constants/modulus_table").span,
        key_moduli.size() + 1);
    require(memory.modulus(static_cast<std::uint8_t>(key_moduli.size())) == t,
            "BGV modulus table failed the q32/mu48 software-executor check");
    for (std::size_t index = 0; index < package.dma.size(); ++index) {
        const auto& binding = package.dma[index];
        require(binding.dma_index == index && binding.span.line_count != 0 &&
                    binding.instruction_index < package.instructions.size(),
                "BGV DMA index, span, or instruction index is unresolved");
    }

    seal::Ciphertext expected = input;
    evaluator.mod_switch_to_next_inplace(expected);
    require(package.correction_factor == expected.correction_factor(),
            "BGV application correction factor differs from modified-SEAL");
    const auto* tables = source->small_ntt_tables();
    const std::uint32_t neg_inverse =
        words(package.image, "constants/bgv_modswitch/neg_inv_t").front();
    for (std::size_t component = 0; component < input.size(); ++component) {
        const std::string component_name = "c" + std::to_string(component);
        const auto dropped = words(package.image,
                                   mod_id("input/" + component_name, last));
        const std::uint32_t psi_last =
            static_cast<std::uint32_t>(tables[last].get_root());
        const auto c_last = hpu::model::negacyclic_inverse(dropped, q_last, psi_last);
        const auto expected_component = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0; basis < last; ++basis) {
            const std::uint32_t qi = static_cast<std::uint32_t>(moduli[basis].value());
            const auto input_q = words(package.image,
                                       mod_id("input/" + component_name, basis));
            const std::uint32_t q_last_mod = words(
                package.image, mod_id("constants/bgv_modswitch/q_last_mod", basis)).front();
            const std::uint32_t inverse = words(
                package.image, mod_id("constants/bgv_modswitch/q_last_inv", basis)).front();
            std::vector<std::uint32_t> correction(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint64_t u =
                    (static_cast<std::uint64_t>(c_last[index]) * neg_inverse) % t;
                correction[index] = static_cast<std::uint32_t>(
                    ((c_last[index] % qi) + (u * q_last_mod) % qi) % qi);
            }
            const auto correction_ntt = hpu::model::negacyclic_forward(
                correction, qi, static_cast<std::uint32_t>(tables[basis].get_root()));
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t actual = static_cast<std::uint32_t>(
                    (((static_cast<std::uint64_t>(input_q[index]) + qi -
                       correction_ntt[index]) % qi) * inverse) % qi);
                if (actual != expected_component.words[basis * degree + index]) {
                    throw std::runtime_error(
                        "prepared BGV application differs from SEAL HPU-layout output");
                }
            }
        }
    }

    const auto artifacts = hpu::seal_adapter::render_bgv_modswitch_runtime_artifacts(
        "bgv_modswitch_demo", package);
    require(artifacts.header.find("hpu_run_bgv_modswitch_demo") != std::string::npos &&
                artifacts.source.find("_resolved_spans[]") != std::string::npos &&
                artifacts.resolved_dma_manifest.find("constants/modulus_table") != std::string::npos &&
                artifacts.resolved_dma_manifest.find("output/c0/mod0") != std::string::npos,
            "BGV runtime artifacts lack resolved spans or the output binding");

    auto corrupted = package;
    corrupted.dma.front().span.line_offset = package.image.capacity_lines();
    bool rejected = false;
    try {
        (void)hpu::seal_adapter::render_bgv_modswitch_runtime_artifacts(
            "bgv_modswitch_demo", corrupted);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "BGV runtime accepted an out-of-range DMA binding");

    corrupted = package;
    corrupted.dma.front().object_slot = 0;
    rejected = false;
    try {
        (void)hpu::seal_adapter::render_bgv_modswitch_runtime_artifacts(
            "bgv_modswitch_demo", corrupted);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "BGV runtime accepted an encoded DMA object mismatch");
}

} // namespace

int main()
{
    try {
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(), "modified-SEAL rejected BGV application context");
        seal::KeyGenerator keys(context);
        seal::Encryptor encryptor(context, keys.secret_key());
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t index = 0; index < slots.size(); ++index) {
            slots[index] = (index * 17 + 3) % 65537;
        }
        seal::Plaintext plain;
        encoder.encode(slots, plain);
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(plain, input);
        seal::Evaluator evaluator(context);
        check_package(context, evaluator, input);
        evaluator.mod_switch_to_next_inplace(input);
        check_package(context, evaluator, input);
        std::cout << "BGV ModSwitch image/relocation/runtime tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV ModSwitch application test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
