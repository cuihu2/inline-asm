#include "hpu/model/hardware_ntt.hpp"
#include "hpu/runtime/software_executor.hpp"
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

std::string mod_id(const std::string& prefix, std::size_t id)
{
    return prefix + "/mod" + std::to_string(id);
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

std::uint32_t add_mod(std::uint32_t a, std::uint32_t b, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(a) + b) % modulus);
}

std::uint32_t mul_mod(std::uint32_t a, std::uint32_t b, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(a) * b) % modulus);
}

void check_package(const seal::SEALContext& context, seal::Evaluator& evaluator,
                   const seal::RelinKeys& keys, const seal::Ciphertext& product)
{
    const auto source = context.get_context_data(product.parms_id());
    const auto& q_moduli = source->parms().coeff_modulus();
    const auto& key_moduli = context.key_context_data()->parms().coeff_modulus();
    const std::size_t q_count = q_moduli.size();
    const std::size_t p_id = key_moduli.size() - 1;
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::uint32_t t = static_cast<std::uint32_t>(
        source->parms().plain_modulus().value());
    const std::uint32_t p = static_cast<std::uint32_t>(key_moduli[p_id].value());
    const std::uint64_t required_lines =
        hpu::seal_adapter::estimate_bgv_keyswitch_image_lines(
            degree, q_count, key_moduli.size());
    auto package = hpu::seal_adapter::build_bgv_keyswitch_application(
        context, product, keys, required_lines);
    require(package.image.used_lines() == required_lines,
            "BGV KeySwitch line estimate differs from actual image");
    require(package.parms_id == product.parms_id() &&
                package.correction_factor == product.correction_factor() &&
                !package.dma.empty() && package.spans().size() == package.dma.size(),
            "BGV KeySwitch metadata or DMA shape is wrong");
    const auto table = words(package.image, "constants/modulus_table");
    require(table.size() == 4 * (key_moduli.size() + 1) &&
                table[4 * p_id] == p && table[4 * key_moduli.size()] == t &&
                package.dma.front().allocation_id == "constants/modulus_table",
            "BGV KeySwitch did not preserve fixed Qmax|P|t MOD_IDs");
    hpu::runtime::HpuSoftwareExecutor memory(package.image);
    memory.load_modulus_table(
        package.image.allocation("constants/modulus_table").span,
        key_moduli.size() + 1);
    require(memory.modulus(static_cast<std::uint8_t>(p_id)) == p &&
                memory.modulus(static_cast<std::uint8_t>(key_moduli.size())) == t,
            "BGV KeySwitch modulus table failed q32/mu48 validation");
    for (std::size_t index = 0; index < package.dma.size(); ++index) {
        const auto& binding = package.dma[index];
        require(binding.dma_index == index && binding.span.line_count != 0 &&
                    binding.instruction_index < package.instructions.size(),
                "BGV KeySwitch has an unresolved DMA binding");
    }

    // Reconstruct the mathematical output solely from prepared HPU_MEM words.
    // This checks evaluation-key limb selection, physical NTT bridge, constants,
    // and the fixed special-P index at both the top and a lower data level.
    std::vector<std::vector<std::uint32_t>> source_coeff(q_count);
    for (std::size_t digit = 0; digit < q_count; ++digit) {
        source_coeff[digit] = hpu::model::negacyclic_inverse(
            words(package.image, mod_id("input/c2", digit)),
            static_cast<std::uint32_t>(q_moduli[digit].value()),
            static_cast<std::uint32_t>(source->small_ntt_tables()[digit].get_root()));
    }
    std::vector<std::vector<std::vector<std::uint32_t>>> acc(
        2, std::vector<std::vector<std::uint32_t>>(
               q_count + 1, std::vector<std::uint32_t>(degree, 0)));
    for (std::size_t target = 0; target <= q_count; ++target) {
        const std::size_t id = target == q_count ? p_id : target;
        const std::uint32_t modulus = static_cast<std::uint32_t>(key_moduli[id].value());
        const std::uint32_t psi = static_cast<std::uint32_t>(
            context.key_context_data()->small_ntt_tables()[id].get_root());
        for (std::size_t digit = 0; digit < q_count; ++digit) {
            std::vector<std::uint32_t> operand;
            if (target == digit) {
                operand = words(package.image, mod_id("input/c2", digit));
            } else {
                operand = source_coeff[digit];
                for (auto& value : operand) value %= modulus;
                operand = hpu::model::negacyclic_forward(operand, modulus, psi);
            }
            for (std::size_t component = 0; component < 2; ++component) {
                const auto key = words(package.image,
                    mod_id("keys/digit" + std::to_string(digit) +
                           "/c" + std::to_string(component), id));
                for (std::size_t k = 0; k < degree; ++k) {
                    acc[component][target][k] = add_mod(
                        acc[component][target][k],
                        mul_mod(operand[k], key[k], modulus), modulus);
                }
            }
        }
    }

    seal::Ciphertext expected = product;
    evaluator.relinearize_inplace(expected, keys);
    require(expected.size() == 2 && expected.is_ntt_form() &&
                expected.correction_factor() == package.correction_factor,
            "BGV KeySwitch changed correction-factor metadata");
    const std::uint32_t neg_inverse =
        words(package.image, "constants/bgv_keyswitch/neg_inv_t").front();
    for (std::size_t component = 0; component < 2; ++component) {
        const auto p_coeff = hpu::model::negacyclic_inverse(
            acc[component][q_count], p,
            static_cast<std::uint32_t>(
                context.key_context_data()->small_ntt_tables()[p_id].get_root()));
        const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const std::uint32_t qi = static_cast<std::uint32_t>(q_moduli[basis].value());
            const std::uint32_t p_mod = words(package.image,
                mod_id("constants/bgv_keyswitch/p_mod", basis)).front();
            const std::uint32_t p_inv = words(package.image,
                mod_id("constants/bgv_keyswitch/p_inv", basis)).front();
            std::vector<std::uint32_t> correction(degree);
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint32_t u = mul_mod(p_coeff[k] % t, neg_inverse, t);
                correction[k] = add_mod(p_coeff[k] % qi,
                                        mul_mod(u, p_mod, qi), qi);
            }
            const auto correction_ntt = hpu::model::negacyclic_forward(
                correction, qi,
                static_cast<std::uint32_t>(source->small_ntt_tables()[basis].get_root()));
            const auto base = words(package.image,
                mod_id("input/c" + std::to_string(component), basis));
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint32_t switched = mul_mod(
                    add_mod(acc[component][basis][k],
                            qi - correction_ntt[k], qi), p_inv, qi);
                const std::uint32_t actual = add_mod(base[k], switched, qi);
                if (actual != expected_hpu.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV KeySwitch HPU_MEM formula differs from modified-SEAL");
                }
            }
        }
    }

    const auto artifacts = hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
        "bgv_relin_demo", package);
    require(artifacts.header.find("hpu_run_bgv_relin_demo") != std::string::npos &&
                artifacts.source.find("_resolved_spans[]") != std::string::npos &&
                artifacts.resolved_dma_manifest.find("keys/digit0/c0/mod") != std::string::npos &&
                artifacts.resolved_dma_manifest.find("output/c1/mod0") != std::string::npos,
            "BGV KeySwitch runtime artifacts lack key or output bindings");
    package.dma.front().span.line_offset = package.image.capacity_lines();
    bool rejected = false;
    try {
        (void)hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
            "bgv_relin_demo", package);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "BGV KeySwitch runtime accepted an out-of-range binding");
    package.dma.front().span = package.image.allocation("constants/modulus_table").span;
    package.dma.front().object_slot = 0;
    rejected = false;
    try {
        (void)hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
            "bgv_relin_demo", package);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "BGV KeySwitch runtime accepted a wrong encoded DMA object");
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const bool target_degree = argc == 2 &&
            std::string(argv[1]) == "--target-degree";
        require(argc == 1 || target_degree, "unknown BGV KeySwitch test argument");
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(target_degree ? 65536 : 128);
        parameters.set_coeff_modulus({
            seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(), "modified-SEAL rejected BGV test context");
        seal::KeyGenerator generator(context);
        seal::RelinKeys keys;
        generator.create_relin_keys(keys);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Plaintext plain("1");
        if (!target_degree) {
            seal::BatchEncoder encoder(context);
            std::vector<std::uint64_t> slots(encoder.slot_count());
            for (std::size_t k = 0; k < slots.size(); ++k) {
                slots[k] = (k * 43 + 11) % 65537;
            }
            encoder.encode(slots, plain);
        }
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(plain, input);
        seal::Evaluator evaluator(context);
        seal::Ciphertext product;
        evaluator.multiply(input, input, product);
        if (target_degree) {
            const std::uint64_t required_lines =
                hpu::seal_adapter::estimate_bgv_keyswitch_image_lines(
                    65536, 3, 4);
            auto package = hpu::seal_adapter::build_bgv_keyswitch_application(
                context, product, keys, required_lines);
            require(required_lines == 136193 &&
                        package.image.used_lines() == required_lines &&
                        !package.instructions.empty() && !package.dma.empty() &&
                        package.spans().size() == package.dma.size(),
                    "N=65536 BGV KeySwitch image does not fit its estimated window");
            const auto artifacts =
                hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                    "bgv_relin_target", package);
            require(artifacts.resolved_dma_manifest.find("output/c1/mod2") !=
                        std::string::npos,
                    "N=65536 BGV KeySwitch runtime lost the final output");
            std::cout << "N=65536 BGV KeySwitch image passed: "
                      << required_lines << " lines, " << package.dma.size()
                      << " DMA bindings\n";
            return 0;
        }
        require(hpu::seal_adapter::estimate_bgv_keyswitch_image_lines(
                    65536, 3, 4) == 136193 &&
                    hpu::seal_adapter::estimate_bgv_keyswitch_image_lines(
                    65536, 2, 4) == 95233,
                "BGV target-degree image capacity estimate changed");
        bool rejected = false;
        try {
            (void)hpu::seal_adapter::build_bgv_keyswitch_application(
                context, product, seal::RelinKeys{}, 2048);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV KeySwitch accepted missing relinearization keys");
        rejected = false;
        try {
            (void)hpu::seal_adapter::build_bgv_keyswitch_application(
                context, product, keys, 194);
        } catch (const std::overflow_error&) {
            rejected = true;
        }
        require(rejected, "BGV KeySwitch ignored HPU_MEM capacity");
        check_package(context, evaluator, keys, product);
        evaluator.mod_switch_to_next_inplace(product);
        check_package(context, evaluator, keys, product);
        std::cout << "BGV KeySwitch image/relocation/runtime tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV KeySwitch application test failed: " << error.what() << '\n';
        return 1;
    }
}
