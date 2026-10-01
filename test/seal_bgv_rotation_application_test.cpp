#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/bgv_keyswitch_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bfv/galois.hpp"

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

std::uint32_t add(std::uint32_t a, std::uint32_t b, std::uint32_t q)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(a) + b) % q);
}

std::uint32_t mul(std::uint32_t a, std::uint32_t b, std::uint32_t q)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(a) * b) % q);
}

void check(const seal::SEALContext& context, seal::Evaluator& evaluator,
           const seal::Ciphertext& input, const seal::GaloisKeys& keys,
           int steps, bool columns)
{
    const auto source = context.get_context_data(input.parms_id());
    const auto& q_moduli = source->parms().coeff_modulus();
    const auto& key_moduli = context.key_context_data()->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = q_moduli.size();
    const std::size_t p_id = key_moduli.size() - 1;
    const std::uint32_t element = columns
        ? hpu::scheme::bfv::column_rotation_galois_element(degree)
        : hpu::scheme::bfv::row_rotation_galois_element(degree, steps);
    const auto capacity = hpu::seal_adapter::estimate_bgv_rotation_image_lines(
        degree, q_count, key_moduli.size());
    auto package = columns
        ? hpu::seal_adapter::build_bgv_rotate_columns_application(
              context, input, keys, capacity)
        : hpu::seal_adapter::build_bgv_rotate_rows_application(
              context, input, keys, steps, capacity);
    require(package.image.used_lines() == capacity &&
                package.spans().size() == package.dma.size() &&
                package.correction_factor == input.correction_factor() &&
                package.parms_id == input.parms_id(),
            "BGV rotation image capacity, DMA or metadata is wrong");
    std::size_t psync_count = 0;
    for (const auto& instruction : package.instructions) {
        psync_count += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
    }
    require(psync_count == 1, "BGV rotation must be one uninterrupted program");
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        require(words(package.image, mod_id("input/c1", basis)) ==
                    std::vector<std::uint32_t>(degree, 0),
                "BGV rotation KeySwitch base c1 is not zero");
    }

    std::vector<std::vector<std::uint32_t>> rotated(q_count);
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto q = static_cast<std::uint32_t>(q_moduli[basis].value());
        const auto psi = static_cast<std::uint32_t>(
            source->small_ntt_tables()[basis].get_root());
        const auto prefix = mod_id("constants/twiddle/galois", basis) + "/intt";
        hpu::model::HardwareNttModel model(
            degree, q, hpu::model::pow_mod(psi, 2, q));
        hpu::model::InverseNttTables tables;
        for (std::size_t stage = 0; stage < model.log_degree(); ++stage) {
            tables.stages.push_back(words(package.image,
                prefix + "/stage" + std::to_string(stage)));
        }
        tables.post_scale = words(package.image,
            prefix + "/post_untwist_scale");
        for (std::size_t component = 0; component < 2; ++component) {
            const auto original = words(package.image,
                mod_id("input/original/c" + std::to_string(component), basis));
            const auto transformed_coeff = model.inverse(original, tables);
            const auto direct_coeff = hpu::model::automorphism_coefficients(
                hpu::model::negacyclic_inverse(original, q, psi), element, q);
            require(transformed_coeff == direct_coeff,
                    "BGV modified-root INTT does not implement Galois automorphism");
            const auto physical = hpu::model::negacyclic_forward(
                transformed_coeff, q, psi);
            if (component == 1) rotated[basis] = physical;
        }
    }

    std::vector<std::vector<std::vector<std::uint32_t>>> accumulators(
        2, std::vector<std::vector<std::uint32_t>>(
               q_count + 1, std::vector<std::uint32_t>(degree, 0)));
    for (std::size_t target = 0; target <= q_count; ++target) {
        const std::size_t id = target == q_count ? p_id : target;
        const auto modulus = static_cast<std::uint32_t>(key_moduli[id].value());
        const auto psi = static_cast<std::uint32_t>(
            context.key_context_data()->small_ntt_tables()[id].get_root());
        for (std::size_t digit = 0; digit < q_count; ++digit) {
            std::vector<std::uint32_t> operand = rotated[digit];
            if (target != digit) {
                operand = hpu::model::negacyclic_inverse(
                    operand, static_cast<std::uint32_t>(q_moduli[digit].value()),
                    static_cast<std::uint32_t>(
                        source->small_ntt_tables()[digit].get_root()));
                for (auto& value : operand) value %= modulus;
                operand = hpu::model::negacyclic_forward(operand, modulus, psi);
            }
            for (std::size_t component = 0; component < 2; ++component) {
                const auto key = words(package.image,
                    mod_id("keys/digit" + std::to_string(digit) + "/c" +
                           std::to_string(component), id));
                for (std::size_t k = 0; k < degree; ++k) {
                    accumulators[component][target][k] = add(
                        accumulators[component][target][k],
                        mul(operand[k], key[k], modulus), modulus);
                }
            }
        }
    }

    seal::Ciphertext expected = input;
    if (columns) evaluator.rotate_columns_inplace(expected, keys);
    else evaluator.rotate_rows_inplace(expected, steps, keys);
    require(expected.correction_factor() == package.correction_factor &&
                expected.parms_id() == package.parms_id,
            "BGV rotation factor or level differs from modified-SEAL");
    const auto p = static_cast<std::uint32_t>(key_moduli[p_id].value());
    const auto t = static_cast<std::uint32_t>(
        source->parms().plain_modulus().value());
    const auto neg_inv = words(package.image,
        "constants/bgv_keyswitch/neg_inv_t").front();
    for (std::size_t component = 0; component < 2; ++component) {
        const auto p_coeff = hpu::model::negacyclic_inverse(
            accumulators[component][q_count], p,
            static_cast<std::uint32_t>(
                context.key_context_data()->small_ntt_tables()[p_id].get_root()));
        const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto q = static_cast<std::uint32_t>(q_moduli[basis].value());
            const auto psi = static_cast<std::uint32_t>(
                source->small_ntt_tables()[basis].get_root());
            const auto p_mod = words(package.image,
                mod_id("constants/bgv_keyswitch/p_mod", basis)).front();
            const auto p_inv = words(package.image,
                mod_id("constants/bgv_keyswitch/p_inv", basis)).front();
            std::vector<std::uint32_t> correction(degree);
            for (std::size_t k = 0; k < degree; ++k) {
                const auto u = mul(p_coeff[k] % t, neg_inv, t);
                correction[k] = add(p_coeff[k] % q, mul(u, p_mod, q), q);
            }
            const auto correction_ntt = hpu::model::negacyclic_forward(
                correction, q, psi);
            const auto base = component == 0
                ? hpu::model::automorphism_fused_inverse(
                    words(package.image,
                        mod_id("input/original/c0", basis)), element, q, psi)
                : std::vector<std::uint32_t>(degree, 0);
            for (std::size_t k = 0; k < degree; ++k) {
                const auto switched = mul(
                    add(accumulators[component][basis][k],
                        q - correction_ntt[k], q), p_inv, q);
                const auto actual = add(base[k], switched, q);
                if (actual != expected_hpu.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV rotation HPU_MEM formula differs from modified-SEAL");
                }
            }
        }
    }
    const auto artifacts = hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
        columns ? "bgv_columns" : "bgv_rows", package);
    require(artifacts.resolved_dma_manifest.find("input/original/c0/mod0") !=
                std::string::npos &&
                artifacts.resolved_dma_manifest.find("output/c1/mod0") !=
                    std::string::npos,
            "BGV rotation runtime omitted input or output binding");
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
        require(context.parameters_set(), "modified-SEAL rejected BGV rotation context");
        seal::KeyGenerator generator(context);
        const std::vector<std::uint32_t> elements{
            hpu::scheme::bfv::row_rotation_galois_element(128, 1),
            hpu::scheme::bfv::row_rotation_galois_element(128, -2),
            hpu::scheme::bfv::column_rotation_galois_element(128)};
        seal::GaloisKeys keys;
        generator.create_galois_keys(elements, keys);
        seal::BatchEncoder encoder(context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t k = 0; k < slots.size(); ++k) {
            slots[k] = (k * 43 + 11) % 65537;
        }
        seal::Plaintext plain;
        encoder.encode(slots, plain);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(plain, input);
        seal::Evaluator evaluator(context);
        check(context, evaluator, input, keys, 1, false);
        check(context, evaluator, input, keys, -2, false);
        check(context, evaluator, input, keys, 0, true);
        evaluator.mod_switch_to_next_inplace(input);
        check(context, evaluator, input, keys, 1, false);
        check(context, evaluator, input, keys, 0, true);
        require(hpu::seal_adapter::estimate_bgv_rotation_image_lines(
                    65536, 3, 4) == 169985,
                "BGV target-degree rotation capacity estimate changed");
        bool rejected = false;
        try {
            (void)hpu::seal_adapter::build_bgv_rotate_rows_application(
                context, input, keys, 0, 2048);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV rotation accepted a zero row step");
        rejected = false;
        try {
            (void)hpu::seal_adapter::build_bgv_rotate_rows_application(
                context, input, keys, 2, 2048);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV rotation accepted a missing Galois key");
        rejected = false;
        try {
            (void)hpu::seal_adapter::build_bgv_rotate_columns_application(
                context, input, keys, 1);
        } catch (const std::overflow_error&) {
            rejected = true;
        }
        require(rejected, "BGV rotation ignored HPU_MEM capacity");
        std::cout << "BGV row/column rotation application tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV rotation application test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
