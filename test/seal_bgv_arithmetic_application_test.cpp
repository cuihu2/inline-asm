#include "hpu/seal/bgv_arithmetic_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"

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

void check_binary(const seal::SEALContext& context, seal::Evaluator& evaluator,
                  const seal::Ciphertext& left, const seal::Ciphertext& right,
                  bool subtract)
{
    const auto source = context.get_context_data(left.parms_id());
    const auto& moduli = source->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::uint32_t t = static_cast<std::uint32_t>(
        source->parms().plain_modulus().value());
    const auto balance = hpu::scheme::bgv::balance_correction_factors(
        static_cast<std::uint32_t>(left.correction_factor()),
        static_cast<std::uint32_t>(right.correction_factor()), t);
    require((static_cast<std::uint64_t>(balance.left_scalar) *
             left.correction_factor()) % t == balance.output_factor &&
                (static_cast<std::uint64_t>(balance.right_scalar) *
                 right.correction_factor()) % t == balance.output_factor,
            "BGV correction factors were not balanced");
    auto package = subtract
        ? hpu::seal_adapter::build_bgv_subtract_application(
              context, left, right, 512)
        : hpu::seal_adapter::build_bgv_add_application(
              context, left, right, 512);
    seal::Ciphertext expected = left;
    if (subtract) evaluator.sub_inplace(expected, right);
    else evaluator.add_inplace(expected, right);
    require(package.parms_id == expected.parms_id() &&
                package.correction_factor == expected.correction_factor() &&
                package.correction_factor == balance.output_factor &&
                package.spans().size() == package.dma.size(),
            "BGV Add/Subtract metadata or DMA shape differs from modified-SEAL");
    for (std::size_t component = 0; component < 2; ++component) {
        const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
            const std::uint32_t qi = static_cast<std::uint32_t>(moduli[basis].value());
            const auto a = words(package.image,
                mod_id("input/left/c" + std::to_string(component), basis));
            const auto b = words(package.image,
                mod_id("input/right/c" + std::to_string(component), basis));
            if (balance.left_scalar != 1) {
                require(words(package.image,
                            mod_id("constants/bgv_balance/left", basis)).front() ==
                            balance.left_scalar % qi,
                        "BGV left scalar image does not match factor balance");
            }
            if (balance.right_scalar != 1) {
                require(words(package.image,
                            mod_id("constants/bgv_balance/right", basis)).front() ==
                            balance.right_scalar % qi,
                        "BGV right scalar image does not match factor balance");
            }
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint64_t scaled_a =
                    (static_cast<std::uint64_t>(a[k]) * balance.left_scalar) % qi;
                const std::uint64_t scaled_b =
                    (static_cast<std::uint64_t>(b[k]) * balance.right_scalar) % qi;
                const std::uint64_t actual = subtract
                    ? (scaled_a + qi - scaled_b) % qi
                    : (scaled_a + scaled_b) % qi;
                if (actual != expected_hpu.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV Add/Subtract prepared HPU words differ from modified-SEAL");
                }
            }
        }
    }
    std::size_t psync_count = 0;
    for (const auto& instruction : package.instructions) {
        psync_count += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
    }
    require(psync_count == 1, "BGV Add/Subtract emitted an extra psync");
    const auto artifacts = hpu::seal_adapter::render_bgv_arithmetic_runtime_artifacts(
        subtract ? "bgv_sub" : "bgv_add", package);
    require(artifacts.resolved_dma_manifest.find("output/c1/mod0") !=
                std::string::npos,
            "BGV Add/Subtract runtime omitted an output binding");
}

void check_negate(const seal::SEALContext& context, seal::Evaluator& evaluator,
                  const seal::Ciphertext& input)
{
    auto package = hpu::seal_adapter::build_bgv_negate_application(
        context, input, 512);
    seal::Ciphertext expected = input;
    evaluator.negate_inplace(expected);
    require(package.correction_factor == expected.correction_factor() &&
                package.parms_id == expected.parms_id(),
            "BGV Negate changed metadata");
    const auto source = context.get_context_data(input.parms_id());
    const std::size_t degree = source->parms().poly_modulus_degree();
    for (std::size_t component = 0; component < 2; ++component) {
        const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0;
             basis < source->parms().coeff_modulus().size(); ++basis) {
            const std::uint32_t qi = static_cast<std::uint32_t>(
                source->parms().coeff_modulus()[basis].value());
            const auto input_words = words(package.image,
                mod_id("input/left/c" + std::to_string(component), basis));
            for (std::size_t k = 0; k < degree; ++k) {
                const std::uint32_t actual = input_words[k] == 0
                    ? 0 : qi - input_words[k];
                if (actual != expected_hpu.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV Negate prepared HPU words differ from modified-SEAL");
                }
            }
        }
    }
}

void check_plain(const seal::SEALContext& context, seal::Evaluator& evaluator,
                 const seal::Ciphertext& input, const seal::Plaintext& plain,
                 int operation)
{
    auto package = operation == 0
        ? hpu::seal_adapter::build_bgv_add_plain_application(context, input, plain, 512)
        : operation == 1
            ? hpu::seal_adapter::build_bgv_subtract_plain_application(context, input, plain, 512)
            : hpu::seal_adapter::build_bgv_multiply_plain_application(context, input, plain, 512);
    seal::Ciphertext expected = input;
    if (operation == 0) evaluator.add_plain_inplace(expected, plain);
    else if (operation == 1) evaluator.sub_plain_inplace(expected, plain);
    else evaluator.multiply_plain_inplace(expected, plain);
    require(package.correction_factor == expected.correction_factor() &&
                package.parms_id == expected.parms_id() &&
                package.spans().size() == package.dma.size(),
            "BGV plaintext operation metadata or DMA shape differs from SEAL");
    const auto source = context.get_context_data(input.parms_id());
    const std::size_t degree = source->parms().poly_modulus_degree();
    for (std::size_t basis = 0;
         basis < source->parms().coeff_modulus().size(); ++basis) {
        const std::uint32_t qi = static_cast<std::uint32_t>(
            source->parms().coeff_modulus()[basis].value());
        const auto p = words(package.image, mod_id("input/plain", basis));
        for (std::size_t component = 0; component < 2; ++component) {
            const auto c = words(package.image,
                mod_id("input/left/c" + std::to_string(component), basis));
            const auto expected_hpu = hpu::seal_adapter::ciphertext_component_to_hpu(
                expected, component, context);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t actual = operation == 2
                    ? static_cast<std::uint32_t>(
                        (static_cast<std::uint64_t>(c[index]) * p[index]) % qi)
                    : component == 1 ? c[index]
                    : operation == 0
                        ? static_cast<std::uint32_t>(
                            (static_cast<std::uint64_t>(c[index]) + p[index]) % qi)
                        : static_cast<std::uint32_t>(
                            (static_cast<std::uint64_t>(c[index]) + qi - p[index]) % qi);
                if (actual != expected_hpu.words[basis * degree + index]) {
                    throw std::runtime_error(
                        "BGV plaintext HPU arithmetic differs from modified-SEAL");
                }
            }
        }
    }
    std::size_t psync_count = 0;
    std::size_t arithmetic_count = 0;
    const auto arithmetic_mnemonic = operation == 0 ? hpu::Mnemonic::kPadd
        : operation == 1 ? hpu::Mnemonic::kPsub : hpu::Mnemonic::kPmul;
    for (const auto& instruction : package.instructions) {
        psync_count += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
        arithmetic_count += instruction.instruction.mnemonic == arithmetic_mnemonic;
    }
    require(psync_count == 1, "BGV plaintext operation emitted extra psync");
    require(arithmetic_count == source->parms().coeff_modulus().size() *
                (operation == 2 ? 2U : 1U),
            "BGV plaintext operation emitted wrong HPU arithmetic count");
    const auto artifacts = hpu::seal_adapter::render_bgv_arithmetic_runtime_artifacts(
        "bgv_plain", package);
    require(artifacts.resolved_dma_manifest.find("input/plain/mod0") !=
                std::string::npos,
            "BGV plaintext runtime omitted prepared plaintext binding");
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
        require(context.parameters_set(), "modified-SEAL rejected BGV arithmetic context");
        seal::KeyGenerator generator(context);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Ciphertext left;
        seal::Ciphertext right;
        encryptor.encrypt_symmetric(seal::Plaintext("3"), left);
        encryptor.encrypt_symmetric(seal::Plaintext("5"), right);
        seal::Evaluator evaluator(context);
        check_binary(context, evaluator, left, right, false);
        check_binary(context, evaluator, left, right, true);
        check_negate(context, evaluator, left);
        for (int operation = 0; operation < 3; ++operation) {
            check_plain(context, evaluator, left,
                        seal::Plaintext("1x^3 + FFFF"), operation);
        }
        evaluator.mod_switch_to_next_inplace(left);
        evaluator.mod_switch_to_next_inplace(right);
        check_binary(context, evaluator, left, right, false);
        check_negate(context, evaluator, left);
        for (int operation = 0; operation < 3; ++operation) {
            check_plain(context, evaluator, left,
                        seal::Plaintext("2x^4 + 3"), operation);
        }

        seal::Ciphertext fresh_lower;
        encryptor.encrypt_zero_symmetric(left.parms_id(), fresh_lower);
        require(left.correction_factor() != fresh_lower.correction_factor(),
                "BGV test failed to create unequal correction factors");
        check_binary(context, evaluator, left, fresh_lower, false);
        check_binary(context, evaluator, left, fresh_lower, true);
        for (const auto factors : {
                 std::pair<std::uint64_t, std::uint64_t>{2, 3},
                 {123, 4567}, {65536, 5}}) {
            auto varied_left = left;
            auto varied_right = right;
            varied_left.correction_factor() = factors.first;
            varied_right.correction_factor() = factors.second;
            check_binary(context, evaluator, varied_left, varied_right, false);
            check_binary(context, evaluator, varied_left, varied_right, true);
        }
        bool rejected = false;
        try {
            (void)hpu::scheme::bgv::balance_correction_factors(0, 1, 65537);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV correction factor helper accepted zero factor");
        std::cout << "BGV ciphertext and plaintext arithmetic application tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV arithmetic application test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
