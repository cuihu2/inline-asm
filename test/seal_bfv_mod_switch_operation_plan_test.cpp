#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "scheme/bfv/modswitch.hpp"

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
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Function> void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

std::vector<std::uint32_t> allocation_words(const hpu::runtime::HpuMemImage& image,
                                            const std::string& id)
{
    const auto& allocation = image.allocation(id);
    const auto first =
        image.words().begin() +
        static_cast<std::ptrdiff_t>(allocation.span.line_offset * hpu::runtime::kHpuMemLineWords);
    return {first, first + static_cast<std::ptrdiff_t>(allocation.word_count)};
}

std::uint32_t first_word(const hpu::runtime::HpuMemImage& image, const std::string& id)
{
    return allocation_words(image, id).front();
}

void require_mod_switch_exact(const ::seal::Ciphertext& expected,
                              const hpu::seal_adapter::PreparedBfvRnsObject& input,
                              const hpu::runtime::HpuMemImage& image,
                              const hpu::seal_adapter::BfvLevelDescriptor& source,
                              const hpu::seal_adapter::BfvLevelDescriptor& destination,
                              std::size_t degree)
{
    require(expected.parms_id() == destination.parms_id && expected.size() == 2,
            "modified-SEAL BFV ModSwitch output metadata is incorrect");
    const std::uint32_t q_last = source.q_moduli.back();
    const std::uint32_t half = q_last >> 1U;
    const int dropped_id = source.keyswitch_layout.q_mod_ids.back();
    for (std::size_t component = 0; component < 2; ++component) {
        const auto dropped = allocation_words(image, input.id + "/c" + std::to_string(component) +
                                                         "/mod" + std::to_string(dropped_id));
        for (std::size_t basis = 0; basis < destination.q_moduli.size(); ++basis) {
            const std::uint32_t q = destination.q_moduli[basis];
            const int q_id = destination.keyswitch_layout.q_mod_ids[basis];
            const auto retained = allocation_words(
                image, input.id + "/c" + std::to_string(component) + "/mod" + std::to_string(q_id));
            const std::uint32_t inverse = hpu::model::inverse_mod_prime(q_last % q, q);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t rounded_last = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(dropped[index]) + half) % q_last);
                const std::uint32_t correction = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(rounded_last % q) + q - (half % q)) % q);
                const std::uint32_t actual = static_cast<std::uint32_t>(
                    ((static_cast<std::uint64_t>(retained[index]) + q - correction) * inverse) % q);
                const std::uint32_t expected_word =
                    static_cast<std::uint32_t>(expected.data(component)[basis * degree + index]);
                if (actual != expected_word) {
                    throw std::runtime_error(
                        "BFV rounded drop-last formula differs from modified-SEAL");
                }
            }
        }
    }
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::BfvContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        spec.plain_modulus_bits = 17;
        const auto bundle = hpu::seal_adapter::create_bfv_context(spec);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);
        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> left_slots(encoder.slot_count());
        std::vector<std::uint64_t> right_slots(encoder.slot_count());
        for (std::size_t index = 0; index < encoder.slot_count(); ++index) {
            left_slots[index] = (index + 2) % bundle.plain_modulus;
            right_slots[index] = (3 * index + 1) % bundle.plain_modulus;
        }
        ::seal::Plaintext left_plain;
        ::seal::Plaintext right_plain;
        encoder.encode(left_slots, left_plain);
        encoder.encode(right_slots, right_plain);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(left_plain, encrypted_left);
        encryptor.encrypt(right_plain, encrypted_right);

        hpu::seal_adapter::BfvApplicationImageBuilder builder(*bundle.context, 12288);
        builder.add_modulus_table();
        builder.add_canonical_twiddles();
        const auto& source = builder.level_chain().top();
        const auto& destination = builder.level_chain().next(source.parms_id);
        const auto left = builder.add_ciphertext("input/left", encrypted_left);
        const auto right = builder.add_ciphertext("input/right", encrypted_right);
        const auto relinearization_key =
            builder.add_relinearization_key("key/relinearization/top", relin_keys, source);
        const auto keyswitch_constants =
            builder.add_keyswitch_constants("constants/keyswitch/top", source);
        const auto multiply_constants =
            builder.add_multiply_constants("constants/multiply/top", source);
        const auto mod_switch_constants =
            builder.add_mod_switch_constants("constants/mod_switch/top_to_next", source);

        const std::size_t source_q_count = source.q_moduli.size();
        require(
            mod_switch_constants.source_parms_id == source.parms_id &&
                mod_switch_constants.destination_parms_id == destination.parms_id &&
                mod_switch_constants.dropped_mod_id == source.keyswitch_layout.q_mod_ids.back() &&
                mod_switch_constants.hardware_constant_polynomial_count == 3 * source_q_count - 1 &&
                mod_switch_constants.hardware_workspace_polynomial_count == 3 * source_q_count &&
                first_word(builder.image(), mod_switch_constants.id) == 0x424d5331U,
            "BFV ModSwitch prepared constants have the wrong shape");
        const int first_q = destination.keyswitch_layout.q_mod_ids.front();
        const std::uint32_t q_last = source.q_moduli.back();
        require(first_word(builder.image(), mod_switch_constants.hardware_prefix +
                                                "/moddown/p_inverse/mod" +
                                                std::to_string(first_q)) ==
                    hpu::model::inverse_mod_prime(q_last % destination.q_moduli.front(),
                                                  destination.q_moduli.front()),
                "BFV ModSwitch prepared an incorrect q_last inverse");

        hpu::seal_adapter::BfvOperationPlan plan(builder);
        const auto product =
            plan.append_multiply("multiply", left, right, relinearization_key, keyswitch_constants,
                                 multiply_constants, "intermediate/product");
        const auto output = plan.append_mod_switch("mod_switch", product, mod_switch_constants,
                                                   "output/product_next");
        require(plan.steps().size() == 2 &&
                    plan.steps()[1].kind == hpu::seal_adapter::BfvOperationKind::mod_switch &&
                    plan.steps()[1].resources.mod_switch_constants_id == mod_switch_constants.id &&
                    output.parms_id == destination.parms_id &&
                    output.chain_index == destination.chain_index &&
                    output.components.size() == 2 &&
                    output.domain == hpu::runtime::PolynomialDomain::coefficient,
                "BFV ModSwitch planner did not perform the adjacent level transition");

        const auto lowered =
            hpu::seal_adapter::lower_bfv_operation_plan(plan, *bundle.context, true, true);
        require(lowered.operations.size() == 2 &&
                    lowered.operations[1].body_asm ==
                        hpu::scheme::bfv::generate_modswitch_body_asm(
                            static_cast<int>(source_q_count), 2, false, false),
                "BFV ModSwitch lowering did not select the nested rounded drop-last kernel");
        const auto relocation = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, builder.image(), *bundle.context);
        require(relocation.complete(), "BFV Multiply/ModSwitch relocation is incomplete");
        const auto has_binding = [&](const std::string& operation_id,
                                     const std::string& allocation_id) {
            return std::any_of(relocation.bindings.begin(), relocation.bindings.end(),
                               [&](const auto& binding) {
                                   return binding.operation_id == operation_id &&
                                          binding.allocation_id == allocation_id;
                               });
        };
        require(
            has_binding("mod_switch",
                        mod_switch_constants.hardware_prefix + "/half/mod" +
                            std::to_string(source.keyswitch_layout.q_mod_ids.back())) &&
                has_binding("mod_switch", mod_switch_constants.hardware_prefix +
                                              "/workspace/bconv/normalized0") &&
                has_binding("mod_switch", mod_switch_constants.hardware_prefix +
                                              "/moddown/p_inverse/mod" + std::to_string(first_q)) &&
                has_binding("mod_switch", "output/product_next/c1/mod" + std::to_string(first_q)),
            "BFV ModSwitch relocation omitted a constant, workspace, or output");

        const auto runtime = hpu::seal_adapter::lower_bfv_runtime_program(lowered, relocation);
        const auto artifacts = hpu::seal_adapter::render_bfv_runtime_artifacts(
            "bfv_multiply_then_mod_switch", runtime, builder.image().capacity_lines());
        require(runtime.dma.size() == relocation.expected_dma_count &&
                    artifacts.header.find("int hpu_run_bfv_multiply_then_mod_switch(void);") !=
                        std::string::npos &&
                    artifacts.resolved_dma_manifest.find("\"mod_switch\"") != std::string::npos &&
                    artifacts.resolved_dma_manifest.find("\"output/product_next/c1/mod") !=
                        std::string::npos,
                "BFV Multiply/ModSwitch runtime artifacts are incomplete");

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected_mod_switch = encrypted_left;
        evaluator.mod_switch_to_next_inplace(expected_mod_switch);
        require_mod_switch_exact(expected_mod_switch, left, builder.image(), source, destination,
                                 spec.poly_modulus_degree);
        ::seal::Ciphertext expected_product;
        evaluator.multiply(encrypted_left, encrypted_right, expected_product);
        evaluator.relinearize_inplace(expected_product, relin_keys);
        evaluator.mod_switch_to_next_inplace(expected_product);
        require(expected_product.parms_id() == output.parms_id &&
                    expected_product.size() == output.components.size(),
                "BFV composed planner metadata differs from modified-SEAL");

        auto wrong_constants = mod_switch_constants;
        wrong_constants.source_parms_id = destination.parms_id;
        require_invalid_argument(
            [&] {
                (void)plan.append_mod_switch("wrong_constants", product, wrong_constants,
                                             "invalid/wrong_constants");
            },
            "BFV ModSwitch accepted constants for the wrong source level");
        require_invalid_argument(
            [&] {
                (void)builder.add_mod_switch_constants("constants/mod_switch/bottom",
                                                       builder.level_chain().bottom());
            },
            "BFV ModSwitch constants were created for the bottom level");

        std::cout << "SEAL BFV Multiply -> ModSwitch planner/runtime path passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL BFV ModSwitch operation plan test failed: " << error.what() << '\n';
        return 1;
    }
}
