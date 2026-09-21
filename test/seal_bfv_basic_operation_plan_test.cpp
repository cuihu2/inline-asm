#include "hpu/model/hardware_ntt.hpp"
#include "hpu/runtime/memory_image.hpp"
#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_software_executor.hpp"
#include "scheme/bfv/basic_arithmetic.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

enum class ExactOperation { add, subtract, add_plain, subtract_plain, negate };

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

std::string limb_id(const hpu::seal_adapter::PreparedBfvRnsObject& object, std::size_t component,
                    std::uint8_t modulus_id)
{
    return object.id + "/c" + std::to_string(component) + "/mod" + std::to_string(modulus_id);
}

std::uint32_t apply_modular(ExactOperation operation, std::uint32_t left, std::uint32_t right,
                            std::uint32_t modulus)
{
    switch (operation) {
    case ExactOperation::add:
    case ExactOperation::add_plain:
        return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) + right) % modulus);
    case ExactOperation::subtract:
    case ExactOperation::subtract_plain:
        return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) + modulus - right) %
                                          modulus);
    case ExactOperation::negate:
        return left == 0 ? 0 : modulus - left;
    }
    throw std::logic_error("unknown exact BFV operation");
}

void require_exact(const ::seal::Ciphertext& expected,
                   const hpu::seal_adapter::PreparedBfvRnsObject& output,
                   const hpu::seal_adapter::PreparedBfvRnsObject& left,
                   const hpu::seal_adapter::PreparedBfvRnsObject* right, ExactOperation operation,
                   const hpu::runtime::HpuMemImage& image,
                   const hpu::seal_adapter::BfvLevelRegistry& registry, const char* name)
{
    if (expected.parms_id() != output.parms_id || expected.size() != output.components.size()) {
        throw std::runtime_error(std::string(name) + " output shape differs from SEAL");
    }
    const std::size_t degree = registry.poly_modulus_degree;
    for (std::size_t component = 0; component < output.components.size(); ++component) {
        const auto& polynomial = output.components[component];
        for (std::size_t basis = 0; basis < polynomial.modulus_ids.size(); ++basis) {
            const std::uint8_t modulus_id = polynomial.modulus_ids[basis];
            const std::uint32_t modulus = registry.modulus_table[modulus_id];
            const auto left_words = allocation_words(image, limb_id(left, component, modulus_id));
            std::vector<std::uint32_t> right_words;
            const bool changes_component = operation != ExactOperation::add_plain &&
                                                   operation != ExactOperation::subtract_plain
                                               ? operation != ExactOperation::negate
                                               : component == 0;
            if (right && changes_component) {
                const std::size_t right_component =
                    operation == ExactOperation::add_plain ||
                            operation == ExactOperation::subtract_plain
                        ? 0
                        : component;
                right_words = allocation_words(image, limb_id(*right, right_component, modulus_id));
            }
            for (std::size_t index = 0; index < degree; ++index) {
                std::uint32_t actual = left_words[index];
                if (operation == ExactOperation::negate) {
                    actual = apply_modular(operation, actual, 0, modulus);
                } else if (changes_component) {
                    actual = apply_modular(operation, actual, right_words[index], modulus);
                }
                const auto expected_word =
                    static_cast<std::uint32_t>(expected.data(component)[basis * degree + index]);
                if (actual != expected_word) {
                    throw std::runtime_error(std::string(name) +
                                             " modular result differs from SEAL");
                }
            }
        }
    }
}

const hpu::seal_adapter::PreparedCanonicalTwiddles&
find_twiddles(const std::vector<hpu::seal_adapter::PreparedCanonicalTwiddles>& tables,
              std::uint8_t modulus_id)
{
    const auto found = std::find_if(tables.begin(), tables.end(), [&](const auto& table) {
        return table.modulus_id == modulus_id;
    });
    if (found == tables.end()) {
        throw std::runtime_error("BFV canonical twiddle table is missing");
    }
    return *found;
}

void require_multiply_plain_exact(
    const ::seal::Ciphertext& expected, const hpu::seal_adapter::PreparedBfvRnsObject& output,
    const hpu::seal_adapter::PreparedBfvRnsObject& ciphertext,
    const hpu::seal_adapter::PreparedBfvRnsObject& plaintext,
    const hpu::runtime::HpuMemImage& image, const hpu::seal_adapter::BfvLevelRegistry& registry,
    const std::vector<hpu::seal_adapter::PreparedCanonicalTwiddles>& tables)
{
    require(expected.parms_id() == output.parms_id && expected.size() == 2,
            "BFV MultiplyPlain output shape differs from SEAL");
    const std::size_t degree = registry.poly_modulus_degree;
    for (std::size_t component = 0; component < output.components.size(); ++component) {
        for (std::size_t basis = 0; basis < output.components[component].modulus_ids.size();
             ++basis) {
            const std::uint8_t modulus_id = output.components[component].modulus_ids[basis];
            const std::uint32_t modulus = registry.modulus_table[modulus_id];
            const auto& twiddles = find_twiddles(tables, modulus_id);
            require(twiddles.modulus == modulus,
                    "BFV MultiplyPlain twiddle modulus is inconsistent");
            auto transformed = hpu::model::negacyclic_forward(
                allocation_words(image, limb_id(ciphertext, component, modulus_id)), modulus,
                twiddles.canonical_psi);
            const auto plain_words = allocation_words(image, limb_id(plaintext, 0, modulus_id));
            for (std::size_t index = 0; index < degree; ++index) {
                transformed[index] = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(transformed[index]) * plain_words[index]) %
                    modulus);
            }
            const auto actual =
                hpu::model::negacyclic_inverse(transformed, modulus, twiddles.canonical_psi);
            for (std::size_t index = 0; index < degree; ++index) {
                const auto expected_word =
                    static_cast<std::uint32_t>(expected.data(component)[basis * degree + index]);
                if (actual[index] != expected_word) {
                    throw std::runtime_error("BFV MultiplyPlain NTT pipeline differs from SEAL");
                }
            }
        }
    }
}

void require_executor_exact(const ::seal::Ciphertext& expected,
                            const hpu::seal_adapter::PreparedBfvRnsObject& output,
                            const hpu::seal_adapter::BfvSoftwareExecutor& executor,
                            const char* name)
{
    if (expected.parms_id() != output.parms_id || expected.size() != output.components.size()) {
        throw std::runtime_error(std::string(name) + " output shape differs from SEAL");
    }
    for (std::size_t component = 0; component < output.components.size(); ++component) {
        const auto actual = executor.export_component(output, component);
        if (!std::equal(actual.words.begin(), actual.words.end(), expected.data(component))) {
            throw std::runtime_error(std::string(name) +
                                     " software execution differs from SEAL coefficients");
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
        key_generator.create_public_key(public_key);

        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> left_slots(encoder.slot_count());
        std::vector<std::uint64_t> right_slots(encoder.slot_count());
        std::vector<std::uint64_t> plain_slots(encoder.slot_count());
        for (std::size_t index = 0; index < encoder.slot_count(); ++index) {
            left_slots[index] = index % 5 == 0 ? bundle.plain_modulus - 1 : index + 3;
            right_slots[index] = index % 7 == 0 ? bundle.plain_modulus - 2 : 2 * index + 1;
            plain_slots[index] = index % 3 == 0 ? bundle.plain_modulus - 3 : 3 * index + 2;
        }
        ::seal::Plaintext encoded_left;
        ::seal::Plaintext encoded_right;
        ::seal::Plaintext encoded_plain;
        encoder.encode(left_slots, encoded_left);
        encoder.encode(right_slots, encoded_right);
        encoder.encode(plain_slots, encoded_plain);

        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_left;
        ::seal::Ciphertext encrypted_right;
        encryptor.encrypt(encoded_left, encrypted_left);
        encryptor.encrypt(encoded_right, encrypted_right);

        hpu::seal_adapter::BfvApplicationImageBuilder image_builder(*bundle.context, 1024);
        image_builder.add_modulus_table();
        const auto canonical_twiddles = image_builder.add_canonical_twiddles();
        const auto left = image_builder.add_ciphertext("input/left", encrypted_left);
        const auto right = image_builder.add_ciphertext("input/right", encrypted_right);
        const auto& top_level = image_builder.level_chain().top();
        const auto plain = image_builder.add_add_subtract_plaintext("input/plain_add_subtract",
                                                                    encoded_plain, top_level);
        const auto multiply_plain =
            image_builder.add_multiply_plaintext("input/plain_multiply", encoded_plain, top_level);

        hpu::seal_adapter::BfvOperationPlan plan(image_builder);
        const auto added = plan.append_add("add", left, right, "output/add");
        const auto subtracted = plan.append_subtract("subtract", left, right, "output/subtract");
        const auto added_plain =
            plan.append_add_plain("add_plain", left, plain, "output/add_plain");
        const auto subtracted_plain =
            plan.append_subtract_plain("subtract_plain", left, plain, "output/subtract_plain");
        const auto multiplied_plain = plan.append_multiply_plain(
            "multiply_plain", left, multiply_plain, "output/multiply_plain");
        const auto negated = plan.append_negate("negate", left, "output/negate");

        const auto& steps = plan.steps();
        require(steps.size() == 6 && steps[0].kind == hpu::seal_adapter::BfvOperationKind::add &&
                    steps[1].kind == hpu::seal_adapter::BfvOperationKind::subtract &&
                    steps[2].kind == hpu::seal_adapter::BfvOperationKind::add_plain &&
                    steps[3].kind == hpu::seal_adapter::BfvOperationKind::subtract_plain &&
                    steps[4].kind == hpu::seal_adapter::BfvOperationKind::multiply_plain &&
                    steps[4].resources.requires_canonical_twiddles &&
                    steps[5].kind == hpu::seal_adapter::BfvOperationKind::negate,
                "BFV basic operation plan lost its explicit step sequence");
        for (const auto& step : steps) {
            require(step.output.metadata.parms_id == top_level.parms_id &&
                        step.output.metadata.chain_index == top_level.chain_index &&
                        step.output.component_count == 2 &&
                        step.output.domain == hpu::runtime::PolynomialDomain::coefficient &&
                        step.output.key_domain == 1,
                    "BFV basic operation plan changed level or representation");
        }

        const auto lowered = hpu::seal_adapter::lower_bfv_operation_plan(plan, *bundle.context);
        const int num_q = static_cast<int>(top_level.q_moduli.size());
        require(lowered.operations.size() == 6 &&
                    lowered.operations[0].body_asm ==
                        hpu::scheme::bfv::generate_add_body_asm(num_q, false, false) &&
                    lowered.operations[1].body_asm ==
                        hpu::scheme::bfv::generate_subtract_body_asm(num_q, false, false) &&
                    lowered.operations[2].body_asm ==
                        hpu::scheme::bfv::generate_add_plain_body_asm(num_q, false, false) &&
                    lowered.operations[3].body_asm ==
                        hpu::scheme::bfv::generate_subtract_plain_body_asm(num_q, false, false) &&
                    lowered.operations[4].body_asm ==
                        hpu::scheme::bfv::generate_multiply_plain_body_asm(
                            static_cast<int>(spec.poly_modulus_degree), num_q, false, false) &&
                    lowered.operations[5].body_asm ==
                        hpu::scheme::bfv::generate_negate_body_asm(num_q, false, false),
                "BFV basic operation lowering selected an incorrect kernel");

        const auto relocations = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, image_builder.image(), *bundle.context);
        std::size_t ntt_stages = 0;
        for (std::size_t remaining = spec.poly_modulus_degree; remaining > 1; remaining >>= 1U) {
            ++ntt_stages;
        }
        const std::size_t expected_dma_count = 1 + 26 * top_level.q_moduli.size() +
                                               2 * top_level.q_moduli.size() * (2 * ntt_stages + 5);
        require(relocations.complete() && relocations.expected_dma_count == expected_dma_count &&
                    relocations.bindings.front().allocation_id == "constants/modulus_table",
                "BFV basic operation relocation is incomplete");
        for (const auto& step : steps) {
            require(std::any_of(relocations.bindings.begin(), relocations.bindings.end(),
                                [&](const hpu::seal_adapter::BfvDmaBinding& binding) {
                                    return binding.operation_id == step.id &&
                                           binding.direction ==
                                               hpu::seal_adapter::BfvDmaDirection::store &&
                                           binding.allocation_id.find(step.output.id) == 0;
                                }),
                    "BFV basic operation output has no resolved DMA binding");
        }

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        hpu::seal_adapter::BfvSoftwareExecutor software_executor(*bundle.context,
                                                                 image_builder.image());
        evaluator.add(encrypted_left, encrypted_right, expected);
        require_exact(expected, added, left, &right, ExactOperation::add, image_builder.image(),
                      image_builder.registry(), "BFV Add");
        software_executor.add(left, right, added);
        require_executor_exact(expected, added, software_executor, "BFV Add");
        evaluator.sub(encrypted_left, encrypted_right, expected);
        require_exact(expected, subtracted, left, &right, ExactOperation::subtract,
                      image_builder.image(), image_builder.registry(), "BFV Subtract");
        software_executor.subtract(left, right, subtracted);
        require_executor_exact(expected, subtracted, software_executor, "BFV Subtract");
        evaluator.add_plain(encrypted_left, encoded_plain, expected);
        require_exact(expected, added_plain, left, &plain, ExactOperation::add_plain,
                      image_builder.image(), image_builder.registry(), "BFV AddPlain");
        software_executor.add_plain(left, plain, added_plain);
        require_executor_exact(expected, added_plain, software_executor, "BFV AddPlain");
        evaluator.sub_plain(encrypted_left, encoded_plain, expected);
        require_exact(expected, subtracted_plain, left, &plain, ExactOperation::subtract_plain,
                      image_builder.image(), image_builder.registry(), "BFV SubtractPlain");
        software_executor.subtract_plain(left, plain, subtracted_plain);
        require_executor_exact(expected, subtracted_plain, software_executor, "BFV SubtractPlain");
        evaluator.multiply_plain(encrypted_left, encoded_plain, expected);
        require_multiply_plain_exact(expected, multiplied_plain, left, multiply_plain,
                                     image_builder.image(), image_builder.registry(),
                                     canonical_twiddles);
        software_executor.multiply_plain(left, multiply_plain, canonical_twiddles,
                                         multiplied_plain);
        require_executor_exact(expected, multiplied_plain, software_executor, "BFV MultiplyPlain");
        evaluator.negate(encrypted_left, expected);
        require_exact(expected, negated, left, nullptr, ExactOperation::negate,
                      image_builder.image(), image_builder.registry(), "BFV Negate");
        software_executor.negate(left, negated);
        require_executor_exact(expected, negated, software_executor, "BFV Negate");

        require_invalid_argument(
            [&] { (void)plan.append_negate("add", left, "output/duplicate_step"); },
            "duplicate BFV operation step id was accepted");
        require_invalid_argument(
            [&] {
                (void)plan.append_add_plain("invalid_multiply_plain", left, multiply_plain,
                                            "output/invalid_plain");
            },
            "NTT-domain BFV MultiplyPlain operand was accepted by AddPlain");
        require_invalid_argument(
            [&] {
                (void)plan.append_multiply_plain("invalid_add_plain", left, plain,
                                                 "output/invalid_multiply_plain");
            },
            "coefficient-domain BFV AddPlain operand was accepted by "
            "MultiplyPlain");
        require_invalid_argument(
            [&] { software_executor.add_plain(left, multiply_plain, added_plain); },
            "BFV software AddPlain accepted an NTT-domain plaintext");
        require_invalid_argument(
            [&] {
                software_executor.multiply_plain(left, plain, canonical_twiddles, multiplied_plain);
            },
            "BFV software MultiplyPlain accepted a coefficient-domain plaintext");

        hpu::seal_adapter::BfvApplicationImageBuilder no_twiddle_builder(*bundle.context, 256);
        no_twiddle_builder.add_modulus_table();
        const auto no_twiddle_ciphertext =
            no_twiddle_builder.add_ciphertext("input/ciphertext", encrypted_left);
        const auto no_twiddle_plaintext = no_twiddle_builder.add_multiply_plaintext(
            "input/plaintext", encoded_plain, no_twiddle_builder.level_chain().top());
        hpu::seal_adapter::BfvOperationPlan no_twiddle_plan(no_twiddle_builder);
        require_invalid_argument(
            [&] {
                (void)no_twiddle_plan.append_multiply_plain("multiply_plain", no_twiddle_ciphertext,
                                                            no_twiddle_plaintext,
                                                            "output/multiply_plain");
            },
            "BFV MultiplyPlain accepted an image without canonical twiddles");

        ::seal::Ciphertext next_level_ciphertext = encrypted_left;
        evaluator.mod_switch_to_next_inplace(next_level_ciphertext);
        const auto next_level =
            image_builder.add_ciphertext("input/next_level", next_level_ciphertext);
        require_invalid_argument(
            [&] {
                (void)plan.append_add("invalid_cross_level", left, next_level,
                                      "output/invalid_cross_level");
            },
            "cross-level BFV ciphertext operands were accepted");

        std::cout << "SEAL BFV basic operation planner/relocation path passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL BFV basic operation plan test failed: " << error.what() << '\n';
        return 1;
    }
}
