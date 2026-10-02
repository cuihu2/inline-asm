#include "hpu/seal/bgv_linear_operation_plan.hpp"
#include "hpu/seal/bgv_modswitch_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"
#include "scheme/bfv/galois.hpp"

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

void check_binary_step(
    const seal::SEALContext& context,
    const hpu::seal_adapter::BgvKeySwitchApplication& package,
    const seal::Ciphertext& left, const seal::Ciphertext& right,
    const seal::Ciphertext& expected, const std::string& step_id,
    bool subtract)
{
    const auto source = context.get_context_data(left.parms_id());
    const auto& moduli = source->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const auto t = static_cast<std::uint32_t>(
        source->parms().plain_modulus().value());
    const auto balance = hpu::scheme::bgv::balance_correction_factors(
        static_cast<std::uint32_t>(left.correction_factor()),
        static_cast<std::uint32_t>(right.correction_factor()), t);
    require(expected.correction_factor() == balance.output_factor,
            "BGV binary step output correction factor differs from SEAL");
    for (std::size_t component = 0; component < 2; ++component) {
        const auto left_physical = hpu::seal_adapter::ciphertext_component_to_hpu(
            left, component, context);
        const auto expected_physical = hpu::seal_adapter::ciphertext_component_to_hpu(
            expected, component, context);
        for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
            const auto q = static_cast<std::uint32_t>(moduli[basis].value());
            const auto right_words = words(package.image,
                "steps/" + step_id + "/right/c" +
                std::to_string(component) + "/mod" + std::to_string(basis));
            if (balance.left_scalar != 1) {
                require(words(package.image,
                    "steps/" + step_id + "/balance/left/mod" +
                    std::to_string(basis)).front() == balance.left_scalar % q,
                    "BGV binary left balance splat is wrong");
            }
            if (balance.right_scalar != 1) {
                require(words(package.image,
                    "steps/" + step_id + "/balance/right/mod" +
                    std::to_string(basis)).front() == balance.right_scalar % q,
                    "BGV binary right balance splat is wrong");
            }
            for (std::size_t k = 0; k < degree; ++k) {
                const auto a = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(
                        left_physical.words[basis * degree + k]) *
                     balance.left_scalar) % q);
                const auto b = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(right_words[k]) *
                     balance.right_scalar) % q);
                const auto actual = subtract
                    ? static_cast<std::uint32_t>(
                        (static_cast<std::uint64_t>(a) + q - b) % q)
                    : static_cast<std::uint32_t>(
                        (static_cast<std::uint64_t>(a) + b) % q);
                if (actual != expected_physical.words[basis * degree + k]) {
                    throw std::runtime_error(
                        "BGV binary chain step differs from modified-SEAL");
                }
            }
        }
    }
}

void check_keyswitch_splice(
    const hpu::seal_adapter::BgvKeySwitchApplication& combined,
    const hpu::seal_adapter::BgvKeySwitchApplication& standalone,
    const std::string& step_id, const std::string& input_prefix,
    const std::string& output_prefix, const std::string& operation,
    const std::string& standalone_input_prefix)
{
    const auto relocated_prefix = "steps/" + step_id + "/" + operation + "/";
    for (const auto& allocation : standalone.image.allocations()) {
        const auto& id = allocation.id;
        if (id == "constants/modulus_table" ||
            id.rfind(standalone_input_prefix + "/c", 0) == 0 ||
            id.rfind("output/c", 0) == 0) {
            continue;
        }
        const auto& relocated = combined.image.allocation(relocated_prefix + id);
        require(relocated.word_count == allocation.word_count &&
                    relocated.read_only == allocation.read_only,
                "BGV KeySwitch resource shape changed during plan composition");
        if (allocation.read_only) {
            require(words(combined.image, relocated_prefix + id) ==
                        words(standalone.image, id),
                    "BGV KeySwitch key/twiddle changed during plan composition");
        }
    }
    const auto middle_count = standalone.instructions.size() - 3;
    bool found = false;
    for (std::size_t index = 0;
         index + middle_count <= combined.instructions.size(); ++index) {
        bool equal = true;
        for (std::size_t offset = 0; offset < middle_count; ++offset) {
            equal &= combined.instructions[index + offset].word ==
                standalone.instructions[offset + 1].word;
        }
        if (!equal) continue;
        for (std::size_t dma_index = 1;
             dma_index < standalone.dma.size(); ++dma_index) {
            const auto& binding = standalone.dma[dma_index];
            const auto& id = binding.allocation_id;
            std::string relocated;
            if (id.rfind(standalone_input_prefix + "/c", 0) == 0) {
                relocated = input_prefix +
                    id.substr(standalone_input_prefix.size());
            } else if (id.rfind("output/c", 0) == 0) {
                relocated = output_prefix + id.substr(std::string("output").size());
            } else {
                relocated = relocated_prefix + id;
            }
            bool matched = false;
            for (const auto& combined_binding : combined.dma) {
                matched |= combined_binding.instruction_index ==
                               index + binding.instruction_index - 1 &&
                    combined_binding.direction == binding.direction &&
                    combined_binding.object_slot == binding.object_slot &&
                    combined_binding.allocation_id == combined.image.allocation(relocated).id;
            }
            if (!matched) {
                equal = false;
                break;
            }
        }
        if (equal) {
            found = true;
            break;
        }
    }
    require(found, "BGV KeySwitch instruction/DMA splice differs from standalone");
}

void check_rotation_splice(
    const hpu::seal_adapter::BgvKeySwitchApplication& combined,
    const hpu::seal_adapter::BgvKeySwitchApplication& standalone,
    const std::string& step_id, const std::string& input_prefix,
    const std::string& output_prefix)
{
    check_keyswitch_splice(combined, standalone, step_id, input_prefix,
                           output_prefix, "rotation", "input/original");
}

void check_multiply_splice(
    const hpu::seal_adapter::BgvKeySwitchApplication& combined,
    const hpu::seal_adapter::BgvKeySwitchApplication& standalone,
    const std::string& step_id, const std::string& input_prefix,
    const std::string& output_prefix)
{
    check_keyswitch_splice(combined, standalone, step_id, input_prefix,
                           output_prefix, "multiply", "input/left");
}

void check_modswitch_splice(
    const hpu::seal_adapter::BgvKeySwitchApplication& combined,
    const hpu::seal_adapter::BgvModSwitchApplication& standalone,
    const std::string& step_id, const std::string& input_prefix,
    const std::string& output_prefix)
{
    const auto relocated_prefix = "steps/" + step_id + "/modswitch/";
    for (const auto& allocation : standalone.image.allocations()) {
        const auto& id = allocation.id;
        if (id == "constants/modulus_table" ||
            id.rfind("input/c", 0) == 0 || id.rfind("output/c", 0) == 0) {
            continue;
        }
        const auto& relocated = combined.image.allocation(relocated_prefix + id);
        require(relocated.word_count == allocation.word_count &&
                    relocated.read_only == allocation.read_only,
                "BGV ModSwitch resource shape changed during composition");
        if (allocation.read_only) {
            require(words(combined.image, relocated_prefix + id) ==
                        words(standalone.image, id),
                    "BGV ModSwitch constants changed during composition");
        }
    }
    const auto middle_count = standalone.instructions.size() - 3;
    bool found = false;
    for (std::size_t index = 0;
         index + middle_count <= combined.instructions.size(); ++index) {
        bool equal = true;
        for (std::size_t offset = 0; offset < middle_count; ++offset) {
            equal &= combined.instructions[index + offset].word ==
                standalone.instructions[offset + 1].word;
        }
        if (!equal) continue;
        for (std::size_t dma_index = 1;
             dma_index < standalone.dma.size(); ++dma_index) {
            const auto& binding = standalone.dma[dma_index];
            const auto& id = binding.allocation_id;
            std::string relocated;
            if (id.rfind("input/c", 0) == 0) {
                relocated = input_prefix + id.substr(std::string("input").size());
            } else if (id.rfind("output/c", 0) == 0) {
                relocated = output_prefix + id.substr(std::string("output").size());
            } else {
                relocated = relocated_prefix + id;
            }
            bool matched = false;
            for (const auto& combined_binding : combined.dma) {
                matched |= combined_binding.instruction_index ==
                               index + binding.instruction_index - 1 &&
                    combined_binding.direction == binding.direction &&
                    combined_binding.object_slot == binding.object_slot &&
                    combined_binding.allocation_id == combined.image.allocation(relocated).id;
            }
            if (!matched) { equal = false; break; }
        }
        if (equal) { found = true; break; }
    }
    require(found, "BGV ModSwitch instruction/DMA splice differs from standalone");
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
        require(context.parameters_set(), "BGV plan test context is invalid");
        seal::KeyGenerator generator(context);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Evaluator evaluator(context);
        seal::Ciphertext input;
        encryptor.encrypt_symmetric(seal::Plaintext("1x^3 + 3"), input);
        evaluator.mod_switch_to_next_inplace(input);
        require(input.correction_factor() != 1,
                "BGV plan test did not reach a nontrivial correction factor");

        hpu::seal_adapter::BgvPlainOperationPlan empty(context, input);
        bool rejected = false;
        try {
            (void)empty.lower(512);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plain plan accepted an empty operation chain");

        const seal::Plaintext plain("1x^2 + FFFF");
        hpu::seal_adapter::BgvPlainOperationPlan plan(context, input);
        plan.append_add_plain("add", plain);
        plan.append_subtract_plain("sub", seal::Plaintext("3"));
        rejected = false;
        try {
            plan.append_multiply_plain("add", seal::Plaintext("2"));
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plain plan accepted a duplicate step id");
        rejected = false;
        try {
            plan.append_add_plain("bad/name", plain);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plain plan accepted an unsafe step id");

        auto package = plan.lower(512);
        require(package.correction_factor == input.correction_factor() &&
                    package.parms_id == input.parms_id(),
                "BGV plain plan changed level or correction factor");
        seal::Ciphertext expected = input;
        evaluator.add_plain_inplace(expected, plain);
        const auto source = context.get_context_data(input.parms_id());
        const std::size_t degree = source->parms().poly_modulus_degree();
        for (std::size_t component = 0; component < 2; ++component) {
            const auto physical = hpu::seal_adapter::ciphertext_component_to_hpu(
                expected, component, context);
            for (std::size_t basis = 0;
                 basis < source->parms().coeff_modulus().size(); ++basis) {
                const auto q = static_cast<std::uint32_t>(
                    source->parms().coeff_modulus()[basis].value());
                const auto input_words = words(package.image,
                    "input/c" + std::to_string(component) + "/mod" +
                    std::to_string(basis));
                const auto plain_words = words(package.image,
                    "steps/add/plain/mod" + std::to_string(basis));
                for (std::size_t k = 0; k < degree; ++k) {
                    const auto actual = component == 0
                        ? static_cast<std::uint32_t>(
                            (static_cast<std::uint64_t>(input_words[k]) +
                             plain_words[k]) % q)
                        : input_words[k];
                    if (actual != physical.words[basis * degree + k]) {
                        throw std::runtime_error(
                            "BGV lower-level plain plan differs from modified-SEAL");
                    }
                }
            }
        }
        std::size_t psync_count = 0;
        for (const auto& instruction : package.instructions) {
            psync_count += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
        }
        require(psync_count == 1, "BGV plain plan emitted multiple psyncs");
        const auto runtime =
            hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                "bgv_plain_plan", package);
        require(runtime.resolved_dma_manifest.find(
                    "steps/add/output/c0/mod0") != std::string::npos &&
                    runtime.resolved_dma_manifest.find(
                    "output/c1/mod0") != std::string::npos,
                "BGV plain plan lost intermediate or final DMA binding");

        seal::Ciphertext fresh_lower;
        encryptor.encrypt_zero_symmetric(input.parms_id(), fresh_lower);
        require(fresh_lower.correction_factor() != input.correction_factor(),
                "BGV mixed-chain test failed to create unequal factors");
        hpu::seal_adapter::BgvLinearOperationPlan mixed(context, input);
        mixed.append_add("mix", fresh_lower);
        mixed.append_add_plain("bias", plain);
        mixed.append_subtract("subtract", fresh_lower);
        auto mixed_package = mixed.lower(1024);
        seal::Ciphertext after_add = input;
        evaluator.add_inplace(after_add, fresh_lower);
        check_binary_step(context, mixed_package, input, fresh_lower,
                          after_add, "mix", false);
        seal::Ciphertext after_plain = after_add;
        evaluator.add_plain_inplace(after_plain, plain);
        for (std::size_t component = 0; component < 2; ++component) {
            const auto before = hpu::seal_adapter::ciphertext_component_to_hpu(
                after_add, component, context);
            const auto after = hpu::seal_adapter::ciphertext_component_to_hpu(
                after_plain, component, context);
            for (std::size_t basis = 0;
                 basis < source->parms().coeff_modulus().size(); ++basis) {
                const auto q = static_cast<std::uint32_t>(
                    source->parms().coeff_modulus()[basis].value());
                const auto prepared = words(mixed_package.image,
                    "steps/bias/plain/mod" + std::to_string(basis));
                for (std::size_t k = 0; k < degree; ++k) {
                    const auto actual = component == 0
                        ? static_cast<std::uint32_t>(
                            (static_cast<std::uint64_t>(
                                before.words[basis * degree + k]) +
                             prepared[k]) % q)
                        : before.words[basis * degree + k];
                    if (actual != after.words[basis * degree + k]) {
                        throw std::runtime_error(
                            "BGV plain step after factor balancing differs from SEAL");
                    }
                }
            }
        }
        seal::Ciphertext after_subtract = after_plain;
        evaluator.sub_inplace(after_subtract, fresh_lower);
        check_binary_step(context, mixed_package, after_plain, fresh_lower,
                          after_subtract, "subtract", true);
        require(mixed_package.correction_factor ==
                    after_subtract.correction_factor(),
                "BGV mixed-chain final correction factor differs from SEAL");
        require(mixed_package.spans().size() == mixed_package.dma.size(),
                "BGV mixed-chain DMA bindings are incomplete");
        std::size_t mixed_psync = 0;
        for (const auto& instruction : mixed_package.instructions) {
            mixed_psync += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
        }
        require(mixed_psync == 1,
                "BGV mixed-chain inserted an intermediate psync");
        const auto mixed_runtime =
            hpu::seal_adapter::render_bgv_keyswitch_runtime_artifacts(
                "bgv_mixed_plan", mixed_package);
        require(mixed_runtime.resolved_dma_manifest.find(
                    "steps/mix/output/c0/mod0") != std::string::npos &&
                    mixed_runtime.resolved_dma_manifest.find(
                    "steps/bias/output/c0/mod0") != std::string::npos,
                "BGV mixed-chain lost an intermediate DMA edge");
        for (const auto& id : {
                 std::string("steps/mix/output/c0/mod0"),
                 std::string("steps/bias/output/c0/mod0")}) {
            bool loaded = false;
            for (const auto& binding : mixed_package.dma) {
                loaded |= binding.direction == hpu::Mnemonic::kDload &&
                    binding.allocation_id == id;
            }
            require(loaded, "BGV mixed-chain did not load a prior HPU output");
        }
        seal::Ciphertext wrong_level;
        encryptor.encrypt_symmetric(seal::Plaintext("1"), wrong_level);
        rejected = false;
        try {
            mixed.append_add("wrong_level", wrong_level);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV mixed-chain accepted different levels");

        const auto row_element = hpu::scheme::bfv::row_rotation_galois_element(
            degree, 1);
        const auto column_element =
            hpu::scheme::bfv::column_rotation_galois_element(degree);
        seal::GaloisKeys galois_keys;
        generator.create_galois_keys(
            std::vector<std::uint32_t>{row_element, column_element},
            galois_keys);
        hpu::seal_adapter::BgvLinearOperationPlan rotate_plan(context, input);
        rotate_plan.append_add_plain("pre", plain);
        rotate_plan.append_rotate_rows("row", 1, galois_keys);
        rotate_plan.append_add_plain("post", seal::Plaintext("4"));
        rotate_plan.append_rotate_columns("column", galois_keys);
        const auto rotated_package = rotate_plan.lower(4096);
        seal::Ciphertext after_pre = input;
        evaluator.add_plain_inplace(after_pre, plain);
        seal::Ciphertext after_row = after_pre;
        evaluator.rotate_rows_inplace(after_row, 1, galois_keys);
        seal::Ciphertext after_post = after_row;
        evaluator.add_plain_inplace(after_post, seal::Plaintext("4"));
        seal::Ciphertext after_column = after_post;
        evaluator.rotate_columns_inplace(after_column, galois_keys);
        const auto standalone_rows =
            hpu::seal_adapter::build_bgv_rotate_rows_application(
                context, after_pre, galois_keys, 1,
                hpu::seal_adapter::estimate_bgv_rotation_image_lines(
                    degree, source->parms().coeff_modulus().size(),
                    context.key_context_data()->parms().coeff_modulus().size()));
        check_rotation_splice(rotated_package, standalone_rows, "row",
                              "steps/pre/output", "steps/row/output");
        const auto standalone_column_after_post =
            hpu::seal_adapter::build_bgv_rotate_columns_application(
                context, after_post, galois_keys,
                hpu::seal_adapter::estimate_bgv_rotation_image_lines(
                    degree, source->parms().coeff_modulus().size(),
                    context.key_context_data()->parms().coeff_modulus().size()));
        check_rotation_splice(rotated_package, standalone_column_after_post,
                              "column", "steps/post/output", "output");
        require(rotated_package.correction_factor ==
                    after_column.correction_factor(),
                "BGV rotation plan changed the output factor");
        for (std::size_t basis = 0;
             basis < source->parms().coeff_modulus().size(); ++basis) {
            const auto q = static_cast<std::uint32_t>(
                source->parms().coeff_modulus()[basis].value());
            const auto post_plain = words(rotated_package.image,
                "steps/post/plain/mod" + std::to_string(basis));
            for (std::size_t component = 0; component < 2; ++component) {
                const auto before = hpu::seal_adapter::ciphertext_component_to_hpu(
                    after_row, component, context);
                const auto after = hpu::seal_adapter::ciphertext_component_to_hpu(
                    after_post, component, context);
                for (std::size_t k = 0; k < degree; ++k) {
                    const auto actual = component == 0
                        ? static_cast<std::uint32_t>(
                            (static_cast<std::uint64_t>(
                                before.words[basis * degree + k]) +
                             post_plain[k]) % q)
                        : before.words[basis * degree + k];
                    if (actual != after.words[basis * degree + k]) {
                        throw std::runtime_error(
                            "BGV post-rotation AddPlain differs from SEAL");
                    }
                }
            }
        }
        hpu::seal_adapter::BgvLinearOperationPlan columns_plan(context, input);
        columns_plan.append_rotate_columns("columns", galois_keys);
        const auto columns_package = columns_plan.lower(4096);
        const auto standalone_columns =
            hpu::seal_adapter::build_bgv_rotate_columns_application(
                context, input, galois_keys,
                hpu::seal_adapter::estimate_bgv_rotation_image_lines(
                    degree, source->parms().coeff_modulus().size(),
                    context.key_context_data()->parms().coeff_modulus().size()));
        check_rotation_splice(columns_package, standalone_columns,
                              "columns", "input", "output");
        rejected = false;
        try {
            rotate_plan.append_rotate_rows("zero", 0, galois_keys);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plan accepted zero-step row rotation");

        seal::Ciphertext top_input;
        encryptor.encrypt_symmetric(seal::Plaintext("1x^3 + 3"), top_input);
        seal::Ciphertext lower_right;
        encryptor.encrypt_zero_symmetric(input.parms_id(), lower_right);
        hpu::seal_adapter::BgvLinearOperationPlan level_plan(context, top_input);
        level_plan.append_add_plain("pre_level", plain);
        level_plan.append_modswitch_to_next("drop_one");
        level_plan.append_add_plain("middle", seal::Plaintext("7"));
        level_plan.append_add("lower_binary", lower_right);
        level_plan.append_rotate_rows("lower_row", 1, galois_keys);
        level_plan.append_modswitch_to_next("drop_two");
        level_plan.append_subtract_plain("last", seal::Plaintext("2"));
        rejected = false;
        try {
            level_plan.append_modswitch_to_next("too_far");
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plan accepted ModSwitch past the last level");
        rejected = false;
        try {
            level_plan.append_add("wrong_after_drop", input);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plan accepted old-level binary operand");

        const auto level_package = level_plan.lower(8192);
        seal::Ciphertext oracle = top_input;
        evaluator.add_plain_inplace(oracle, plain);
        const auto standalone_drop_one =
            hpu::seal_adapter::build_bgv_modswitch_application(
                context, oracle, 8192);
        check_modswitch_splice(level_package, standalone_drop_one, "drop_one",
                               "steps/pre_level/output", "steps/drop_one/output");
        evaluator.mod_switch_to_next_inplace(oracle);
        const auto before_middle = oracle;
        evaluator.add_plain_inplace(oracle, seal::Plaintext("7"));
        const auto after_middle = oracle;
        const auto lower_source = context.get_context_data(oracle.parms_id());
        for (std::size_t basis = 0;
             basis < lower_source->parms().coeff_modulus().size(); ++basis) {
            const auto q = static_cast<std::uint32_t>(
                lower_source->parms().coeff_modulus()[basis].value());
            const auto prepared = words(level_package.image,
                "steps/middle/plain/mod" + std::to_string(basis));
            const auto before = hpu::seal_adapter::ciphertext_component_to_hpu(
                before_middle, 0, context);
            const auto after = hpu::seal_adapter::ciphertext_component_to_hpu(
                after_middle, 0, context);
            for (std::size_t k = 0; k < degree; ++k) {
                require((static_cast<std::uint64_t>(
                    before.words[basis * degree + k]) + prepared[k]) % q ==
                    after.words[basis * degree + k],
                    "BGV AddPlain after ModSwitch differs from SEAL");
            }
        }
        evaluator.add_inplace(oracle, lower_right);
        check_binary_step(context, level_package, after_middle, lower_right,
                          oracle, "lower_binary", false);
        const auto standalone_lower_row =
            hpu::seal_adapter::build_bgv_rotate_rows_application(
                context, oracle, galois_keys, 1,
                hpu::seal_adapter::estimate_bgv_rotation_image_lines(
                    degree, lower_source->parms().coeff_modulus().size(),
                    context.key_context_data()->parms().coeff_modulus().size()));
        check_rotation_splice(level_package, standalone_lower_row, "lower_row",
                              "steps/lower_binary/output", "steps/lower_row/output");
        evaluator.rotate_rows_inplace(oracle, 1, galois_keys);
        const auto standalone_drop_two =
            hpu::seal_adapter::build_bgv_modswitch_application(
                context, oracle, 8192);
        check_modswitch_splice(level_package, standalone_drop_two, "drop_two",
                               "steps/lower_row/output", "steps/drop_two/output");
        evaluator.mod_switch_to_next_inplace(oracle);
        const auto before_last = oracle;
        evaluator.sub_plain_inplace(oracle, seal::Plaintext("2"));
        require(level_package.parms_id == oracle.parms_id() &&
                    level_package.correction_factor == oracle.correction_factor(),
                "BGV multi-level plan metadata differs from SEAL");
        const auto final_source = context.get_context_data(oracle.parms_id());
        for (std::size_t basis = 0;
             basis < final_source->parms().coeff_modulus().size(); ++basis) {
            const auto q = static_cast<std::uint32_t>(
                final_source->parms().coeff_modulus()[basis].value());
            const auto prepared = words(level_package.image,
                "steps/last/plain/mod" + std::to_string(basis));
            const auto before = hpu::seal_adapter::ciphertext_component_to_hpu(
                before_last, 0, context);
            const auto after = hpu::seal_adapter::ciphertext_component_to_hpu(
                oracle, 0, context);
            for (std::size_t k = 0; k < degree; ++k) {
                require((static_cast<std::uint64_t>(
                    before.words[basis * degree + k]) + q - prepared[k]) % q ==
                    after.words[basis * degree + k],
                    "BGV SubPlain after two ModSwitches differs from SEAL");
            }
        }
        std::size_t level_psync = 0;
        for (const auto& instruction : level_package.instructions) {
            level_psync += instruction.instruction.mnemonic == hpu::Mnemonic::kPsync;
        }
        require(level_psync == 1 &&
                    level_package.spans().size() == level_package.dma.size(),
                "BGV multi-level plan has an incomplete command stream");

        seal::RelinKeys relin_keys;
        generator.create_relin_keys(relin_keys);
        seal::Ciphertext top_right;
        encryptor.encrypt_symmetric(seal::Plaintext("5"), top_right);
        hpu::seal_adapter::BgvLinearOperationPlan multiply_plan(context, top_input);
        multiply_plan.append_add_plain("pre_multiply", seal::Plaintext("3"));
        multiply_plan.append_multiply("top_multiply", top_right, relin_keys);
        multiply_plan.append_modswitch_to_next("drop_after_multiply");
        multiply_plan.append_multiply("lower_multiply", lower_right, relin_keys);
        multiply_plan.append_add_plain("post_multiply", seal::Plaintext("9"));
        rejected = false;
        try {
            multiply_plan.append_multiply("old_level_multiply", top_right,
                                          relin_keys);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plan accepted old-level multiplication operand");
        rejected = false;
        try {
            multiply_plan.append_multiply("missing_key", lower_right,
                                          seal::RelinKeys{});
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "BGV plan accepted a missing relinearization key");

        const auto multiply_package = multiply_plan.lower(16384);
        seal::Ciphertext multiply_oracle = top_input;
        evaluator.add_plain_inplace(multiply_oracle, seal::Plaintext("3"));
        const auto standalone_top_multiply =
            hpu::seal_adapter::build_bgv_multiply_relinearize_application(
                context, multiply_oracle, top_right, relin_keys, 16384);
        check_multiply_splice(multiply_package, standalone_top_multiply,
                              "top_multiply", "steps/pre_multiply/output",
                              "steps/top_multiply/output");
        evaluator.multiply_inplace(multiply_oracle, top_right);
        evaluator.relinearize_inplace(multiply_oracle, relin_keys);
        const auto standalone_drop_after_multiply =
            hpu::seal_adapter::build_bgv_modswitch_application(
                context, multiply_oracle, 16384);
        check_modswitch_splice(multiply_package, standalone_drop_after_multiply,
                               "drop_after_multiply",
                               "steps/top_multiply/output",
                               "steps/drop_after_multiply/output");
        evaluator.mod_switch_to_next_inplace(multiply_oracle);
        const auto standalone_lower_multiply =
            hpu::seal_adapter::build_bgv_multiply_relinearize_application(
                context, multiply_oracle, lower_right, relin_keys, 16384);
        check_multiply_splice(multiply_package, standalone_lower_multiply,
                              "lower_multiply", "steps/drop_after_multiply/output",
                              "steps/lower_multiply/output");
        evaluator.multiply_inplace(multiply_oracle, lower_right);
        evaluator.relinearize_inplace(multiply_oracle, relin_keys);
        const auto before_post_multiply = multiply_oracle;
        evaluator.add_plain_inplace(multiply_oracle, seal::Plaintext("9"));
        require(multiply_package.parms_id == multiply_oracle.parms_id() &&
                    multiply_package.correction_factor ==
                        multiply_oracle.correction_factor(),
                "BGV multiplication-chain metadata differs from SEAL");
        const auto multiply_source = context.get_context_data(
            multiply_oracle.parms_id());
        const auto before_post_physical =
            hpu::seal_adapter::ciphertext_component_to_hpu(
                before_post_multiply, 0, context);
        const auto after_post_physical =
            hpu::seal_adapter::ciphertext_component_to_hpu(
                multiply_oracle, 0, context);
        for (std::size_t basis = 0;
             basis < multiply_source->parms().coeff_modulus().size(); ++basis) {
            const auto q = static_cast<std::uint32_t>(
                multiply_source->parms().coeff_modulus()[basis].value());
            const auto prepared = words(multiply_package.image,
                "steps/post_multiply/plain/mod" + std::to_string(basis));
            for (std::size_t k = 0; k < degree; ++k) {
                require((static_cast<std::uint64_t>(
                    before_post_physical.words[basis * degree + k]) +
                    prepared[k]) % q ==
                    after_post_physical.words[basis * degree + k],
                    "BGV AddPlain after multiplication differs from SEAL");
            }
        }
        std::size_t multiply_psync = 0;
        std::size_t multiply_modtable_load = 0;
        for (const auto& encoded : multiply_package.instructions) {
            multiply_psync += encoded.instruction.mnemonic == hpu::Mnemonic::kPsync;
            multiply_modtable_load +=
                encoded.instruction.mnemonic == hpu::Mnemonic::kDload &&
                encoded.instruction.obj_id == 4 && encoded.instruction.type == 2;
        }
        require(multiply_psync == 1 && multiply_modtable_load == 1 &&
                    multiply_package.spans().size() == multiply_package.dma.size(),
                "BGV multiplication chain has an incomplete command stream");
        std::cout << "BGV plain operation plan tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BGV plain operation plan test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
