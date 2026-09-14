#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/software_executor.hpp"
#include "poly/cmult.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "scheme/ckks/relinearize.hpp"
#include "scheme/ckks/rescale.hpp"
#include "util/hpu_asm.hpp"

#include <seal/seal.h>

#include <algorithm>
#include <cmath>
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

std::size_t count_token(const std::string& text, const std::string& token)
{
    std::size_t result = 0;
    std::size_t position = 0;
    while ((position = text.find(token, position)) != std::string::npos) {
        ++result;
        position += token.size();
    }
    return result;
}

template <typename Function>
void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

void require_exact(
    const ::seal::Ciphertext& expected,
    const hpu::seal_adapter::PreparedRnsObject& actual,
    const hpu::seal_adapter::CkksSoftwareExecutor& executor,
    const ::seal::SEALContext& context)
{
    require(
        expected.parms_id() == actual.parms_id
            && expected.size() == actual.components.size(),
        "planned result shape differs from SEAL");
    for (std::size_t component = 0; component < expected.size(); ++component) {
        const auto seal_words = hpu::seal_adapter::hpu_to_seal_ntt(
            executor.export_component(actual, component),
            actual.parms_id, context);
        require(
            std::equal(
                seal_words.begin(), seal_words.end(), expected.data(component)),
            "planned result words differ from SEAL");
    }
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const hpu::seal_adapter::CkksLevelChain level_chain(*bundle.context);
        const auto& top = level_chain.top();

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::RelinKeys relin_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_relin_keys(relin_keys);

        constexpr double scale = 4096.0;
        ::seal::CKKSEncoder encoder(*bundle.context);
        ::seal::Plaintext encoded_input;
        encoder.encode(std::vector<double>{0.25, -1.0}, scale, encoded_input);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted_input;
        encryptor.encrypt(encoded_input, encrypted_input);

        hpu::seal_adapter::CkksApplicationImageBuilder image_builder(
            *bundle.context, 512);
        image_builder.add_modulus_table();
        const auto canonical_twiddles =
            image_builder.add_canonical_twiddles();
        const auto prepared_input = image_builder.add_ciphertext(
            "input/x", encrypted_input);
        const auto prepared_relinearization_key =
            image_builder.add_relinearization_key(
                "key/relinearization/top", relin_keys, top);
        const auto keyswitch_constants =
            image_builder.add_keyswitch_constants(
                "constants/keyswitch/top", top);
        const auto rescale_constants = image_builder.add_rescale_constants(
            "constants/rescale/top_to_next", top);

        const auto squared_metadata =
            hpu::seal_adapter::infer_ckks_multiply_metadata(
                level_chain, prepared_input.metadata(), prepared_input.metadata());
        const auto rescaled_metadata =
            hpu::seal_adapter::infer_ckks_rescale_metadata(
                level_chain, squared_metadata);
        ::seal::Plaintext encoded_one;
        encoder.encode(
            std::vector<double>{1.0, 1.0}, rescaled_metadata.parms_id,
            rescaled_metadata.scale, encoded_one);
        const auto prepared_one = image_builder.add_plaintext(
            "constant/one/next", encoded_one);

        hpu::seal_adapter::CkksOperationPlan empty_plan(image_builder);
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::lower_ckks_operation_plan(
                    empty_plan, *bundle.context);
            },
            "operation lowering accepted an empty plan");
        hpu::seal_adapter::CkksOperationPlan plan(image_builder);
        hpu::seal_adapter::CkksApplicationImageBuilder foreign_builder(
            *bundle.context, 64);
        const auto foreign_input = foreign_builder.add_ciphertext(
            "input/x", encrypted_input);
        require_invalid_argument(
            [&] {
                (void)plan.append_square(
                    "foreign_square", foreign_input, "invalid/foreign");
            },
            "operation plan accepted an object from another HPU_MEM image");
        const auto tensor = plan.append_square(
            "square", prepared_input, "intermediate/tensor");
        require_invalid_argument(
            [&] {
                (void)plan.append_square(
                    "square", prepared_input, "invalid/duplicate_step");
            },
            "operation plan accepted a duplicate step id");
        auto wrong_keyswitch_constants = keyswitch_constants;
        wrong_keyswitch_constants.chain_index =
            level_chain.next(top.parms_id).chain_index;
        require_invalid_argument(
            [&] {
                (void)plan.append_relinearize(
                    "invalid_relinearize", tensor,
                    prepared_relinearization_key, wrong_keyswitch_constants,
                    "invalid/relinearized");
            },
            "operation plan accepted wrong-level relinearization constants");
        auto compact_only_keyswitch_constants = keyswitch_constants;
        compact_only_keyswitch_constants.hardware_prefix.clear();
        compact_only_keyswitch_constants.hardware_constant_polynomial_count = 0;
        compact_only_keyswitch_constants.hardware_workspace_polynomial_count = 0;
        require_invalid_argument(
            [&] {
                (void)plan.append_relinearize(
                    "missing_hardware_relinearize", tensor,
                    prepared_relinearization_key,
                    compact_only_keyswitch_constants,
                    "invalid/missing_hardware_relinearized");
            },
            "operation plan accepted compact-only KeySwitch constants");
        const auto relinearized = plan.append_relinearize(
            "relinearize", tensor, prepared_relinearization_key,
            keyswitch_constants, "intermediate/relinearized");
        auto wrong_rescale_constants = rescale_constants;
        wrong_rescale_constants.destination_parms_id = top.parms_id;
        require_invalid_argument(
            [&] {
                (void)plan.append_rescale(
                    "invalid_rescale", relinearized,
                    wrong_rescale_constants, "invalid/rescaled");
            },
            "operation plan accepted wrong-level Rescale constants");
        const auto rescaled = plan.append_rescale(
            "rescale", relinearized, rescale_constants,
            "intermediate/rescaled");
        auto wrong_scale_plaintext = prepared_one;
        wrong_scale_plaintext.scale *= 2.0;
        require_invalid_argument(
            [&] {
                (void)plan.append_add_plain(
                    "invalid_add_plain", rescaled, wrong_scale_plaintext,
                    "invalid/output");
            },
            "operation plan accepted an incompatible AddPlain scale");
        const auto output = plan.append_add_plain(
            "add_one", rescaled, prepared_one, "output/x2_plus_one");

        const auto& steps = plan.steps();
        require(
            steps.size() == 4
                && steps[0].kind
                    == hpu::seal_adapter::CkksOperationKind::square
                && steps[1].kind
                    == hpu::seal_adapter::CkksOperationKind::relinearize
                && steps[2].kind
                    == hpu::seal_adapter::CkksOperationKind::rescale
                && steps[3].kind
                    == hpu::seal_adapter::CkksOperationKind::add_plain,
            "operation plan did not preserve the explicit step sequence");
        require(
            steps[1].resources.requires_canonical_twiddles
                && steps[1].resources.evaluation_key_ids
                    == std::vector<std::string>{"key/relinearization/top"}
                && steps[1].resources.constant_ids
                    == std::vector<std::string>{"constants/keyswitch/top"}
                && steps[2].resources.requires_canonical_twiddles
                && steps[2].resources.constant_ids
                    == std::vector<std::string>{
                        "constants/rescale/top_to_next"}
                && !steps[3].resources.requires_canonical_twiddles,
            "operation plan recorded incorrect level-specific resources");
        require(
            steps[0].output.component_count == 3
                && steps[1].output.component_count == 2
                && steps[2].output.metadata.parms_id
                    == level_chain.next(top.parms_id).parms_id
                && steps[3].output.metadata.parms_id
                    == steps[2].output.metadata.parms_id,
            "operation plan recorded incorrect output metadata");

        const auto lowered = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context);
        const auto& next_level = level_chain.next(top.parms_id);
        require(
            lowered.operations.size() == steps.size()
                && lowered.operations[0].operation.output.id
                    == "intermediate/tensor"
                && lowered.operations[3].operation.inputs[1].id
                    == "constant/one/next",
            "lowering lost the operation relocation manifest");
        require(
            lowered.operations[0].body_asm
                == ::generate_hpu_cmult_body_asm(
                    static_cast<int>(top.q_moduli.size()), false, false)
                && lowered.operations[1].body_asm
                    == hpu::scheme::ckks::generate_relinearize_ntt_body_asm(
                        static_cast<int>(spec.poly_modulus_degree),
                        top.rns_layout, false, false)
                && lowered.operations[2].body_asm
                    == hpu::scheme::ckks::generate_rescale_ntt_body_asm(
                        static_cast<int>(spec.poly_modulus_degree),
                        static_cast<int>(top.q_moduli.size()), false, false)
                && lowered.operations[3].body_asm
                    == hpu::scheme::ckks::generate_add_plain_body_asm(
                        static_cast<int>(next_level.q_moduli.size()),
                        false, false),
            "operation lowering selected the wrong level-specific kernel");
        require(
            count_token(lowered.body_asm, hpu::dload(
                4, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) == 1
                && count_token(lowered.body_asm, hpu::pfree(4)) == 1
                && count_token(lowered.body_asm, hpu::psync()) == 1
                && lowered.body_asm.rfind(hpu::psync())
                    + hpu::psync().size() == lowered.body_asm.size(),
            "operation lowering duplicated application lifecycle state");
        for (const auto& operation : lowered.operations) {
            require(
                count_token(operation.body_asm, hpu::dload(
                    4, hpu::DataType::mod_ctx,
                    hpu::DloadFlag::small_bank)) == 0
                    && count_token(operation.body_asm, hpu::pfree(4)) == 0
                    && count_token(operation.body_asm, hpu::psync()) == 0,
                "nested planned kernel owns application lifecycle state");
        }
        const auto nested = hpu::seal_adapter::lower_ckks_operation_plan(
            plan, *bundle.context, false, false);
        require(
            count_token(nested.body_asm, hpu::dload(
                4, hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank)) == 0
                && count_token(nested.body_asm, hpu::pfree(4)) == 0
                && count_token(nested.body_asm, hpu::psync()) == 0,
            "nested operation plan emitted application lifecycle state");

        const auto relocations =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                lowered, image_builder.image(), *bundle.context);
        const std::size_t generated_dma_count =
            count_token(lowered.body_asm, "\"dload ")
            + count_token(lowered.body_asm, "\"dstore ");
        const std::size_t relinearize_dma_count =
            count_token(lowered.operations[1].body_asm, "\"dload ")
            + count_token(lowered.operations[1].body_asm, "\"dstore ");
        require(
            relocations.expected_dma_count == generated_dma_count
                && relocations.bindings.size()
                    == 44 + relinearize_dma_count
                && !relocations.complete(),
            "relocation schedule did not account for generated DMA instructions");
        require(
            relocations.unresolved_operations.size() == 1
                && relocations.unresolved_operations[0].operation_index == 2
                && relocations.unresolved_operations[0].operation_id
                    == "rescale"
                && relocations.unresolved_operations[0].dma_count != 0
                && relocations.bindings.size()
                    + relocations.unresolved_operations[0].dma_count
                    == relocations.expected_dma_count,
            "relocation schedule hid unresolved complex-kernel resources");
        require(
            relocations.bindings.front().operation_id == "$application"
                && !relocations.bindings.front().operation_index.has_value()
                && relocations.bindings.front().allocation_id
                    == "constants/modulus_table"
                && relocations.bindings.front().object_slot == 4
                && relocations.bindings.front().span.line_count != 0
                && relocations.bindings[1].allocation_id == "input/x/c0/mod0"
                && relocations.bindings[1].object_slot == 0
                && relocations.bindings[3].allocation_id
                    == "intermediate/tensor/c0/mod0"
                && relocations.bindings.back().allocation_id
                    == "output/x2_plus_one/c1/mod1"
                && relocations.bindings.back().program_dma_index
                    == generated_dma_count - 1,
            "pointwise relocation bindings have incorrect spans or ordinals");
        const auto has_binding = [&](const std::string& allocation_id) {
            return std::any_of(
                relocations.bindings.begin(), relocations.bindings.end(),
                [&](const hpu::seal_adapter::CkksDmaBinding& binding) {
                    return binding.operation_id == "relinearize"
                        && binding.allocation_id == allocation_id;
                });
        };
        require(
            has_binding("intermediate/tensor/c2/mod0")
                && has_binding(
                    "constants/twiddle/canonical/mod0/intt/stage0")
                && has_binding(
                    "constants/keyswitch/top/hardware/modup/d0/qhat_inv/mod0")
                && has_binding(
                    "key/relinearization/top/d0/c0/mod0")
                && has_binding(
                    "constants/keyswitch/top/hardware/workspace/accumulator/c0/mod0")
                && has_binding("intermediate/relinearized/c1/mod2"),
            "Relinearize relocation omitted an operand class");

        hpu::seal_adapter::CkksLoweredProgram fully_bound_program;
        fully_bound_program.operations = {
            lowered.operations[0], lowered.operations[1],
            lowered.operations[3]};
        fully_bound_program.body_asm = hpu::dload(
            4, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        fully_bound_program.body_asm += lowered.operations[0].body_asm;
        fully_bound_program.body_asm += lowered.operations[1].body_asm;
        fully_bound_program.body_asm += lowered.operations[3].body_asm;
        const auto fully_bound_relocations =
            hpu::seal_adapter::build_ckks_relocation_schedule(
                fully_bound_program, image_builder.image(), *bundle.context);
        require(
            fully_bound_relocations.complete()
                && fully_bound_relocations.expected_dma_count
                    == 44 + relinearize_dma_count
                && fully_bound_relocations.bindings.size()
                    == fully_bound_relocations.expected_dma_count
                && fully_bound_relocations.unresolved_operations.empty(),
            "fully resolvable program produced an incomplete schedule");

        hpu::seal_adapter::CkksSoftwareExecutor executor(
            *bundle.context, image_builder.image());
        executor.square(prepared_input, tensor);
        executor.relinearize(
            tensor, prepared_relinearization_key, keyswitch_constants,
            relinearized, canonical_twiddles);
        executor.rescale(
            relinearized, rescale_constants, rescaled, canonical_twiddles);
        executor.add_plain(rescaled, prepared_one, output);

        ::seal::Evaluator evaluator(*bundle.context);
        ::seal::Ciphertext expected;
        evaluator.square(encrypted_input, expected);
        evaluator.relinearize_inplace(expected, relin_keys);
        evaluator.rescale_to_next_inplace(expected);
        evaluator.add_plain_inplace(expected, encoded_one);
        require_exact(expected, output, executor, *bundle.context);

        std::cout << "SEAL CKKS explicit operation plan passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS operation plan test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
