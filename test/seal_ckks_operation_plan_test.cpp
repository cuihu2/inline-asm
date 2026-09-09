#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/operation_plan.hpp"
#include "hpu/seal/software_executor.hpp"

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
