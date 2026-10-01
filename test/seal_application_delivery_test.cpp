#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/software_executor.hpp"
#include "hpu/seal/bfv_software_executor.hpp"

#include <iostream>
#include <stdexcept>

namespace {
using namespace hpu::seal_adapter;

template<class F>
void rejects(F action, const std::string& fragment)
{
    try { action(); }
    catch (const std::exception& error) {
        if (std::string(error.what()).find(fragment) != std::string::npos) return;
        throw;
    }
    throw std::runtime_error("delivery accepted invalid input: " + fragment);
}

void test_ckks()
{
    CkksContextSpec spec;
    spec.poly_modulus_degree = 128;
    spec.coeff_modulus_bits = {20, 20, 20};
    const auto bundle = create_ckks_context(spec);
    const auto& context = *bundle.context;
    seal::KeyGenerator keys(context);
    seal::Plaintext plaintext;
    seal::CKKSEncoder(context).encode(1.25, 4096.0, plaintext);
    seal::Ciphertext encrypted;
    seal::Encryptor(context, keys.secret_key()).encrypt_symmetric(plaintext, encrypted);
    CkksApplicationImageBuilder image(context, 256);
    image.add_modulus_table();
    const auto input = image.add_ciphertext("input", encrypted);
    CkksOperationPlan plan(image);
    const auto output = plan.append_add("double", input, input, "output");
    CkksSoftwareExecutor executor(context, image.image());
    executor.add(input, input, output);
    seal::Ciphertext oracle;
    seal::Evaluator(context).add(encrypted, encrypted, oracle);
    const auto lowered = lower_ckks_operation_plan(plan, context);
    const auto runtime = lower_ckks_runtime_program(
        lowered, build_ckks_relocation_schedule(lowered, image.image(), context));
    const auto artifacts = render_ckks_runtime_artifacts("ckks_test", runtime, 256);
    const auto make = [&](const std::vector<seal::Ciphertext>& oracles,
                          const std::vector<std::uint32_t>& words) {
        return make_ckks_application_package("ckks_test", context, lowered, runtime,
                                             artifacts, image.image(), oracles, words);
    };
    make({oracle}, executor.memory().words());
    rejects([&] { make({}, executor.memory().words()); }, "snapshot");
    rejects([&] { make({oracle}, {}); }, "image size");
    auto corrupt = executor.memory().words();
    corrupt[output.components[0].limbs[0].line_offset * 64] ^= 1;
    rejects([&] { make({oracle}, corrupt); }, "output/c0/mod0 word 0");
    auto wrong_scale = oracle;
    wrong_scale.scale() *= 2;
    rejects([&] { make({wrong_scale}, executor.memory().words()); }, "scale");
    auto wrong_level = oracle;
    seal::Evaluator(context).mod_switch_to_next_inplace(wrong_level);
    rejects([&] { make({wrong_level}, executor.memory().words()); }, "metadata");
    auto wrong_shape = oracle;
    wrong_shape.resize(context, oracle.parms_id(), 3);
    rejects([&] { make({wrong_shape}, executor.memory().words()); }, "metadata");
}

void test_bfv()
{
    BfvContextSpec spec;
    spec.poly_modulus_degree = 128;
    spec.coeff_modulus_bits = {20, 20, 20};
    const auto bundle = create_bfv_context(spec);
    const auto& context = *bundle.context;
    seal::KeyGenerator keys(context);
    seal::Ciphertext encrypted;
    seal::Encryptor(context, keys.secret_key()).encrypt_symmetric(seal::Plaintext("2"), encrypted);
    BfvApplicationImageBuilder image(context, 256);
    image.add_modulus_table();
    const auto input = image.add_ciphertext("input", encrypted);
    BfvOperationPlan plan(image);
    const auto output = plan.append_add("double", input, input, "output");
    BfvSoftwareExecutor executor(context, image.image());
    executor.add(input, input, output);
    seal::Ciphertext oracle;
    seal::Evaluator(context).add(encrypted, encrypted, oracle);
    const auto lowered = lower_bfv_operation_plan(plan, context);
    const auto runtime = lower_bfv_runtime_program(
        lowered, build_bfv_relocation_schedule(lowered, image.image(), context));
    const auto artifacts = render_bfv_runtime_artifacts("bfv_test", runtime, 256);
    const auto make = [&](const std::vector<seal::Ciphertext>& oracles,
                          const std::vector<std::uint32_t>& words) {
        return make_bfv_application_package("bfv_test", context, lowered, runtime,
                                            artifacts, image.image(), oracles, words);
    };
    make({oracle}, executor.memory().words());
    auto corrupt = executor.memory().words();
    corrupt[output.components[1].limbs[0].line_offset * 64] ^= 1;
    rejects([&] { make({oracle}, corrupt); }, "output/c1/mod0 word 0");
    rejects([&] { make({}, executor.memory().words()); }, "snapshot");
    auto wrong_level = oracle;
    seal::Evaluator(context).mod_switch_to_next_inplace(wrong_level);
    rejects([&] { make({wrong_level}, executor.memory().words()); }, "metadata");
}

void test_bgv()
{
    seal::EncryptionParameters parameters(seal::scheme_type::bgv);
    parameters.set_poly_modulus_degree(128);
    parameters.set_coeff_modulus(seal::CoeffModulus::Create(128, {20, 20, 20}));
    parameters.set_plain_modulus(65537);
    seal::SEALContext context(parameters, true, seal::sec_level_type::none);
    seal::KeyGenerator keys(context);
    seal::Ciphertext input;
    seal::Encryptor(context, keys.secret_key()).encrypt_symmetric(seal::Plaintext("2"), input);
    BgvLinearOperationPlan plan(context, input);
    plan.append_add_plain("add", seal::Plaintext("3"));
    const auto application = plan.lower(256);
    auto oracle = input;
    seal::Evaluator(context).add_plain_inplace(oracle, seal::Plaintext("3"));
    const auto request = make_bgv_application_package("bgv_test", context, plan, application, {oracle});
    if (request.oracle_report_json.find("\"overall_status\":\"pass\"") == std::string::npos ||
        request.oracle_report_json.find("\"oracle_verified\":true") == std::string::npos ||
        request.oracle_report_json.find("\"golden_matches_oracle\":true") == std::string::npos ||
        request.oracle_report_json.find(
            "\"name\":\"host_software_model_to_oracle\",\"required\":true,\"status\":\"pass\",\"model\":\"BgvSoftwareExecutor\"") ==
            std::string::npos ||
        request.oracle_report_json.find("\"model_verified\":true") == std::string::npos)
        throw std::runtime_error("BGV package verification status is ambiguous");
    rejects([&] { make_bgv_application_package("bgv_test", context, plan, application, {}); }, "snapshot");
    oracle.correction_factor() = 2;
    rejects([&] { make_bgv_application_package("bgv_test", context, plan, application, {oracle}); }, "metadata");
}
} // namespace

int main()
{
    try {
        test_ckks();
        test_bfv();
        test_bgv();
        std::cout << "SEAL application delivery oracle checks PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
