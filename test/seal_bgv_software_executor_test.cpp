#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/bgv_software_executor.hpp"
#include "hpu/seal/ntt_bridge.hpp"
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

void compare_step(
    const seal::SEALContext& context,
    const hpu::seal_adapter::BgvLinearOperationPlan& plan,
    const hpu::seal_adapter::BgvKeySwitchApplication& application,
    const hpu::runtime::HpuSoftwareExecutor& memory,
    const seal::Ciphertext& oracle,
    std::size_t step_index)
{
    const std::string prefix = step_index + 1 == plan.steps().size()
        ? "output" : "steps/" + plan.steps()[step_index].id + "/output";
    const auto level = context.get_context_data(oracle.parms_id());
    require(level && oracle.size() == 2,
            "BGV executor test oracle has an invalid shape");
    const std::size_t degree = level->parms().poly_modulus_degree();
    for (std::size_t component = 0; component < 2; ++component) {
        const auto expected = hpu::seal_adapter::ciphertext_component_to_hpu(
            oracle, component, context);
        for (std::size_t basis = 0;
             basis < level->parms().coeff_modulus().size(); ++basis) {
            const auto id = prefix + "/c" + std::to_string(component) +
                "/mod" + std::to_string(basis);
            const auto& allocation = application.image.allocation(id);
            const auto actual = memory.read(allocation.span, degree);
            const auto first = expected.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            if (!std::equal(actual.begin(), actual.end(), first)) {
                throw std::runtime_error(
                    "BgvSoftwareExecutor differs from modified-SEAL at " + id);
            }
        }
    }
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
        seal::SEALContext context(
            parameters, true, seal::sec_level_type::none);
        require(context.parameters_set(),
                "modified-SEAL rejected BGV executor test context");

        seal::KeyGenerator generator(context);
        seal::RelinKeys relin_keys;
        seal::GaloisKeys galois_keys;
        generator.create_relin_keys(relin_keys);
        generator.create_galois_keys(
            std::vector<std::uint32_t>{
                hpu::scheme::bfv::row_rotation_galois_element(128, 1),
                hpu::scheme::bfv::column_rotation_galois_element(128)},
            galois_keys);
        seal::Encryptor encryptor(context, generator.secret_key());
        seal::Ciphertext input;
        seal::Ciphertext right;
        encryptor.encrypt_symmetric(seal::Plaintext("2x^3 + 7"), input);
        encryptor.encrypt_symmetric(seal::Plaintext("3x^2 + 5"), right);

        const seal::Plaintext addend("3");
        const seal::Plaintext subtrahend("1x^1 + 1");
        const seal::Plaintext multiplier("2");
        const seal::Plaintext final_addend("7");
        const seal::Plaintext final_subtrahend("2");
        hpu::seal_adapter::BgvLinearOperationPlan plan(context, input);
        plan.append_add_plain("add_plain", addend);
        plan.append_subtract_plain("subtract_plain", subtrahend);
        plan.append_multiply_plain("multiply_plain", multiplier);
        plan.append_add("add_ciphertext", right);
        plan.append_subtract("subtract_ciphertext", right);
        plan.append_rotate_rows("rotate_rows", 1, galois_keys);
        plan.append_rotate_columns("rotate_columns", galois_keys);
        plan.append_multiply("multiply_ciphertext", right, relin_keys);
        plan.append_modswitch_to_next("modswitch");
        plan.append_add_plain("add_after_modswitch", final_addend);
        plan.append_rotate_rows("rotate_after_modswitch", 1, galois_keys);
        plan.append_modswitch_to_next("second_modswitch");
        plan.append_subtract_plain(
            "subtract_after_second_modswitch", final_subtrahend);

        auto application = plan.lower(16384);
        hpu::seal_adapter::BgvSoftwareExecutor executor(
            context, application.image);
        executor.execute(plan);

        seal::Evaluator evaluator(context);
        seal::Ciphertext expected = input;
        std::vector<seal::Ciphertext> snapshots;
        evaluator.add_plain_inplace(expected, addend);
        snapshots.push_back(expected);
        evaluator.sub_plain_inplace(expected, subtrahend);
        snapshots.push_back(expected);
        evaluator.multiply_plain_inplace(expected, multiplier);
        snapshots.push_back(expected);
        evaluator.add_inplace(expected, right);
        snapshots.push_back(expected);
        evaluator.sub_inplace(expected, right);
        snapshots.push_back(expected);
        evaluator.rotate_rows_inplace(expected, 1, galois_keys);
        snapshots.push_back(expected);
        evaluator.rotate_columns_inplace(expected, galois_keys);
        snapshots.push_back(expected);
        evaluator.multiply_inplace(expected, right);
        evaluator.relinearize_inplace(expected, relin_keys);
        snapshots.push_back(expected);
        evaluator.mod_switch_to_next_inplace(expected);
        snapshots.push_back(expected);
        evaluator.add_plain_inplace(expected, final_addend);
        snapshots.push_back(expected);
        evaluator.rotate_rows_inplace(expected, 1, galois_keys);
        snapshots.push_back(expected);
        evaluator.mod_switch_to_next_inplace(expected);
        snapshots.push_back(expected);
        evaluator.sub_plain_inplace(expected, final_subtrahend);
        snapshots.push_back(expected);

        require(snapshots.size() == plan.steps().size(),
                "BGV executor test snapshot count differs from plan");
        for (std::size_t index = 0; index < snapshots.size(); ++index) {
            compare_step(context, plan, application, executor.memory(),
                         snapshots[index], index);
        }
        const auto request =
            hpu::seal_adapter::make_bgv_application_package(
                "bgv_software_executor_test", context, plan, application,
                snapshots, executor.memory().words());
        require(request.oracle_report_json.find(
                    "\"model\":\"BgvSoftwareExecutor\"") !=
                    std::string::npos &&
                    request.oracle_report_json.find(
                    "\"model_verified\":true") != std::string::npos,
                "BGV delivery report omitted software-model verification");

        std::cout << "BgvSoftwareExecutor full-plan differential test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BgvSoftwareExecutor test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
