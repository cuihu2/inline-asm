#include "hpu/seal/bfv_application_image.hpp"
#include "hpu/seal/bfv_context.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_plan.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_operation_runtime.hpp"
#include "scheme/bfv/galois.hpp"
#include "scheme/bfv/rotate.hpp"
#include "util/hpu_asm.hpp"

#include <seal/seal.h>

#include <algorithm>
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

std::size_t count_token(const std::string& text, const std::string& token)
{
    std::size_t count = 0;
    for (std::size_t position = 0;
         (position = text.find(token, position)) != std::string::npos;
         position += token.size()) {
        ++count;
    }
    return count;
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
        const hpu::seal_adapter::BfvLevelChain level_chain(*bundle.context);
        const auto& level = level_chain.top();
        constexpr int row_steps = 2;
        const auto row_element =
            hpu::scheme::bfv::row_rotation_galois_element(spec.poly_modulus_degree, row_steps);
        const auto column_element =
            hpu::scheme::bfv::column_rotation_galois_element(spec.poly_modulus_degree);

        ::seal::KeyGenerator key_generator(*bundle.context);
        ::seal::PublicKey public_key;
        ::seal::GaloisKeys galois_keys;
        key_generator.create_public_key(public_key);
        key_generator.create_galois_keys(
            std::vector<std::uint32_t>{row_element, column_element}, galois_keys);

        ::seal::BatchEncoder encoder(*bundle.context);
        std::vector<std::uint64_t> slots(encoder.slot_count());
        for (std::size_t index = 0; index < slots.size(); ++index) {
            slots[index] = (3 * index + 1) % bundle.plain_modulus;
        }
        ::seal::Plaintext plaintext;
        encoder.encode(slots, plaintext);
        ::seal::Encryptor encryptor(*bundle.context, public_key);
        ::seal::Ciphertext encrypted;
        encryptor.encrypt(plaintext, encrypted);

        hpu::seal_adapter::BfvApplicationImageBuilder image_builder(*bundle.context, 8192);
        image_builder.add_modulus_table();
        image_builder.add_canonical_twiddles();
        const auto input = image_builder.add_ciphertext("input/x", encrypted);
        const auto constants =
            image_builder.add_keyswitch_constants("constants/keyswitch/top", level);
        const auto row_key = image_builder.add_row_rotation_key(
            "key/rotate_rows_2/top", galois_keys, row_steps, level);
        const auto column_key = image_builder.add_column_rotation_key(
            "key/rotate_columns/top", galois_keys, level);
        const auto row_twiddles = image_builder.add_row_rotation_twiddles(
            "rotate_rows_2/top", row_steps, level);
        const auto column_twiddles = image_builder.add_column_rotation_twiddles(
            "rotate_columns/top", level);
        const auto row_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_rows_2", level, 2,
            hpu::runtime::PolynomialDomain::coefficient, row_element);
        const auto column_workspace = image_builder.reserve_ciphertext(
            "scratch/rotate_columns", level, 2,
            hpu::runtime::PolynomialDomain::coefficient, column_element);

        hpu::seal_adapter::BfvOperationPlan plan(image_builder);
        auto wrong_workspace = row_workspace;
        wrong_workspace.key_domain = column_element;
        require_invalid_argument(
            [&] {
                (void)plan.append_rotate_rows("invalid_workspace", input, row_steps, row_key,
                                              constants, row_twiddles, wrong_workspace,
                                              "invalid/workspace");
            },
            "BFV RotateRows accepted a workspace in the wrong key domain");
        require_invalid_argument(
            [&] {
                (void)plan.append_rotate_rows("invalid_twiddles", input, row_steps, row_key,
                                              constants, column_twiddles, row_workspace,
                                              "invalid/twiddles");
            },
            "BFV RotateRows accepted twiddles for another Galois element");

        const auto row_output = plan.append_rotate_rows(
            "rotate_rows_2", input, row_steps, row_key, constants, row_twiddles,
            row_workspace, "output/rotate_rows_2");
        const auto column_output = plan.append_rotate_columns(
            "rotate_columns", input, column_key, constants, column_twiddles,
            column_workspace, "output/rotate_columns");
        require(row_output.key_domain == 1 && column_output.key_domain == 1 &&
                    plan.steps().size() == 2 &&
                    plan.steps()[0].kind == hpu::seal_adapter::BfvOperationKind::rotate_rows &&
                    plan.steps()[1].kind == hpu::seal_adapter::BfvOperationKind::rotate_columns &&
                    plan.steps()[0].resources.galois_element == row_element &&
                    plan.steps()[1].resources.galois_element == column_element,
                "BFV rotation planner lost operation metadata");

        const auto lowered = hpu::seal_adapter::lower_bfv_operation_plan(
            plan, *bundle.context, true, true);
        require(lowered.operations.size() == 2 &&
                    lowered.operations[0].body_asm == hpu::scheme::bfv::generate_rotate_body_asm(
                        static_cast<int>(spec.poly_modulus_degree), level.keyswitch_layout,
                        row_element, false, false) &&
                    lowered.operations[1].body_asm == hpu::scheme::bfv::generate_rotate_body_asm(
                        static_cast<int>(spec.poly_modulus_degree), level.keyswitch_layout,
                        column_element, false, false) &&
                    count_token(lowered.body_asm,
                                hpu::dload(4, hpu::DataType::mod_ctx,
                                           hpu::DloadFlag::small_bank)) == 1 &&
                    count_token(lowered.body_asm, hpu::pfree(4)) == 1,
                "BFV rotation lowering selected the wrong kernel or modulus-table lifetime");

        const auto relocation = hpu::seal_adapter::build_bfv_relocation_schedule(
            lowered, image_builder.image(), *bundle.context);
        require(relocation.complete() && relocation.bindings.size() == relocation.expected_dma_count,
                "BFV rotation relocation is incomplete");
        const auto has_binding = [&](const std::string& operation, const std::string& allocation) {
            return std::any_of(relocation.bindings.begin(), relocation.bindings.end(),
                               [&](const auto& binding) {
                                   return binding.operation_id == operation &&
                                          binding.allocation_id == allocation;
                               });
        };
        require(has_binding("rotate_rows_2",
                            "constants/twiddle/canonical/mod0/ntt/pre_twist") &&
                    has_binding("rotate_rows_2",
                                "constants/twiddle/rotate_rows_2/top/mod0/intt/stage0") &&
                    has_binding("rotate_rows_2", "scratch/rotate_rows_2/c1/mod0") &&
                    has_binding("rotate_rows_2", "key/rotate_rows_2/top/d0/c0/mod0") &&
                    has_binding("rotate_rows_2", "output/rotate_rows_2/c1/mod0") &&
                    has_binding("rotate_columns",
                                "constants/twiddle/rotate_columns/top/mod0/intt/stage0"),
                "BFV rotation relocation missed a required resource");

        const auto runtime = hpu::seal_adapter::lower_bfv_runtime_program(lowered, relocation);
        require(!runtime.instructions.empty() && runtime.dma.size() == relocation.expected_dma_count,
                "BFV rotation runtime lowering is incomplete");

        std::cout << "BFV Galois operation plan tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "BFV Galois operation plan test failed: " << error.what() << '\n';
        return 1;
    }
}
