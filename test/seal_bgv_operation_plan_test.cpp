#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/bgv_operation_plan.hpp"
#include "hpu/seal/bgv_software_executor.hpp"
#include "scheme/bfv/galois.hpp"

#include <seal/seal.h>
#include <iostream>
#include <stdexcept>

namespace {
void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}
template<class F> void rejects(F action)
{
    try { action(); } catch (const std::invalid_argument&) { return; }
    throw std::runtime_error("BGV graph accepted invalid input");
}
}

int main()
{
    try {
        seal::EncryptionParameters parameters(seal::scheme_type::bgv);
        parameters.set_poly_modulus_degree(128);
        parameters.set_coeff_modulus({seal::Modulus(2013265921U), seal::Modulus(1811939329U),
            seal::Modulus(469762049U), seal::Modulus(1224736769U)});
        parameters.set_plain_modulus(65537);
        seal::SEALContext context(parameters, true, seal::sec_level_type::none);
        seal::KeyGenerator generator(context);
        seal::GaloisKeys galois;
        seal::RelinKeys relin;
        generator.create_galois_keys(std::vector<std::uint32_t>{
            hpu::scheme::bfv::row_rotation_galois_element(128, 1)}, galois);
        generator.create_relin_keys(relin);
        seal::Ciphertext encrypted;
        seal::Encryptor(context, generator.secret_key()).encrypt_symmetric(seal::Plaintext("2x^1 + 3"), encrypted);
        hpu::seal_adapter::BgvOperationPlan plan(context);
        const auto x = plan.add_ciphertext("input/x", encrypted);
        const auto a = plan.append_rotate_rows("left", x, 1, galois);
        const auto b = plan.append_rotate_rows("right", x, 1, galois);
        const auto sum = plan.append_add("join", a, b);
        const auto tensor = plan.append_multiply("tensor", x, sum);
        require(tensor.component_count == 3, "raw BGV Multiply unexpectedly relinearized");
        const auto product = plan.append_relinearize("relinearize", tensor, relin);
        const auto switched = plan.append_modswitch_to_next("drop", product);
        plan.set_output(switched);
        // A later top-level branch must not change the selected output level.
        const auto unrelated = plan.append_add_plain("later_branch", x, seal::Plaintext("7"));
        require(unrelated.parms_id == x.parms_id && plan.final_output().parms_id == switched.parms_id,
                "BGV graph treated independent branches as a linear level chain");
        require(plan.steps()[0].galois_keys == plan.steps()[1].galois_keys,
                "BGV graph copied the same Galois key per node");
        rejects([&] { plan.append_add("bad_level", x, switched); });
        rejects([&] { plan.append_relinearize("bad_shape", x, relin); });
        rejects([&] { plan.append_add_plain("left", x, seal::Plaintext("1")); });
        hpu::seal_adapter::BgvOperationPlan foreign(context, encrypted);
        rejects([&] { plan.append_add("foreign", x, foreign.input()); });
        auto forged = x; forged.correction_factor = 2;
        rejects([&] { plan.append_add("forged", x, forged); });
        rejects([&] { plan.set_output(x); });

        // The plan owns snapshots: changing the caller's input/key containers
        // after construction cannot alter lowering or software execution.
        encrypted.data()[0] ^= 1;
        galois = seal::GaloisKeys{};
        relin = seal::RelinKeys{};
        const auto application = plan.lower(4096);
        const auto& twiddle_a = application.image.allocation("steps/left/rotation/constants/twiddle/canonical/mod0/ntt/stage0");
        const auto& twiddle_b = application.image.allocation("steps/right/rotation/constants/twiddle/canonical/mod0/ntt/stage0");
        require(twiddle_a.span.line_offset == twiddle_b.span.line_offset,
                "identical BGV branch twiddles were duplicated in HPU_MEM");
        const auto& key_a = application.image.allocation("steps/left/rotation/keys/digit0/c0/mod0");
        const auto& key_b = application.image.allocation("steps/right/rotation/keys/digit0/c0/mod0");
        require(key_a.span.line_offset == key_b.span.line_offset,
                "identical BGV evaluation-key payloads were duplicated");
        require(application.image.capacity_lines() == application.image.used_lines(),
                "BGV graph retained unused window capacity");
        hpu::seal_adapter::BgvSoftwareExecutor executor(context, application.image);
        executor.execute(plan);

        // Restore independent host objects from the captured encrypted input
        // and the key snapshots, then run Evaluator along the declared graph.
        encrypted.data()[0] ^= 1;
        seal::Evaluator oracle(context);
        seal::Ciphertext ha, hb, hs, ht, hp, hd, hu;
        oracle.rotate_rows(encrypted, 1, *plan.steps()[0].galois_keys, ha);
        oracle.rotate_rows(encrypted, 1, *plan.steps()[1].galois_keys, hb);
        oracle.add(ha, hb, hs); oracle.multiply(encrypted, hs, ht);
        oracle.relinearize(ht, *plan.steps()[4].relin_keys, hp);
        oracle.mod_switch_to_next(hp, hd); oracle.add_plain(encrypted, seal::Plaintext("7"), hu);
        std::vector<seal::Ciphertext> snapshots{ha, hb, hs, ht, hp, hd, hu};
        auto request = hpu::seal_adapter::make_bgv_application_package(
            "bgv_graph", context, plan, application, snapshots, executor.memory().words());
        require(request.outputs.size() == 43, "BGV graph lost a three-component or branch golden");
        auto wrong = snapshots; wrong[2].correction_factor() = 2;
        rejects([&] { hpu::seal_adapter::make_bgv_application_package(
            "wrong", context, plan, application, wrong, executor.memory().words()); });
        for (const auto& dma : application.dma) {
            if (!dma.operation_index) {
                require(dma.operation_id == "$application", "BGV prologue has a spurious operation id");
                continue;
            }
            require(dma.operation_id == plan.steps()[*dma.operation_index].id,
                    "BGV DMA origin is detached from its graph node");
            require(application.image.allocation(dma.allocation_id).id == dma.allocation_id,
                    "BGV DMA exports a logical alias instead of the physical allocation");
        }
        std::cout << "BGV graph, resource sharing and per-step SEAL differential checks PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
