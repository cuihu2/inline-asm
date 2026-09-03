#include "hpu/runtime/application.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}
template <typename Function>
void require_throws(Function function, const char* message)
{
    try {
        function();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error(message);
}

} // namespace

int main()
{
    try {
        hpu::runtime::Application application;
        hpu::runtime::ObjectState state;
        state.backing = {32, 1024};
        state.required_output = true;
        state.modulus_ids = {0, 1, 2, 3};
        application.register_object("ct0", state);
        application.load_modulus_table({0, 2});
        application.load_object("ct0", 0);
        application.run_kernel("multiply", {"ct0"});
        application.run_kernel("relinearize", {"ct0"});

        require(
            application.object("ct0").resident_slot == 0,
            "object did not stay resident across kernels");
        require_throws(
            [&] { application.finish(); },
            "psync accepted a required dirty output");

        application.store_object("ct0");
        application.finish();
        require(application.finished(), "application did not finish");
        require(
            application.events().back().kind == hpu::runtime::EventKind::psync,
            "final event is not psync");

        std::size_t psync_count = 0;
        for (const auto& event : application.events()) {
            if (event.kind == hpu::runtime::EventKind::psync) {
                ++psync_count;
            }
        }
        require(psync_count == 1, "application emitted more than one psync");

        // A split Rotate schedule needs no modified-root transform state at a
        // boundary. The two resident objects carry only coefficient-domain
        // representation and sigma_k(s) key-domain metadata into KeySwitch.
        hpu::runtime::Application rotate;
        hpu::runtime::ObjectState rotate_state;
        rotate_state.backing = {2048, 1024};
        rotate_state.required_output = true;
        rotate_state.modulus_ids = {0, 1, 2, 3};
        rotate_state.domain =
            hpu::runtime::PolynomialDomain::canonical_ntt_physical;
        rotate.register_object("c0", rotate_state);
        rotate_state.backing = {3072, 1024};
        rotate.register_object("c1", rotate_state);
        rotate.load_modulus_table({0, 2});
        rotate.load_object("c0", 0);
        rotate.load_object("c1", 1);
        rotate.run_kernel("fused_inverse_automorphism", {"c0", "c1"});
        rotate.set_representation(
            "c0", hpu::runtime::PolynomialDomain::coefficient,
            0, {0, 1, 2, 3}, 3);
        rotate.set_representation(
            "c1", hpu::runtime::PolynomialDomain::coefficient,
            0, {0, 1, 2, 3}, 3);
        require(rotate.object("c0").key_domain == 3
                    && rotate.object("c1").resident_slot == 1,
                "Rotate key-domain metadata did not survive the kernel boundary");
        rotate.run_kernel("galois_keyswitch", {"c0", "c1"});
        rotate.set_representation(
            "c0", hpu::runtime::PolynomialDomain::coefficient,
            0, {0, 1, 2, 3}, 1);
        rotate.set_representation(
            "c1", hpu::runtime::PolynomialDomain::coefficient,
            0, {0, 1, 2, 3}, 1);
        rotate.run_kernel("canonical_output_ntt", {"c0", "c1"});
        rotate.set_representation(
            "c0", hpu::runtime::PolynomialDomain::canonical_ntt_physical,
            0, {0, 1, 2, 3});
        rotate.set_representation(
            "c1", hpu::runtime::PolynomialDomain::canonical_ntt_physical,
            0, {0, 1, 2, 3});
        rotate.store_object("c0");
        rotate.store_object("c1");
        rotate.finish();
        require(rotate.object("c0").key_domain == 1
                    && rotate.object("c0").domain
                        == hpu::runtime::PolynomialDomain::canonical_ntt_physical,
                "Rotate did not return to the canonical SEAL-facing representation");
        std::cout << "HPU application state tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU application state test failed: " << error.what() << '\n';
        return 1;
    }
}
