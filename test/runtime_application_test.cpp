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
        std::cout << "HPU application state tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU application state test failed: " << error.what() << '\n';
        return 1;
    }
}
