#include "native_kernel_fixture.hpp"

#include "hpu/delivery/application_package.hpp"
#include "hpu/delivery/resource_compiler.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#ifndef HPU_DELIVERY_REVISION
#define HPU_DELIVERY_REVISION "unknown"
#endif
#ifndef HPU_DELIVERY_TREE_STATE
#define HPU_DELIVERY_TREE_STATE "unknown"
#endif

namespace {
struct Options {
    std::string kernel = "cmult";
    std::filesystem::path destination;
    bool profile_execution = false;
};

Options parse_options(int argc, char** argv)
{
    Options result;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--case" && i + 1 < argc) result.kernel = argv[++i];
        else if (argument == "--profile-execution") result.profile_execution = true;
        else if (argument == "--emit-dir" && i + 1 < argc) result.destination = argv[++i];
        else throw std::invalid_argument("usage: hpu_native_kernel_application_example "
            "[--case cmult|ntt|intt] [--profile-execution] --emit-dir PATH");
    }
    if (result.destination.empty() ||
        (result.kernel != "cmult" && result.kernel != "ntt" && result.kernel != "intt"))
        throw std::invalid_argument("usage: hpu_native_kernel_application_example "
            "[--case cmult|ntt|intt] [--profile-execution] --emit-dir PATH");
    return result;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        const auto options = parse_options(argc, argv);
        auto fixture = options.kernel == "cmult" ? native_kernel_example::cmult_fixture()
            : native_kernel_example::transform_fixture(options.kernel == "intt");
        const auto* revision = std::getenv("HPU_DELIVERY_COMMIT");
        const auto* state = std::getenv("HPU_DELIVERY_WORKTREE_STATE");
        auto request = native_kernel_example::package_request(fixture, options.kernel,
            {"inline-asm", revision ? revision : HPU_DELIVERY_REVISION,
             state ? state : HPU_DELIVERY_TREE_STATE});
        hpu::delivery::compile_application_resources(request, fixture.image, true, true,
            hpu::model::InstructionNttContract::raw_bit_reversed_coefficients,
            options.profile_execution);
        hpu::delivery::write_application_package(options.destination, request);
        std::cout << "Native " << options.kernel << " application package: "
                  << options.destination.string()
                  << "\nResource and verification details: oracle/report.json\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Native kernel application failed: " << error.what() << '\n';
        return 1;
    }
}
