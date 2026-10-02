#pragma once

#include <filesystem>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>

struct DeliveryOptions {
    bool print_program = false;
    std::optional<std::filesystem::path> emit_directory;
    std::optional<std::size_t> poly_modulus_degree;
};

inline DeliveryOptions parse_delivery_options(int argc, char** argv, const char* print_option)
{
    DeliveryOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == print_option) options.print_program = true;
        else if (arg == "--emit-dir" && i + 1 < argc) options.emit_directory = argv[++i];
        else if (arg == "--degree" && i + 1 < argc) {
            const std::string text = argv[++i];
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
                throw std::invalid_argument("--degree requires an integer in [128, 65536]");
            const auto degree = std::stoull(text);
            if (degree < 128 || degree > 65536 || (degree & (degree - 1)))
                throw std::invalid_argument("--degree must be a power of two in [128, 65536]");
            options.poly_modulus_degree = static_cast<std::size_t>(degree);
        }
        else throw std::invalid_argument(std::string("usage: ") + argv[0] +
            " [" + print_option + "] [--degree N] [--emit-dir PATH]");
    }
    return options;
}

inline std::string delivery_artifact_stem(const char* base, const DeliveryOptions& options,
                                         std::size_t default_degree = 128)
{
    const auto degree = options.poly_modulus_degree.value_or(default_degree);
    return std::string(base) + (degree == default_degree ? "" : "_n" + std::to_string(degree));
}

inline std::uint64_t delivery_construction_limit(std::size_t degree, std::uint64_t quick_limit)
{
    // This bounds preparation; emitted windows are trimmed to their actual layout.
    return degree >= 4096 ? UINT64_C(16777216) : quick_limit;
}
