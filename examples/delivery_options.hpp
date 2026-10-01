#pragma once

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

struct DeliveryOptions {
    bool print_program = false;
    std::optional<std::filesystem::path> emit_directory;
};

inline DeliveryOptions parse_delivery_options(int argc, char** argv, const char* print_option)
{
    DeliveryOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == print_option) options.print_program = true;
        else if (arg == "--emit-dir" && i + 1 < argc) options.emit_directory = argv[++i];
        else throw std::invalid_argument(std::string("usage: ") + argv[0] +
            " [" + print_option + "] [--emit-dir PATH]");
    }
    return options;
}
