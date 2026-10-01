#include "hpu/delivery/application_package.hpp"
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv)
{
    try {
        if (argc != 2) throw std::invalid_argument("usage: hpu_validate_package PACKAGE_DIR");
        hpu::delivery::validate_application_package_on_disk(argv[1]);
        std::cout << "Application package validation PASS: " << argv[1] << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Application package validation failed: " << error.what() << '\n';
        return 1;
    }
}
