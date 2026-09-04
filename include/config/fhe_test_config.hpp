#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace hpu::test {

struct FheTestConfig {
    std::size_t N;
    std::size_t num_q;
    std::size_t num_p;
    std::size_t bfv_num_b;
    std::uint64_t hpu_mem_max_lines;
    std::size_t dnum;
    std::uint64_t auto_galois_element;
    std::uint64_t plaintext_modulus;
    std::uint64_t seed;
};

std::filesystem::path default_fhe_test_config_path();
FheTestConfig load_fhe_test_config(const std::filesystem::path& path);

} // namespace hpu::test
