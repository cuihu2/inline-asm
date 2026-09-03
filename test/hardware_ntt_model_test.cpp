#include "hpu/model/hardware_ntt.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::uint32_t kModulus = 2013265921U;
constexpr std::uint32_t kPrimitiveRoot = 31U;

std::uint32_t psi_for(std::size_t degree)
{
    return hpu::model::pow_mod(
        kPrimitiveRoot,
        (static_cast<std::uint64_t>(kModulus) - 1U) / (2 * degree),
        kModulus);
}
std::vector<std::uint32_t> deterministic_input(std::size_t degree)
{
    std::vector<std::uint32_t> input(degree);
    std::uint64_t state = 0x4850555f4e545455ULL;
    for (std::uint32_t& value : input) {
        state ^= state << 13U;
        state ^= state >> 7U;
        state ^= state << 17U;
        value = static_cast<std::uint32_t>(state % kModulus);
    }
    return input;
}

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_degree(std::size_t degree)
{
    const std::uint32_t psi = psi_for(degree);
    const std::uint32_t omega = hpu::model::pow_mod(psi, 2, kModulus);
    hpu::model::HardwareNttModel model(degree, kModulus, omega);
    const auto input = deterministic_input(degree);

    const auto physical = model.forward(input);
    require(model.inverse(physical) == input, "cyclic HPU NTT round-trip failed");

    const auto negacyclic = hpu::model::negacyclic_forward(input, kModulus, psi);
    require(
        hpu::model::negacyclic_inverse(negacyclic, kModulus, psi) == input,
        "negacyclic HPU NTT round-trip failed");

    const auto layout = model.forward_layout();
    std::vector<bool> seen(degree, false);
    for (std::size_t logical : layout) {
        require(logical < degree && !seen[logical], "forward layout is not a permutation");
        seen[logical] = true;
    }

    const auto inverse_tables = model.inverse_twiddles();
    require(inverse_tables.stages.size() == model.log_degree(), "wrong inverse stage count");
    require(inverse_tables.post_scale.size() == degree, "wrong inverse post-scale size");
}

void test_fused_automorphism(std::size_t degree, std::uint64_t galois_element)
{
    const std::uint32_t psi = psi_for(degree);
    const auto input = deterministic_input(degree);
    const auto canonical_ntt = hpu::model::negacyclic_forward(input, kModulus, psi);
    const auto expected_coefficients = hpu::model::automorphism_coefficients(
        input, galois_element, kModulus);
    const auto expected_ntt = hpu::model::negacyclic_forward(
        expected_coefficients, kModulus, psi);

    require(
        hpu::model::automorphism_fused_inverse(
            canonical_ntt, galois_element, kModulus, psi) == expected_ntt,
        "INTT-fused automorphism disagrees with coefficient reference");
    require(
        hpu::model::automorphism_fused_forward(
            canonical_ntt, galois_element, kModulus, psi) == expected_ntt,
        "NTT-fused automorphism disagrees with coefficient reference");
}

} // namespace

int main()
{
    try {
        test_degree(128);
        test_degree(2048);
        test_degree(65536);
        test_fused_automorphism(128, 3);
        test_fused_automorphism(65536, 3);
        std::cout << "HPU NTT model tests passed, including N=65536 and fused automorphism\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU NTT model test failed: " << error.what() << '\n';
        return 1;
    }
}
