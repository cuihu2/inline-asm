#include "hpu/model/hardware_ntt.hpp"

#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace {

constexpr std::uint32_t kModulus = 2013265921U;
constexpr std::uint32_t kPrimitiveRoot = 31U;

std::uint32_t multiply_mod(
    std::uint32_t left,
    std::uint32_t right,
    std::uint32_t modulus)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % modulus);
}

std::size_t bit_reverse(std::size_t value, std::size_t degree)
{
    std::size_t reversed = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        reversed = (reversed << 1U) | (value & 1U);
        value >>= 1U;
    }
    return reversed;
}

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

// Independent iterative Cooley-Tukey oracle. Unlike the hardware model, this
// performs an explicit input bit reversal and has no loader or P network.
std::vector<std::uint32_t> mathematical_ntt(
    const std::vector<std::uint32_t>& input,
    std::uint32_t omega)
{
    const std::size_t degree = input.size();
    std::vector<std::uint32_t> values(degree);
    for (std::size_t index = 0; index < degree; ++index) {
        values[bit_reverse(index, degree)] = input[index];
    }
    for (std::size_t length = 2; length <= degree; length <<= 1U) {
        const std::size_t half = length / 2;
        const std::uint32_t step = hpu::model::pow_mod(
            omega, degree / length, kModulus);
        for (std::size_t base = 0; base < degree; base += length) {
            std::uint32_t twiddle = 1;
            for (std::size_t offset = 0; offset < half; ++offset) {
                const std::uint32_t even = values[base + offset];
                const std::uint32_t odd = multiply_mod(
                    values[base + offset + half], twiddle, kModulus);
                const std::uint64_t sum = static_cast<std::uint64_t>(even) + odd;
                values[base + offset] = static_cast<std::uint32_t>(
                    sum >= kModulus ? sum - kModulus : sum);
                values[base + offset + half] = even >= odd
                    ? even - odd
                    : static_cast<std::uint32_t>(
                        static_cast<std::uint64_t>(even) + kModulus - odd);
                twiddle = multiply_mod(twiddle, step, kModulus);
            }
        }
    }
    return values;
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

    const auto layout = model.forward_layout();
    std::vector<std::uint32_t> logical_ntt(degree);
    for (std::size_t position = 0; position < degree; ++position) {
        logical_ntt[layout[position]] = physical[position];
    }
    require(
        logical_ntt == mathematical_ntt(input, omega),
        "HPU forward transform disagrees with mathematical NTT");

    const auto negacyclic = hpu::model::negacyclic_forward(input, kModulus, psi);
    require(
        hpu::model::negacyclic_inverse(negacyclic, kModulus, psi) == input,
        "negacyclic HPU NTT round-trip failed");

    std::vector<bool> seen(degree, false);
    for (std::size_t logical : layout) {
        require(logical < degree && !seen[logical], "forward layout is not a permutation");
        seen[logical] = true;
    }

    const auto inverse_tables = model.inverse_twiddles();
    require(inverse_tables.stages.size() == model.log_degree(), "wrong inverse stage count");
    require(inverse_tables.post_scale.size() == degree, "wrong inverse post-scale size");
}

void test_delta_basis()
{
    constexpr std::size_t degree = 128;
    const std::uint32_t psi = psi_for(degree);
    const std::uint32_t omega = hpu::model::pow_mod(psi, 2, kModulus);
    hpu::model::HardwareNttModel model(degree, kModulus, omega);
    std::vector<std::uint32_t> delta(degree, 0);
    delta[1] = 1;
    const auto physical = model.forward(delta);
    const auto layout = model.forward_layout();
    std::vector<std::uint32_t> logical(degree);
    for (std::size_t position = 0; position < degree; ++position) {
        logical[layout[position]] = physical[position];
    }
    for (std::size_t frequency = 0; frequency < degree; ++frequency) {
        require(
            logical[frequency] == hpu::model::pow_mod(omega, frequency, kModulus),
            "forward(delta_1) is not omega^k");
    }
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
        test_delta_basis();
        test_fused_automorphism(128, 3);
        test_fused_automorphism(65536, 3);
        std::cout << "HPU NTT model tests passed, including N=65536 and fused automorphism\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU NTT model test failed: " << error.what() << '\n';
        return 1;
    }
}
