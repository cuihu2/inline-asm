#include "hpu/runtime/memory_image.hpp"
#include "hpu/runtime/software_executor.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>

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
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

std::vector<std::uint32_t> modulus_record(std::uint32_t modulus)
{
    const std::uint64_t mu = static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(1) << 64) / modulus);
    return {modulus, static_cast<std::uint32_t>(mu),
            static_cast<std::uint32_t>(mu >> 32), 0};
}

void check_modulus(std::uint32_t modulus)
{
    constexpr std::uint32_t maximum = std::numeric_limits<std::uint32_t>::max();
    hpu::runtime::HpuMemImage image(8);
    const auto table = image.add(
        "modulus", modulus_record(modulus),
        hpu::runtime::AllocationKind::modulus_table);
    const std::vector<std::uint32_t> wide{
        modulus, modulus == maximum ? maximum : modulus + 1,
        maximum - 2, maximum - 1, maximum};
    const auto left = image.add(
        "left", wide, hpu::runtime::AllocationKind::workspace);
    const auto right = image.add(
        "right", {1, modulus - 1, maximum, maximum, maximum},
        hpu::runtime::AllocationKind::workspace);
    const auto one = image.add(
        "one", {1, 1, 1, 1, 1}, hpu::runtime::AllocationKind::constant);
    const auto accumulator = image.add(
        "accumulator", {0, 1, modulus - 1, 0, 1},
        hpu::runtime::AllocationKind::workspace, false);
    const auto output = image.reserve(
        "output", wide.size(), hpu::runtime::AllocationKind::output);

    hpu::runtime::HpuSoftwareExecutor executor(image);
    executor.load_modulus_table(table.span, 1);
    executor.pointwise(
        output.span, left.span, right.span, wide.size(), 0,
        hpu::runtime::PointwiseOperation::multiply);
    const auto product = executor.read(output.span, wide.size());
    const auto right_words = executor.read(right.span, wide.size());
    for (std::size_t index = 0; index < wide.size(); ++index) {
        const auto expected = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(wide[index]) * right_words[index])
            % modulus);
        require(product[index] == expected, "wide PMUL result differs from modular product");
        require(product[index] < modulus, "PMUL result is not canonical");
    }

    executor.multiply_accumulate(
        accumulator.span, left.span, right.span, wide.size(), 0);
    const auto accumulated = executor.read(accumulator.span, wide.size());
    const std::vector<std::uint32_t> initial{0, 1, modulus - 1, 0, 1};
    for (std::size_t index = 0; index < wide.size(); ++index) {
        const auto expected = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(initial[index]) + product[index])
            % modulus);
        require(accumulated[index] == expected, "wide PMAC multiplicand was rejected or miscomputed");
    }

    require_throws(
        [&] { executor.pointwise(
            output.span, left.span, right.span, wide.size(), 0,
            hpu::runtime::PointwiseOperation::add); },
        "PADD accepted a noncanonical input");
    require_throws(
        [&] { executor.pointwise(
            output.span, left.span, right.span, wide.size(), 0,
            hpu::runtime::PointwiseOperation::subtract); },
        "PSUB accepted a noncanonical input");

    executor.write(accumulator.span, {modulus, 0, 0, 0, 0});
    require_throws(
        [&] { executor.multiply_accumulate(
            accumulator.span, left.span, right.span, wide.size(), 0); },
        "PMAC accepted a noncanonical accumulator");

    // A wide input becomes safe for the one-subtraction add/sub data path
    // after PMUL(x, 1) has written a canonical residue.
    executor.pointwise(
        output.span, left.span, one.span, wide.size(), 0,
        hpu::runtime::PointwiseOperation::multiply);
    executor.pointwise(
        output.span, output.span, one.span, wide.size(), 0,
        hpu::runtime::PointwiseOperation::add);
    const auto normalized_plus_one = executor.read(output.span, wide.size());
    for (std::size_t index = 0; index < wide.size(); ++index) {
        require(
            normalized_plus_one[index]
                == (static_cast<std::uint64_t>(wide[index]) + 1) % modulus,
            "PMUL(x, 1) did not normalize before PADD");
    }
}

} // namespace

int main()
{
    try {
        check_modulus(65537);
        check_modulus(2013265921);
        check_modulus(4294967291U);
        check_modulus(std::numeric_limits<std::uint32_t>::max());
        std::cout << "HPU software executor PMUL/PMAC range tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU software executor range test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
