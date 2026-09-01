#include "scheme/bgv/encode.hpp"
#include "scheme/ckks/encode.hpp"
#include "scheme/bfv/encode.hpp"

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstdint>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void require(bool condition, const std::string& message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void expect_failure(const std::function<void()>& action, const std::string& name)
{
    try {
        action();
    } catch (const std::exception&) {
        return;
    }
    throw std::runtime_error("expected failure: " + name);
}

std::vector<std::uint64_t> apply_galois_3(
    const std::vector<std::uint64_t>& coefficients,
    std::uint64_t modulus)
{
    const std::size_t N = coefficients.size();
    std::vector<std::uint64_t> result(N, 0);
    for (std::size_t source = 0; source < N; ++source) {
        const std::size_t exponent = (3 * source) % (2 * N);
        if (exponent < N) {
            result[exponent] = coefficients[source] % modulus;
        } else {
            const auto value = coefficients[source] % modulus;
            result[exponent - N] = value == 0 ? 0 : modulus - value;
        }
    }
    return result;
}

void test_ckks()
{
    constexpr std::size_t N = 16;
    constexpr double scale = 1048576.0;
    const std::vector<std::complex<double>> input{
        {1.25, -0.5}, {-2.0, 0.75}, {0.0, 0.0}, {3.5, 1.0},
    };
    const auto encoded = hpu::scheme::ckks::encode_slots(input, N, scale);
    require(encoded.coefficients.size() == N, "CKKS coefficient count");
    require(encoded.slot_count == input.size(), "CKKS slot metadata");
    const auto decoded = hpu::scheme::ckks::decode_slots(
        encoded.coefficients, encoded.scale);
    for (std::size_t i = 0; i < input.size(); ++i) {
        require(std::abs(decoded[i] - input[i]) < 1e-4,
                "CKKS complex slot round-trip");
    }
    for (std::size_t i = input.size(); i < decoded.size(); ++i) {
        require(std::abs(decoded[i]) < 1e-4, "CKKS zero-filled slot");
    }

    const std::vector<std::complex<double>> real_slots{{1.0, 0.0}, {-4.0, 0.0}};
    const auto real_encoded = hpu::scheme::ckks::encode_slots(real_slots, N, scale);
    const auto real_decoded = hpu::scheme::ckks::decode_slots(
        real_encoded.coefficients, scale);
    require(std::abs(real_decoded[0] - real_slots[0]) < 1e-4,
            "CKKS real slot round-trip");

    expect_failure(
        [] { hpu::scheme::ckks::encode_slots({}, 12, 1.0); }, "CKKS invalid N");
    expect_failure(
        [] { hpu::scheme::ckks::encode_slots(
            std::vector<std::complex<double>>(9), 16, 1.0); },
        "CKKS slot overflow");
    expect_failure(
        [] { hpu::scheme::ckks::encode_slots(
            {{std::numeric_limits<double>::quiet_NaN(), 0.0}}, 16, 1.0); },
        "CKKS NaN");
    expect_failure(
        [] { hpu::scheme::ckks::encode_slots(
            {{std::numeric_limits<double>::infinity(), 0.0}}, 16, 1.0); },
        "CKKS infinity");
    expect_failure(
        [] { hpu::scheme::ckks::encode_slots({{1.0, 0.0}}, 16, 0.0); },
        "CKKS invalid scale");
    expect_failure(
        [] { hpu::scheme::ckks::encode_slots(
            {{1.0e100, 0.0}}, 16, 1.0e100); },
        "CKKS coefficient overflow");
}

void test_bgv()
{
    constexpr std::size_t N = 16;
    constexpr std::uint64_t t = 65537;
    const std::vector<std::int64_t> coefficient_input{0, 1, -1, 32768, -32768};
    const auto coefficients = hpu::scheme::bgv::encode_coefficients(
        coefficient_input, N, t);
    const auto coefficient_output = hpu::scheme::bgv::decode_coefficients(
        coefficients, t);
    require(std::equal(coefficient_input.begin(), coefficient_input.end(),
                       coefficient_output.begin()),
            "BGV coefficient round-trip");
    const auto composite_coefficients = hpu::scheme::bgv::encode_coefficients(
        {-1, 2}, N, 81921);
    const auto composite_decoded = hpu::scheme::bgv::decode_coefficients(
        composite_coefficients, 81921);
    require(composite_decoded[0] == -1 && composite_decoded[1] == 2,
            "BGV coefficient encoding permits composite t");

    std::vector<std::int64_t> slots(N);
    for (std::size_t i = 0; i < N; ++i) {
        slots[i] = static_cast<std::int64_t>(i) - 8;
    }
    const auto batched = hpu::scheme::bgv::encode_slots(slots, N, t);
    const auto decoded = hpu::scheme::bgv::decode_slots(batched, t);
    require(decoded == slots, "BGV batch round-trip");

    const auto rotated_coefficients = apply_galois_3(batched, t);
    const auto rotated_slots = hpu::scheme::bgv::decode_slots(
        rotated_coefficients, t);
    const std::size_t row_size = N / 2;
    for (std::size_t row = 0; row < 2; ++row) {
        for (std::size_t column = 0; column < row_size; ++column) {
            const auto expected = slots[row * row_size + (column + 1) % row_size];
            require(rotated_slots[row * row_size + column] == expected,
                    "BGV generator-3 row rotation");
        }
    }

    expect_failure(
        [] { hpu::scheme::bgv::encode_coefficients({32769}, N, t); },
        "BGV centered range");
    expect_failure(
        [] { hpu::scheme::bgv::encode_slots(
            std::vector<std::int64_t>(N + 1), N, t); },
        "BGV slot overflow");
    expect_failure(
        [] { hpu::scheme::bgv::encode_slots({}, N, 81921); },
        "BGV composite t");
    expect_failure(
        [] { hpu::scheme::bgv::encode_slots({}, N, 65539); },
        "BGV non-batching t");
}

void test_bfv()
{
    constexpr std::size_t N = 16;
    constexpr std::uint64_t t = 65537;
    const std::vector<std::int64_t> coefficients{0, 1, -1, 17, -17};
    const auto encoded_coefficients = hpu::scheme::bfv::encode_coefficients(
        coefficients, N, t);
    const auto decoded_coefficients = hpu::scheme::bfv::decode_coefficients(
        encoded_coefficients, t);
    require(std::equal(coefficients.begin(), coefficients.end(),
                       decoded_coefficients.begin()),
            "BFV coefficient round-trip");

    std::vector<std::int64_t> slots(N);
    for (std::size_t i = 0; i < N; ++i) {
        slots[i] = static_cast<std::int64_t>(i) - 8;
    }
    const auto encoded_slots = hpu::scheme::bfv::encode_slots(slots, N, t);
    require(hpu::scheme::bfv::decode_slots(encoded_slots, t) == slots,
            "BFV batch round-trip");

    const auto rotated_coefficients = apply_galois_3(encoded_slots, t);
    const auto rotated_slots = hpu::scheme::bfv::decode_slots(
        rotated_coefficients, t);
    const std::size_t row_size = N / 2;
    for (std::size_t row = 0; row < 2; ++row) {
        for (std::size_t column = 0; column < row_size; ++column) {
            require(
                rotated_slots[row * row_size + column]
                    == slots[row * row_size + (column + 1) % row_size],
                "BFV generator-3 row rotation");
        }
    }

    expect_failure(
        [] { hpu::scheme::bfv::encode_coefficients({32769}, N, t); },
        "BFV centered range");
    expect_failure(
        [] { hpu::scheme::bfv::encode_slots(
            std::vector<std::int64_t>(N + 1), N, t); },
        "BFV slot overflow");
    expect_failure(
        [] { hpu::scheme::bfv::encode_slots({}, N, 81921); },
        "BFV composite t");
    expect_failure(
        [] { hpu::scheme::bfv::encode_slots({}, N, 65539); },
        "BFV non-batching t");
}

} // namespace

int main()
{
    try {
        test_ckks();
        test_bgv();
        test_bfv();
        std::cout << "CKKS/BGV/BFV scheme Encode self-test passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Scheme Encode self-test failed: " << exception.what() << '\n';
        return 1;
    }
}
