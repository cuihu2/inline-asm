#include "scheme/ckks/encode.hpp"

#include "util/validation.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace hpu::scheme::ckks {
namespace {

constexpr double kPi = 3.141592653589793238462643383279502884;

unsigned log2_exact(std::size_t value)
{
    unsigned result = 0;
    while ((std::size_t{1} << result) < value) {
        ++result;
    }
    return result;
}

std::size_t reverse_bits(std::size_t value, unsigned width)
{
    std::size_t reversed = 0;
    for (unsigned bit = 0; bit < width; ++bit) {
        reversed = (reversed << 1U) | ((value >> bit) & 1U);
    }
    return reversed;
}

std::vector<std::size_t> generator3_slot_roots(std::size_t N)
{
    const unsigned log_n = log2_exact(N);
    const std::size_t slot_count = N / 2;
    const std::size_t m = 2 * N;
    std::vector<std::size_t> roots(N);
    std::size_t position = 1;
    for (std::size_t slot = 0; slot < slot_count; ++slot) {
        // Keep the bit-reverse step explicit: this is the SEAL matrix map,
        // converted back to logical root order for the local FFT.
        const std::size_t first_map = reverse_bits((position - 1) / 2, log_n);
        const std::size_t second_map =
            reverse_bits((m - position - 1) / 2, log_n);
        roots[slot] = reverse_bits(first_map, log_n);
        roots[slot_count + slot] = reverse_bits(second_map, log_n);
        position = (position * 3) & (m - 1);
    }
    return roots;
}

void fft(std::vector<std::complex<double>>& values, bool inverse)
{
    const std::size_t N = values.size();
    for (std::size_t i = 1, j = 0; i < N; ++i) {
        std::size_t bit = N >> 1U;
        while ((j & bit) != 0) {
            j ^= bit;
            bit >>= 1U;
        }
        j ^= bit;
        if (i < j) {
            std::swap(values[i], values[j]);
        }
    }

    for (std::size_t length = 2; length <= N; length <<= 1U) {
        const double angle = (inverse ? 2.0 : -2.0) * kPi
            / static_cast<double>(length);
        const std::complex<double> step = std::polar(1.0, angle);
        for (std::size_t begin = 0; begin < N; begin += length) {
            std::complex<double> twiddle{1.0, 0.0};
            for (std::size_t j = 0; j < length / 2; ++j) {
                const auto even = values[begin + j];
                const auto odd = values[begin + j + length / 2] * twiddle;
                values[begin + j] = even + odd;
                values[begin + j + length / 2] = even - odd;
                twiddle *= step;
            }
        }
    }

    if (inverse) {
        for (auto& value : values) {
            value /= static_cast<double>(N);
        }
    }
}

void validate_ring(std::size_t N)
{
    if (N < 2 || !hpu::is_power_of_two(N)) {
        throw std::invalid_argument("CKKS N must be a power of two and at least 2");
    }
}

} // namespace

EncodedPlaintext encode_slots(
    const std::vector<std::complex<double>>& complex_slots,
    std::size_t N,
    double scale)
{
    validate_ring(N);
    if (complex_slots.size() > N / 2) {
        throw std::invalid_argument("CKKS slot count exceeds N/2");
    }
    if (!std::isfinite(scale) || scale <= 0.0) {
        throw std::invalid_argument("CKKS scale must be finite and positive");
    }
    for (const auto& slot : complex_slots) {
        if (!std::isfinite(slot.real()) || !std::isfinite(slot.imag())) {
            throw std::invalid_argument("CKKS slots must be finite");
        }
    }

    const auto roots = generator3_slot_roots(N);
    std::vector<std::complex<double>> evaluations(N, {0.0, 0.0});
    for (std::size_t slot = 0; slot < complex_slots.size(); ++slot) {
        evaluations[roots[slot]] = complex_slots[slot];
        evaluations[roots[N / 2 + slot]] = std::conj(complex_slots[slot]);
    }

    fft(evaluations, false);
    EncodedPlaintext encoded;
    encoded.coefficients.resize(N);
    encoded.scale = scale;
    encoded.slot_count = complex_slots.size();
    const long double lower =
        static_cast<long double>(std::numeric_limits<std::int64_t>::min());
    const long double upper =
        static_cast<long double>(std::numeric_limits<std::int64_t>::max());
    for (std::size_t coefficient = 0; coefficient < N; ++coefficient) {
        const double angle = -kPi * static_cast<double>(coefficient)
            / static_cast<double>(N);
        const auto value = evaluations[coefficient]
            * std::polar(1.0, angle) / static_cast<double>(N);
        const long double scaled = static_cast<long double>(value.real()) * scale;
        if (!std::isfinite(static_cast<double>(scaled))
            || scaled < lower - 0.5L || scaled > upper + 0.5L) {
            throw std::overflow_error("CKKS encoded coefficient exceeds int64 range");
        }
        encoded.coefficients[coefficient] = static_cast<std::int64_t>(
            std::llround(scaled));
    }
    return encoded;
}

std::vector<std::complex<double>> decode_slots(
    const std::vector<std::int64_t>& centered_coefficients,
    double scale)
{
    const std::size_t N = centered_coefficients.size();
    validate_ring(N);
    if (!std::isfinite(scale) || scale <= 0.0) {
        throw std::invalid_argument("CKKS scale must be finite and positive");
    }

    std::vector<std::complex<double>> values(N);
    for (std::size_t coefficient = 0; coefficient < N; ++coefficient) {
        const double angle = kPi * static_cast<double>(coefficient)
            / static_cast<double>(N);
        values[coefficient] =
            (static_cast<double>(centered_coefficients[coefficient]) / scale)
            * std::polar(1.0, angle);
    }
    fft(values, true);
    for (auto& value : values) {
        value *= static_cast<double>(N);
    }

    const auto roots = generator3_slot_roots(N);
    std::vector<std::complex<double>> slots(N / 2);
    for (std::size_t slot = 0; slot < slots.size(); ++slot) {
        slots[slot] = values[roots[slot]];
    }
    return slots;
}

} // namespace hpu::scheme::ckks
