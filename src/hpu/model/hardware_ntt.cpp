#include "hpu/model/hardware_ntt.hpp"

#include <algorithm>
#include <array>
#include <numeric>
#include <stdexcept>
#include <utility>

namespace hpu::model {
namespace {

constexpr std::size_t kArrayWidth = 128;
constexpr std::size_t kButterflyCount = 64;
constexpr std::size_t kMaxDegree = 65536;

std::uint32_t add_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    const std::uint64_t sum = static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(sum >= modulus ? sum - modulus : sum);
}

std::uint32_t sub_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return left >= right ? left - right : static_cast<std::uint32_t>(
        static_cast<std::uint64_t>(left) + modulus - right);
}

std::uint32_t mul_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % modulus);
}

template <typename T>
std::array<T, kArrayWidth> apply_p(std::array<T, kArrayWidth> values, std::size_t count = 1)
{
    for (std::size_t rotation = 0; rotation < count % 7; ++rotation) {
        std::array<T, kArrayWidth> shifted {};
        for (std::size_t old_position = 0; old_position < kArrayWidth; ++old_position) {
            const std::size_t new_position =
                (old_position >> 1U) | ((old_position & 1U) << 6U);
            shifted[new_position] = values[old_position];
        }
        values = shifted;
    }
    return values;
}

template <typename T>
std::pair<std::array<T, kArrayWidth>, std::array<std::size_t, kArrayWidth>> load_batch(
    const std::vector<T>& values,
    const NttBatch& batch)
{
    std::array<T, kArrayWidth> registers {};
    std::array<std::size_t, kArrayWidth> positions {};
    if (!batch.interleaved) {
        for (std::size_t i = 0; i < kArrayWidth; ++i) {
            positions[i] = batch.first + i;
            registers[i] = values[positions[i]];
        }
    } else {
        for (std::size_t i = 0; i < kButterflyCount; ++i) {
            positions[2 * i] = batch.first + i;
            positions[2 * i + 1] = batch.second + i;
            registers[2 * i] = values[positions[2 * i]];
            registers[2 * i + 1] = values[positions[2 * i + 1]];
        }
    }
    return {registers, positions};
}

template <typename T>
void store_batch(
    std::vector<T>& values,
    const std::array<T, kArrayWidth>& registers,
    const std::array<std::size_t, kArrayWidth>& positions)
{
    for (std::size_t i = 0; i < kArrayWidth; ++i) {
        values[positions[i]] = registers[i];
    }
}

std::uint64_t inverse_mod_small(std::uint64_t value, std::uint64_t modulus)
{
    // This helper is used only for odd Galois elements modulo 2N <= 131072.
    std::int64_t old_r = static_cast<std::int64_t>(value);
    std::int64_t r = static_cast<std::int64_t>(modulus);
    std::int64_t old_s = 1;
    std::int64_t s = 0;
    while (r != 0) {
        const std::int64_t quotient = old_r / r;
        const std::int64_t next_r = old_r - quotient * r;
        old_r = r;
        r = next_r;
        const std::int64_t next_s = old_s - quotient * s;
        old_s = s;
        s = next_s;
    }
    if (old_r != 1) {
        throw std::invalid_argument("Galois element is not invertible modulo 2N");
    }
    old_s %= static_cast<std::int64_t>(modulus);
    if (old_s < 0) {
        old_s += static_cast<std::int64_t>(modulus);
    }
    return static_cast<std::uint64_t>(old_s);
}

void validate_negacyclic_root(
    std::size_t degree,
    std::uint32_t modulus,
    std::uint32_t psi)
{
    if (pow_mod(psi, degree, modulus) != modulus - 1U
        || pow_mod(psi, 2 * degree, modulus) != 1U) {
        throw std::invalid_argument("psi is not a primitive 2N-th root");
    }
}

} // namespace

std::uint32_t pow_mod(
    std::uint32_t base,
    std::uint64_t exponent,
    std::uint32_t modulus)
{
    if (modulus < 2) {
        throw std::invalid_argument("modulus must be at least two");
    }
    std::uint32_t result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = mul_mod(result, base, modulus);
        }
        exponent >>= 1U;
        if (exponent != 0) {
            base = mul_mod(base, base, modulus);
        }
    }
    return result;
}

std::uint32_t inverse_mod_prime(std::uint32_t value, std::uint32_t modulus)
{
    if (value == 0 || modulus < 3) {
        throw std::invalid_argument("non-zero value and prime modulus required");
    }
    return pow_mod(value, static_cast<std::uint64_t>(modulus) - 2U, modulus);
}

HardwareNttModel::HardwareNttModel(
    std::size_t degree,
    std::uint32_t modulus,
    std::uint32_t omega)
    : degree_(degree), modulus_(modulus), omega_(omega), log_degree_(0)
{
    if (degree < kArrayWidth || degree > kMaxDegree || (degree & (degree - 1)) != 0) {
        throw std::invalid_argument("HPU NTT degree must be a power of two in [128, 65536]");
    }
    for (std::size_t value = degree; value > 1; value >>= 1U) {
        ++log_degree_;
    }
    if (modulus < 3 || pow_mod(omega, degree, modulus) != 1U
        || pow_mod(omega, degree / 2, modulus) == 1U) {
        throw std::invalid_argument("omega is not a primitive N-th root");
    }
}

std::size_t HardwareNttModel::degree() const noexcept { return degree_; }
std::uint32_t HardwareNttModel::modulus() const noexcept { return modulus_; }
std::uint32_t HardwareNttModel::omega() const noexcept { return omega_; }
std::size_t HardwareNttModel::log_degree() const noexcept { return log_degree_; }

std::vector<NttBatch> HardwareNttModel::stage_batches(std::size_t forward_stage) const
{
    if (forward_stage >= log_degree_) {
        throw std::out_of_range("NTT stage is outside log2(N)");
    }
    const std::size_t m = std::size_t{1} << forward_stage;
    std::vector<NttBatch> batches;
    batches.reserve(degree_ / kArrayWidth);
    if (m < kArrayWidth) {
        for (std::size_t base = 0; base < degree_; base += kArrayWidth) {
            batches.push_back({false, base, base + kButterflyCount});
        }
    } else {
        for (std::size_t group = 0; group < degree_; group += 2 * m) {
            for (std::size_t offset = 0; offset < m; offset += kButterflyCount) {
                batches.push_back({true, group + offset, group + m + offset});
            }
        }
    }
    return batches;
}

std::vector<std::size_t> HardwareNttModel::forward_layout() const
{
    std::vector<std::size_t> labels(degree_);
    std::iota(labels.begin(), labels.end(), 0);
    for (std::size_t stage = 0; stage < log_degree_; ++stage) {
        for (const NttBatch& batch : stage_batches(stage)) {
            auto loaded = load_batch(labels, batch);
            loaded.first = apply_p(loaded.first);
            store_batch(labels, loaded.first, loaded.second);
        }
    }
    return labels;
}

std::vector<std::vector<std::uint32_t>> HardwareNttModel::forward_twiddles() const
{
    std::vector<std::size_t> labels(degree_);
    std::iota(labels.begin(), labels.end(), 0);
    std::vector<std::vector<std::uint32_t>> tables;
    tables.reserve(log_degree_);
    for (std::size_t stage = 0; stage < log_degree_; ++stage) {
        const std::size_t m = std::size_t{1} << stage;
        std::vector<std::uint32_t> table;
        table.reserve(degree_ / 2);
        for (const NttBatch& batch : stage_batches(stage)) {
            auto loaded = load_batch(labels, batch);
            for (std::size_t lane = 0; lane < kButterflyCount; ++lane) {
                const std::size_t lower = loaded.first[2 * lane];
                const std::size_t upper = loaded.first[2 * lane + 1];
                if (upper != lower + m) {
                    throw std::logic_error("forward loader/P schedule produced an invalid pair");
                }
                const std::uint64_t exponent = (lower % m) * degree_ / (2 * m);
                table.push_back(pow_mod(omega_, exponent, modulus_));
            }
            loaded.first = apply_p(loaded.first);
            store_batch(labels, loaded.first, loaded.second);
        }
        tables.push_back(std::move(table));
    }
    return tables;
}

InverseNttTables HardwareNttModel::inverse_twiddles() const
{
    std::vector<std::size_t> labels = forward_layout();
    std::vector<std::uint32_t> scales(degree_, 1);
    InverseNttTables result;
    result.stages.reserve(log_degree_);

    for (std::size_t inverse_stage = 0; inverse_stage < log_degree_; ++inverse_stage) {
        const std::size_t forward_stage = log_degree_ - 1 - inverse_stage;
        const std::size_t m = std::size_t{1} << forward_stage;
        std::vector<std::uint32_t> table;
        table.reserve(degree_ / 2);
        for (const NttBatch& batch : stage_batches(forward_stage)) {
            auto loaded_labels = load_batch(labels, batch);
            auto loaded_scales = load_batch(scales, batch);
            loaded_labels.first = apply_p(loaded_labels.first, 6);
            loaded_scales.first = apply_p(loaded_scales.first, 6);
            for (std::size_t lane = 0; lane < kButterflyCount; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const std::size_t lower = loaded_labels.first[even];
                const std::size_t upper = loaded_labels.first[odd];
                if (upper != lower + m) {
                    throw std::logic_error("inverse loader/P^-1 schedule produced an invalid pair");
                }
                const std::uint32_t alpha = loaded_scales.first[even];
                const std::uint32_t beta = loaded_scales.first[odd];
                table.push_back(mul_mod(alpha, inverse_mod_prime(beta, modulus_), modulus_));
                const std::uint64_t exponent = (lower % m) * degree_ / (2 * m);
                loaded_scales.first[even] = alpha;
                loaded_scales.first[odd] = mul_mod(
                    alpha, pow_mod(omega_, exponent, modulus_), modulus_);
            }
            store_batch(labels, loaded_labels.first, loaded_labels.second);
            store_batch(scales, loaded_scales.first, loaded_scales.second);
        }
        result.stages.push_back(std::move(table));
    }

    const std::uint32_t degree_inverse = inverse_mod_prime(
        static_cast<std::uint32_t>(degree_ % modulus_), modulus_);
    result.post_scale.resize(degree_);
    for (std::size_t position = 0; position < degree_; ++position) {
        if (labels[position] != position) {
            throw std::logic_error("inverse dual schedule did not restore logical layout");
        }
        result.post_scale[position] = mul_mod(
            inverse_mod_prime(scales[position], modulus_), degree_inverse, modulus_);
    }
    return result;
}

std::vector<std::uint32_t> HardwareNttModel::forward(
    const std::vector<std::uint32_t>& coefficients) const
{
    if (coefficients.size() != degree_) {
        throw std::invalid_argument("forward input length does not equal N");
    }
    std::vector<std::uint32_t> values = coefficients;
    std::vector<std::size_t> labels(degree_);
    std::iota(labels.begin(), labels.end(), 0);
    const auto tables = forward_twiddles();
    for (std::size_t stage = 0; stage < log_degree_; ++stage) {
        std::size_t twiddle = 0;
        for (const NttBatch& batch : stage_batches(stage)) {
            auto loaded_values = load_batch(values, batch);
            auto loaded_labels = load_batch(labels, batch);
            for (std::size_t lane = 0; lane < kButterflyCount; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const std::uint32_t a = loaded_values.first[even];
                const std::uint32_t product = mul_mod(
                    loaded_values.first[odd], tables[stage][twiddle++], modulus_);
                loaded_values.first[even] = add_mod(a, product, modulus_);
                loaded_values.first[odd] = sub_mod(a, product, modulus_);
            }
            loaded_values.first = apply_p(loaded_values.first);
            loaded_labels.first = apply_p(loaded_labels.first);
            store_batch(values, loaded_values.first, loaded_values.second);
            store_batch(labels, loaded_labels.first, loaded_labels.second);
        }
    }
    return values;
}

std::vector<std::uint32_t> HardwareNttModel::inverse(
    const std::vector<std::uint32_t>& physical_ntt) const
{
    if (physical_ntt.size() != degree_) {
        throw std::invalid_argument("inverse input length does not equal N");
    }
    std::vector<std::uint32_t> values = physical_ntt;
    const InverseNttTables tables = inverse_twiddles();
    for (std::size_t inverse_stage = 0; inverse_stage < log_degree_; ++inverse_stage) {
        const std::size_t forward_stage = log_degree_ - 1 - inverse_stage;
        std::size_t twiddle = 0;
        for (const NttBatch& batch : stage_batches(forward_stage)) {
            auto loaded = load_batch(values, batch);
            loaded.first = apply_p(loaded.first, 6);
            for (std::size_t lane = 0; lane < kButterflyCount; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const std::uint32_t a = loaded.first[even];
                const std::uint32_t product = mul_mod(
                    loaded.first[odd], tables.stages[inverse_stage][twiddle++], modulus_);
                loaded.first[even] = add_mod(a, product, modulus_);
                loaded.first[odd] = sub_mod(a, product, modulus_);
            }
            store_batch(values, loaded.first, loaded.second);
        }
    }
    for (std::size_t position = 0; position < degree_; ++position) {
        values[position] = mul_mod(values[position], tables.post_scale[position], modulus_);
    }
    return values;
}

std::vector<std::uint32_t> negacyclic_forward(
    const std::vector<std::uint32_t>& coefficients,
    std::uint32_t modulus,
    std::uint32_t psi)
{
    const std::size_t degree = coefficients.size();
    validate_negacyclic_root(degree, modulus, psi);
    std::vector<std::uint32_t> twisted(degree);
    std::uint32_t power = 1;
    for (std::size_t i = 0; i < degree; ++i) {
        twisted[i] = mul_mod(coefficients[i], power, modulus);
        power = mul_mod(power, psi, modulus);
    }
    HardwareNttModel model(degree, modulus, mul_mod(psi, psi, modulus));
    return model.forward(twisted);
}

std::vector<std::uint32_t> negacyclic_inverse(
    const std::vector<std::uint32_t>& physical_ntt,
    std::uint32_t modulus,
    std::uint32_t psi)
{
    const std::size_t degree = physical_ntt.size();
    validate_negacyclic_root(degree, modulus, psi);
    HardwareNttModel model(degree, modulus, mul_mod(psi, psi, modulus));
    std::vector<std::uint32_t> coefficients = model.inverse(physical_ntt);
    const std::uint32_t inverse_psi = inverse_mod_prime(psi, modulus);
    std::uint32_t power = 1;
    for (std::size_t i = 0; i < degree; ++i) {
        coefficients[i] = mul_mod(coefficients[i], power, modulus);
        power = mul_mod(power, inverse_psi, modulus);
    }
    return coefficients;
}

std::vector<std::uint32_t> automorphism_coefficients(
    const std::vector<std::uint32_t>& coefficients,
    std::uint64_t galois_element,
    std::uint32_t modulus)
{
    const std::size_t degree = coefficients.size();
    const std::uint64_t ring_order = 2 * degree;
    const std::uint64_t normalized_galois = galois_element % ring_order;
    if ((normalized_galois & 1U) == 0
        || std::gcd(normalized_galois, ring_order) != 1) {
        throw std::invalid_argument("Galois element must be odd and coprime to 2N");
    }
    std::vector<std::uint32_t> result(degree, 0);
    for (std::size_t i = 0; i < degree; ++i) {
        std::uint64_t index = (i * normalized_galois) % ring_order;
        std::uint32_t value = coefficients[i];
        if (index >= degree) {
            index -= degree;
            value = value == 0 ? 0 : modulus - value;
        }
        result[index] = add_mod(result[index], value, modulus);
    }
    return result;
}

std::vector<std::uint32_t> automorphism_fused_inverse(
    const std::vector<std::uint32_t>& canonical_physical_ntt,
    std::uint64_t galois_element,
    std::uint32_t modulus,
    std::uint32_t psi)
{
    if (canonical_physical_ntt.size() < kArrayWidth) {
        throw std::invalid_argument("fused automorphism requires a complete HPU polynomial");
    }
    const std::uint64_t ring_order = 2 * canonical_physical_ntt.size();
    const std::uint64_t inverse_galois = inverse_mod_small(
        galois_element % ring_order, ring_order);
    const std::uint32_t modified_psi = pow_mod(psi, inverse_galois, modulus);
    const auto rotated_coefficients = negacyclic_inverse(
        canonical_physical_ntt, modulus, modified_psi);
    return negacyclic_forward(rotated_coefficients, modulus, psi);
}

std::vector<std::uint32_t> automorphism_fused_forward(
    const std::vector<std::uint32_t>& canonical_physical_ntt,
    std::uint64_t galois_element,
    std::uint32_t modulus,
    std::uint32_t psi)
{
    if (canonical_physical_ntt.size() < kArrayWidth) {
        throw std::invalid_argument("fused automorphism requires a complete HPU polynomial");
    }
    const auto coefficients = negacyclic_inverse(canonical_physical_ntt, modulus, psi);
    const std::uint64_t normalized_galois =
        galois_element % (2 * canonical_physical_ntt.size());
    const std::uint32_t modified_psi = pow_mod(psi, normalized_galois, modulus);
    return negacyclic_forward(coefficients, modulus, modified_psi);
}

} // namespace hpu::model
