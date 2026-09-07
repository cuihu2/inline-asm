#include "hpu/runtime/software_executor.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace hpu::runtime {
namespace {

std::uint64_t barrett_mu(std::uint32_t modulus)
{
    const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
    const std::uint64_t quotient = maximum / modulus;
    const std::uint64_t remainder = maximum % modulus;
    return quotient + (remainder + 1 >= modulus ? 1 : 0);
}

} // namespace

HpuSoftwareExecutor::HpuSoftwareExecutor(const HpuMemImage& image)
    : words_(image.words())
{}

void HpuSoftwareExecutor::load_modulus_table(
    HpuMemSpan span,
    std::size_t modulus_count)
{
    if (modulus_table_loaded_) {
        throw std::logic_error("software executor loaded the modulus table more than once");
    }
    if (modulus_count == 0
        || modulus_count > std::numeric_limits<std::uint8_t>::max() + std::size_t{1}) {
        throw std::invalid_argument("invalid software-executor modulus count");
    }
    const auto records = read(span, modulus_count * 4);
    moduli_.reserve(modulus_count);
    for (std::size_t index = 0; index < modulus_count; ++index) {
        const std::uint32_t modulus = records[index * 4];
        const std::uint64_t mu = records[index * 4 + 1]
            | (static_cast<std::uint64_t>(records[index * 4 + 2] & 0xffffU) << 32U);
        if (modulus < 65537 || records[index * 4 + 3] != 0
            || (records[index * 4 + 2] & 0xffff0000U) != 0
            || mu != barrett_mu(modulus)) {
            throw std::invalid_argument("invalid HPU modulus/mu table record");
        }
        moduli_.push_back(modulus);
    }
    modulus_table_loaded_ = true;
}

std::uint32_t HpuSoftwareExecutor::modulus(std::uint8_t modulus_id) const
{
    if (!modulus_table_loaded_ || modulus_id >= moduli_.size()) {
        throw std::out_of_range("HPU MOD_ID is not loaded");
    }
    return moduli_[modulus_id];
}

std::size_t HpuSoftwareExecutor::checked_word_offset(
    HpuMemSpan span,
    std::size_t word_count) const
{
    if (span.line_count == 0
        || span.line_offset > std::numeric_limits<std::size_t>::max() / kHpuMemLineWords
        || span.line_count > std::numeric_limits<std::size_t>::max() / kHpuMemLineWords) {
        throw std::invalid_argument("invalid HPU_MEM software-executor span");
    }
    const std::size_t offset = static_cast<std::size_t>(span.line_offset)
        * kHpuMemLineWords;
    const std::size_t capacity = static_cast<std::size_t>(span.line_count)
        * kHpuMemLineWords;
    if (word_count > capacity || offset > words_.size()
        || capacity > words_.size() - offset) {
        throw std::out_of_range("HPU_MEM software-executor span exceeds the image");
    }
    return offset;
}

std::vector<std::uint32_t> HpuSoftwareExecutor::read(
    HpuMemSpan span,
    std::size_t word_count) const
{
    const std::size_t offset = checked_word_offset(span, word_count);
    return std::vector<std::uint32_t>(
        words_.begin() + static_cast<std::ptrdiff_t>(offset),
        words_.begin() + static_cast<std::ptrdiff_t>(offset + word_count));
}

void HpuSoftwareExecutor::write(
    HpuMemSpan span,
    const std::vector<std::uint32_t>& words)
{
    const std::size_t offset = checked_word_offset(span, words.size());
    std::copy(words.begin(), words.end(), words_.begin()
        + static_cast<std::ptrdiff_t>(offset));
}

void HpuSoftwareExecutor::copy(
    HpuMemSpan destination,
    HpuMemSpan source,
    std::size_t word_count)
{
    write(destination, read(source, word_count));
}

void HpuSoftwareExecutor::pointwise(
    HpuMemSpan destination,
    HpuMemSpan left,
    HpuMemSpan right,
    std::size_t word_count,
    std::uint8_t modulus_id,
    PointwiseOperation operation)
{
    const std::uint32_t q = modulus(modulus_id);
    const auto left_words = read(left, word_count);
    const auto right_words = read(right, word_count);
    std::vector<std::uint32_t> output(word_count);
    for (std::size_t index = 0; index < word_count; ++index) {
        if (left_words[index] >= q || right_words[index] >= q) {
            throw std::invalid_argument("HPU pointwise operand is not reduced modulo q");
        }
        switch (operation) {
        case PointwiseOperation::add: {
            const std::uint64_t sum = static_cast<std::uint64_t>(left_words[index])
                + right_words[index];
            output[index] = static_cast<std::uint32_t>(sum >= q ? sum - q : sum);
            break;
        }
        case PointwiseOperation::subtract:
            output[index] = left_words[index] >= right_words[index]
                ? left_words[index] - right_words[index]
                : static_cast<std::uint32_t>(
                    static_cast<std::uint64_t>(left_words[index]) + q
                    - right_words[index]);
            break;
        case PointwiseOperation::multiply:
            output[index] = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(left_words[index])
                    * right_words[index]) % q);
            break;
        }
    }
    write(destination, output);
}

void HpuSoftwareExecutor::multiply_accumulate(
    HpuMemSpan accumulator,
    HpuMemSpan left,
    HpuMemSpan right,
    std::size_t word_count,
    std::uint8_t modulus_id)
{
    const std::uint32_t q = modulus(modulus_id);
    auto accumulator_words = read(accumulator, word_count);
    const auto left_words = read(left, word_count);
    const auto right_words = read(right, word_count);
    for (std::size_t index = 0; index < word_count; ++index) {
        if (accumulator_words[index] >= q || left_words[index] >= q
            || right_words[index] >= q) {
            throw std::invalid_argument(
                "HPU multiply-accumulate operand is not reduced modulo q");
        }
        const std::uint32_t product = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(left_words[index])
                * right_words[index]) % q);
        const std::uint64_t sum = static_cast<std::uint64_t>(
            accumulator_words[index]) + product;
        accumulator_words[index] = static_cast<std::uint32_t>(
            sum >= q ? sum - q : sum);
    }
    write(accumulator, accumulator_words);
}

const std::vector<std::uint32_t>& HpuSoftwareExecutor::words() const noexcept
{
    return words_;
}

} // namespace hpu::runtime
