#include "config/fhe_test_config.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

#ifndef HPU_DEFAULT_TEST_CONFIG_PATH
#error "HPU_DEFAULT_TEST_CONFIG_PATH must be defined by the build system"
#endif

namespace hpu::test {
namespace {

std::string trim(const std::string& value)
{
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::uint64_t parse_unsigned(
    const std::string& text,
    const std::string& key,
    std::size_t line_number)
{
    int base = 10;
    std::string digits = text;
    if (digits.size() > 2 && digits[0] == '0'
        && (digits[1] == 'x' || digits[1] == 'X')) {
        base = 16;
        digits.erase(0, 2);
    }
    if (digits.empty()) {
        throw std::runtime_error(
            "empty value for " + key + " at line " + std::to_string(line_number));
    }

    std::uint64_t value = 0;
    const char* begin = digits.data();
    const char* end = begin + digits.size();
    const auto result = std::from_chars(begin, end, value, base);
    if (result.ec != std::errc{} || result.ptr != end) {
        throw std::runtime_error(
            "invalid unsigned integer for " + key + " at line "
            + std::to_string(line_number) + ": " + text);
    }
    return value;
}

std::size_t checked_size(
    const std::unordered_map<std::string, std::uint64_t>& values,
    const std::string& key)
{
    const auto value = values.at(key);
    if (value > std::numeric_limits<std::size_t>::max()) {
        throw std::runtime_error(key + " does not fit size_t");
    }
    return static_cast<std::size_t>(value);
}

void validate(const FheTestConfig& config)
{
    constexpr std::size_t kWordsPerLine = 64;
    constexpr std::size_t kRegularBankLines = 1024;
    constexpr std::size_t kMaxModContexts = 256;

    if (config.N < 128 || (config.N & (config.N - 1)) != 0) {
        throw std::runtime_error(
            "N must be a power of two and at least 128 for the 128-register NTT array");
    }
    if ((config.N + kWordsPerLine - 1) / kWordsPerLine > kRegularBankLines) {
        throw std::runtime_error("N exceeds one 1024-line regular SRAM bank");
    }
    if (config.num_q < 2) {
        throw std::runtime_error("num_q must be at least 2 for the Rescale UT");
    }
    if (config.num_p == 0) {
        throw std::runtime_error("num_p must be positive");
    }
    if (config.dnum == 0 || config.num_q % config.dnum != 0) {
        throw std::runtime_error("dnum must be positive and divide num_q");
    }
    if (config.num_q > kMaxModContexts
        || config.num_p > kMaxModContexts - config.num_q) {
        throw std::runtime_error("num_q + num_p exceeds the 8-bit MOD_ID space");
    }
    if (config.auto_index != 1) {
        throw std::runtime_error("auto_index must be 1; only Galois element 3 is frozen");
    }
    if (config.plaintext_modulus < 2
        || config.plaintext_modulus > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("plaintext_modulus must fit uint32 and be at least 2");
    }
}

} // namespace

std::filesystem::path default_fhe_test_config_path()
{
    return HPU_DEFAULT_TEST_CONFIG_PATH;
}

FheTestConfig load_fhe_test_config(const std::filesystem::path& path)
{
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open FHE test config: " + path.string());
    }

    const std::array<std::string, 7> allowed_keys{
        "N",
        "num_q",
        "num_p",
        "dnum",
        "auto_index",
        "plaintext_modulus",
        "seed",
    };
    std::unordered_map<std::string, std::uint64_t> values;
    std::string line;
    for (std::size_t line_number = 1; std::getline(input, line); ++line_number) {
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) {
            line.erase(comment);
        }
        line = trim(line);
        if (line.empty()) {
            continue;
        }

        const std::size_t separator = line.find('=');
        if (separator == std::string::npos || line.find('=', separator + 1) != std::string::npos) {
            throw std::runtime_error(
                "expected key=value at line " + std::to_string(line_number));
        }
        const std::string key = trim(line.substr(0, separator));
        const std::string value = trim(line.substr(separator + 1));
        if (std::find(allowed_keys.begin(), allowed_keys.end(), key)
            == allowed_keys.end()) {
            throw std::runtime_error(
                "unknown config key at line " + std::to_string(line_number) + ": " + key);
        }
        if (values.find(key) != values.end()) {
            throw std::runtime_error(
                "duplicate config key at line " + std::to_string(line_number) + ": " + key);
        }
        values.emplace(key, parse_unsigned(value, key, line_number));
    }

    std::ostringstream missing;
    for (const std::string& key : allowed_keys) {
        if (values.find(key) == values.end()) {
            if (missing.tellp() > 0) {
                missing << ", ";
            }
            missing << key;
        }
    }
    if (missing.tellp() > 0) {
        throw std::runtime_error("missing config keys: " + missing.str());
    }

    const FheTestConfig config{
        checked_size(values, "N"),
        checked_size(values, "num_q"),
        checked_size(values, "num_p"),
        checked_size(values, "dnum"),
        checked_size(values, "auto_index"),
        values.at("plaintext_modulus"),
        values.at("seed"),
    };
    validate(config);
    return config;
}

} // namespace hpu::test
