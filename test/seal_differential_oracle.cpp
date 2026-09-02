#include <seal/seal.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#ifndef HPU_SEAL_GIT_COMMIT
#define HPU_SEAL_GIT_COMMIT "unknown"
#endif
#ifndef HPU_SEAL_WORKTREE_STATE
#define HPU_SEAL_WORKTREE_STATE "unknown"
#endif
#ifndef HPU_SEAL_CMAKE_SHA256
#define HPU_SEAL_CMAKE_SHA256 "unknown"
#endif
#ifndef HPU_SEAL_EVALUATOR_SHA256
#define HPU_SEAL_EVALUATOR_SHA256 "unknown"
#endif
#ifndef HPU_SEAL_RNS_CPP_SHA256
#define HPU_SEAL_RNS_CPP_SHA256 "unknown"
#endif
#ifndef HPU_SEAL_RNS_HPP_SHA256
#define HPU_SEAL_RNS_HPP_SHA256 "unknown"
#endif

namespace {

struct Options {
    std::filesystem::path outputs_root;
    std::filesystem::path report_dir;
};

struct CsvTable {
    std::vector<std::string> header;
    std::vector<std::vector<std::string>> rows;
};

struct OracleParameters {
    std::size_t n{};
    std::vector<std::uint64_t> q;
    std::uint64_t special_p{};
    std::uint64_t plain_modulus{};
    std::uint64_t seed{};
    double ckks_input_scale{};
    double ckks_output_scale{};
    double ckks_roundtrip_error_bound{};
    double ckks_multiply_error_bound{};
    double ckks_rotation_error_bound{};
    int rotation_step{};
};

struct ReportRecord {
    std::string scheme;
    std::string checkpoint;
    std::size_t compared_count{};
    std::size_t mismatch_count{};
    double max_error{};
    double error_bound{};
    std::string status;
};

std::string trim(std::string value)
{
    const std::size_t first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return {};
    }
    const std::size_t last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::vector<std::string> parse_csv_row(const std::string& row)
{
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (std::size_t index = 0; index < row.size(); ++index) {
        const char ch = row[index];
        if (quoted) {
            if (ch == '"') {
                if (index + 1 < row.size() && row[index + 1] == '"') {
                    field.push_back('"');
                    ++index;
                } else {
                    quoted = false;
                }
            } else {
                field.push_back(ch);
            }
        } else if (ch == ',') {
            fields.push_back(trim(field));
            field.clear();
        } else if (ch == '"' && field.empty()) {
            quoted = true;
        } else {
            field.push_back(ch);
        }
    }
    if (quoted) {
        throw std::runtime_error("unterminated quoted CSV field");
    }
    fields.push_back(trim(field));
    return fields;
}

CsvTable read_csv(const std::filesystem::path& path)
{
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("cannot open CSV fixture: " + path.string());
    }

    CsvTable table;
    std::string line;
    if (!std::getline(input, line)) {
        throw std::runtime_error("empty CSV fixture: " + path.string());
    }
    table.header = parse_csv_row(line);
    std::size_t line_number = 1;
    while (std::getline(input, line)) {
        ++line_number;
        if (trim(line).empty()) {
            continue;
        }
        auto fields = parse_csv_row(line);
        if (fields.size() != table.header.size()) {
            throw std::runtime_error(
                path.string() + ":" + std::to_string(line_number)
                + " has " + std::to_string(fields.size())
                + " fields; expected " + std::to_string(table.header.size()));
        }
        table.rows.push_back(std::move(fields));
    }
    return table;
}

std::size_t column_index(
    const CsvTable& table,
    const std::filesystem::path& path,
    const std::string& name)
{
    const auto found = std::find(table.header.begin(), table.header.end(), name);
    if (found == table.header.end()) {
        throw std::runtime_error(
            "missing column '" + name + "' in " + path.string());
    }
    return static_cast<std::size_t>(found - table.header.begin());
}

std::uint64_t parse_u64(
    const std::string& text,
    const std::filesystem::path& path,
    std::size_t row)
{
    std::size_t consumed = 0;
    std::uint64_t value = 0;
    try {
        value = std::stoull(text, &consumed, 0);
    } catch (const std::exception&) {
        throw std::runtime_error(
            path.string() + ": invalid unsigned value at data row "
            + std::to_string(row));
    }
    if (consumed != text.size()) {
        throw std::runtime_error(
            path.string() + ": invalid unsigned suffix at data row "
            + std::to_string(row));
    }
    return value;
}

std::int64_t parse_i64(
    const std::string& text,
    const std::filesystem::path& path,
    std::size_t row)
{
    std::size_t consumed = 0;
    std::int64_t value = 0;
    try {
        value = std::stoll(text, &consumed, 0);
    } catch (const std::exception&) {
        throw std::runtime_error(
            path.string() + ": invalid signed value at data row "
            + std::to_string(row));
    }
    if (consumed != text.size()) {
        throw std::runtime_error(
            path.string() + ": invalid signed suffix at data row "
            + std::to_string(row));
    }
    return value;
}

double parse_double(
    const std::string& text,
    const std::filesystem::path& path,
    std::size_t row)
{
    std::size_t consumed = 0;
    double value = 0.0;
    try {
        value = std::stod(text, &consumed);
    } catch (const std::exception&) {
        throw std::runtime_error(
            path.string() + ": invalid floating-point value at data row "
            + std::to_string(row));
    }
    if (consumed != text.size() || !std::isfinite(value)) {
        throw std::runtime_error(
            path.string() + ": invalid floating-point suffix at data row "
            + std::to_string(row));
    }
    return value;
}

void validate_index_column(
    const CsvTable& table,
    const std::filesystem::path& path,
    const std::string& index_name)
{
    const std::size_t index_column = column_index(table, path, index_name);
    for (std::size_t row = 0; row < table.rows.size(); ++row) {
        if (parse_u64(table.rows[row][index_column], path, row + 1) != row) {
            throw std::runtime_error(
                path.string() + ": non-contiguous " + index_name
                + " at data row " + std::to_string(row + 1));
        }
    }
}

std::vector<std::int64_t> read_i64_column(
    const std::filesystem::path& path,
    const std::string& index_name,
    const std::string& value_name,
    std::size_t expected_size)
{
    const CsvTable table = read_csv(path);
    validate_index_column(table, path, index_name);
    const std::size_t value_column = column_index(table, path, value_name);
    if (table.rows.size() != expected_size) {
        throw std::runtime_error(
            path.string() + ": expected " + std::to_string(expected_size)
            + " rows, found " + std::to_string(table.rows.size()));
    }
    std::vector<std::int64_t> values;
    values.reserve(table.rows.size());
    for (std::size_t row = 0; row < table.rows.size(); ++row) {
        values.push_back(parse_i64(table.rows[row][value_column], path, row + 1));
    }
    return values;
}

std::vector<std::uint64_t> read_u64_column(
    const std::filesystem::path& path,
    const std::string& index_name,
    const std::string& value_name,
    std::size_t expected_size)
{
    const CsvTable table = read_csv(path);
    validate_index_column(table, path, index_name);
    const std::size_t value_column = column_index(table, path, value_name);
    if (table.rows.size() != expected_size) {
        throw std::runtime_error(
            path.string() + ": expected " + std::to_string(expected_size)
            + " rows, found " + std::to_string(table.rows.size()));
    }
    std::vector<std::uint64_t> values;
    values.reserve(table.rows.size());
    for (std::size_t row = 0; row < table.rows.size(); ++row) {
        values.push_back(parse_u64(table.rows[row][value_column], path, row + 1));
    }
    return values;
}

std::vector<std::complex<double>> read_complex_column(
    const std::filesystem::path& path,
    const std::string& real_name,
    const std::string& imag_name,
    std::size_t expected_size)
{
    const CsvTable table = read_csv(path);
    validate_index_column(table, path, "slot");
    const std::size_t real_column = column_index(table, path, real_name);
    const std::size_t imag_column = column_index(table, path, imag_name);
    if (table.rows.size() != expected_size) {
        throw std::runtime_error(
            path.string() + ": expected " + std::to_string(expected_size)
            + " rows, found " + std::to_string(table.rows.size()));
    }
    std::vector<std::complex<double>> values;
    values.reserve(table.rows.size());
    for (std::size_t row = 0; row < table.rows.size(); ++row) {
        values.emplace_back(
            parse_double(table.rows[row][real_column], path, row + 1),
            parse_double(table.rows[row][imag_column], path, row + 1));
    }
    return values;
}

OracleParameters read_parameters(const std::filesystem::path& path)
{
    const CsvTable table = read_csv(path);
    if (table.header != std::vector<std::string>{ "name", "index", "value" }) {
        throw std::runtime_error(
            "unexpected SEAL oracle parameter schema in " + path.string());
    }

    std::map<std::pair<std::string, std::string>, std::string> values;
    for (std::size_t row = 0; row < table.rows.size(); ++row) {
        const auto key = std::make_pair(table.rows[row][0], table.rows[row][1]);
        if (!values.emplace(key, table.rows[row][2]).second) {
            throw std::runtime_error(
                path.string() + ": duplicate parameter " + key.first);
        }
    }
    const auto get = [&](const std::string& name, const std::string& index = "") {
        const auto found = values.find({ name, index });
        if (found == values.end()) {
            throw std::runtime_error(
                path.string() + ": missing parameter " + name
                + (index.empty() ? "" : "[" + index + "]"));
        }
        return found->second;
    };

    OracleParameters parameters;
    parameters.n = static_cast<std::size_t>(
        parse_u64(get("poly_modulus_degree"), path, 0));
    for (std::size_t index = 0;; ++index) {
        const auto found = values.find(
            { "coeff_modulus_q", std::to_string(index) });
        if (found == values.end()) {
            break;
        }
        parameters.q.push_back(parse_u64(found->second, path, index + 1));
    }
    parameters.special_p = parse_u64(get("special_modulus_p", "0"), path, 0);
    parameters.plain_modulus = parse_u64(get("plain_modulus"), path, 0);
    parameters.seed = parse_u64(get("seed"), path, 0);
    parameters.ckks_input_scale = parse_double(get("ckks_input_scale"), path, 0);
    parameters.ckks_output_scale = parse_double(get("ckks_output_scale"), path, 0);
    parameters.ckks_roundtrip_error_bound =
        parse_double(get("ckks_roundtrip_error_bound"), path, 0);
    parameters.ckks_multiply_error_bound =
        parse_double(get("ckks_multiply_error_bound"), path, 0);
    parameters.ckks_rotation_error_bound =
        parse_double(get("ckks_rotation_error_bound"), path, 0);
    parameters.rotation_step = static_cast<int>(
        parse_u64(get("rotation_step"), path, 0));

    if (parameters.n == 0 || parameters.q.size() < 2
        || parameters.special_p == 0 || parameters.plain_modulus == 0
        || parameters.ckks_input_scale <= 0.0
        || parameters.ckks_output_scale <= 0.0
        || parameters.ckks_roundtrip_error_bound <= 0.0
        || parameters.ckks_multiply_error_bound <= 0.0
        || parameters.ckks_rotation_error_bound <= 0.0
        || parameters.rotation_step != 1) {
        throw std::runtime_error("invalid SEAL oracle parameter values in " + path.string());
    }
    for (const auto& entry : values) {
        if (entry.first.first == "coeff_modulus_q") {
            const std::size_t index = static_cast<std::size_t>(
                parse_u64(entry.first.second, path, 0));
            if (index >= parameters.q.size()) {
                throw std::runtime_error(
                    path.string() + ": non-contiguous coeff_modulus_q indices");
            }
        }
    }
    return parameters;
}

class Reporter {
public:
    Reporter(std::filesystem::path report_dir, std::filesystem::path outputs_root)
        : report_dir_(std::move(report_dir)), outputs_root_(std::move(outputs_root))
    {
        std::filesystem::create_directories(report_dir_);
    }

    void condition(
        const std::string& scheme,
        const std::string& checkpoint,
        bool passed,
        const std::string& detail)
    {
        records_.push_back({
            scheme, checkpoint, 1, passed ? 0U : 1U,
            passed ? 0.0 : 1.0, 0.0, passed ? "PASS" : "FAIL" });
        if (!passed) {
            throw std::runtime_error(scheme + " " + checkpoint + ": " + detail);
        }
    }

    template <typename T>
    void exact(
        const std::string& scheme,
        const std::string& checkpoint,
        const std::vector<T>& expected,
        const std::vector<T>& actual)
    {
        if (expected.size() != actual.size()) {
            records_.push_back({
                scheme, checkpoint, std::max(expected.size(), actual.size()), 1,
                1.0, 0.0, "FAIL" });
            throw std::runtime_error(
                scheme + " " + checkpoint + ": vector size mismatch (expected "
                + std::to_string(expected.size()) + ", actual "
                + std::to_string(actual.size()) + ")");
        }
        std::size_t mismatches = 0;
        std::size_t first = 0;
        for (std::size_t index = 0; index < expected.size(); ++index) {
            if (expected[index] != actual[index]) {
                if (mismatches == 0) {
                    first = index;
                }
                ++mismatches;
            }
        }
        records_.push_back({
            scheme, checkpoint, expected.size(), mismatches,
            mismatches == 0 ? 0.0 : 1.0, 0.0,
            mismatches == 0 ? "PASS" : "FAIL" });
        if (mismatches != 0) {
            std::ostringstream message;
            message << scheme << ' ' << checkpoint << ": " << mismatches
                    << " mismatches; first at index " << first
                    << " (expected " << expected[first] << ", actual "
                    << actual[first] << ')';
            throw std::runtime_error(message.str());
        }
    }

    void approximate(
        const std::string& scheme,
        const std::string& checkpoint,
        const std::vector<std::complex<double>>& expected,
        const std::vector<std::complex<double>>& actual,
        double bound)
    {
        if (expected.size() != actual.size()) {
            records_.push_back({
                scheme, checkpoint, std::max(expected.size(), actual.size()), 1,
                std::numeric_limits<double>::infinity(), bound, "FAIL" });
            throw std::runtime_error(
                scheme + " " + checkpoint + ": vector size mismatch");
        }
        std::size_t mismatches = 0;
        std::size_t first = 0;
        double max_error = 0.0;
        for (std::size_t index = 0; index < expected.size(); ++index) {
            const double error = std::abs(actual[index] - expected[index]);
            if (!std::isfinite(error) || error > bound) {
                if (mismatches == 0) {
                    first = index;
                }
                ++mismatches;
            }
            max_error = std::isfinite(error)
                ? std::max(max_error, error)
                : std::numeric_limits<double>::infinity();
        }
        records_.push_back({
            scheme, checkpoint, expected.size(), mismatches, max_error, bound,
            mismatches == 0 ? "PASS" : "FAIL" });
        if (mismatches != 0) {
            std::ostringstream message;
            message << std::setprecision(17) << scheme << ' ' << checkpoint
                    << ": " << mismatches << " values exceed " << bound
                    << "; first at slot " << first << " (expected "
                    << expected[first] << ", actual " << actual[first] << ')';
            throw std::runtime_error(message.str());
        }
    }

    void scalar(
        const std::string& scheme,
        const std::string& checkpoint,
        double expected,
        double actual,
        double bound)
    {
        const double error = std::abs(actual - expected);
        const bool passed = std::isfinite(error) && error <= bound;
        records_.push_back({
            scheme, checkpoint, 1, passed ? 0U : 1U, error, bound,
            passed ? "PASS" : "FAIL" });
        if (!passed) {
            std::ostringstream message;
            message << std::setprecision(17) << scheme << ' ' << checkpoint
                    << ": expected " << expected << ", actual " << actual
                    << ", bound " << bound;
            throw std::runtime_error(message.str());
        }
    }

    void fatal(const std::string& detail)
    {
        records_.push_back({ "META", "fatal", 0, 1, 1.0, 0.0, "FAIL" });
        fatal_detail_ = detail;
    }

    void write() const
    {
        std::filesystem::create_directories(report_dir_);
        {
            std::ofstream output(report_dir_ / "report.csv");
            if (!output) {
                throw std::runtime_error("cannot write SEAL oracle report.csv");
            }
            output << "scheme,checkpoint,compared_count,mismatch_count,max_error,error_bound,status\n";
            output << std::setprecision(17);
            for (const ReportRecord& record : records_) {
                output << record.scheme << ',' << record.checkpoint << ','
                       << record.compared_count << ',' << record.mismatch_count
                       << ',' << record.max_error << ',' << record.error_bound
                       << ',' << record.status << '\n';
            }
        }
        {
            std::ofstream output(report_dir_ / "metadata.txt");
            if (!output) {
                throw std::runtime_error("cannot write SEAL oracle metadata.txt");
            }
            output << "oracle=HPU_SEAL_DIFFERENTIAL_V1\n"
                   << "security_status=FUNCTIONAL_TEST_ONLY\n"
                   << "outputs_root=" << outputs_root_.string() << '\n'
                   << "seal_git_commit=" << HPU_SEAL_GIT_COMMIT << '\n'
                   << "seal_worktree_state=" << HPU_SEAL_WORKTREE_STATE << '\n'
                   << "seal_experimental_bfv_no_smrq=ON\n"
                   << "seal_experimental_bfv_branchless_sk=ON\n"
                   << "seal_CMakeLists_sha256=" << HPU_SEAL_CMAKE_SHA256 << '\n'
                   << "seal_evaluator_cpp_sha256=" << HPU_SEAL_EVALUATOR_SHA256 << '\n'
                   << "seal_rns_cpp_sha256=" << HPU_SEAL_RNS_CPP_SHA256 << '\n'
                   << "seal_rns_h_sha256=" << HPU_SEAL_RNS_HPP_SHA256 << '\n';
            if (!fatal_detail_.empty()) {
                output << "failure=" << fatal_detail_ << '\n';
            }
        }
    }

private:
    std::filesystem::path report_dir_;
    std::filesystem::path outputs_root_;
    std::vector<ReportRecord> records_;
    std::string fatal_detail_;
};

std::vector<std::uint64_t> canonicalize(
    const std::vector<std::int64_t>& values,
    std::uint64_t modulus)
{
    if (modulus > static_cast<std::uint64_t>(
            std::numeric_limits<std::int64_t>::max())) {
        throw std::runtime_error("plain modulus does not fit signed conversion");
    }
    const auto signed_modulus = static_cast<std::int64_t>(modulus);
    std::vector<std::uint64_t> result(values.size());
    for (std::size_t index = 0; index < values.size(); ++index) {
        std::int64_t residue = values[index] % signed_modulus;
        if (residue < 0) {
            residue += signed_modulus;
        }
        result[index] = static_cast<std::uint64_t>(residue);
    }
    return result;
}

std::vector<std::uint64_t> plaintext_coefficients(
    const seal::Plaintext& plaintext,
    std::size_t n)
{
    if (plaintext.coeff_count() > n) {
        throw std::runtime_error("SEAL plaintext has more than N coefficients");
    }
    std::vector<std::uint64_t> result(n, 0);
    std::copy_n(plaintext.data(), plaintext.coeff_count(), result.begin());
    return result;
}

std::vector<std::uint64_t> modulus_values(
    const std::vector<seal::Modulus>& moduli)
{
    std::vector<std::uint64_t> values;
    values.reserve(moduli.size());
    for (const seal::Modulus& modulus : moduli) {
        values.push_back(modulus.value());
    }
    return values;
}

seal::EncryptionParameters make_encryption_parameters(
    seal::scheme_type scheme,
    const OracleParameters& oracle_parameters,
    std::uint64_t scheme_tag)
{
    seal::EncryptionParameters parameters(scheme);
    parameters.set_poly_modulus_degree(oracle_parameters.n);
    std::vector<seal::Modulus> coeff_modulus;
    coeff_modulus.reserve(oracle_parameters.q.size() + 1);
    for (std::uint64_t modulus : oracle_parameters.q) {
        coeff_modulus.emplace_back(modulus);
    }
    coeff_modulus.emplace_back(oracle_parameters.special_p);
    parameters.set_coeff_modulus(coeff_modulus);
    if (scheme == seal::scheme_type::bfv || scheme == seal::scheme_type::bgv) {
        parameters.set_plain_modulus(oracle_parameters.plain_modulus);
    }
    seal::prng_seed_type seed{
        oracle_parameters.seed, scheme_tag, 0x485055ULL, 1, 2, 3, 4, 5 };
    parameters.set_random_generator(
        std::make_shared<seal::Blake2xbPRNGFactory>(seed));
    return parameters;
}

void validate_context(
    const std::string& scheme,
    const seal::SEALContext& context,
    const OracleParameters& parameters,
    Reporter& reporter)
{
    reporter.condition(
        scheme, "parameters_set", context.parameters_set(),
        "SEAL rejected the configured parameter chain");
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    reporter.condition(
        scheme, "key_context_present", static_cast<bool>(key_data),
        "missing key context");
    reporter.condition(
        scheme, "ciphertext_context_present", static_cast<bool>(first_data),
        "missing first ciphertext context");

    std::vector<std::uint64_t> expected_key = parameters.q;
    expected_key.push_back(parameters.special_p);
    reporter.exact(
        scheme, "key_context_Q_plus_P0", expected_key,
        modulus_values(key_data->parms().coeff_modulus()));
    reporter.exact(
        scheme, "ciphertext_context_Q", parameters.q,
        modulus_values(first_data->parms().coeff_modulus()));

    const auto next_data = first_data->next_context_data();
    reporter.condition(
        scheme, "next_context_present", static_cast<bool>(next_data),
        "missing Q-without-last context");
    const std::vector<std::uint64_t> expected_next(
        parameters.q.begin(), parameters.q.end() - 1);
    reporter.exact(
        scheme, "next_context_Q_without_last", expected_next,
        modulus_values(next_data->parms().coeff_modulus()));
}

std::vector<std::uint64_t> decrypt_batch(
    seal::Decryptor& decryptor,
    seal::BatchEncoder& encoder,
    const seal::Ciphertext& ciphertext)
{
    seal::Plaintext plaintext;
    decryptor.decrypt(ciphertext, plaintext);
    std::vector<std::uint64_t> slots;
    encoder.decode(plaintext, slots);
    return slots;
}

void run_integer_scheme(
    seal::scheme_type scheme_type,
    const std::string& scheme,
    const std::filesystem::path& outputs_root,
    const OracleParameters& parameters,
    Reporter& reporter)
{
    const std::string lower = scheme == "BFV" ? "bfv" : "bgv";
    const auto encode_host =
        outputs_root / (lower + "_encode") / "test_data" / "host";
    const auto multiply_host =
        outputs_root / (lower + "_ciphertext_multiply") / "test_data" / "host";

    const auto encode_slots_signed = read_i64_column(
        encode_host / "batch_slots.csv", "index", "input", parameters.n);
    const auto encode_slots = canonicalize(
        encode_slots_signed, parameters.plain_modulus);
    const auto expected_coefficients = read_u64_column(
        encode_host / "batch_coefficients_mod_t.csv", "index",
        "coefficient_mod_t", parameters.n);
    const auto left_signed = read_i64_column(
        multiply_host / "input_slots_a.csv", "index", "input", parameters.n);
    const auto right_signed = read_i64_column(
        multiply_host / "input_slots_b.csv", "index", "input", parameters.n);
    const auto product_signed = read_i64_column(
        multiply_host / "decoded_product.csv", "slot", "expected", parameters.n);
    const auto fixture_actual_signed = read_i64_column(
        multiply_host / "decoded_product.csv", "slot", "actual", parameters.n);
    const auto left = canonicalize(left_signed, parameters.plain_modulus);
    const auto right = canonicalize(right_signed, parameters.plain_modulus);
    const auto expected_product = canonicalize(
        product_signed, parameters.plain_modulus);
    const auto fixture_actual = canonicalize(
        fixture_actual_signed, parameters.plain_modulus);
    reporter.exact(scheme, "fixture_encode_multiply_input", encode_slots, left);
    reporter.exact(
        scheme, "fixture_reference_product", expected_product, fixture_actual);

    const std::filesystem::path rotation_path = scheme == "BFV"
        ? encode_host / "rotate_left_1_expected_slots.csv"
        : encode_host / "auto_x3_expected_slots.csv";
    const auto rotation_signed = read_i64_column(
        rotation_path, "index", "expected", parameters.n);
    const auto expected_rotation = canonicalize(
        rotation_signed, parameters.plain_modulus);

    auto encryption_parameters = make_encryption_parameters(
        scheme_type, parameters, scheme == "BFV" ? 0x424656ULL : 0x424756ULL);
    seal::SEALContext context(
        encryption_parameters, true, seal::sec_level_type::none);
    validate_context(scheme, context, parameters, reporter);

    seal::KeyGenerator key_generator(context);
    const seal::SecretKey secret_key = key_generator.secret_key();
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;
    seal::GaloisKeys galois_keys;
    key_generator.create_public_key(public_key);
    key_generator.create_relin_keys(relin_keys);
    key_generator.create_galois_keys(galois_keys);

    seal::BatchEncoder encoder(context);
    reporter.condition(
        scheme, "slot_count", encoder.slot_count() == parameters.n,
        "BatchEncoder slot count differs from N");
    seal::Plaintext encode_plain;
    encoder.encode(encode_slots, encode_plain);
    reporter.exact(
        scheme, "batch_encode_coefficients", expected_coefficients,
        plaintext_coefficients(encode_plain, parameters.n));

    seal::Plaintext left_plain;
    seal::Plaintext right_plain;
    encoder.encode(left, left_plain);
    encoder.encode(right, right_plain);
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::Ciphertext left_cipher;
    seal::Ciphertext right_cipher;
    encryptor.encrypt(left_plain, left_cipher);
    encryptor.encrypt(right_plain, right_cipher);
    reporter.exact(
        scheme, "fresh_encrypt_decrypt", left,
        decrypt_batch(decryptor, encoder, left_cipher));

    seal::Ciphertext product;
    evaluator.multiply(left_cipher, right_cipher, product);
    reporter.condition(
        scheme, "multiply_component_count", product.size() == 3,
        "ciphertext multiply did not produce three components");
    reporter.exact(
        scheme, "multiply_three_component_decrypt", expected_product,
        decrypt_batch(decryptor, encoder, product));

    evaluator.relinearize_inplace(product, relin_keys);
    reporter.condition(
        scheme, "relinearized_component_count", product.size() == 2,
        "relinearization did not reduce the ciphertext to two components");
    reporter.exact(
        scheme, "relinearize_decrypt", expected_product,
        decrypt_batch(decryptor, encoder, product));

    evaluator.mod_switch_to_next_inplace(product);
    reporter.condition(
        scheme, "modswitch_context",
        product.parms_id()
            == context.first_context_data()->next_context_data()->parms_id(),
        "modulus switch did not move to Q without q_last");
    reporter.exact(
        scheme, "modswitch_decrypt", expected_product,
        decrypt_batch(decryptor, encoder, product));

    seal::Ciphertext rotated = left_cipher;
    evaluator.rotate_rows_inplace(
        rotated, parameters.rotation_step, galois_keys);
    reporter.exact(
        scheme, "rotate_left_1_decrypt", expected_rotation,
        decrypt_batch(decryptor, encoder, rotated));
}

std::vector<std::complex<double>> decrypt_ckks(
    seal::Decryptor& decryptor,
    seal::CKKSEncoder& encoder,
    const seal::Ciphertext& ciphertext)
{
    seal::Plaintext plaintext;
    decryptor.decrypt(ciphertext, plaintext);
    std::vector<std::complex<double>> slots;
    encoder.decode(plaintext, slots);
    return slots;
}

void run_ckks(
    const std::filesystem::path& outputs_root,
    const OracleParameters& parameters,
    Reporter& reporter)
{
    constexpr const char* kScheme = "CKKS";
    const auto encode_host =
        outputs_root / "ckks_encode" / "test_data" / "host";
    const auto multiply_host =
        outputs_root / "ckks_ciphertext_multiply" / "test_data" / "host";
    const std::size_t slot_count = parameters.n / 2;
    const auto encode_a = read_complex_column(
        encode_host / "slots_a.csv", "input_real", "input_imag", slot_count);
    const auto encode_b = read_complex_column(
        encode_host / "slots_b.csv", "input_real", "input_imag", slot_count);
    const auto left = read_complex_column(
        multiply_host / "input_slots_a.csv", "input_real", "input_imag", slot_count);
    const auto right = read_complex_column(
        multiply_host / "input_slots_b.csv", "input_real", "input_imag", slot_count);
    const auto expected_product = read_complex_column(
        multiply_host / "decoded_product.csv", "expected_real", "expected_imag",
        slot_count);
    const auto fixture_actual = read_complex_column(
        multiply_host / "decoded_product.csv", "actual_real", "actual_imag",
        slot_count);
    const auto expected_rotation = read_complex_column(
        encode_host / "rotate_left_1_expected_slots.csv",
        "expected_real", "expected_imag", slot_count);
    reporter.approximate(kScheme, "fixture_input_a", encode_a, left, 0.0);
    reporter.approximate(kScheme, "fixture_input_b", encode_b, right, 0.0);
    reporter.approximate(
        kScheme, "fixture_reference_product", expected_product, fixture_actual,
        parameters.ckks_multiply_error_bound);

    auto encryption_parameters = make_encryption_parameters(
        seal::scheme_type::ckks, parameters, 0x434B4B53ULL);
    seal::SEALContext context(
        encryption_parameters, true, seal::sec_level_type::none);
    validate_context(kScheme, context, parameters, reporter);

    seal::CKKSEncoder encoder(context);
    reporter.condition(
        kScheme, "slot_count", encoder.slot_count() == slot_count,
        "CKKSEncoder slot count differs from N/2");
    seal::Plaintext left_plain;
    seal::Plaintext right_plain;
    encoder.encode(
        left, context.first_parms_id(), parameters.ckks_input_scale, left_plain);
    encoder.encode(
        right, context.first_parms_id(), parameters.ckks_input_scale, right_plain);
    std::vector<std::complex<double>> roundtrip_left;
    std::vector<std::complex<double>> roundtrip_right;
    encoder.decode(left_plain, roundtrip_left);
    encoder.decode(right_plain, roundtrip_right);
    reporter.approximate(
        kScheme, "encode_decode_a", left, roundtrip_left,
        parameters.ckks_roundtrip_error_bound);
    reporter.approximate(
        kScheme, "encode_decode_b", right, roundtrip_right,
        parameters.ckks_roundtrip_error_bound);

    seal::KeyGenerator key_generator(context);
    const seal::SecretKey secret_key = key_generator.secret_key();
    seal::PublicKey public_key;
    seal::RelinKeys relin_keys;
    seal::GaloisKeys galois_keys;
    key_generator.create_public_key(public_key);
    key_generator.create_relin_keys(relin_keys);
    key_generator.create_galois_keys(galois_keys);
    seal::Encryptor encryptor(context, public_key);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secret_key);
    seal::Ciphertext left_cipher;
    seal::Ciphertext right_cipher;
    encryptor.encrypt(left_plain, left_cipher);
    encryptor.encrypt(right_plain, right_cipher);
    reporter.approximate(
        kScheme, "fresh_encrypt_decrypt", left,
        decrypt_ckks(decryptor, encoder, left_cipher),
        parameters.ckks_roundtrip_error_bound);

    seal::Ciphertext product;
    evaluator.multiply(left_cipher, right_cipher, product);
    reporter.condition(
        kScheme, "multiply_component_count", product.size() == 3,
        "ciphertext multiply did not produce three components");
    reporter.approximate(
        kScheme, "multiply_three_component_decrypt", expected_product,
        decrypt_ckks(decryptor, encoder, product),
        parameters.ckks_multiply_error_bound);

    evaluator.relinearize_inplace(product, relin_keys);
    reporter.condition(
        kScheme, "relinearized_component_count", product.size() == 2,
        "relinearization did not reduce the ciphertext to two components");
    reporter.approximate(
        kScheme, "relinearize_decrypt", expected_product,
        decrypt_ckks(decryptor, encoder, product),
        parameters.ckks_multiply_error_bound);

    evaluator.rescale_to_next_inplace(product);
    reporter.condition(
        kScheme, "rescale_context",
        product.parms_id()
            == context.first_context_data()->next_context_data()->parms_id(),
        "rescale did not move to Q without q_last");
    const double scale_bound = std::max(
        1e-9, std::abs(parameters.ckks_output_scale) * 1e-12);
    reporter.scalar(
        kScheme, "rescale_output_scale", parameters.ckks_output_scale,
        product.scale(), scale_bound);
    reporter.approximate(
        kScheme, "rescale_decrypt", expected_product,
        decrypt_ckks(decryptor, encoder, product),
        parameters.ckks_multiply_error_bound);

    seal::Ciphertext rotated = left_cipher;
    evaluator.rotate_vector_inplace(
        rotated, parameters.rotation_step, galois_keys);
    reporter.approximate(
        kScheme, "rotate_left_1_decrypt", expected_rotation,
        decrypt_ckks(decryptor, encoder, rotated),
        parameters.ckks_rotation_error_bound);
}

Options parse_options(int argc, char* argv[])
{
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "--outputs-root") {
            if (++index >= argc) {
                throw std::runtime_error("--outputs-root requires a path");
            }
            options.outputs_root = argv[index];
        } else if (argument == "--report-dir") {
            if (++index >= argc) {
                throw std::runtime_error("--report-dir requires a path");
            }
            options.report_dir = argv[index];
        } else {
            throw std::runtime_error("unknown argument: " + argument);
        }
    }
    if (options.outputs_root.empty() || options.report_dir.empty()) {
        throw std::runtime_error(
            "usage: hpu_seal_differential_test --outputs-root PATH --report-dir PATH");
    }
    return options;
}

} // namespace

int main(int argc, char* argv[])
{
    Options options;
    try {
        options = parse_options(argc, argv);
    } catch (const std::exception& exception) {
        std::cerr << "SEAL differential oracle argument error: "
                  << exception.what() << '\n';
        return 2;
    }

    Reporter reporter(options.report_dir, options.outputs_root);
    try {
        const OracleParameters parameters = read_parameters(
            options.outputs_root / "seal_oracle" / "parameters.csv");
        run_integer_scheme(
            seal::scheme_type::bfv, "BFV", options.outputs_root,
            parameters, reporter);
        run_integer_scheme(
            seal::scheme_type::bgv, "BGV", options.outputs_root,
            parameters, reporter);
        run_ckks(options.outputs_root, parameters, reporter);
        reporter.write();
        std::cout << "SEAL BFV/BGV/CKKS differential oracle: PASS\n";
        std::cout << "Report: " << (options.report_dir / "report.csv") << '\n';
        return 0;
    } catch (const std::exception& exception) {
        reporter.fatal(exception.what());
        try {
            reporter.write();
        } catch (const std::exception& report_exception) {
            std::cerr << "Failed to write SEAL oracle report: "
                      << report_exception.what() << '\n';
        }
        std::cerr << "SEAL differential oracle failed: "
                  << exception.what() << '\n';
        return 1;
    }
}
