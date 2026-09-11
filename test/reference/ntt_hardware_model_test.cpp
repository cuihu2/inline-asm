#include <algorithm>
#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using U64 = std::uint64_t;
using U128 = unsigned __int128;
using Row = std::unordered_map<std::string, std::string>;

constexpr std::size_t kRegisterCount = 128;
constexpr std::size_t kLaneCount = 64;

struct Batch {
    bool interleaved = false;
    std::size_t first = 0;
    std::size_t second = 0;
};

struct ForwardSchedule {
    std::vector<std::vector<U64>> twiddles;
    std::vector<std::vector<std::size_t>> stage_layouts;
    std::vector<std::size_t> final_layout;
};

struct InverseLane {
    std::size_t stage = 0;
    std::size_t forward_stage = 0;
    std::size_t m = 0;
    std::size_t batch = 0;
    std::size_t lane = 0;
    std::size_t lower = 0;
    std::size_t upper = 0;
    U64 w_forward = 0;
    U64 w_inverse = 0;
    U64 w_bf = 0;
    U64 alpha = 0;
    U64 beta = 0;
};

struct InverseSchedule {
    std::vector<std::vector<U64>> twiddles;
    std::vector<InverseLane> lanes;
};

std::vector<std::string> split_csv(std::string line)
{
    if (!line.empty() && line.back() == '\r') {
        line.pop_back();
    }
    std::vector<std::string> fields;
    std::stringstream input(line);
    std::string field;
    while (std::getline(input, field, ',')) {
        fields.push_back(field);
    }
    return fields;
}

std::vector<Row> read_csv(const std::filesystem::path& path)
{
    std::ifstream input(path);
    if (!input) {
        throw std::runtime_error("failed to open fixture " + path.string());
    }
    std::string line;
    if (!std::getline(input, line)) {
        throw std::runtime_error("empty fixture " + path.string());
    }
    const std::vector<std::string> header = split_csv(line);
    std::vector<Row> rows;
    while (std::getline(input, line)) {
        if (line.empty() || line == "\r") {
            continue;
        }
        const std::vector<std::string> fields = split_csv(line);
        if (fields.size() != header.size()) {
            throw std::runtime_error("malformed fixture row in " + path.string());
        }
        Row row;
        for (std::size_t i = 0; i < header.size(); ++i) {
            row.emplace(header[i], fields[i]);
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

U64 parse_u64(const Row& row, const std::string& field)
{
    const auto found = row.find(field);
    if (found == row.end()) {
        throw std::runtime_error("fixture field is missing: " + field);
    }
    std::size_t consumed = 0;
    const U64 value = std::stoull(found->second, &consumed, 0);
    if (consumed != found->second.size()) {
        throw std::runtime_error("invalid fixture integer in field " + field);
    }
    return value;
}

std::vector<U64> read_column(
    const std::filesystem::path& path, const std::string& field)
{
    const std::vector<Row> rows = read_csv(path);
    std::vector<U64> values;
    values.reserve(rows.size());
    for (const Row& row : rows) {
        values.push_back(parse_u64(row, field));
    }
    return values;
}

U64 add_mod(U64 left, U64 right, U64 modulus)
{
    return static_cast<U64>((static_cast<U128>(left) + right) % modulus);
}

U64 sub_mod(U64 left, U64 right, U64 modulus)
{
    return left >= right ? left - right : modulus - (right - left);
}

U64 mul_mod(U64 left, U64 right, U64 modulus)
{
    return static_cast<U64>(static_cast<U128>(left) * right % modulus);
}

U64 pow_mod(U64 base, U64 exponent, U64 modulus)
{
    U64 result = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1U;
    }
    return result;
}

U64 inverse_mod_prime(U64 value, U64 modulus)
{
    if (value == 0) {
        throw std::runtime_error("cannot invert zero");
    }
    return pow_mod(value, modulus - 2, modulus);
}

std::size_t bit_reverse(std::size_t value, std::size_t n)
{
    std::size_t reversed = 0;
    for (std::size_t bits = n; bits > 1; bits >>= 1U) {
        reversed = (reversed << 1U) | (value & 1U);
        value >>= 1U;
    }
    return reversed;
}

std::vector<Batch> stage_batches(std::size_t n, std::size_t stage)
{
    const std::size_t m = std::size_t{1} << stage;
    std::vector<Batch> batches;
    if (m < kRegisterCount) {
        for (std::size_t base = 0; base < n; base += kRegisterCount) {
            batches.push_back({false, base, base + kLaneCount});
        }
    } else {
        for (std::size_t group = 0; group < n; group += 2 * m) {
            for (std::size_t offset = 0; offset < m; offset += kLaneCount) {
                batches.push_back({true, group + offset, group + m + offset});
            }
        }
    }
    return batches;
}

template <typename T>
std::pair<std::array<T, kRegisterCount>,
          std::array<std::size_t, kRegisterCount>>
load_batch(const std::vector<T>& values, const Batch& batch)
{
    std::array<T, kRegisterCount> registers {};
    std::array<std::size_t, kRegisterCount> positions {};
    if (!batch.interleaved) {
        for (std::size_t i = 0; i < kRegisterCount; ++i) {
            positions[i] = batch.first + i;
            registers[i] = values[positions[i]];
        }
    } else {
        for (std::size_t i = 0; i < kLaneCount; ++i) {
            positions[2 * i] = batch.first + i;
            positions[2 * i + 1] = batch.second + i;
            registers[2 * i] = values[positions[2 * i]];
            registers[2 * i + 1] = values[positions[2 * i + 1]];
        }
    }
    return {registers, positions};
}

template <typename T>
void store_batch(std::vector<T>& values,
                 const std::array<T, kRegisterCount>& registers,
                 const std::array<std::size_t, kRegisterCount>& positions)
{
    for (std::size_t i = 0; i < kRegisterCount; ++i) {
        values[positions[i]] = registers[i];
    }
}

template <typename T>
std::array<T, kRegisterCount> apply_p(
    std::array<T, kRegisterCount> registers, std::size_t count = 1)
{
    for (std::size_t rotation = 0; rotation < count % 7; ++rotation) {
        std::array<T, kRegisterCount> shifted {};
        for (std::size_t old_position = 0;
             old_position < kRegisterCount; ++old_position) {
            const std::size_t new_position =
                (old_position >> 1U) | ((old_position & 1U) << 6U);
            shifted[new_position] = registers[old_position];
        }
        registers = shifted;
    }
    return registers;
}

void forward_stage(std::vector<U64>& values,
                   const std::vector<U64>& twiddles,
                   std::size_t stage,
                   U64 modulus)
{
    std::size_t twiddle_index = 0;
    for (const Batch& batch : stage_batches(values.size(), stage)) {
        auto loaded = load_batch(values, batch);
        for (std::size_t lane = 0; lane < kLaneCount; ++lane) {
            const std::size_t even = 2 * lane;
            const std::size_t odd = even + 1;
            const U64 a = loaded.first[even];
            const U64 product = mul_mod(
                loaded.first[odd], twiddles.at(twiddle_index++), modulus);
            loaded.first[even] = add_mod(a, product, modulus);
            loaded.first[odd] = sub_mod(a, product, modulus);
        }
        loaded.first = apply_p(loaded.first);
        store_batch(values, loaded.first, loaded.second);
    }
    if (twiddle_index != values.size() / 2) {
        throw std::runtime_error("forward stage consumed the wrong twiddle count");
    }
}

void inverse_stage(std::vector<U64>& values,
                   const std::vector<U64>& twiddles,
                   std::size_t forward_stage,
                   U64 modulus)
{
    std::size_t twiddle_index = 0;
    for (const Batch& batch : stage_batches(values.size(), forward_stage)) {
        auto loaded = load_batch(values, batch);
        loaded.first = apply_p(loaded.first, 6);
        for (std::size_t lane = 0; lane < kLaneCount; ++lane) {
            const std::size_t even = 2 * lane;
            const std::size_t odd = even + 1;
            const U64 a = loaded.first[even];
            const U64 product = mul_mod(
                loaded.first[odd], twiddles.at(twiddle_index++), modulus);
            loaded.first[even] = add_mod(a, product, modulus);
            loaded.first[odd] = sub_mod(a, product, modulus);
        }
        store_batch(values, loaded.first, loaded.second);
    }
    if (twiddle_index != values.size() / 2) {
        throw std::runtime_error("inverse stage consumed the wrong twiddle count");
    }
}

ForwardSchedule make_forward_schedule(std::size_t n, U64 modulus, U64 omega)
{
    const std::size_t log_n = static_cast<std::size_t>(__builtin_ctzll(n));
    std::vector<std::size_t> labels(n);
    std::iota(labels.begin(), labels.end(), 0);
    ForwardSchedule schedule;
    for (std::size_t stage = 0; stage < log_n; ++stage) {
        const std::size_t m = std::size_t{1} << stage;
        std::vector<U64> twiddles;
        for (const Batch& batch : stage_batches(n, stage)) {
            auto loaded = load_batch(labels, batch);
            for (std::size_t lane = 0; lane < kLaneCount; ++lane) {
                const std::size_t lower = loaded.first[2 * lane];
                const std::size_t upper = loaded.first[2 * lane + 1];
                if (upper != lower + m) {
                    throw std::runtime_error("bad forward lane pairing");
                }
                const U64 exponent = static_cast<U64>(
                    (lower % m) * n / (2 * m));
                twiddles.push_back(pow_mod(omega, exponent, modulus));
            }
            loaded.first = apply_p(loaded.first);
            store_batch(labels, loaded.first, loaded.second);
        }
        schedule.twiddles.push_back(std::move(twiddles));
        schedule.stage_layouts.push_back(labels);
    }
    schedule.final_layout = std::move(labels);
    return schedule;
}

InverseSchedule make_inverse_schedule(
    std::size_t n, U64 modulus, U64 omega,
    const std::vector<std::size_t>& forward_layout)
{
    const std::size_t log_n = static_cast<std::size_t>(__builtin_ctzll(n));
    std::vector<std::size_t> labels = forward_layout;
    std::vector<U64> scales(n, 1);
    InverseSchedule schedule;
    for (std::size_t inverse = 0; inverse < log_n; ++inverse) {
        const std::size_t forward = log_n - 1 - inverse;
        const std::size_t m = std::size_t{1} << forward;
        std::vector<U64> twiddles;
        std::size_t batch_index = 0;
        for (const Batch& batch : stage_batches(n, forward)) {
            auto loaded_labels = load_batch(labels, batch);
            auto loaded_scales = load_batch(scales, batch);
            loaded_labels.first = apply_p(loaded_labels.first, 6);
            loaded_scales.first = apply_p(loaded_scales.first, 6);
            for (std::size_t lane = 0; lane < kLaneCount; ++lane) {
                const std::size_t even = 2 * lane;
                const std::size_t odd = even + 1;
                const std::size_t lower = loaded_labels.first[even];
                const std::size_t upper = loaded_labels.first[odd];
                if (upper != lower + m) {
                    throw std::runtime_error("bad inverse lane pairing");
                }
                const U64 alpha = loaded_scales.first[even];
                const U64 beta = loaded_scales.first[odd];
                const U64 exponent = static_cast<U64>(
                    (lower % m) * n / (2 * m));
                const U64 w_forward = pow_mod(omega, exponent, modulus);
                const U64 w_bf = mul_mod(
                    alpha, inverse_mod_prime(beta, modulus), modulus);
                twiddles.push_back(w_bf);
                schedule.lanes.push_back(
                    {inverse, forward, m, batch_index, lane, lower, upper,
                     w_forward, inverse_mod_prime(w_forward, modulus), w_bf,
                     alpha, beta});
                loaded_scales.first[even] = alpha;
                loaded_scales.first[odd] = mul_mod(
                    alpha, w_forward, modulus);
            }
            store_batch(labels, loaded_labels.first, loaded_labels.second);
            store_batch(scales, loaded_scales.first, loaded_scales.second);
            ++batch_index;
        }
        schedule.twiddles.push_back(std::move(twiddles));
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (labels[i] != i || scales[i] != 1) {
            throw std::runtime_error("inverse schedule did not restore layout/scale");
        }
    }
    return schedule;
}

template <typename T>
void require_equal(const std::vector<T>& actual,
                   const std::vector<T>& expected,
                   const std::string& label)
{
    if (actual.size() != expected.size()) {
        throw std::runtime_error(label + " size mismatch");
    }
    for (std::size_t i = 0; i < actual.size(); ++i) {
        if (actual[i] != expected[i]) {
            throw std::runtime_error(
                label + " mismatch at index " + std::to_string(i)
                + ": actual=" + std::to_string(actual[i])
                + ", expected=" + std::to_string(expected[i]));
        }
    }
}

std::vector<U64> first_half(const std::vector<U64>& values)
{
    return {values.begin(), values.begin()
        + static_cast<std::ptrdiff_t>(values.size() / 2)};
}

void test_rtl_stage_fixtures(const std::filesystem::path& root)
{
    constexpr U64 modulus = 0xFFFFFFFEULL;
    const auto pntt_root = root / "rtl_pntt";
    std::vector<U64> pntt = read_column(pntt_root / "obj0_poly.csv", "value");
    const std::vector<U64> pntt_twiddle = first_half(
        read_column(pntt_root / "obj1_twiddle.csv", "value"));
    forward_stage(pntt, pntt_twiddle, 0, modulus);
    require_equal(
        pntt,
        read_column(pntt_root / "obj2_output_exp_vs_rtl.csv", "rtl_act"),
        "RTL PNTT stage 0");

    const auto pintt_root = root / "rtl_pintt";
    std::vector<U64> pintt0 = read_column(
        pintt_root / "obj0_polyA.csv", "value");
    inverse_stage(pintt0, std::vector<U64>(pintt0.size() / 2, 1), 8, modulus);
    require_equal(
        pintt0,
        read_column(
            pintt_root / "obj2_stage0_output_exp_vs_rtl.csv", "rtl_act"),
        "RTL PINTT stage 0");

    std::vector<U64> pintt1 = read_column(
        pintt_root / "obj1_polyB.csv", "value");
    const std::vector<U64> pintt_twiddle = first_half(
        read_column(pintt_root / "obj4_twiddle.csv", "value"));
    inverse_stage(pintt1, pintt_twiddle, 7, modulus);
    require_equal(
        pintt1,
        read_column(
            pintt_root / "obj3_stage1_output_exp_vs_rtl.csv", "rtl_act"),
        "RTL PINTT stage 1");
}

void test_full_model_fixture(const std::filesystem::path& root)
{
    constexpr std::size_t n = 512;
    constexpr U64 modulus = 1073750017ULL;
    constexpr U64 omega = 387049130ULL;
    const auto full_root = root / "full_n512";
    const ForwardSchedule forward = make_forward_schedule(n, modulus, omega);
    std::vector<U64> values = read_column(
        full_root / "input_poly.csv", "value");
    for (std::size_t stage = 0; stage < forward.twiddles.size(); ++stage) {
        forward_stage(values, forward.twiddles[stage], stage, modulus);
        const auto stage_path = full_root /
            ("stage" + std::to_string(stage) + "_mem_after.csv");
        require_equal(values, read_column(stage_path, "value"),
                      "full PNTT stage " + std::to_string(stage));
        require_equal(
            forward.stage_layouts[stage],
            [&stage_path]() {
                const std::vector<U64> raw = read_column(
                    stage_path, "logical_label");
                return std::vector<std::size_t>(raw.begin(), raw.end());
            }(),
            "full PNTT layout stage " + std::to_string(stage));
    }
    require_equal(
        values, read_column(full_root / "output_physical.csv", "value"),
        "full PNTT physical output");
    std::vector<U64> logical(n);
    for (std::size_t position = 0; position < n; ++position) {
        logical[forward.final_layout[position]] = values[position];
    }
    require_equal(
        logical, read_column(full_root / "output_logical.csv", "value"),
        "full PNTT logical output");

    const InverseSchedule inverse = make_inverse_schedule(
        n, modulus, omega, forward.final_layout);
    const std::vector<Row> rows = read_csv(
        full_root / "intt_bf_twiddles.csv");
    if (rows.size() != inverse.lanes.size()) {
        throw std::runtime_error("INTT twiddle fixture row count mismatch");
    }
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const InverseLane& lane = inverse.lanes[i];
        const std::array<std::pair<const char*, U64>, 12> expected{{
            {"stage_k", lane.stage}, {"fwd_stage_s", lane.forward_stage},
            {"m", lane.m}, {"batch_idx", lane.batch}, {"lane", lane.lane},
            {"lower_logical", lane.lower}, {"upper_logical", lane.upper},
            {"w_forward", lane.w_forward}, {"w_dif_inverse", lane.w_inverse},
            {"w_bf_actual", lane.w_bf}, {"scale_even_in", lane.alpha},
            {"scale_odd_in", lane.beta}}};
        for (const auto& field : expected) {
            if (parse_u64(rows[i], field.first) != field.second) {
                throw std::runtime_error(
                    "INTT twiddle fixture mismatch at row "
                    + std::to_string(i) + ", field " + field.first);
            }
        }
    }

    for (std::size_t stage = 0; stage < inverse.twiddles.size(); ++stage) {
        inverse_stage(
            values, inverse.twiddles[stage],
            inverse.twiddles.size() - 1 - stage, modulus);
    }
    const U64 n_inverse = inverse_mod_prime(n, modulus);
    for (U64& value : values) {
        value = mul_mod(value, n_inverse, modulus);
    }
    require_equal(
        values, read_column(full_root / "input_poly.csv", "value"),
        "full PNTT/PINTT round trip");
}

U64 find_primitive_2n_root(std::size_t n, U64 modulus)
{
    const U64 exponent = (modulus - 1) / (2 * n);
    for (U64 candidate = 2; candidate < modulus; ++candidate) {
        const U64 psi = pow_mod(candidate, exponent, modulus);
        if (pow_mod(psi, n, modulus) == modulus - 1) {
            return psi;
        }
    }
    throw std::runtime_error("failed to find primitive 2N-th root");
}

std::vector<U64> schoolbook_negacyclic(
    const std::vector<U64>& left,
    const std::vector<U64>& right,
    U64 modulus)
{
    const std::size_t n = left.size();
    std::vector<U64> result(n, 0);
    for (std::size_t i = 0; i < n; ++i) {
        for (std::size_t j = 0; j < n; ++j) {
            const U64 product = mul_mod(left[i], right[j], modulus);
            if (i + j < n) {
                result[i + j] = add_mod(result[i + j], product, modulus);
            } else {
                result[i + j - n] = sub_mod(
                    result[i + j - n], product, modulus);
            }
        }
    }
    return result;
}

void test_fhe_negacyclic_semantics()
{
    constexpr std::size_t n = 512;
    constexpr U64 modulus = 1073750017ULL;
    const U64 psi = find_primitive_2n_root(n, modulus);
    const U64 omega = mul_mod(psi, psi, modulus);
    const ForwardSchedule forward = make_forward_schedule(n, modulus, omega);
    const InverseSchedule inverse = make_inverse_schedule(
        n, modulus, omega, forward.final_layout);

    std::vector<U64> left(n);
    std::vector<U64> right(n);
    std::vector<U64> left_physical(n);
    std::vector<U64> right_physical(n);
    for (std::size_t i = 0; i < n; ++i) {
        left[i] = (17 * i * i + 31 * i + 7) % modulus;
        right[i] = (29 * i * i + 11 * i + 5) % modulus;
    }
    for (std::size_t position = 0; position < n; ++position) {
        const std::size_t logical = bit_reverse(position, n);
        const U64 twist = pow_mod(psi, logical, modulus);
        left_physical[position] = mul_mod(left[logical], twist, modulus);
        right_physical[position] = mul_mod(right[logical], twist, modulus);
    }
    for (std::size_t stage = 0; stage < forward.twiddles.size(); ++stage) {
        forward_stage(left_physical, forward.twiddles[stage], stage, modulus);
        forward_stage(right_physical, forward.twiddles[stage], stage, modulus);
    }
    std::vector<U64> product(n);
    for (std::size_t i = 0; i < n; ++i) {
        product[i] = mul_mod(left_physical[i], right_physical[i], modulus);
    }
    for (std::size_t stage = 0; stage < inverse.twiddles.size(); ++stage) {
        inverse_stage(
            product, inverse.twiddles[stage],
            inverse.twiddles.size() - 1 - stage, modulus);
    }
    const U64 n_inverse = inverse_mod_prime(n, modulus);
    const U64 psi_inverse = inverse_mod_prime(psi, modulus);
    for (std::size_t position = 0; position < n; ++position) {
        const std::size_t logical = bit_reverse(position, n);
        product[position] = mul_mod(
            product[position],
            mul_mod(
                n_inverse, pow_mod(psi_inverse, logical, modulus), modulus),
            modulus);
    }
    const std::vector<U64> expected = schoolbook_negacyclic(
        left, right, modulus);
    for (std::size_t position = 0; position < n; ++position) {
        const std::size_t logical = bit_reverse(position, n);
        if (product[position] != expected[logical]) {
            throw std::runtime_error(
                "negacyclic convolution mismatch at physical position "
                + std::to_string(position));
        }
    }
}

} // namespace

int main()
{
    try {
        const std::filesystem::path fixture_root = HPU_NTT_FIXTURE_DIR;
        test_rtl_stage_fixtures(fixture_root);
        test_full_model_fixture(fixture_root);
        test_fhe_negacyclic_semantics();
        std::cout
            << "HPU NTT hardware model: RTL stages, full N=512 schedule, "
               "and FHE negacyclic convolution PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HPU NTT hardware model test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
