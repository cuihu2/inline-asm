#include "hpu/delivery/application_package.hpp"

#include "assembler.hpp"
#include "executable.hpp"
#include "hpu/delivery/checksum.hpp"
#include "hpu/delivery/io.hpp"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>

#include <sys/stat.h>
#include <unistd.h>

namespace hpu::delivery {
namespace {

constexpr std::size_t kLineWords = hpu::runtime::kHpuMemLineWords;
constexpr std::size_t kLineBytes = kLineWords * sizeof(std::uint32_t);
constexpr const char* kFilesManifestPath = "provenance/files.csv";

struct FileArtifact {
    std::string path;
    std::string role;
    std::string bytes;
};

struct ManifestEntry {
    std::string path;
    std::string role;
    std::uint64_t bytes = 0;
    std::uint64_t fnv1a64 = 0;
};

std::string context_case(const ApplicationPackageRequest& request)
{
    return "application package case '"
        + (request.case_name.empty() ? std::string("<empty>") : request.case_name)
        + "'";
}

std::string output_context(
    const ApplicationPackageRequest& request,
    const VerifiedOutputLimb& output)
{
    return context_case(request) + " output object '" + output.object_id
        + "' component " + std::to_string(output.component) + " MOD_ID "
        + std::to_string(static_cast<unsigned>(output.modulus_id));
}

bool same_span(
    const hpu::runtime::HpuMemSpan& left,
    const hpu::runtime::HpuMemSpan& right) noexcept
{
    return left.line_offset == right.line_offset
        && left.line_count == right.line_count;
}

bool span_within(
    const hpu::runtime::HpuMemSpan& span,
    std::uint64_t line_limit) noexcept
{
    return span.line_count != 0
        && span.line_offset < line_limit
        && span.line_count <= line_limit - span.line_offset;
}

bool spans_overlap(
    const hpu::runtime::HpuMemSpan& left,
    const hpu::runtime::HpuMemSpan& right) noexcept
{
    return left.line_offset < right.line_offset + right.line_count
        && right.line_offset < left.line_offset + left.line_count;
}

void validate_identifier(
    const std::string& value,
    const std::string& field,
    bool path_component)
{
    if (value.empty()) {
        throw std::invalid_argument(field + " must not be empty");
    }
    for (const unsigned char byte : value) {
        if (byte == 0 || byte == ',' || byte == '"'
            || byte == '\r' || byte == '\n') {
            throw std::invalid_argument(
                field + " contains a forbidden comma, quote, NUL, CR, or LF");
        }
        if (path_component && (byte == '/' || byte == '\\')) {
            throw std::invalid_argument(
                field + " contains a forbidden path separator");
        }
    }
    if (path_component && (value == "." || value == "..")) {
        throw std::invalid_argument(
            field + " must not be '.' or '..'");
    }
}

std::string scheme_name(SchemeKind scheme)
{
    switch (scheme) {
    case SchemeKind::ckks:
        return "ckks";
    case SchemeKind::bfv:
        return "bfv";
    case SchemeKind::bgv:
        return "bgv";
    }
    throw std::invalid_argument("unknown application package scheme");
}

std::string allocation_kind_name(hpu::runtime::AllocationKind kind)
{
    switch (kind) {
    case hpu::runtime::AllocationKind::modulus_table:
        return "modulus_table";
    case hpu::runtime::AllocationKind::constant:
        return "constant";
    case hpu::runtime::AllocationKind::ciphertext:
        return "ciphertext";
    case hpu::runtime::AllocationKind::plaintext:
        return "plaintext";
    case hpu::runtime::AllocationKind::evaluation_key:
        return "evaluation_key";
    case hpu::runtime::AllocationKind::twiddle:
        return "twiddle";
    case hpu::runtime::AllocationKind::workspace:
        return "workspace";
    case hpu::runtime::AllocationKind::output:
        return "output";
    }
    throw std::invalid_argument("unknown HPU_MEM allocation kind");
}

std::string output_domain_name(OutputDomain domain)
{
    switch (domain) {
    case OutputDomain::coefficient:
        return "coefficient";
    case OutputDomain::canonical_ntt_physical:
        return "canonical_ntt_physical";
    }
    throw std::invalid_argument("unknown golden output domain");
}

std::string json_escape(const std::string& value)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    for (const unsigned char byte : value) {
        switch (byte) {
        case '"':
            output << "\\\"";
            break;
        case '\\':
            output << "\\\\";
            break;
        case '\b':
            output << "\\b";
            break;
        case '\f':
            output << "\\f";
            break;
        case '\n':
            output << "\\n";
            break;
        case '\r':
            output << "\\r";
            break;
        case '\t':
            output << "\\t";
            break;
        default:
            if (byte < 0x20U) {
                output << "\\u" << std::hex << std::setw(4)
                       << std::setfill('0') << static_cast<unsigned>(byte)
                       << std::dec;
            } else {
                output << static_cast<char>(byte);
            }
        }
    }
    return output.str();
}

std::string hex64(std::uint64_t value)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
    return output.str();
}

std::uint64_t hash_bytes(const std::string& bytes)
{
    return fnv1a64_bytes(std::vector<std::uint8_t>(bytes.begin(), bytes.end()));
}

bool path_bytes_less(const std::string& left, const std::string& right)
{
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end(),
        [](char left_byte, char right_byte) {
            return static_cast<unsigned char>(left_byte)
                < static_cast<unsigned char>(right_byte);
        });
}

std::string render_bits(std::uint32_t value, unsigned width)
{
    std::string bits;
    bits.reserve(width + 1U);
    for (unsigned bit = width; bit != 0; --bit) {
        bits.push_back(((value >> (bit - 1U)) & 1U) != 0U ? '1' : '0');
    }
    bits.push_back('\n');
    return bits;
}

std::string render_program_words(
    const std::vector<hpu::EncodedInstruction>& instructions,
    bool commands)
{
    std::string output;
    for (const auto& instruction : instructions) {
        output += render_bits(
            commands ? instruction.command26 : instruction.word,
            commands ? 26U : 32U);
    }
    return output;
}

std::pair<std::vector<std::uint32_t>, std::vector<std::uint32_t>>
allocation_words(
    const hpu::runtime::HpuMemImage& image,
    const hpu::runtime::HpuMemAllocation& allocation)
{
    const std::size_t begin = static_cast<std::size_t>(
        allocation.span.line_offset) * kLineWords;
    const std::size_t padded_count = static_cast<std::size_t>(
        allocation.span.line_count) * kLineWords;
    const auto first = image.words().begin()
        + static_cast<std::vector<std::uint32_t>::difference_type>(begin);
    std::vector<std::uint32_t> padded(
        first,
        first + static_cast<std::vector<std::uint32_t>::difference_type>(
                    padded_count));
    std::vector<std::uint32_t> payload(
        padded.begin(),
        padded.begin()
            + static_cast<std::vector<std::uint32_t>::difference_type>(
                allocation.word_count));
    return {std::move(payload), std::move(padded)};
}

std::string initialization_name(
    const hpu::runtime::HpuMemAllocation& allocation,
    const std::vector<std::uint32_t>& payload)
{
    const bool zero = std::all_of(
        payload.begin(), payload.end(),
        [](std::uint32_t word) { return word == 0; });
    if (zero
        && (allocation.kind == hpu::runtime::AllocationKind::output
            || allocation.kind == hpu::runtime::AllocationKind::workspace)) {
        return "zero_reserved";
    }
    return "payload";
}

std::string render_package_json(const ApplicationPackageRequest& request)
{
    const std::string stem = request.program.stem;
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "{\n"
           << "  \"schema\": \"hpu-application-package\",\n"
           << "  \"schema_version\": 1,\n"
           << "  \"scheme\": \"" << scheme_name(request.scheme) << "\",\n"
           << "  \"case_name\": \"" << json_escape(request.case_name) << "\",\n"
           << "  \"word_bits\": 32,\n"
           << "  \"line_words\": 64,\n"
           << "  \"line_bytes\": 256,\n"
           << "  \"byte_order\": \"little-endian\",\n"
           << "  \"parameters\": \"metadata/parameters.json\",\n"
           << "  \"operation_graph\": \"metadata/operation_graph.json\",\n"
           << "  \"program_source\": \"program/" << stem << ".c\",\n"
           << "  \"program_header\": \"program/" << stem << ".h\",\n"
           << "  \"program_asm\": \"program/" << stem << ".asm\",\n"
           << "  \"program_inst32\": \"program/" << stem << ".inst32\",\n"
           << "  \"program_cmd26\": \"program/" << stem << ".cmd26\",\n"
           << "  \"dma_relocation_manifest\": "
              "\"program/dma_relocation_manifest.csv\",\n"
           << "  \"image\": \"memory/hpu_mem_image.u32.bin\",\n"
           << "  \"line_map\": \"memory/line_map.csv\",\n"
           << "  \"memory_manifest\": \"memory/memory_manifest.csv\",\n"
           << "  \"memory_abi\": \"memory/abi.json\",\n"
           << "  \"memory_config\": \"memory/hpu_mem_config.json\",\n"
           << "  \"golden_manifest\": \"golden/golden_manifest.csv\",\n"
           << "  \"oracle_report\": \"oracle/report.json\"";
    if (request.semantic_report) {
        output << ",\n  \"semantic_report\": \"semantic/decoded.json\",\n"
               << "  \"semantic_media_type\": \""
               << json_escape(request.semantic_report->media_type) << "\"";
    }
    output << "\n}\n";
    return output.str();
}

std::string render_build_json(const ApplicationPackageRequest& request)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "{\n"
           << "  \"schema\": \"hpu-application-package-build\",\n"
           << "  \"schema_version\": 1,\n"
           << "  \"repository\": \"" << json_escape(request.producer.repository)
           << "\",\n"
           << "  \"commit\": \"" << json_escape(request.producer.commit)
           << "\",\n"
           << "  \"worktree_state\": \""
           << json_escape(request.producer.worktree_state) << "\"\n"
           << "}\n";
    return output.str();
}

std::string render_abi_json()
{
    return
        "{\n"
        "  \"schema\": \"hpu-dma-abi\",\n"
        "  \"schema_version\": 1,\n"
        "  \"rs1\": \"x10\",\n"
        "  \"rs2\": \"x11\",\n"
        "  \"word_bits\": 32,\n"
        "  \"line_words\": 64,\n"
        "  \"line_bytes\": 256,\n"
        "  \"byte_order\": \"little-endian\"\n"
        "}\n";
}

std::string render_memory_config_json(
    const hpu::runtime::HpuMemImage& image)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "{\n"
           << "  \"capacity_lines\": " << image.capacity_lines() << ",\n"
           << "  \"used_lines\": " << image.used_lines() << "\n"
           << "}\n";
    return output.str();
}

std::string render_line_map(const hpu::runtime::HpuMemImage& image)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "allocation_id,kind,read_only,line_offset,line_count,payload_words,"
              "padded_words,initialization\n";
    for (const auto& allocation : image.allocations()) {
        const auto words = allocation_words(image, allocation);
        output << allocation.id << ',' << allocation_kind_name(allocation.kind)
               << ',' << (allocation.read_only ? "true" : "false") << ','
               << allocation.span.line_offset << ',' << allocation.span.line_count
               << ',' << allocation.word_count << ','
               << allocation.span.line_count * kLineWords << ','
               << initialization_name(allocation, words.first) << '\n';
    }
    return output.str();
}

std::string render_memory_manifest(const hpu::runtime::HpuMemImage& image)
{
    std::ostringstream output;
    output.imbue(std::locale::classic());
    output << "allocation_id,kind,read_only,line_offset,line_count,payload_words,"
              "padded_words,initialization,payload_fnv1a64,padded_fnv1a64\n";
    for (const auto& allocation : image.allocations()) {
        const auto words = allocation_words(image, allocation);
        output << allocation.id << ',' << allocation_kind_name(allocation.kind)
               << ',' << (allocation.read_only ? "true" : "false") << ','
               << allocation.span.line_offset << ',' << allocation.span.line_count
               << ',' << allocation.word_count << ','
               << allocation.span.line_count * kLineWords << ','
               << initialization_name(allocation, words.first) << ','
               << hex64(fnv1a64_words32_le(words.first)) << ','
               << hex64(fnv1a64_words32_le(words.second)) << '\n';
    }
    return output.str();
}

std::string golden_relative_path(const VerifiedOutputLimb& output)
{
    return "golden/objects/" + output.object_id + "/c"
        + std::to_string(output.component) + "/mod"
        + std::to_string(static_cast<unsigned>(output.modulus_id))
        + ".u32.bin";
}

std::vector<std::uint32_t> padded_golden_words(
    const VerifiedOutputLimb& output)
{
    std::vector<std::uint32_t> padded(
        static_cast<std::size_t>(output.destination.line_count) * kLineWords,
        0);
    std::copy(
        output.golden_words.begin(), output.golden_words.end(), padded.begin());
    return padded;
}

std::string render_golden_manifest(
    const std::vector<VerifiedOutputLimb>& outputs)
{
    std::ostringstream manifest;
    manifest.imbue(std::locale::classic());
    manifest << "object_id,component,modulus_id,modulus,domain,path,line_offset,"
                "line_count,payload_words,padded_words,payload_fnv1a64,"
                "padded_fnv1a64\n";
    for (const auto& output : outputs) {
        const auto padded = padded_golden_words(output);
        manifest << output.object_id << ',' << output.component << ','
                 << static_cast<unsigned>(output.modulus_id) << ','
                 << output.modulus << ',' << output_domain_name(output.domain)
                 << ',' << golden_relative_path(output) << ','
                 << output.destination.line_offset << ','
                 << output.destination.line_count << ',' << output.word_count
                 << ',' << padded.size() << ','
                 << hex64(fnv1a64_words32_le(output.golden_words)) << ','
                 << hex64(fnv1a64_words32_le(padded)) << '\n';
    }
    return manifest.str();
}

std::string role_for_path(const std::string& path)
{
    if (path == "package.json") {
        return "package_descriptor";
    }
    const std::size_t slash = path.find('/');
    return slash == std::string::npos ? "artifact" : path.substr(0, slash);
}

std::string render_files_manifest(const std::vector<FileArtifact>& files)
{
    std::ostringstream manifest;
    manifest.imbue(std::locale::classic());
    manifest << "path,role,bytes,fnv1a64\n";
    for (const auto& file : files) {
        manifest << file.path << ',' << file.role << ',' << file.bytes.size()
                 << ',' << hex64(hash_bytes(file.bytes)) << '\n';
    }
    return manifest.str();
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error(
            "application package path '" + path.string()
            + "' could not be opened");
    }
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

std::vector<std::string> split_csv_row(
    const std::string& line,
    const std::filesystem::path& manifest_path,
    std::size_t expected_fields)
{
    std::vector<std::string> fields;
    std::size_t begin = 0;
    for (;;) {
        const std::size_t comma = line.find(',', begin);
        fields.push_back(line.substr(begin, comma - begin));
        if (comma == std::string::npos) {
            break;
        }
        begin = comma + 1;
    }
    if (fields.size() != expected_fields) {
        throw std::runtime_error(
            "application package manifest '" + manifest_path.string()
            + "' row must have exactly " + std::to_string(expected_fields)
            + " unquoted fields");
    }
    return fields;
}

std::uint64_t parse_u64(
    const std::string& text,
    int base,
    const std::filesystem::path& path,
    const char* field)
{
    if (text.empty() || text.front() == '-' || text.front() == '+') {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has invalid " + field + " field '" + text + "'");
    }
    std::size_t consumed = 0;
    unsigned long long value = 0;
    try {
        value = std::stoull(text, &consumed, base);
    } catch (const std::exception&) {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has invalid " + field + " field '" + text + "'");
    }
    if (consumed != text.size()) {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has invalid " + field + " field '" + text + "'");
    }
    if (value > std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has overflowing " + field + " field '" + text + "'");
    }
    return static_cast<std::uint64_t>(value);
}

std::uint64_t parse_decimal_u64(
    const std::string& text,
    const std::filesystem::path& path,
    const char* field)
{
    if (text.empty()
        || !std::all_of(
            text.begin(), text.end(),
            [](unsigned char byte) { return std::isdigit(byte) != 0; })) {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has invalid " + field + " field '" + text + "'");
    }
    const std::uint64_t value = parse_u64(text, 10, path, field);
    if (text != std::to_string(value)) {
        throw std::runtime_error(
            "application package manifest '" + path.string() + "' " + field
            + " field must use canonical unsigned decimal form, got '"
            + text + "'");
    }
    return value;
}

std::uint64_t parse_fnv1a64(
    const std::string& text,
    const std::filesystem::path& path,
    const char* field)
{
    if (text.size() != 18U || text[0] != '0' || text[1] != 'x'
        || !std::all_of(
            text.begin() + 2, text.end(), [](unsigned char byte) {
                return std::isdigit(byte) != 0
                    || (byte >= static_cast<unsigned char>('a')
                        && byte <= static_cast<unsigned char>('f'));
            })) {
        throw std::runtime_error(
            "application package manifest '" + path.string() + "' " + field
            + " field must be 0x followed by 16 lowercase hexadecimal digits, got '"
            + text + "'");
    }
    return parse_u64(text, 16, path, field);
}

enum class JsonKind { object, array, string, number, literal };

struct JsonValue {
    JsonKind kind;
    std::string text;
};

// A strict JSON syntax reader for the flat v1 descriptor. Unknown fields can
// contain nested JSON and are parsed, but only top-level fields are returned.
class JsonReader {
public:
    JsonReader(const std::string& data, const std::filesystem::path& path)
        : data_(data), path_(path)
    {}

    std::map<std::string, JsonValue> read_document()
    {
        skip_space();
        if (position_ >= data_.size() || data_[position_] != '{') {
            fail("top-level value must be an object");
        }
        std::map<std::string, JsonValue> fields;
        parse_object(&fields, 0);
        skip_space();
        if (position_ != data_.size()) {
            fail("trailing bytes after top-level object");
        }
        return fields;
    }

private:
    [[noreturn]] void fail(const std::string& reason) const
    {
        throw std::runtime_error(
            "application package JSON '" + path_.string() + "' at byte "
            + std::to_string(position_) + ": " + reason);
    }

    void skip_space()
    {
        while (position_ < data_.size()
            && (data_[position_] == ' ' || data_[position_] == '\n'
                || data_[position_] == '\t' || data_[position_] == '\r')) {
            ++position_;
        }
    }

    bool take(char expected)
    {
        skip_space();
        if (position_ < data_.size() && data_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void expect(char expected)
    {
        if (!take(expected)) {
            fail(std::string("expected '") + expected + "'");
        }
    }

    unsigned hex_quad()
    {
        unsigned value = 0;
        for (unsigned i = 0; i < 4; ++i) {
            if (position_ >= data_.size()) fail("incomplete Unicode escape");
            const char digit = data_[position_++];
            unsigned n = 0;
            if (digit >= '0' && digit <= '9') n = digit - '0';
            else if (digit >= 'a' && digit <= 'f') n = digit - 'a' + 10;
            else if (digit >= 'A' && digit <= 'F') n = digit - 'A' + 10;
            else fail("invalid Unicode escape");
            value = (value << 4U) | n;
        }
        return value;
    }

    static void append_utf8(std::string& result, unsigned codepoint)
    {
        if (codepoint <= 0x7f) result.push_back(static_cast<char>(codepoint));
        else if (codepoint <= 0x7ff) {
            result.push_back(static_cast<char>(0xc0 | (codepoint >> 6U)));
            result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else if (codepoint <= 0xffff) {
            result.push_back(static_cast<char>(0xe0 | (codepoint >> 12U)));
            result.push_back(static_cast<char>(0x80 | ((codepoint >> 6U) & 0x3f)));
            result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        } else {
            result.push_back(static_cast<char>(0xf0 | (codepoint >> 18U)));
            result.push_back(static_cast<char>(0x80 | ((codepoint >> 12U) & 0x3f)));
            result.push_back(static_cast<char>(0x80 | ((codepoint >> 6U) & 0x3f)));
            result.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
        }
    }

    std::string parse_string()
    {
        if (position_ >= data_.size() || data_[position_++] != '"') {
            fail("expected a quoted string");
        }
        std::string result;
        while (position_ < data_.size()) {
            const unsigned char ch =
                static_cast<unsigned char>(data_[position_++]);
            if (ch == '"') return result;
            if (ch < 0x20) fail("unescaped control character in string");
            if (ch != '\\') {
                if (ch >= 0x80U) {
                    unsigned continuations = 0;
                    unsigned codepoint = 0;
                    unsigned minimum = 0;
                    if (ch >= 0xc2U && ch <= 0xdfU) {
                        continuations = 1; codepoint = ch & 0x1fU;
                        minimum = 0x80U;
                    } else if (ch >= 0xe0U && ch <= 0xefU) {
                        continuations = 2; codepoint = ch & 0x0fU;
                        minimum = 0x800U;
                    } else if (ch >= 0xf0U && ch <= 0xf4U) {
                        continuations = 3; codepoint = ch & 0x07U;
                        minimum = 0x10000U;
                    } else {
                        fail("invalid UTF-8 leading byte in string");
                    }
                    result.push_back(static_cast<char>(ch));
                    for (unsigned index = 0; index < continuations; ++index) {
                        if (position_ >= data_.size()) {
                            fail("incomplete UTF-8 sequence in string");
                        }
                        const unsigned char next =
                            static_cast<unsigned char>(data_[position_++]);
                        if ((next & 0xc0U) != 0x80U) {
                            fail("invalid UTF-8 continuation byte in string");
                        }
                        codepoint = (codepoint << 6U) | (next & 0x3fU);
                        result.push_back(static_cast<char>(next));
                    }
                    if (codepoint < minimum
                        || (codepoint >= 0xd800U && codepoint <= 0xdfffU)
                        || codepoint > 0x10ffffU) {
                        fail("invalid UTF-8 codepoint in string");
                    }
                    continue;
                }
                result.push_back(static_cast<char>(ch));
                continue;
            }
            if (position_ >= data_.size()) fail("incomplete string escape");
            const char escaped = data_[position_++];
            switch (escaped) {
            case '"': case '\\': case '/': result.push_back(escaped); break;
            case 'b': result.push_back('\b'); break;
            case 'f': result.push_back('\f'); break;
            case 'n': result.push_back('\n'); break;
            case 'r': result.push_back('\r'); break;
            case 't': result.push_back('\t'); break;
            case 'u': {
                unsigned codepoint = hex_quad();
                if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
                    if (position_ + 2 > data_.size()
                        || data_[position_] != '\\'
                        || data_[position_ + 1] != 'u') {
                        fail("high surrogate without a low surrogate");
                    }
                    position_ += 2;
                    const unsigned low = hex_quad();
                    if (low < 0xdc00 || low > 0xdfff) {
                        fail("invalid low surrogate");
                    }
                    codepoint = 0x10000U + ((codepoint - 0xd800U) << 10U)
                        + (low - 0xdc00U);
                } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
                    fail("unpaired low surrogate");
                }
                append_utf8(result, codepoint);
                break;
            }
            default: fail("invalid string escape");
            }
        }
        fail("unterminated JSON string");
    }

    JsonValue parse_value(unsigned depth)
    {
        if (depth > 64) fail("JSON nesting exceeds 64 levels");
        skip_space();
        if (position_ >= data_.size()) fail("missing JSON value");
        const char first = data_[position_];
        if (first == '"') return {JsonKind::string, parse_string()};
        if (first == '{') {
            parse_object(nullptr, depth);
            return {JsonKind::object, {}};
        }
        if (first == '[') {
            ++position_;
            if (!take(']')) {
                do {
                    (void)parse_value(depth + 1);
                    if (take(']')) break;
                    expect(',');
                } while (true);
            }
            return {JsonKind::array, {}};
        }
        for (const char* literal : {"true", "false", "null"}) {
            const std::string value(literal);
            if (data_.compare(position_, value.size(), value) == 0) {
                position_ += value.size();
                return {JsonKind::literal, value};
            }
        }
        const std::size_t begin = position_;
        if (first == '-') ++position_;
        if (position_ >= data_.size()) fail("invalid JSON number");
        if (data_[position_] == '0') ++position_;
        else {
            if (data_[position_] < '1' || data_[position_] > '9') {
                fail("invalid JSON value");
            }
            do { ++position_; }
            while (position_ < data_.size()
                && data_[position_] >= '0' && data_[position_] <= '9');
        }
        if (position_ < data_.size() && data_[position_] == '.') {
            ++position_;
            if (position_ >= data_.size() || data_[position_] < '0'
                || data_[position_] > '9') fail("invalid fraction");
            do { ++position_; }
            while (position_ < data_.size()
                && data_[position_] >= '0' && data_[position_] <= '9');
        }
        if (position_ < data_.size()
            && (data_[position_] == 'e' || data_[position_] == 'E')) {
            ++position_;
            if (position_ < data_.size()
                && (data_[position_] == '+' || data_[position_] == '-')) ++position_;
            if (position_ >= data_.size() || data_[position_] < '0'
                || data_[position_] > '9') fail("invalid exponent");
            do { ++position_; }
            while (position_ < data_.size()
                && data_[position_] >= '0' && data_[position_] <= '9');
        }
        return {JsonKind::number, data_.substr(begin, position_ - begin)};
    }

    void parse_object(std::map<std::string, JsonValue>* top, unsigned depth)
    {
        expect('{');
        if (take('}')) return;
        std::set<std::string> names;
        do {
            skip_space();
            const std::string name = parse_string();
            if (!names.insert(name).second) fail("duplicate JSON key '" + name + "'");
            expect(':');
            JsonValue value = parse_value(depth + 1);
            if (top != nullptr) top->emplace(name, std::move(value));
            if (take('}')) return;
            expect(',');
        } while (true);
    }

    const std::string& data_;
    const std::filesystem::path& path_;
    std::size_t position_ = 0;
};

std::uint64_t extract_json_u64(
    const std::string& json,
    const std::string& key,
    const std::filesystem::path& path)
{
    const auto fields = JsonReader(json, path).read_document();
    const auto found = fields.find(key);
    if (found == fields.end()) {
        throw std::runtime_error(
            "application package JSON '" + path.string()
            + "' is missing integer field '" + key + "'");
    }
    if (found->second.kind != JsonKind::number) {
        throw std::runtime_error(
            "application package JSON '" + path.string()
            + "' has non-integer field '" + key + "'");
    }
    return parse_decimal_u64(found->second.text, path, key.c_str());
}

std::vector<ManifestEntry> parse_files_manifest(
    const std::filesystem::path& path)
{
    const std::string contents = read_file(path);
    std::istringstream input(contents);
    input.imbue(std::locale::classic());
    std::string line;
    if (!std::getline(input, line)
        || line != "path,role,bytes,fnv1a64") {
        throw std::runtime_error(
            "application package manifest '" + path.string()
            + "' has an invalid header");
    }

    std::vector<ManifestEntry> entries;
    std::string previous_path;
    while (std::getline(input, line)) {
        if (line.empty()) {
            throw std::runtime_error(
                "application package manifest '" + path.string()
                + "' contains an empty row");
        }
        const auto fields = split_csv_row(line, path, 4);
        validate_package_relative_path(fields[0]);
        if (fields[0] == kFilesManifestPath) {
            throw std::runtime_error(
                "application package manifest must not list itself at path '"
                + fields[0] + "'");
        }
        if (std::filesystem::path(fields[0]).lexically_normal().generic_string()
            != fields[0]) {
            throw std::runtime_error(
                "application package manifest path '" + fields[0]
                + "' is not normalized");
        }
        if (!previous_path.empty()
            && !path_bytes_less(previous_path, fields[0])) {
            throw std::runtime_error(
                "application package manifest path '" + fields[0]
                + "' is duplicated or not sorted by UTF-8 path bytes");
        }
        validate_identifier(fields[1], "files.csv role", false);
        if (fields[1] != role_for_path(fields[0])) {
            throw std::runtime_error(
                "application package manifest path '" + fields[0]
                + "' has role '" + fields[1] + "' instead of '"
                + role_for_path(fields[0]) + "'");
        }
        entries.push_back({
            fields[0], fields[1], parse_decimal_u64(fields[2], path, "bytes"),
            parse_fnv1a64(fields[3], path, "fnv1a64")});
        previous_path = fields[0];
    }
    return entries;
}

std::set<std::string> parse_golden_manifest_paths(
    const std::filesystem::path& path)
{
    const std::string contents = read_file(path);
    std::istringstream input(contents);
    input.imbue(std::locale::classic());
    std::string line;
    const std::string expected_header =
        "object_id,component,modulus_id,modulus,domain,path,line_offset,"
        "line_count,payload_words,padded_words,payload_fnv1a64,padded_fnv1a64";
    if (!std::getline(input, line) || line != expected_header) {
        throw std::runtime_error(
            "application package golden manifest '" + path.string()
            + "' has an invalid header");
    }

    std::set<std::string> paths;
    while (std::getline(input, line)) {
        if (line.empty()) {
            throw std::runtime_error(
                "application package golden manifest '" + path.string()
                + "' contains an empty row");
        }
        const auto fields = split_csv_row(line, path, 12);
        validate_identifier(fields[0], "golden object_id", true);
        const std::uint64_t component =
            parse_u64(fields[1], 10, path, "component");
        const std::uint64_t modulus_id =
            parse_u64(fields[2], 10, path, "modulus_id");
        if (fields[1] != std::to_string(component)
            || fields[2] != std::to_string(modulus_id)) {
            throw std::runtime_error(
                "application package golden manifest '" + path.string()
                + "' component and modulus_id must use canonical decimal form");
        }
        const std::string expected_path =
            "golden/objects/" + fields[0] + "/c" + fields[1] + "/mod"
            + fields[2] + ".u32.bin";
        validate_package_relative_path(fields[5]);
        if (fields[5] != expected_path) {
            throw std::runtime_error(
                "application package golden manifest path '" + fields[5]
                + "' does not match object/component/MOD_ID path '"
                + expected_path + "'");
        }
        if (!paths.insert(fields[5]).second) {
            throw std::runtime_error(
                "application package golden manifest duplicates path '"
                + fields[5] + "'");
        }
    }
    return paths;
}

struct AllocationManifestRow {
    std::string allocation_id;
    std::string kind;
    bool read_only = false;
    std::uint64_t line_offset = 0;
    std::uint64_t line_count = 0;
    std::uint64_t payload_words = 0;
    std::uint64_t padded_words = 0;
    std::string initialization;
    std::uint64_t payload_fnv1a64 = 0;
    std::uint64_t padded_fnv1a64 = 0;
};

struct GoldenManifestRow {
    std::string object_id;
    std::uint64_t component = 0;
    std::uint64_t modulus_id = 0;
    std::uint32_t modulus = 0;
    std::string domain;
    std::string path;
    std::uint64_t line_offset = 0;
    std::uint64_t line_count = 0;
    std::uint64_t payload_words = 0;
    std::uint64_t padded_words = 0;
    std::uint64_t payload_fnv1a64 = 0;
    std::uint64_t padded_fnv1a64 = 0;
};

bool valid_allocation_kind(const std::string& kind)
{
    static const std::set<std::string> kinds{
        "modulus_table", "constant", "ciphertext", "plaintext",
        "evaluation_key", "twiddle", "workspace", "output"};
    return kinds.count(kind) != 0;
}

std::uint64_t checked_padded_words(
    std::uint64_t line_count,
    const std::filesystem::path& path,
    const std::string& row_context)
{
    if (line_count == 0
        || line_count > std::numeric_limits<std::uint64_t>::max() / kLineWords) {
        throw std::runtime_error(
            "application package manifest '" + path.string() + "' "
            + row_context + " has zero or overflowing line_count");
    }
    return line_count * kLineWords;
}

std::vector<AllocationManifestRow> parse_allocation_manifest(
    const std::filesystem::path& path,
    bool include_hashes,
    const std::string& manifest_name)
{
    const std::string expected_header = include_hashes
        ? "allocation_id,kind,read_only,line_offset,line_count,payload_words,"
          "padded_words,initialization,payload_fnv1a64,padded_fnv1a64"
        : "allocation_id,kind,read_only,line_offset,line_count,payload_words,"
          "padded_words,initialization";
    std::istringstream input(read_file(path));
    input.imbue(std::locale::classic());
    std::string line;
    if (!std::getline(input, line) || line != expected_header) {
        throw std::runtime_error(
            "application package " + manifest_name + " manifest '"
            + path.string() + "' has an invalid header");
    }

    std::vector<AllocationManifestRow> rows;
    std::set<std::string> allocation_ids;
    while (std::getline(input, line)) {
        if (line.empty()) {
            throw std::runtime_error(
                "application package " + manifest_name + " manifest '"
                + path.string() + "' contains an empty row");
        }
        const auto fields = split_csv_row(line, path, include_hashes ? 10U : 8U);
        validate_identifier(fields[0], manifest_name + " allocation_id", false);
        if (!allocation_ids.insert(fields[0]).second) {
            throw std::runtime_error(
                "application package " + manifest_name
                + " has duplicate allocation_id '" + fields[0] + "'");
        }
        if (!valid_allocation_kind(fields[1])) {
            throw std::runtime_error(
                "application package " + manifest_name + " allocation '"
                + fields[0] + "' has invalid kind '" + fields[1] + "'");
        }
        bool read_only = false;
        if (fields[2] == "true") {
            read_only = true;
        } else if (fields[2] != "false") {
            throw std::runtime_error(
                "application package " + manifest_name + " allocation '"
                + fields[0] + "' has invalid read_only value '" + fields[2]
                + "'");
        }
        if (fields[7] != "payload" && fields[7] != "zero_reserved") {
            throw std::runtime_error(
                "application package " + manifest_name + " allocation '"
                + fields[0] + "' has invalid initialization '" + fields[7]
                + "'");
        }

        AllocationManifestRow row;
        row.allocation_id = fields[0];
        row.kind = fields[1];
        row.read_only = read_only;
        row.line_offset = parse_decimal_u64(fields[3], path, "line_offset");
        row.line_count = parse_decimal_u64(fields[4], path, "line_count");
        row.payload_words = parse_decimal_u64(fields[5], path, "payload_words");
        row.padded_words = parse_decimal_u64(fields[6], path, "padded_words");
        row.initialization = fields[7];
        const std::string row_context =
            "allocation '" + row.allocation_id + "'";
        const std::uint64_t expected_padded =
            checked_padded_words(row.line_count, path, row_context);
        if (row.payload_words == 0 || row.payload_words > expected_padded
            || row.padded_words != expected_padded
            || (row.payload_words - 1U) / kLineWords + 1U
                != row.line_count) {
            throw std::runtime_error(
                "application package " + manifest_name + " " + row_context
                + " has inconsistent line_count/payload_words/padded_words");
        }
        if (include_hashes) {
            row.payload_fnv1a64 =
                parse_fnv1a64(fields[8], path, "payload_fnv1a64");
            row.padded_fnv1a64 =
                parse_fnv1a64(fields[9], path, "padded_fnv1a64");
        }
        for (const auto& previous : rows) {
            const hpu::runtime::HpuMemSpan current_span{
                row.line_offset, row.line_count};
            const hpu::runtime::HpuMemSpan previous_span{
                previous.line_offset, previous.line_count};
            if (spans_overlap(current_span, previous_span)) {
                throw std::runtime_error(
                    "application package " + manifest_name + " allocation '"
                    + row.allocation_id + "' overlaps allocation '"
                    + previous.allocation_id + "'");
            }
        }
        rows.push_back(std::move(row));
    }
    if (rows.empty()) {
        throw std::runtime_error(
            "application package " + manifest_name
            + " must contain at least one allocation row");
    }
    return rows;
}

std::vector<GoldenManifestRow> parse_golden_manifest(
    const std::filesystem::path& path)
{
    std::istringstream input(read_file(path));
    input.imbue(std::locale::classic());
    std::string line;
    const std::string expected_header =
        "object_id,component,modulus_id,modulus,domain,path,line_offset,"
        "line_count,payload_words,padded_words,payload_fnv1a64,padded_fnv1a64";
    if (!std::getline(input, line) || line != expected_header) {
        throw std::runtime_error(
            "application package golden manifest '" + path.string()
            + "' has an invalid header");
    }

    std::vector<GoldenManifestRow> rows;
    std::set<std::tuple<std::string, std::uint64_t, std::uint64_t>> keys;
    std::set<std::string> paths;
    while (std::getline(input, line)) {
        if (line.empty()) {
            throw std::runtime_error(
                "application package golden manifest '" + path.string()
                + "' contains an empty row");
        }
        const auto fields = split_csv_row(line, path, 12);
        validate_identifier(fields[0], "golden object_id", true);
        GoldenManifestRow row;
        row.object_id = fields[0];
        row.component = parse_decimal_u64(fields[1], path, "component");
        row.modulus_id = parse_decimal_u64(fields[2], path, "modulus_id");
        const std::uint64_t modulus =
            parse_decimal_u64(fields[3], path, "modulus");
        const std::string context =
            "golden object '" + row.object_id + "' component "
            + std::to_string(row.component) + " MOD_ID "
            + std::to_string(row.modulus_id);
        if (row.modulus_id > std::numeric_limits<std::uint8_t>::max()) {
            throw std::runtime_error(
                "application package " + context + " modulus_id overflows u8");
        }
        if (modulus == 0) {
            throw std::runtime_error(
                "application package " + context + " modulus must be nonzero");
        }
        if (modulus > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error(
                "application package " + context + " modulus overflows u32");
        }
        row.modulus = static_cast<std::uint32_t>(modulus);
        if (fields[4] != "coefficient"
            && fields[4] != "canonical_ntt_physical") {
            throw std::runtime_error(
                "application package " + context + " has invalid domain '"
                + fields[4] + "'");
        }
        row.domain = fields[4];
        row.path = fields[5];
        validate_package_relative_path(row.path);
        const std::string expected_path =
            "golden/objects/" + row.object_id + "/c"
            + std::to_string(row.component) + "/mod"
            + std::to_string(row.modulus_id) + ".u32.bin";
        if (row.path != expected_path) {
            throw std::runtime_error(
                "application package " + context + " path '" + row.path
                + "' does not match '" + expected_path + "'");
        }
        if (!keys.emplace(
                row.object_id, row.component, row.modulus_id).second) {
            throw std::runtime_error(
                "application package " + context + " is duplicated");
        }
        if (!paths.insert(row.path).second) {
            throw std::runtime_error(
                "application package golden manifest duplicates path '"
                + row.path + "'");
        }
        row.line_offset = parse_decimal_u64(fields[6], path, "line_offset");
        row.line_count = parse_decimal_u64(fields[7], path, "line_count");
        row.payload_words = parse_decimal_u64(fields[8], path, "payload_words");
        row.padded_words = parse_decimal_u64(fields[9], path, "padded_words");
        const std::uint64_t expected_padded =
            checked_padded_words(row.line_count, path, context);
        if (row.payload_words == 0 || row.payload_words > expected_padded
            || row.padded_words != expected_padded
            || (row.payload_words - 1U) / kLineWords + 1U
                != row.line_count) {
            throw std::runtime_error(
                "application package " + context
                + " has inconsistent line_count/payload_words/padded_words");
        }
        row.payload_fnv1a64 =
            parse_fnv1a64(fields[10], path, "payload_fnv1a64");
        row.padded_fnv1a64 =
            parse_fnv1a64(fields[11], path, "padded_fnv1a64");
        rows.push_back(std::move(row));
    }
    if (rows.empty()) {
        throw std::runtime_error(
            "application package golden manifest must contain at least one row");
    }
    return rows;
}

std::string extract_json_string(
    const std::string& json,
    const std::string& key,
    const std::filesystem::path& path,
    bool required)
{
    const auto fields = JsonReader(json, path).read_document();
    const auto found = fields.find(key);
    if (found == fields.end()) {
        if (!required) return {};
        throw std::runtime_error(
            "application package JSON '" + path.string()
            + "' is missing string field '" + key + "'");
    }
    if (found->second.kind != JsonKind::string) {
        throw std::runtime_error(
            "application package JSON '" + path.string()
            + "' has non-string field '" + key + "'");
    }
    return found->second.text;
}

std::uint32_t read_u32_le(const std::string& bytes, std::size_t word)
{
    const std::size_t offset = word * sizeof(std::uint32_t);
    std::uint32_t value = 0;
    for (unsigned byte = 0; byte < sizeof(std::uint32_t); ++byte) {
        value |= static_cast<std::uint32_t>(
                     static_cast<unsigned char>(bytes[offset + byte]))
            << (8U * byte);
    }
    return value;
}

// Cross-check the *meaning* of the manifests against the physical files. The
// files.csv hash alone only detects uncoordinated edits, not a modified file
// accompanied by an updated manifest.
std::vector<std::string> split_resolved_dma_csv(
    const std::string& line, const std::filesystem::path& path)
{
    std::vector<std::string> fields;
    std::size_t position = 0;
    for (;;) {
        std::string field;
        if (position < line.size() && line[position] == '"') {
            ++position;
            bool closed = false;
            while (position < line.size()) {
                if (line[position] != '"') {
                    field.push_back(line[position++]);
                } else if (position + 1 < line.size()
                           && line[position + 1] == '"') {
                    field.push_back('"');
                    position += 2;
                } else {
                    ++position;
                    closed = true;
                    break;
                }
            }
            if (!closed || (position < line.size() && line[position] != ',')) {
                throw std::runtime_error(
                    "application package DMA manifest '" + path.string()
                    + "' has malformed CSV quoting");
            }
        } else {
            while (position < line.size() && line[position] != ',') {
                if (line[position] == '"') {
                    throw std::runtime_error(
                        "application package DMA manifest '" + path.string()
                        + "' has a quote in an unquoted CSV field");
                }
                field.push_back(line[position++]);
            }
        }
        fields.push_back(std::move(field));
        if (position == line.size()) break;
        ++position;
    }
    if (fields.size() != 14) {
        throw std::runtime_error(
            "application package DMA manifest '" + path.string()
            + "' row must have exactly 14 fields");
    }
    return fields;
}

std::vector<hpu::runtime::HpuMemSpan> validate_resolved_dma_manifest(
    const std::string& contents,
    const std::filesystem::path& path,
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<AllocationManifestRow>& allocations,
    std::uint64_t used_lines,
    const std::vector<hpu::runtime::HpuMemSpan>* ordered_spans)
{
    static constexpr const char* kHeader =
        "instruction_index,dma_index,operation_index,operation_id,"
        "operation_dma_index,direction,object_slot,type_or_release,flag,"
        "allocation_id,line_offset,line_count,word_hex,normalized_asm";
    const auto relocations = hpu::collect_dma_relocations(instructions);
    std::istringstream input(contents);
    input.imbue(std::locale::classic());
    std::string line;
    if (!std::getline(input, line) || line != kHeader) {
        throw std::runtime_error(
            "application package DMA manifest '" + path.string()
            + "' has an invalid header");
    }
    std::size_t index = 0;
    std::vector<hpu::runtime::HpuMemSpan> resolved_spans;
    while (std::getline(input, line)) {
        if (index >= relocations.size()) {
            throw std::runtime_error(
                "application package DMA manifest '" + path.string()
                + "' has more relocations than the encoded program");
        }
        const auto fields = split_resolved_dma_csv(line, path);
        const auto& relocation = relocations[index];
        const auto& instruction = instructions[relocation.instruction_index];
        const auto number = [&](std::size_t column, const char* name) {
            return parse_decimal_u64(fields[column], path, name);
        };
        if (!fields[2].empty()) {
            (void)number(2, "operation_index");
        }
        (void)number(4, "operation_dma_index");
        const std::uint64_t offset = number(10, "line_offset");
        const std::uint64_t count = number(11, "line_count");
        if (number(0, "instruction_index") != relocation.instruction_index
            || number(1, "dma_index") != index
            || fields[5] != hpu::to_string(relocation.direction)
            || number(6, "object_slot") != relocation.object_id
            || number(7, "type_or_release") != relocation.type_or_release
            || number(8, "flag") != relocation.flag
            || fields[12] != hpu::format_word_hex(instruction.word)
            || fields[13] != instruction.normalized_asm) {
            throw std::runtime_error(
                "application package DMA manifest '" + path.string()
                + "' relocation " + std::to_string(index)
                + " disagrees with the encoded program");
        }
        if (count == 0 || offset >= used_lines || count > used_lines - offset
            || (ordered_spans != nullptr
                && (index >= ordered_spans->size()
                    || (*ordered_spans)[index].line_offset != offset
                    || (*ordered_spans)[index].line_count != count))) {
            throw std::runtime_error(
                "application package DMA manifest '" + path.string()
                + "' relocation " + std::to_string(index)
                + " has an invalid or mismatched ordered span");
        }
        bool found = false;
        for (const auto& allocation : allocations) {
            if (allocation.allocation_id == fields[9]
                && offset >= allocation.line_offset
                && offset - allocation.line_offset < allocation.line_count
                && count <= allocation.line_count
                    - (offset - allocation.line_offset)) {
                if (relocation.direction == hpu::Mnemonic::kDstore
                    && allocation.read_only) {
                    throw std::runtime_error(
                        "application package DMA manifest DSTORE targets read_only allocation '"
                        + allocation.allocation_id + "'");
                }
                found = true;
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(
                "application package DMA manifest '" + path.string()
                + "' relocation " + std::to_string(index)
                + " span does not belong to allocation_id '" + fields[9] + "'");
        }
        resolved_spans.push_back({offset, count});
        ++index;
    }
    if (index != relocations.size()) {
        throw std::runtime_error(
            "application package DMA manifest '" + path.string()
            + "' is missing encoded program relocations");
    }
    return resolved_spans;
}

void validate_program_source(
    const std::string& stem,
    const std::string& source,
    const std::vector<hpu::EncodedInstruction>& instructions,
    std::uint64_t capacity_lines,
    const std::vector<hpu::runtime::HpuMemSpan>& spans)
{
    const std::string base = hpu::render_executable_source(
        stem, instructions, capacity_lines);
    if (source == base) return;
    const std::string identifier = hpu::c_identifier(stem);
    std::ostringstream expected;
    expected << base << "\nstatic const hpu_dma_span_t hpu_program_"
             << identifier << "_resolved_spans[] = {\n";
    for (const auto& span : spans) {
        expected << "    { UINT32_C(" << span.line_offset
                 << "), UINT32_C(" << span.line_count << ") },\n";
    }
    expected << "};\n\nint hpu_run_" << identifier << "(void) {\n"
             << "    return hpu_program_" << identifier << "(\n"
             << "        hpu_program_" << identifier
             << "_resolved_spans,\n"
             << "        HPU_PROGRAM_";
    for (char character : identifier) {
        expected << static_cast<char>(std::toupper(
            static_cast<unsigned char>(character)));
    }
    expected << "_DMA_COUNT);\n}\n";
    if (source != expected.str()) {
        throw std::runtime_error(
            "application package program source differs from encoded instructions or DMA spans");
    }
}

void validate_program_header(
    const std::string& stem, const std::string& header,
    std::size_t dma_count)
{
    std::string expected = hpu::render_executable_header(stem, dma_count);
    if (header == expected) return;
    const std::string marker = "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    const auto position = expected.find(marker);
    if (position == std::string::npos) {
        throw std::logic_error(
            "generated executable header has an unexpected structure");
    }
    expected.insert(position,
        "int hpu_run_" + hpu::c_identifier(stem) + "(void);\n\n");
    if (header != expected) {
        throw std::runtime_error(
            "application package program header differs from encoded DMA count");
    }
}

void validate_physical_artifacts(const std::filesystem::path& root)
{
    const auto line_map = parse_allocation_manifest(
        root / "memory/line_map.csv", false, "line_map");
    const auto memory = parse_allocation_manifest(
        root / "memory/memory_manifest.csv", true, "memory manifest");
    if (line_map.size() != memory.size()) {
        throw std::runtime_error(
            "application package line_map and memory manifest allocation counts differ");
    }

    const std::filesystem::path config_path = root / "memory/hpu_mem_config.json";
    const std::string config = read_file(config_path);
    const std::uint64_t used_lines =
        extract_json_u64(config, "used_lines", config_path);
    const std::uint64_t capacity_lines =
        extract_json_u64(config, "capacity_lines", config_path);
    if (used_lines == 0 || used_lines > capacity_lines
        || used_lines > std::numeric_limits<std::size_t>::max() / kLineBytes) {
        throw std::runtime_error(
            "application package memory configuration has invalid used_lines/capacity_lines");
    }
    const std::string image = read_file(root / "memory/hpu_mem_image.u32.bin");
    if (image.size() != static_cast<std::size_t>(used_lines) * kLineBytes) {
        throw std::runtime_error(
            "application package HPU_MEM image bytes do not match used_lines");
    }

    std::map<std::pair<std::uint64_t, std::uint64_t>,
             const AllocationManifestRow*> output_spans;
    std::uint64_t next_line = 0;
    for (std::size_t index = 0; index < memory.size(); ++index) {
        const auto& allocation = memory[index];
        const auto& mapped = line_map[index];
        const std::string id = allocation.allocation_id;
        if (id != mapped.allocation_id || allocation.kind != mapped.kind
            || allocation.read_only != mapped.read_only
            || allocation.line_offset != mapped.line_offset
            || allocation.line_count != mapped.line_count
            || allocation.payload_words != mapped.payload_words
            || allocation.padded_words != mapped.padded_words
            || allocation.initialization != mapped.initialization) {
            throw std::runtime_error(
                "application package line_map allocation '" + id
                + "' line_offset/kind/span/word_count disagrees with memory manifest");
        }
        if (allocation.line_offset != next_line
            || allocation.line_offset >= used_lines
            || allocation.line_count > used_lines - allocation.line_offset) {
            throw std::runtime_error(
                "application package memory manifest allocation '" + id
                + "' is not a consecutive span inside the HPU_MEM image");
        }
        next_line = allocation.line_offset + allocation.line_count;
        const std::size_t begin =
            static_cast<std::size_t>(allocation.line_offset) * kLineBytes;
        const std::size_t payload_bytes =
            static_cast<std::size_t>(allocation.payload_words) * sizeof(std::uint32_t);
        const std::size_t padded_bytes =
            static_cast<std::size_t>(allocation.padded_words) * sizeof(std::uint32_t);
        const bool output = allocation.kind == "output";
        if (output && allocation.read_only) {
            throw std::runtime_error(
                "application package output allocation '" + id
                + "' must not be read_only");
        }
        if (output || allocation.initialization == "zero_reserved") {
            for (std::size_t word = 0; word < allocation.padded_words; ++word) {
                if (read_u32_le(image, begin / sizeof(std::uint32_t) + word) != 0) {
                    throw std::runtime_error(
                        "application package output allocation '" + id
                        + "' initial word " + std::to_string(word)
                        + " must be zero (including padding)");
                }
            }
        }
        if (hash_bytes(image.substr(begin, payload_bytes))
            != allocation.payload_fnv1a64) {
            throw std::runtime_error(
                "application package memory manifest allocation '" + id
                + "' payload_fnv1a64 disagrees with image");
        }
        if (hash_bytes(image.substr(begin, padded_bytes))
            != allocation.padded_fnv1a64) {
            throw std::runtime_error(
                "application package memory manifest allocation '" + id
                + "' padded_fnv1a64 disagrees with image");
        }
        if (output) {
            output_spans.emplace(
                std::make_pair(allocation.line_offset, allocation.line_count),
                &allocation);
        }
    }
    if (next_line != used_lines) {
        throw std::runtime_error(
            "application package memory manifest does not cover used_lines");
    }

    const std::string descriptor = read_file(root / "package.json");
    const std::filesystem::path descriptor_path = root / "package.json";
    const std::string asm_path = extract_json_string(
        descriptor, "program_asm", descriptor_path, true);
    const std::string inst32_path = extract_json_string(
        descriptor, "program_inst32", descriptor_path, true);
    const std::string cmd26_path = extract_json_string(
        descriptor, "program_cmd26", descriptor_path, true);
    std::vector<hpu::EncodedInstruction> assembled;
    try {
        assembled = hpu::assemble_source(read_file(root / asm_path));
        hpu::validate_executable_program(assembled);
    } catch (const std::exception& error) {
        throw std::runtime_error(
            "application package program assembly cannot be assembled: "
            + std::string(error.what()));
    }
    if (read_file(root / inst32_path)
        != render_program_words(assembled, false)) {
        throw std::runtime_error(
            "application package program inst32 differs from assembly");
    }
    if (read_file(root / cmd26_path)
        != render_program_words(assembled, true)) {
        throw std::runtime_error(
            "application package program cmd26 differs from assembly");
    }
    const auto resolved_spans = validate_resolved_dma_manifest(
        read_file(root / "program/dma_relocation_manifest.csv"),
        root / "program/dma_relocation_manifest.csv", assembled, memory,
        used_lines, nullptr);
    validate_program_source(
        std::filesystem::path(asm_path).stem().string(),
        read_file(root / extract_json_string(
            descriptor, "program_source", descriptor_path, true)),
        assembled, capacity_lines, resolved_spans);
    validate_program_header(
        std::filesystem::path(asm_path).stem().string(),
        read_file(root / extract_json_string(
            descriptor, "program_header", descriptor_path, true)),
        resolved_spans.size());
    const auto golden = parse_golden_manifest(
        root / "golden/golden_manifest.csv");
    if (golden.size() != output_spans.size()) {
        throw std::runtime_error(
            "application package golden manifest must cover each output allocation exactly once");
    }
    std::set<std::string> covered_outputs;
    for (const auto& limb : golden) {
        const std::string context =
            "application package golden object '" + limb.object_id
            + "' component " + std::to_string(limb.component)
            + " MOD_ID " + std::to_string(limb.modulus_id);
        const auto found = output_spans.find(
            {limb.line_offset, limb.line_count});
        if (found == output_spans.end()
            || found->second->payload_words != limb.payload_words) {
            throw std::runtime_error(
                context + " line_offset/line_count/payload_words does not match an output allocation");
        }
        if (!covered_outputs.insert(found->second->allocation_id).second) {
            throw std::runtime_error(
                context + " repeats an output allocation");
        }
        const std::string bytes = read_file(root / limb.path);
        if (limb.padded_words > std::numeric_limits<std::size_t>::max() / 4U
            || bytes.size() != limb.padded_words * 4U) {
            throw std::runtime_error(context + " bytes do not match padded_words");
        }
        if (hash_bytes(bytes.substr(0, limb.payload_words * 4U))
            != limb.payload_fnv1a64
            || hash_bytes(bytes) != limb.padded_fnv1a64) {
            throw std::runtime_error(
                context + " payload_fnv1a64/padded_fnv1a64 disagrees with golden file");
        }
        for (std::size_t word = 0; word < limb.padded_words; ++word) {
            const std::uint32_t value = read_u32_le(bytes, word);
            if (word < limb.payload_words && value >= limb.modulus) {
                throw std::runtime_error(
                    context + " word " + std::to_string(word)
                    + " is not less than modulus " + std::to_string(limb.modulus));
            }
            if (word >= limb.payload_words && value != 0) {
                throw std::runtime_error(
                    context + " padding word " + std::to_string(word)
                    + " must be zero");
            }
        }
    }
}

void require_regular_file(
    const std::filesystem::path& root,
    const std::string& relative)
{
    validate_package_relative_path(relative);
    const std::filesystem::path path = root / relative;
    const std::filesystem::file_status status =
        std::filesystem::symlink_status(path);
    if (!std::filesystem::is_regular_file(status)) {
        throw std::runtime_error(
            "application package required path '" + relative
            + "' is missing or is not a regular file");
    }
}

class StagingCleanup {
public:
    explicit StagingCleanup(std::filesystem::path path)
        : path_(std::move(path))
    {}

    ~StagingCleanup()
    {
        if (!path_.empty()) {
            std::error_code error;
            std::filesystem::remove_all(path_, error);
        }
    }

    void release() noexcept { path_.clear(); }

    StagingCleanup(const StagingCleanup&) = delete;
    StagingCleanup& operator=(const StagingCleanup&) = delete;

private:
    std::filesystem::path path_;
};

std::filesystem::path create_private_staging(
    const std::filesystem::path& output_root)
{
    std::filesystem::path parent = output_root.parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    std::error_code error;
    std::filesystem::create_directories(parent, error);
    if (error) {
        throw std::runtime_error(
            "failed to create application package parent '" + parent.string()
            + "': " + error.message());
    }
    std::string name = output_root.filename().string();
    if (name.empty()) {
        throw std::invalid_argument(
            "application package output root '" + output_root.string()
            + "' has no final path component");
    }
    std::string path_template =
        (parent / ("." + name + ".staging.XXXXXX")).string();
    std::vector<char> mutable_template(
        path_template.begin(), path_template.end());
    mutable_template.push_back('\0');
    char* const created = ::mkdtemp(mutable_template.data());
    if (created == nullptr) {
        throw std::runtime_error(
            "failed to create private application package staging directory next to '"
            + output_root.string() + "': "
            + std::error_code(errno, std::generic_category()).message());
    }
    if (::chmod(created, S_IRWXU) != 0) {
        const int error_number = errno;
        std::error_code ignored;
        std::filesystem::remove_all(created, ignored);
        throw std::runtime_error(
            "failed to set private mode 0700 on staging directory '"
            + std::string(created) + "': "
            + std::error_code(error_number, std::generic_category()).message());
    }
    return created;
}

} // namespace

void validate_application_package_request(
    const ApplicationPackageRequest& request)
{
    (void)scheme_name(request.scheme);
    validate_identifier(request.case_name, "case_name", true);
    validate_identifier(
        request.program.stem,
        context_case(request) + " program stem",
        true);
    validate_identifier(
        request.producer.repository,
        context_case(request) + " producer repository",
        false);
    validate_identifier(
        request.producer.commit,
        context_case(request) + " producer commit",
        false);
    validate_identifier(
        request.producer.worktree_state,
        context_case(request) + " producer worktree_state",
        false);

    if (request.initial_image == nullptr) {
        throw std::invalid_argument(
            context_case(request) + " initial_image must not be null");
    }
    const auto& image = *request.initial_image;
    if (image.used_lines()
            > std::numeric_limits<std::size_t>::max() / kLineWords
        || image.words().size()
            != static_cast<std::size_t>(image.used_lines()) * kLineWords) {
        throw std::invalid_argument(
            context_case(request)
            + " initial image used words must equal used_lines * 64");
    }
    if (image.used_lines() > image.capacity_lines()) {
        throw std::invalid_argument(
            context_case(request) + " initial image exceeds capacity_lines");
    }

    std::set<std::string> allocation_ids;
    const auto& allocations = image.allocations();
    for (std::size_t index = 0; index < allocations.size(); ++index) {
        const auto& allocation = allocations[index];
        validate_identifier(
            allocation.id,
            context_case(request) + " allocation_id",
            false);
        if (!allocation_ids.insert(allocation.id).second) {
            throw std::invalid_argument(
                context_case(request) + " has duplicate allocation_id '"
                + allocation.id + "'");
        }
        if (!span_within(allocation.span, image.used_lines())) {
            throw std::invalid_argument(
                context_case(request) + " allocation '" + allocation.id
                + "' is outside the initial image");
        }
        const std::uint64_t expected_lines =
            (allocation.word_count + kLineWords - 1U) / kLineWords;
        if (allocation.word_count == 0
            || allocation.span.line_count != expected_lines) {
            throw std::invalid_argument(
                context_case(request) + " allocation '" + allocation.id
                + "' has inconsistent span and word_count");
        }
        for (std::size_t previous = 0; previous < index; ++previous) {
            if (spans_overlap(allocation.span, allocations[previous].span)) {
                throw std::invalid_argument(
                    context_case(request) + " allocation '" + allocation.id
                    + "' overlaps allocation '" + allocations[previous].id + "'");
            }
        }
    }

    try {
        hpu::validate_executable_program(request.program.instructions);
    } catch (const std::exception& error) {
        throw std::invalid_argument(
            context_case(request) + " executable program is invalid: "
            + error.what());
    }
    try {
        const auto assembled = hpu::assemble_source(request.program.assembly);
        if (assembled.size() != request.program.instructions.size()) {
            throw std::invalid_argument("assembly and instructions have different lengths");
        }
        for (std::size_t index = 0; index < assembled.size(); ++index) {
            if (assembled[index].word != request.program.instructions[index].word
                || assembled[index].command26
                    != request.program.instructions[index].command26) {
                throw std::invalid_argument(
                    "assembly and instructions differ at index "
                    + std::to_string(index));
            }
        }
    } catch (const std::exception& error) {
        throw std::invalid_argument(
            context_case(request) + " program assembly does not match instructions: "
            + error.what());
    }
    std::vector<hpu::DmaRelocation> relocations;
    try {
        relocations = hpu::collect_dma_relocations(request.program.instructions);
    } catch (const std::exception& error) {
        throw std::invalid_argument(
            context_case(request) + " DMA program is invalid: " + error.what());
    }
    if (request.program.ordered_dma_spans.size() != relocations.size()) {
        throw std::invalid_argument(
            context_case(request) + " ordered DMA span count "
            + std::to_string(request.program.ordered_dma_spans.size())
            + " does not match relocation count "
            + std::to_string(relocations.size()));
    }
    for (std::size_t index = 0;
         index < request.program.ordered_dma_spans.size(); ++index) {
        const auto& span = request.program.ordered_dma_spans[index];
        if (!span_within(span, image.used_lines())) {
            throw std::invalid_argument(
                context_case(request) + " DMA span " + std::to_string(index)
                + " is zero or outside used_lines of the serialized image");
        }
        if (relocations[index].direction == hpu::Mnemonic::kDstore) {
            for (const auto& allocation : allocations) {
                if (spans_overlap(span, allocation.span)
                    && allocation.read_only) {
                    throw std::invalid_argument(
                        context_case(request) + " DSTORE span "
                        + std::to_string(index) + " points to read_only allocation '"
                        + allocation.id + "'");
                }
            }
        }
    }
    std::vector<AllocationManifestRow> dma_allocations;
    for (const auto& allocation : allocations) {
        AllocationManifestRow row;
        row.allocation_id = allocation.id;
        row.line_offset = allocation.span.line_offset;
        row.line_count = allocation.span.line_count;
        row.read_only = allocation.read_only;
        dma_allocations.push_back(std::move(row));
    }
    validate_resolved_dma_manifest(
        request.program.resolved_dma_manifest,
        "program/dma_relocation_manifest.csv", request.program.instructions,
        dma_allocations, image.used_lines(), &request.program.ordered_dma_spans);
    validate_program_source(
        request.program.stem, request.program.source,
        request.program.instructions, image.capacity_lines(),
        request.program.ordered_dma_spans);
    validate_program_header(
        request.program.stem, request.program.header, relocations.size());

    std::set<std::tuple<std::string, std::size_t, std::uint8_t>> output_keys;
    std::map<std::string, std::size_t> output_coverage;
    for (const auto& output : request.outputs) {
        (void)output_domain_name(output.domain);
        validate_identifier(
            output.object_id,
            output_context(request, output) + " object_id",
            true);
        if (!output_keys.emplace(
                output.object_id, output.component, output.modulus_id).second) {
            throw std::invalid_argument(
                output_context(request, output) + " has a duplicate golden key");
        }
        const hpu::runtime::HpuMemAllocation* matched = nullptr;
        for (const auto& allocation : allocations) {
            if (same_span(output.destination, allocation.span)
                && output.word_count == allocation.word_count) {
                if (matched != nullptr) {
                    throw std::invalid_argument(
                        output_context(request, output)
                        + " matches more than one allocation");
                }
                matched = &allocation;
            }
        }
        if (matched == nullptr
            || matched->kind != hpu::runtime::AllocationKind::output
            || matched->read_only) {
            throw std::invalid_argument(
                output_context(request, output)
                + " must exactly match one non-readonly output allocation span and word_count");
        }
        ++output_coverage[matched->id];
        if (output.modulus == 0) {
            throw std::invalid_argument(
                output_context(request, output) + " modulus must be nonzero");
        }
        if (output.golden_words.size() != output.word_count) {
            throw std::invalid_argument(
                output_context(request, output) + " golden_words size "
                + std::to_string(output.golden_words.size())
                + " does not equal word_count "
                + std::to_string(output.word_count));
        }
        for (std::size_t word = 0; word < output.golden_words.size(); ++word) {
            if (output.golden_words[word] >= output.modulus) {
                throw std::invalid_argument(
                    output_context(request, output) + " golden word "
                    + std::to_string(word) + " is not less than modulus "
                    + std::to_string(output.modulus));
            }
        }
    }
    for (const auto& allocation : allocations) {
        if (allocation.kind != hpu::runtime::AllocationKind::output) {
            continue;
        }
        if (allocation.read_only) {
            throw std::invalid_argument(
                context_case(request) + " output allocation '" + allocation.id
                + "' is read_only");
        }
        if (output_coverage[allocation.id] != 1) {
            throw std::invalid_argument(
                context_case(request) + " output allocation '" + allocation.id
                + "' must be covered by exactly one golden limb");
        }
        const auto words = allocation_words(image, allocation);
        for (std::size_t word = 0; word < words.first.size(); ++word) {
            if (words.first[word] != 0) {
                throw std::invalid_argument(
                    context_case(request) + " output allocation '" + allocation.id
                    + "' initial payload word " + std::to_string(word)
                    + " must be zero");
            }
        }
    }

    if (request.parameters_json.empty()) {
        throw std::invalid_argument(
            context_case(request) + " parameters_json must not be empty");
    }
    if (request.operation_graph_json.empty()) {
        throw std::invalid_argument(
            context_case(request) + " operation_graph_json must not be empty");
    }
    if (request.oracle_report_json.empty()) {
        throw std::invalid_argument(
            context_case(request) + " oracle_report_json must not be empty");
    }
    if (request.semantic_report) {
        validate_identifier(
            request.semantic_report->media_type,
            context_case(request) + " semantic media_type",
            false);
        if (request.semantic_report->contents.empty()) {
            throw std::invalid_argument(
                context_case(request) + " semantic report contents must not be empty");
        }
    }
}

ApplicationPackageReport write_application_package(
    const std::filesystem::path& output_root,
    const ApplicationPackageRequest& request)
{
    validate_application_package_request(request);
    if (output_root.empty()) {
        throw std::invalid_argument("application package output root is empty");
    }
    std::error_code target_error;
    const std::filesystem::file_status target_status =
        std::filesystem::symlink_status(output_root, target_error);
    if (target_error
        && target_status.type() != std::filesystem::file_type::not_found) {
        throw std::runtime_error(
            "failed to inspect application package target '"
            + output_root.string() + "': " + target_error.message());
    }
    if (std::filesystem::exists(target_status)
        || std::filesystem::is_symlink(target_status)) {
        throw std::invalid_argument(
            "application package target '" + output_root.string()
            + "' already exists; v1 never removes or overwrites a target");
    }

    const auto& image = *request.initial_image;
    std::vector<FileArtifact> files;
    const auto add = [&](std::string path, std::string bytes) {
        files.push_back({path, role_for_path(path), std::move(bytes)});
    };
    add("package.json", render_package_json(request));
    add("metadata/parameters.json", request.parameters_json);
    add("metadata/operation_graph.json", request.operation_graph_json);
    add("program/" + request.program.stem + ".c", request.program.source);
    add("program/" + request.program.stem + ".h", request.program.header);
    add("program/" + request.program.stem + ".asm", request.program.assembly);
    add(
        "program/" + request.program.stem + ".inst32",
        render_program_words(request.program.instructions, false));
    add(
        "program/" + request.program.stem + ".cmd26",
        render_program_words(request.program.instructions, true));
    add(
        "program/dma_relocation_manifest.csv",
        request.program.resolved_dma_manifest);
    add("memory/hpu_mem_image.u32.bin", render_u32_le(image.words()));
    add("memory/line_map.csv", render_line_map(image));
    add("memory/memory_manifest.csv", render_memory_manifest(image));
    add("memory/abi.json", render_abi_json());
    add("memory/hpu_mem_config.json", render_memory_config_json(image));
    add("golden/golden_manifest.csv", render_golden_manifest(request.outputs));
    for (const auto& output : request.outputs) {
        add(
            golden_relative_path(output),
            render_u32_le(padded_golden_words(output)));
    }
    add("oracle/report.json", request.oracle_report_json);
    if (request.semantic_report) {
        add("semantic/decoded.json", request.semantic_report->contents);
    }
    add("provenance/build.json", render_build_json(request));
    std::sort(
        files.begin(), files.end(),
        [](const FileArtifact& left, const FileArtifact& right) {
            return path_bytes_less(left.path, right.path);
        });
    files.push_back({
        kFilesManifestPath, "provenance_manifest", render_files_manifest(files)});
    std::sort(
        files.begin(), files.end(),
        [](const FileArtifact& left, const FileArtifact& right) {
            return path_bytes_less(left.path, right.path);
        });

    const std::filesystem::path staging = create_private_staging(output_root);
    StagingCleanup cleanup(staging);
    for (const auto& file : files) {
        const std::filesystem::path destination =
            resolve_package_destination(staging, file.path);
        write_file_atomic(destination, file.bytes);
    }
    validate_application_package_on_disk(staging);

    publish_directory_noreplace(staging, output_root);
    cleanup.release();

    ApplicationPackageReport report;
    report.root = output_root;
    for (const auto& file : files) {
        report.files.push_back(file.path);
    }
    report.image_fnv1a64 = fnv1a64_words32_le(image.words());
    return report;
}

void validate_application_package_on_disk(
    const std::filesystem::path& package_root)
{
    const std::filesystem::file_status root_status =
        std::filesystem::symlink_status(package_root);
    if (std::filesystem::is_symlink(root_status)
        || !std::filesystem::is_directory(root_status)) {
        throw std::runtime_error(
            "application package root '" + package_root.string()
            + "' must be a non-symlink directory");
    }

    const std::vector<std::string> fixed_required{
        "package.json",
        "metadata/parameters.json",
        "metadata/operation_graph.json",
        "program/dma_relocation_manifest.csv",
        "memory/hpu_mem_image.u32.bin",
        "memory/line_map.csv",
        "memory/memory_manifest.csv",
        "memory/abi.json",
        "memory/hpu_mem_config.json",
        "golden/golden_manifest.csv",
        "oracle/report.json",
        "provenance/build.json",
        kFilesManifestPath,
    };
    for (const auto& relative : fixed_required) {
        require_regular_file(package_root, relative);
    }

    const std::filesystem::path descriptor_path = package_root / "package.json";
    const std::string descriptor = read_file(descriptor_path);
    if (extract_json_string(
            descriptor, "schema", descriptor_path, true)
        != "hpu-application-package") {
        throw std::runtime_error(
            "application package descriptor '" + descriptor_path.string()
            + "' has unsupported schema");
    }
    if (extract_json_u64(
            descriptor, "schema_version", descriptor_path)
        != kApplicationPackageSchemaVersion) {
        throw std::runtime_error(
            "application package descriptor '" + descriptor_path.string()
            + "' has unsupported schema_version");
    }
    const std::string scheme = extract_json_string(
        descriptor, "scheme", descriptor_path, true);
    if (scheme != "ckks" && scheme != "bfv" && scheme != "bgv") {
        throw std::runtime_error(
            "application package descriptor has unsupported scheme '"
            + scheme + "'");
    }
    const std::vector<std::string> path_fields{
        "parameters", "operation_graph", "program_source", "program_header",
        "program_asm", "program_inst32", "program_cmd26",
        "dma_relocation_manifest", "image", "line_map", "memory_manifest",
        "memory_abi", "memory_config", "golden_manifest", "oracle_report"};
    std::map<std::string, std::string> descriptor_paths;
    for (const auto& field : path_fields) {
        const std::string relative =
            extract_json_string(descriptor, field, descriptor_path, true);
        require_regular_file(package_root, relative);
        descriptor_paths.emplace(field, relative);
    }
    const std::map<std::string, std::string> fixed_descriptor_paths{
        {"parameters", "metadata/parameters.json"},
        {"operation_graph", "metadata/operation_graph.json"},
        {"dma_relocation_manifest", "program/dma_relocation_manifest.csv"},
        {"image", "memory/hpu_mem_image.u32.bin"},
        {"line_map", "memory/line_map.csv"},
        {"memory_manifest", "memory/memory_manifest.csv"},
        {"memory_abi", "memory/abi.json"},
        {"memory_config", "memory/hpu_mem_config.json"},
        {"golden_manifest", "golden/golden_manifest.csv"},
        {"oracle_report", "oracle/report.json"},
    };
    for (const auto& fixed : fixed_descriptor_paths) {
        if (descriptor_paths.at(fixed.first) != fixed.second) {
            throw std::runtime_error(
                "application package descriptor path field '" + fixed.first
                + "' must be '" + fixed.second + "'");
        }
    }
    const std::string program_asm = descriptor_paths.at("program_asm");
    constexpr const char* kProgramPrefix = "program/";
    constexpr const char* kAsmSuffix = ".asm";
    if (program_asm.rfind(kProgramPrefix, 0) != 0
        || program_asm.size() <= std::string(kProgramPrefix).size()
                + std::string(kAsmSuffix).size()
        || program_asm.compare(
               program_asm.size() - std::string(kAsmSuffix).size(),
               std::string(kAsmSuffix).size(),
               kAsmSuffix)
            != 0) {
        throw std::runtime_error(
            "application package descriptor program_asm path '" + program_asm
            + "' does not have the required program/<stem>.asm form");
    }
    const std::string program_stem = program_asm.substr(
        std::string(kProgramPrefix).size(),
        program_asm.size() - std::string(kProgramPrefix).size()
            - std::string(kAsmSuffix).size());
    validate_identifier(program_stem, "package program stem", true);
    const std::map<std::string, std::string> program_suffixes{
        {"program_source", ".c"},
        {"program_header", ".h"},
        {"program_asm", ".asm"},
        {"program_inst32", ".inst32"},
        {"program_cmd26", ".cmd26"},
    };
    for (const auto& item : program_suffixes) {
        const std::string expected =
            std::string(kProgramPrefix) + program_stem + item.second;
        if (descriptor_paths.at(item.first) != expected) {
            throw std::runtime_error(
                "application package descriptor path field '" + item.first
                + "' must be '" + expected + "'");
        }
    }
    const std::string semantic = extract_json_string(
        descriptor, "semantic_report", descriptor_path, false);
    if (!semantic.empty()) {
        if (semantic != "semantic/decoded.json") {
            throw std::runtime_error(
                "application package descriptor semantic_report path must be "
                "'semantic/decoded.json'");
        }
        require_regular_file(package_root, semantic);
    }

    std::set<std::string> schema_paths{
        "package.json",
        "provenance/build.json",
    };
    for (const auto& item : descriptor_paths) {
        schema_paths.insert(item.second);
    }
    if (!semantic.empty()) {
        schema_paths.insert(semantic);
    }
    const auto golden_paths = parse_golden_manifest_paths(
        package_root / descriptor_paths.at("golden_manifest"));
    schema_paths.insert(golden_paths.begin(), golden_paths.end());

    const auto manifest_entries =
        parse_files_manifest(package_root / kFilesManifestPath);
    std::set<std::string> declared_paths;
    for (const auto& entry : manifest_entries) {
        declared_paths.insert(entry.path);
        require_regular_file(package_root, entry.path);
        const std::string bytes = read_file(package_root / entry.path);
        if (bytes.size() != entry.bytes) {
            throw std::runtime_error(
                "application package file '" + entry.path
                + "' bytes mismatch: manifest=" + std::to_string(entry.bytes)
                + " actual=" + std::to_string(bytes.size()));
        }
        const std::uint64_t actual_hash = hash_bytes(bytes);
        if (actual_hash != entry.fnv1a64) {
            throw std::runtime_error(
                "application package file '" + entry.path
                + "' fnv1a64 mismatch: manifest=" + hex64(entry.fnv1a64)
                + " actual=" + hex64(actual_hash));
        }
    }

    std::set<std::string> actual_paths;
    std::error_code traversal_error;
    std::filesystem::recursive_directory_iterator iterator(
        package_root,
        std::filesystem::directory_options::none,
        traversal_error);
    const std::filesystem::recursive_directory_iterator end;
    if (traversal_error) {
        throw std::runtime_error(
            "failed to enumerate application package root '"
            + package_root.string() + "': " + traversal_error.message());
    }
    while (iterator != end) {
        const std::filesystem::path path = iterator->path();
        const std::string relative =
            path.lexically_relative(package_root).generic_string();
        const std::filesystem::file_status status =
            std::filesystem::symlink_status(path, traversal_error);
        if (traversal_error) {
            throw std::runtime_error(
                "failed to inspect application package path '" + relative
                + "': " + traversal_error.message());
        }
        if (std::filesystem::is_symlink(status)) {
            iterator.disable_recursion_pending();
            throw std::runtime_error(
                "application package path '" + relative
                + "' is a forbidden symlink");
        }
        if (std::filesystem::is_regular_file(status)) {
            if (relative != kFilesManifestPath) {
                actual_paths.insert(relative);
            }
        } else if (!std::filesystem::is_directory(status)) {
            throw std::runtime_error(
                "application package path '" + relative
                + "' is neither a directory nor a regular file");
        }
        iterator.increment(traversal_error);
        if (traversal_error) {
            throw std::runtime_error(
                "failed while enumerating application package root '"
                + package_root.string() + "': " + traversal_error.message());
        }
    }

    for (const auto& actual : actual_paths) {
        if (schema_paths.count(actual) == 0) {
            throw std::runtime_error(
                "application package contains extra regular file '" + actual
                + "' outside the v1 artifact allow-list");
        }
        if (declared_paths.count(actual) == 0) {
            throw std::runtime_error(
                "application package contains extra regular file '" + actual
                + "' not declared by provenance/files.csv");
        }
    }
    for (const auto& declared : declared_paths) {
        if (actual_paths.count(declared) == 0) {
            throw std::runtime_error(
                "application package is missing manifest-declared file '"
                + declared + "'");
        }
    }
    for (const auto& expected : schema_paths) {
        if (actual_paths.count(expected) == 0) {
            throw std::runtime_error(
                "application package is missing v1 artifact '" + expected
                + "'");
        }
    }
    validate_physical_artifacts(package_root);
}

} // namespace hpu::delivery
