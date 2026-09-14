#include "hpu/seal/operation_runtime.hpp"

#include "assembler.hpp"
#include "executable.hpp"

#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::string csv_field(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (char character : value) {
        if (character == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(character);
    }
    escaped.push_back('"');
    return escaped;
}

const char* direction_name(CkksDmaDirection direction)
{
    return direction == CkksDmaDirection::load ? "dload" : "dstore";
}

void validate_encoded_binding(
    const hpu::DmaRelocation& encoded,
    const CkksDmaBinding& binding)
{
    const bool load = encoded.direction == hpu::Mnemonic::kDload;
    if (encoded.dma_index != binding.program_dma_index
        || encoded.object_id != binding.object_slot
        || load != (binding.direction == CkksDmaDirection::load)
        || (load
            && (encoded.type_or_release
                    != static_cast<std::uint8_t>(binding.load_type)
                || encoded.flag
                    != static_cast<std::uint8_t>(binding.load_flag)))
        || (!load
            && encoded.type_or_release != binding.store_release)) {
        throw std::invalid_argument(
            "encoded DMA instruction disagrees with CKKS relocation at index "
            + std::to_string(encoded.dma_index));
    }
}

std::string render_resolved_manifest(const CkksRuntimeProgram& program)
{
    std::ostringstream output;
    output
        << "instruction_index,dma_index,operation_index,operation_id,"
           "operation_dma_index,direction,object_slot,type_or_release,flag,"
           "allocation_id,line_offset,line_count,word_hex,normalized_asm\n";
    for (const auto& dma : program.dma) {
        const auto& binding = dma.binding;
        const auto& instruction = program.instructions[dma.instruction_index];
        output << dma.instruction_index << ','
               << binding.program_dma_index << ',';
        if (binding.operation_index.has_value()) {
            output << *binding.operation_index;
        }
        output << ',' << csv_field(binding.operation_id) << ','
               << binding.operation_dma_index << ','
               << direction_name(binding.direction) << ','
               << binding.object_slot << ','
               << (binding.direction == CkksDmaDirection::load
                    ? static_cast<int>(binding.load_type)
                    : binding.store_release)
               << ','
               << (binding.direction == CkksDmaDirection::load
                    ? static_cast<int>(binding.load_flag) : 0)
               << ',' << csv_field(binding.allocation_id) << ','
               << binding.span.line_offset << ','
               << binding.span.line_count << ','
               << hpu::format_word_hex(instruction.word) << ','
               << csv_field(instruction.normalized_asm) << '\n';
    }
    return output.str();
}

void require_renderable_spans(
    const CkksRuntimeProgram& program,
    std::uint64_t hpu_mem_line_count)
{
    if (hpu_mem_line_count == 0
        || hpu_mem_line_count
            > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(
            "resolved CKKS runtime requires a uint32-addressable HPU_MEM");
    }
    for (const auto& dma : program.dma) {
        const auto& span = dma.binding.span;
        if (span.line_count == 0
            || span.line_offset > std::numeric_limits<std::uint32_t>::max()
            || span.line_count > std::numeric_limits<std::uint32_t>::max()
            || span.line_offset >= hpu_mem_line_count
            || span.line_count > hpu_mem_line_count - span.line_offset) {
            throw std::invalid_argument(
                "resolved CKKS DMA span is outside HPU_MEM: "
                + dma.binding.allocation_id);
        }
    }
}

void validate_runtime_program(const CkksRuntimeProgram& program)
{
    if (program.instructions.empty() || program.dma.empty()) {
        throw std::invalid_argument("empty CKKS runtime program");
    }
    hpu::validate_executable_program(program.instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(program.instructions);
    if (encoded_dma.size() != program.dma.size()) {
        throw std::invalid_argument(
            "CKKS runtime DMA records differ from encoded instructions");
    }
    for (std::size_t index = 0; index < encoded_dma.size(); ++index) {
        if (program.dma[index].instruction_index
                != encoded_dma[index].instruction_index
            || program.dma[index].binding.program_dma_index != index) {
            throw std::invalid_argument(
                "CKKS runtime DMA records are not in encoded program order");
        }
        validate_encoded_binding(
            encoded_dma[index], program.dma[index].binding);
    }
}

} // namespace

std::vector<hpu::runtime::HpuMemSpan> CkksRuntimeProgram::spans() const
{
    std::vector<hpu::runtime::HpuMemSpan> result;
    result.reserve(dma.size());
    for (const auto& entry : dma) {
        result.push_back(entry.binding.span);
    }
    return result;
}

CkksRuntimeProgram lower_ckks_runtime_program(
    const CkksLoweredProgram& lowered,
    const CkksRelocationSchedule& relocation)
{
    if (!relocation.complete()) {
        throw std::invalid_argument(
            "cannot lower an incomplete CKKS relocation schedule");
    }
    CkksRuntimeProgram result;
    result.instructions = hpu::assemble_source(lowered.body_asm);
    hpu::validate_executable_program(result.instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(result.instructions);
    if (encoded_dma.size() != relocation.expected_dma_count
        || encoded_dma.size() != relocation.bindings.size()) {
        throw std::invalid_argument(
            "encoded CKKS DMA count differs from the relocation schedule");
    }
    result.dma.reserve(encoded_dma.size());
    for (std::size_t index = 0; index < encoded_dma.size(); ++index) {
        const auto& binding = relocation.bindings[index];
        if (binding.program_dma_index != index) {
            throw std::invalid_argument(
                "CKKS relocation bindings are not in program DMA order");
        }
        validate_encoded_binding(encoded_dma[index], binding);
        result.dma.push_back(CkksRuntimeDma{
            encoded_dma[index].instruction_index, binding});
    }
    return result;
}

CkksRuntimeArtifacts render_ckks_runtime_artifacts(
    const std::string& stem,
    const CkksRuntimeProgram& program,
    std::uint64_t hpu_mem_line_count)
{
    validate_runtime_program(program);
    require_renderable_spans(program, hpu_mem_line_count);
    const std::string identifier = hpu::c_identifier(stem);

    CkksRuntimeArtifacts result;
    result.header = hpu::render_executable_header(stem, program.dma.size());
    const std::string declaration =
        "int hpu_run_" + identifier + "(void);\n\n";
    const std::string header_marker =
        "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    const auto header_position = result.header.find(header_marker);
    if (header_position == std::string::npos) {
        throw std::logic_error(
            "generated executable header has an unexpected structure");
    }
    result.header.insert(header_position, declaration);

    result.source = hpu::render_executable_source(
        stem, program.instructions, hpu_mem_line_count);
    std::ostringstream resolved;
    resolved << "\nstatic const hpu_dma_span_t hpu_program_" << identifier
             << "_resolved_spans[] = {\n";
    for (const auto& dma : program.dma) {
        resolved << "    { UINT32_C(" << dma.binding.span.line_offset
                 << "), UINT32_C(" << dma.binding.span.line_count
                 << ") },\n";
    }
    resolved << "};\n\nint hpu_run_" << identifier << "(void) {\n"
             << "    return hpu_program_" << identifier << "(\n"
             << "        hpu_program_" << identifier
             << "_resolved_spans,\n"
             << "        HPU_PROGRAM_";
    for (char character : identifier) {
        resolved << static_cast<char>(std::toupper(
            static_cast<unsigned char>(character)));
    }
    resolved << "_DMA_COUNT);\n}\n";
    result.source += resolved.str();
    result.resolved_dma_manifest = render_resolved_manifest(program);
    return result;
}

} // namespace hpu::seal_adapter
