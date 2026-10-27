#include "hpu/delivery/resource_compiler.hpp"
#include "hpu/compiler/ssa_optimization.hpp"
#include <tuple>
#include "executable.hpp"
#include "assembler.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>

namespace hpu::delivery {
namespace {

std::string json_string(const std::string& value)
{
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : value) {
        if (c == '"' || c == '\\') out << '\\' << c;
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 32) {
            const char* digits = "0123456789abcdef";
            out << "\\u00" << digits[c >> 4] << digits[c & 15];
        } else out << c;
    }
    return out.str() + '"';
}

const hpu::runtime::HpuMemAllocation& containing_allocation(
    const hpu::runtime::HpuMemImage& image, hpu::runtime::HpuMemSpan span)
{
    for (const auto& allocation : image.allocations()) {
        if (span.line_offset >= allocation.span.line_offset &&
            span.line_count <= allocation.span.line_count &&
            span.line_offset - allocation.span.line_offset <= allocation.span.line_count - span.line_count)
            return allocation;
    }
    throw std::invalid_argument("golden destination has no physical allocation");
}

void append_json_members(std::string& object, const std::string& members)
{
    const auto closing = object.find_last_of('}');
    if (closing == std::string::npos) throw std::invalid_argument("invalid generated JSON object");
    object.insert(closing, "," + members);
}

std::string csv_field(const std::string& value)
{
    std::string result = "\"";
    for (char c : value) {
        if (c == '\"') result += '\"';
        result += c;
    }
    return result + '\"';
}

hpu::ExecutionProfileWindow add_execution_boundaries(
    hpu::compiler::CompiledResources& resources)
{
    const auto arithmetic = [](const auto& item) {
        const auto format = hpu::instruction_format(item.instruction.mnemonic);
        return format == hpu::Format::kAR3 || format == hpu::Format::kSTG;
    };
    const auto& original = resources.instructions;
    const auto first = std::find_if(original.begin(), original.end(), arithmetic);
    const auto last = std::find_if(original.rbegin(), original.rend(), arithmetic);
    if (first == original.end())
        throw std::invalid_argument("execution profiling requires arithmetic instructions");
    const auto first_index = static_cast<std::size_t>(first - original.begin());
    const auto last_index = original.size() - 1 - static_cast<std::size_t>(last - original.rbegin());
    const auto sync = hpu::assemble_source("psync\n").front();
    std::vector<hpu::EncodedInstruction> instructions;
    instructions.reserve(original.size() + 2);
    std::vector<std::size_t> remap(original.size());
    for (std::size_t index = 0; index < original.size(); ++index) {
        if (index == first_index &&
            (index == 0 || original[index - 1].instruction.mnemonic != hpu::Mnemonic::kPsync))
            instructions.push_back(sync);
        remap[index] = instructions.size();
        instructions.push_back(original[index]);
        if (index == last_index &&
            (index + 1 == original.size() ||
             original[index + 1].instruction.mnemonic != hpu::Mnemonic::kPsync))
            instructions.push_back(sync);
    }
    const hpu::ExecutionProfileWindow window{remap[first_index], remap[last_index] + 1};
    for (auto& dma : resources.dma) dma.instruction_index = remap.at(dma.instruction_index);
    resources.instructions = std::move(instructions);
    hpu::validate_execution_profile_window(resources.instructions, window);
    return window;
}

void render_program(ProgramArtifacts& program, const hpu::compiler::CompiledResources& resources)
{
    const auto identifier = hpu::c_identifier(program.stem);
    program.header = hpu::render_executable_header(program.stem, resources.dma.size());
    const std::string marker = "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    const auto position = program.header.find(marker);
    if (position == std::string::npos) throw std::logic_error("unexpected runtime header layout");
    program.header.insert(position, "int hpu_run_" + identifier + "(void);\n\n");
    program.instructions = resources.instructions;
    std::vector<hpu::ExecutableDmaSpan> fixed_spans;
    std::ostringstream manifest, assembly;
    manifest << "instruction_index,dma_index,operation_index,operation_id,operation_dma_index,direction,object_slot,type_or_release,flag,allocation_id,line_offset,line_count,word_hex,normalized_asm,cp\n";
    std::map<std::string, std::size_t> operation_indices;
    program.ordered_dma_spans.clear();
    program.resource_dma = resources.dma;
    for (std::size_t i = 0; i < resources.dma.size(); ++i) {
        const auto& dma = resources.dma[i];
        const auto& encoded = resources.instructions.at(dma.instruction_index);
        const auto& inst = encoded.instruction;
        const bool load = inst.mnemonic == hpu::Mnemonic::kDload;
        const auto operation_dma_index = operation_indices[dma.operation_id]++;
        program.resource_dma[i].operation_dma_index = operation_dma_index;
        fixed_spans.push_back({dma.span.line_offset, dma.span.line_count});
        manifest << dma.instruction_index << ',' << i << ',';
        if (dma.operation_index) manifest << *dma.operation_index;
        manifest << ',' << csv_field(dma.operation_id) << ',' << operation_dma_index << ','
                 << (load ? "dload" : "dstore") << ',' << unsigned(inst.obj_id) << ',' << unsigned(inst.type)
                 << ',' << (load ? unsigned(inst.dma_flag) : 0) << ',' << csv_field(dma.allocation_id)
                 << ',' << dma.span.line_offset << ',' << dma.span.line_count << ','
                 << hpu::format_word_hex(encoded.word) << ',' << csv_field(encoded.normalized_asm) << ',' << unsigned(inst.cp) << '\n';
        program.ordered_dma_spans.push_back(dma.span);
    }
    program.source = hpu::render_fixed_executable_source(
        program.stem, program.instructions, resources.image.capacity_lines(), fixed_spans);
    if (program.profile_execution) {
        const auto& window = program.execution_profile.value();
        program.header = hpu::render_profiled_executable_header(
            program.stem, program.instructions, resources.dma.size(), window);
        program.source = hpu::render_profiled_executable_source(
            program.stem, program.instructions, resources.image.capacity_lines(), fixed_spans, window);
    }
    program.resolved_dma_manifest = manifest.str();
    for (const auto& instruction : program.instructions) assembly << instruction.normalized_asm << '\n';
    program.assembly = assembly.str();
}

} // namespace

std::string compile_application_resources(
    hpu::delivery::ApplicationPackageRequest& request,
    hpu::runtime::HpuMemImage& image, bool optimize, bool require_instruction_verification,
    hpu::model::InstructionNttContract instruction_ntt_contract,
    bool profile_execution)
{
    if (request.program.resources_compiled)
        throw std::invalid_argument("application resources are already compiled");
    hpu::model::InstructionExecutionOptions execution_options;
    execution_options.ntt_contract = instruction_ntt_contract;
    std::optional<hpu::model::InstructionExecutionResult> baseline_execution;
    std::vector<hpu::runtime::HpuMemSpan> baseline_output_spans;
    hpu::compiler::CompileOptions options;
    options.dma_cache_policy = hpu::compiler::DmaCachePolicy::twiddle_loads_only;
    options.automatic_lifetimes = true;
    options.prune_unused_buffers = true;
    options.optimization = optimize ? hpu::compiler::OptimizationMode::optimized
                                   : hpu::compiler::OptimizationMode::no_opt;
    using Layout = hpu::compiler::MemoryLayout;
    using Kind = hpu::runtime::AllocationKind;
    for (const auto& allocation : image.allocations()) {
        if (allocation.kind == Kind::ciphertext && allocation.read_only)
            options.buffer_layouts.emplace(allocation.id,
                request.scheme == hpu::delivery::SchemeKind::bfv
                    ? Layout::coefficient_bit_reversed : Layout::canonical_ntt_physical);
        else if (allocation.kind == Kind::evaluation_key
            || (allocation.kind == Kind::plaintext
                && request.scheme != hpu::delivery::SchemeKind::bfv))
            options.buffer_layouts.emplace(allocation.id, Layout::canonical_ntt_physical);
    }
    // Output labels describe the golden ABI, not a claim that the instruction
    // stream has already produced those words. Mutable transform scratch can
    // cross domains and is deliberately not assigned one permanent layout.
    for (const auto& output : request.outputs) {
        const auto& allocation = containing_allocation(image, output.destination);
        options.required_outputs.insert(allocation.id);
        const auto layout = output.domain == hpu::delivery::OutputDomain::coefficient
            ? Layout::coefficient_natural
            : output.domain == hpu::delivery::OutputDomain::coefficient_bit_reversed
                ? Layout::coefficient_bit_reversed : Layout::canonical_ntt_physical;
        const auto inserted = options.buffer_layouts.emplace(allocation.id, layout);
        if (!inserted.second && inserted.first->second != layout)
            throw std::invalid_argument("conflicting output buffer layouts: " + allocation.id);
    }
    if (!request.program.operator_program)
        throw std::invalid_argument("resource compilation requires native operator IR");
    const auto& dma = request.program.resource_dma;
    if (dma.size() != request.program.ordered_dma_spans.size())
        throw std::invalid_argument("native operator DMA ports are incomplete");
    for (std::size_t i = 0; i < dma.size(); ++i) {
        const auto span = request.program.ordered_dma_spans[i];
        if (span.line_offset != dma[i].span.line_offset || span.line_count != dma[i].span.line_count)
            throw std::invalid_argument("native operator DMA port disagrees with baseline span");
    }
    auto source = *request.program.operator_program;
    if (!dma.empty()) source.bind_ports(dma);
    // Immutable inputs have one layout for their entire lifetime. Mutable
    // transform scratch crosses domains and must not receive a permanent tag.
    for (auto& port : source.ports) {
        if (!port.binding || !port.load) continue;
        const auto& allocation = image.allocation(port.binding->allocation_id);
        if (!allocation.read_only) continue;
        if (port.layout != Layout::unspecified) {
            const auto inserted = options.buffer_layouts.emplace(allocation.id, port.layout);
            if (!inserted.second && inserted.first->second != port.layout)
                throw std::invalid_argument("conflicting input buffer layouts: " + allocation.id);
        } else {
            const auto found = options.buffer_layouts.find(allocation.id);
            if (found != options.buffer_layouts.end()) port.layout = found->second;
        }
    }
    const auto compile_candidate = [&](const hpu::resource::OperatorProgram& native,
                                       bool optimized, const char* name) {
        auto candidate_options = options;
        candidate_options.optimization = optimized ? hpu::compiler::OptimizationMode::optimized
                                                  : hpu::compiler::OptimizationMode::no_opt;
        auto virtual_program = hpu::resource::bind_program(native, image);
        auto candidate = hpu::compiler::compile_resources(std::move(virtual_program), {}, dma, image,
                                                         candidate_options);
        candidate.report.selected_schedule = name;
        return candidate;
    };
    std::optional<std::pair<std::uint64_t, std::size_t>> checkpoint_cost;
    std::string checkpoint_error;
    try {
        auto canonical = hpu::resource::canonical_operator_program(source, image, options.required_outputs);
        const auto checkpoints = compile_candidate(canonical, false, "all_checkpoints");
        checkpoint_cost = std::make_pair(checkpoints.report.dload_bytes + checkpoints.report.dstore_bytes,
                                         checkpoints.dma.size());
    } catch (const hpu::compiler::ResourceCapacityError& error) {
        // An unreachable branch must not block a valid required-output graph
        // merely because this optional full-source diagnostic cannot fit.
        checkpoint_error = error.what();
    }
    auto policy_only = hpu::resource::output_root_operator_program(source, image, options.required_outputs);
    auto resources = compile_candidate(policy_only, false, "original");
    std::optional<hpu::resource::OperatorProgram> selected_native;
    if (profile_execution) selected_native = policy_only;
    bool selected_optimized = false;
    for (const auto& output : request.outputs) {
        const auto& allocation = containing_allocation(image, output.destination);
        baseline_output_spans.push_back(hpu::compiler::relocate_span(resources, allocation.id, output.destination));
    }
    std::vector<hpu::runtime::HpuMemSpan> canonical_spans;
    for (const auto& entry : resources.dma) canonical_spans.push_back(entry.span);
    baseline_execution = hpu::model::execute_instructions(
        resources.instructions, canonical_spans, resources.image, execution_options);
    const auto baseline_dma_bytes = resources.report.dload_bytes + resources.report.dstore_bytes;
    const auto baseline_dma_count = resources.dma.size();
    const auto key = [](const hpu::compiler::CompiledResources& candidate) {
        return std::make_tuple(candidate.report.dload_bytes + candidate.report.dstore_bytes,
                               candidate.dma.size(), candidate.instructions.size());
    };
    std::ostringstream candidate_reports;
    candidate_reports << "{\"name\":\"original\",\"dma_bytes\":" << baseline_dma_bytes
        << ",\"dma_count\":" << resources.dma.size() << '}';
    if (optimize) {
        for (const bool reorder : {false, true}) {
            hpu::resource::SsaOptimizationReport pass_report;
            const auto native = hpu::resource::optimize_operator_program(
                source, image, options.required_outputs, reorder, &pass_report);
            const auto* name = reorder ? "reordered" : "reuse";
            try {
                auto candidate = compile_candidate(native, true, name);
                candidate_reports << ",{\"name\":" << json_string(name)
                    << ",\"dma_bytes\":" << candidate.report.dload_bytes + candidate.report.dstore_bytes
                    << ",\"dma_count\":" << candidate.dma.size()
                    << ",\"merged_reads\":" << pass_report.merged_reads
                    << ",\"forwarded_reads\":" << pass_report.forwarded_reads
                    << ",\"dead_operations\":" << pass_report.dead_operations << '}';
                if (key(candidate) < key(resources)) {
                    resources = std::move(candidate);
                    if (profile_execution) selected_native = native;
                    selected_optimized = true;
                }
            } catch (const hpu::compiler::ResourceCapacityError& error) {
                candidate_reports << ",{\"name\":" << json_string(name)
                    << ",\"status\":\"infeasible\",\"reason\":" << json_string(error.what()) << '}';
            }
        }
    }
    const auto unprofiled_dma_bytes = resources.report.dload_bytes + resources.report.dstore_bytes;
    const auto unprofiled_dma_count = resources.dma.size();
    request.program.profile_execution = profile_execution;
    request.program.execution_profile.reset();
    if (profile_execution) {
        options.preload_readonly_inputs = true;
        resources = compile_candidate(*selected_native, selected_optimized, "entry_preload");
        request.program.execution_profile = add_execution_boundaries(resources);
    }
    resources.report.original_dma_bytes = baseline_dma_bytes;
    resources.report.original_dma_count = baseline_dma_count;
    for (auto& output : request.outputs) {
        const auto& allocation = containing_allocation(image, output.destination);
        output.destination = hpu::compiler::relocate_span(resources, allocation.id, output.destination);
    }

    render_program(request.program, resources);
    request.program.dma_cache_policy = options.dma_cache_policy;

    auto resource_report = hpu::compiler::render_resource_report(resources);
    std::uint64_t removed_checkpoint_bytes = 0;
    for (const auto& allocation : image.allocations())
        if (allocation.kind == Kind::output && !options.required_outputs.count(allocation.id))
            removed_checkpoint_bytes += allocation.span.line_count * 256;
    append_json_members(resource_report,
        "\"candidate_schedules\":[" + candidate_reports.str() + "]" +
        ",\"all_checkpoint_status\":" + json_string(checkpoint_cost ? "compiled" : "infeasible") +
        ",\"all_checkpoint_reason\":" + json_string(checkpoint_error) +
        ",\"all_checkpoint_dma_bytes\":" + (checkpoint_cost ? std::to_string(checkpoint_cost->first) : "null") +
        ",\"all_checkpoint_dma_count\":" + (checkpoint_cost ? std::to_string(checkpoint_cost->second) : "null") +
        ",\"output_policy_saved_dma_bytes\":" +
            (checkpoint_cost ? std::to_string(static_cast<std::int64_t>(checkpoint_cost->first) -
                static_cast<std::int64_t>(baseline_dma_bytes)) : "null") +
        ",\"removed_checkpoint_min_write_bytes\":" + std::to_string(removed_checkpoint_bytes));
    image = std::move(resources.image);
    request.initial_image = &image;
    const auto execution = hpu::model::execute_instructions(
        request.program.instructions, request.program.ordered_dma_spans, image, execution_options);
    std::vector<hpu::model::InstructionMemoryExpectation> expected;
    for (const auto& output : request.outputs)
        expected.push_back({output.object_id + "/c" + std::to_string(output.component) +
            "/q" + std::to_string(output.modulus_id), output.destination, output.golden_words});
    const auto comparison = hpu::model::compare_instruction_memory(execution, expected);
    bool optimization_verified = !optimize;
    if (baseline_execution && baseline_execution->report.completed() && execution.report.completed()) {
        std::vector<hpu::model::InstructionMemoryExpectation> baseline_expected;
        for (std::size_t i = 0; i < request.outputs.size(); ++i) {
            const auto begin = baseline_output_spans[i].line_offset * hpu::runtime::kHpuMemLineWords;
            const auto& output = request.outputs[i];
            const auto& words = baseline_execution->words;
            if (begin > words.size() || output.word_count > words.size() - begin)
                throw std::runtime_error("baseline instruction output exceeds image");
            baseline_expected.push_back({expected[i].id, output.destination,
                std::vector<std::uint32_t>(words.begin() + begin, words.begin() + begin + output.word_count)});
        }
        const auto equivalence = hpu::model::compare_instruction_memory(execution, baseline_expected);
        if (!equivalence.verified)
            throw std::runtime_error("resource optimization changed encoded execution: " + equivalence.message);
        optimization_verified = true;
    }
    const auto status = comparison.verified ? "pass" : execution.report.completed() ? "fail" :
        execution.report.status == hpu::model::InstructionExecutionStatus::unsupported_contract ? "unsupported" : "fail";
    const auto message = execution.report.completed() ? comparison.message : execution.report.message;
    if ((require_instruction_verification || profile_execution) && !comparison.verified)
        throw std::runtime_error("encoded instruction verification " + std::string(status)
            + " [" + hpu::model::instruction_ntt_contract_name(execution.report.ntt_contract)
            + "]: " + message);

    std::ostringstream diagnostic;
    diagnostic << "{\"status\":" << json_string(status)
        << ",\"required\":" << (require_instruction_verification ? "true" : "false")
        << ",\"verified\":" << (comparison.verified ? "true" : "false")
        << ",\"ntt_contract\":" << json_string(
            hpu::model::instruction_ntt_contract_name(execution.report.ntt_contract))
        << ",\"hardware_contract_verified\":"
            << (execution.report.hardware_contract_verified ? "true" : "false")
        << ",\"forward_boundary_conversions\":" << execution.report.forward_boundary_conversions
        << ",\"inverse_boundary_conversions\":" << execution.report.inverse_boundary_conversions
        << ",\"message\":" << json_string(message)
        << ",\"executed_instructions\":" << execution.report.executed_instructions
        << ",\"instruction_index\":" << execution.report.instruction_index
        << ",\"compared_words\":" << comparison.compared_words
        << ",\"object_id\":" << json_string(comparison.object_id)
        << ",\"object_word_index\":" << comparison.object_word_index
        << ",\"expected\":" << comparison.expected << ",\"actual\":" << comparison.actual << '}';
    append_json_members(request.oracle_report_json,
        "\"compiler_resources\":" + resource_report +
        ",\"host_instruction_model\":" + diagnostic.str() +
        ",\"host_instruction_model_verified\":" + (comparison.verified ? "true" : "false") +
        ",\"optimization_equivalence_verified\":" + (optimization_verified ? "true" : "false"));
    if (profile_execution) {
        const auto& window = *request.program.execution_profile;
        std::size_t prefix_loads = 0, body_loads = 0, body_stores = 0, suffix_stores = 0;
        for (const auto& dma_entry : resources.dma) {
            const auto index = dma_entry.instruction_index;
            const auto mnemonic = resources.instructions[index].instruction.mnemonic;
            if (index < window.begin_instruction && mnemonic == hpu::Mnemonic::kDload) ++prefix_loads;
            else if (index >= window.end_instruction && mnemonic == hpu::Mnemonic::kDstore) ++suffix_stores;
            else if (index >= window.begin_instruction && index < window.end_instruction) {
                if (mnemonic == hpu::Mnemonic::kDload) ++body_loads;
                else if (mnemonic == hpu::Mnemonic::kDstore) ++body_stores;
            }
        }
        append_json_members(request.oracle_report_json,
            "\"execution_profile\":{\"enabled\":true,\"window_count\":1,"
            "\"timing_measured\":false,\"includes_residual_dma\":true,"
            "\"prefix_dload_count\":" + std::to_string(prefix_loads) +
            ",\"window_dload_count\":" + std::to_string(body_loads) +
            ",\"window_dstore_count\":" + std::to_string(body_stores) +
            ",\"suffix_dstore_count\":" + std::to_string(suffix_stores) +
            ",\"unprofiled_dma_bytes\":" + std::to_string(unprofiled_dma_bytes) +
            ",\"unprofiled_dma_count\":" + std::to_string(unprofiled_dma_count) + "}");
    }
    request.program.resources_compiled = true;
    hpu::delivery::validate_application_package_request(request);
    return resource_report;
}

} // namespace hpu::delivery
