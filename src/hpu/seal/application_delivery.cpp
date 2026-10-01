#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "assembler.hpp"
#include "executable.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <locale>
#include <sstream>
#include <stdexcept>

#ifndef HPU_DELIVERY_REVISION
#define HPU_DELIVERY_REVISION "unknown"
#endif
#ifndef HPU_DELIVERY_TREE_STATE
#define HPU_DELIVERY_TREE_STATE "unknown"
#endif

namespace hpu::seal_adapter {
namespace {
using hpu::delivery::ApplicationPackageRequest;
using hpu::delivery::SchemeKind;

std::ostringstream stream()
{
    std::ostringstream out;
    out.imbue(std::locale::classic());
    out << std::setprecision(17);
    return out;
}

std::string quoted(const std::string& value)
{
    auto out = stream();
    out << '"';
    for (unsigned char ch : value) {
        if (ch == '"' || ch == '\\') out << '\\' << ch;
        else if (ch < 32) out << "\\u" << std::hex << std::setw(4)
                              << std::setfill('0') << unsigned(ch) << std::dec;
        else out << ch;
    }
    out << '"';
    return out.str();
}

std::string parms_id_json(const ::seal::parms_id_type& id)
{
    auto out = stream();
    out << '[';
    for (std::size_t i = 0; i < id.size(); ++i) {
        if (i) out << ',';
        out << id[i];
    }
    out << ']';
    return out.str();
}

ApplicationPackageRequest base_request(
    const std::string& stem, const ::seal::SEALContext& context,
    SchemeKind scheme, const hpu::runtime::HpuMemImage& image)
{
    const auto expected = scheme == SchemeKind::ckks ? ::seal::scheme_type::ckks
        : scheme == SchemeKind::bfv ? ::seal::scheme_type::bfv : ::seal::scheme_type::bgv;
    if (!context.parameters_set() || context.key_context_data()->parms().scheme() != expected)
        throw std::invalid_argument("delivery scheme/context mismatch");
    ApplicationPackageRequest request;
    request.scheme = scheme;
    request.case_name = stem;
    request.initial_image = &image;
    request.program.stem = stem;
    const char* commit = std::getenv("HPU_DELIVERY_COMMIT");
    const char* state = std::getenv("HPU_DELIVERY_WORKTREE_STATE");
    request.producer = {"inline-asm", commit ? commit : HPU_DELIVERY_REVISION,
                        state ? state : HPU_DELIVERY_TREE_STATE};
    auto out = stream();
    const auto key = context.key_context_data();
    out << "{\"scheme\":" << quoted(scheme == SchemeKind::ckks ? "ckks" :
                                        scheme == SchemeKind::bfv ? "bfv" : "bgv")
        << ",\"poly_modulus_degree\":" << key->parms().poly_modulus_degree()
        << ",\"security_level_bits\":" << static_cast<int>(key->qualifiers().sec_level)
        << ",\"plain_modulus\":" << key->parms().plain_modulus().value()
        << ",\"key_moduli\":[";
    for (std::size_t i = 0; i < key->parms().coeff_modulus().size(); ++i) {
        if (i) out << ',';
        out << key->parms().coeff_modulus()[i].value();
    }
    out << "],\"levels\":[";
    bool first = true;
    for (auto level = context.first_context_data(); level; level = level->next_context_data()) {
        if (!first) out << ',';
        first = false;
        out << "{\"parms_id\":" << parms_id_json(level->parms_id())
            << ",\"chain_index\":" << level->chain_index() << ",\"moduli\":[";
        for (std::size_t i = 0; i < level->parms().coeff_modulus().size(); ++i) {
            if (i) out << ',';
            out << level->parms().coeff_modulus()[i].value();
        }
        out << "]}";
    }
    out << "]}\n";
    request.parameters_json = out.str();
    return request;
}

void append_outputs(ApplicationPackageRequest& request,
                    const ::seal::SEALContext& context,
                    const std::string& allocation_prefix, std::size_t step_index,
                    const ::seal::Ciphertext& oracle,
                    const std::vector<std::uint32_t>* model)
{
    if (oracle.size() == 0 || !::seal::is_valid_for(oracle, context))
        throw std::invalid_argument("delivery oracle ciphertext is invalid");
    const auto& image = *request.initial_image;
    if (model && model->size() != image.words().size())
        throw std::invalid_argument("delivery executed image size differs from initial image");
    for (std::size_t component = 0; component < oracle.size(); ++component) {
        const auto words = request.scheme == SchemeKind::bfv
            ? bfv_ciphertext_component_to_hpu(oracle, component, context)
            : ciphertext_component_to_hpu(oracle, component, context);
        for (std::size_t limb = 0; limb < words.modulus_ids.size(); ++limb) {
            const auto mod_id = words.modulus_ids[limb];
            const auto id = allocation_prefix + "/c" + std::to_string(component)
                + "/mod" + std::to_string(mod_id);
            const auto& allocation = image.allocation(id);
            if (allocation.kind != hpu::runtime::AllocationKind::output ||
                allocation.read_only || allocation.word_count != words.degree)
                throw std::invalid_argument("delivery output shape/kind mismatch: " + id);
            const std::size_t offset = allocation.span.line_offset * hpu::runtime::kHpuMemLineWords;
            const auto begin = words.words.begin() + limb * words.degree;
            if (model) {
                for (std::size_t i = 0; i < words.degree; ++i) {
                    if (model->at(offset + i) != begin[i])
                        throw std::runtime_error("delivery SEAL/model mismatch: " + id +
                                                 " word " + std::to_string(i));
                }
            }
            hpu::delivery::VerifiedOutputLimb output;
            output.object_id = "step_" + std::to_string(step_index);
            output.component = component;
            output.modulus_id = mod_id;
            output.modulus = words.moduli[limb];
            output.domain = request.scheme == SchemeKind::bfv
                ? hpu::delivery::OutputDomain::coefficient
                : hpu::delivery::OutputDomain::canonical_ntt_physical;
            output.destination = allocation.span;
            output.word_count = words.degree;
            output.golden_words.assign(begin, begin + words.degree);
            request.outputs.push_back(std::move(output));
        }
    }
}

const char* name(CkksOperationKind kind)
{
    switch (kind) {
#define OP(x) case CkksOperationKind::x: return #x
        OP(add); OP(subtract); OP(multiply); OP(multiply_plain); OP(square);
        OP(relinearize); OP(rescale); OP(add_plain); OP(subtract_plain);
        OP(negate); OP(rotate); OP(conjugate);
#undef OP
    }
    throw std::invalid_argument("unknown CKKS operation");
}
const char* name(BfvOperationKind kind)
{
    switch (kind) {
#define OP(x) case BfvOperationKind::x: return #x
        OP(add); OP(subtract); OP(multiply); OP(add_plain); OP(subtract_plain);
        OP(multiply_plain); OP(negate); OP(mod_switch); OP(rotate_rows); OP(rotate_columns);
#undef OP
    }
    throw std::invalid_argument("unknown BFV operation");
}
const char* name(BgvPlainOperationKind kind)
{
    switch (kind) {
    case BgvPlainOperationKind::add: return "add_plain";
    case BgvPlainOperationKind::subtract: return "subtract_plain";
    case BgvPlainOperationKind::multiply: return "multiply_plain";
    case BgvPlainOperationKind::add_ciphertext: return "add";
    case BgvPlainOperationKind::subtract_ciphertext: return "subtract";
    case BgvPlainOperationKind::multiply_ciphertext: return "multiply_relinearize";
    case BgvPlainOperationKind::rotate_rows: return "rotate_rows";
    case BgvPlainOperationKind::rotate_columns: return "rotate_columns";
    case BgvPlainOperationKind::modswitch_to_next: return "mod_switch";
    }
    throw std::invalid_argument("unknown BGV operation");
}

void output_metadata(std::ostringstream& graph, const std::string& id,
                     const ::seal::Ciphertext& oracle, std::size_t index)
{
    graph << ",\"output\":" << quoted(id)
          << ",\"golden_object_id\":\"step_" << index << '"'
          << ",\"parms_id\":" << parms_id_json(oracle.parms_id())
          << ",\"component_count\":" << oracle.size()
          << ",\"scale\":" << oracle.scale()
          << ",\"correction_factor\":" << oracle.correction_factor();
}

void report(ApplicationPackageRequest& request, const char* model)
{
    auto out = stream();
    out << "{\"oracle\":\"modified-SEAL Evaluator\",\"golden_source\":\"SEAL ciphertext in HPU layout\","
           "\"model\":" << (model ? quoted(model) : "null")
        << ",\"raw_physical_words_equal\":" << (model ? "true" : "null")
        << ",\"model_verified\":" << (model ? "true" : "false")
        << ",\"verified_limb_count\":" << request.outputs.size()
        << ",\"instruction_execution_verified\":false,\"rtl_verified\":false,\"hardware_verified\":false}\n";
    request.oracle_report_json = out.str();
}

void check_scale(const CkksPlannedValue& value, const ::seal::Ciphertext& oracle)
{
    if (!std::isfinite(value.metadata.scale) || !std::isfinite(oracle.scale()) ||
        value.metadata.scale <= 0 || oracle.scale() <= 0 ||
        std::abs(value.metadata.scale - oracle.scale()) >
            1e-12 * std::max(value.metadata.scale, oracle.scale()))
        throw std::invalid_argument("delivery oracle scale differs from planned output");
}
void check_scale(const BfvPlannedValue&, const ::seal::Ciphertext&) {}

template<class Lowered, class Runtime, class Artifacts>
ApplicationPackageRequest make_planned(
    const std::string& stem, const ::seal::SEALContext& context, SchemeKind scheme,
    const Lowered& lowered, const Runtime& runtime, const Artifacts& artifacts,
    const hpu::runtime::HpuMemImage& image,
    const std::vector<::seal::Ciphertext>& oracles,
    const std::vector<std::uint32_t>& executed)
{
    if (lowered.operations.empty() || oracles.size() != lowered.operations.size())
        throw std::invalid_argument("delivery requires one SEAL oracle snapshot per operation");
    auto request = base_request(stem, context, scheme, image);
    request.program = {stem, lowered.body_asm, runtime.instructions, artifacts.header,
                       artifacts.source, artifacts.resolved_dma_manifest, runtime.spans()};
    auto graph = stream();
    graph << "{\"operations\":[";
    for (std::size_t i = 0; i < oracles.size(); ++i) {
        const auto& step = lowered.operations[i].operation;
        const auto& oracle = oracles[i];
        const auto& value = step.output;
        if (value.metadata.parms_id != oracle.parms_id() ||
            value.component_count != oracle.size() || value.key_domain != 1 ||
            value.domain != (scheme == SchemeKind::bfv
                ? hpu::runtime::PolynomialDomain::coefficient
                : hpu::runtime::PolynomialDomain::canonical_ntt_physical))
            throw std::invalid_argument("delivery oracle metadata differs from planned output: " + value.id);
        check_scale(value, oracle);
        append_outputs(request, context, value.id, i, oracle, &executed);
        if (i) graph << ',';
        graph << "{\"id\":" << quoted(step.id) << ",\"kind\":" << quoted(name(step.kind))
              << ",\"inputs\":[";
        for (std::size_t j = 0; j < step.inputs.size(); ++j) {
            if (j) graph << ',';
            graph << quoted(step.inputs[j].id);
        }
        graph << "],\"workspaces\":[";
        for (std::size_t j = 0; j < step.workspaces.size(); ++j) {
            if (j) graph << ',';
            graph << quoted(step.workspaces[j].id);
        }
        graph << ']';
        output_metadata(graph, value.id, oracle, i);
        graph << '}';
    }
    graph << "],\"final_output\":" << quoted(lowered.operations.back().operation.output.id) << "}\n";
    request.operation_graph_json = graph.str();
    report(request, scheme == SchemeKind::ckks ? "CkksSoftwareExecutor" : "BfvSoftwareExecutor");
    hpu::delivery::validate_application_package_request(request);
    return request;
}
} // namespace

hpu::delivery::ApplicationPackageRequest make_ckks_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const CkksLoweredProgram& lowered, const CkksRuntimeProgram& runtime,
    const CkksRuntimeArtifacts& artifacts, const hpu::runtime::HpuMemImage& image,
    const std::vector<::seal::Ciphertext>& oracles,
    const std::vector<std::uint32_t>& executed)
{
    return make_planned(stem, context, SchemeKind::ckks, lowered, runtime, artifacts,
                        image, oracles, executed);
}

hpu::delivery::ApplicationPackageRequest make_bfv_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const BfvLoweredProgram& lowered, const BfvRuntimeProgram& runtime,
    const BfvRuntimeArtifacts& artifacts, const hpu::runtime::HpuMemImage& image,
    const std::vector<::seal::Ciphertext>& oracles,
    const std::vector<std::uint32_t>& executed)
{
    return make_planned(stem, context, SchemeKind::bfv, lowered, runtime, artifacts,
                        image, oracles, executed);
}

hpu::delivery::ApplicationPackageRequest make_bgv_application_package(
    const std::string& stem, const ::seal::SEALContext& context,
    const BgvLinearOperationPlan& plan, const BgvKeySwitchApplication& application,
    const std::vector<::seal::Ciphertext>& oracles)
{
    if (oracles.empty() || oracles.size() != plan.steps().size())
        throw std::invalid_argument("BGV delivery requires one SEAL oracle snapshot per operation");
    if (application.parms_id != oracles.back().parms_id() ||
        application.correction_factor != oracles.back().correction_factor())
        throw std::invalid_argument("BGV delivery oracle metadata differs from application");
    auto request = base_request(stem, context, SchemeKind::bgv, application.image);
    const auto artifacts = render_bgv_keyswitch_runtime_artifacts(stem, application);
    auto& program = request.program;
    program.instructions = application.instructions;
    program.ordered_dma_spans = application.spans();
    program.header = artifacts.header;
    program.source = artifacts.source;
    for (const auto& instruction : program.instructions)
        program.assembly += instruction.normalized_asm + '\n';
    // Normalize BGV's original six-column CSV to the common resolved DMA ABI.
    auto manifest = stream();
    manifest << "instruction_index,dma_index,operation_index,operation_id,operation_dma_index,"
                "direction,object_slot,type_or_release,flag,allocation_id,line_offset,line_count,word_hex,normalized_asm\n";
    for (const auto& dma : application.dma) {
        const auto& instruction = application.instructions.at(dma.instruction_index);
        manifest << dma.instruction_index << ',' << dma.dma_index << ",,application,"
                 << dma.dma_index << ',' << hpu::to_string(dma.direction) << ','
                 << unsigned(dma.object_slot) << ',' << unsigned(dma.type_or_release) << ','
                 << unsigned(dma.flag) << ',' << '"' << dma.allocation_id << "\","
                 << dma.span.line_offset << ',' << dma.span.line_count << ','
                 << hpu::format_word_hex(instruction.word) << ",\"" << instruction.normalized_asm << "\"\n";
    }
    program.resolved_dma_manifest = manifest.str();
    auto graph = stream();
    graph << "{\"operations\":[";
    std::string prior = "input";
    for (std::size_t i = 0; i < oracles.size(); ++i) {
        const auto& step = plan.steps()[i];
        const auto prefix = i + 1 == oracles.size() ? "output" : "steps/" + step.id + "/output";
        append_outputs(request, context, prefix, i, oracles[i], nullptr);
        if (i) graph << ',';
        graph << "{\"id\":" << quoted(step.id) << ",\"kind\":" << quoted(name(step.kind))
              << ",\"inputs\":[" << quoted(prior);
        if (step.kind == BgvPlainOperationKind::add ||
            step.kind == BgvPlainOperationKind::subtract ||
            step.kind == BgvPlainOperationKind::multiply)
            graph << ',' << quoted("steps/" + step.id + "/plain");
        else if (step.kind == BgvPlainOperationKind::add_ciphertext ||
                 step.kind == BgvPlainOperationKind::subtract_ciphertext)
            graph << ',' << quoted("steps/" + step.id + "/right");
        else if (step.kind == BgvPlainOperationKind::multiply_ciphertext)
            graph << ',' << quoted("steps/" + step.id + "/multiply/input/right");
        graph << "],\"rotation_steps\":" << step.rotation_steps;
        output_metadata(graph, prefix, oracles[i], i);
        graph << '}';
        prior = prefix;
    }
    graph << "],\"final_output\":\"output\"}\n";
    request.operation_graph_json = graph.str();
    report(request, nullptr);
    hpu::delivery::validate_application_package_request(request);
    return request;
}

hpu::delivery::SemanticReport ckks_delivery_semantics(
    const std::vector<double>& decoded, std::size_t count, double error, double tolerance)
{
    if (count == 0 || count > decoded.size() || !std::isfinite(error) ||
        !std::isfinite(tolerance) || error < 0 || tolerance <= 0 || error > tolerance)
        throw std::invalid_argument("invalid CKKS delivery semantic report");
    auto out = stream();
    out << "{\"decoded_model\":[";
    for (std::size_t i = 0; i < count; ++i) {
        if (!std::isfinite(decoded[i])) throw std::invalid_argument("nonfinite decoded value");
        if (i) out << ',';
        out << decoded[i];
    }
    out << "],\"maximum_absolute_error\":" << error << ",\"tolerance\":" << tolerance << "}\n";
    return {"application/json", out.str()};
}

hpu::delivery::SemanticReport integer_delivery_semantics(const std::vector<std::uint64_t>& decoded)
{
    auto out = stream();
    out << "{\"decoded\":[";
    for (std::size_t i = 0; i < decoded.size(); ++i) {
        if (i) out << ',';
        out << decoded[i];
    }
    out << "]}\n";
    return {"application/json", out.str()};
}
} // namespace hpu::seal_adapter
