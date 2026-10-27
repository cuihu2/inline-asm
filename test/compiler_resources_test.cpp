#include "hpu/compiler/resource_ir.hpp"
#include "hpu/compiler/operator_resources.hpp"
#include "hpu/compiler/detail/use_index.hpp"
#include "hpu/model/instruction_executor.hpp"
#include "hpu/model/hardware_ntt.hpp"
#include "assembler.hpp"
#include "encoder.hpp"
#include "executable.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using hpu::compiler::ResolvedDma;
using hpu::runtime::AllocationKind;

void require(bool condition, const char* message)
{
    if (!condition) throw std::runtime_error(message);
}

template <class Function> void require_throws(Function function, const char* message)
{
    try { function(); } catch (const std::exception&) { return; }
    throw std::runtime_error(message);
}

std::vector<ResolvedDma> bindings(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const hpu::runtime::HpuMemImage& image,
    const std::vector<std::string>& ids)
{
    const auto relocations = hpu::collect_dma_relocations(instructions);
    require(relocations.size() == ids.size(), "incorrect test DMA recipe");
    std::vector<ResolvedDma> result;
    for (std::size_t index = 0; index < ids.size(); ++index) {
        result.push_back({relocations[index].instruction_index, ids[index],
            image.allocation(ids[index]).span, index / 3, "node", index});
    }
    return result;
}

// Independent pointwise replay checks that DMA rewrites preserve words and
// that spills never overwrite immutable inputs. NTT math is tested separately.
std::vector<std::uint32_t> replay(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image)
{
    auto memory = image.words();
    std::array<std::vector<std::uint32_t>, 64> objects;
    std::size_t dma_index = 0;
    constexpr std::uint32_t modulus = 65537;
    for (const auto& encoded : instructions) {
        const auto& op = encoded.instruction;
        switch (op.mnemonic) {
        case hpu::Mnemonic::kDload:
        case hpu::Mnemonic::kDstore: {
            const auto& entry = dma.at(dma_index++);
            const auto begin = entry.span.line_offset * 64;
            const auto count = entry.span.line_count * 64;
            if (op.mnemonic == hpu::Mnemonic::kDload) {
                objects[op.obj_id] = std::vector<std::uint32_t>(
                    memory.begin() + begin, memory.begin() + begin + count);
            } else {
                require(objects[op.obj_id].size() == count, "replay store length mismatch");
                std::copy(objects[op.obj_id].begin(), objects[op.obj_id].end(),
                    memory.begin() + begin);
                if (op.type == 1) objects[op.obj_id].clear();
            }
            break;
        }
        case hpu::Mnemonic::kPadd:
        case hpu::Mnemonic::kPsub:
        case hpu::Mnemonic::kPmul:
        case hpu::Mnemonic::kPmac: {
            const auto left = objects[op.psrc1];
            const auto right = op.imm8 < 0 ? objects[op.psrc2]
                : std::vector<std::uint32_t>(left.size(), op.imm8);
            const auto accumulator = objects[op.pdst];
            require(!left.empty() && left.size() == right.size(), "replay operand mismatch");
            auto& destination = objects[op.pdst];
            destination.resize(left.size());
            for (std::size_t index = 0; index < left.size(); ++index) {
                std::uint64_t value = 0;
                switch (op.mnemonic) {
                case hpu::Mnemonic::kPadd: value = left[index] + right[index]; break;
                case hpu::Mnemonic::kPsub: value = left[index] + modulus - right[index]; break;
                default:
                    value = std::uint64_t(left[index]) * right[index];
                    if (op.mnemonic == hpu::Mnemonic::kPmac) value += accumulator[index];
                    break;
                }
                destination[index] = value % modulus;
            }
            break;
        }
        case hpu::Mnemonic::kPfree: objects[op.idx0].clear(); break;
        default: break;
        }
    }
    return memory;
}

std::vector<std::uint32_t> allocation_words(
    const std::vector<std::uint32_t>& memory,
    const hpu::runtime::HpuMemImage& image, const std::string& id)
{
    const auto& allocation = image.allocation(id);
    const auto begin = memory.begin() + allocation.span.line_offset * 64;
    return {begin, begin + allocation.word_count};
}

void test_scratch_reuse()
{
    hpu::runtime::HpuMemImage image(64);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.add("b", std::vector<std::uint32_t>(128, 5), AllocationKind::ciphertext);
    image.add_alias("b_alias", "b");
    image.reserve("scratch/a", 128, AllocationKind::workspace);
    image.reserve("output/a", 128, AllocationKind::output);
    image.reserve("scratch/b", 128, AllocationKind::workspace);
    image.reserve("output/b", 128, AllocationKind::output);
    image.add("scratch/initial", std::vector<std::uint32_t>(128, 9), AllocationKind::workspace, false);
    image.reserve("output/initial", 128, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndload x10, x11, p1, 0, 0, 0\n"
        "padd p2, p0, p1\ndstore x10, x11, p2, 0, 0\npfree p0\npfree p1\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 2\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndload x10, x11, p1, 0, 0, 0\n"
        "padd p2, p0, p1\ndstore x10, x11, p2, 0, 0\npfree p0\npfree p1\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 3\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 2\ndstore x10, x11, p0, 0, 0\n"
        "pfree p4\npsync\n");
    const auto dma = bindings(instructions, image,
        {"moduli", "a", "b_alias", "scratch/a", "scratch/a", "output/a",
         "a", "b", "scratch/b", "scratch/b", "output/b", "scratch/initial", "output/initial"});
    hpu::compiler::CompileOptions optimized_options;
    optimized_options.buffer_layouts.emplace("a", hpu::compiler::MemoryLayout::coefficient_natural);
    optimized_options.buffer_layouts.emplace("b", hpu::compiler::MemoryLayout::coefficient_natural);
    const auto optimized = hpu::compiler::optimize_resources(instructions, dma, image, optimized_options);
    hpu::compiler::CompileOptions options;
    options.optimization = hpu::compiler::OptimizationMode::no_opt;
    options.buffer_layouts = optimized_options.buffer_layouts;
    const auto baseline = hpu::compiler::optimize_resources(instructions, dma, image, options);
    require(baseline.instructions.size() == instructions.size()
            && baseline.image.words() == image.words()
            && baseline.image.capacity_lines() == image.capacity_lines(), "NoOpt altered the image");
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        require(baseline.instructions[index].word == instructions[index].word, "NoOpt altered instruction words");
    }
    require(optimized.report.deferred_scratch_stores == 2
            && optimized.dma.size() + 4 == dma.size(), "unique scratch store/load was not removed");
    require(optimized.image.used_lines() < image.used_lines()
            && optimized.report.scratch_arena_lines == 2, "nonoverlapping scratch buffers were not reused");
    require(optimized.image.contains("scratch/initial"), "initial-memory-dependent scratch was reused");
    for (const auto* resources : {&baseline, &optimized}) {
        for (const auto& buffer : resources->buffers) {
            if (buffer.logical_id == "a" || buffer.logical_id == "b")
                require(buffer.layout == hpu::compiler::MemoryLayout::coefficient_natural,
                        "explicit layout annotation was lost during resource compilation");
            else require(buffer.layout == hpu::compiler::MemoryLayout::unspecified,
                         "compiler invented a layout for an unannotated buffer");
        }
    }
    const auto first = hpu::compiler::relocate_span(optimized, "scratch/a", image.allocation("scratch/a").span);
    const auto second = hpu::compiler::relocate_span(optimized, "scratch/b", image.allocation("scratch/b").span);
    require(first.line_offset == second.line_offset, "disjoint scratch lifetimes did not share DDR");
    const auto original_words = replay(instructions, dma, image);
    const auto optimized_words = replay(optimized.instructions, optimized.dma, optimized.image);
    for (const std::string id : {"output/a", "output/b", "output/initial", "a", "b"}) {
        require(allocation_words(original_words, image, id)
                    == allocation_words(optimized_words, optimized.image, id), "optimized words differ from baseline");
    }
    const auto again = hpu::compiler::optimize_resources(instructions, dma, image, optimized_options);
    require(again.image.words() == optimized.image.words()
            && hpu::compiler::render_resource_report(again)
                == hpu::compiler::render_resource_report(optimized), "resource allocation is nondeterministic");
    for (std::size_t index = 0; index < again.instructions.size(); ++index) {
        require(again.instructions[index].word == optimized.instructions[index].word,
                "slot scheduling is nondeterministic");
    }
    auto invalid = dma;
    invalid.front().span.line_count += 1;
    require_throws([&] { hpu::compiler::import_resolved_program(instructions, invalid, image); },
                   "DMA range outside allocation accepted");
    options.buffer_layouts.emplace("absent", hpu::compiler::MemoryLayout::coefficient_bit_reversed);
    require_throws([&] { hpu::compiler::optimize_resources(instructions, dma, image, options); },
                   "layout annotation for an absent buffer was accepted");
    options.buffer_layouts.erase("absent");
    options.buffer_layouts["a"] = static_cast<hpu::compiler::MemoryLayout>(100);
    require_throws([&] { hpu::compiler::optimize_resources(instructions, dma, image, options); },
                   "invalid layout annotation was accepted");
}

void test_dirty_spill()
{
    hpu::runtime::HpuMemImage image(8192);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    for (int index = 0; index < 6; ++index) {
        image.add("input/" + std::to_string(index), std::vector<std::uint32_t>(65536, index + 1),
            AllocationKind::ciphertext);
    }
    image.reserve("output", 65536, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 1, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 1, 0\npmul p0, p0, 2\n"
        "dload x10, x11, p1, 0, 1, 0\ndload x10, x11, p2, 0, 1, 0\n"
        "dload x10, x11, p3, 0, 1, 0\ndload x10, x11, p5, 0, 1, 0\n"
        "dload x10, x11, p6, 0, 1, 0\n"
        "padd p1, p1, p2\npfree p2\npadd p3, p3, p5\npfree p5\n"
        "padd p6, p6, p1\npfree p1\npadd p0, p0, p3\npfree p3\n"
        "padd p0, p0, p6\npfree p6\ndstore x10, x11, p0, 0, 1\npfree p4\npsync\n");
    const auto dma = bindings(instructions, image,
        {"moduli", "input/0", "input/1", "input/2", "input/3", "input/4", "input/5", "output"});
    const auto optimized = hpu::compiler::optimize_resources(instructions, dma, image);
    require(optimized.report.spills >= 1 && optimized.report.reloads >= 1,
            "dirty victim did not spill and reload");
    require(optimized.report.peak_regular_banks <= 5 && optimized.report.peak_object_slots <= 64,
            "scheduler confused logical slots and physical banks");
    for (const auto& entry : optimized.dma) {
        require(entry.operation_id == "node" && entry.operation_index.has_value(),
                "spill/reload changed graph operation provenance");
    }
    std::size_t default_policy_dma = 0;
    for (const auto& entry : optimized.dma) {
        const auto& op = optimized.instructions[entry.instruction_index].instruction;
        if (op.cp == 0) ++default_policy_dma;
    }
    require(default_policy_dma == optimized.report.spills + optimized.report.reloads,
            "inserted spill/reload inherited the original DMA cache policy");
    const auto original = replay(instructions, dma, image);
    const auto actual = replay(optimized.instructions, optimized.dma, optimized.image);
    require(allocation_words(original, image, "output")
                == allocation_words(actual, optimized.image, "output"), "spill corrupted arithmetic");
    for (int index = 0; index < 6; ++index) {
        const auto id = "input/" + std::to_string(index);
        require(allocation_words(image.words(), image, id)
                    == allocation_words(actual, optimized.image, id), "dirty spill overwrote immutable input");
    }
    hpu::compiler::CompileOptions options;
    options.optimization = hpu::compiler::OptimizationMode::no_opt;
    require_throws([&] { hpu::compiler::optimize_resources(instructions, dma, image, options); },
                   "NoOpt accepted six simultaneous regular-bank objects");
}

void test_stage_bank_and_multiple_readers()
{
    hpu::runtime::HpuMemImage image(16384);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    for (int index = 0; index < 6; ++index) {
        image.add("input/" + std::to_string(index), std::vector<std::uint32_t>(index == 1 ? 128 : 65536, index + 1),
            AllocationKind::twiddle);
    }
    image.reserve("scratch", 65536, AllocationKind::workspace);
    image.reserve("output/1", 65536, AllocationKind::output);
    image.reserve("output/2", 65536, AllocationKind::output);
    const auto stages = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndload x10, x11, p1, 0, 0, 32\n"
        "dload x10, x11, p2, 0, 0, 0\ndload x10, x11, p3, 0, 0, 0\n"
        "dload x10, x11, p5, 0, 0, 0\ndload x10, x11, p6, 0, 0, 0\npntt p0, p1, 0, 0, 0\n"
        "pfree p1\npmul p2, p2, p3\npfree p3\npmul p2, p2, p5\npfree p5\n"
        "pmul p2, p2, p6\npfree p6\npmul p0, p0, p2\npfree p2\ndstore x10, x11, p0, 0, 0\npfree p4\npsync\n");
    const auto stage_dma = bindings(stages, image,
        {"moduli", "input/0", "input/1", "input/2", "input/3", "input/4", "input/5", "output/1"});
    const auto staged = hpu::compiler::optimize_resources(stages, stage_dma, image);
    require(staged.report.peak_regular_banks <= 5 && staged.report.reloads >= 1,
            "NTT out-of-place output bank was not reserved");
    const auto multiple = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 2\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 2\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 3\ndstore x10, x11, p0, 0, 0\n"
        "pfree p4\npsync\n");
    const auto multi_dma = bindings(multiple, image,
        {"moduli", "input/0", "scratch", "scratch", "output/1", "scratch", "output/2"});
    const auto optimized = hpu::compiler::optimize_resources(multiple, multi_dma, image);
    require(optimized.report.deferred_scratch_stores == 0,
            "writeback was removed despite multiple DDR readers");
    const auto expected = replay(multiple, multi_dma, image);
    const auto actual = replay(optimized.instructions, optimized.dma, optimized.image);
    for (const std::string id : {"output/1", "output/2"}) {
        require(allocation_words(expected, image, id)
                    == allocation_words(actual, optimized.image, id), "multiple-reader memory semantics changed");
    }
    auto readonly_dma = multi_dma;
    readonly_dma[2].allocation_id = "input/0";
    readonly_dma[2].span = image.allocation("input/0").span;
    require_throws([&] { hpu::compiler::optimize_resources(multiple, readonly_dma, image); },
                   "DSTORE to immutable allocation accepted");
}

void test_destination_shape_change()
{
    hpu::runtime::HpuMemImage image(16);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.add("b", std::vector<std::uint32_t>(128, 4), AllocationKind::ciphertext);
    image.add("old_destination", std::vector<std::uint32_t>(64, 7), AllocationKind::constant);
    image.reserve("output", 128, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndload x10, x11, p1, 0, 0, 0\n"
        "dload x10, x11, p2, 0, 0, 0\npadd p2, p0, p1\n"
        "pfree p0\npfree p1\ndstore x10, x11, p2, 0, 0\npfree p4\npsync\n");
    const auto dma = bindings(instructions, image,
        {"moduli", "a", "b", "old_destination", "output"});
    const auto optimized = hpu::compiler::optimize_resources(instructions, dma, image);
    const auto original = replay(instructions, dma, image);
    const auto actual = replay(optimized.instructions, optimized.dma, optimized.image);
    require(allocation_words(original, image, "output")
                == allocation_words(actual, optimized.image, "output"),
            "arithmetic destination did not inherit source shape");
}

void test_partial_initialization_and_overlapping_lifetimes()
{
    hpu::runtime::HpuMemImage image(32);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("input", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("scratch/a", 128, AllocationKind::workspace);
    image.reserve("scratch/b", 128, AllocationKind::workspace);
    image.reserve("scratch/partial", 256, AllocationKind::workspace);
    image.reserve("output/a", 128, AllocationKind::output);
    image.reserve("output/b", 128, AllocationKind::output);
    image.reserve("output/partial", 128, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 2\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\npmul p0, p0, 3\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndload x10, x11, p1, 0, 0, 0\n"
        "padd p2, p0, p1\npfree p0\npfree p1\ndstore x10, x11, p2, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndstore x10, x11, p0, 0, 0\n"
        "dload x10, x11, p0, 0, 0, 0\ndstore x10, x11, p0, 0, 0\npfree p4\npsync\n");
    auto dma = bindings(instructions, image,
        {"moduli", "input", "scratch/a", "input", "scratch/b", "scratch/a", "scratch/b",
         "output/a", "scratch/a", "output/b", "input", "scratch/partial", "scratch/partial", "output/partial"});
    dma[11].span.line_count = 2;
    dma[12].span.line_offset += 2;
    dma[12].span.line_count = 2;
    const auto optimized = hpu::compiler::optimize_resources(instructions, dma, image);
    const auto a = hpu::compiler::relocate_span(optimized, "scratch/a", image.allocation("scratch/a").span);
    const auto b = hpu::compiler::relocate_span(optimized, "scratch/b", image.allocation("scratch/b").span);
    require(a.line_offset + a.line_count <= b.line_offset || b.line_offset + b.line_count <= a.line_offset,
            "overlapping scratch lifetimes shared bytes");
    require(optimized.image.contains("scratch/partial"),
            "partially initialized workspace was reused despite unwritten reads");
    const auto expected = replay(instructions, dma, image);
    const auto actual = replay(optimized.instructions, optimized.dma, optimized.image);
    for (const std::string id : {"output/a", "output/b", "output/partial"}) {
        require(allocation_words(expected, image, id)
                    == allocation_words(actual, optimized.image, id), "partial initialization changed output");
    }
}

void test_native_operator_resources()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(32);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(128, 2), AllocationKind::ciphertext);
    image.add("b", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    for (const std::string name : {"first", "second"}) {
        image.reserve("scratch/" + name, 128, AllocationKind::workspace);
        image.reserve("output/" + name, 128, AllocationKind::output);
    }
    r::Recording recording;
    auto assembly = r::read(r::modulus_table, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    assembly += r::select_modulus(0);
    for (int branch = 0; branch < 2; ++branch) {
        assembly += r::read(r::value, hpu::DataType::poly);
        assembly += r::read(r::auxiliary, hpu::DataType::poly);
        assembly += r::add(r::accumulator, r::value, r::auxiliary);
        assembly += r::discard(r::value);
        assembly += r::discard(r::auxiliary);
        assembly += r::publish(r::accumulator);
        assembly += r::read(r::value, hpu::DataType::poly);
        assembly += r::multiply_immediate(r::value, r::value, branch + 2);
        assembly += r::publish(r::value);
    }
    assembly += r::discard(r::modulus_table);
    assembly += r::finish_program();
    const auto source = recording.finish();
    const auto baseline = hpu::assemble_source(assembly);
    const auto dma = bindings(baseline, image, {"moduli", "a", "b", "scratch/first",
        "scratch/first", "output/first", "a", "b", "scratch/second", "scratch/second", "output/second"});
    auto native = r::bind_program(source, baseline, dma, image);
    // The native path must not inherit any physical allocation choices.
    for (auto& node : native.instructions) {
        node.instruction.pdst = node.instruction.psrc1 = node.instruction.psrc2 = 99;
        node.instruction.obj_id = 99;
    }
    const auto compiled = hpu::compiler::compile_resources(native, baseline, dma, image);
    require(compiled.report.ir_origin == hpu::compiler::ResourceIrOrigin::operator_emission,
            "native operator resource IR was not used");
    require(compiled.report.deferred_scratch_stores == 2 && compiled.dma.size() == dma.size() - 4,
            "native operator scratch traffic was not eliminated");
    const auto a = hpu::compiler::relocate_span(compiled, "scratch/first", image.allocation("scratch/first").span);
    const auto b = hpu::compiler::relocate_span(compiled, "scratch/second", image.allocation("scratch/second").span);
    require(a.line_offset == b.line_offset, "native disjoint workspaces were not reused");
    const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
    require(allocation_words(actual, compiled.image, "output/first") == std::vector<std::uint32_t>(128, 10),
            "native first branch differs from independent arithmetic");
    require(allocation_words(actual, compiled.image, "output/second") == std::vector<std::uint32_t>(128, 15),
            "native second branch differs from independent arithmetic");
    hpu::compiler::CompileOptions no_opt;
    no_opt.optimization = hpu::compiler::OptimizationMode::no_opt;
    const auto original = hpu::compiler::compile_resources(r::bind_program(source, baseline, dma, image),
                                                          baseline, dma, image, no_opt);
    require(original.image.words() == image.words(), "native NoOpt altered memory");
    for (std::size_t i = 0; i < baseline.size(); ++i)
        require(original.instructions[i].word == baseline[i].word, "native NoOpt altered baseline instructions");
    auto incomplete = source;
    incomplete.operations.pop_back();
    require_throws([&] { r::bind_program(incomplete, baseline, dma, image); }, "incomplete native coverage was accepted");
    auto corrupt = source;
    for (auto& node : corrupt.operations)
        if (node.instruction.mnemonic == hpu::Mnemonic::kPmul) { ++node.instruction.imm8; break; }
    require_throws([&] { r::bind_program(corrupt, baseline, dma, image); }, "native arithmetic divergence was accepted");
    auto invalid_dma = dma;
    invalid_dma[3].allocation_id = "a";
    invalid_dma[3].span = image.allocation("a").span;
    require_throws([&] { r::bind_program(source, baseline, invalid_dma, image); }, "native read-only write accepted");
}

void test_use_index()
{
    hpu::compiler::VirtualProgram program;
    program.objects.resize(1000);
    for (std::size_t i = 0; i < 3000; ++i) {
        hpu::compiler::VirtualInstruction op;
        op.instruction.mnemonic = i % 11 == 0 ? hpu::Mnemonic::kPfree : hpu::Mnemonic::kPmul;
        op.uses = {i % 1000, i % 1000, (i * 7) % 1000};
        op.reload_retained_object = i % 13 == 0;
        if (op.reload_retained_object) op.definitions = {(i + 17) % 1000};
        program.instructions.push_back(op);
    }
    hpu::compiler::detail::UseIndex index(program);
    for (std::size_t i = 0; i < program.instructions.size(); ++i) {
        index.consume(program.instructions[i], i);
        for (const auto id : {i % 1000, (i + 17) % 1000}) {
            auto expected = hpu::compiler::detail::UseIndex::none;
            for (std::size_t j = i + 1; j < program.instructions.size(); ++j) {
                const auto& op = program.instructions[j];
                if (op.instruction.mnemonic == hpu::Mnemonic::kPfree) continue;
                if (std::find(op.uses.begin(), op.uses.end(), id) != op.uses.end() ||
                    (op.reload_retained_object && std::find(op.definitions.begin(), op.definitions.end(), id) != op.definitions.end())) {
                    expected = j; break;
                }
            }
            require(index.next(id) == expected, "indexed next use differs from future scan");
        }
    }
}

void test_ssa_versions_and_ports()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(128);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(128, 2), AllocationKind::ciphertext);
    image.add("b", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("old", 128, AllocationKind::output);
    image.reserve("new", 128, AllocationKind::output);
    r::Recording recording;
    const auto mod = r::make_operand("context");
    const auto a = r::make_operand("input"), b = r::make_operand("input"), sum = r::make_operand("result");
    require(a != b, "equal debug labels alias independent operands");
    r::read(mod, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    r::select_modulus(0);
    r::read(a, hpu::DataType::poly); r::read(b, hpu::DataType::poly);
    r::multiply(sum, a, b);
    const auto old = recording.value(sum);
    r::accumulate(sum, a, b);
    require(old != recording.value(sum), "PMAC overwrote an SSA definition");
    r::Operation save;
    save.instruction.mnemonic = hpu::Mnemonic::kDstore;
    save.instruction.rs1 = 10; save.instruction.rs2 = 11; save.instruction.type = 1;
    save.inputs = {old}; recording.emit(save);
    r::publish(sum);
    r::finish_program();
    auto program = recording.finish();
    const std::vector<std::string> names{"moduli", "a", "b", "old", "new"};
    for (std::size_t i = 0; i < names.size(); ++i)
        program.bind_port(i, {0, names[i], image.allocation(names[i]).span, 0, "ssa", i});
    auto ir = r::bind_program(program, image);
    require(ir.buffers.size() > image.allocations().size(), "live old accumulator did not get a snapshot");
    const auto compiled = hpu::compiler::compile_resources(ir, {}, {}, image);
    hpu::compiler::CompileOptions noopt;
    noopt.optimization = hpu::compiler::OptimizationMode::no_opt;
    const auto plain = hpu::compiler::compile_resources(ir, {}, {}, image, noopt);
    const auto plain_words = replay(plain.instructions, plain.dma, plain.image);
    require(allocation_words(plain_words, plain.image, "old") == std::vector<std::uint32_t>(128, 6),
            "native NoOpt did not preserve an old SSA version");
    const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
    require(allocation_words(actual, compiled.image, "old") == std::vector<std::uint32_t>(128, 6),
            "PMAC destroyed the old SSA version");
    require(allocation_words(actual, compiled.image, "new") == std::vector<std::uint32_t>(128, 12),
            "PMAC did not initialize its new accumulator version");
    auto duplicate = program;
    duplicate.operations.push_back(program.operations.at(4));
    require_throws([&] { r::bind_program(duplicate, image); }, "duplicate SSA definition accepted");
    auto missing = program; missing.ports.front().binding.reset();
    require_throws([&] { r::bind_program(missing, image); }, "missing explicit data binding accepted");
}

void test_unbounded_operand_ids()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(128);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.reserve("answer", 128, AllocationKind::output);
    r::Recording recording;
    const auto mod = r::make_operand("moduli");
    r::read(mod, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    r::select_modulus(0);
    std::vector<r::Operand> inputs;
    std::vector<std::string> ports{"moduli"};
    for (int i = 0; i < 20; ++i) {
        const auto name = "input_" + std::to_string(i);
        image.add(name, std::vector<std::uint32_t>(128, i + 1), AllocationKind::ciphertext);
        inputs.push_back(r::make_operand("input"));
        r::read(inputs.back(), hpu::DataType::poly); ports.push_back(name);
    }
    const auto result = r::make_operand("sum");
    r::add(result, inputs[0], inputs[1]);
    for (std::size_t i = 2; i < inputs.size(); ++i) r::add(result, result, inputs[i]);
    r::publish(result); ports.push_back("answer");
    r::finish_program();
    auto source = recording.finish();
    for (std::size_t i = 0; i < ports.size(); ++i)
        source.bind_port(i, {0, ports[i], image.allocation(ports[i]).span, 0, "sum", i});
    const auto compiled = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image);
    const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
    require(allocation_words(actual, compiled.image, "answer") == std::vector<std::uint32_t>(128, 210),
            "more than eight independent operands corrupted the sum");
    require(compiled.report.peak_regular_banks <= 5 && compiled.report.peak_object_slots > 8
            && compiled.report.spills == 0 && compiled.report.reloads == 0,
            "small independent objects did not share physical banks");
}

void test_full_64_object_bank_layout()
{
    // Forty N8192 objects share five ordinary banks, while fourteen stage
    // parameter objects and one modulus table occupy all of Bank 5. This
    // catches both the obsolete eight-slot limit and one-object-per-bank model.
    hpu::runtime::HpuMemImage image(8192);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    std::string assembly = "dload x10, x11, p63, 1, 0, 32\npmodld 0\n";
    std::vector<std::string> names{"moduli"};
    for (int id = 0; id < 40; ++id) {
        const auto name = "data/" + std::to_string(id);
        image.add(name, std::vector<std::uint32_t>(8192, id), AllocationKind::ciphertext);
        assembly += "dload x10, x11, p" + std::to_string(id) + ", 0, 0, 0\n";
        names.push_back(name);
    }
    for (int id = 40; id < 54; ++id) {
        const auto name = "parameters/" + std::to_string(id);
        image.add(name, std::vector<std::uint32_t>(128, 1), AllocationKind::twiddle);
        assembly += "dload x10, x11, p" + std::to_string(id) + ", 0, 0, 32\n";
        names.push_back(name);
    }
    for (int id = 0; id < 54; ++id) assembly += "pfree p" + std::to_string(id) + "\n";
    assembly += "pfree p63\npsync\n";
    const auto instructions = hpu::assemble_source(assembly);
    const auto dma = bindings(instructions, image, names);
    for (const auto mode : {hpu::compiler::OptimizationMode::no_opt,
                            hpu::compiler::OptimizationMode::optimized}) {
        hpu::compiler::CompileOptions options;
        options.optimization = mode;
        const auto compiled = hpu::compiler::optimize_resources(instructions, dma, image, options);
        require(compiled.report.peak_object_slots == 55
                && compiled.report.peak_regular_banks == 5
                && compiled.report.peak_regular_lines == 5120
                && compiled.report.peak_small_lines == 32,
                "compiler failed to reproduce the 40-poly plus 14-parameter physical layout");
        require(compiled.report.spills == 0 && compiled.report.reloads == 0,
                "fitting bank intervals caused unnecessary spills");
    }
}

void test_store_retention_and_pmac_capacity()
{
    hpu::runtime::HpuMemImage image(8192);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(65536, 2), AllocationKind::ciphertext);
    image.add("b", std::vector<std::uint32_t>(65536, 3), AllocationKind::ciphertext);
    image.reserve("before", 65536, AllocationKind::output);
    image.reserve("after", 65536, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p63, 1, 0, 32\npmodld 0\n"
        "dload x10, x11, p32, 0, 0, 1\ndload x10, x11, p33, 0, 0, 2\n"
        "pmul p34, p32, p33\npsync\ndstore x10, x11, p34, 0, 0\npsync\n"
        "pmac p34, p32, p33\ndstore x10, x11, p34, 1, 0\n"
        "pfree p32\npfree p33\npfree p63\npsync\n");
    const auto dma = bindings(instructions, image, {"moduli", "a", "b", "before", "after"});
    for (const auto mode : {hpu::compiler::OptimizationMode::no_opt,
                            hpu::compiler::OptimizationMode::optimized}) {
        hpu::compiler::CompileOptions options;
        options.optimization = mode;
        const auto compiled = hpu::compiler::optimize_resources(instructions, dma, image, options);
        const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
        require(allocation_words(actual, compiled.image, "before")
                    == std::vector<std::uint32_t>(65536, 6)
                && allocation_words(actual, compiled.image, "after")
                    == std::vector<std::uint32_t>(65536, 12),
                "REL=0 lost the accumulator before PMAC");
        require(compiled.report.peak_regular_lines == 4096,
                "PMAC did not budget old and new accumulator regions simultaneously");
    }
}

void test_ntt_preserves_live_ssa_input()
{
    namespace r = hpu::resource;
    constexpr std::uint32_t q = 65537;
    const hpu::model::HardwareNttModel model(128, q, hpu::model::pow_mod(3, (q - 1) / 128, q));
    for (const bool inverse : {false, true}) {
        hpu::runtime::HpuMemImage image(64);
        std::vector<std::uint32_t> input(128);
        for (std::size_t i = 0; i < input.size(); ++i) input[i] = (i * 97) % q;
        const auto table = inverse ? model.inverse_twiddles().stages[3] : model.forward_twiddles()[3];
        constexpr auto mu = std::numeric_limits<std::uint64_t>::max() / q;
        image.add("moduli", {q, static_cast<std::uint32_t>(mu), static_cast<std::uint32_t>(mu >> 32), 0},
                  AllocationKind::modulus_table);
        image.add("input", input, AllocationKind::ciphertext);
        image.add("table", hpu::model::pack_stage_twiddles(table, q, input.size()),
                  AllocationKind::twiddle);
        image.reserve("old", input.size(), AllocationKind::output);
        image.reserve("new", input.size(), AllocationKind::output);
        r::Recording recording;
        const auto mod = r::make_operand("moduli"), data = r::make_operand("data"), twiddle = r::make_operand("table");
        r::read(mod, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        r::select_modulus(0);
        r::read(data, hpu::DataType::poly); r::read(twiddle, hpu::DataType::twiddle_parameters);
        const auto old = recording.value(data);
        if (inverse) r::intt_stage(data, twiddle, 3);
        else r::ntt_stage(data, twiddle, 3);
        r::Operation save;
        save.instruction.mnemonic = hpu::Mnemonic::kDstore;
        save.instruction.rs1 = 10; save.instruction.rs2 = 11;
        save.inputs = {old}; recording.emit(save);
        r::publish(data); r::finish_program();
        auto source = recording.finish();
        const std::vector<std::string> names{"moduli", "input", "table", "old", "new"};
        for (std::size_t i = 0; i < names.size(); ++i)
            source.bind_port(i, {0, names[i], image.allocation(names[i]).span, 0, "stage", i});
        const auto expected = hpu::model::execute_ntt_stage(input, table, q, 3, inverse);
        for (const auto optimization : {hpu::compiler::OptimizationMode::optimized, hpu::compiler::OptimizationMode::no_opt}) {
            hpu::compiler::CompileOptions options; options.optimization = optimization;
            const auto compiled = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
            std::vector<hpu::runtime::HpuMemSpan> spans;
            for (const auto& dma : compiled.dma) spans.push_back(dma.span);
            hpu::model::InstructionExecutionOptions execution_options;
            execution_options.ntt_contract = hpu::model::InstructionNttContract::legacy_raw_stage;
            const auto execution = hpu::model::execute_instructions(compiled.instructions, spans, compiled.image, execution_options);
            if (!execution.report.completed())
                throw std::runtime_error("SSA snapshot stage replay failed: " + execution.report.message);
            require(allocation_words(execution.words, compiled.image, "old") == input,
                    "transform destroyed or normalized a live old SSA value");
            require(allocation_words(execution.words, compiled.image, "new") == expected,
                    "transform did not produce the new SSA value");
        }
        auto malformed = source;
        malformed.operations.at(4).tied_input.reset();
        require_throws([&] { r::bind_program(malformed, image); }, "untied transform was accepted");
    }
}

void test_online_pmul_parameter_lifetime_and_destination()
{
    namespace r = hpu::resource;
    constexpr std::uint32_t q = 65537;
    constexpr std::size_t degree = 8192;
    constexpr std::uint32_t c = 13, ratio = 3;
    for (const bool preserve_source : {false, true}) {
        hpu::runtime::HpuMemImage image(512);
        constexpr auto mu = std::numeric_limits<std::uint64_t>::max() / q;
        image.add("moduli", {q, static_cast<std::uint32_t>(mu),
                  static_cast<std::uint32_t>(mu >> 32U), 0}, AllocationKind::modulus_table);
        std::vector<std::uint32_t> input(degree), expected(degree);
        std::uint32_t factor = c;
        for (std::size_t i = 0; i < degree; ++i) {
            input[i] = static_cast<std::uint32_t>((97 * i + 3) % q);
            expected[i] = static_cast<std::uint32_t>(std::uint64_t(input[i]) * factor % q);
            factor = static_cast<std::uint32_t>(std::uint64_t(factor) * ratio % q);
        }
        image.add("input", input, AllocationKind::ciphertext);
        image.add("parameters", hpu::model::pack_online_pmul_parameters(c, ratio, q, degree),
                  AllocationKind::twiddle);
        image.reserve("result", degree, AllocationKind::output);
        if (preserve_source) image.reserve("original", degree, AllocationKind::output);
        const auto bind = [&](const std::string& id) -> ResolvedDma {
            return {0, id, image.allocation(id).span, 0, "online_pmul", 0};
        };
        r::Recording recording;
        const auto mod = r::make_operand("moduli"), data = r::make_operand("data"),
                   parameters = r::make_operand("parameters");
        const auto result = preserve_source ? r::make_operand("independent_result") : data;
        r::input(mod, bind("moduli"), hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        r::select_modulus(0);
        r::input(data, bind("input"), hpu::DataType::poly);
        r::input(parameters, bind("parameters"), hpu::DataType::online_pmul_parameters);
        r::multiply_online(result, data, parameters);
        r::output(result, bind("result"));
        // The parameter dies at PMUL, but the polynomial source remains live.
        // A generic arithmetic allocator must not steal the two-line Bank 5
        // parameter slot as the 128-line polynomial destination.
        if (preserve_source) r::output(data, bind("original"));
        r::finish_program();
        const auto source = recording.finish();
        for (const auto optimization : {hpu::compiler::OptimizationMode::optimized,
                                        hpu::compiler::OptimizationMode::no_opt}) {
            hpu::compiler::CompileOptions options;
            options.optimization = optimization;
            options.automatic_lifetimes = true;
            options.required_outputs = {"result"};
            if (preserve_source) options.required_outputs.insert("original");
            const auto compiled = hpu::compiler::compile_resources(
                r::bind_program(source, image), {}, {}, image, options);
            std::size_t online_count = 0;
            for (const auto& encoded : compiled.instructions) {
                const auto& op = encoded.instruction;
                if (op.mnemonic != hpu::Mnemonic::kPmul || op.mode != 1) continue;
                ++online_count;
                require(op.psrc2 != op.pdst && op.psrc2 != op.psrc1,
                        "online PMUL aliases its parameter and polynomial object IDs");
                if (preserve_source)
                    require(op.pdst != op.psrc1,
                            "online PMUL overwrote a still-live SSA source");
            }
            require(online_count == 1, "resource compiler lost the online PMUL mode");
            std::vector<hpu::runtime::HpuMemSpan> spans;
            for (const auto& dma : compiled.dma) spans.push_back(dma.span);
            const auto execution = hpu::model::execute_instructions(
                compiled.instructions, spans, compiled.image);
            require(execution.report.completed(), execution.report.message.c_str());
            require(allocation_words(execution.words, compiled.image, "result") == expected,
                    "online PMUL resource lowering changed geometric multiplication");
            if (preserve_source)
                require(allocation_words(execution.words, compiled.image, "original") == input,
                        "online PMUL resource lowering destroyed a live source");
        }
    }
}

void test_deferred_reload_storage_lifetime()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(64);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("input", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("scratch", 128, AllocationKind::workspace);
    image.reserve("old", 128, AllocationKind::output);
    image.reserve("new", 128, AllocationKind::output);
    r::Recording recording;
    const auto mod = r::make_operand("moduli"), input = r::make_operand("input"), data = r::make_operand("data");
    r::read(mod, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank); r::select_modulus(0);
    r::read(input, hpu::DataType::poly);
    r::multiply_immediate(data, input, 2); r::publish(data);
    // There is no explicit SSA use of the old version until the delayed reload.
    // Its underlying storage still cannot be reused by this definition.
    r::multiply_immediate(data, data, 2); r::publish(data);
    r::read(data, hpu::DataType::poly); r::publish(data); r::finish_program();
    auto source = recording.finish();
    const std::vector<std::string> names{"moduli", "input", "scratch", "new", "scratch", "old"};
    for (std::size_t i = 0; i < names.size(); ++i)
        source.bind_port(i, {0, names[i], image.allocation(names[i]).span, 0, "reload", i});
    for (const auto optimization : {hpu::compiler::OptimizationMode::optimized, hpu::compiler::OptimizationMode::no_opt}) {
        hpu::compiler::CompileOptions options; options.optimization = optimization;
        const auto compiled = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
        const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
        require(allocation_words(actual, compiled.image, "old") == std::vector<std::uint32_t>(128, 6),
                "reused storage corrupted a delayed reload");
        require(allocation_words(actual, compiled.image, "new") == std::vector<std::uint32_t>(128, 12),
                "delayed reload corrupted the new SSA value");
    }
}

void test_per_command_cache_policy()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(32);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("input", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("before", 128, AllocationKind::output);
    image.reserve("after", 128, AllocationKind::output);
    r::Recording recording;
    auto assembly = r::read(r::modulus_table, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank, hpu::CachePolicy::allocate);
    assembly += r::select_modulus(0);
    assembly += r::read(r::value, hpu::DataType::poly,
                        hpu::DloadFlag::regular_bank, hpu::CachePolicy::allocate);
    assembly += r::multiply_immediate(r::value, r::value, 2);
    assembly += r::publish(r::value, 0);
    assembly += r::publish(r::value, 1, hpu::CachePolicy::allocate);
    assembly += r::discard(r::modulus_table);
    assembly += r::finish_program();
    const auto source = recording.finish();
    const auto instructions = hpu::assemble_source(assembly);
    const auto dma = bindings(instructions, image, {"moduli", "input", "before", "after"});
    const auto ir = r::bind_program(source, instructions, dma, image);
    for (const auto mode : {hpu::compiler::OptimizationMode::optimized,
                            hpu::compiler::OptimizationMode::no_opt}) {
        hpu::compiler::CompileOptions options; options.optimization = mode;
        const auto compiled = hpu::compiler::compile_resources(ir, instructions, dma, image, options);
        const std::array<std::uint8_t, 4> policies{1, 1, 0, 1};
        require(compiled.dma.size() == policies.size(), "cache-policy test lost a required transfer");
        for (std::size_t i = 0; i < policies.size(); ++i) {
            const auto& op = compiled.instructions[compiled.dma[i].instruction_index].instruction;
            require(op.cp == policies[i], "native lowering changed a per-command cache policy");
            if (op.mnemonic == hpu::Mnemonic::kDload)
                require(op.type == (i == 0 ? 1 : 0), "logical payload type leaked into MOD encoding");
        }
        const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
        require(allocation_words(actual, compiled.image, "before") == std::vector<std::uint32_t>(128, 6)
                && allocation_words(actual, compiled.image, "after") == std::vector<std::uint32_t>(128, 6),
                "cache hints changed object retention or arithmetic");
    }
    auto mismatched = source;
    mismatched.operations[2].instruction.cp = 0;
    require_throws([&] { r::bind_program(mismatched, instructions, dma, image); },
                   "compatibility baseline ignored a mismatched cache hint");
    const auto rendered = r::render_operator_ir(source);
    require(rendered.find("mod=1 cp=1 bank_mask=32") != std::string::npos
            && rendered.find("release=0 cp=0") != std::string::npos,
            "operator IR omitted the independent MOD/REL and CP fields");
    {
        r::Recording seeds;
        const auto seed_assembly = r::read(r::transform_table, hpu::DataType::twiddle_parameters);
        const auto native = seeds.finish();
        const auto wire = hpu::assemble_source(seed_assembly);
        require(native.operations.front().instruction.type == 0
                && native.operations.front().instruction.cp == 0
                && native.operations.front().instruction.dma_flag == 32
                && wire.front().instruction.type == 0
                && wire.front().instruction.dma_flag == 32,
                "twiddle logical type did not lower to ordinary MOD=0 with explicit Bank 5 mask");
    }
}

void require_twiddle_cache_policy(const hpu::compiler::CompiledResources& compiled)
{
    for (const auto& dma : compiled.dma) {
        const auto& encoded = compiled.instructions.at(dma.instruction_index);
        const auto& op = encoded.instruction;
        const auto& allocation = compiled.image.allocation(dma.allocation_id);
        const auto expected = op.mnemonic == hpu::Mnemonic::kDload
                && allocation.kind == AllocationKind::twiddle
            ? 1 : 0;
        require(op.cp == expected, "final DMA hint does not match physical allocation kind");
        require(encoded.word == hpu::encode_instruction(op)
                    && encoded.command26 == hpu::precode_command26(encoded.word)
                    && encoded.normalized_asm == hpu::to_string(op),
                "DMA cache rewrite left stale machine code or assembly");
    }
}

void test_twiddle_cache_policy()
{
    hpu::runtime::HpuMemImage image(64);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("opaque/alpha", std::vector<std::uint32_t>(128, 1), AllocationKind::twiddle);
    image.add("opaque/beta", std::vector<std::uint32_t>(256, 2), AllocationKind::twiddle);
    image.add_alias("renamed/vector", "opaque/beta");
    // Both its name and its Bank 5 placement deliberately resemble twiddles.
    image.add("twiddle/not_a_table", std::vector<std::uint32_t>(128, 7), AllocationKind::constant);
    image.add("input", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("writable/table", 128, AllocationKind::twiddle);
    image.reserve("output", 128, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 1, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 32\npfree p0\n"
        "dload x10, x11, p1, 0, 1, 32\npfree p1\n"
        "dload x10, x11, p2, 0, 0, 0\npfree p2\n"
        "dload x10, x11, p0, 0, 1, 0\npmul p0, p0, 2\n"
        "dstore x10, x11, p0, 0, 1\ndstore x10, x11, p0, 1, 1\n"
        "pfree p4\npsync\n");
    auto dma = bindings(instructions, image,
        {"moduli", "opaque/alpha", "twiddle/not_a_table", "renamed/vector", "input",
         "writable/table", "output"});
    // A load of a subspan through an alias must retain its physical kind.
    ++dma[3].span.line_offset;
    dma[3].span.line_count = 2;
    for (const auto mode : {hpu::compiler::OptimizationMode::no_opt,
                            hpu::compiler::OptimizationMode::optimized}) {
        hpu::compiler::CompileOptions options;
        options.optimization = mode;
        options.dma_cache_policy = hpu::compiler::DmaCachePolicy::twiddle_loads_only;
        const auto compiled = hpu::compiler::optimize_resources(instructions, dma, image, options);
        require_twiddle_cache_policy(compiled);
        require(compiled.dma.size() == dma.size(), "cache policy changed required DMA coverage");
        const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
        require(allocation_words(actual, compiled.image, "output") == std::vector<std::uint32_t>(128, 6),
                "cache policy changed arithmetic output");
        if (mode == hpu::compiler::OptimizationMode::no_opt) {
            require(compiled.image.words() == image.words(), "NoOpt cache policy changed payloads");
            for (std::size_t i = 0; i < instructions.size(); ++i) {
                const auto mnemonic = instructions[i].instruction.mnemonic;
                if (mnemonic != hpu::Mnemonic::kDload && mnemonic != hpu::Mnemonic::kDstore)
                    require(compiled.instructions[i].word == instructions[i].word,
                            "cache policy changed a non-DMA instruction");
            }
        }
    }
}

void test_twiddle_cache_policy_after_eviction()
{
    hpu::runtime::HpuMemImage image(8192);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    for (int i = 0; i < 6; ++i)
        image.add("opaque/" + std::to_string(i), std::vector<std::uint32_t>(65536, i + 1),
                  i == 0 ? AllocationKind::twiddle : AllocationKind::ciphertext);
    image.reserve("output", 65536, AllocationKind::output);
    const auto instructions = hpu::assemble_source(
        "dload x10, x11, p4, 1, 1, 32\npmodld 0\n"
        "dload x10, x11, p0, 0, 0, 0\n"
        "dload x10, x11, p1, 0, 1, 0\ndload x10, x11, p2, 0, 1, 0\n"
        "dload x10, x11, p3, 0, 1, 0\ndload x10, x11, p5, 0, 1, 0\n"
        "dload x10, x11, p6, 0, 1, 0\n"
        "padd p1, p1, p2\npfree p2\npadd p3, p3, p5\npfree p5\n"
        "padd p6, p6, p1\npfree p1\npadd p0, p0, p3\npfree p3\n"
        "padd p0, p0, p6\npfree p6\ndstore x10, x11, p0, 1, 1\npfree p4\npsync\n");
    const auto dma = bindings(instructions, image,
        {"moduli", "opaque/0", "opaque/1", "opaque/2", "opaque/3", "opaque/4", "opaque/5", "output"});
    hpu::compiler::CompileOptions options;
    options.dma_cache_policy = hpu::compiler::DmaCachePolicy::twiddle_loads_only;
    const auto compiled = hpu::compiler::optimize_resources(instructions, dma, image, options);
    require(compiled.report.reloads > 0, "twiddle pressure test did not force a reload");
    require_twiddle_cache_policy(compiled);
    std::size_t table_loads = 0;
    for (const auto& entry : compiled.dma) {
        const auto& op = compiled.instructions[entry.instruction_index].instruction;
        if (entry.allocation_id == "opaque/0" && op.mnemonic == hpu::Mnemonic::kDload) ++table_loads;
    }
    require(table_loads >= 2, "evicted twiddle was not reloaded from its immutable allocation");
    const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
    require(allocation_words(actual, compiled.image, "output") == std::vector<std::uint32_t>(65536, 21),
            "cache policy changed arithmetic across an eviction");

    // Once modified, the same logical object spills into workspace. Its
    // reload must use that final physical kind, rather than remember CP=1.
    std::string dirty_source;
    for (const auto& encoded : instructions) {
        dirty_source += encoded.normalized_asm + '\n';
        if (encoded.instruction.mnemonic == hpu::Mnemonic::kDload
            && encoded.instruction.obj_id == 0)
            dirty_source += "pmul p0, p0, 2\n";
    }
    const auto dirty_instructions = hpu::assemble_source(dirty_source);
    const auto dirty_dma = bindings(dirty_instructions, image,
        {"moduli", "opaque/0", "opaque/1", "opaque/2", "opaque/3", "opaque/4", "opaque/5", "output"});
    const auto dirty = hpu::compiler::optimize_resources(dirty_instructions, dirty_dma, image, options);
    require(dirty.report.spills > 0 && dirty.report.reloads > 0,
            "dirty twiddle pressure test did not insert spill and reload");
    require_twiddle_cache_policy(dirty);
    std::size_t workspace_loads = 0, workspace_stores = 0;
    for (const auto& entry : dirty.dma) {
        if (dirty.image.allocation(entry.allocation_id).kind != AllocationKind::workspace) continue;
        const auto& op = dirty.instructions[entry.instruction_index].instruction;
        if (op.mnemonic == hpu::Mnemonic::kDload) ++workspace_loads;
        else ++workspace_stores;
    }
    require(workspace_loads > 0 && workspace_stores > 0,
            "dirty spill did not pass through a non-twiddle physical allocation");
    const auto dirty_actual = replay(dirty.instructions, dirty.dma, dirty.image);
    require(allocation_words(dirty_actual, dirty.image, "output") == std::vector<std::uint32_t>(65536, 22),
            "cache policy changed arithmetic across a dirty spill");
}

void test_nested_recording()
{
    namespace r = hpu::resource;
    r::Recording outer;
    r::read(r::value, hpu::DataType::poly);
    {
        r::Recording inner;
        r::read(r::auxiliary, hpu::DataType::poly);
        r::discard(r::auxiliary);
        require(inner.finish().operations.size() == 2, "nested recorder lost its fragment");
    }
    try {
        r::Recording interrupted;
        r::discard(r::value);
        throw std::runtime_error("test unwind");
    } catch (const std::runtime_error&) {}
    r::discard(r::value);
    require(outer.finish().operations.size() == 2, "nested recorder contaminated its parent or failed to restore it");
}

void test_fragment_ssa_renaming()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(64);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("input", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.reserve("output", 128, AllocationKind::output);
    const auto mod = r::make_operand("moduli"), data = r::make_operand("data");
    r::Recording outer;
    r::read(mod, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank); r::select_modulus(0);
    r::read(data, hpu::DataType::poly);
    r::OperatorProgram fragment;
    {
        r::Recording inner;
        r::multiply_immediate(data, data, 2);
        fragment = inner.finish();
    }
    outer.append(fragment); outer.append(fragment);
    r::publish(data); r::finish_program();
    auto source = outer.finish();
    require(source.operations.at(3).outputs != source.operations.at(4).outputs,
            "repeated fragment aliased SSA definitions");
    require(source.operations.at(4).inputs == source.operations.at(3).outputs,
            "fragment live-in did not connect to the previous SSA version");
    const std::vector<std::string> names{"moduli", "input", "output"};
    for (std::size_t i = 0; i < names.size(); ++i)
        source.bind_port(i, {0, names[i], image.allocation(names[i]).span, 0, "fragments", i});
    const auto compiled = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image);
    const auto actual = replay(compiled.instructions, compiled.dma, compiled.image);
    require(allocation_words(actual, compiled.image, "output") == std::vector<std::uint32_t>(128, 12),
            "renamed fragments corrupted their shared live-in");
}

void test_entry_preload_preserves_continuous_schedule()
{
    namespace r = hpu::resource;
    hpu::runtime::HpuMemImage image(32);
    image.add("moduli", {65537}, AllocationKind::modulus_table);
    image.add("a", std::vector<std::uint32_t>(128, 3), AllocationKind::ciphertext);
    image.add("late/b", std::vector<std::uint32_t>(128, 5), AllocationKind::evaluation_key);
    image.add("mutable", std::vector<std::uint32_t>(128, 7), AllocationKind::workspace, false);
    image.reserve("output", 128, AllocationKind::output);
    const auto binding = [&](const std::string& id) -> ResolvedDma {
        return {0, id, image.allocation(id).span, 0, "continuous", 0};
    };
    r::Recording recording;
    const auto mod = r::make_operand("mod"), a = r::make_operand("a"),
               b = r::make_operand("b"), mutable_value = r::make_operand("mutable");
    r::input(mod, binding("moduli"), hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    r::select_modulus(0);
    r::input(a, binding("a"), hpu::DataType::poly);
    r::multiply_immediate(a, a, 2);
    r::input(b, binding("late/b"), hpu::DataType::poly);
    r::add(a, a, b);
    r::input(mutable_value, binding("mutable"), hpu::DataType::poly);
    r::add(a, a, mutable_value);
    r::output(a, binding("output"));
    r::finish_program();
    const auto source = recording.finish();
    hpu::compiler::CompileOptions options;
    options.automatic_lifetimes = true;
    const auto baseline = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
    options.preload_readonly_inputs = true;
    const auto prepared = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
    const auto first_compute = [](const auto& program) {
        for (std::size_t i = 0; i < program.instructions.size(); ++i)
            if (program.instructions[i].instruction.mnemonic == hpu::Mnemonic::kPmul) return i;
        return program.instructions.size();
    };
    const auto load_position = [](const auto& program, const std::string& id) {
        for (const auto& dma : program.dma)
            if (dma.allocation_id == id) return dma.instruction_index;
        throw std::runtime_error("expected input load is missing");
    };
    require(load_position(baseline, "late/b") > first_compute(baseline)
            && load_position(prepared, "late/b") < first_compute(prepared),
            "immutable late input was not brought forward to entry");
    require(load_position(prepared, "mutable") > first_compute(prepared),
            "mutable memory read crossed the computation boundary");
    const auto computation_order = [](const auto& program) {
        std::vector<std::pair<hpu::Mnemonic, int>> sequence;
        for (const auto& encoded : program.instructions) {
            const auto& op = encoded.instruction;
            if (op.mnemonic == hpu::Mnemonic::kPmul || op.mnemonic == hpu::Mnemonic::kPadd
                || op.mnemonic == hpu::Mnemonic::kPsync || op.mnemonic == hpu::Mnemonic::kPmodld)
                sequence.emplace_back(op.mnemonic, op.imm8);
        }
        return sequence;
    };
    require(computation_order(prepared) == computation_order(baseline),
            "entry preloading changed computation order or inserted window waits");
    require(prepared.report.preloaded_dma_count == 3
            && prepared.report.preloaded_dma_bytes == 5 * 256
            && prepared.report.dma_count == baseline.report.dma_count
            && prepared.report.dload_bytes == baseline.report.dload_bytes
            && prepared.report.dstore_bytes == baseline.report.dstore_bytes,
            "entry preparation duplicated IO or reported incorrect preload metrics");
    const auto actual = replay(prepared.instructions, prepared.dma, prepared.image);
    require(allocation_words(actual, prepared.image, "output") == std::vector<std::uint32_t>(128, 18),
            "entry preloading changed arithmetic or mutable memory contents");
    // With only two full-size banks, reserve the transient working space and
    // leave the existing on-demand stream intact rather than forcing spills.
    options.regular_bank_count = 2;
    hpu::runtime::HpuMemImage large_image(8192);
    large_image.add("moduli", {65537}, AllocationKind::modulus_table);
    for (const auto& id : {"a", "late/b"})
        large_image.add(id, std::vector<std::uint32_t>(65536, id == std::string("a") ? 3 : 5),
                        AllocationKind::ciphertext);
    large_image.add("mutable", std::vector<std::uint32_t>(65536, 7), AllocationKind::workspace, false);
    large_image.reserve("output", 65536, AllocationKind::output);
    auto large_source = source;
    for (auto& port : large_source.ports)
        port.binding->span = large_image.allocation(port.binding->allocation_id).span;
    const auto constrained = hpu::compiler::compile_resources(
        r::bind_program(large_source, large_image), {}, {}, large_image, options);
    require(constrained.report.preloaded_dma_count == 1 && constrained.report.spills == 0,
            "entry preloading occupied capacity needed by the continuous computation");
    const auto constrained_words = replay(constrained.instructions, constrained.dma, constrained.image);
    require(allocation_words(constrained_words, constrained.image, "output")
                == std::vector<std::uint32_t>(65536, 18),
            "capacity-limited entry preparation changed the result");
}

void test_entry_preloads_complete_ntt_parameters()
{
    namespace r = hpu::resource;
    constexpr std::uint32_t q = 65537;
    constexpr std::size_t degree = 8192;
    const hpu::model::HardwareNttModel model(degree, q,
        hpu::model::pow_mod(3, (q - 1) / degree, q));
    hpu::runtime::HpuMemImage image(512);
    constexpr auto mu = std::numeric_limits<std::uint64_t>::max() / q;
    image.add("moduli", {q, static_cast<std::uint32_t>(mu), static_cast<std::uint32_t>(mu >> 32), 0},
              AllocationKind::modulus_table);
    std::vector<std::uint32_t> input(degree);
    for (std::size_t i = 0; i < degree; ++i) input[i] = static_cast<std::uint32_t>((97 * i + 3) % q);
    image.add("input", input, AllocationKind::ciphertext);
    image.add("pre", hpu::model::pack_online_pmul_parameters(1, 3, q, degree), AllocationKind::twiddle);
    const auto tables = model.forward_twiddles();
    for (std::size_t stage = 0; stage < tables.size(); ++stage)
        image.add("stage/" + std::to_string(stage), hpu::model::pack_stage_twiddles(tables[stage], q, degree),
                  AllocationKind::twiddle);
    image.reserve("output", degree, AllocationKind::output);
    const auto binding = [&](const std::string& id) -> ResolvedDma {
        return {0, id, image.allocation(id).span, 0, "transform", 0};
    };
    r::Recording recording;
    const auto mod = r::make_operand("mod"), data = r::make_operand("data");
    r::input(mod, binding("moduli"), hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    r::select_modulus(0);
    r::input(data, binding("input"), hpu::DataType::poly);
    const auto pre = r::make_operand("pre");
    r::input(pre, binding("pre"), hpu::DataType::online_pmul_parameters);
    r::multiply_online(data, data, pre);
    for (std::size_t stage = 0; stage < tables.size(); ++stage) {
        const auto parameters = r::make_operand("stage");
        r::input(parameters, binding("stage/" + std::to_string(stage)), hpu::DataType::twiddle_parameters);
        r::ntt_stage(data, parameters, static_cast<int>(stage));
    }
    r::output(data, binding("output"));
    r::finish_program();
    const auto source = recording.finish();
    hpu::compiler::CompileOptions options;
    options.automatic_lifetimes = true;
    const auto baseline = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
    options.preload_readonly_inputs = true;
    const auto prepared = hpu::compiler::compile_resources(r::bind_program(source, image), {}, {}, image, options);
    require(prepared.report.preloaded_dma_count == 16 && prepared.report.spills == 0
            && prepared.report.reloads == 0 && prepared.report.dma_count == baseline.report.dma_count,
            "complete single-modulus NTT parameter set was not retained at entry");
    bool computation_started = false;
    for (const auto& encoded : prepared.instructions) {
        const auto mnemonic = encoded.instruction.mnemonic;
        if (mnemonic == hpu::Mnemonic::kPmul || mnemonic == hpu::Mnemonic::kPntt) computation_started = true;
        require(mnemonic != hpu::Mnemonic::kDload || !computation_started,
                "NTT parameter load remained inside the continuous execution interval");
    }
    const auto execute = [&](const auto& program) {
        std::vector<hpu::runtime::HpuMemSpan> ranges;
        for (const auto& dma : program.dma) ranges.push_back(dma.span);
        const auto result = hpu::model::execute_instructions(program.instructions, ranges, program.image);
        require(result.report.completed(), result.report.message.c_str());
        return allocation_words(result.words, program.image, "output");
    };
    require(execute(prepared) == execute(baseline), "entry preloading changed the NTT result");
}

} // namespace

int main()
{
    try {
        test_per_command_cache_policy();
        test_twiddle_cache_policy();
        test_twiddle_cache_policy_after_eviction();
        test_use_index();
        test_ssa_versions_and_ports();
        test_unbounded_operand_ids();
        test_full_64_object_bank_layout();
        test_store_retention_and_pmac_capacity();
        test_ntt_preserves_live_ssa_input();
        test_online_pmul_parameter_lifetime_and_destination();
        test_deferred_reload_storage_lifetime();
        test_native_operator_resources();
        test_nested_recording();
        test_fragment_ssa_renaming();
        test_entry_preload_preserves_continuous_schedule();
        test_entry_preloads_complete_ntt_parameters();
        test_scratch_reuse();
        test_dirty_spill();
        test_stage_bank_and_multiple_readers();
        test_destination_shape_change();
        test_partial_initialization_and_overlapping_lifetimes();
        std::cout << "Compiler resource IR, DDR reuse and bank scheduling tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Compiler resource test failed: " << error.what() << '\n';
        return 1;
    }
}
