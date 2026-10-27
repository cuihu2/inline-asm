#include "hpu/compiler/resource_ir.hpp"
#include "hpu/compiler/operator_resources.hpp"
#include "hpu/compiler/detail/use_index.hpp"
#include "hpu/runtime/bank_allocator.hpp"

#include "encoder.hpp"
#include "executable.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace hpu::compiler {
namespace {

constexpr std::size_t kNoUse = std::numeric_limits<std::size_t>::max();
constexpr const char* kScratchArena = "$compiler/scratch_arena";

bool contains(hpu::runtime::HpuMemSpan outer, hpu::runtime::HpuMemSpan inner)
{
    return inner.line_count != 0 && inner.line_offset >= outer.line_offset
        && inner.line_offset - outer.line_offset <= outer.line_count
        && inner.line_count <= outer.line_count - (inner.line_offset - outer.line_offset);
}

bool overlaps(hpu::runtime::HpuMemSpan a, hpu::runtime::HpuMemSpan b)
{
    return a.line_offset < b.line_offset + b.line_count
        && b.line_offset < a.line_offset + a.line_count;
}

bool same_span(hpu::runtime::HpuMemSpan a, hpu::runtime::HpuMemSpan b)
{
    return a.line_offset == b.line_offset && a.line_count == b.line_count;
}

hpu::EncodedInstruction encode(hpu::Instruction instruction)
{
    const auto word = hpu::encode_instruction(instruction);
    return {instruction, word, hpu::precode_command26(word), hpu::to_string(instruction)};
}

void unique_push(std::vector<ObjectId>& values, ObjectId value)
{
    if (std::find(values.begin(), values.end(), value) == values.end()) {
        values.push_back(value);
    }
}

std::string json_string(const std::string& value)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char character : value) {
        if (character == '\\' || character == '"') {
            result += '\\';
            result += static_cast<char>(character);
        } else if (character < 0x20) {
            result += "\\u00";
            result += hex[character >> 4];
            result += hex[character & 15];
        } else {
            result += static_cast<char>(character);
        }
    }
    result += '"';
    return result;
}

const char* layout_name(MemoryLayout layout)
{
    switch (layout) {
    case MemoryLayout::coefficient_natural: return "coefficient_natural";
    case MemoryLayout::coefficient_bit_reversed: return "coefficient_bit_reversed";
    case MemoryLayout::canonical_ntt_physical: return "canonical_ntt_physical";
    default: return "unspecified";
    }
}

std::vector<std::optional<std::size_t>> dma_by_instruction(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma)
{
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    if (encoded_dma.size() != dma.size()) {
        throw std::invalid_argument("resolved DMA count differs from encoded program");
    }
    std::vector<std::optional<std::size_t>> indices(instructions.size());
    for (std::size_t index = 0; index < dma.size(); ++index) {
        if (dma[index].instruction_index != encoded_dma[index].instruction_index) {
            throw std::invalid_argument("resolved DMA must be in encoded instruction order");
        }
        indices[dma[index].instruction_index] = index;
    }
    return indices;
}

void apply_dma_cache_policy(CompiledResources& resources, DmaCachePolicy policy)
{
    if (policy == DmaCachePolicy::preserve) return;
    if (policy != DmaCachePolicy::twiddle_loads_only) {
        throw std::invalid_argument("unknown DMA cache policy");
    }
    // Require complete one-to-one provenance before editing any hint. Object
    // slots and Bank 5 masks cannot identify data after eviction and reuse.
    dma_by_instruction(resources.instructions, resources.dma);
    for (const auto& dma : resources.dma) {
        const auto& allocation = resources.image.allocation(dma.allocation_id);
        if (!contains(allocation.span, dma.span)) {
            throw std::invalid_argument("DMA cache policy range exceeds allocation: " + allocation.id);
        }
        auto& encoded = resources.instructions.at(dma.instruction_index);
        auto instruction = encoded.instruction;
        instruction.cp = instruction.mnemonic == hpu::Mnemonic::kDload
                && allocation.kind == hpu::runtime::AllocationKind::twiddle
            ? 1 : 0;
        encoded = encode(instruction);
    }
}

void record_io(CompiledResources& resources, const std::vector<ResolvedDma>& original)
{
    auto& report = resources.report;
    for (const auto& entry : original) report.original_dma_bytes += entry.span.line_count * 256;
    std::set<std::tuple<std::string, std::uint64_t, std::uint64_t>> reads;
    for (const auto& entry : resources.dma) {
        const auto bytes = entry.span.line_count * 256;
        const auto& instruction = resources.instructions.at(entry.instruction_index).instruction;
        if (entry.purpose == "spill") report.spill_write_bytes += bytes;
        if (entry.purpose == "reload") report.reload_read_bytes += bytes;
        if (entry.purpose == "exact_copy") report.exact_copy_bytes += bytes;
        if (instruction.mnemonic == hpu::Mnemonic::kDload) {
            report.dload_bytes += bytes;
            if (!reads.emplace(entry.allocation_id, entry.span.line_offset, entry.span.line_count).second)
                report.repeated_range_read_bytes += bytes;
        } else {
            report.dstore_bytes += bytes;
            if (resources.image.allocation(entry.allocation_id).kind == hpu::runtime::AllocationKind::output)
                report.required_output_write_bytes += bytes;
        }
    }
    report.initial_image_bytes = resources.image.used_lines() * 256;
}

// Removing a writeback is safe only when there is one exact consumer before
// the next overlapping write. Other loads could observe the old DDR contents.
std::map<std::size_t, std::size_t> deferred_store_pairs(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image)
{
    std::map<std::size_t, std::size_t> pairs;
    for (std::size_t index = 0; index < dma.size(); ++index) {
        const auto& store = dma[index];
        const auto& allocation = image.allocation(store.allocation_id);
        if (instructions[store.instruction_index].instruction.mnemonic
                != hpu::Mnemonic::kDstore
            || allocation.kind != hpu::runtime::AllocationKind::workspace
            || allocation.read_only) {
            continue;
        }
        std::optional<std::size_t> consumer;
        for (std::size_t next = index + 1; next < dma.size(); ++next) {
            if (!overlaps(store.span, dma[next].span)) continue;
            if (instructions[dma[next].instruction_index].instruction.mnemonic
                    == hpu::Mnemonic::kDload
                && same_span(store.span, dma[next].span)) {
                consumer = next;
            }
            break;
        }
        if (!consumer) continue;
        bool observed = false;
        for (std::size_t instruction = store.instruction_index + 1;
             instruction < dma[*consumer].instruction_index; ++instruction)
            if (instructions[instruction].instruction.mnemonic == hpu::Mnemonic::kPsync) observed = true;
        if (observed) continue;
        bool another_read = false;
        for (std::size_t next = *consumer + 1; next < dma.size(); ++next) {
            if (!overlaps(store.span, dma[next].span)) continue;
            another_read = instructions[dma[next].instruction_index].instruction.mnemonic
                != hpu::Mnemonic::kDstore;
            // A partial overlapping write leaves part of the old value live.
            if (!contains(dma[next].span, store.span)) another_read = true;
            break;
        }
        if (!another_read) pairs.emplace(index, *consumer);
    }
    return pairs;
}

void analyze_buffers(VirtualProgram& program,
                     const std::vector<ResolvedDma>& dma,
                     const std::vector<hpu::EncodedInstruction>& instructions,
                     const hpu::runtime::HpuMemImage& image)
{
    std::map<std::string, BufferId> ids;
    std::vector<std::vector<bool>> written;
    for (BufferId index = 0; index < program.buffers.size(); ++index) {
        auto& buffer = program.buffers[index];
        ids.emplace(buffer.id, index);
        buffer.first_use = kNoUse;
        buffer.fully_defined_before_read = true;
        written.emplace_back(buffer.original_span.line_count, false);
    }
    for (const auto& entry : dma) {
        const auto& allocation = image.allocation(entry.allocation_id);
        const BufferId id = ids.at(allocation.id);
        auto& buffer = program.buffers[id];
        buffer.first_use = std::min(buffer.first_use, entry.instruction_index);
        buffer.last_use = std::max(buffer.last_use, entry.instruction_index);
        const auto offset = entry.span.line_offset - allocation.span.line_offset;
        const bool load = instructions[entry.instruction_index].instruction.mnemonic
            == hpu::Mnemonic::kDload;
        for (std::uint64_t line = offset; line < offset + entry.span.line_count; ++line) {
            if (load && !written[id][line]) buffer.fully_defined_before_read = false;
            if (!load) written[id][line] = true;
        }
    }
    for (auto& buffer : program.buffers) {
        buffer.retained = buffer.kind != hpu::runtime::AllocationKind::workspace
            || buffer.read_only || !buffer.fully_defined_before_read;
        if (buffer.first_use == kNoUse) {
            // Unused payloads are kept for deterministic image compatibility.
            buffer.first_use = 0;
            buffer.retained = true;
        }
    }
}

hpu::runtime::BankAllocatorOptions bank_options(const CompileOptions& options)
{
    hpu::runtime::BankAllocatorOptions result;
    result.regular_bank_count = options.regular_bank_count;
    result.regular_bank_lines = options.regular_bank_lines;
    result.mod_table_lines = options.mod_table_lines;
    return result;
}

void record_bank_usage(ResourceReport& report,
                       const hpu::runtime::BankAllocator& allocator)
{
    const auto stats = allocator.stats();
    report.peak_regular_banks = stats.peak_regular_banks;
    report.peak_object_slots = stats.peak_resident_objects;
    report.peak_regular_lines = stats.peak_regular_lines;
    report.peak_small_lines = stats.peak_small_lines;
}

ResourceReport inspect_original(const std::vector<hpu::EncodedInstruction>& instructions,
                                const std::vector<ResolvedDma>& dma,
                                const hpu::runtime::HpuMemImage& image,
                                const CompileOptions& options)
{
    const auto lookup = dma_by_instruction(instructions, dma);
    hpu::runtime::BankAllocator allocator(bank_options(options));
    ResourceReport report;
    report.original_ddr_lines = image.used_lines();
    report.allocated_ddr_lines = image.used_lines();
    report.original_dma_count = report.dma_count = dma.size();
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& op = instructions[index].instruction;
        switch (op.mnemonic) {
        case hpu::Mnemonic::kDload:
            allocator.load(op.obj_id, dma.at(*lookup[index]).span.line_count,
                           op.type, op.dma_flag);
            break;
        case hpu::Mnemonic::kDstore:
            if (op.type == 1) allocator.release(op.obj_id);
            break;
        case hpu::Mnemonic::kPfree: allocator.release(op.idx0); break;
        case hpu::Mnemonic::kPadd:
        case hpu::Mnemonic::kPsub:
        case hpu::Mnemonic::kPmul:
        case hpu::Mnemonic::kPmac:
            if (op.mnemonic == hpu::Mnemonic::kPmul && op.mode == 1)
                allocator.online_multiply(op.pdst, op.psrc1, op.psrc2);
            else allocator.arithmetic(op.pdst, op.psrc1,
                op.imm8 < 0 ? std::optional<std::uint8_t>(op.psrc2) : std::nullopt,
                op.mnemonic == hpu::Mnemonic::kPmac);
            break;
        case hpu::Mnemonic::kPntt:
        case hpu::Mnemonic::kPintt: allocator.ntt(op.pdst); break;
        default: break;
        }
    }
    record_bank_usage(report, allocator);
    return report;
}

struct PendingDma {
    std::size_t instruction_index;
    BufferRange range;
    ResolvedDma origin;
};

struct ScheduledProgram {
    std::vector<hpu::EncodedInstruction> instructions;
    std::vector<PendingDma> dma;
    ResourceReport report;
};

class Scheduler {
public:
    Scheduler(VirtualProgram& program, const CompileOptions& options,
              std::size_t preload_limit = 0)
        : program_(program), states_(program.objects.size()), uses_(program),
          allocator_(bank_options(options)), automatic_(options.automatic_lifetimes),
          preload_limit_(preload_limit) {}

    ScheduledProgram run()
    {
        if (preload_limit_) preload_inputs();
        for (cursor_ = 0; cursor_ < program_.instructions.size(); ++cursor_) {
            const auto op = program_.instructions[cursor_];
            uses_.consume(op, cursor_);
            current_origin_ = op.origin.value_or(ResolvedDma{});
            excluded_.clear();
            excluded_.insert(op.uses.begin(), op.uses.end());
            excluded_.insert(op.definitions.begin(), op.definitions.end());
            switch (op.instruction.mnemonic) {
            case hpu::Mnemonic::kDload: load(op); break;
            case hpu::Mnemonic::kDstore: store(op); break;
            case hpu::Mnemonic::kPfree:
                if (next_use(op.uses.at(0)) == kNoUse) release(op.uses.at(0));
                break;
            case hpu::Mnemonic::kPmodld:
                if (modulus_) ensure(*modulus_);
                emit(op.instruction);
                break;
            case hpu::Mnemonic::kPsync:
                // PSYNC only waits. In particular an intermediate wait must
                // preserve dirty values and REL=0 objects used afterwards.
                emit(op.instruction);
                break;
            default: kernel(op); break;
            }
            if (automatic_) {
                auto dead = op.uses;
                dead.insert(dead.end(), op.definitions.begin(), op.definitions.end());
                for (const auto id : dead)
                    if ((!modulus_ || *modulus_ != id) && next_use(id) == kNoUse) release(id);
            }
        }
        hpu::validate_executable_program(result_.instructions);
        result_.report.dma_count = result_.dma.size();
        return std::move(result_);
    }

private:
    struct State {
        std::optional<std::uint8_t> slot;
        std::optional<BufferRange> home;
        std::optional<BufferId> spill;
        bool dirty = false;
        bool initialized = false;
        std::size_t loads = 0;
        bool exact_copy = false;
        std::string logical_value;
        std::optional<std::size_t> prefetched_definition;
    };

    void preload_inputs()
    {
        // Only initial immutable memory versions can move across arbitrary
        // operations. A later DLOAD into reused storage is not an initial
        // definition and must retain its position in the normal schedule.
        std::vector<std::optional<std::size_t>> first_definition(states_.size());
        std::vector<std::size_t> load_count(states_.size());
        std::uint64_t largest_block = 128;
        for (const auto& shape : program_.objects) {
            if (shape.type == 1 || (shape.dma_flag && !(shape.dma_flag & 0x1f))) continue;
            std::uint64_t capacity = 128;
            while (capacity < shape.line_count) capacity *= 2;
            largest_block = std::max(largest_block, capacity);
        }
        for (std::size_t i = 0; i < program_.instructions.size(); ++i) {
            const auto& op = program_.instructions[i];
            for (const auto id : op.definitions) {
                if (!first_definition[id]) first_definition[id] = i;
                if (op.instruction.mnemonic == hpu::Mnemonic::kDload) ++load_count[id];
            }
        }
        const auto& limits = allocator_.options();
        const auto total_lines = limits.regular_bank_count * limits.regular_bank_lines;
        const auto regular_budget = total_lines > 2 * largest_block
            ? total_lines - 2 * largest_block : 0;
        std::uint64_t immutable_small_lines = 0;
        for (std::size_t i = 0; i < program_.instructions.size(); ++i) {
            const auto& op = program_.instructions[i];
            if (op.instruction.mnemonic != hpu::Mnemonic::kDload || !op.memory
                || op.definitions.size() != 1) continue;
            const auto id = op.definitions.front();
            const auto& shape = program_.objects[id];
            if (shape.type != 1 && shape.dma_flag == 0x20
                && first_definition[id] == i && load_count[id] == 1
                && program_.buffers[op.memory->buffer].read_only)
                immutable_small_lines += shape.line_count;
        }
        // A complete single-modulus N8192 transform has exactly fourteen
        // two-line parameters, which can all stay in Bank 5. Otherwise leave
        // two parameter slots available for later on-demand resources.
        const auto small_budget = immutable_small_lines
                <= limits.small_bank_lines - limits.mod_table_lines
            ? limits.small_bank_lines : limits.small_bank_lines - 4;
        std::size_t ordinary_count = 0;
        bool modulus_loaded = false;
        const auto try_load = [&](std::size_t i) {
            const auto& op = program_.instructions[i];
            if (op.instruction.mnemonic != hpu::Mnemonic::kDload
                || !op.memory || op.definitions.size() != 1 || op.reload_retained_object
                || !program_.buffers[op.memory->buffer].read_only) return;
            const auto id = op.definitions.front();
            const auto& shape = program_.objects[id];
            if (first_definition[id] != i || load_count[id] != 1
                || (shape.type != 1 && next_use(id) == kNoUse)) return;
            if (shape.type == 1 ? modulus_loaded : ordinary_count >= preload_limit_) return;
            std::array<bool, 64> used{};
            for (const auto other : resident_) used[*states_[other].slot] = true;
            auto free_slot = std::find(used.begin(), used.end(), false);
            if (shape.type == 1 && !used[4]) free_slot = used.begin() + 4;
            // Leave logical names available for normal instruction results.
            if (free_slot == used.end() || resident_.size() >= 60) return;
            const auto slot = static_cast<std::uint8_t>(free_slot - used.begin());
            auto trial = allocator_;
            try { trial.load(slot, shape.line_count, shape.type, shape.dma_flag); }
            catch (const hpu::runtime::BankAllocationError&) { return; }
            if (shape.type != 1 && (trial.stats().regular_lines > regular_budget
                || trial.stats().small_lines > small_budget)) return;
            allocator_ = std::move(trial);
            auto& state = states_[id];
            state.slot = slot;
            state.home = op.memory;
            state.initialized = true;
            state.loads = 1;
            state.exact_copy = op.exact_copy;
            state.logical_value = op.logical_value;
            state.prefetched_definition = i;
            resident_.insert(id);
            if (shape.type == 1) { modulus_ = id; modulus_loaded = true; }
            else ++ordinary_count;
            auto instruction = op.instruction;
            instruction.obj_id = slot;
            auto origin = op.origin.value_or(ResolvedDma{});
            origin.purpose = op.exact_copy ? "exact_copy" : "input";
            origin.logical_value = op.logical_value;
            emit_dma(instruction, *op.memory, std::move(origin));
            ++result_.report.preloaded_dma_count;
            result_.report.preloaded_dma_bytes += shape.line_count * 256;
            measure();
        };
        // The fixed modulus-table owner remains the first resident resource.
        bool has_modulus_load = false;
        for (std::size_t i = 0; i < program_.instructions.size(); ++i) {
            const auto& op = program_.instructions[i];
            if (op.instruction.mnemonic == hpu::Mnemonic::kDload && !op.definitions.empty()
                && program_.objects[op.definitions.front()].type == 1) {
                has_modulus_load = true;
                try_load(i);
                break;
            }
        }
        if (has_modulus_load && !modulus_loaded) return;
        for (std::size_t i = 0; i < program_.instructions.size(); ++i) {
            const auto& op = program_.instructions[i];
            if (op.instruction.mnemonic == hpu::Mnemonic::kDload && !op.definitions.empty()
                && program_.objects[op.definitions.front()].type != 1) try_load(i);
        }
    }

    std::size_t next_use(ObjectId id) const
    {
        return uses_.next(id);
    }

    void measure() { record_bank_usage(result_.report, allocator_); }

    void emit(hpu::Instruction instruction) { result_.instructions.push_back(encode(instruction)); }

    void emit_dma(hpu::Instruction instruction, BufferRange range, ResolvedDma origin)
    {
        const std::size_t index = result_.instructions.size();
        emit(instruction);
        origin.instruction_index = index;
        result_.dma.push_back({index, range, std::move(origin)});
        auto& buffer = program_.buffers[range.buffer];
        buffer.first_use = std::min(buffer.first_use, cursor_);
        buffer.last_use = std::max(buffer.last_use, cursor_);
    }

    void release(ObjectId id)
    {
        auto& state = states_[id];
        if (!state.slot) return;
        hpu::Instruction free;
        free.mnemonic = hpu::Mnemonic::kPfree;
        free.idx0 = *state.slot;
        free.idx1 = 0;
        emit(free);
        allocator_.release(*state.slot);
        state.slot.reset();
        resident_.erase(id);
    }

    void evict(ObjectId id, bool preserve_current_use = false)
    {
        auto& state = states_[id];
        if (state.dirty && (preserve_current_use || next_use(id) != kNoUse)) {
            if (!state.spill) {
                VirtualBuffer buffer;
                buffer.id = "$compiler/spill/" + std::to_string(id);
                buffer.original_span = {0, program_.objects[id].line_count};
                buffer.word_count = buffer.original_span.line_count
                    * hpu::runtime::kHpuMemLineWords;
                buffer.retained = false;
                buffer.fully_defined_before_read = true;
                buffer.first_use = cursor_;
                buffer.last_use = cursor_;
                state.spill = program_.buffers.size();
                program_.buffers.push_back(std::move(buffer));
            }
            const BufferRange spill{*state.spill, 0, program_.objects[id].line_count};
            hpu::Instruction store;
            store.mnemonic = hpu::Mnemonic::kDstore;
            store.rs1 = 10;
            store.rs2 = 11;
            store.obj_id = *state.slot;
            store.type = 1;
            auto origin = current_origin_;
            origin.purpose = "spill";
            origin.logical_value = state.logical_value;
            emit_dma(store, spill, std::move(origin));
            allocator_.release(*state.slot);
            state.slot.reset();
            resident_.erase(id);
            state.home = spill;
            state.dirty = false;
            ++result_.report.spills;
        } else {
            release(id);
        }
    }

    void evict_one()
    {
        std::optional<ObjectId> victim;
        std::size_t farthest = 0;
        std::uint64_t cheapest = std::numeric_limits<std::uint64_t>::max();
        for (const auto id : resident_) {
            if (excluded_.count(id)) continue;
            if (automatic_ && modulus_ && *modulus_ == id) continue;
            const auto next = next_use(id);
            const auto cost = next == kNoUse ? 0 : program_.objects[id].line_count
                * (states_[id].dirty ? 2 : 1);
            if (!victim || (automatic_ && cost < cheapest)
                || ((!automatic_ || cost == cheapest)
                    && (next > farthest || (next == farthest && id < *victim)))) {
                victim = id;
                farthest = next;
                cheapest = cost;
            }
        }
        if (!victim) {
            throw ResourceCapacityError(
                "kernel operands exceed aligned physical bank capacity");
        }
        evict(*victim);
    }

    std::uint8_t allocate_slot(ObjectId id)
    {
        for (;;) {
            std::array<bool, 64> used{};
            for (const auto other : resident_) used[*states_[other].slot] = true;
            auto first = std::find(used.begin(), used.end(), false);
            // Preserve the familiar modulus-table name when available; p4 is
            // otherwise an ordinary usable logical object, just like p0..p63.
            if (program_.objects[id].type == 1 && !used[4]) first = used.begin() + 4;
            if (first != used.end()) {
                states_[id].slot = static_cast<std::uint8_t>(first - used.begin());
                resident_.insert(id);
                return *states_[id].slot;
            }
            evict_one();
        }
    }

    template <class Request> void allocate_physical(
        Request request, std::uint64_t lines = 0, std::uint8_t allowed = 0x3f)
    {
        for (;;) {
            try {
                request();
                measure();
                return;
            } catch (const hpu::runtime::BankAllocationError&) {
                // Hardware never spills automatically. Only explicit compiler
                // writebacks/frees change ownership before retrying a request.
                if (!automatic_) { evict_one(); continue; }
                // Probe whole aligned candidate intervals. Evicting an object
                // in an unrelated bank cannot resolve the failed allocation.
                const auto original = allocator_;
                std::vector<ObjectId> best;
                std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
                std::size_t best_distance = 0;
                for (std::size_t bank = 0; bank < 6; ++bank) {
                    if (!(allowed & (1U << bank))) continue;
                    std::uint64_t capacity = bank == 5 ? lines : 128;
                    while (capacity < lines) capacity *= 2;
                    const auto limit = bank == 5 ? 32U : 1024U;
                    const auto stride = bank == 5 ? 2U : capacity;
                    if (!capacity || capacity > limit) continue;
                    for (std::uint64_t base = bank == 5 ? allocator_.options().mod_table_lines : 0;
                         base + capacity <= limit; base += stride) {
                        std::vector<ObjectId> victims;
                        std::uint64_t cost = 0;
                        std::size_t distance = kNoUse;
                        bool blocked = false;
                        for (const auto id : resident_) {
                            if (!states_[id].slot) continue;
                            const auto& allocation = allocator_.allocation(*states_[id].slot);
                            if (!allocation || allocation->bank != bank
                                || base >= allocation->base_line + allocation->capacity_lines
                                || allocation->base_line >= base + capacity) continue;
                            if (excluded_.count(id) || (modulus_ && *modulus_ == id)) { blocked = true; break; }
                            victims.push_back(id);
                            const auto next = next_use(id);
                            if (next != kNoUse)
                                cost += program_.objects[id].line_count * (states_[id].dirty ? 2 : 1);
                            distance = std::min(distance, next);
                        }
                        if (blocked || victims.empty()) continue;
                        allocator_ = original;
                        for (const auto id : victims) allocator_.release(*states_[id].slot);
                        bool fits = true;
                        try { request(); } catch (const hpu::runtime::BankAllocationError&) { fits = false; }
                        allocator_ = original;
                        if (fits && (best.empty() || cost < best_cost
                            || (cost == best_cost && distance > best_distance))) {
                            best = std::move(victims); best_cost = cost; best_distance = distance;
                        }
                    }
                }
                allocator_ = original;
                if (best.empty()) throw ResourceCapacityError("kernel operands exceed allowed aligned bank capacity");
                for (const auto id : best) evict(id);
            }
        }
    }

    void place_load(ObjectId id)
    {
        excluded_.insert(id);
        const auto& shape = program_.objects[id];
        // Bank 5 has one fixed modulus-table owner, even though its logical ID
        // can be any of the 64 slots. A previously evicted table is reloadable.
        if (shape.type == 1) {
            for (auto it = resident_.begin(); it != resident_.end();) {
                const auto other = *it++;
                if (other != id && program_.objects[other].type == 1) evict(other);
            }
        }
        const auto slot = states_[id].slot ? *states_[id].slot : allocate_slot(id);
        try {
            allocate_physical([&] {
                allocator_.load(slot, shape.line_count, shape.type, shape.dma_flag);
            }, shape.line_count, shape.dma_flag ? shape.dma_flag : shape.type == 1 ? 0x20 : 0x1f);
        } catch (...) {
            // A failed placement has no resident value. In particular store()
            // may free the replacement and retry this exact memory version.
            if (allocator_.allocation(slot)) allocator_.release(slot);
            states_[id].slot.reset();
            resident_.erase(id);
            throw;
        }
    }

    void ensure(ObjectId id)
    {
        auto& state = states_[id];
        if (state.slot) return;
        if (!state.initialized || !state.home) {
            throw std::logic_error("virtual object has no reloadable definition");
        }
        place_load(id);
        const auto slot = *state.slot;
        hpu::Instruction load;
        load.mnemonic = hpu::Mnemonic::kDload;
        load.rs1 = 10;
        load.rs2 = 11;
        load.obj_id = slot;
        load.type = program_.objects[id].type;
        load.dma_flag = program_.objects[id].dma_flag;
        auto origin = current_origin_;
        origin.purpose = state.exact_copy ? "exact_copy" : state.loads ? "reload" : "input";
        origin.logical_value = state.logical_value;
        emit_dma(load, *state.home, std::move(origin));
        if (!automatic_ || state.loads++) ++result_.report.reloads;
    }

    void load(const VirtualInstruction& op)
    {
        const ObjectId id = op.definitions.at(0);
        auto& state = states_[id];
        if (state.prefetched_definition == cursor_) {
            // This exact immutable definition was materialized at entry. If
            // normal allocation evicted it, its unchanged home still reloads
            // on demand; do not erase its residency or memory version here.
            state.prefetched_definition.reset();
            return;
        }
        if (op.reload_retained_object) {
            ensure(id);
            return;
        }
        state.home = op.memory;
        state.initialized = true;
        state.dirty = false;
        state.exact_copy = op.exact_copy;
        state.logical_value = op.logical_value;
        if (program_.objects[id].type == 1) modulus_ = id;
        // Immutable inputs are references, materialized at their first actual
        // consumer. Mutable reads stay eager to preserve read-before-write.
        if (automatic_ && program_.buffers[op.memory->buffer].read_only) return;
        // Conservative native lowering can materialize a formerly deferred
        // reload into the same storage object. DLOAD replaces that definition.
        release(id);
        auto instruction = op.instruction;
        place_load(id);
        instruction.obj_id = *state.slot;
        if (program_.objects[id].type == 1) modulus_ = id;
        auto origin = *op.origin;
        origin.purpose = op.exact_copy ? "exact_copy" : "input";
        origin.logical_value = state.logical_value;
        emit_dma(instruction, *op.memory, std::move(origin));
        ++state.loads;
    }

    void store(const VirtualInstruction& op)
    {
        const ObjectId id = op.uses.at(0);
        if (!op.required_store) {
            ++result_.report.deferred_scratch_stores;
            return;
        }
        if (automatic_) {
            // A backing is a particular memory version, not merely an address.
            // Freeze old live versions before a write destroys their home.
            for (ObjectId other = 0; other < states_.size(); ++other) {
                auto& state = states_[other];
                if (other == id || !state.initialized || !state.home || next_use(other) == kNoUse
                    || state.home->buffer != op.memory->buffer
                    || !overlaps({state.home->line_offset, state.home->line_count},
                                 {op.memory->line_offset, op.memory->line_count})) continue;
                const bool protected_before = excluded_.count(other) != 0;
                try { ensure(other); }
                catch (const ResourceCapacityError&) {
                    if (!states_[id].slot) throw;
                    // The replacement may occupy the only allowed interval.
                    // Give it an exact backing while freezing the old version.
                    evict(id, true);
                    ensure(other);
                }
                state.dirty = true;
                state.home.reset();
                if (!protected_before) excluded_.erase(other);
            }
        }
        ensure(id);
        auto instruction = op.instruction;
        instruction.obj_id = *states_[id].slot;
        if (automatic_) instruction.type = next_use(id) == kNoUse ? 1 : 0;
        auto origin = *op.origin;
        origin.purpose = op.exact_copy ? "exact_copy" : "store";
        origin.logical_value = states_[id].logical_value;
        emit_dma(instruction, *op.memory, std::move(origin));
        if (instruction.type == 1) {
            allocator_.release(*states_[id].slot);
            states_[id].slot.reset();
            resident_.erase(id);
        }
        states_[id].home = op.memory;
        states_[id].dirty = false;
    }

    void kernel(const VirtualInstruction& op)
    {
        for (ObjectId id : op.uses) ensure(id);
        std::vector<std::uint8_t> source_slots;
        for (const auto id : op.uses) source_slots.push_back(*states_[id].slot);
        const ObjectId destination = op.definitions.at(0);
        if (automatic_ && !states_[destination].slot
            && op.instruction.mnemonic != hpu::Mnemonic::kPmac
            && op.instruction.mnemonic != hpu::Mnemonic::kPntt
            && op.instruction.mnemonic != hpu::Mnemonic::kPintt) {
            for (const auto source : op.uses) {
                if (op.instruction.mnemonic == hpu::Mnemonic::kPmul && op.instruction.mode == 1
                    && source != op.uses.front()) continue;
                if (next_use(source) != kNoUse || !states_[source].slot
                    || program_.objects[source].type == 1) continue;
                states_[destination].slot = states_[source].slot;
                states_[source].slot.reset(); resident_.erase(source); resident_.insert(destination);
                break;
            }
        }
        if (!states_[destination].slot) allocate_slot(destination);
        const bool stage = op.instruction.mnemonic == hpu::Mnemonic::kPntt
            || op.instruction.mnemonic == hpu::Mnemonic::kPintt;
        auto instruction = op.instruction;
        instruction.pdst = *states_[destination].slot;
        if (stage) {
            // STG uses begin with data, then twiddle.
            instruction.psrc1 = source_slots.at(1);
        } else {
            instruction.psrc1 = source_slots.at(0);
            if (instruction.imm8 < 0) instruction.psrc2 = source_slots.at(1);
        }
        std::uint8_t allowed = 0x1f;
        if (stage) {
            const auto bank = allocator_.allocation(instruction.pdst)->bank;
            if (bank < 5) allowed &= static_cast<std::uint8_t>(~(1U << bank));
        }
        allocate_physical([&] {
            if (stage) allocator_.ntt(instruction.pdst);
            else if (instruction.mnemonic == hpu::Mnemonic::kPmul && instruction.mode == 1)
                allocator_.online_multiply(instruction.pdst, instruction.psrc1, instruction.psrc2);
            else allocator_.arithmetic(instruction.pdst, instruction.psrc1,
                instruction.imm8 < 0 ? std::optional<std::uint8_t>(instruction.psrc2) : std::nullopt,
                instruction.mnemonic == hpu::Mnemonic::kPmac);
        }, program_.objects[destination].line_count, allowed);
        emit(instruction);
        states_[destination].initialized = true;
        states_[destination].dirty = true;
        states_[destination].exact_copy = false;
        states_[destination].logical_value = op.logical_value;
        measure();
    }

    VirtualProgram& program_;
    std::vector<State> states_;
    detail::UseIndex uses_;
    hpu::runtime::BankAllocator allocator_;
    std::optional<ObjectId> modulus_;
    std::set<ObjectId> resident_;
    ScheduledProgram result_;
    std::set<ObjectId> excluded_;
    std::size_t cursor_ = 0;
    ResolvedDma current_origin_;
    bool automatic_ = false;
    std::size_t preload_limit_ = 0;
};

std::vector<LogicalBufferPlacement> place_buffers(
    const VirtualProgram& program,
    const hpu::runtime::HpuMemImage& original,
    hpu::runtime::HpuMemImage& image,
    std::uint64_t& arena_lines,
    bool reuse_scratch = true)
{
    std::vector<LogicalBufferPlacement> result(program.buffers.size());
    std::vector<BufferId> scratch;
    for (BufferId id = 0; id < program.buffers.size(); ++id) {
        const auto& buffer = program.buffers[id];
        auto& placement = result[id];
        placement.logical_id = buffer.id;
        placement.original_span = buffer.original_span;
        placement.retained = buffer.retained;
        placement.first_use = buffer.first_use;
        placement.last_use = buffer.last_use;
        placement.layout = buffer.layout;
        if (!buffer.materialized) continue;
        if (!buffer.retained && reuse_scratch) {
            scratch.push_back(id);
            continue;
        }
        hpu::runtime::HpuMemAllocation allocation;
        if (original.contains(buffer.id)) {
            const auto begin = original.words().begin()
                + buffer.original_span.line_offset * hpu::runtime::kHpuMemLineWords;
            std::vector<std::uint32_t> words(begin, begin + buffer.word_count);
            allocation = image.add(buffer.id, words, buffer.kind, buffer.read_only);
        } else {
            allocation = image.reserve(buffer.id, buffer.word_count, buffer.kind);
        }
        placement.physical_allocation_id = allocation.id;
        placement.span = allocation.span;
    }
    std::sort(scratch.begin(), scratch.end(), [&](BufferId a, BufferId b) {
        const auto& left = program.buffers[a];
        const auto& right = program.buffers[b];
        return left.first_use != right.first_use
            ? left.first_use < right.first_use : a < b;
    });
    std::vector<BufferId> placed;
    arena_lines = 0;
    for (BufferId id : scratch) {
        const auto& buffer = program.buffers[id];
        std::vector<hpu::runtime::HpuMemSpan> occupied;
        for (BufferId previous : placed) {
            const auto& other = program.buffers[previous];
            if (other.first_use <= buffer.last_use && buffer.first_use <= other.last_use) {
                occupied.push_back(result[previous].span);
            }
        }
        std::sort(occupied.begin(), occupied.end(), [](auto a, auto b) {
            return a.line_offset < b.line_offset;
        });
        std::uint64_t offset = 0;
        for (const auto& span : occupied) {
            if (offset + buffer.original_span.line_count <= span.line_offset) break;
            offset = std::max(offset, span.line_offset + span.line_count);
        }
        result[id].physical_allocation_id = kScratchArena;
        result[id].span = {offset, buffer.original_span.line_count};
        arena_lines = std::max(arena_lines, offset + buffer.original_span.line_count);
        placed.push_back(id);
    }
    if (arena_lines) {
        const auto arena = image.reserve(kScratchArena,
            arena_lines * hpu::runtime::kHpuMemLineWords,
            hpu::runtime::AllocationKind::workspace);
        for (BufferId id : scratch) result[id].span.line_offset += arena.span.line_offset;
    }
    image.trim_capacity_to_used_lines();
    return result;
}

} // namespace

VirtualProgram import_resolved_program(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image)
{
    hpu::validate_executable_program(instructions);
    const auto lookup = dma_by_instruction(instructions, dma);
    const auto pairs = deferred_store_pairs(instructions, dma, image);
    std::map<std::size_t, ObjectId> pending_reload;
    std::array<std::optional<ObjectId>, 64> live;
    std::map<std::string, BufferId> buffer_ids;
    VirtualProgram result;
    for (const auto& allocation : image.allocations()) {
        VirtualBuffer buffer;
        buffer.id = allocation.id;
        buffer.original_span = allocation.span;
        buffer.word_count = allocation.word_count;
        buffer.kind = allocation.kind;
        buffer.read_only = allocation.read_only;
        buffer_ids.emplace(buffer.id, result.buffers.size());
        result.buffers.push_back(std::move(buffer));
    }
    auto object = [&](int slot) -> ObjectId {
        if (slot < 0 || slot >= 64 || !live[slot]) {
            throw std::invalid_argument("virtual instruction references a released object");
        }
        return *live[slot];
    };
    std::optional<ResolvedDma> origin;
    for (std::size_t index = 0; index < instructions.size(); ++index) {
        const auto& instruction = instructions[index].instruction;
        VirtualInstruction op;
        op.instruction = instruction;
        if (lookup[index]) {
            origin = dma[*lookup[index]];
            const auto& allocation = image.allocation(origin->allocation_id);
            if (!contains(allocation.span, origin->span)) {
                throw std::invalid_argument("DMA range exceeds allocation: " + allocation.id);
            }
            if (instruction.mnemonic == hpu::Mnemonic::kDstore && allocation.read_only) {
                throw std::invalid_argument("DSTORE targets read-only allocation: " + allocation.id);
            }
            origin->allocation_id = allocation.id;
            op.memory = BufferRange{buffer_ids.at(allocation.id),
                origin->span.line_offset - allocation.span.line_offset,
                origin->span.line_count};
        }
        op.origin = origin;
        switch (instruction.mnemonic) {
        case hpu::Mnemonic::kDload: {
            const auto reused = pending_reload.find(*lookup[index]);
            ObjectId id;
            if (reused != pending_reload.end()) {
                id = reused->second;
                op.reload_retained_object = true;
            } else {
                id = result.objects.size();
                result.objects.push_back({op.memory->line_count, instruction.type,
                    instruction.dma_flag});
            }
            live[instruction.obj_id] = id;
            op.definitions.push_back(id);
            break;
        }
        case hpu::Mnemonic::kDstore: {
            const ObjectId id = object(instruction.obj_id);
            if (result.objects[id].line_count != op.memory->line_count) {
                throw std::invalid_argument("DSTORE length differs from resident object");
            }
            op.uses.push_back(id);
            const auto match = pairs.find(*lookup[index]);
            if (match != pairs.end()
                && instructions[dma[match->second].instruction_index].instruction.type
                    == result.objects[id].type
                && instructions[dma[match->second].instruction_index].instruction.dma_flag
                    == result.objects[id].dma_flag) {
                op.required_store = false;
                pending_reload.emplace(match->second, id);
            }
            if (instruction.type == 1) live[instruction.obj_id].reset();
            break;
        }
        case hpu::Mnemonic::kPfree:
            op.uses.push_back(object(instruction.idx0));
            live[instruction.idx0].reset();
            break;
        case hpu::Mnemonic::kPntt:
        case hpu::Mnemonic::kPintt:
            op.uses.push_back(object(instruction.pdst));
            op.uses.push_back(object(instruction.psrc1));
            op.definitions.push_back(object(instruction.pdst));
            break;
        case hpu::Mnemonic::kPadd:
        case hpu::Mnemonic::kPsub:
        case hpu::Mnemonic::kPmul:
        case hpu::Mnemonic::kPmac: {
            op.uses.push_back(object(instruction.psrc1));
            if (instruction.imm8 < 0) op.uses.push_back(object(instruction.psrc2));
            if (instruction.mnemonic == hpu::Mnemonic::kPmac) {
                unique_push(op.uses, object(instruction.pdst));
            }
            if (!live[instruction.pdst]
                || result.objects[*live[instruction.pdst]].line_count
                    != result.objects[op.uses[0]].line_count) {
                if (instruction.mnemonic == hpu::Mnemonic::kPmac) {
                    throw std::invalid_argument("PMAC accumulator shape differs from source");
                }
                const ObjectId id = result.objects.size();
                const auto& source = result.objects[op.uses[0]];
                result.objects.push_back({source.line_count, source.type, 0});
                live[instruction.pdst] = id;
            }
            op.definitions.push_back(object(instruction.pdst));
            break;
        }
        default: break;
        }
        result.instructions.push_back(std::move(op));
    }
    analyze_buffers(result, dma, instructions, image);
    return result;
}

VirtualProgram import_operator_program(
    const hpu::resource::OperatorProgram& source,
    const hpu::runtime::HpuMemImage& image)
{
    if (source.operations.empty()) throw std::invalid_argument("operator program is empty");
    VirtualProgram result;
    result.origin = ResourceIrOrigin::operator_emission;
    std::map<std::string, BufferId> buffer_ids;
    for (const auto& allocation : image.allocations()) {
        VirtualBuffer b;
        b.id = allocation.id; b.original_span = allocation.span; b.word_count = allocation.word_count;
        b.kind = allocation.kind; b.read_only = allocation.read_only;
        buffer_ids.emplace(b.id, result.buffers.size());
        result.buffers.push_back(std::move(b));
    }
    std::vector<bool> defined(source.values.size());
    std::vector<std::size_t> last_use(source.values.size(), 0);
    std::vector<hpu::EncodedInstruction> semantic;
    std::vector<ResolvedDma> dma;
    std::vector<std::optional<std::size_t>> lookup(source.operations.size());
    std::vector<bool> ports_seen(source.ports.size());
    for (std::size_t i = 0; i < source.operations.size(); ++i) {
        const auto& node = source.operations[i];
        const auto mnemonic = node.instruction.mnemonic;
        std::size_t input_count = 0, output_count = 0;
        std::optional<std::size_t> tied;
        switch (mnemonic) {
        case hpu::Mnemonic::kDload: output_count = 1; break;
        case hpu::Mnemonic::kDstore: case hpu::Mnemonic::kPfree: input_count = 1; break;
        case hpu::Mnemonic::kPmodld: case hpu::Mnemonic::kPsync: break;
        case hpu::Mnemonic::kPntt: case hpu::Mnemonic::kPintt:
            input_count = 2; output_count = 1; tied = 0; break;
        case hpu::Mnemonic::kPadd: case hpu::Mnemonic::kPsub:
            input_count = 2; output_count = 1; break;
        case hpu::Mnemonic::kPmul: case hpu::Mnemonic::kPmac:
            input_count = node.instruction.imm8 < 0 ? 2 : 1;
            output_count = 1;
            if (mnemonic == hpu::Mnemonic::kPmac) tied = input_count++;
            break;
        default: throw std::invalid_argument("unsupported operator instruction");
        }
        if (node.inputs.size() != input_count || node.outputs.size() != output_count || node.tied_input != tied)
            throw std::invalid_argument("operator has invalid SSA operands or tied input");
        if (node.reuse && !defined.at(*node.reuse))
            throw std::invalid_argument("operator reuses an undefined SSA value");
        for (const auto value : node.inputs) {
            if (!defined.at(value)) throw std::invalid_argument("operator SSA uses an undefined value");
            if (mnemonic != hpu::Mnemonic::kPfree) last_use[value] = i;
        }
        for (const auto value : node.outputs) {
            if (defined.at(value) || source.values.at(value).parameter)
                throw std::invalid_argument("operator SSA value has multiple definitions");
            defined[value] = true;
        }
        semantic.push_back({node.instruction, 0, 0, {}});
        const bool memory = mnemonic == hpu::Mnemonic::kDload || mnemonic == hpu::Mnemonic::kDstore;
        if (memory != node.port.has_value()) throw std::invalid_argument("operator has a missing or unexpected data port");
        if (node.port) {
            const auto& port = source.ports.at(*node.port);
            if (ports_seen.at(*node.port) || port.operation_index != i ||
                port.load != (mnemonic == hpu::Mnemonic::kDload) || !port.binding)
                throw std::invalid_argument("operator data port is unbound or inconsistent");
            ports_seen[*node.port] = true;
            auto binding = *port.binding;
            binding.instruction_index = i;
            const auto& allocation = image.allocation(binding.allocation_id);
            if (!contains(allocation.span, binding.span)) throw std::invalid_argument("operator port exceeds allocation");
            if (!port.load && allocation.read_only) throw std::invalid_argument("operator writes a read-only allocation");
            binding.allocation_id = allocation.id;
            lookup[i] = dma.size();
            dma.push_back(std::move(binding));
        }
    }
    if (std::find(ports_seen.begin(), ports_seen.end(), false) != ports_seen.end())
        throw std::invalid_argument("operator contains an unused data port");
    analyze_buffers(result, dma, semantic, image);
    const auto pairs = deferred_store_pairs(semantic, dma, image);
    std::map<std::size_t, ObjectId> pending_reload;
    std::vector<std::optional<ObjectId>> objects(source.values.size());
    std::vector<std::size_t> object_last_use;
    std::vector<std::optional<BufferRange>> initial_homes;
    const auto assign = [&](hpu::resource::ValueId value, ObjectId object) {
        objects.at(value) = object;
        object_last_use.at(object) = std::max(object_last_use.at(object), last_use.at(value));
    };
    const auto new_object = [&](VirtualObject shape) {
        const auto id = result.objects.size();
        result.objects.push_back(shape); object_last_use.push_back(0); initial_homes.push_back({});
        return id;
    };
    const auto get = [&](hpu::resource::ValueId value) {
        if (!objects.at(value)) throw std::invalid_argument("SSA input has no storage definition");
        return *objects.at(value);
    };
    std::optional<ResolvedDma> origin;
    for (std::size_t i = 0; i < source.operations.size(); ++i) {
        const auto& node = source.operations[i];
        VirtualInstruction op;
        op.instruction = node.instruction;
        if (lookup[i]) {
            origin = dma.at(*lookup[i]);
            const auto& allocation = image.allocation(origin->allocation_id);
            op.memory = BufferRange{buffer_ids.at(allocation.id),
                origin->span.line_offset - allocation.span.line_offset, origin->span.line_count};
        }
        op.origin = origin;
        if (!node.outputs.empty() || !node.inputs.empty()) {
            const auto value = !node.outputs.empty() ? node.outputs.front() : node.inputs.front();
            op.logical_value = source.values.at(value).variable.label + "/v" + std::to_string(value);
        }
        for (const auto value : node.inputs) op.uses.push_back(get(value));
        switch (node.instruction.mnemonic) {
        case hpu::Mnemonic::kDload: {
            const auto found = pending_reload.find(*lookup[i]);
            ObjectId id;
            if (found != pending_reload.end()) { id = found->second; op.reload_retained_object = true; }
            else id = new_object({op.memory->line_count, node.instruction.type, node.instruction.dma_flag});
            assign(node.outputs.at(0), id); op.definitions = {id};
            initial_homes[id] = op.memory;
            break;
        }
        case hpu::Mnemonic::kDstore: {
            const auto id = op.uses.at(0);
            if (result.objects[id].line_count != op.memory->line_count)
                throw std::invalid_argument("operator output has an incompatible length");
            const auto pair = pairs.find(*lookup[i]);
            if (pair != pairs.end() && semantic[dma[pair->second].instruction_index].instruction.type == result.objects[id].type &&
                semantic[dma[pair->second].instruction_index].instruction.dma_flag == result.objects[id].dma_flag) {
                op.required_store = false; pending_reload.emplace(pair->second, id);
                // A deferred reload is an implicit SSA consumer. Keep the
                // producer's storage intact across the gap, even though the
                // load defines a different SSA value at the source level.
                object_last_use[id] = std::max(object_last_use[id], dma[pair->second].instruction_index);
            }
            break;
        }
        case hpu::Mnemonic::kPntt: case hpu::Mnemonic::kPintt:
        case hpu::Mnemonic::kPadd: case hpu::Mnemonic::kPsub:
        case hpu::Mnemonic::kPmul: case hpu::Mnemonic::kPmac: {
            const auto shape = result.objects.at(op.uses.at(0));
            std::optional<ObjectId> reuse;
            if (node.reuse && *node.reuse < objects.size() && objects[*node.reuse]) {
                const auto id = *objects[*node.reuse];
                if (result.objects[id].line_count == shape.line_count && object_last_use[id] <= i) reuse = id;
            }
            if (node.tied_input) {
                const auto id = op.uses.at(*node.tied_input);
                if (result.objects[id].line_count != shape.line_count)
                    throw std::invalid_argument("tied SSA input has incompatible shape");
                if (object_last_use[id] <= i) reuse = id;
                else {
                    // Preserve exact words through DMA. Arithmetic copies would
                    // change noncanonical/lazy residues or table payloads.
                    const bool reload_source = initial_homes[id]
                        && result.buffers[initial_homes[id]->buffer].read_only;
                    const auto buffer = result.buffers.size();
                    VirtualBuffer snapshot;
                    snapshot.id = "$compiler/ssa_copy/" + std::to_string(node.outputs.at(0));
                    snapshot.original_span = {0, shape.line_count};
                    snapshot.word_count = shape.line_count * hpu::runtime::kHpuMemLineWords;
                    snapshot.kind = hpu::runtime::AllocationKind::workspace;
                    snapshot.retained = false; snapshot.fully_defined_before_read = true;
                    snapshot.first_use = snapshot.last_use = i;
                    if (!reload_source) result.buffers.push_back(std::move(snapshot));
                    const BufferRange range = reload_source ? *initial_homes[id]
                        : BufferRange{buffer, 0, shape.line_count};
                    VirtualInstruction save;
                    save.instruction.mnemonic = hpu::Mnemonic::kDstore;
                    save.instruction.rs1 = 10; save.instruction.rs2 = 11;
                    save.uses = {id}; save.memory = range; save.origin = origin;
                    save.exact_copy = true;
                    save.logical_value = source.values.at(node.inputs.at(*node.tied_input)).variable.label
                        + "/v" + std::to_string(node.inputs.at(*node.tied_input));
                    if (!reload_source) result.instructions.push_back(save);
                    const auto copy = new_object(shape);
                    VirtualInstruction load;
                    load.instruction.mnemonic = hpu::Mnemonic::kDload;
                    load.instruction.rs1 = 10; load.instruction.rs2 = 11;
                    load.instruction.type = shape.type; load.instruction.dma_flag = shape.dma_flag;
                    load.definitions = {copy}; load.memory = range; load.origin = origin;
                    load.exact_copy = true;
                    load.logical_value = save.logical_value;
                    result.instructions.push_back(load);
                    op.uses[*node.tied_input] = copy; reuse = copy;
                }
            }
            const auto id = reuse ? *reuse : new_object({shape.line_count, shape.type, 0});
            assign(node.outputs.at(0), id); op.definitions = {id};
            initial_homes[id].reset();
            break;
        }
        case hpu::Mnemonic::kPfree: case hpu::Mnemonic::kPmodld: case hpu::Mnemonic::kPsync: break;
        }
        result.instructions.push_back(std::move(op));
    }
    return result;
}

CompiledResources optimize_resources(
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image,
    const CompileOptions& options)
{
    return compile_resources(import_resolved_program(instructions, dma, image),
                             instructions, dma, image, options);
}

CompiledResources compile_resources(
    VirtualProgram program,
    const std::vector<hpu::EncodedInstruction>& instructions,
    const std::vector<ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image,
    const CompileOptions& options)
{
    if (options.regular_bank_count == 0 || options.regular_bank_count > 5
        || options.regular_bank_lines == 0 || options.regular_bank_lines > 1024
        || options.mod_table_lines == 0 || options.mod_table_lines > 16) {
        throw std::invalid_argument("invalid resource limits for HPU ISA");
    }
    for (const auto& annotation : options.buffer_layouts) {
        const auto found = std::find_if(program.buffers.begin(), program.buffers.end(),
            [&](const auto& buffer) { return buffer.id == annotation.first; });
        if (found == program.buffers.end())
            throw std::invalid_argument("layout annotation names an absent buffer: " + annotation.first);
        switch (annotation.second) {
        case MemoryLayout::unspecified:
        case MemoryLayout::coefficient_natural:
        case MemoryLayout::coefficient_bit_reversed:
        case MemoryLayout::canonical_ntt_physical: break;
        default: throw std::invalid_argument("unknown buffer layout annotation");
        }
        found->layout = annotation.second;
    }
    const bool ssa_copies = std::any_of(program.buffers.begin(), program.buffers.end(),
        [](const auto& buffer) { return buffer.id.rfind("$compiler/ssa_copy/", 0) == 0; });
    for (auto& op : program.instructions)
        if (op.memory && op.instruction.mnemonic == hpu::Mnemonic::kDstore
            && options.required_outputs.count(program.buffers[op.memory->buffer].id))
            op.required_store = true;
    for (auto& buffer : program.buffers)
        if (options.required_outputs.count(buffer.id)) buffer.retained = true;
    if (options.optimization == OptimizationMode::no_opt && !instructions.empty() && !ssa_copies
        && !options.automatic_lifetimes && !options.preload_readonly_inputs) {
        CompiledResources result(image.capacity_lines());
        result.image = image;
        result.instructions = instructions;
        result.dma = dma;
        result.report = inspect_original(instructions, dma, image, options);
        result.report.ir_origin = program.origin;
        for (const auto& buffer : program.buffers) {
            result.buffers.push_back({buffer.id, buffer.id, buffer.original_span,
                buffer.original_span, true, buffer.first_use, buffer.last_use, buffer.layout});
        }
        apply_dma_cache_policy(result, options.dma_cache_policy);
        record_io(result, dma);
        return result;
    }
    if (options.optimization == OptimizationMode::no_opt) {
        for (auto& op : program.instructions) {
            op.required_store = true;
            op.reload_retained_object = false;
        }
    }
    // Preloading is a preparation candidate, not a different execution
    // allocator. Keep the unmodified normal schedule unless entry residency
    // can be gained without extra transfers, reloads, or dirty spills.
    ScheduledProgram scheduled;
    if (options.preload_readonly_inputs) {
        auto normal_program = program;
        scheduled = Scheduler(normal_program, options).run();
        const auto dma_cost = [](const ScheduledProgram& candidate) {
            std::uint64_t lines = 0;
            for (const auto& dma : candidate.dma) lines += dma.range.line_count;
            return std::make_pair(lines, candidate.dma.size());
        };
        const auto baseline_cost = dma_cost(scheduled);
        for (const auto limit : {24U, 12U, 6U, 3U}) {
            auto candidate_program = program;
            try {
                auto candidate = Scheduler(candidate_program, options, limit).run();
                const auto cost = dma_cost(candidate);
                if (candidate.report.preloaded_dma_count == 0
                    || cost.first > baseline_cost.first || cost.second > baseline_cost.second
                    || candidate.report.spills > scheduled.report.spills
                    || candidate.report.reloads > scheduled.report.reloads) continue;
                scheduled = std::move(candidate);
                normal_program = std::move(candidate_program);
                break;
            } catch (const ResourceCapacityError&) {
                // Speculative early residency can block an otherwise valid
                // aligned transient placement. The original schedule remains
                // valid and the next smaller admission limit may still fit.
            }
        }
        program = std::move(normal_program);
    } else {
        scheduled = Scheduler(program, options).run();
    }
    if (options.prune_unused_buffers) {
        for (auto& buffer : program.buffers) buffer.materialized = false;
        for (const auto& entry : scheduled.dma) program.buffers[entry.range.buffer].materialized = true;
        for (auto& buffer : program.buffers) {
            if (buffer.kind == hpu::runtime::AllocationKind::output
                && !options.required_outputs.count(buffer.id)) {
                buffer.kind = hpu::runtime::AllocationKind::workspace;
                buffer.retained = !buffer.fully_defined_before_read;
            }
        }
    }
    std::uint64_t capacity = image.used_lines();
    for (const auto& buffer : program.buffers) {
        if (buffer.id.rfind("$compiler/spill/", 0) == 0 ||
            buffer.id.rfind("$compiler/ssa_copy/", 0) == 0) {
            capacity += buffer.original_span.line_count;
        }
    }
    CompiledResources result(std::max<std::uint64_t>(1, capacity));
    result.instructions = std::move(scheduled.instructions);
    result.report = scheduled.report;
    result.report.ir_origin = program.origin;
    result.report.original_dma_count = dma.empty()
        ? std::count_if(program.instructions.begin(), program.instructions.end(),
              [](const auto& op) { return op.memory.has_value(); })
        : dma.size();
    result.report.original_ddr_lines = image.used_lines();
    result.buffers = place_buffers(program, image, result.image,
        result.report.scratch_arena_lines, options.optimization == OptimizationMode::optimized);
    result.report.allocated_ddr_lines = result.image.used_lines();
    result.dma.reserve(scheduled.dma.size());
    for (auto& entry : scheduled.dma) {
        const auto& placement = result.buffers[entry.range.buffer];
        entry.origin.instruction_index = entry.instruction_index;
        entry.origin.allocation_id = placement.physical_allocation_id;
        entry.origin.span = {placement.span.line_offset + entry.range.line_offset,
                            entry.range.line_count};
        result.dma.push_back(std::move(entry.origin));
    }
    apply_dma_cache_policy(result, options.dma_cache_policy);
    record_io(result, dma);
    return result;
}

hpu::runtime::HpuMemSpan relocate_span(
    const CompiledResources& resources,
    const std::string& logical_allocation_id,
    hpu::runtime::HpuMemSpan original_span)
{
    const auto found = std::find_if(resources.buffers.begin(), resources.buffers.end(),
        [&](const auto& buffer) { return buffer.logical_id == logical_allocation_id; });
    if (found == resources.buffers.end() || found->physical_allocation_id.empty()
        || !contains(found->original_span, original_span)) {
        throw std::invalid_argument("cannot relocate logical range: " + logical_allocation_id);
    }
    return {found->span.line_offset + original_span.line_offset - found->original_span.line_offset,
            original_span.line_count};
}

std::string render_resource_report(const CompiledResources& resources)
{
    const auto& report = resources.report;
    std::ostringstream output;
    output << "{\n  \"original_ddr_lines\": " << report.original_ddr_lines
           << ",\n  \"ir_source\": " << json_string(
               report.ir_origin == ResourceIrOrigin::operator_emission ? "operator" : "encoded_import")
           << ",\n  \"allocated_ddr_lines\": " << report.allocated_ddr_lines
           << ",\n  \"scratch_arena_lines\": " << report.scratch_arena_lines
           << ",\n  \"original_dma_count\": " << report.original_dma_count
           << ",\n  \"dma_count\": " << report.dma_count
           << ",\n  \"peak_regular_banks\": " << report.peak_regular_banks
           << ",\n  \"peak_object_slots\": " << report.peak_object_slots
           << ",\n  \"peak_regular_lines\": " << report.peak_regular_lines
           << ",\n  \"peak_small_lines\": " << report.peak_small_lines
           << ",\n  \"deferred_scratch_stores\": " << report.deferred_scratch_stores
           << ",\n  \"spills\": " << report.spills
           << ",\n  \"reloads\": " << report.reloads
           << ",\n  \"dload_bytes\": " << report.dload_bytes
           << ",\n  \"dstore_bytes\": " << report.dstore_bytes
           << ",\n  \"dma_bytes\": " << report.dload_bytes + report.dstore_bytes
           << ",\n  \"original_dma_bytes\": " << report.original_dma_bytes
           << ",\n  \"spill_write_bytes\": " << report.spill_write_bytes
           << ",\n  \"reload_read_bytes\": " << report.reload_read_bytes
           << ",\n  \"exact_copy_bytes\": " << report.exact_copy_bytes
           << ",\n  \"preloaded_dma_count\": " << report.preloaded_dma_count
           << ",\n  \"preloaded_dma_bytes\": " << report.preloaded_dma_bytes
           << ",\n  \"repeated_range_read_bytes\": " << report.repeated_range_read_bytes
           << ",\n  \"required_output_write_bytes\": " << report.required_output_write_bytes
           << ",\n  \"initial_image_bytes\": " << report.initial_image_bytes
           << ",\n  \"selected_schedule\": " << json_string(report.selected_schedule)
           << ",\n  \"logical_buffers\": [";
    for (std::size_t index = 0; index < resources.buffers.size(); ++index) {
        const auto& buffer = resources.buffers[index];
        output << (index ? ",\n" : "\n")
               << "    {\"logical_id\": " << json_string(buffer.logical_id)
               << ", \"allocation_id\": " << json_string(buffer.physical_allocation_id)
               << ", \"materialized\": " << (buffer.physical_allocation_id.empty() ? "false" : "true")
               << ", \"original_line_offset\": " << buffer.original_span.line_offset
               << ", \"original_line_count\": " << buffer.original_span.line_count
               << ", \"line_offset\": " << buffer.span.line_offset
               << ", \"line_count\": " << buffer.span.line_count
               << ", \"retained\": " << (buffer.retained ? "true" : "false")
               << ", \"first_use\": " << buffer.first_use
               << ", \"last_use\": " << buffer.last_use
               << ", \"layout\": " << json_string(layout_name(buffer.layout)) << '}';
    }
    output << "\n  ],\n  \"io_by_allocation\": [";
    struct Io { std::size_t reads = 0, writes = 0; std::uint64_t read_bytes = 0, write_bytes = 0; };
    std::map<std::string, Io> by_allocation, by_value;
    for (const auto& dma : resources.dma) {
        auto& io = by_allocation[dma.allocation_id];
        auto& value_io = by_value[dma.logical_value.empty() ? "$encoded_import" : dma.logical_value];
        if (resources.instructions[dma.instruction_index].instruction.mnemonic == hpu::Mnemonic::kDload) {
            ++io.reads; io.read_bytes += dma.span.line_count * 256;
            ++value_io.reads; value_io.read_bytes += dma.span.line_count * 256;
        } else {
            ++io.writes; io.write_bytes += dma.span.line_count * 256;
            ++value_io.writes; value_io.write_bytes += dma.span.line_count * 256;
        }
    }
    bool first = true;
    for (const auto& entry : by_allocation) {
        if (!first) output << ',';
        first = false;
        output << "\n    {\"allocation_id\":" << json_string(entry.first)
            << ",\"reads\":" << entry.second.reads << ",\"writes\":" << entry.second.writes
            << ",\"read_bytes\":" << entry.second.read_bytes
            << ",\"write_bytes\":" << entry.second.write_bytes << '}';
    }
    output << "\n  ],\n  \"io_by_value\": [";
    first = true;
    for (const auto& entry : by_value) {
        if (!first) output << ',';
        first = false;
        output << "\n    {\"value\":" << json_string(entry.first)
            << ",\"reads\":" << entry.second.reads << ",\"writes\":" << entry.second.writes
            << ",\"read_bytes\":" << entry.second.read_bytes
            << ",\"write_bytes\":" << entry.second.write_bytes << '}';
    }
    output << "\n  ],\n  \"io_by_kind\": [";
    std::map<unsigned, Io> by_kind;
    for (const auto& entry : by_allocation) {
        auto& io = by_kind[static_cast<unsigned>(resources.image.allocation(entry.first).kind)];
        io.reads += entry.second.reads; io.writes += entry.second.writes;
        io.read_bytes += entry.second.read_bytes; io.write_bytes += entry.second.write_bytes;
    }
    constexpr const char* kinds[] = {"modulus_table", "constant", "ciphertext", "plaintext",
        "evaluation_key", "twiddle", "workspace", "output"};
    first = true;
    for (const auto& entry : by_kind) {
        if (!first) output << ',';
        first = false;
        output << "\n    {\"kind\":" << json_string(kinds[entry.first])
            << ",\"read_bytes\":" << entry.second.read_bytes
            << ",\"write_bytes\":" << entry.second.write_bytes << '}';
    }
    output << "\n  ]\n}\n";
    return output.str();
}

} // namespace hpu::compiler

namespace hpu::resource {
hpu::compiler::VirtualProgram bind_program(const OperatorProgram& program,
    const hpu::runtime::HpuMemImage& image)
{
    return hpu::compiler::import_operator_program(program, image);
}
hpu::compiler::VirtualProgram bind_program(const OperatorProgram& program,
    const std::vector<hpu::EncodedInstruction>& baseline,
    const std::vector<hpu::compiler::ResolvedDma>& dma,
    const hpu::runtime::HpuMemImage& image)
{
    if (program.operations.size() != baseline.size())
        throw std::invalid_argument("operator IR does not cover the complete baseline program");
    for (std::size_t i = 0; i < baseline.size(); ++i) {
        const auto& a = program.operations[i].instruction;
        const auto& b = baseline[i].instruction;
        if (a.mnemonic != b.mnemonic || a.imm8 != b.imm8 || a.mod_id != b.mod_id ||
            a.mode != b.mode || a.flag != b.flag || a.type != b.type || a.dma_flag != b.dma_flag || a.cp != b.cp ||
            ((a.mnemonic == hpu::Mnemonic::kPntt || a.mnemonic == hpu::Mnemonic::kPintt) && a.idx0 != b.idx0))
            throw std::invalid_argument("operator IR disagrees with its compatibility baseline");
    }
    auto bound = program;
    bound.bind_ports(dma);
    return bind_program(bound, image);
}
} // namespace hpu::resource
