#include "hpu/seal/bfv_operation_relocation.hpp"

#include "hpu/seal/bfv_level.hpp"

#include <regex>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

constexpr const char* kModulusTableId = "constants/modulus_table";
constexpr const char* kApplicationOperationId = "$application";
constexpr int kModulusTableObject = 4;

struct DmaInstruction {
    BfvDmaDirection direction = BfvDmaDirection::load;
    int object_slot = 0;
    hpu::DataType load_type = hpu::DataType::poly;
    hpu::DloadFlag load_flag = hpu::DloadFlag::regular_bank;
    int store_release = 0;
};

std::vector<DmaInstruction> parse_dma_instructions(const std::string& body)
{
    static const std::regex pattern(
        "\\\"d(load|store) x10, x11, p([0-9]+), ([0-9]+)(?:, ([0-9]+))?");
    std::vector<DmaInstruction> result;
    for (std::sregex_iterator it(body.begin(), body.end(), pattern), end; it != end; ++it) {
        DmaInstruction instruction;
        instruction.direction =
            (*it)[1].str() == "load" ? BfvDmaDirection::load : BfvDmaDirection::store;
        instruction.object_slot = std::stoi((*it)[2].str());
        const int operand = std::stoi((*it)[3].str());
        if (instruction.direction == BfvDmaDirection::load) {
            if (!(*it)[4].matched || operand < static_cast<int>(hpu::DataType::seg) ||
                operand > static_cast<int>(hpu::DataType::mod_ctx)) {
                throw std::logic_error("generated BFV dload has an invalid operand");
            }
            instruction.load_type = static_cast<hpu::DataType>(operand);
            const int flag = std::stoi((*it)[4].str());
            if (flag < static_cast<int>(hpu::DloadFlag::regular_bank) ||
                flag > static_cast<int>(hpu::DloadFlag::small_bank)) {
                throw std::logic_error("generated BFV dload has an invalid bank flag");
            }
            instruction.load_flag = static_cast<hpu::DloadFlag>(flag);
        } else {
            if ((*it)[4].matched) {
                throw std::logic_error("generated BFV dstore has too many operands");
            }
            instruction.store_release = operand;
        }
        result.push_back(instruction);
    }
    std::size_t dma_token_count = 0;
    for (const char* token : {"\"dload ", "\"dstore "}) {
        std::size_t position = 0;
        while ((position = body.find(token, position)) != std::string::npos) {
            ++dma_token_count;
            position += std::char_traits<char>::length(token);
        }
    }
    if (dma_token_count != result.size()) {
        throw std::logic_error("generated BFV DMA instruction does not use the frozen x10/x11 ABI");
    }
    return result;
}

bool same_instruction(const DmaInstruction& left, const DmaInstruction& right)
{
    return left.direction == right.direction && left.object_slot == right.object_slot &&
           (left.direction == BfvDmaDirection::load
                ? left.load_type == right.load_type && left.load_flag == right.load_flag
                : left.store_release == right.store_release);
}

std::string limb_id(const BfvPlannedValue& value, std::size_t component, int modulus_id)
{
    return value.id + "/c" + std::to_string(component) + "/mod" + std::to_string(modulus_id);
}

class OperationBindingBuilder {
public:
    OperationBindingBuilder(BfvRelocationSchedule& schedule, const hpu::runtime::HpuMemImage& image,
                            const BfvLoweredOperation& operation, std::size_t operation_index,
                            std::size_t first_program_dma_index, std::size_t polynomial_words,
                            std::vector<DmaInstruction> instructions)
        : schedule_(schedule), image_(image), operation_(operation),
          operation_index_(operation_index), first_program_dma_index_(first_program_dma_index),
          polynomial_words_(polynomial_words), instructions_(std::move(instructions))
    {
    }

    void load(int slot, const std::string& allocation_id)
    {
        append(BfvDmaDirection::load, slot, allocation_id, hpu::DataType::poly,
               hpu::DloadFlag::regular_bank, 0);
    }

    void store(int slot, const std::string& allocation_id)
    {
        append(BfvDmaDirection::store, slot, allocation_id, hpu::DataType::poly,
               hpu::DloadFlag::regular_bank, 1);
    }

    void finish() const
    {
        if (cursor_ != instructions_.size()) {
            throw std::logic_error(
                "BFV relocation recipe did not consume every DMA instruction for " +
                operation_.operation.id);
        }
    }

private:
    void append(BfvDmaDirection direction, int slot, const std::string& allocation_id,
                hpu::DataType load_type, hpu::DloadFlag load_flag, int store_release)
    {
        if (cursor_ >= instructions_.size()) {
            throw std::logic_error("BFV relocation recipe exceeds generated DMA instructions for " +
                                   operation_.operation.id);
        }
        const auto& instruction = instructions_[cursor_];
        if (instruction.direction != direction || instruction.object_slot != slot ||
            (direction == BfvDmaDirection::load &&
             (instruction.load_type != load_type || instruction.load_flag != load_flag)) ||
            (direction == BfvDmaDirection::store && instruction.store_release != store_release)) {
            throw std::logic_error("BFV relocation recipe disagrees with generated DMA ABI for " +
                                   operation_.operation.id);
        }

        const auto& allocation = image_.allocation(allocation_id);
        if (allocation.word_count != polynomial_words_ || allocation.span.line_count == 0) {
            throw std::invalid_argument(
                "BFV polynomial relocation has an incompatible allocation: " + allocation_id);
        }
        if (direction == BfvDmaDirection::store && allocation.read_only) {
            throw std::invalid_argument("BFV dstore relocation targets a read-only allocation: " +
                                        allocation_id);
        }

        BfvDmaBinding binding;
        binding.program_dma_index = first_program_dma_index_ + cursor_;
        binding.operation_index = operation_index_;
        binding.operation_dma_index = cursor_;
        binding.operation_id = operation_.operation.id;
        binding.direction = direction;
        binding.object_slot = slot;
        binding.load_type = instruction.load_type;
        binding.load_flag = instruction.load_flag;
        binding.store_release = instruction.store_release;
        binding.allocation_id = allocation.id;
        binding.span = allocation.span;
        schedule_.bindings.push_back(std::move(binding));
        ++cursor_;
    }

    BfvRelocationSchedule& schedule_;
    const hpu::runtime::HpuMemImage& image_;
    const BfvLoweredOperation& operation_;
    std::size_t operation_index_;
    std::size_t first_program_dma_index_;
    std::size_t polynomial_words_;
    std::vector<DmaInstruction> instructions_;
    std::size_t cursor_ = 0;
};

void bind_ciphertext_binary(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                            const BfvLevelDescriptor& level)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2 ||
        step.inputs[1].component_count != 2 || step.output.component_count != 2) {
        throw std::invalid_argument("invalid BFV Add/Subtract relocation manifest");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        for (int modulus_id : level.keyswitch_layout.q_mod_ids) {
            bindings.load(0, limb_id(step.inputs[0], component, modulus_id));
            bindings.load(1, limb_id(step.inputs[1], component, modulus_id));
            bindings.store(2, limb_id(step.output, component, modulus_id));
        }
    }
    bindings.finish();
}

void bind_plain_binary(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                       const BfvLevelDescriptor& level)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2 ||
        step.inputs[1].component_count != 1 || step.output.component_count != 2) {
        throw std::invalid_argument("invalid BFV AddPlain/SubtractPlain relocation manifest");
    }
    for (int modulus_id : level.keyswitch_layout.q_mod_ids) {
        bindings.load(0, limb_id(step.inputs[0], 0, modulus_id));
        bindings.load(1, limb_id(step.inputs[1], 0, modulus_id));
        bindings.store(2, limb_id(step.output, 0, modulus_id));
        bindings.load(0, limb_id(step.inputs[0], 1, modulus_id));
        bindings.store(0, limb_id(step.output, 1, modulus_id));
    }
    bindings.finish();
}

void bind_negate(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                 const BfvLevelDescriptor& level)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 2 ||
        step.output.component_count != 2) {
        throw std::invalid_argument("invalid BFV Negate relocation manifest");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        for (int modulus_id : level.keyswitch_layout.q_mod_ids) {
            bindings.load(0, limb_id(step.inputs[0], component, modulus_id));
            bindings.store(2, limb_id(step.output, component, modulus_id));
        }
    }
    bindings.finish();
}

} // namespace

BfvRelocationSchedule build_bfv_relocation_schedule(const BfvLoweredProgram& program,
                                                    const hpu::runtime::HpuMemImage& image,
                                                    const ::seal::SEALContext& context)
{
    if (program.operations.empty()) {
        throw std::invalid_argument("cannot relocate an empty BFV lowered program");
    }
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::bfv ||
        key_data->parms().poly_modulus_degree() == 0) {
        throw std::invalid_argument("BFV relocation requires a valid BFV context");
    }
    const std::size_t degree = key_data->parms().poly_modulus_degree();
    const BfvLevelChain level_chain(context);

    const auto program_instructions = parse_dma_instructions(program.body_asm);
    std::vector<std::vector<DmaInstruction>> operation_instructions;
    operation_instructions.reserve(program.operations.size());
    std::size_t operation_dma_count = 0;
    for (const auto& operation : program.operations) {
        operation_instructions.push_back(parse_dma_instructions(operation.body_asm));
        operation_dma_count += operation_instructions.back().size();
    }
    if (program_instructions.size() < operation_dma_count ||
        program_instructions.size() - operation_dma_count > 1) {
        throw std::invalid_argument("lowered BFV program has an unsupported global DMA layout");
    }

    const std::size_t global_dma_count = program_instructions.size() - operation_dma_count;
    BfvRelocationSchedule result;
    result.expected_dma_count = program_instructions.size();
    if (global_dma_count == 1) {
        const DmaInstruction expected{BfvDmaDirection::load, kModulusTableObject,
                                      hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank, 0};
        if (!same_instruction(program_instructions.front(), expected)) {
            throw std::invalid_argument("lowered BFV global DMA is not the modulus-table load");
        }
        const auto& allocation = image.allocation(kModulusTableId);
        if (allocation.kind != hpu::runtime::AllocationKind::modulus_table ||
            !allocation.read_only || allocation.span.line_count == 0) {
            throw std::invalid_argument(
                "BFV modulus-table relocation has an incompatible allocation");
        }
        BfvDmaBinding binding;
        binding.program_dma_index = 0;
        binding.operation_dma_index = 0;
        binding.operation_id = kApplicationOperationId;
        binding.direction = BfvDmaDirection::load;
        binding.object_slot = kModulusTableObject;
        binding.load_type = hpu::DataType::mod_ctx;
        binding.load_flag = hpu::DloadFlag::small_bank;
        binding.allocation_id = allocation.id;
        binding.span = allocation.span;
        result.bindings.push_back(std::move(binding));
    }

    std::size_t first_program_dma_index = global_dma_count;
    for (std::size_t operation_index = 0; operation_index < program.operations.size();
         ++operation_index) {
        const auto& operation = program.operations[operation_index];
        const auto& instructions = operation_instructions[operation_index];
        for (std::size_t local = 0; local < instructions.size(); ++local) {
            if (!same_instruction(instructions[local],
                                  program_instructions[first_program_dma_index + local])) {
                throw std::invalid_argument(
                    "lowered BFV operation DMA stream differs from program body");
            }
        }
        const auto& step = operation.operation;
        if (step.inputs.empty()) {
            throw std::invalid_argument("BFV relocation manifest has no input");
        }
        OperationBindingBuilder bindings(result, image, operation, operation_index,
                                         first_program_dma_index, degree, instructions);
        const auto& level = level_chain.require(step.inputs.front().metadata.parms_id);
        switch (step.kind) {
        case BfvOperationKind::add:
        case BfvOperationKind::subtract:
            bind_ciphertext_binary(bindings, step, level);
            break;
        case BfvOperationKind::add_plain:
        case BfvOperationKind::subtract_plain:
            bind_plain_binary(bindings, step, level);
            break;
        case BfvOperationKind::negate:
            bind_negate(bindings, step, level);
            break;
        }
        first_program_dma_index += instructions.size();
    }
    if (first_program_dma_index != program_instructions.size()) {
        throw std::logic_error("BFV relocation did not account for the complete DMA stream");
    }
    return result;
}

} // namespace hpu::seal_adapter
