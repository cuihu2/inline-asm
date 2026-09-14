#include "hpu/seal/operation_relocation.hpp"

#include "hpu/seal/ckks_level.hpp"

#include <algorithm>
#include <regex>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

constexpr const char* kModulusTableId = "constants/modulus_table";
constexpr const char* kApplicationOperationId = "$application";
constexpr int kModulusTableObject = 4;

struct DmaInstruction {
    CkksDmaDirection direction = CkksDmaDirection::load;
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
    for (std::sregex_iterator it(body.begin(), body.end(), pattern), end;
         it != end; ++it) {
        DmaInstruction instruction;
        instruction.direction = (*it)[1].str() == "load"
            ? CkksDmaDirection::load
            : CkksDmaDirection::store;
        instruction.object_slot = std::stoi((*it)[2].str());
        const int operand = std::stoi((*it)[3].str());
        if (instruction.direction == CkksDmaDirection::load) {
            if (!(*it)[4].matched
                || operand < static_cast<int>(hpu::DataType::seg)
                || operand > static_cast<int>(hpu::DataType::mod_ctx)) {
                throw std::logic_error("generated dload has an invalid operand");
            }
            instruction.load_type = static_cast<hpu::DataType>(operand);
            const int flag = std::stoi((*it)[4].str());
            if (flag < static_cast<int>(hpu::DloadFlag::regular_bank)
                || flag > static_cast<int>(hpu::DloadFlag::small_bank)) {
                throw std::logic_error("generated dload has an invalid bank flag");
            }
            instruction.load_flag = static_cast<hpu::DloadFlag>(flag);
        } else {
            if ((*it)[4].matched) {
                throw std::logic_error("generated dstore has too many operands");
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
        throw std::logic_error(
            "generated DMA instruction does not use the frozen x10/x11 ABI");
    }
    return result;
}

bool same_instruction(
    const DmaInstruction& left,
    const DmaInstruction& right)
{
    return left.direction == right.direction
        && left.object_slot == right.object_slot
        && (left.direction == CkksDmaDirection::load
            ? left.load_type == right.load_type
                && left.load_flag == right.load_flag
            : left.store_release == right.store_release);
}

std::string limb_id(
    const CkksPlannedValue& value,
    std::size_t component,
    int modulus_id)
{
    return value.id + "/c" + std::to_string(component)
        + "/mod" + std::to_string(modulus_id);
}

class OperationBindingBuilder {
public:
    OperationBindingBuilder(
        CkksRelocationSchedule& schedule,
        const hpu::runtime::HpuMemImage& image,
        const CkksLoweredOperation& operation,
        std::size_t operation_index,
        std::size_t first_program_dma_index,
        std::size_t polynomial_words,
        std::vector<DmaInstruction> instructions)
        : schedule_(schedule), image_(image), operation_(operation),
          operation_index_(operation_index),
          first_program_dma_index_(first_program_dma_index),
          polynomial_words_(polynomial_words),
          instructions_(std::move(instructions))
    {}

    void load(int slot, const std::string& allocation_id)
    {
        load_words(slot, allocation_id, polynomial_words_);
    }

    void load_words(
        int slot,
        const std::string& allocation_id,
        std::size_t expected_words)
    {
        append(
            CkksDmaDirection::load, slot, allocation_id,
            hpu::DataType::poly, hpu::DloadFlag::regular_bank, 0,
            expected_words);
    }

    void store(int slot, const std::string& allocation_id)
    {
        append(
            CkksDmaDirection::store, slot, allocation_id,
            hpu::DataType::poly, hpu::DloadFlag::regular_bank, 1,
            polynomial_words_);
    }

    void finish() const
    {
        if (cursor_ != instructions_.size()) {
            throw std::logic_error(
                "relocation recipe did not consume every generated DMA instruction for "
                + operation_.operation.id);
        }
    }

private:
    void append(
        CkksDmaDirection direction,
        int slot,
        const std::string& allocation_id,
        hpu::DataType load_type,
        hpu::DloadFlag load_flag,
        int store_release,
        std::size_t expected_words)
    {
        if (cursor_ >= instructions_.size()) {
            throw std::logic_error(
                "relocation recipe exceeds generated DMA instructions for "
                + operation_.operation.id);
        }
        const auto& instruction = instructions_[cursor_];
        if (instruction.direction != direction
            || instruction.object_slot != slot
            || (direction == CkksDmaDirection::load
                && (instruction.load_type != load_type
                    || instruction.load_flag != load_flag))
            || (direction == CkksDmaDirection::store
                && instruction.store_release != store_release)) {
            throw std::logic_error(
                "relocation recipe disagrees with generated DMA ABI for "
                + operation_.operation.id);
        }

        const auto& allocation = image_.allocation(allocation_id);
        if (allocation.word_count != expected_words
            || allocation.span.line_count == 0) {
            throw std::invalid_argument(
                "CKKS polynomial relocation has an incompatible allocation: "
                + allocation_id);
        }
        if (direction == CkksDmaDirection::store && allocation.read_only) {
            throw std::invalid_argument(
                "CKKS dstore relocation targets a read-only allocation: "
                + allocation_id);
        }

        CkksDmaBinding binding;
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

    CkksRelocationSchedule& schedule_;
    const hpu::runtime::HpuMemImage& image_;
    const CkksLoweredOperation& operation_;
    std::size_t operation_index_;
    std::size_t first_program_dma_index_;
    std::size_t polynomial_words_;
    std::vector<DmaInstruction> instructions_;
    std::size_t cursor_ = 0;
};

void bind_square(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 2
        || step.output.component_count != 3) {
        throw std::invalid_argument("invalid Square relocation manifest");
    }
    const auto& input = step.inputs[0];
    for (int modulus_id : level.rns_layout.q_mod_ids) {
        const auto in0 = limb_id(input, 0, modulus_id);
        const auto in1 = limb_id(input, 1, modulus_id);
        bindings.load(0, in0);
        bindings.load(1, in0);
        bindings.store(2, limb_id(step.output, 0, modulus_id));

        bindings.load(0, in0);
        bindings.load(1, in1);
        bindings.load(0, in1);
        bindings.load(1, in0);
        bindings.store(2, limb_id(step.output, 1, modulus_id));

        bindings.load(0, in1);
        bindings.load(1, in1);
        bindings.store(2, limb_id(step.output, 2, modulus_id));
    }
    bindings.finish();
}

void bind_ciphertext_binary(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2
        || step.inputs[1].component_count != 2
        || step.output.component_count != 2) {
        throw std::invalid_argument(
            "invalid Add/Subtract relocation manifest");
    }
    const auto& left = step.inputs[0];
    const auto& right = step.inputs[1];
    for (std::size_t component = 0; component < 2; ++component) {
        for (int modulus_id : level.rns_layout.q_mod_ids) {
            bindings.load(0, limb_id(left, component, modulus_id));
            bindings.load(1, limb_id(right, component, modulus_id));
            bindings.store(2, limb_id(step.output, component, modulus_id));
        }
    }
    bindings.finish();
}

void bind_plain_binary(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2
        || step.inputs[1].component_count != 1
        || step.output.component_count != 2) {
        throw std::invalid_argument("invalid AddPlain relocation manifest");
    }
    const auto& ciphertext = step.inputs[0];
    const auto& plaintext = step.inputs[1];
    for (int modulus_id : level.rns_layout.q_mod_ids) {
        bindings.load(0, limb_id(ciphertext, 0, modulus_id));
        bindings.load(1, limb_id(plaintext, 0, modulus_id));
        bindings.store(2, limb_id(step.output, 0, modulus_id));
        bindings.load(0, limb_id(ciphertext, 1, modulus_id));
        bindings.store(0, limb_id(step.output, 1, modulus_id));
    }
    bindings.finish();
}

void bind_multiply_plain(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2
        || step.inputs[1].component_count != 1
        || step.output.component_count != 2) {
        throw std::invalid_argument(
            "invalid MultiplyPlain relocation manifest");
    }
    const auto& ciphertext = step.inputs[0];
    const auto& plaintext = step.inputs[1];
    for (int modulus_id : level.rns_layout.q_mod_ids) {
        bindings.load(0, limb_id(ciphertext, 0, modulus_id));
        bindings.load(1, limb_id(plaintext, 0, modulus_id));
        bindings.store(2, limb_id(step.output, 0, modulus_id));
        bindings.load(0, limb_id(ciphertext, 1, modulus_id));
        bindings.store(2, limb_id(step.output, 1, modulus_id));
    }
    bindings.finish();
}

void bind_negate(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 2
        || step.output.component_count != 2) {
        throw std::invalid_argument("invalid Negate relocation manifest");
    }
    const auto& input = step.inputs[0];
    for (std::size_t component = 0; component < 2; ++component) {
        for (int modulus_id : level.rns_layout.q_mod_ids) {
            bindings.load(0, limb_id(input, component, modulus_id));
            bindings.store(2, limb_id(step.output, component, modulus_id));
        }
    }
    bindings.finish();
}

std::size_t ntt_stage_count(std::size_t degree)
{
    std::size_t stages = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        ++stages;
    }
    return stages;
}

std::string canonical_twiddle_id(
    int modulus_id,
    bool inverse,
    const std::string& suffix)
{
    return "constants/twiddle/canonical/mod" + std::to_string(modulus_id)
        + (inverse ? "/intt/" : "/ntt/") + suffix;
}

std::string workspace_mod_id(
    const std::string& prefix,
    const std::string& role,
    int modulus_id)
{
    return prefix + "/workspace/" + role
        + "/mod" + std::to_string(modulus_id);
}

void bind_transform_limb(
    OperationBindingBuilder& bindings,
    const std::string& data_id,
    int modulus_id,
    std::size_t degree,
    bool inverse)
{
    bindings.load(0, data_id);
    const std::size_t stages = ntt_stage_count(degree);
    if (!inverse) {
        bindings.load_words(
            3, canonical_twiddle_id(
                modulus_id, false, "pre_twist"),
            degree);
    }
    for (std::size_t stage = 0; stage < stages; ++stage) {
        bindings.load_words(
            3, canonical_twiddle_id(
                modulus_id, inverse,
                "stage" + std::to_string(stage)),
            degree / 2);
    }
    if (inverse) {
        bindings.load_words(
            3, canonical_twiddle_id(
                modulus_id, true, "post_untwist_scale"),
            degree);
    }
    bindings.store(0, data_id);
}

void bind_relinearize(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& level,
    std::size_t degree)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 3
        || step.output.component_count != 2
        || step.resources.evaluation_key_ids.size() != 1
        || step.resources.constant_ids.size() != 1
        || !step.resources.requires_canonical_twiddles) {
        throw std::invalid_argument(
            "invalid Relinearize relocation manifest");
    }
    const auto& tensor = step.inputs[0];
    const auto& layout = level.rns_layout;
    const std::string& evaluation_key_id =
        step.resources.evaluation_key_ids[0];
    const std::string hardware_prefix =
        step.resources.constant_ids[0] + "/hardware";
    std::vector<int> full_contexts = layout.q_mod_ids;
    full_contexts.insert(
        full_contexts.end(), layout.p_mod_ids.begin(),
        layout.p_mod_ids.end());

    for (std::size_t component = 0; component < 3; ++component) {
        for (int context : layout.q_mod_ids) {
            bind_transform_limb(
                bindings, limb_id(tensor, component, context),
                context, degree, true);
        }
    }

    for (std::size_t digit = 0; digit < layout.key_digits.size(); ++digit) {
        const auto& sources = layout.key_digits[digit];
        std::vector<int> targets;
        for (int context : layout.q_mod_ids) {
            if (std::find(sources.begin(), sources.end(), context)
                == sources.end()) {
                targets.push_back(context);
            }
        }
        targets.insert(
            targets.end(), layout.p_mod_ids.begin(), layout.p_mod_ids.end());
        const std::string digit_prefix = hardware_prefix
            + "/modup/d" + std::to_string(digit);

        for (int source : sources) {
            bindings.load(0, limb_id(tensor, 2, source));
            bindings.store(
                0, workspace_mod_id(
                    hardware_prefix, "modup", source));
        }
        for (std::size_t source_index = 0;
             source_index < sources.size(); ++source_index) {
            const int source = sources[source_index];
            bindings.load(0, limb_id(tensor, 2, source));
            bindings.load(
                1, digit_prefix + "/qhat_inv/mod"
                    + std::to_string(source));
            bindings.store(
                0, hardware_prefix + "/workspace/bconv/normalized"
                    + std::to_string(source_index));
        }
        for (int target : targets) {
            for (std::size_t source_index = 0;
                 source_index < sources.size(); ++source_index) {
                const int source = sources[source_index];
                bindings.load(
                    0, hardware_prefix + "/workspace/bconv/normalized"
                        + std::to_string(source_index));
                bindings.load(
                    1, digit_prefix + "/qhat_mod_target/target"
                        + std::to_string(target) + "/source"
                        + std::to_string(source));
            }
            bindings.store(
                2, workspace_mod_id(
                    hardware_prefix, "modup", target));
        }

        for (int context : full_contexts) {
            bind_transform_limb(
                bindings,
                workspace_mod_id(hardware_prefix, "modup", context),
                context, degree, false);
        }

        for (int component = 0; component < 2; ++component) {
            for (int context : full_contexts) {
                bindings.load(
                    0, workspace_mod_id(
                        hardware_prefix, "modup", context));
                bindings.load(
                    1, evaluation_key_id + "/d" + std::to_string(digit)
                        + "/c" + std::to_string(component) + "/mod"
                        + std::to_string(context));
                if (digit != 0) {
                    bindings.load(
                        2, workspace_mod_id(
                            hardware_prefix,
                            "accumulator/c" + std::to_string(component),
                            context));
                }
                bindings.store(
                    2, workspace_mod_id(
                        hardware_prefix,
                        "accumulator/c" + std::to_string(component),
                        context));
            }
        }
    }

    for (int component = 0; component < 2; ++component) {
        for (int context : full_contexts) {
            const auto accumulator = workspace_mod_id(
                hardware_prefix,
                "accumulator/c" + std::to_string(component), context);
            bind_transform_limb(
                bindings, accumulator, context, degree, true);
        }
    }

    const std::string moddown_prefix = hardware_prefix + "/moddown";
    for (int component = 0; component < 2; ++component) {
        const std::string accumulator_role =
            "accumulator/c" + std::to_string(component);
        for (std::size_t source_index = 0;
             source_index < layout.p_mod_ids.size(); ++source_index) {
            const int source = layout.p_mod_ids[source_index];
            bindings.load(
                0, workspace_mod_id(
                    hardware_prefix, accumulator_role, source));
            bindings.load(
                1, moddown_prefix + "/qhat_inv/mod"
                    + std::to_string(source));
            bindings.store(
                0, hardware_prefix + "/workspace/bconv/normalized"
                    + std::to_string(source_index));
        }
        for (int target : layout.q_mod_ids) {
            for (std::size_t source_index = 0;
                 source_index < layout.p_mod_ids.size(); ++source_index) {
                const int source = layout.p_mod_ids[source_index];
                bindings.load(
                    0, hardware_prefix + "/workspace/bconv/normalized"
                        + std::to_string(source_index));
                bindings.load(
                    1, moddown_prefix + "/qhat_mod_target/target"
                        + std::to_string(target) + "/source"
                        + std::to_string(source));
            }
            bindings.store(
                2, workspace_mod_id(
                    hardware_prefix, "moddown/correction", target));
        }
        for (int context : layout.q_mod_ids) {
            const auto accumulator = workspace_mod_id(
                hardware_prefix, accumulator_role, context);
            bindings.load(0, accumulator);
            bindings.load(
                1, workspace_mod_id(
                    hardware_prefix, "moddown/correction", context));
            bindings.load(
                2, moddown_prefix + "/p_inverse/mod"
                    + std::to_string(context));
            bindings.store(0, accumulator);
        }
    }

    for (int context : layout.q_mod_ids) {
        bindings.load(
            0, workspace_mod_id(
                hardware_prefix, "accumulator/c0", context));
        bindings.load(1, limb_id(tensor, 0, context));
        bindings.store(2, limb_id(step.output, 0, context));
    }
    for (int context : layout.q_mod_ids) {
        bindings.load(0, limb_id(tensor, 1, context));
        bindings.load(
            1, workspace_mod_id(
                hardware_prefix, "accumulator/c1", context));
        bindings.store(2, limb_id(step.output, 1, context));
    }

    for (std::size_t component = 0; component < 2; ++component) {
        for (int context : layout.q_mod_ids) {
            bind_transform_limb(
                bindings, limb_id(step.output, component, context),
                context, degree, false);
        }
    }
    bindings.finish();
}

void bind_rescale(
    OperationBindingBuilder& bindings,
    const CkksOperationStep& step,
    const CkksLevelDescriptor& source_level,
    const CkksLevelDescriptor& destination_level,
    std::size_t degree)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 2
        || step.output.component_count != 2
        || step.resources.constant_ids.size() != 1
        || !step.resources.evaluation_key_ids.empty()
        || !step.resources.requires_canonical_twiddles
        || source_level.rns_layout.q_mod_ids.size() < 2
        || destination_level.rns_layout.q_mod_ids.size() + 1
            != source_level.rns_layout.q_mod_ids.size()
        || !std::equal(
            destination_level.rns_layout.q_mod_ids.begin(),
            destination_level.rns_layout.q_mod_ids.end(),
            source_level.rns_layout.q_mod_ids.begin())) {
        throw std::invalid_argument("invalid Rescale relocation manifest");
    }
    const auto& input = step.inputs[0];
    const auto& source_contexts = source_level.rns_layout.q_mod_ids;
    const auto& destination_contexts =
        destination_level.rns_layout.q_mod_ids;
    const int dropped_context = source_contexts.back();
    const std::string hardware_prefix =
        step.resources.constant_ids[0] + "/hardware";

    for (std::size_t component = 0; component < 2; ++component) {
        for (int context : source_contexts) {
            bind_transform_limb(
                bindings, limb_id(input, component, context),
                context, degree, true);
        }
    }

    for (std::size_t component = 0; component < 2; ++component) {
        const std::string rounded_role =
            "rounded/c" + std::to_string(component);
        for (int context : source_contexts) {
            bindings.load(0, limb_id(input, component, context));
            bindings.load(
                1, hardware_prefix + "/half/mod"
                    + std::to_string(context));
            bindings.store(
                0, workspace_mod_id(
                    hardware_prefix, rounded_role, context));
        }

        bindings.load(
            0, workspace_mod_id(
                hardware_prefix, rounded_role, dropped_context));
        bindings.load(
            1, hardware_prefix + "/moddown/qhat_inv/mod"
                + std::to_string(dropped_context));
        bindings.store(
            0, hardware_prefix + "/workspace/bconv/normalized0");
        for (int target : destination_contexts) {
            bindings.load(
                0, hardware_prefix + "/workspace/bconv/normalized0");
            bindings.load(
                1, hardware_prefix + "/moddown/qhat_mod_target/target"
                    + std::to_string(target) + "/source"
                    + std::to_string(dropped_context));
            bindings.store(
                2, workspace_mod_id(
                    hardware_prefix, "moddown/correction", target));
        }
        for (int context : destination_contexts) {
            bindings.load(
                0, workspace_mod_id(
                    hardware_prefix, rounded_role, context));
            bindings.load(
                1, workspace_mod_id(
                    hardware_prefix, "moddown/correction", context));
            bindings.load(
                2, hardware_prefix + "/moddown/q_last_inverse/mod"
                    + std::to_string(context));
            bindings.store(0, limb_id(step.output, component, context));
        }
    }

    for (std::size_t component = 0; component < 2; ++component) {
        for (int context : destination_contexts) {
            bind_transform_limb(
                bindings, limb_id(step.output, component, context),
                context, degree, false);
        }
    }
    bindings.finish();
}

} // namespace

CkksRelocationSchedule build_ckks_relocation_schedule(
    const CkksLoweredProgram& program,
    const hpu::runtime::HpuMemImage& image,
    const ::seal::SEALContext& context)
{
    if (program.operations.empty()) {
        throw std::invalid_argument(
            "cannot relocate an empty CKKS lowered program");
    }
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::ckks
        || key_data->parms().poly_modulus_degree() == 0) {
        throw std::invalid_argument(
            "CKKS relocation requires a valid CKKS context");
    }
    const std::size_t degree = key_data->parms().poly_modulus_degree();
    const CkksLevelChain level_chain(context);

    const auto program_instructions = parse_dma_instructions(program.body_asm);
    std::vector<std::vector<DmaInstruction>> operation_instructions;
    operation_instructions.reserve(program.operations.size());
    std::size_t operation_dma_count = 0;
    for (const auto& operation : program.operations) {
        operation_instructions.push_back(
            parse_dma_instructions(operation.body_asm));
        operation_dma_count += operation_instructions.back().size();
    }
    if (program_instructions.size() < operation_dma_count
        || program_instructions.size() - operation_dma_count > 1) {
        throw std::invalid_argument(
            "lowered CKKS program has an unsupported global DMA layout");
    }

    const std::size_t global_dma_count =
        program_instructions.size() - operation_dma_count;
    CkksRelocationSchedule result;
    result.expected_dma_count = program_instructions.size();
    if (global_dma_count == 1) {
        const DmaInstruction expected{
            CkksDmaDirection::load,
            kModulusTableObject,
            hpu::DataType::mod_ctx,
            hpu::DloadFlag::small_bank,
            0};
        if (!same_instruction(program_instructions.front(), expected)) {
            throw std::invalid_argument(
                "lowered CKKS global DMA is not the modulus-table load");
        }
        const auto& allocation = image.allocation(kModulusTableId);
        if (allocation.kind != hpu::runtime::AllocationKind::modulus_table
            || !allocation.read_only || allocation.span.line_count == 0) {
            throw std::invalid_argument(
                "CKKS modulus-table relocation has an incompatible allocation");
        }
        CkksDmaBinding binding;
        binding.program_dma_index = 0;
        binding.operation_dma_index = 0;
        binding.operation_id = kApplicationOperationId;
        binding.direction = CkksDmaDirection::load;
        binding.object_slot = kModulusTableObject;
        binding.load_type = hpu::DataType::mod_ctx;
        binding.load_flag = hpu::DloadFlag::small_bank;
        binding.allocation_id = allocation.id;
        binding.span = allocation.span;
        result.bindings.push_back(std::move(binding));
    }

    std::size_t first_program_dma_index = global_dma_count;
    for (std::size_t operation_index = 0;
         operation_index < program.operations.size(); ++operation_index) {
        const auto& operation = program.operations[operation_index];
        const auto& instructions = operation_instructions[operation_index];
        for (std::size_t local = 0; local < instructions.size(); ++local) {
            if (!same_instruction(
                    instructions[local],
                    program_instructions[first_program_dma_index + local])) {
                throw std::invalid_argument(
                    "lowered operation DMA stream differs from program body");
            }
        }

        const auto& step = operation.operation;
        switch (step.kind) {
        case CkksOperationKind::add:
        case CkksOperationKind::subtract: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "Add/Subtract relocation manifest has no left input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_ciphertext_binary(
                bindings, step,
                level_chain.require(step.inputs[0].metadata.parms_id));
            break;
        }
        case CkksOperationKind::multiply_plain: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "MultiplyPlain relocation manifest has no ciphertext input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_multiply_plain(
                bindings, step,
                level_chain.require(step.inputs[0].metadata.parms_id));
            break;
        }
        case CkksOperationKind::square: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "Square relocation manifest has no input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_square(
                bindings, step, level_chain.require(step.inputs[0].metadata.parms_id));
            break;
        }
        case CkksOperationKind::add_plain:
        case CkksOperationKind::subtract_plain: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "AddPlain relocation manifest has no ciphertext input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_plain_binary(
                bindings, step, level_chain.require(step.inputs[0].metadata.parms_id));
            break;
        }
        case CkksOperationKind::negate: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "Negate relocation manifest has no input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_negate(
                bindings, step,
                level_chain.require(step.inputs[0].metadata.parms_id));
            break;
        }
        case CkksOperationKind::relinearize: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "Relinearize relocation manifest has no tensor input");
            }
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_relinearize(
                bindings, step,
                level_chain.require(step.inputs[0].metadata.parms_id),
                degree);
            break;
        }
        case CkksOperationKind::rescale: {
            if (step.inputs.empty()) {
                throw std::invalid_argument(
                    "Rescale relocation manifest has no ciphertext input");
            }
            const auto& source_level =
                level_chain.require(step.inputs[0].metadata.parms_id);
            OperationBindingBuilder bindings(
                result, image, operation, operation_index,
                first_program_dma_index, degree, instructions);
            bind_rescale(
                bindings, step, source_level,
                level_chain.next(source_level.parms_id), degree);
            break;
        }
        }
        first_program_dma_index += instructions.size();
    }
    if (first_program_dma_index != program_instructions.size()) {
        throw std::logic_error(
            "CKKS relocation did not account for the complete DMA stream");
    }
    return result;
}

} // namespace hpu::seal_adapter
