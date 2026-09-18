#include "hpu/seal/bfv_operation_relocation.hpp"

#include "hpu/seal/bfv_level.hpp"

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
        load_words(slot, allocation_id, polynomial_words_);
    }

    void load_words(int slot, const std::string& allocation_id, std::size_t expected_words)
    {
        append(BfvDmaDirection::load, slot, allocation_id, hpu::DataType::poly,
               hpu::DloadFlag::regular_bank, 0, expected_words);
    }

    void store(int slot, const std::string& allocation_id)
    {
        append(BfvDmaDirection::store, slot, allocation_id, hpu::DataType::poly,
               hpu::DloadFlag::regular_bank, 1, polynomial_words_);
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
                hpu::DataType load_type, hpu::DloadFlag load_flag, int store_release,
                std::size_t expected_words)
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
        if (allocation.word_count != expected_words || allocation.span.line_count == 0) {
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

std::size_t ntt_stage_count(std::size_t degree)
{
    std::size_t stages = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        ++stages;
    }
    return stages;
}

std::string canonical_twiddle_id(int modulus_id, bool inverse, const std::string& suffix)
{
    return "constants/twiddle/canonical/mod" + std::to_string(modulus_id) +
           (inverse ? "/intt/" : "/ntt/") + suffix;
}

std::string workspace_mod_id(const std::string& prefix, const std::string& role, int modulus_id)
{
    return prefix + "/workspace/" + role + "/mod" + std::to_string(modulus_id);
}

void bind_transform_limb(OperationBindingBuilder& bindings, const std::string& input_id,
                         const std::string& output_id, int modulus_id, std::size_t degree,
                         bool inverse)
{
    bindings.load(0, input_id);
    const std::size_t stages = ntt_stage_count(degree);
    if (!inverse) {
        bindings.load_words(3, canonical_twiddle_id(modulus_id, false, "pre_twist"), degree);
    }
    for (std::size_t stage = 0; stage < stages; ++stage) {
        bindings.load_words(
            3, canonical_twiddle_id(modulus_id, inverse, "stage" + std::to_string(stage)),
            degree / 2);
    }
    if (inverse) {
        bindings.load_words(3, canonical_twiddle_id(modulus_id, true, "post_untwist_scale"),
                            degree);
    }
    bindings.store(0, output_id);
}

void bind_bconv(OperationBindingBuilder& bindings, const std::vector<int>& sources,
                const std::vector<int>& targets, const std::vector<std::string>& source_ids,
                const std::vector<std::string>& target_ids, const std::string& normalized_prefix,
                const std::string& inverse_prefix, const std::string& target_prefix)
{
    if (sources.size() != source_ids.size() || targets.size() != target_ids.size()) {
        throw std::logic_error("BFV BConv relocation shape mismatch");
    }
    for (std::size_t source_index = 0; source_index < sources.size(); ++source_index) {
        const int source = sources[source_index];
        bindings.load(0, source_ids[source_index]);
        bindings.load(1, inverse_prefix + "/qhat_inv/mod" + std::to_string(source));
        bindings.store(0, normalized_prefix + std::to_string(source_index));
    }
    for (std::size_t target_index = 0; target_index < targets.size(); ++target_index) {
        const int target = targets[target_index];
        for (std::size_t source_index = 0; source_index < sources.size(); ++source_index) {
            bindings.load(0, normalized_prefix + std::to_string(source_index));
            bindings.load(1, target_prefix + "/qhat_mod_target/target" + std::to_string(target) +
                                 "/source" + std::to_string(sources[source_index]));
        }
        bindings.store(2, target_ids[target_index]);
    }
}

std::vector<std::string> workspace_ids(const std::string& prefix, const std::string& role,
                                       const std::vector<int>& contexts)
{
    std::vector<std::string> result;
    result.reserve(contexts.size());
    for (int context : contexts) {
        result.push_back(workspace_mod_id(prefix, role, context));
    }
    return result;
}

std::vector<std::string> value_limb_ids(const BfvPlannedValue& value, std::size_t component,
                                        const std::vector<int>& contexts)
{
    std::vector<std::string> result;
    result.reserve(contexts.size());
    for (int context : contexts) {
        result.push_back(limb_id(value, component, context));
    }
    return result;
}

void bind_bfv_multiply(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                       const BfvLevelDescriptor& level, std::size_t degree)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2 ||
        step.inputs[1].component_count != 2 || step.output.component_count != 2 ||
        !step.resources.requires_canonical_twiddles || step.resources.evaluation_key_id.empty() ||
        step.resources.keyswitch_constants_id.empty() ||
        step.resources.multiply_constants_id.empty()) {
        throw std::invalid_argument("invalid BFV Multiply relocation manifest");
    }
    const auto& q = level.keyswitch_layout.q_mod_ids;
    const auto& p = level.keyswitch_layout.p_mod_ids;
    const auto& b = level.b_mod_ids;
    if (p.size() != 1 || q.size() < 2 || b.size() < q.size()) {
        throw std::invalid_argument("unsupported BFV Multiply relocation layout");
    }
    std::vector<int> bsk = b;
    bsk.push_back(level.m_sk_mod_id);
    std::vector<int> q_bsk = q;
    q_bsk.insert(q_bsk.end(), bsk.begin(), bsk.end());
    std::vector<int> q_p = q;
    q_p.insert(q_p.end(), p.begin(), p.end());

    const std::string multiply_prefix = step.resources.multiply_constants_id + "/hardware";
    const std::string multiply_normalized = multiply_prefix + "/workspace/bconv/normalized";
    const std::string q_to_bsk = multiply_prefix + "/q_to_bsk";
    const auto input_role = [](int input) { return "input/i" + std::to_string(input); };
    const auto tensor_role = [](int component) { return "tensor/c" + std::to_string(component); };

    const BfvPlannedValue* input_values[] = {&step.inputs[0], &step.inputs[0], &step.inputs[1],
                                             &step.inputs[1]};
    const std::size_t input_components[] = {0, 1, 0, 1};
    for (int input = 0; input < 4; ++input) {
        bind_bconv(bindings, q, bsk,
                   value_limb_ids(*input_values[input], input_components[input], q),
                   workspace_ids(multiply_prefix, input_role(input), bsk), multiply_normalized,
                   q_to_bsk, q_to_bsk);
    }

    for (int input = 0; input < 4; ++input) {
        for (int context : q) {
            bind_transform_limb(bindings,
                                limb_id(*input_values[input], input_components[input], context),
                                workspace_mod_id(multiply_prefix, input_role(input), context),
                                context, degree, false);
        }
    }
    for (int input = 0; input < 4; ++input) {
        for (int context : bsk) {
            const auto id = workspace_mod_id(multiply_prefix, input_role(input), context);
            bind_transform_limb(bindings, id, id, context, degree, false);
        }
    }

    const auto bind_tensor_basis = [&](const std::vector<int>& contexts) {
        for (int context : contexts) {
            const auto input = [&](int index) {
                return workspace_mod_id(multiply_prefix, input_role(index), context);
            };
            bindings.load(0, input(0));
            bindings.load(1, input(2));
            bindings.store(2, workspace_mod_id(multiply_prefix, tensor_role(0), context));
            bindings.load(0, input(0));
            bindings.load(1, input(3));
            bindings.load(0, input(1));
            bindings.load(1, input(2));
            bindings.store(2, workspace_mod_id(multiply_prefix, tensor_role(1), context));
            bindings.load(0, input(1));
            bindings.load(1, input(3));
            bindings.store(2, workspace_mod_id(multiply_prefix, tensor_role(2), context));
        }
    };
    bind_tensor_basis(q);
    bind_tensor_basis(bsk);

    for (int component = 0; component < 3; ++component) {
        for (int context : q) {
            const auto id = workspace_mod_id(multiply_prefix, tensor_role(component), context);
            bind_transform_limb(bindings, id, id, context, degree, true);
        }
    }
    for (int component = 0; component < 3; ++component) {
        for (int context : bsk) {
            const auto id = workspace_mod_id(multiply_prefix, tensor_role(component), context);
            bind_transform_limb(bindings, id, id, context, degree, true);
        }
    }

    for (int component = 0; component < 3; ++component) {
        for (int context : q_bsk) {
            const auto tensor = workspace_mod_id(multiply_prefix, tensor_role(component), context);
            bindings.load(0, tensor);
            bindings.load(1, multiply_prefix + "/t/mod" + std::to_string(context));
            bindings.store(0, tensor);
        }
    }

    for (int component = 0; component < 3; ++component) {
        const auto converted_role = "fast_floor/converted/c" + std::to_string(component);
        bind_bconv(bindings, q, bsk, workspace_ids(multiply_prefix, tensor_role(component), q),
                   workspace_ids(multiply_prefix, converted_role, bsk), multiply_normalized,
                   q_to_bsk, q_to_bsk);
        for (int context : bsk) {
            const auto tensor = workspace_mod_id(multiply_prefix, tensor_role(component), context);
            bindings.load(0, tensor);
            bindings.load(1, workspace_mod_id(multiply_prefix, converted_role, context));
            bindings.load(2,
                          multiply_prefix + "/fast_floor/q_inverse/mod" + std::to_string(context));
            bindings.store(0, tensor);
        }
    }

    const std::string b_to_q = multiply_prefix + "/b_to_q";
    const std::string b_to_msk = multiply_prefix + "/b_to_msk";
    const std::string msk_to_q = multiply_prefix + "/msk_to_q";
    for (int component = 0; component < 3; ++component) {
        const auto source_ids = workspace_ids(multiply_prefix, tensor_role(component), b);
        const auto y_role = "branchless/y/c" + std::to_string(component);
        const auto alpha_role = "branchless/alpha/c" + std::to_string(component);
        bind_bconv(bindings, b, q, source_ids, workspace_ids(multiply_prefix, y_role, q),
                   multiply_normalized, b_to_q, b_to_q);
        bind_bconv(bindings, b, {level.m_sk_mod_id}, source_ids,
                   workspace_ids(multiply_prefix, alpha_role, {level.m_sk_mod_id}),
                   multiply_normalized, b_to_q, b_to_msk);

        const auto alpha_msk = workspace_mod_id(multiply_prefix, alpha_role, level.m_sk_mod_id);
        bindings.load(0, alpha_msk);
        bindings.load(1,
                      workspace_mod_id(multiply_prefix, tensor_role(component), level.m_sk_mod_id));
        bindings.load(2, multiply_prefix + "/branchless/b_inverse/mod" +
                             std::to_string(level.m_sk_mod_id));
        bindings.store(0, alpha_msk);

        bind_bconv(bindings, {level.m_sk_mod_id}, q, {alpha_msk},
                   workspace_ids(multiply_prefix, alpha_role, q), multiply_normalized, msk_to_q,
                   msk_to_q);
        for (int context : q) {
            bindings.load(2, workspace_mod_id(multiply_prefix, y_role, context));
            bindings.load(0, workspace_mod_id(multiply_prefix, alpha_role, context));
            bindings.load(1,
                          multiply_prefix + "/branchless/negative_b/mod" + std::to_string(context));
            bindings.store(2, workspace_mod_id(multiply_prefix, tensor_role(component), context));
        }
    }

    const std::string keyswitch_prefix = step.resources.keyswitch_constants_id + "/hardware";
    const std::string keyswitch_normalized = keyswitch_prefix + "/workspace/bconv/normalized";
    for (std::size_t digit = 0; digit < level.keyswitch_layout.key_digits.size(); ++digit) {
        const auto& sources = level.keyswitch_layout.key_digits[digit];
        std::vector<int> targets;
        for (int context : q) {
            if (std::find(sources.begin(), sources.end(), context) == sources.end()) {
                targets.push_back(context);
            }
        }
        targets.insert(targets.end(), p.begin(), p.end());
        const std::string digit_prefix = keyswitch_prefix + "/modup/d" + std::to_string(digit);
        const auto switching_ids = workspace_ids(multiply_prefix, tensor_role(2), sources);
        for (std::size_t index = 0; index < sources.size(); ++index) {
            bindings.load(0, switching_ids[index]);
            bindings.store(0, workspace_mod_id(keyswitch_prefix, "modup", sources[index]));
        }
        bind_bconv(bindings, sources, targets, switching_ids,
                   workspace_ids(keyswitch_prefix, "modup", targets), keyswitch_normalized,
                   digit_prefix, digit_prefix);
        for (int context : q_p) {
            const auto id = workspace_mod_id(keyswitch_prefix, "modup", context);
            bind_transform_limb(bindings, id, id, context, degree, false);
        }
        for (int component = 0; component < 2; ++component) {
            const auto accumulator_role = "accumulator/c" + std::to_string(component);
            for (int context : q_p) {
                bindings.load(0, workspace_mod_id(keyswitch_prefix, "modup", context));
                bindings.load(1, step.resources.evaluation_key_id + "/d" + std::to_string(digit) +
                                     "/c" + std::to_string(component) + "/mod" +
                                     std::to_string(context));
                if (digit != 0) {
                    bindings.load(2, workspace_mod_id(keyswitch_prefix, accumulator_role, context));
                }
                bindings.store(2, workspace_mod_id(keyswitch_prefix, accumulator_role, context));
            }
        }
    }
    for (int component = 0; component < 2; ++component) {
        const auto accumulator_role = "accumulator/c" + std::to_string(component);
        for (int context : q_p) {
            const auto id = workspace_mod_id(keyswitch_prefix, accumulator_role, context);
            bind_transform_limb(bindings, id, id, context, degree, true);
        }
    }

    const int p_context = p.front();
    const std::string moddown_prefix = keyswitch_prefix + "/moddown";
    for (int component = 0; component < 2; ++component) {
        const auto accumulator_role = "accumulator/c" + std::to_string(component);
        for (int context : q_p) {
            const auto accumulator = workspace_mod_id(keyswitch_prefix, accumulator_role, context);
            bindings.load(0, accumulator);
            bindings.load(1, keyswitch_prefix + "/half/mod" + std::to_string(context));
            bindings.store(0, accumulator);
        }
        bind_bconv(bindings, {p_context}, q,
                   workspace_ids(keyswitch_prefix, accumulator_role, {p_context}),
                   workspace_ids(keyswitch_prefix, "moddown/correction", q), keyswitch_normalized,
                   moddown_prefix, moddown_prefix);
        for (int context : q) {
            const auto accumulator = workspace_mod_id(keyswitch_prefix, accumulator_role, context);
            bindings.load(0, accumulator);
            bindings.load(1, workspace_mod_id(keyswitch_prefix, "moddown/correction", context));
            bindings.load(2, moddown_prefix + "/p_inverse/mod" + std::to_string(context));
            bindings.store(0, accumulator);
        }
    }
    for (int context : q) {
        bindings.load(0, workspace_mod_id(keyswitch_prefix, "accumulator/c0", context));
        bindings.load(1, workspace_mod_id(multiply_prefix, tensor_role(0), context));
        bindings.store(2, limb_id(step.output, 0, context));
    }
    for (int context : q) {
        bindings.load(0, workspace_mod_id(multiply_prefix, tensor_role(1), context));
        bindings.load(1, workspace_mod_id(keyswitch_prefix, "accumulator/c1", context));
        bindings.store(2, limb_id(step.output, 1, context));
    }
    bindings.finish();
}

void bind_multiply_plain(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                         const BfvLevelDescriptor& level, std::size_t degree)
{
    if (step.inputs.size() != 2 || step.inputs[0].component_count != 2 ||
        step.inputs[1].component_count != 1 || step.output.component_count != 2 ||
        !step.resources.requires_canonical_twiddles) {
        throw std::invalid_argument("invalid BFV MultiplyPlain relocation manifest");
    }
    const std::size_t stages = ntt_stage_count(degree);
    for (std::size_t component = 0; component < 2; ++component) {
        for (int modulus_id : level.keyswitch_layout.q_mod_ids) {
            bindings.load(0, limb_id(step.inputs[0], component, modulus_id));
            bindings.load_words(3, canonical_twiddle_id(modulus_id, false, "pre_twist"), degree);
            for (std::size_t stage = 0; stage < stages; ++stage) {
                bindings.load_words(
                    3, canonical_twiddle_id(modulus_id, false, "stage" + std::to_string(stage)),
                    degree / 2);
            }
            bindings.load(1, limb_id(step.inputs[1], 0, modulus_id));
            for (std::size_t stage = 0; stage < stages; ++stage) {
                bindings.load_words(
                    3, canonical_twiddle_id(modulus_id, true, "stage" + std::to_string(stage)),
                    degree / 2);
            }
            bindings.load_words(3, canonical_twiddle_id(modulus_id, true, "post_untwist_scale"),
                                degree);
            bindings.store(0, limb_id(step.output, component, modulus_id));
        }
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

void bind_mod_switch(OperationBindingBuilder& bindings, const BfvOperationStep& step,
                     const BfvLevelDescriptor& source, const BfvLevelDescriptor& destination)
{
    if (step.inputs.size() != 1 || step.inputs[0].component_count != 2 ||
        step.output.component_count != 2 || step.resources.requires_canonical_twiddles ||
        step.resources.mod_switch_constants_id.empty() ||
        source.keyswitch_layout.q_mod_ids.size() < 2 ||
        destination.keyswitch_layout.q_mod_ids.size() + 1 !=
            source.keyswitch_layout.q_mod_ids.size() ||
        !std::equal(destination.keyswitch_layout.q_mod_ids.begin(),
                    destination.keyswitch_layout.q_mod_ids.end(),
                    source.keyswitch_layout.q_mod_ids.begin())) {
        throw std::invalid_argument("invalid BFV ModSwitch relocation manifest");
    }
    const auto& source_contexts = source.keyswitch_layout.q_mod_ids;
    const auto& destination_contexts = destination.keyswitch_layout.q_mod_ids;
    const int dropped_context = source_contexts.back();
    const std::string hardware_prefix = step.resources.mod_switch_constants_id + "/hardware";
    for (std::size_t component = 0; component < 2; ++component) {
        const std::string rounded_role = "rounded/c" + std::to_string(component);
        for (int context : source_contexts) {
            bindings.load(0, limb_id(step.inputs.front(), component, context));
            bindings.load(1, hardware_prefix + "/half/mod" + std::to_string(context));
            bindings.store(0, workspace_mod_id(hardware_prefix, rounded_role, context));
        }

        bindings.load(0, workspace_mod_id(hardware_prefix, rounded_role, dropped_context));
        bindings.load(1,
                      hardware_prefix + "/moddown/qhat_inv/mod" + std::to_string(dropped_context));
        bindings.store(0, hardware_prefix + "/workspace/bconv/normalized0");
        for (int target : destination_contexts) {
            bindings.load(0, hardware_prefix + "/workspace/bconv/normalized0");
            bindings.load(1, hardware_prefix + "/moddown/qhat_mod_target/target" +
                                 std::to_string(target) + "/source" +
                                 std::to_string(dropped_context));
            bindings.store(2, workspace_mod_id(hardware_prefix, "moddown/correction", target));
        }
        for (int context : destination_contexts) {
            bindings.load(0, workspace_mod_id(hardware_prefix, rounded_role, context));
            bindings.load(1, workspace_mod_id(hardware_prefix, "moddown/correction", context));
            bindings.load(2, hardware_prefix + "/moddown/p_inverse/mod" + std::to_string(context));
            bindings.store(0, limb_id(step.output, component, context));
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
        case BfvOperationKind::multiply:
            bind_bfv_multiply(bindings, step, level, degree);
            break;
        case BfvOperationKind::add_plain:
        case BfvOperationKind::subtract_plain:
            bind_plain_binary(bindings, step, level);
            break;
        case BfvOperationKind::multiply_plain:
            bind_multiply_plain(bindings, step, level, degree);
            break;
        case BfvOperationKind::negate:
            bind_negate(bindings, step, level);
            break;
        case BfvOperationKind::mod_switch:
            bind_mod_switch(bindings, step, level,
                            level_chain.require(step.output.metadata.parms_id));
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
