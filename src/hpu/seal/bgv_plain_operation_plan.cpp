#include "hpu/seal/bgv_plain_operation_plan.hpp"

#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"
#include "scheme/bfv/galois.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include "assembler.hpp"
#include "executable.hpp"

#include <cctype>
#include <limits>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(std::uint64_t value)
{
    if (value < 65537 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("BGV linear-chain modulus is outside the HPU PE range");
    }
    return static_cast<std::uint32_t>(value);
}

std::uint64_t barrett_mu(std::uint32_t modulus)
{
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(1) << 64) / modulus);
}

std::string mod_id(const std::string& prefix, std::size_t basis)
{
    return prefix + "/mod" + std::to_string(basis);
}

std::vector<std::uint32_t> allocation_words(
    const hpu::runtime::HpuMemImage& image,
    const hpu::runtime::HpuMemAllocation& allocation)
{
    const std::size_t first = allocation.span.line_offset *
        hpu::runtime::kHpuMemLineWords;
    return {image.words().begin() + static_cast<std::ptrdiff_t>(first),
            image.words().begin() +
                static_cast<std::ptrdiff_t>(first + allocation.word_count)};
}

class DmaRecipe {
public:
    DmaRecipe(const hpu::runtime::HpuMemImage& image,
              const std::vector<hpu::DmaRelocation>& encoded)
        : image_(image), encoded_(encoded)
    {}

    void load(int slot, const std::string& id,
              hpu::DataType type = hpu::DataType::poly,
              hpu::DloadFlag flag = hpu::DloadFlag::regular_bank)
    {
        bind(id, hpu::Mnemonic::kDload, slot,
             static_cast<std::uint8_t>(type), static_cast<std::uint8_t>(flag));
    }

    void store(int slot, const std::string& id)
    {
        bind(id, hpu::Mnemonic::kDstore, slot, 1, 0);
    }

    void replay(const BgvKeySwitchDmaBinding& binding,
                const std::string& relocated_id)
    {
        if (binding.direction == hpu::Mnemonic::kDload) {
            load(binding.object_slot, relocated_id,
                 static_cast<hpu::DataType>(binding.type_or_release),
                 static_cast<hpu::DloadFlag>(binding.flag));
        } else if (binding.direction == hpu::Mnemonic::kDstore) {
            store(binding.object_slot, relocated_id);
        } else {
            throw std::logic_error("BGV rotation has a non-DMA binding");
        }
    }

    std::vector<BgvKeySwitchDmaBinding> finish()
    {
        if (bindings_.size() != encoded_.size()) {
            throw std::logic_error("BGV linear-chain DMA recipe is incomplete");
        }
        return std::move(bindings_);
    }

private:
    void bind(const std::string& id, hpu::Mnemonic direction, int slot,
              std::uint8_t type_or_release, std::uint8_t flag)
    {
        const std::size_t index = bindings_.size();
        if (index >= encoded_.size()) {
            throw std::logic_error("BGV linear-chain DMA recipe exceeds stream");
        }
        const auto& instruction = encoded_[index];
        const auto& allocation = image_.allocation(id);
        if (instruction.dma_index != index ||
            instruction.direction != direction ||
            instruction.object_id != slot ||
            instruction.type_or_release != type_or_release ||
            instruction.flag != flag || allocation.span.line_count == 0 ||
            (direction == hpu::Mnemonic::kDstore && allocation.read_only)) {
            throw std::invalid_argument(
                "BGV linear-chain DMA binding disagrees with encoded instruction: " + id);
        }
        bindings_.push_back({
            index, instruction.instruction_index, instruction.direction,
            instruction.object_id, instruction.type_or_release,
            instruction.flag, id, allocation.span});
    }

    const hpu::runtime::HpuMemImage& image_;
    const std::vector<hpu::DmaRelocation>& encoded_;
    std::vector<BgvKeySwitchDmaBinding> bindings_;
};

} // namespace

BgvPlainOperationPlan::BgvPlainOperationPlan(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input)
    : context_(context), input_(input)
{
    const auto source = context_.get_context_data(input_.parms_id());
    if (!source || source->parms().scheme() != ::seal::scheme_type::bgv ||
        !::seal::is_valid_for(input_, context_) || !input_.is_ntt_form() ||
        input_.size() != 2) {
        throw std::invalid_argument(
            "BGV linear-chain input must be a valid two-component NTT ciphertext");
    }
}

void BgvPlainOperationPlan::require_step_id(const std::string& id) const
{
    if (id.empty() ||
        (id[0] != '_' && !std::isalpha(static_cast<unsigned char>(id[0])))) {
        throw std::invalid_argument("BGV linear-chain step id is invalid");
    }
    for (char character : id) {
        if (character != '_' &&
            !std::isalnum(static_cast<unsigned char>(character))) {
            throw std::invalid_argument("BGV linear-chain step id must be alphanumeric");
        }
    }
    for (const auto& step : steps_) {
        if (step.id == id) {
            throw std::invalid_argument("BGV linear-chain step id is duplicated");
        }
    }
}

void BgvPlainOperationPlan::append(
    std::string id, BgvPlainOperationKind kind,
    const ::seal::Plaintext& plaintext)
{
    require_step_id(id);
    const auto source = context_.get_context_data(input_.parms_id());
    if (!::seal::is_valid_for(plaintext, context_) || plaintext.is_ntt_form() ||
        plaintext.coeff_count() > source->parms().poly_modulus_degree()) {
        throw std::invalid_argument("BGV linear-chain plaintext is invalid");
    }
    steps_.push_back({std::move(id), kind, plaintext, {}});
}

void BgvPlainOperationPlan::append(
    std::string id, BgvPlainOperationKind kind,
    const ::seal::Ciphertext& right)
{
    require_step_id(id);
    if (!::seal::is_valid_for(right, context_) || !right.is_ntt_form() ||
        right.size() != 2 || right.parms_id() != input_.parms_id()) {
        throw std::invalid_argument(
            "BGV linear-chain binary operand must be a matching two-component NTT ciphertext");
    }
    steps_.push_back({std::move(id), kind, {}, right});
}

void BgvPlainOperationPlan::append_add_plain(
    std::string id, const ::seal::Plaintext& plaintext)
{
    append(std::move(id), BgvPlainOperationKind::add, plaintext);
}

void BgvPlainOperationPlan::append_subtract_plain(
    std::string id, const ::seal::Plaintext& plaintext)
{
    append(std::move(id), BgvPlainOperationKind::subtract, plaintext);
}

void BgvPlainOperationPlan::append_multiply_plain(
    std::string id, const ::seal::Plaintext& plaintext)
{
    append(std::move(id), BgvPlainOperationKind::multiply, plaintext);
}

void BgvPlainOperationPlan::append_add(
    std::string id, const ::seal::Ciphertext& right)
{
    append(std::move(id), BgvPlainOperationKind::add_ciphertext, right);
}

void BgvPlainOperationPlan::append_subtract(
    std::string id, const ::seal::Ciphertext& right)
{
    append(std::move(id), BgvPlainOperationKind::subtract_ciphertext, right);
}

void BgvPlainOperationPlan::append_rotation(
    std::string id, BgvPlainOperationKind kind, int steps,
    const ::seal::GaloisKeys& keys)
{
    require_step_id(id);
    const auto source = context_.get_context_data(input_.parms_id());
    if (!source->qualifiers().using_batching ||
        keys.parms_id() != context_.key_parms_id()) {
        throw std::invalid_argument(
            "BGV linear-chain rotation requires batching and matching Galois keys");
    }
    const auto degree = source->parms().poly_modulus_degree();
    const auto element = kind == BgvPlainOperationKind::rotate_rows
        ? hpu::scheme::bfv::row_rotation_galois_element(degree, steps)
        : hpu::scheme::bfv::column_rotation_galois_element(degree);
    if (!keys.has_key(element)) {
        throw std::invalid_argument("BGV linear-chain rotation Galois key is missing");
    }
    steps_.push_back({std::move(id), kind, {}, {}, keys, steps});
}

void BgvPlainOperationPlan::append_rotate_rows(
    std::string id, int steps, const ::seal::GaloisKeys& keys)
{
    append_rotation(std::move(id), BgvPlainOperationKind::rotate_rows,
                    steps, keys);
}

void BgvPlainOperationPlan::append_rotate_columns(
    std::string id, const ::seal::GaloisKeys& keys)
{
    append_rotation(std::move(id), BgvPlainOperationKind::rotate_columns,
                    0, keys);
}

const std::vector<BgvPlainOperationStep>&
BgvPlainOperationPlan::steps() const noexcept
{
    return steps_;
}

BgvKeySwitchApplication BgvPlainOperationPlan::lower(
    std::uint64_t capacity_lines) const
{
    if (steps_.empty()) {
        throw std::invalid_argument("BGV linear-chain has no steps");
    }
    const auto source = context_.get_context_data(input_.parms_id());
    const auto first_data = context_.first_context_data();
    const auto key_data = context_.key_context_data();
    const auto& q_moduli = source->parms().coeff_modulus();
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = q_moduli.size();
    if (!first_data || key_moduli.size() !=
            first_data->parms().coeff_modulus().size() + 1 ||
        key_moduli.size() + 1 > static_cast<std::size_t>(hpu::kMaxModContexts) ||
        q_count == 0 || q_count > first_data->parms().coeff_modulus().size() ||
        degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree))) {
        throw std::invalid_argument("unsupported BGV linear-chain Qmax|P|t layout");
    }
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        if (q_moduli[basis].value() != key_moduli[basis].value()) {
            throw std::invalid_argument("BGV active Q is not a key-context prefix");
        }
    }
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    hpu::runtime::HpuMemImage image(capacity_lines);
    std::vector<std::uint32_t> table;
    for (const auto& modulus : key_moduli) {
        const auto q = narrow(modulus.value());
        const auto mu = barrett_mu(q);
        table.insert(table.end(), {q, static_cast<std::uint32_t>(mu),
                                   static_cast<std::uint32_t>(mu >> 32U), 0});
    }
    const auto mu_t = barrett_mu(t);
    table.insert(table.end(), {t, static_cast<std::uint32_t>(mu_t),
                               static_cast<std::uint32_t>(mu_t >> 32U), 0});
    image.add("constants/modulus_table", table,
              hpu::runtime::AllocationKind::modulus_table);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto prepared = ciphertext_component_to_hpu(
            input_, component, context_);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto first = prepared.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            image.add(mod_id("input/c" + std::to_string(component), basis),
                      std::vector<std::uint32_t>(first, first + degree),
                      hpu::runtime::AllocationKind::ciphertext);
        }
    }
    ::seal::Evaluator evaluator(context_);
    std::uint32_t current_factor = static_cast<std::uint32_t>(
        input_.correction_factor());
    std::vector<hpu::scheme::bgv::CorrectionBalance> balances(steps_.size());
    std::vector<std::optional<BgvKeySwitchApplication>> rotations(steps_.size());
    std::vector<std::string> output_prefixes;
    for (std::size_t index = 0; index < steps_.size(); ++index) {
        const auto& step = steps_[index];
        const std::string step_prefix = "steps/" + step.id;
        const bool binary = step.kind == BgvPlainOperationKind::add_ciphertext ||
            step.kind == BgvPlainOperationKind::subtract_ciphertext;
        const bool rotation = step.kind == BgvPlainOperationKind::rotate_rows ||
            step.kind == BgvPlainOperationKind::rotate_columns;
        if (rotation) {
            const auto rotation_capacity = estimate_bgv_rotation_image_lines(
                degree, q_count, key_moduli.size());
            rotations[index] = step.kind == BgvPlainOperationKind::rotate_rows
                ? build_bgv_rotate_rows_application(
                    context_, input_, step.galois_keys,
                    step.rotation_steps, rotation_capacity)
                : build_bgv_rotate_columns_application(
                    context_, input_, step.galois_keys, rotation_capacity);
            for (const auto& allocation : rotations[index]->image.allocations()) {
                const auto& id = allocation.id;
                if (id == "constants/modulus_table" ||
                    id.rfind("input/original/c", 0) == 0 ||
                    id.rfind("output/c", 0) == 0) {
                    continue;
                }
                const auto relocated_id = step_prefix + "/rotation/" + id;
                if (allocation.read_only) {
                    image.add(relocated_id,
                              allocation_words(rotations[index]->image, allocation),
                              allocation.kind);
                } else {
                    image.reserve(relocated_id, allocation.word_count,
                                  allocation.kind);
                }
            }
        } else if (binary) {
            const auto balance = hpu::scheme::bgv::balance_correction_factors(
                current_factor,
                static_cast<std::uint32_t>(step.ciphertext.correction_factor()), t);
            balances[index] = balance;
            current_factor = balance.output_factor;
            for (std::size_t component = 0; component < 2; ++component) {
                const auto prepared = ciphertext_component_to_hpu(
                    step.ciphertext, component, context_);
                for (std::size_t basis = 0; basis < q_count; ++basis) {
                    const auto first = prepared.words.begin() +
                        static_cast<std::ptrdiff_t>(basis * degree);
                    image.add(mod_id(step_prefix + "/right/c" +
                                         std::to_string(component), basis),
                              std::vector<std::uint32_t>(first, first + degree),
                              hpu::runtime::AllocationKind::ciphertext);
                }
            }
            for (std::size_t basis = 0; basis < q_count; ++basis) {
                const auto q = narrow(q_moduli[basis].value());
                if (balance.left_scalar != 1) {
                    image.add(mod_id(step_prefix + "/balance/left", basis),
                              std::vector<std::uint32_t>(degree,
                                  balance.left_scalar % q),
                              hpu::runtime::AllocationKind::constant);
                }
                if (balance.right_scalar != 1) {
                    image.add(mod_id(step_prefix + "/balance/right", basis),
                              std::vector<std::uint32_t>(degree,
                                  balance.right_scalar % q),
                              hpu::runtime::AllocationKind::constant);
                }
            }
        } else {
            ::seal::Plaintext prepared = step.plaintext;
            if (step.kind != BgvPlainOperationKind::multiply) {
                for (std::size_t coefficient = 0;
                     coefficient < prepared.coeff_count(); ++coefficient) {
                    prepared[coefficient] = static_cast<std::uint64_t>(
                        (static_cast<unsigned __int128>(prepared[coefficient]) *
                         current_factor) % t);
                }
            }
            evaluator.transform_to_ntt_inplace(prepared, input_.parms_id());
            const auto physical = plaintext_to_hpu(prepared, context_);
            for (std::size_t basis = 0; basis < q_count; ++basis) {
                const auto first = physical.words.begin() +
                    static_cast<std::ptrdiff_t>(basis * degree);
                image.add(mod_id(step_prefix + "/plain", basis),
                          std::vector<std::uint32_t>(first, first + degree),
                          hpu::runtime::AllocationKind::plaintext);
            }
        }
        const std::string output_prefix = index + 1 == steps_.size()
            ? "output" : "steps/" + step.id + "/output";
        output_prefixes.push_back(output_prefix);
        for (std::size_t component = 0; component < 2; ++component) {
            for (std::size_t basis = 0; basis < q_count; ++basis) {
                image.reserve(mod_id(output_prefix + "/c" +
                                         std::to_string(component), basis),
                              degree, hpu::runtime::AllocationKind::output);
            }
        }
    }

    std::vector<hpu::EncodedInstruction> instructions;
    const auto append_source = [&](const std::string& source) {
        const auto encoded = hpu::assemble_source(source);
        instructions.insert(instructions.end(), encoded.begin(), encoded.end());
    };
    append_source(hpu::dload(4, hpu::DataType::mod_ctx,
                             hpu::DloadFlag::small_bank));
    for (std::size_t index = 0; index < steps_.size(); ++index) {
        const auto& step = steps_[index];
        switch (step.kind) {
        case BgvPlainOperationKind::add:
            append_source(hpu::scheme::ckks::generate_add_plain_body_asm(
                static_cast<int>(q_count), false, false));
            break;
        case BgvPlainOperationKind::subtract:
            append_source(hpu::scheme::ckks::generate_subtract_plain_body_asm(
                static_cast<int>(q_count), false, false));
            break;
        case BgvPlainOperationKind::multiply:
            append_source(hpu::scheme::ckks::generate_multiply_plain_body_asm(
                static_cast<int>(q_count), false, false));
            break;
        case BgvPlainOperationKind::add_ciphertext:
            append_source(hpu::scheme::bgv::generate_add_body_asm(
                static_cast<int>(q_count), balances[index], false, false));
            break;
        case BgvPlainOperationKind::subtract_ciphertext:
            append_source(hpu::scheme::bgv::generate_subtract_body_asm(
                static_cast<int>(q_count), balances[index], false, false));
            break;
        case BgvPlainOperationKind::rotate_rows:
        case BgvPlainOperationKind::rotate_columns: {
            const auto& standalone = rotations[index]->instructions;
            if (standalone.size() < 3 ||
                standalone.front().instruction.mnemonic != hpu::Mnemonic::kDload ||
                standalone[standalone.size() - 2].instruction.mnemonic !=
                    hpu::Mnemonic::kPfree ||
                standalone.back().instruction.mnemonic != hpu::Mnemonic::kPsync) {
                throw std::logic_error("BGV standalone rotation prologue/epilogue changed");
            }
            instructions.insert(instructions.end(), standalone.begin() + 1,
                                standalone.end() - 2);
            break;
        }
        }
    }
    append_source(hpu::pfree(4) + hpu::psync());
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(image, encoded_dma);
    recipe.load(4, "constants/modulus_table", hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank);
    for (std::size_t index = 0; index < steps_.size(); ++index) {
        const auto& step = steps_[index];
        const std::string input_prefix = index == 0
            ? "input" : output_prefixes[index - 1];
        const auto& output_prefix = output_prefixes[index];
        const std::string step_prefix = "steps/" + step.id;
        const bool binary = step.kind == BgvPlainOperationKind::add_ciphertext ||
            step.kind == BgvPlainOperationKind::subtract_ciphertext;
        const bool rotation = step.kind == BgvPlainOperationKind::rotate_rows ||
            step.kind == BgvPlainOperationKind::rotate_columns;
        if (rotation) {
            const auto& standalone = *rotations[index];
            if (standalone.dma.empty() ||
                standalone.dma.front().allocation_id != "constants/modulus_table") {
                throw std::logic_error("BGV rotation DMA prologue changed");
            }
            for (std::size_t dma_index = 1;
                 dma_index < standalone.dma.size(); ++dma_index) {
                const auto& binding = standalone.dma[dma_index];
                const auto& id = binding.allocation_id;
                std::string relocated_id;
                if (id.rfind("input/original/c", 0) == 0) {
                    relocated_id = input_prefix +
                        id.substr(std::string("input/original").size());
                } else if (id.rfind("output/c", 0) == 0) {
                    relocated_id = output_prefix +
                        id.substr(std::string("output").size());
                } else {
                    relocated_id = step_prefix + "/rotation/" + id;
                }
                recipe.replay(binding, relocated_id);
            }
        } else if (binary) {
            const auto& balance = balances[index];
            for (std::size_t component = 0; component < 2; ++component) {
                for (std::size_t basis = 0; basis < q_count; ++basis) {
                    const auto suffix = "/c" + std::to_string(component);
                    recipe.load(0, mod_id(input_prefix + suffix, basis));
                    if (balance.left_scalar != 1) {
                        recipe.load(3, mod_id(step_prefix + "/balance/left", basis));
                    }
                    recipe.load(1, mod_id(step_prefix + "/right" + suffix, basis));
                    if (balance.right_scalar != 1) {
                        recipe.load(3, mod_id(step_prefix + "/balance/right", basis));
                    }
                    recipe.store(2, mod_id(output_prefix + suffix, basis));
                }
            }
        } else {
            for (std::size_t basis = 0; basis < q_count; ++basis) {
                recipe.load(0, mod_id(input_prefix + "/c0", basis));
                recipe.load(1, mod_id(step_prefix + "/plain", basis));
                recipe.store(2, mod_id(output_prefix + "/c0", basis));
                recipe.load(0, mod_id(input_prefix + "/c1", basis));
                recipe.store(step.kind == BgvPlainOperationKind::multiply ? 2 : 0,
                             mod_id(output_prefix + "/c1", basis));
            }
        }
    }
    auto bindings = recipe.finish();
    return {std::move(image), input_.parms_id(), current_factor,
            std::move(instructions), std::move(bindings)};
}

} // namespace hpu::seal_adapter
