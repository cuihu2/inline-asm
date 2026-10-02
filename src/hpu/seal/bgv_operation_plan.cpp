#include "hpu/seal/bgv_operation_plan.hpp"

#include "hpu/seal/bgv_modswitch_application.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "poly/cmult.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"
#include "scheme/bgv/ciphertext_multiply.hpp"
#include "scheme/bgv/modswitch.hpp"
#include "scheme/bfv/galois.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"
#include "assembler.hpp"
#include "executable.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <utility>

namespace hpu::seal_adapter {
namespace {
using Kind = BgvOperationKind;
using Image = hpu::runtime::HpuMemImage;
using AllocationKind = hpu::runtime::AllocationKind;

std::uint32_t narrow(std::uint64_t value)
{
    if (value < 65537 || value > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("BGV modulus is outside the HPU PE range");
    return static_cast<std::uint32_t>(value);
}

std::string mod_id(const std::string& prefix, std::size_t basis)
{
    return prefix + "/mod" + std::to_string(basis);
}

void require_value_id(const std::string& id)
{
    if (id.empty() || id == "output")
        throw std::invalid_argument("BGV value id is empty or reserved");
    bool start = true;
    for (unsigned char c : id) {
        if (c == '/') {
            if (start) throw std::invalid_argument("BGV value id has an empty segment");
            start = true;
        } else {
            if ((start && c != '_' && !std::isalpha(c)) ||
                (!start && c != '_' && !std::isalnum(c)))
                throw std::invalid_argument("BGV value id is invalid");
            start = false;
        }
    }
    if (start) throw std::invalid_argument("BGV value id has an empty segment");
}

bool same_ciphertext(const ::seal::Ciphertext& a, const ::seal::Ciphertext& b)
{
    return a.parms_id() == b.parms_id() && a.size() == b.size() &&
        a.poly_modulus_degree() == b.poly_modulus_degree() &&
        a.coeff_modulus_size() == b.coeff_modulus_size() &&
        a.is_ntt_form() == b.is_ntt_form() && a.scale() == b.scale() &&
        a.correction_factor() == b.correction_factor() &&
        (a.size() == 0 || std::equal(a.data(),
            a.data() + a.size() * a.poly_modulus_degree() * a.coeff_modulus_size(), b.data()));
}

template<class Key>
std::shared_ptr<const Key> intern_keys(
    const Key& keys, std::vector<std::shared_ptr<const Key>>& registry)
{
    for (const auto& existing : registry) {
        if (keys.parms_id() != existing->parms_id() ||
            keys.data().size() != existing->data().size()) continue;
        bool equal = true;
        for (std::size_t i = 0; equal && i < keys.data().size(); ++i) {
            equal = keys.data()[i].size() == existing->data()[i].size();
            for (std::size_t j = 0; equal && j < keys.data()[i].size(); ++j)
                equal = same_ciphertext(keys.data()[i][j].data(), existing->data()[i][j].data());
        }
        if (equal) return existing;
    }
    auto captured = std::make_shared<const Key>(keys);
    registry.push_back(captured);
    return captured;
}

// Intern actual payload bytes, not only names or hashes. Kind and word count
// participate in the lookup; hash collisions are resolved by exact comparison.
class ReadOnlyResources {
public:
    explicit ReadOnlyResources(Image& image) : image_(image) {}
    void add(const std::string& id, const std::vector<std::uint32_t>& words,
             AllocationKind kind)
    {
        std::uint64_t hash = 14695981039346656037ULL;
        hash = (hash ^ static_cast<unsigned>(kind)) * 1099511628211ULL;
        for (auto word : words) hash = (hash ^ word) * 1099511628211ULL;
        auto& bucket = buckets_[hash];
        for (const auto& target : bucket) {
            const auto& allocation = image_.allocation(target);
            const auto first = image_.words().begin() +
                allocation.span.line_offset * hpu::runtime::kHpuMemLineWords;
            if (allocation.kind == kind && allocation.word_count == words.size() &&
                std::equal(words.begin(), words.end(), first)) {
                image_.add_alias(id, target);
                return;
            }
        }
        image_.add(id, words, kind);
        bucket.push_back(id);
    }
private:
    Image& image_;
    std::unordered_map<std::uint64_t, std::vector<std::string>> buckets_;
};

class DmaRecipe {
public:
    DmaRecipe(const Image& image, const std::vector<hpu::DmaRelocation>& encoded,
              std::optional<std::size_t> operation_index = {},
              std::string operation_id = "$application")
        : image_(image), encoded_(encoded), operation_index_(operation_index),
          operation_id_(std::move(operation_id)) {}

    void load(int slot, const std::string& id,
              hpu::DataType type = hpu::DataType::poly,
              hpu::DloadFlag flag = hpu::DloadFlag::regular_bank)
    { bind(id, hpu::Mnemonic::kDload, slot, static_cast<std::uint8_t>(type),
           static_cast<std::uint8_t>(flag)); }
    void store(int slot, const std::string& id)
    { bind(id, hpu::Mnemonic::kDstore, slot, 1, 0); }
    template<class Binding>
    void replay(const Binding& binding, const std::string& id)
    { bind(id, binding.direction, binding.object_slot,
           binding.type_or_release, binding.flag); }
    std::vector<BgvKeySwitchDmaBinding> finish()
    {
        if (bindings_.size() != encoded_.size())
            throw std::logic_error("BGV operation DMA recipe is incomplete");
        return std::move(bindings_);
    }
private:
    void bind(const std::string& id, hpu::Mnemonic direction, int slot,
              std::uint8_t type, std::uint8_t flag)
    {
        const auto index = bindings_.size();
        if (index >= encoded_.size())
            throw std::logic_error("BGV operation DMA recipe exceeds stream");
        const auto& instruction = encoded_[index];
        const auto& allocation = image_.allocation(id);
        if (instruction.dma_index != index || instruction.direction != direction ||
            instruction.object_id != slot || instruction.type_or_release != type ||
            instruction.flag != flag ||
            (direction == hpu::Mnemonic::kDstore && allocation.read_only))
            throw std::logic_error("BGV DMA binding disagrees with instruction: " + id);
        BgvKeySwitchDmaBinding binding{index, instruction.instruction_index, direction,
            instruction.object_id, type, flag, allocation.id, allocation.span};
        binding.operation_index = operation_index_;
        binding.operation_id = operation_id_;
        binding.operation_dma_index = index;
        bindings_.push_back(std::move(binding));
    }
    const Image& image_;
    const std::vector<hpu::DmaRelocation>& encoded_;
    std::optional<std::size_t> operation_index_;
    std::string operation_id_;
    std::vector<BgvKeySwitchDmaBinding> bindings_;
};

} // namespace

BgvOperationPlan::BgvOperationPlan(const ::seal::SEALContext& context) : context_(context)
{
    if (!context.parameters_set() || !context.key_context_data() ||
        context.key_context_data()->parms().scheme() != ::seal::scheme_type::bgv)
        throw std::invalid_argument("BGV plan requires a valid BGV context");
    narrow(context.key_context_data()->parms().plain_modulus().value());
}

BgvOperationPlan::BgvOperationPlan(const ::seal::SEALContext& context,
                                   const ::seal::Ciphertext& input)
    : BgvOperationPlan(context)
{ add_ciphertext("input", input); }

BgvPlannedValue BgvOperationPlan::add_ciphertext(std::string id,
                                                 const ::seal::Ciphertext& input)
{
    require_value_id(id);
    if (!::seal::is_valid_for(input, context_) || !input.is_ntt_form() ||
        (input.size() != 2 && input.size() != 3))
        throw std::invalid_argument("BGV input must be a valid two/three-component NTT ciphertext");
    for (const auto& record : values_)
        if (record.value.id == id) throw std::invalid_argument("BGV value id is duplicated");
    std::shared_ptr<const ::seal::Ciphertext> captured;
    for (const auto& record : values_)
        if (record.imported && same_ciphertext(*record.imported, input)) {
            captured = record.imported;
            break;
        }
    if (!captured) captured = std::make_shared<const ::seal::Ciphertext>(input);
    BgvPlannedValue value;
    value.id = std::move(id);
    value.parms_id = input.parms_id();
    value.correction_factor = input.correction_factor();
    value.component_count = input.size();
    value.owner_ = owner_;
    value.index_ = values_.size();
    values_.push_back({value, std::move(captured)});
    return value;
}

void BgvOperationPlan::validate_value(const BgvPlannedValue& value,
                                       std::size_t components) const
{
    if (value.owner_ != owner_ || value.index_ >= values_.size())
        throw std::invalid_argument("BGV value belongs to a different plan");
    const auto& known = values_[value.index_].value;
    if (value.id != known.id || value.parms_id != known.parms_id ||
        value.correction_factor != known.correction_factor ||
        value.component_count != known.component_count ||
        (components && value.component_count != components))
        throw std::invalid_argument("BGV value metadata or component count is invalid");
}

const BgvPlannedValue& BgvOperationPlan::input() const
{
    if (values_.empty() || !values_.front().imported)
        throw std::logic_error("BGV plan has no imported input");
    return values_.front().value;
}
const BgvPlannedValue& BgvOperationPlan::tail() const
{ return steps_.empty() ? input() : steps_.back().output; }
const BgvPlannedValue& BgvOperationPlan::final_output() const
{
    if (steps_.empty()) throw std::logic_error("BGV plan has no steps");
    return values_.at(output_index_).value;
}
void BgvOperationPlan::set_output(const BgvPlannedValue& output)
{
    validate_value(output, 0);
    if (values_[output.index_].imported)
        throw std::invalid_argument("BGV final output must be produced by an operation");
    output_index_ = output.index_;
    explicit_output_ = true;
}
std::string BgvOperationPlan::allocation_prefix(const BgvPlannedValue& value) const
{
    validate_value(value, 0);
    return !steps_.empty() && value.index_ == output_index_ ? "output" : value.id;
}

void BgvOperationPlan::require_step_id(const std::string& id) const
{
    if (id.empty() || (id.front() != '_' && !std::isalpha(static_cast<unsigned char>(id.front()))))
        throw std::invalid_argument("BGV step id is invalid");
    for (unsigned char c : id)
        if (c != '_' && !std::isalnum(c)) throw std::invalid_argument("BGV step id must be alphanumeric");
    for (const auto& step : steps_)
        if (step.id == id) throw std::invalid_argument("BGV step id is duplicated");
}

BgvPlannedValue BgvOperationPlan::commit(BgvOperationStep step, std::string output_id,
    ::seal::parms_id_type parms_id, std::uint64_t factor, std::size_t components)
{
    if (output_id.empty()) output_id = "steps/" + step.id + "/output";
    require_value_id(output_id);
    for (const auto& record : values_)
        if (record.value.id == output_id) throw std::invalid_argument("BGV value id is duplicated");
    BgvPlannedValue output;
    output.id = std::move(output_id);
    output.parms_id = parms_id;
    output.correction_factor = factor;
    output.component_count = components;
    output.index_ = values_.size();
    output.owner_ = owner_;
    step.output = output;
    values_.push_back({output, {}});
    steps_.push_back(std::move(step));
    if (!explicit_output_) output_index_ = output.index_;
    return output;
}

std::shared_ptr<const ::seal::RelinKeys> BgvOperationPlan::share_keys(const ::seal::RelinKeys& keys)
{ return intern_keys(keys, relin_keys_); }
std::shared_ptr<const ::seal::GaloisKeys> BgvOperationPlan::share_keys(const ::seal::GaloisKeys& keys)
{ return intern_keys(keys, galois_keys_); }

BgvPlannedValue BgvOperationPlan::append_plain(std::string id, Kind kind,
    const BgvPlannedValue& input, const ::seal::Plaintext& plain, std::string output_id)
{
    require_step_id(id);
    validate_value(input, 2);
    if (!::seal::is_valid_for(plain, context_) || plain.is_ntt_form())
        throw std::invalid_argument("BGV plan plaintext is invalid");
    std::shared_ptr<const ::seal::Plaintext> captured;
    for (const auto& existing : plaintexts_)
        if (plain.coeff_count() == existing->coeff_count() &&
            (plain.coeff_count() == 0 || std::equal(
                plain.data(), plain.data() + plain.coeff_count(), existing->data()))) {
            captured = existing;
            break;
        }
    if (!captured) {
        captured = std::make_shared<const ::seal::Plaintext>(plain);
        plaintexts_.push_back(captured);
    }
    BgvOperationStep step;
    step.id = std::move(id); step.kind = kind; step.inputs = {input}; step.plaintext = captured;
    return commit(std::move(step), std::move(output_id), input.parms_id, input.correction_factor, 2);
}

BgvPlannedValue BgvOperationPlan::append_binary(std::string id, Kind kind,
    const BgvPlannedValue& left, const BgvPlannedValue& right, std::string output_id)
{
    require_step_id(id); validate_value(left, 2); validate_value(right, 2);
    if (left.parms_id != right.parms_id)
        throw std::invalid_argument("BGV binary operands must have matching levels");
    const auto t = narrow(context_.key_context_data()->parms().plain_modulus().value());
    const auto factor = kind == Kind::multiply_tensor
        ? hpu::scheme::bgv::multiply_correction_factor(left.correction_factor, right.correction_factor, t)
        : hpu::scheme::bgv::balance_correction_factors(left.correction_factor, right.correction_factor, t).output_factor;
    BgvOperationStep step;
    step.id = std::move(id); step.kind = kind; step.inputs = {left, right};
    return commit(std::move(step), std::move(output_id), left.parms_id, factor,
                  kind == Kind::multiply_tensor ? 3 : 2);
}

BgvPlannedValue BgvOperationPlan::append_add_plain(std::string id, const BgvPlannedValue& x,
    const ::seal::Plaintext& p, std::string out)
{ return append_plain(std::move(id), Kind::add, x, p, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_subtract_plain(std::string id, const BgvPlannedValue& x,
    const ::seal::Plaintext& p, std::string out)
{ return append_plain(std::move(id), Kind::subtract, x, p, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_multiply_plain(std::string id, const BgvPlannedValue& x,
    const ::seal::Plaintext& p, std::string out)
{ return append_plain(std::move(id), Kind::multiply, x, p, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_add(std::string id, const BgvPlannedValue& a,
    const BgvPlannedValue& b, std::string out)
{ return append_binary(std::move(id), Kind::add_ciphertext, a, b, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_subtract(std::string id, const BgvPlannedValue& a,
    const BgvPlannedValue& b, std::string out)
{ return append_binary(std::move(id), Kind::subtract_ciphertext, a, b, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_multiply(std::string id, const BgvPlannedValue& a,
    const BgvPlannedValue& b, std::string out)
{ return append_binary(std::move(id), Kind::multiply_tensor, a, b, std::move(out)); }

BgvPlannedValue BgvOperationPlan::append_relinearize(std::string id, const BgvPlannedValue& tensor,
    const ::seal::RelinKeys& keys, std::string output_id)
{
    require_step_id(id); validate_value(tensor, 3);
    if (!::seal::is_valid_for(keys, context_) || !keys.has_key(2))
        throw std::invalid_argument("BGV relinearization key is invalid or missing");
    BgvOperationStep step;
    step.id = std::move(id); step.kind = Kind::relinearize; step.inputs = {tensor};
    step.relin_keys = share_keys(keys);
    return commit(std::move(step), std::move(output_id), tensor.parms_id, tensor.correction_factor, 2);
}

BgvPlannedValue BgvOperationPlan::append_multiply_relinearize(std::string id,
    const BgvPlannedValue& a, const BgvPlannedValue& b, const ::seal::RelinKeys& keys,
    std::string output_id)
{
    require_step_id(id); validate_value(a, 2); validate_value(b, 2);
    if (a.parms_id != b.parms_id || !::seal::is_valid_for(keys, context_) || !keys.has_key(2))
        throw std::invalid_argument("BGV fused multiply requires matching levels and relinearization key");
    BgvOperationStep step;
    step.id = std::move(id); step.kind = Kind::multiply_ciphertext; step.inputs = {a, b};
    step.relin_keys = share_keys(keys);
    const auto factor = hpu::scheme::bgv::multiply_correction_factor(a.correction_factor,
        b.correction_factor, context_.key_context_data()->parms().plain_modulus().value());
    return commit(std::move(step), std::move(output_id), a.parms_id, factor, 2);
}

BgvPlannedValue BgvOperationPlan::append_rotation(std::string id, Kind kind,
    const BgvPlannedValue& input, int steps, const ::seal::GaloisKeys& keys, std::string output_id)
{
    require_step_id(id); validate_value(input, 2);
    const auto source = context_.get_context_data(input.parms_id);
    if (!source->qualifiers().using_batching || !::seal::is_valid_for(keys, context_))
        throw std::invalid_argument("BGV rotation requires batching and matching Galois keys");
    const auto degree = source->parms().poly_modulus_degree();
    const auto element = kind == Kind::rotate_rows
        ? hpu::scheme::bfv::row_rotation_galois_element(degree, steps)
        : hpu::scheme::bfv::column_rotation_galois_element(degree);
    if (!keys.has_key(element)) throw std::invalid_argument("BGV rotation Galois key is missing");
    BgvOperationStep step;
    step.id = std::move(id); step.kind = kind; step.inputs = {input};
    step.rotation_steps = steps; step.galois_keys = share_keys(keys);
    return commit(std::move(step), std::move(output_id), input.parms_id, input.correction_factor, 2);
}
BgvPlannedValue BgvOperationPlan::append_rotate_rows(std::string id, const BgvPlannedValue& x,
    int steps, const ::seal::GaloisKeys& keys, std::string out)
{ return append_rotation(std::move(id), Kind::rotate_rows, x, steps, keys, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_rotate_columns(std::string id, const BgvPlannedValue& x,
    const ::seal::GaloisKeys& keys, std::string out)
{ return append_rotation(std::move(id), Kind::rotate_columns, x, 0, keys, std::move(out)); }
BgvPlannedValue BgvOperationPlan::append_modswitch_to_next(std::string id,
    const BgvPlannedValue& input, std::string output_id)
{
    require_step_id(id); validate_value(input, 2);
    const auto source = context_.get_context_data(input.parms_id);
    if (!source->next_context_data()) throw std::invalid_argument("BGV plan has no next level");
    const auto factor = hpu::scheme::bgv::modswitch_correction_factor(input.correction_factor,
        source->parms().coeff_modulus().back().value(), source->parms().plain_modulus().value());
    BgvOperationStep step;
    step.id = std::move(id); step.kind = Kind::modswitch_to_next; step.inputs = {input};
    return commit(std::move(step), std::move(output_id), source->next_context_data()->parms_id(), factor, 2);
}

void BgvOperationPlan::append_add_plain(std::string id, const ::seal::Plaintext& p)
{ append_add_plain(std::move(id), tail(), p); }
void BgvOperationPlan::append_subtract_plain(std::string id, const ::seal::Plaintext& p)
{ append_subtract_plain(std::move(id), tail(), p); }
void BgvOperationPlan::append_multiply_plain(std::string id, const ::seal::Plaintext& p)
{ append_multiply_plain(std::move(id), tail(), p); }
void BgvOperationPlan::append_add(std::string id, const ::seal::Ciphertext& right)
{
    require_step_id(id); const auto left = tail();
    validate_value(left, 2);
    if (right.parms_id() != left.parms_id || right.size() != 2)
        throw std::invalid_argument("BGV binary operands must have matching levels and two components");
    const auto b = add_ciphertext("steps/" + id + "/right", right);
    append_add(std::move(id), left, b);
}
void BgvOperationPlan::append_subtract(std::string id, const ::seal::Ciphertext& right)
{
    require_step_id(id); const auto left = tail();
    validate_value(left, 2);
    if (right.parms_id() != left.parms_id || right.size() != 2)
        throw std::invalid_argument("BGV binary operands must have matching levels and two components");
    const auto b = add_ciphertext("steps/" + id + "/right", right);
    append_subtract(std::move(id), left, b);
}
void BgvOperationPlan::append_multiply(std::string id, const ::seal::Ciphertext& right,
                                       const ::seal::RelinKeys& keys)
{
    require_step_id(id); const auto left = tail();
    validate_value(left, 2);
    if (right.parms_id() != left.parms_id || right.size() != 2)
        throw std::invalid_argument("BGV binary operands must have matching levels and two components");
    if (!::seal::is_valid_for(keys, context_) || !keys.has_key(2))
        throw std::invalid_argument("BGV relinearization key is invalid or missing");
    const auto b = add_ciphertext("steps/" + id + "/multiply/input/right", right);
    append_multiply_relinearize(std::move(id), left, b, keys);
}
void BgvOperationPlan::append_rotate_rows(std::string id, int steps, const ::seal::GaloisKeys& keys)
{ append_rotate_rows(std::move(id), tail(), steps, keys); }
void BgvOperationPlan::append_rotate_columns(std::string id, const ::seal::GaloisKeys& keys)
{ append_rotate_columns(std::move(id), tail(), keys); }
void BgvOperationPlan::append_modswitch_to_next(std::string id)
{ append_modswitch_to_next(std::move(id), tail()); }
const std::vector<BgvOperationStep>& BgvOperationPlan::steps() const noexcept { return steps_; }

BgvKeySwitchApplication BgvOperationPlan::lower(std::uint64_t capacity_lines) const
{
    if (steps_.empty()) throw std::invalid_argument("BGV plan has no steps");
    const auto key_data = context_.key_context_data();
    const auto first_data = context_.first_context_data();
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto degree = key_data->parms().poly_modulus_degree();
    if (!first_data || key_moduli.size() != first_data->parms().coeff_modulus().size() + 1 ||
        key_moduli.size() + 1 > static_cast<std::size_t>(hpu::kMaxModContexts) ||
        degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree)))
        throw std::invalid_argument("unsupported BGV Qmax|P|t layout");
    const auto t = narrow(key_data->parms().plain_modulus().value());
    Image image(capacity_lines);
    std::vector<std::uint32_t> table;
    const auto append_modulus = [&](std::uint32_t q) {
        const auto mu = static_cast<std::uint64_t>((static_cast<unsigned __int128>(1) << 64) / q);
        table.insert(table.end(), {q, static_cast<std::uint32_t>(mu),
                                   static_cast<std::uint32_t>(mu >> 32U), 0});
    };
    for (const auto& modulus : key_moduli) append_modulus(narrow(modulus.value()));
    append_modulus(t);
    image.add("constants/modulus_table", table, AllocationKind::modulus_table);
    ReadOnlyResources resources(image);
    for (const auto& record : values_) {
        if (!record.imported) continue;
        for (std::size_t c = 0; c < record.value.component_count; ++c) {
            const auto physical = ciphertext_component_to_hpu(*record.imported, c, context_);
            for (std::size_t q = 0; q < physical.moduli.size(); ++q) {
                const auto begin = physical.words.begin() + q * degree;
                resources.add(mod_id(record.value.id + "/c" + std::to_string(c), q),
                              {begin, begin + degree}, AllocationKind::ciphertext);
            }
        }
    }
    std::vector<hpu::EncodedInstruction> instructions;
    std::vector<BgvKeySwitchDmaBinding> bindings;
    const auto append_program = [&](const std::vector<hpu::EncodedInstruction>& body,
                                    std::vector<BgvKeySwitchDmaBinding> dma) {
        const auto base = instructions.size();
        const auto dma_base = bindings.size();
        instructions.insert(instructions.end(), body.begin(), body.end());
        for (auto& binding : dma) {
            binding.instruction_index += base;
            binding.dma_index += dma_base;
            bindings.push_back(std::move(binding));
        }
    };
    {
        const auto body = hpu::assemble_source(hpu::dload(4, hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank));
        const auto encoded = hpu::collect_dma_relocations(body);
        DmaRecipe recipe(image, encoded);
        recipe.load(4, "constants/modulus_table", hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
        append_program(body, recipe.finish());
    }
    ::seal::Evaluator plain_preparer(context_);
    const auto shape = [&](const BgvPlannedValue& value) {
        ::seal::Ciphertext result;
        result.resize(context_, value.parms_id, value.component_count);
        result.is_ntt_form() = true;
        result.correction_factor() = value.correction_factor;
        return result;
    };
    for (std::size_t index = 0; index < steps_.size(); ++index) {
        const auto& step = steps_[index];
        const auto& left = step.inputs.front();
        const auto input_prefix = allocation_prefix(left);
        const auto output_prefix = allocation_prefix(step.output);
        const auto step_prefix = "steps/" + step.id;
        const auto source = context_.get_context_data(left.parms_id);
        const auto q_count = source->parms().coeff_modulus().size();
        for (std::size_t c = 0; c < step.output.component_count; ++c)
            for (std::size_t q = 0; q < context_.get_context_data(step.output.parms_id)->parms().coeff_modulus().size(); ++q)
                image.reserve(mod_id(output_prefix + "/c" + std::to_string(c), q), degree, AllocationKind::output);

        // Compose one operation at a time. Temporary standalone images die at
        // the end of this iteration instead of being retained for the full graph.
        const auto compose = [&](const auto& standalone, const std::string& resource,
                                  const std::vector<std::pair<std::string, std::string>>& remaps) {
            const auto relocate = [&](const std::string& id) {
                if (id == "constants/modulus_table") return id;
                for (const auto& mapping : remaps)
                    if (id.rfind(mapping.first + "/c", 0) == 0)
                        return mapping.second + id.substr(mapping.first.size());
                if (id.rfind("output/c", 0) == 0) return output_prefix + id.substr(6);
                return resource + "/" + id;
            };
            for (const auto& allocation : standalone.image.allocations()) {
                const auto relocated = relocate(allocation.id);
                if (image.contains(relocated) || relocated.rfind(resource + "/", 0) != 0) continue;
                if (allocation.read_only) {
                    const auto begin = standalone.image.words().begin() +
                        allocation.span.line_offset * hpu::runtime::kHpuMemLineWords;
                    resources.add(relocated, {begin, begin + allocation.word_count}, allocation.kind);
                } else image.reserve(relocated, allocation.word_count, allocation.kind);
            }
            const auto& stream = standalone.instructions;
            if (stream.size() < 3 || stream.front().instruction.mnemonic != hpu::Mnemonic::kDload ||
                stream[stream.size() - 2].instruction.mnemonic != hpu::Mnemonic::kPfree ||
                stream[stream.size() - 2].instruction.idx0 != 4 ||
                stream.back().instruction.mnemonic != hpu::Mnemonic::kPsync ||
                standalone.dma.empty() || standalone.dma.front().allocation_id != "constants/modulus_table")
                throw std::logic_error("BGV standalone operation prologue/epilogue changed");
            const std::vector<hpu::EncodedInstruction> body(stream.begin() + 1, stream.end() - 2);
            const auto encoded = hpu::collect_dma_relocations(body);
            DmaRecipe recipe(image, encoded, index, step.id);
            for (std::size_t d = 1; d < standalone.dma.size(); ++d)
                recipe.replay(standalone.dma[d], relocate(standalone.dma[d].allocation_id));
            append_program(body, recipe.finish());
        };
        if (step.kind == Kind::rotate_rows || step.kind == Kind::rotate_columns) {
            const auto capacity = estimate_bgv_rotation_image_lines(degree, q_count, key_moduli.size());
            const auto application = step.kind == Kind::rotate_rows
                ? build_bgv_rotate_rows_application(context_, shape(left), *step.galois_keys, step.rotation_steps, capacity)
                : build_bgv_rotate_columns_application(context_, shape(left), *step.galois_keys, capacity);
            compose(application, step_prefix + "/rotation", {{"input/original", input_prefix}});
            continue;
        }
        if (step.kind == Kind::multiply_ciphertext) {
            const auto capacity = estimate_bgv_multiply_relinearize_image_lines(degree, q_count, key_moduli.size());
            const auto application = build_bgv_multiply_relinearize_application(
                context_, shape(left), shape(step.inputs[1]), *step.relin_keys, capacity);
            compose(application, step_prefix + "/multiply", {{"input/left", input_prefix},
                {"input/right", allocation_prefix(step.inputs[1])}});
            continue;
        }
        if (step.kind == Kind::relinearize) {
            const auto capacity = estimate_bgv_keyswitch_image_lines(degree, q_count, key_moduli.size());
            const auto application = build_bgv_keyswitch_application(context_, shape(left), *step.relin_keys, capacity);
            compose(application, step_prefix + "/relinearize", {{"input", input_prefix}});
            continue;
        }
        if (step.kind == Kind::modswitch_to_next) {
            const auto application = build_bgv_modswitch_application(context_, shape(left), capacity_lines);
            compose(application, step_prefix + "/modswitch", {{"input", input_prefix}});
            continue;
        }
        std::string assembly;
        hpu::scheme::bgv::CorrectionBalance balance{};
        const bool binary = step.kind == Kind::add_ciphertext || step.kind == Kind::subtract_ciphertext;
        if (binary) {
            balance = hpu::scheme::bgv::balance_correction_factors(left.correction_factor,
                step.inputs[1].correction_factor, t);
            for (std::size_t q = 0; q < q_count; ++q) {
                const auto modulus = narrow(source->parms().coeff_modulus()[q].value());
                if (balance.left_scalar != 1) resources.add(mod_id(step_prefix + "/balance/left", q),
                    std::vector<std::uint32_t>(degree, balance.left_scalar % modulus), AllocationKind::constant);
                if (balance.right_scalar != 1) resources.add(mod_id(step_prefix + "/balance/right", q),
                    std::vector<std::uint32_t>(degree, balance.right_scalar % modulus), AllocationKind::constant);
            }
            assembly = step.kind == Kind::add_ciphertext
                ? hpu::scheme::bgv::generate_add_body_asm(q_count, balance, false, false)
                : hpu::scheme::bgv::generate_subtract_body_asm(q_count, balance, false, false);
        } else if (step.kind == Kind::multiply_tensor) {
            assembly = generate_hpu_cmult_body_asm(q_count, false, false);
        } else {
            auto plain = *step.plaintext;
            if (step.kind != Kind::multiply)
                for (std::size_t c = 0; c < plain.coeff_count(); ++c)
                    plain[c] = (static_cast<unsigned __int128>(plain[c]) * left.correction_factor) % t;
            plain_preparer.transform_to_ntt_inplace(plain, left.parms_id);
            const auto physical = plaintext_to_hpu(plain, context_);
            for (std::size_t q = 0; q < q_count; ++q) {
                const auto begin = physical.words.begin() + q * degree;
                resources.add(mod_id(step_prefix + "/plain", q), {begin, begin + degree}, AllocationKind::plaintext);
            }
            if (step.kind == Kind::add) assembly = hpu::scheme::ckks::generate_add_plain_body_asm(q_count, false, false);
            else if (step.kind == Kind::subtract) assembly = hpu::scheme::ckks::generate_subtract_plain_body_asm(q_count, false, false);
            else assembly = hpu::scheme::ckks::generate_multiply_plain_body_asm(q_count, false, false);
        }
        const auto body = hpu::assemble_source(assembly);
        const auto encoded = hpu::collect_dma_relocations(body);
        DmaRecipe recipe(image, encoded, index, step.id);
        if (binary) {
            const auto right_prefix = allocation_prefix(step.inputs[1]);
            for (std::size_t c = 0; c < 2; ++c) for (std::size_t q = 0; q < q_count; ++q) {
                const auto suffix = "/c" + std::to_string(c);
                recipe.load(0, mod_id(input_prefix + suffix, q));
                if (balance.left_scalar != 1) recipe.load(3, mod_id(step_prefix + "/balance/left", q));
                recipe.load(1, mod_id(right_prefix + suffix, q));
                if (balance.right_scalar != 1) recipe.load(3, mod_id(step_prefix + "/balance/right", q));
                recipe.store(2, mod_id(output_prefix + suffix, q));
            }
        } else if (step.kind == Kind::multiply_tensor) {
            const auto right_prefix = allocation_prefix(step.inputs[1]);
            for (std::size_t q = 0; q < q_count; ++q) {
                recipe.load(0, mod_id(input_prefix + "/c0", q)); recipe.load(1, mod_id(right_prefix + "/c0", q));
                recipe.store(2, mod_id(output_prefix + "/c0", q));
                recipe.load(0, mod_id(input_prefix + "/c0", q)); recipe.load(1, mod_id(right_prefix + "/c1", q));
                recipe.load(0, mod_id(input_prefix + "/c1", q)); recipe.load(1, mod_id(right_prefix + "/c0", q));
                recipe.store(2, mod_id(output_prefix + "/c1", q));
                recipe.load(0, mod_id(input_prefix + "/c1", q)); recipe.load(1, mod_id(right_prefix + "/c1", q));
                recipe.store(2, mod_id(output_prefix + "/c2", q));
            }
        } else {
            for (std::size_t q = 0; q < q_count; ++q) {
                recipe.load(0, mod_id(input_prefix + "/c0", q)); recipe.load(1, mod_id(step_prefix + "/plain", q));
                recipe.store(2, mod_id(output_prefix + "/c0", q));
                recipe.load(0, mod_id(input_prefix + "/c1", q));
                recipe.store(step.kind == Kind::multiply ? 2 : 0, mod_id(output_prefix + "/c1", q));
            }
        }
        append_program(body, recipe.finish());
    }
    const auto ending = hpu::assemble_source(hpu::pfree(4) + hpu::psync());
    append_program(ending, {});
    hpu::validate_executable_program(instructions);
    image.trim_capacity_to_used_lines();
    const auto& output = final_output();
    return {std::move(image), output.parms_id, output.correction_factor,
            std::move(instructions), std::move(bindings)};
}

} // namespace hpu::seal_adapter
