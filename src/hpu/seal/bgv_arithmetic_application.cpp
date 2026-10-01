#include "hpu/seal/bgv_arithmetic_application.hpp"

#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"
#include "scheme/ckks/basic_arithmetic.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include "assembler.hpp"
#include "executable.hpp"

#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

enum class Operation { add, subtract, negate, add_plain, subtract_plain, multiply_plain };

bool is_plain(Operation operation)
{
    return operation == Operation::add_plain ||
           operation == Operation::subtract_plain ||
           operation == Operation::multiply_plain;
}

std::uint32_t narrow(std::uint64_t value)
{
    if (value < 65537 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("BGV arithmetic modulus is outside the HPU PE range");
    }
    return static_cast<std::uint32_t>(value);
}

std::string mod_id(const std::string& prefix, std::size_t basis)
{
    return prefix + "/mod" + std::to_string(basis);
}

std::uint64_t barrett_mu(std::uint32_t modulus)
{
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(1) << 64) / modulus);
}

void add_component(hpu::runtime::HpuMemImage& image,
                   const ::seal::Ciphertext& ciphertext,
                   const ::seal::SEALContext& context,
                   const std::string& prefix,
                   std::size_t component, std::size_t q_count,
                   std::size_t degree)
{
    const auto converted = ciphertext_component_to_hpu(
        ciphertext, component, context);
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto first = converted.words.begin() +
            static_cast<std::ptrdiff_t>(basis * degree);
        image.add(mod_id(prefix + "/c" + std::to_string(component), basis),
                  std::vector<std::uint32_t>(first, first + degree),
                  hpu::runtime::AllocationKind::ciphertext);
    }
}

void add_plaintext(hpu::runtime::HpuMemImage& image,
                   const ::seal::Plaintext& plaintext,
                   const ::seal::Ciphertext& ciphertext,
                   const ::seal::SEALContext& context,
                   Operation operation, std::size_t q_count,
                   std::size_t degree)
{
    if (!::seal::is_valid_for(plaintext, context) || plaintext.is_ntt_form() ||
        plaintext.coeff_count() > degree) {
        throw std::invalid_argument("BGV plaintext must be valid coefficient-domain input");
    }
    ::seal::Plaintext prepared = plaintext;
    if (operation != Operation::multiply_plain) {
        const auto t = context.get_context_data(ciphertext.parms_id())
            ->parms().plain_modulus().value();
        for (std::size_t index = 0; index < prepared.coeff_count(); ++index) {
            prepared[index] = static_cast<std::uint64_t>(
                (static_cast<unsigned __int128>(prepared[index]) *
                 ciphertext.correction_factor()) % t);
        }
    }
    ::seal::Evaluator evaluator(context);
    evaluator.transform_to_ntt_inplace(prepared, ciphertext.parms_id());
    const auto converted = plaintext_to_hpu(prepared, context);
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto first = converted.words.begin() +
            static_cast<std::ptrdiff_t>(basis * degree);
        image.add(mod_id("input/plain", basis),
                  std::vector<std::uint32_t>(first, first + degree),
                  hpu::runtime::AllocationKind::plaintext);
    }
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

    std::vector<BgvKeySwitchDmaBinding> finish()
    {
        if (bindings_.size() != encoded_.size()) {
            throw std::logic_error("BGV arithmetic DMA recipe is incomplete");
        }
        return std::move(bindings_);
    }

private:
    void bind(const std::string& id, hpu::Mnemonic direction,
              int slot, std::uint8_t type_or_release, std::uint8_t flag)
    {
        const std::size_t index = bindings_.size();
        if (index >= encoded_.size()) {
            throw std::logic_error("BGV arithmetic DMA recipe exceeds encoded stream");
        }
        const auto& instruction = encoded_[index];
        const auto& allocation = image_.allocation(id);
        if (instruction.dma_index != index ||
            instruction.direction != direction ||
            instruction.object_id != slot ||
            instruction.type_or_release != type_or_release ||
            instruction.flag != flag ||
            allocation.span.line_count == 0 ||
            (direction == hpu::Mnemonic::kDstore && allocation.read_only)) {
            throw std::invalid_argument(
                "BGV arithmetic DMA binding disagrees with encoded instruction: " + id);
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

BgvArithmeticApplication build(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& left,
    const ::seal::Ciphertext* right, const ::seal::Plaintext* plaintext,
    Operation operation,
    std::uint64_t capacity_lines)
{
    const auto source = context.get_context_data(left.parms_id());
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    if (!source || !key_data || !first_data ||
        source->parms().scheme() != ::seal::scheme_type::bgv ||
        !::seal::is_valid_for(left, context) || !left.is_ntt_form() ||
        left.size() != 2 ||
        (is_plain(operation) ? !plaintext : operation != Operation::negate &&
         (!right || !::seal::is_valid_for(*right, context) ||
          !right->is_ntt_form() || right->size() != 2 ||
          right->parms_id() != left.parms_id()))) {
        throw std::invalid_argument("BGV arithmetic requires matching two-component NTT ciphertexts");
    }
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& top_moduli = first_data->parms().coeff_modulus();
    const auto& q_moduli = source->parms().coeff_modulus();
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = q_moduli.size();
    if (key_moduli.size() != top_moduli.size() + 1 ||
        key_moduli.size() + 1 > static_cast<std::size_t>(hpu::kMaxModContexts) ||
        q_count == 0 || q_count > top_moduli.size() ||
        degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree))) {
        throw std::invalid_argument("unsupported BGV arithmetic Qmax|P|t layout");
    }
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        if (q_moduli[basis].value() != key_moduli[basis].value()) {
            throw std::invalid_argument("BGV arithmetic active Q is not a key-context prefix");
        }
    }
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    const auto balance = operation == Operation::negate || is_plain(operation)
        ? hpu::scheme::bgv::CorrectionBalance{
            static_cast<std::uint32_t>(left.correction_factor()), 1, 1}
        : hpu::scheme::bgv::balance_correction_factors(
            static_cast<std::uint32_t>(left.correction_factor()),
            static_cast<std::uint32_t>(right->correction_factor()), t);

    hpu::runtime::HpuMemImage image(capacity_lines);
    std::vector<std::uint32_t> table;
    for (const auto& modulus : key_moduli) {
        const std::uint32_t value = narrow(modulus.value());
        const std::uint64_t mu = barrett_mu(value);
        table.insert(table.end(), {value, static_cast<std::uint32_t>(mu),
                                   static_cast<std::uint32_t>(mu >> 32U), 0});
    }
    const std::uint64_t mu_t = barrett_mu(t);
    table.insert(table.end(), {t, static_cast<std::uint32_t>(mu_t),
                               static_cast<std::uint32_t>(mu_t >> 32U), 0});
    image.add("constants/modulus_table", table,
              hpu::runtime::AllocationKind::modulus_table);
    for (std::size_t component = 0; component < 2; ++component) {
        add_component(image, left, context, "input/left", component,
                      q_count, degree);
        if (right && !is_plain(operation)) {
            add_component(image, *right, context, "input/right", component,
                          q_count, degree);
        }
    }
    if (is_plain(operation)) {
        add_plaintext(image, *plaintext, left, context, operation, q_count, degree);
    }
    if (operation != Operation::negate) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto q = narrow(q_moduli[basis].value());
            if (balance.left_scalar != 1) {
                image.add(mod_id("constants/bgv_balance/left", basis),
                          std::vector<std::uint32_t>(degree, balance.left_scalar % q),
                          hpu::runtime::AllocationKind::constant);
            }
            if (balance.right_scalar != 1) {
                image.add(mod_id("constants/bgv_balance/right", basis),
                          std::vector<std::uint32_t>(degree, balance.right_scalar % q),
                          hpu::runtime::AllocationKind::constant);
            }
        }
    }
    for (std::size_t component = 0; component < 2; ++component) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            image.reserve(mod_id("output/c" + std::to_string(component), basis),
                          degree, hpu::runtime::AllocationKind::output);
        }
    }
    std::string body;
    if (operation == Operation::negate) {
        body = hpu::scheme::bgv::generate_negate_body_asm(
            static_cast<int>(q_count), true, true);
    } else if (operation == Operation::add_plain) {
        body = hpu::scheme::ckks::generate_add_plain_body_asm(
            static_cast<int>(q_count), true, true);
    } else if (operation == Operation::subtract_plain) {
        body = hpu::scheme::ckks::generate_subtract_plain_body_asm(
            static_cast<int>(q_count), true, true);
    } else if (operation == Operation::multiply_plain) {
        body = hpu::scheme::ckks::generate_multiply_plain_body_asm(
            static_cast<int>(q_count), true, true);
    } else if (operation == Operation::add) {
        body = hpu::scheme::bgv::generate_add_body_asm(
            static_cast<int>(q_count), balance, true, true);
    } else {
        body = hpu::scheme::bgv::generate_subtract_body_asm(
            static_cast<int>(q_count), balance, true, true);
    }
    auto instructions = hpu::assemble_source(body);
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(image, encoded_dma);
    recipe.load(4, "constants/modulus_table", hpu::DataType::mod_ctx,
                hpu::DloadFlag::small_bank);
    if (is_plain(operation)) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            recipe.load(0, mod_id("input/left/c0", basis));
            recipe.load(1, mod_id("input/plain", basis));
            recipe.store(2, mod_id("output/c0", basis));
            recipe.load(0, mod_id("input/left/c1", basis));
            if (operation == Operation::multiply_plain) {
                recipe.store(2, mod_id("output/c1", basis));
            } else {
                recipe.store(0, mod_id("output/c1", basis));
            }
        }
    } else for (std::size_t component = 0; component < 2; ++component) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            recipe.load(0, mod_id("input/left/c" + std::to_string(component), basis));
            if (operation != Operation::negate) {
                if (balance.left_scalar != 1) {
                    recipe.load(3, mod_id("constants/bgv_balance/left", basis));
                }
                recipe.load(1, mod_id("input/right/c" + std::to_string(component), basis));
                if (balance.right_scalar != 1) {
                    recipe.load(3, mod_id("constants/bgv_balance/right", basis));
                }
            }
            recipe.store(2, mod_id("output/c" + std::to_string(component), basis));
        }
    }
    auto bindings = recipe.finish();
    return {std::move(image), left.parms_id(), balance.output_factor,
            std::move(instructions), std::move(bindings)};
}

} // namespace

BgvArithmeticApplication build_bgv_add_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& left,
    const ::seal::Ciphertext& right, std::uint64_t capacity_lines)
{
    return build(context, left, &right, nullptr, Operation::add, capacity_lines);
}

BgvArithmeticApplication build_bgv_subtract_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& left,
    const ::seal::Ciphertext& right, std::uint64_t capacity_lines)
{
    return build(context, left, &right, nullptr, Operation::subtract, capacity_lines);
}

BgvArithmeticApplication build_bgv_negate_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input,
    std::uint64_t capacity_lines)
{
    return build(context, input, nullptr, nullptr, Operation::negate, capacity_lines);
}

BgvArithmeticApplication build_bgv_add_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines)
{
    return build(context, ciphertext, nullptr, &plaintext,
                 Operation::add_plain, capacity_lines);
}

BgvArithmeticApplication build_bgv_subtract_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines)
{
    return build(context, ciphertext, nullptr, &plaintext,
                 Operation::subtract_plain, capacity_lines);
}

BgvArithmeticApplication build_bgv_multiply_plain_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& ciphertext,
    const ::seal::Plaintext& plaintext, std::uint64_t capacity_lines)
{
    return build(context, ciphertext, nullptr, &plaintext,
                 Operation::multiply_plain, capacity_lines);
}

BgvArithmeticRuntimeArtifacts render_bgv_arithmetic_runtime_artifacts(
    const std::string& stem, const BgvArithmeticApplication& application)
{
    return render_bgv_keyswitch_runtime_artifacts(stem, application);
}

} // namespace hpu::seal_adapter
