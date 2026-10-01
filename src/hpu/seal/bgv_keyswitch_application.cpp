#include "hpu/seal/bgv_keyswitch_application.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/automorphism.hpp"
#include "hpu/seal/ntt_bridge.hpp"
#include "scheme/bfv/galois.hpp"
#include "scheme/bgv/keyswitch.hpp"
#include "scheme/bgv/ciphertext_multiply.hpp"
#include "scheme/bgv/modswitch.hpp"
#include "util/hpu_asm.hpp"
#include "util/ntt.hpp"
#include "util/validation.hpp"

#include "assembler.hpp"
#include "executable.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(std::uint64_t value)
{
    if (value < 65537 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument("BGV KeySwitch modulus is outside the HPU PE range");
    }
    return static_cast<std::uint32_t>(value);
}

std::uint64_t barrett_mu(std::uint32_t modulus)
{
    return static_cast<std::uint64_t>(
        (static_cast<unsigned __int128>(1) << 64) / modulus);
}

std::size_t bit_reverse(std::size_t value, std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t width = degree; width > 1; width >>= 1U) {
        result = (result << 1U) | (value & 1U);
        value >>= 1U;
    }
    return result;
}

std::string mod_id(const std::string& prefix, std::size_t id)
{
    return prefix + "/mod" + std::to_string(id);
}

std::string stage_id(const std::string& prefix, std::size_t stage)
{
    return prefix + "/stage" + std::to_string(stage);
}

std::vector<std::uint32_t> splat(std::size_t degree, std::uint32_t value)
{
    return std::vector<std::uint32_t>(degree, value);
}

std::size_t ntt_stage_count(std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t remaining = degree; remaining > 1; remaining >>= 1U) {
        ++result;
    }
    return result;
}

void add_twiddles(hpu::runtime::HpuMemImage& image, std::size_t degree,
                  std::size_t modulus_id, std::uint32_t modulus, std::uint32_t psi)
{
    const std::string prefix = mod_id("constants/twiddle/canonical", modulus_id);
    hpu::model::HardwareNttModel model(
        degree, modulus, hpu::model::pow_mod(psi, 2, modulus));
    std::vector<std::uint32_t> pre_twist(degree);
    for (std::size_t index = 0; index < degree; ++index) {
        pre_twist[index] = hpu::model::pow_mod(
            psi, bit_reverse(index, degree), modulus);
    }
    image.add(prefix + "/ntt/pre_twist", pre_twist,
              hpu::runtime::AllocationKind::twiddle);
    const auto forward = model.forward_twiddles();
    for (std::size_t stage = 0; stage < forward.size(); ++stage) {
        image.add(stage_id(prefix + "/ntt", stage), forward[stage],
                  hpu::runtime::AllocationKind::twiddle);
    }
    const auto inverse = model.inverse_twiddles();
    for (std::size_t stage = 0; stage < inverse.stages.size(); ++stage) {
        image.add(stage_id(prefix + "/intt", stage), inverse.stages[stage],
                  hpu::runtime::AllocationKind::twiddle);
    }
    const std::uint32_t inverse_psi = hpu::model::inverse_mod_prime(psi, modulus);
    std::vector<std::uint32_t> post(degree);
    for (std::size_t index = 0; index < degree; ++index) {
        const std::uint32_t untwist = hpu::model::pow_mod(
            inverse_psi, bit_reverse(index, degree), modulus);
        post[index] = static_cast<std::uint32_t>(
            (static_cast<std::uint64_t>(inverse.post_scale[index]) * untwist) % modulus);
    }
    image.add(prefix + "/intt/post_untwist_scale", post,
              hpu::runtime::AllocationKind::twiddle);
}

void add_galois_twiddles(hpu::runtime::HpuMemImage& image,
                         const std::vector<FusedInverseAutomorphismTables>& tables)
{
    for (std::size_t basis = 0; basis < tables.size(); ++basis) {
        const auto prefix = mod_id("constants/twiddle/galois", basis) + "/intt";
        for (std::size_t stage = 0; stage < tables[basis].stages.size(); ++stage) {
            image.add(stage_id(prefix, stage), tables[basis].stages[stage],
                      hpu::runtime::AllocationKind::twiddle);
        }
        image.add(prefix + "/post_untwist_scale",
                  tables[basis].post_untwist_scale,
                  hpu::runtime::AllocationKind::twiddle);
    }
}

class DmaRecipe {
public:
    DmaRecipe(const hpu::runtime::HpuMemImage& image,
              const std::vector<hpu::DmaRelocation>& encoded)
        : image_(image), encoded_(encoded)
    {}

    void load(int slot, const std::string& id, std::size_t words,
              hpu::DataType type = hpu::DataType::poly,
              hpu::DloadFlag flag = hpu::DloadFlag::regular_bank)
    {
        bind(id, words, hpu::Mnemonic::kDload, slot,
             static_cast<std::uint8_t>(type), static_cast<std::uint8_t>(flag));
    }

    void store(int slot, const std::string& id, std::size_t words)
    {
        bind(id, words, hpu::Mnemonic::kDstore, slot, 1, 0);
    }

    void replay(const BgvKeySwitchDmaBinding& binding)
    {
        const auto& allocation = image_.allocation(binding.allocation_id);
        bind(binding.allocation_id, allocation.word_count, binding.direction,
             binding.object_slot, binding.type_or_release, binding.flag);
    }

    std::vector<BgvKeySwitchDmaBinding> finish()
    {
        if (bindings_.size() != encoded_.size()) {
            throw std::logic_error("BGV KeySwitch DMA recipe did not consume every instruction");
        }
        return std::move(bindings_);
    }

private:
    void bind(const std::string& id, std::size_t words, hpu::Mnemonic direction,
              int slot, std::uint8_t type_or_release, std::uint8_t flag)
    {
        const std::size_t index = bindings_.size();
        if (index >= encoded_.size()) {
            throw std::logic_error("BGV KeySwitch DMA recipe exceeds encoded stream");
        }
        const auto& instruction = encoded_[index];
        const auto& allocation = image_.allocation(id);
        if (instruction.dma_index != index || instruction.direction != direction ||
            instruction.object_id != slot ||
            instruction.type_or_release != type_or_release ||
            (direction == hpu::Mnemonic::kDload && instruction.flag != flag) ||
            allocation.word_count != words || allocation.span.line_count == 0 ||
            (direction == hpu::Mnemonic::kDstore && allocation.read_only)) {
            throw std::invalid_argument(
                "BGV KeySwitch DMA binding disagrees with encoded instruction or image: " + id);
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

std::string csv_field(const std::string& value)
{
    std::string result = "\"";
    for (char character : value) {
        if (character == '"') result += '"';
        result += character;
    }
    return result + '"';
}

} // namespace

std::vector<hpu::runtime::HpuMemSpan> BgvKeySwitchApplication::spans() const
{
    std::vector<hpu::runtime::HpuMemSpan> result;
    result.reserve(dma.size());
    for (const auto& binding : dma) result.push_back(binding.span);
    return result;
}

std::uint64_t estimate_bgv_keyswitch_image_lines(
    std::size_t degree, std::size_t active_q_count,
    std::size_t key_modulus_count)
{
    if (degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree)) ||
        active_q_count == 0 || key_modulus_count < 2 ||
        active_q_count >= key_modulus_count ||
        key_modulus_count + 1 > static_cast<std::size_t>(hpu::kMaxModContexts)) {
        throw std::invalid_argument("unsupported BGV KeySwitch image dimensions");
    }
    const std::uint64_t q = active_q_count;
    const std::uint64_t polynomial_lines = degree / hpu::runtime::kHpuMemLineWords;
    const std::uint64_t stage_lines = degree / (2 * hpu::runtime::kHpuMemLineWords);
    const std::uint64_t stages = ntt_stage_count(degree);
    const std::uint64_t twiddle_lines_per_modulus =
        2 * polynomial_lines + 2 * stages * stage_lines;
    // Constants: 1+2q; input: 3q; source scratch: q; keys: 2q(q+1);
    // accumulators: 2(q+1); P correction scratch: 4; outputs: 2q.
    const std::uint64_t resident_polynomials = 7 + 12 * q + 2 * q * q;
    const std::uint64_t modulus_table_lines =
        (4 * (key_modulus_count + 1) + hpu::runtime::kHpuMemLineWords - 1) /
        hpu::runtime::kHpuMemLineWords;
    return modulus_table_lines + (q + 1) * twiddle_lines_per_modulus +
           resident_polynomials * polynomial_lines;
}

std::uint64_t estimate_bgv_multiply_relinearize_image_lines(
    std::size_t degree, std::size_t active_q_count,
    std::size_t key_modulus_count)
{
    const std::uint64_t base = estimate_bgv_keyswitch_image_lines(
        degree, active_q_count, key_modulus_count);
    return base + 4 * active_q_count *
        (degree / hpu::runtime::kHpuMemLineWords);
}

std::uint64_t estimate_bgv_rotation_image_lines(
    std::size_t degree, std::size_t active_q_count,
    std::size_t key_modulus_count)
{
    const std::uint64_t base = estimate_bgv_keyswitch_image_lines(
        degree, active_q_count, key_modulus_count);
    const std::uint64_t polynomial_lines = degree / hpu::runtime::kHpuMemLineWords;
    const std::uint64_t stage_lines = degree / (2 * hpu::runtime::kHpuMemLineWords);
    return base + active_q_count *
        (3 * polynomial_lines + ntt_stage_count(degree) * stage_lines);
}

static BgvKeySwitchApplication build_bgv_keyswitch_application_impl(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& product,
    const ::seal::KSwitchKeys& keys, std::size_t key_index,
    std::uint64_t capacity_lines, bool reserve_product)
{
    const auto key_data = context.key_context_data();
    const auto first_data = context.first_context_data();
    const auto source = context.get_context_data(product.parms_id());
    if (!context.parameters_set() || !key_data || !first_data || !source ||
        key_data->parms().scheme() != ::seal::scheme_type::bgv ||
        !::seal::is_valid_for(product, context) || !product.is_ntt_form() ||
        product.size() != 3 || key_index >= keys.data().size() ||
        keys.data()[key_index].empty() ||
        keys.parms_id() != context.key_parms_id()) {
        throw std::invalid_argument("BGV KeySwitch requires a three-component NTT shape and matching switching key");
    }
    const std::size_t degree = source->parms().poly_modulus_degree();
    const auto& key_moduli = key_data->parms().coeff_modulus();
    const auto& top_moduli = first_data->parms().coeff_modulus();
    const auto& active_moduli = source->parms().coeff_modulus();
    const std::size_t q_count = active_moduli.size();
    const std::size_t p_id = key_moduli.size() - 1;
    const std::size_t t_id = key_moduli.size();
    if (key_moduli.size() != top_moduli.size() + 1 ||
        t_id >= static_cast<std::size_t>(hpu::kMaxModContexts) ||
        q_count < 1 || q_count > top_moduli.size() ||
        keys.data(key_index).size() < q_count ||
        degree > static_cast<std::size_t>(std::numeric_limits<int>::max()) ||
        !hpu::is_valid_ntt_size(static_cast<int>(degree))) {
        throw std::invalid_argument("unsupported BGV KeySwitch Qmax|P|t level layout");
    }
    const std::uint64_t required_lines = estimate_bgv_keyswitch_image_lines(
        degree, q_count, key_moduli.size());
    if (capacity_lines < required_lines) {
        throw std::overflow_error(
            "BGV KeySwitch HPU_MEM image needs " + std::to_string(required_lines) +
            " lines; capacity is " + std::to_string(capacity_lines));
    }
    std::vector<std::uint32_t> moduli;
    moduli.reserve(q_count + 1);
    for (std::size_t index = 0; index < q_count; ++index) {
        if (active_moduli[index].value() != key_moduli[index].value()) {
            throw std::invalid_argument("BGV active Q is not a key-context prefix");
        }
        moduli.push_back(narrow(active_moduli[index].value()));
    }
    moduli.push_back(narrow(key_moduli[p_id].value()));
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    const auto constants = hpu::scheme::bgv::prepare_ntt_modswitch_constants(moduli, t);
    hpu::RnsDecompositionLayout layout;
    for (std::size_t index = 0; index < q_count; ++index) {
        layout.q_mod_ids.push_back(static_cast<int>(index));
        layout.key_digits.push_back({static_cast<int>(index)});
    }
    layout.p_mod_ids = {static_cast<int>(p_id)};

    hpu::runtime::HpuMemImage image(capacity_lines);
    std::vector<std::uint32_t> modulus_words;
    for (const auto& modulus : key_moduli) {
        const std::uint32_t value = narrow(modulus.value());
        const std::uint64_t mu = barrett_mu(value);
        modulus_words.insert(modulus_words.end(), {
            value, static_cast<std::uint32_t>(mu),
            static_cast<std::uint32_t>(mu >> 32U), 0});
    }
    const std::uint64_t t_mu = barrett_mu(t);
    modulus_words.insert(modulus_words.end(), {
        t, static_cast<std::uint32_t>(t_mu),
        static_cast<std::uint32_t>(t_mu >> 32U), 0});
    image.add("constants/modulus_table", modulus_words,
              hpu::runtime::AllocationKind::modulus_table);
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        add_twiddles(image, degree, basis, moduli[basis],
                     static_cast<std::uint32_t>(source->small_ntt_tables()[basis].get_root()));
    }
    add_twiddles(image, degree, p_id, moduli.back(),
                 static_cast<std::uint32_t>(key_data->small_ntt_tables()[p_id].get_root()));
    const std::string constant_prefix = "constants/bgv_keyswitch";
    image.add(constant_prefix + "/neg_inv_t",
              splat(degree, constants.neg_q_last_inverse_mod_t),
              hpu::runtime::AllocationKind::constant);
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        image.add(mod_id(constant_prefix + "/p_mod", basis),
                  splat(degree, constants.q_last_mod_q[basis]),
                  hpu::runtime::AllocationKind::constant);
        image.add(mod_id(constant_prefix + "/p_inv", basis),
                  splat(degree, constants.q_last_inverse_mod_q[basis]),
                  hpu::runtime::AllocationKind::constant);
    }

    for (std::size_t component = 0; component < 3; ++component) {
        HpuRnsPolynomial prepared;
        if (!reserve_product) {
            prepared = ciphertext_component_to_hpu(product, component, context);
        }
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const std::string id = mod_id(
                "input/c" + std::to_string(component), basis);
            if (reserve_product) {
                image.reserve(id, degree, hpu::runtime::AllocationKind::workspace);
            } else {
                const auto first = prepared.words.begin() +
                    static_cast<std::ptrdiff_t>(basis * degree);
                image.add(id, std::vector<std::uint32_t>(first, first + degree),
                          hpu::runtime::AllocationKind::ciphertext);
            }
        }
    }
    for (std::size_t digit = 0; digit < q_count; ++digit) {
        image.reserve(mod_id("workspace/bgv_keyswitch/switch_coeff", digit),
                      degree, hpu::runtime::AllocationKind::workspace);
        const auto& key = keys.data(key_index)[digit].data();
        if (!key.is_ntt_form() ||
            key.parms_id() != context.key_parms_id() || key.size() != 2) {
            throw std::invalid_argument("BGV switching key digit has an invalid shape");
        }
        std::vector<std::size_t> modulus_indices;
        for (std::size_t basis = 0; basis < q_count; ++basis) modulus_indices.push_back(basis);
        modulus_indices.push_back(p_id);
        for (std::size_t component = 0; component < 2; ++component) {
            const auto prepared = ciphertext_component_to_hpu(
                key, component, context, modulus_indices);
            for (std::size_t target = 0; target <= q_count; ++target) {
                const auto first = prepared.words.begin() +
                    static_cast<std::ptrdiff_t>(target * degree);
                image.add(mod_id("keys/digit" + std::to_string(digit) +
                                     "/c" + std::to_string(component), target == q_count ? p_id : target),
                          std::vector<std::uint32_t>(first, first + degree),
                          hpu::runtime::AllocationKind::evaluation_key);
            }
        }
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const std::string prefix = "workspace/bgv_keyswitch/c" + std::to_string(component);
        for (std::size_t target = 0; target <= q_count; ++target) {
            image.reserve(mod_id(prefix + "/acc", target == q_count ? p_id : target),
                          degree, hpu::runtime::AllocationKind::workspace);
        }
        image.reserve(prefix + "/p_coeff", degree,
                      hpu::runtime::AllocationKind::workspace);
        image.reserve(prefix + "/u_t", degree,
                      hpu::runtime::AllocationKind::workspace);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            image.reserve(mod_id("output/c" + std::to_string(component), basis),
                          degree, hpu::runtime::AllocationKind::output);
        }
    }

    const auto body = hpu::scheme::bgv::generate_keyswitch_ntt_body_asm(
        static_cast<int>(degree), layout, static_cast<int>(t_id), true, true);
    auto instructions = hpu::assemble_source(body);
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(image, encoded_dma);
    const std::size_t stages = ntt_stage_count(degree);
    const auto twiddle = [](std::size_t id) {
        return mod_id("constants/twiddle/canonical", id);
    };
    const auto accumulator = [p_id, q_count](std::size_t component, std::size_t target) {
        return mod_id("workspace/bgv_keyswitch/c" + std::to_string(component) + "/acc",
                      target == q_count ? p_id : target);
    };
    const auto inverse_twiddles = [&](std::size_t id) {
        for (std::size_t stage = 0; stage < stages; ++stage) {
            recipe.load(3, stage_id(twiddle(id) + "/intt", stage), degree / 2);
        }
        recipe.load(3, twiddle(id) + "/intt/post_untwist_scale", degree);
    };
    const auto forward_twiddles = [&](std::size_t id) {
        recipe.load(3, twiddle(id) + "/ntt/pre_twist", degree);
        for (std::size_t stage = 0; stage < stages; ++stage) {
            recipe.load(3, stage_id(twiddle(id) + "/ntt", stage), degree / 2);
        }
    };

    recipe.load(4, "constants/modulus_table", modulus_words.size(),
                hpu::DataType::mod_ctx, hpu::DloadFlag::small_bank);
    for (std::size_t digit = 0; digit < q_count; ++digit) {
        const std::string switch_coeff =
            mod_id("workspace/bgv_keyswitch/switch_coeff", digit);
        recipe.load(0, mod_id("input/c2", digit), degree);
        inverse_twiddles(digit);
        recipe.store(0, switch_coeff, degree);
        for (std::size_t target = 0; target <= q_count; ++target) {
            const std::size_t id = target == q_count ? p_id : target;
            if (target == digit) {
                recipe.load(0, mod_id("input/c2", digit), degree);
            } else {
                recipe.load(0, switch_coeff, degree);
                forward_twiddles(id);
            }
            for (std::size_t component = 0; component < 2; ++component) {
                recipe.load(1, mod_id("keys/digit" + std::to_string(digit) +
                                          "/c" + std::to_string(component), id), degree);
                if (digit != 0) recipe.load(2, accumulator(component, target), degree);
                recipe.store(2, accumulator(component, target), degree);
            }
        }
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const std::string prefix = "workspace/bgv_keyswitch/c" + std::to_string(component);
        recipe.load(0, accumulator(component, q_count), degree);
        inverse_twiddles(p_id);
        recipe.store(0, prefix + "/p_coeff", degree);
        recipe.load(0, prefix + "/p_coeff", degree);
        recipe.load(1, constant_prefix + "/neg_inv_t", degree);
        recipe.store(0, prefix + "/u_t", degree);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            recipe.load(0, prefix + "/u_t", degree);
            recipe.load(1, mod_id(constant_prefix + "/p_mod", basis), degree);
            recipe.load(1, prefix + "/p_coeff", degree);
            forward_twiddles(basis);
            recipe.load(1, accumulator(component, basis), degree);
            recipe.load(0, mod_id(constant_prefix + "/p_inv", basis), degree);
            recipe.load(0, mod_id("input/c" + std::to_string(component), basis), degree);
            recipe.store(1, mod_id("output/c" + std::to_string(component), basis), degree);
        }
    }
    auto bindings = recipe.finish();
    return {std::move(image), product.parms_id(), product.correction_factor(),
            std::move(instructions), std::move(bindings)};
}

BgvKeySwitchApplication build_bgv_keyswitch_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& product,
    const ::seal::RelinKeys& relin_keys, std::uint64_t capacity_lines)
{
    return build_bgv_keyswitch_application_impl(
        context, product, relin_keys, ::seal::RelinKeys::get_index(2),
        capacity_lines, false);
}

BgvKeySwitchApplication build_bgv_multiply_relinearize_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& left,
    const ::seal::Ciphertext& right, const ::seal::RelinKeys& relin_keys,
    std::uint64_t capacity_lines)
{
    const auto source = context.get_context_data(left.parms_id());
    const auto key_data = context.key_context_data();
    if (!source || !key_data ||
        source->parms().scheme() != ::seal::scheme_type::bgv ||
        !::seal::is_valid_for(left, context) ||
        !::seal::is_valid_for(right, context) ||
        !left.is_ntt_form() || !right.is_ntt_form() ||
        left.size() != 2 || right.size() != 2 ||
        left.parms_id() != right.parms_id()) {
        throw std::invalid_argument(
            "BGV Multiply+Relinearize requires two matching two-component NTT ciphertexts");
    }
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = source->parms().coeff_modulus().size();
    const std::size_t key_modulus_count =
        key_data->parms().coeff_modulus().size();
    const std::uint64_t required_lines =
        estimate_bgv_multiply_relinearize_image_lines(
            degree, q_count, key_modulus_count);
    if (capacity_lines < required_lines) {
        throw std::overflow_error(
            "BGV Multiply+Relinearize HPU_MEM image needs " +
            std::to_string(required_lines) + " lines; capacity is " +
            std::to_string(capacity_lines));
    }

    // Resize only the ciphertext *shape* to reuse the KeySwitch image layout.
    // The mutable tensor spans are not populated from these dummy components.
    ::seal::Ciphertext product_shape = left;
    product_shape.resize(context, left.parms_id(), 3);
    auto application = build_bgv_keyswitch_application_impl(
        context, product_shape, relin_keys, ::seal::RelinKeys::get_index(2),
        capacity_lines, true);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto left_hpu = ciphertext_component_to_hpu(left, component, context);
        const auto right_hpu = ciphertext_component_to_hpu(right, component, context);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto left_first = left_hpu.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            const auto right_first = right_hpu.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            application.image.add(
                mod_id("input/left/c" + std::to_string(component), basis),
                std::vector<std::uint32_t>(left_first, left_first + degree),
                hpu::runtime::AllocationKind::ciphertext);
            application.image.add(
                mod_id("input/right/c" + std::to_string(component), basis),
                std::vector<std::uint32_t>(right_first, right_first + degree),
                hpu::runtime::AllocationKind::ciphertext);
        }
    }
    if (application.image.used_lines() != required_lines) {
        throw std::logic_error("BGV Multiply+Relinearize image size differs from estimate");
    }
    hpu::RnsDecompositionLayout layout;
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        layout.q_mod_ids.push_back(static_cast<int>(basis));
        layout.key_digits.push_back({static_cast<int>(basis)});
    }
    layout.p_mod_ids = {static_cast<int>(key_modulus_count - 1)};
    const auto body = hpu::scheme::bgv::generate_ciphertext_multiply_ntt_body_asm(
        static_cast<int>(degree), layout, static_cast<int>(key_modulus_count),
        true, true);
    auto instructions = hpu::assemble_source(body);
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(application.image, encoded_dma);
    recipe.replay(application.dma.front());
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        recipe.load(0, mod_id("input/left/c0", basis), degree);
        recipe.load(1, mod_id("input/right/c0", basis), degree);
        recipe.store(2, mod_id("input/c0", basis), degree);

        recipe.load(0, mod_id("input/left/c0", basis), degree);
        recipe.load(1, mod_id("input/right/c1", basis), degree);
        recipe.load(0, mod_id("input/left/c1", basis), degree);
        recipe.load(1, mod_id("input/right/c0", basis), degree);
        recipe.store(2, mod_id("input/c1", basis), degree);

        recipe.load(0, mod_id("input/left/c1", basis), degree);
        recipe.load(1, mod_id("input/right/c1", basis), degree);
        recipe.store(2, mod_id("input/c2", basis), degree);
    }
    for (std::size_t index = 1; index < application.dma.size(); ++index) {
        recipe.replay(application.dma[index]);
    }
    application.instructions = std::move(instructions);
    application.dma = recipe.finish();
    const std::uint32_t t = narrow(source->parms().plain_modulus().value());
    application.correction_factor =
        hpu::scheme::bgv::multiply_correction_factor(
            left.correction_factor(), right.correction_factor(), t);
    return application;
}

static BgvKeySwitchApplication build_bgv_galois_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input,
    const ::seal::GaloisKeys& galois_keys, std::uint32_t galois_element,
    std::uint64_t capacity_lines)
{
    const auto source = context.get_context_data(input.parms_id());
    const auto key_data = context.key_context_data();
    if (!source || !key_data ||
        source->parms().scheme() != ::seal::scheme_type::bgv ||
        !source->qualifiers().using_batching ||
        !::seal::is_valid_for(input, context) || !input.is_ntt_form() ||
        input.size() != 2 ||
        galois_keys.parms_id() != context.key_parms_id() ||
        !galois_keys.has_key(galois_element)) {
        throw std::invalid_argument(
            "BGV rotation requires batching, a two-component NTT ciphertext and matching Galois key");
    }
    const std::size_t degree = source->parms().poly_modulus_degree();
    const std::size_t q_count = source->parms().coeff_modulus().size();
    const std::size_t key_modulus_count =
        key_data->parms().coeff_modulus().size();
    const std::uint64_t required_lines = estimate_bgv_rotation_image_lines(
        degree, q_count, key_modulus_count);
    if (capacity_lines < required_lines) {
        throw std::overflow_error(
            "BGV rotation HPU_MEM image needs " + std::to_string(required_lines) +
            " lines; capacity is " + std::to_string(capacity_lines));
    }

    ::seal::Ciphertext shape = input;
    shape.resize(context, input.parms_id(), 3);
    auto application = build_bgv_keyswitch_application_impl(
        context, shape, galois_keys,
        ::seal::GaloisKeys::get_index(galois_element),
        capacity_lines, true);
    const auto fused = create_fused_inverse_automorphism_tables(
        input.parms_id(), galois_element, context);
    add_galois_twiddles(application.image, fused);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto converted = ciphertext_component_to_hpu(
            input, component, context);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto first = converted.words.begin() +
                static_cast<std::ptrdiff_t>(basis * degree);
            application.image.add(
                mod_id("input/original/c" + std::to_string(component), basis),
                std::vector<std::uint32_t>(first, first + degree),
                hpu::runtime::AllocationKind::ciphertext);
        }
    }
    if (application.image.used_lines() != required_lines) {
        throw std::logic_error("BGV rotation image size differs from estimate");
    }
    hpu::RnsDecompositionLayout layout;
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        layout.q_mod_ids.push_back(static_cast<int>(basis));
        layout.key_digits.push_back({static_cast<int>(basis)});
    }
    layout.p_mod_ids = {static_cast<int>(key_modulus_count - 1)};
    std::ostringstream body;
    body << "        /* BGV Galois automorphism in HPU, then Galois KeySwitch */\n";
    body << hpu::dload(4, hpu::DataType::mod_ctx,
                       hpu::DloadFlag::small_bank);
    for (std::size_t component = 0; component < 2; ++component) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            body << hpu::pmodld(static_cast<int>(basis));
            body << hpu::dload(0, hpu::DataType::poly);
            body << generate_hpu_intt_body_asm(
                static_cast<int>(degree), 0, 3, false);
            body << generate_hpu_ntt_body_asm(
                static_cast<int>(degree), 0, 3, false);
            body << hpu::dstore(0, 1);
        }
    }
    body << hpu::scheme::bgv::generate_keyswitch_ntt_body_asm(
        static_cast<int>(degree), layout,
        static_cast<int>(key_modulus_count), false, false);
    body << hpu::pfree(4) << hpu::psync();
    auto instructions = hpu::assemble_source(body.str());
    hpu::validate_executable_program(instructions);
    const auto encoded_dma = hpu::collect_dma_relocations(instructions);
    DmaRecipe recipe(application.image, encoded_dma);
    recipe.replay(application.dma.front());
    const std::size_t stages = ntt_stage_count(degree);
    for (std::size_t component = 0; component < 2; ++component) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto fused_prefix =
                mod_id("constants/twiddle/galois", basis) + "/intt";
            const auto canonical_prefix =
                mod_id("constants/twiddle/canonical", basis) + "/ntt";
            recipe.load(0,
                mod_id("input/original/c" + std::to_string(component), basis), degree);
            for (std::size_t stage = 0; stage < stages; ++stage) {
                recipe.load(3, stage_id(fused_prefix, stage), degree / 2);
            }
            recipe.load(3, fused_prefix + "/post_untwist_scale", degree);
            recipe.load(3, canonical_prefix + "/pre_twist", degree);
            for (std::size_t stage = 0; stage < stages; ++stage) {
                recipe.load(3, stage_id(canonical_prefix, stage), degree / 2);
            }
            recipe.store(0,
                mod_id(component == 0 ? "input/c0" : "input/c2", basis), degree);
        }
    }
    for (std::size_t index = 1; index < application.dma.size(); ++index) {
        recipe.replay(application.dma[index]);
    }
    application.instructions = std::move(instructions);
    application.dma = recipe.finish();
    application.correction_factor = input.correction_factor();
    return application;
}

BgvKeySwitchApplication build_bgv_rotate_rows_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input,
    const ::seal::GaloisKeys& galois_keys, int steps,
    std::uint64_t capacity_lines)
{
    const auto source = context.get_context_data(input.parms_id());
    if (!source) throw std::invalid_argument("BGV rotation level is unknown");
    return build_bgv_galois_application(
        context, input, galois_keys,
        hpu::scheme::bfv::row_rotation_galois_element(
            source->parms().poly_modulus_degree(), steps),
        capacity_lines);
}

BgvKeySwitchApplication build_bgv_rotate_columns_application(
    const ::seal::SEALContext& context, const ::seal::Ciphertext& input,
    const ::seal::GaloisKeys& galois_keys,
    std::uint64_t capacity_lines)
{
    const auto source = context.get_context_data(input.parms_id());
    if (!source) throw std::invalid_argument("BGV rotation level is unknown");
    return build_bgv_galois_application(
        context, input, galois_keys,
        hpu::scheme::bfv::column_rotation_galois_element(
            source->parms().poly_modulus_degree()),
        capacity_lines);
}

BgvKeySwitchRuntimeArtifacts render_bgv_keyswitch_runtime_artifacts(
    const std::string& stem, const BgvKeySwitchApplication& application)
{
    if (application.image.capacity_lines() > std::numeric_limits<std::uint32_t>::max() ||
        application.dma.empty()) {
        throw std::invalid_argument("BGV KeySwitch runtime needs a nonempty uint32-addressable image");
    }
    const auto encoded = hpu::collect_dma_relocations(application.instructions);
    hpu::validate_executable_program(application.instructions);
    if (encoded.size() != application.dma.size()) {
        throw std::invalid_argument("BGV KeySwitch encoded DMA count differs from bindings");
    }
    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto& binding = application.dma[index];
        const auto& allocation = application.image.allocation(binding.allocation_id);
        if (binding.dma_index != index ||
            binding.instruction_index != encoded[index].instruction_index ||
            binding.direction != encoded[index].direction ||
            binding.object_slot != encoded[index].object_id ||
            binding.type_or_release != encoded[index].type_or_release ||
            binding.flag != encoded[index].flag ||
            binding.span.line_offset != allocation.span.line_offset ||
            binding.span.line_count != allocation.span.line_count ||
            binding.span.line_offset >= application.image.capacity_lines() ||
            binding.span.line_count > application.image.capacity_lines() - binding.span.line_offset) {
            throw std::invalid_argument("BGV KeySwitch runtime binding is unresolved or out of range");
        }
    }
    const std::string identifier = hpu::c_identifier(stem);
    BgvKeySwitchRuntimeArtifacts result;
    result.header = hpu::render_executable_header(stem, application.dma.size());
    const std::string marker = "#ifdef __cplusplus\n}\n#endif\n\n#endif\n";
    const auto position = result.header.find(marker);
    if (position == std::string::npos) {
        throw std::logic_error("BGV KeySwitch executable header has unexpected structure");
    }
    result.header.insert(position, "int hpu_run_" + identifier + "(void);\n\n");
    result.source = hpu::render_executable_source(
        stem, application.instructions, application.image.capacity_lines());
    std::ostringstream source;
    source << "\nstatic const hpu_dma_span_t hpu_program_" << identifier
           << "_resolved_spans[] = {\n";
    for (const auto& binding : application.dma) {
        source << "    { UINT32_C(" << binding.span.line_offset << "), UINT32_C("
               << binding.span.line_count << ") },\n";
    }
    source << "};\n\nint hpu_run_" << identifier << "(void) {\n"
           << "    return hpu_program_" << identifier << "(\n"
           << "        hpu_program_" << identifier << "_resolved_spans,\n"
           << "        HPU_PROGRAM_";
    for (char character : identifier) {
        source << static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    }
    source << "_DMA_COUNT);\n}\n";
    result.source += source.str();

    std::ostringstream manifest;
    manifest << "instruction_index,dma_index,allocation_id,line_offset,line_count,word_hex\n";
    for (std::size_t index = 0; index < application.dma.size(); ++index) {
        const auto& binding = application.dma[index];
        manifest << binding.instruction_index << ',' << index << ','
                 << csv_field(binding.allocation_id) << ','
                 << binding.span.line_offset << ',' << binding.span.line_count << ','
                 << hpu::format_word_hex(
                        application.instructions[binding.instruction_index].word) << '\n';
    }
    result.resolved_dma_manifest = manifest.str();
    return result;
}

} // namespace hpu::seal_adapter
