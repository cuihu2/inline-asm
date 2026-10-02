#include "hpu/seal/bgv_software_executor.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "scheme/bfv/galois.hpp"

#include <algorithm>
#include <stdexcept>

namespace hpu::seal_adapter {
namespace {

std::string mod_id(const std::string& prefix, std::size_t id)
{
    return prefix + "/mod" + std::to_string(id);
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

std::uint32_t add_mod(
    std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    const std::uint64_t sum = static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(sum >= modulus ? sum - modulus : sum);
}

std::uint32_t subtract_mod(
    std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return left >= right
        ? left - right
        : static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(left) + modulus - right);
}

std::uint32_t multiply_mod(
    std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % modulus);
}

} // namespace

BgvSoftwareExecutor::BgvSoftwareExecutor(
    const ::seal::SEALContext& context,
    const hpu::runtime::HpuMemImage& image)
    : context_(context), image_(image), memory_(image)
{
    const auto key_data = context_.key_context_data();
    if (!context_.parameters_set() || !key_data ||
        key_data->parms().scheme() != ::seal::scheme_type::bgv) {
        throw std::invalid_argument(
            "BGV software executor requires a valid BGV SEALContext");
    }
    degree_ = key_data->parms().poly_modulus_degree();
    key_modulus_count_ = key_data->parms().coeff_modulus().size();
    memory_.load_modulus_table(
        allocation("constants/modulus_table").span,
        key_modulus_count_ + 1);
    for (std::size_t index = 0; index < key_modulus_count_; ++index) {
        if (memory_.modulus(static_cast<std::uint8_t>(index)) !=
            key_data->parms().coeff_modulus()[index].value()) {
            throw std::invalid_argument(
                "BGV HPU modulus table differs from SEALContext");
        }
    }
    if (memory_.modulus(static_cast<std::uint8_t>(key_modulus_count_)) !=
        key_data->parms().plain_modulus().value()) {
        throw std::invalid_argument(
            "BGV HPU plaintext modulus differs from SEALContext");
    }
}

bool BgvSoftwareExecutor::has(const std::string& id) const noexcept
{
    return image_.contains(id);
}

const hpu::runtime::HpuMemAllocation& BgvSoftwareExecutor::allocation(
    const std::string& id) const
{
    if (!image_.contains(id)) {
        throw std::invalid_argument(
            "BGV software executor lacks HPU_MEM allocation: " + id);
    }
    return image_.allocation(id);
}

BgvSoftwareExecutor::Limb BgvSoftwareExecutor::read(
    const std::string& id) const
{
    const auto& item = allocation(id);
    if (item.word_count != degree_) {
        throw std::invalid_argument(
            "BGV software executor polynomial has the wrong degree: " + id);
    }
    return memory_.read(item.span, degree_);
}

void BgvSoftwareExecutor::write(
    const std::string& id, const Limb& words)
{
    const auto& item = allocation(id);
    if (item.read_only || item.word_count != degree_ ||
        words.size() != degree_) {
        throw std::invalid_argument(
            "BGV software executor cannot write allocation: " + id);
    }
    memory_.write(item.span, words);
}

std::size_t BgvSoftwareExecutor::limb_count(
    const std::string& prefix) const
{
    std::size_t count = 0;
    while (has(mod_id(prefix, count))) ++count;
    return count;
}

std::uint32_t BgvSoftwareExecutor::constant(
    const std::string& id, std::uint32_t modulus) const
{
    const auto words = read(id);
    if (words.empty() || words.front() >= modulus ||
        !std::all_of(words.begin(), words.end(),
            [&](std::uint32_t word) { return word == words.front(); })) {
        throw std::invalid_argument(
            "BGV software executor constant is not a reduced splat: " + id);
    }
    return words.front();
}

BgvSoftwareExecutor::Limb BgvSoftwareExecutor::inverse_ntt(
    const Limb& words, std::size_t modulus_id,
    const std::string& twiddle_prefix) const
{
    if (words.size() != degree_ || modulus_id >= key_modulus_count_) {
        throw std::invalid_argument("BGV inverse NTT shape is invalid");
    }
    const auto key_data = context_.key_context_data();
    const auto modulus = memory_.modulus(
        static_cast<std::uint8_t>(modulus_id));
    const auto psi = static_cast<std::uint32_t>(
        key_data->small_ntt_tables()[modulus_id].get_root());
    hpu::model::HardwareNttModel model(
        degree_, modulus, hpu::model::pow_mod(psi, 2, modulus));
    hpu::model::InverseNttTables tables;
    tables.stages.reserve(model.log_degree());
    for (std::size_t stage = 0; stage < model.log_degree(); ++stage) {
        const auto& item = allocation(
            twiddle_prefix + "/intt/stage" + std::to_string(stage));
        tables.stages.push_back(memory_.read(item.span, degree_ / 2));
    }
    tables.post_scale = read(
        twiddle_prefix + "/intt/post_untwist_scale");
    return model.inverse(words, tables);
}

BgvSoftwareExecutor::Limb BgvSoftwareExecutor::forward_ntt(
    const Limb& coefficients, std::size_t modulus_id,
    const std::string& twiddle_prefix) const
{
    if (coefficients.size() != degree_ || modulus_id >= key_modulus_count_) {
        throw std::invalid_argument("BGV forward NTT shape is invalid");
    }
    const auto key_data = context_.key_context_data();
    const auto modulus = memory_.modulus(
        static_cast<std::uint8_t>(modulus_id));
    const auto psi = static_cast<std::uint32_t>(
        key_data->small_ntt_tables()[modulus_id].get_root());
    hpu::model::HardwareNttModel model(
        degree_, modulus, hpu::model::pow_mod(psi, 2, modulus));
    std::vector<std::vector<std::uint32_t>> stages;
    stages.reserve(model.log_degree());
    for (std::size_t stage = 0; stage < model.log_degree(); ++stage) {
        const auto& item = allocation(
            twiddle_prefix + "/ntt/stage" + std::to_string(stage));
        stages.push_back(memory_.read(item.span, degree_ / 2));
    }
    const auto pre_twist = read(twiddle_prefix + "/ntt/pre_twist");
    Limb prepared = coefficients;
    for (std::size_t index = 0; index < degree_; ++index) {
        if (prepared[index] >= modulus) {
            throw std::invalid_argument(
                "BGV forward NTT input is not reduced modulo q");
        }
        prepared[index] = multiply_mod(
            prepared[index], pre_twist[bit_reverse(index, degree_)], modulus);
    }
    return model.forward(prepared, stages);
}

void BgvSoftwareExecutor::execute_plain(
    const BgvOperationStep& step,
    const std::string& input_prefix,
    const std::string& output_prefix,
    std::size_t q_count)
{
    const std::string step_prefix = "steps/" + step.id;
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto modulus = memory_.modulus(
            static_cast<std::uint8_t>(basis));
        const auto plain = read(mod_id(step_prefix + "/plain", basis));
        for (std::size_t component = 0; component < 2; ++component) {
            const auto input = read(mod_id(
                input_prefix + "/c" + std::to_string(component), basis));
            Limb output(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                if (input[index] >= modulus || plain[index] >= modulus) {
                    throw std::invalid_argument(
                        "BGV plain-operation operand is not reduced modulo q");
                }
                if (step.kind == BgvPlainOperationKind::multiply) {
                    output[index] = multiply_mod(
                        input[index], plain[index], modulus);
                } else if (component == 1) {
                    output[index] = input[index];
                } else if (step.kind == BgvPlainOperationKind::add) {
                    output[index] = add_mod(
                        input[index], plain[index], modulus);
                } else if (step.kind == BgvPlainOperationKind::subtract) {
                    output[index] = subtract_mod(
                        input[index], plain[index], modulus);
                } else {
                    throw std::logic_error("unsupported BGV plain operation");
                }
            }
            write(mod_id(
                output_prefix + "/c" + std::to_string(component), basis),
                output);
        }
    }
}

void BgvSoftwareExecutor::execute_binary(
    const BgvOperationStep& step,
    const std::string& input_prefix,
    const std::string& right_prefix,
    const std::string& output_prefix,
    std::size_t q_count)
{
    const std::string step_prefix = "steps/" + step.id;
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto modulus = memory_.modulus(
            static_cast<std::uint8_t>(basis));
        const auto left_id = mod_id(step_prefix + "/balance/left", basis);
        const auto right_id = mod_id(step_prefix + "/balance/right", basis);
        const std::uint32_t left_scalar = has(left_id)
            ? constant(left_id, modulus) : 1;
        const std::uint32_t right_scalar = has(right_id)
            ? constant(right_id, modulus) : 1;
        for (std::size_t component = 0; component < 2; ++component) {
            const std::string suffix = "/c" + std::to_string(component);
            const auto left = read(mod_id(input_prefix + suffix, basis));
            const auto right = read(mod_id(right_prefix + suffix, basis));
            Limb output(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                if (left[index] >= modulus || right[index] >= modulus) {
                    throw std::invalid_argument(
                        "BGV binary operand is not reduced modulo q");
                }
                const auto balanced_left = multiply_mod(
                    left[index], left_scalar, modulus);
                const auto balanced_right = multiply_mod(
                    right[index], right_scalar, modulus);
                output[index] =
                    step.kind == BgvPlainOperationKind::add_ciphertext
                    ? add_mod(balanced_left, balanced_right, modulus)
                    : subtract_mod(balanced_left, balanced_right, modulus);
            }
            write(mod_id(output_prefix + suffix, basis), output);
        }
    }
}

void BgvSoftwareExecutor::execute_keyswitch(
    const std::string& resource_prefix,
    const std::string& output_prefix,
    std::size_t q_count,
    const std::string& input_prefix)
{
    const auto source_prefix = input_prefix.empty()
        ? resource_prefix + "/input" : input_prefix;
    if (q_count == 0 || q_count >= key_modulus_count_) {
        throw std::invalid_argument("BGV KeySwitch active base is invalid");
    }
    const std::size_t p_id = key_modulus_count_ - 1;
    const std::uint32_t t = memory_.modulus(
        static_cast<std::uint8_t>(key_modulus_count_));
    std::vector<Limb> source_coeff(q_count);
    for (std::size_t digit = 0; digit < q_count; ++digit) {
        const auto switching = read(mod_id(
            source_prefix + "/c2", digit));
        const auto twiddle = mod_id(
            resource_prefix + "/constants/twiddle/canonical", digit);
        source_coeff[digit] = inverse_ntt(switching, digit, twiddle);
        write(mod_id(
            resource_prefix +
                "/workspace/bgv_keyswitch/switch_coeff",
            digit), source_coeff[digit]);
    }

    std::vector<std::vector<Limb>> accumulators(
        2, std::vector<Limb>(q_count + 1, Limb(degree_, 0)));
    for (std::size_t target = 0; target <= q_count; ++target) {
        const std::size_t modulus_id = target == q_count ? p_id : target;
        const auto modulus = memory_.modulus(
            static_cast<std::uint8_t>(modulus_id));
        const auto twiddle = mod_id(
            resource_prefix + "/constants/twiddle/canonical", modulus_id);
        for (std::size_t digit = 0; digit < q_count; ++digit) {
            Limb operand;
            if (target == digit) {
                operand = read(mod_id(
                    source_prefix + "/c2", digit));
            } else {
                operand = source_coeff[digit];
                for (auto& word : operand) word %= modulus;
                operand = forward_ntt(operand, modulus_id, twiddle);
            }
            for (std::size_t component = 0; component < 2; ++component) {
                const auto key = read(mod_id(
                    resource_prefix + "/keys/digit" +
                        std::to_string(digit) + "/c" +
                        std::to_string(component),
                    modulus_id));
                for (std::size_t index = 0; index < degree_; ++index) {
                    accumulators[component][target][index] = add_mod(
                        accumulators[component][target][index],
                        multiply_mod(operand[index], key[index], modulus),
                        modulus);
                }
            }
        }
        for (std::size_t component = 0; component < 2; ++component) {
            write(mod_id(
                resource_prefix + "/workspace/bgv_keyswitch/c" +
                    std::to_string(component) + "/acc",
                modulus_id), accumulators[component][target]);
        }
    }

    const auto neg_inverse = constant(
        resource_prefix + "/constants/bgv_keyswitch/neg_inv_t", t);
    const auto p = memory_.modulus(static_cast<std::uint8_t>(p_id));
    const auto p_twiddle = mod_id(
        resource_prefix + "/constants/twiddle/canonical", p_id);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto p_coeff = inverse_ntt(
            accumulators[component][q_count], p_id, p_twiddle);
        const std::string workspace =
            resource_prefix + "/workspace/bgv_keyswitch/c" +
            std::to_string(component);
        write(workspace + "/p_coeff", p_coeff);
        Limb u_t(degree_);
        for (std::size_t index = 0; index < degree_; ++index) {
            u_t[index] = multiply_mod(p_coeff[index] % t, neg_inverse, t);
        }
        write(workspace + "/u_t", u_t);
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto modulus = memory_.modulus(
                static_cast<std::uint8_t>(basis));
            const auto p_mod = constant(mod_id(
                resource_prefix + "/constants/bgv_keyswitch/p_mod",
                basis), modulus);
            const auto p_inv = constant(mod_id(
                resource_prefix + "/constants/bgv_keyswitch/p_inv",
                basis), modulus);
            Limb correction(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                correction[index] = add_mod(
                    p_coeff[index] % modulus,
                    multiply_mod(u_t[index], p_mod, modulus), modulus);
            }
            const auto correction_ntt = forward_ntt(
                correction, basis,
                mod_id(resource_prefix +
                    "/constants/twiddle/canonical", basis));
            const auto base = read(mod_id(
                source_prefix + "/c" +
                    std::to_string(component), basis));
            Limb output(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                const auto reduced = multiply_mod(
                    subtract_mod(
                        accumulators[component][basis][index],
                        correction_ntt[index], modulus),
                    p_inv, modulus);
                output[index] = add_mod(base[index], reduced, modulus);
            }
            write(mod_id(
                output_prefix + "/c" + std::to_string(component), basis),
                output);
        }
    }
}

void BgvSoftwareExecutor::execute_tensor(
    const std::string& input_prefix,
    const std::string& right_prefix,
    const std::string& output_prefix,
    std::size_t q_count)
{
    for (std::size_t basis = 0; basis < q_count; ++basis) {
        const auto modulus = memory_.modulus(
            static_cast<std::uint8_t>(basis));
        const auto left0 = read(mod_id(input_prefix + "/c0", basis));
        const auto left1 = read(mod_id(input_prefix + "/c1", basis));
        const auto right0 = read(mod_id(right_prefix + "/c0", basis));
        const auto right1 = read(mod_id(right_prefix + "/c1", basis));
        Limb tensor0(degree_), tensor1(degree_), tensor2(degree_);
        for (std::size_t index = 0; index < degree_; ++index) {
            tensor0[index] = multiply_mod(left0[index], right0[index], modulus);
            tensor1[index] = add_mod(
                multiply_mod(left0[index], right1[index], modulus),
                multiply_mod(left1[index], right0[index], modulus), modulus);
            tensor2[index] = multiply_mod(left1[index], right1[index], modulus);
        }
        write(mod_id(output_prefix + "/c0", basis), tensor0);
        write(mod_id(output_prefix + "/c1", basis), tensor1);
        write(mod_id(output_prefix + "/c2", basis), tensor2);
    }
}

void BgvSoftwareExecutor::execute_rotation(
    const BgvOperationStep& step,
    const std::string& input_prefix,
    const std::string& output_prefix,
    std::size_t q_count)
{
    const std::string resource = "steps/" + step.id + "/rotation";
    const std::uint32_t element =
        step.kind == BgvPlainOperationKind::rotate_rows
        ? hpu::scheme::bfv::row_rotation_galois_element(
            degree_, step.rotation_steps)
        : hpu::scheme::bfv::column_rotation_galois_element(degree_);
    for (std::size_t component = 0; component < 2; ++component) {
        for (std::size_t basis = 0; basis < q_count; ++basis) {
            const auto original = read(mod_id(
                input_prefix + "/c" + std::to_string(component), basis));
            const auto coefficients = inverse_ntt(
                original, basis,
                mod_id(resource + "/constants/twiddle/galois", basis));
            const auto modulus = memory_.modulus(
                static_cast<std::uint8_t>(basis));
            const auto psi = static_cast<std::uint32_t>(
                context_.key_context_data()->small_ntt_tables()[basis]
                    .get_root());
            const auto expected_coefficients =
                hpu::model::automorphism_coefficients(
                    hpu::model::negacyclic_inverse(
                        original, modulus, psi),
                    element, modulus);
            if (coefficients != expected_coefficients) {
                throw std::runtime_error(
                    "BGV fused Galois twiddles disagree with the plan step");
            }
            const auto rotated = forward_ntt(
                coefficients, basis,
                mod_id(resource + "/constants/twiddle/canonical", basis));
            write(mod_id(
                resource + (component == 0 ? "/input/c0" : "/input/c2"),
                basis), rotated);
        }
    }
    execute_keyswitch(resource, output_prefix, q_count);
}

void BgvSoftwareExecutor::execute_modswitch(
    const BgvOperationStep& step,
    const std::string& input_prefix,
    const std::string& output_prefix,
    std::size_t q_count)
{
    if (q_count < 2) {
        throw std::invalid_argument("BGV ModSwitch has no next level");
    }
    const std::string resource = "steps/" + step.id + "/modswitch";
    const std::size_t last = q_count - 1;
    const auto t = memory_.modulus(
        static_cast<std::uint8_t>(key_modulus_count_));
    const auto neg_inverse = constant(
        resource + "/constants/bgv_modswitch/neg_inv_t", t);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto last_coeff = inverse_ntt(
            read(mod_id(input_prefix + "/c" +
                            std::to_string(component), last)),
            last,
            mod_id(resource + "/constants/twiddle/canonical", last));
        const std::string workspace =
            resource + "/workspace/bgv_modswitch/c" +
            std::to_string(component);
        write(workspace + "/last_coeff", last_coeff);
        Limb u_t(degree_);
        for (std::size_t index = 0; index < degree_; ++index) {
            u_t[index] = multiply_mod(
                last_coeff[index] % t, neg_inverse, t);
        }
        write(workspace + "/u_t", u_t);
        for (std::size_t basis = 0; basis < last; ++basis) {
            const auto modulus = memory_.modulus(
                static_cast<std::uint8_t>(basis));
            const auto q_last_mod = constant(mod_id(
                resource + "/constants/bgv_modswitch/q_last_mod",
                basis), modulus);
            const auto q_last_inv = constant(mod_id(
                resource + "/constants/bgv_modswitch/q_last_inv",
                basis), modulus);
            Limb correction(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                correction[index] = add_mod(
                    last_coeff[index] % modulus,
                    multiply_mod(u_t[index], q_last_mod, modulus), modulus);
            }
            const auto correction_ntt = forward_ntt(
                correction, basis,
                mod_id(resource + "/constants/twiddle/canonical", basis));
            const auto input = read(mod_id(
                input_prefix + "/c" + std::to_string(component), basis));
            Limb output(degree_);
            for (std::size_t index = 0; index < degree_; ++index) {
                output[index] = multiply_mod(
                    subtract_mod(input[index], correction_ntt[index], modulus),
                    q_last_inv, modulus);
            }
            write(mod_id(
                output_prefix + "/c" + std::to_string(component), basis),
                output);
        }
    }
}

void BgvSoftwareExecutor::execute(const BgvOperationPlan& plan)
{
    if (plan.steps().empty()) {
        throw std::invalid_argument("BGV software executor requires a nonempty plan");
    }
    for (std::size_t index = 0; index < plan.steps().size(); ++index) {
        const auto& step = plan.steps()[index];
        const auto input_prefix = plan.allocation_prefix(step.inputs.front());
        const auto output_prefix = plan.allocation_prefix(step.output);
        const auto source = context_.get_context_data(step.inputs.front().parms_id);
        if (!source) throw std::invalid_argument("BGV software input level is invalid");
        const auto q_count = source->parms().coeff_modulus().size();
        for (std::size_t c = 0; c < step.inputs.front().component_count; ++c)
            if (limb_count(input_prefix + "/c" + std::to_string(c)) != q_count)
                throw std::invalid_argument("BGV software input has an invalid RNS shape");
        switch (step.kind) {
        case BgvPlainOperationKind::add:
        case BgvPlainOperationKind::subtract:
        case BgvPlainOperationKind::multiply:
            execute_plain(step, input_prefix, output_prefix, q_count);
            break;
        case BgvPlainOperationKind::add_ciphertext:
        case BgvPlainOperationKind::subtract_ciphertext:
            execute_binary(step, input_prefix, plan.allocation_prefix(step.inputs[1]), output_prefix, q_count);
            break;
        case BgvPlainOperationKind::multiply_ciphertext:
            execute_tensor(input_prefix, plan.allocation_prefix(step.inputs[1]),
                "steps/" + step.id + "/multiply/input", q_count);
            execute_keyswitch("steps/" + step.id + "/multiply", output_prefix, q_count);
            break;
        case BgvPlainOperationKind::multiply_tensor:
            execute_tensor(input_prefix, plan.allocation_prefix(step.inputs[1]), output_prefix, q_count);
            break;
        case BgvPlainOperationKind::relinearize:
            execute_keyswitch("steps/" + step.id + "/relinearize", output_prefix, q_count, input_prefix);
            break;
        case BgvPlainOperationKind::rotate_rows:
        case BgvPlainOperationKind::rotate_columns:
            execute_rotation(step, input_prefix, output_prefix, q_count);
            break;
        case BgvPlainOperationKind::modswitch_to_next:
            execute_modswitch(step, input_prefix, output_prefix, q_count);
            break;
        }
        const auto output_q_count = context_.get_context_data(step.output.parms_id)->parms().coeff_modulus().size();
        for (std::size_t c = 0; c < step.output.component_count; ++c)
            if (limb_count(output_prefix + "/c" + std::to_string(c)) != output_q_count)
                throw std::invalid_argument("BGV software output has an invalid RNS shape: " + output_prefix);
    }
}

const hpu::runtime::HpuSoftwareExecutor&
BgvSoftwareExecutor::memory() const noexcept
{
    return memory_;
}

} // namespace hpu::seal_adapter
