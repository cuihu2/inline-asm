#include "hpu/seal/software_executor.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "scheme/ckks/galois.hpp"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace hpu::seal_adapter {
namespace {

bool compatible_scales(double left, double right)
{
    return std::isfinite(left) && std::isfinite(right)
        && left > 0.0 && right > 0.0
        && std::abs(left - right) <= 1e-6 * std::max(left, right);
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

std::uint32_t multiply_mod(
    std::uint32_t left,
    std::uint32_t right,
    std::uint32_t modulus)
{
    return static_cast<std::uint32_t>(
        (static_cast<std::uint64_t>(left) * right) % modulus);
}

std::uint32_t add_mod(
    std::uint32_t left,
    std::uint32_t right,
    std::uint32_t modulus)
{
    const std::uint64_t sum = static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(sum >= modulus ? sum - modulus : sum);
}

std::uint32_t subtract_mod(
    std::uint32_t left,
    std::uint32_t right,
    std::uint32_t modulus)
{
    return left >= right
        ? left - right
        : static_cast<std::uint32_t>(
            static_cast<std::uint64_t>(left) + modulus - right);
}

const PreparedCanonicalTwiddles& find_tables(
    const std::vector<PreparedCanonicalTwiddles>& tables,
    std::uint8_t modulus_id)
{
    const auto found = std::find_if(
        tables.begin(), tables.end(),
        [&](const PreparedCanonicalTwiddles& entry) {
            return entry.modulus_id == modulus_id;
        });
    if (found == tables.end()) {
        throw std::invalid_argument("canonical HPU NTT tables lack an active MOD_ID");
    }
    return *found;
}

const PreparedFusedAutomorphismTwiddles& find_fused_tables(
    const std::vector<PreparedFusedAutomorphismTwiddles>& tables,
    std::uint8_t modulus_id)
{
    const auto found = std::find_if(
        tables.begin(), tables.end(),
        [&](const PreparedFusedAutomorphismTwiddles& entry) {
            return entry.modulus_id == modulus_id;
        });
    if (found == tables.end()) {
        throw std::invalid_argument(
            "fused automorphism tables lack an active MOD_ID");
    }
    return *found;
}

} // namespace

CkksSoftwareExecutor::CkksSoftwareExecutor(
    const ::seal::SEALContext& context,
    const hpu::runtime::HpuMemImage& image)
    : context_(context), memory_(image)
{
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::ckks) {
        throw std::invalid_argument("CKKS software executor requires a CKKS SEALContext");
    }
    memory_.load_modulus_table(
        image.allocation("constants/modulus_table").span,
        key_data->parms().coeff_modulus().size());
}

void CkksSoftwareExecutor::validate_object(
    const PreparedRnsObject& object,
    std::size_t component_count) const
{
    const auto data = context_.get_context_data(object.parms_id);
    if (!data || data->parms().scheme() != ::seal::scheme_type::ckks
        || object.components.size() != component_count) {
        throw std::invalid_argument("prepared CKKS object has an invalid level or component count");
    }
    const std::size_t degree = data->parms().poly_modulus_degree();
    const std::size_t modulus_count = data->parms().coeff_modulus().size();
    for (const PreparedPolynomial& polynomial : object.components) {
        if (polynomial.degree != degree
            || polynomial.limbs.size() != modulus_count
            || polynomial.modulus_ids.size() != modulus_count) {
            throw std::invalid_argument("prepared CKKS polynomial has an invalid RNS shape");
        }
        for (std::size_t basis = 0; basis < modulus_count; ++basis) {
            if (polynomial.modulus_ids[basis] != basis) {
                throw std::invalid_argument("prepared CKKS data object has unstable MOD_ID order");
            }
        }
    }
}

void CkksSoftwareExecutor::require_same_level(
    const PreparedRnsObject& left,
    const PreparedRnsObject& right,
    const PreparedRnsObject& output) const
{
    if (left.parms_id != right.parms_id || left.parms_id != output.parms_id) {
        throw std::invalid_argument("CKKS software operands have different parms_id values");
    }
}

void CkksSoftwareExecutor::ciphertext_binary(
    const PreparedRnsObject& left,
    const PreparedRnsObject& right,
    const PreparedRnsObject& output,
    hpu::runtime::PointwiseOperation operation)
{
    validate_object(left, 2);
    validate_object(right, 2);
    validate_object(output, 2);
    require_same_level(left, right, output);
    if (!compatible_scales(left.scale, right.scale)
        || !compatible_scales(left.scale, output.scale)) {
        throw std::invalid_argument("CKKS Add/Sub requires matching scales");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const auto& left_poly = left.components[component];
        const auto& right_poly = right.components[component];
        const auto& output_poly = output.components[component];
        for (std::size_t basis = 0; basis < left_poly.limbs.size(); ++basis) {
            memory_.pointwise(
                output_poly.limbs[basis],
                left_poly.limbs[basis],
                right_poly.limbs[basis],
                left_poly.degree,
                left_poly.modulus_ids[basis],
                operation);
        }
    }
}

void CkksSoftwareExecutor::add(
    const PreparedRnsObject& left,
    const PreparedRnsObject& right,
    const PreparedRnsObject& output)
{
    ciphertext_binary(
        left, right, output, hpu::runtime::PointwiseOperation::add);
}

void CkksSoftwareExecutor::subtract(
    const PreparedRnsObject& left,
    const PreparedRnsObject& right,
    const PreparedRnsObject& output)
{
    ciphertext_binary(
        left, right, output, hpu::runtime::PointwiseOperation::subtract);
}

void CkksSoftwareExecutor::plaintext_binary(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& plaintext,
    const PreparedRnsObject& output,
    hpu::runtime::PointwiseOperation operation)
{
    validate_object(ciphertext, 2);
    validate_object(plaintext, 1);
    validate_object(output, 2);
    require_same_level(ciphertext, plaintext, output);
    if ((operation == hpu::runtime::PointwiseOperation::multiply
            && !compatible_scales(
                ciphertext.scale * plaintext.scale, output.scale))
        || (operation != hpu::runtime::PointwiseOperation::multiply
            && (!compatible_scales(ciphertext.scale, plaintext.scale)
                || !compatible_scales(ciphertext.scale, output.scale)))) {
        throw std::invalid_argument("CKKS plaintext operation has incompatible scales");
    }

    const auto& plain_poly = plaintext.components[0];
    for (std::size_t component = 0; component < 2; ++component) {
        const auto& cipher_poly = ciphertext.components[component];
        const auto& output_poly = output.components[component];
        for (std::size_t basis = 0; basis < cipher_poly.limbs.size(); ++basis) {
            if (operation != hpu::runtime::PointwiseOperation::multiply
                && component == 1) {
                memory_.copy(
                    output_poly.limbs[basis], cipher_poly.limbs[basis],
                    cipher_poly.degree);
            } else {
                memory_.pointwise(
                    output_poly.limbs[basis],
                    cipher_poly.limbs[basis],
                    plain_poly.limbs[basis],
                    cipher_poly.degree,
                    cipher_poly.modulus_ids[basis],
                    operation);
            }
        }
    }
}

void CkksSoftwareExecutor::multiply_plain(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& plaintext,
    const PreparedRnsObject& output)
{
    plaintext_binary(
        ciphertext, plaintext, output,
        hpu::runtime::PointwiseOperation::multiply);
}

void CkksSoftwareExecutor::add_plain(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& plaintext,
    const PreparedRnsObject& output)
{
    plaintext_binary(
        ciphertext, plaintext, output,
        hpu::runtime::PointwiseOperation::add);
}

void CkksSoftwareExecutor::subtract_plain(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& plaintext,
    const PreparedRnsObject& output)
{
    plaintext_binary(
        ciphertext, plaintext, output,
        hpu::runtime::PointwiseOperation::subtract);
}

void CkksSoftwareExecutor::negate(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& output)
{
    validate_object(ciphertext, 2);
    validate_object(output, 2);
    require_same_level(ciphertext, ciphertext, output);
    if (!compatible_scales(ciphertext.scale, output.scale)
        || ciphertext.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || output.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || ciphertext.key_domain != 1 || output.key_domain != 1) {
        throw std::invalid_argument(
            "CKKS Negate has incompatible scale/representation metadata");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const auto& source = ciphertext.components[component];
        const auto& destination = output.components[component];
        for (std::size_t basis = 0; basis < source.limbs.size(); ++basis) {
            const std::uint32_t q = memory_.modulus(
                source.modulus_ids[basis]);
            auto words = memory_.read(source.limbs[basis], source.degree);
            for (std::uint32_t& word : words) {
                if (word >= q) {
                    throw std::invalid_argument(
                        "CKKS Negate input is not reduced modulo q");
                }
                word = word == 0 ? 0 : q - word;
            }
            memory_.write(destination.limbs[basis], words);
        }
    }
}

void CkksSoftwareExecutor::square(
    const PreparedRnsObject& ciphertext,
    const PreparedRnsObject& tensor_output)
{
    multiply(ciphertext, ciphertext, tensor_output);
}

void CkksSoftwareExecutor::multiply(
    const PreparedRnsObject& left,
    const PreparedRnsObject& right,
    const PreparedRnsObject& tensor_output)
{
    validate_object(left, 2);
    validate_object(right, 2);
    validate_object(tensor_output, 3);
    require_same_level(left, right, tensor_output);
    if (left.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || right.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || tensor_output.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || left.key_domain != 1 || right.key_domain != 1
        || tensor_output.key_domain != 1
        || !compatible_scales(
            left.scale * right.scale, tensor_output.scale)) {
        throw std::invalid_argument(
            "CKKS Multiply has incompatible output scale/representation");
    }
    const auto& left0 = left.components[0];
    const auto& left1 = left.components[1];
    const auto& right0 = right.components[0];
    const auto& right1 = right.components[1];
    const auto& t0 = tensor_output.components[0];
    const auto& t1 = tensor_output.components[1];
    const auto& t2 = tensor_output.components[2];
    for (std::size_t basis = 0; basis < left0.limbs.size(); ++basis) {
        const auto mod_id = left0.modulus_ids[basis];
        memory_.pointwise(
            t0.limbs[basis], left0.limbs[basis], right0.limbs[basis],
            left0.degree, mod_id,
            hpu::runtime::PointwiseOperation::multiply);
        memory_.pointwise(
            t1.limbs[basis], left0.limbs[basis], right1.limbs[basis],
            left0.degree, mod_id,
            hpu::runtime::PointwiseOperation::multiply);
        memory_.multiply_accumulate(
            t1.limbs[basis], left1.limbs[basis], right0.limbs[basis],
            left0.degree, mod_id);
        memory_.pointwise(
            t2.limbs[basis], left1.limbs[basis], right1.limbs[basis],
            left0.degree, mod_id,
            hpu::runtime::PointwiseOperation::multiply);
    }
}

void CkksSoftwareExecutor::validate_evaluation_key(
    const PreparedEvaluationKey& evaluation_key,
    const PreparedRnsObject& operand) const
{
    if (evaluation_key.data_parms_id != operand.parms_id
        || evaluation_key.chain_index != operand.chain_index
        || !hpu::is_valid_rns_decomposition_layout(
            static_cast<int>(operand.components.front().degree),
            evaluation_key.rns_layout)
        || evaluation_key.digits.size()
            != evaluation_key.rns_layout.key_digits.size()) {
        throw std::invalid_argument(
            "CKKS evaluation key does not describe the operand level");
    }
    const auto& q_ids = evaluation_key.rns_layout.q_mod_ids;
    const auto& p_ids = evaluation_key.rns_layout.p_mod_ids;
    if (p_ids.size() != 1 || q_ids.size() != operand.components.front().limbs.size()) {
        throw std::invalid_argument(
            "CKKS software KeySwitch currently requires one SEAL special prime");
    }
    std::vector<std::uint8_t> full_ids;
    for (int id : q_ids) {
        full_ids.push_back(static_cast<std::uint8_t>(id));
    }
    if (!std::equal(
            full_ids.begin(), full_ids.end(),
            operand.components.front().modulus_ids.begin())) {
        throw std::invalid_argument(
            "CKKS evaluation-key Q order differs from the operand");
    }
    full_ids.push_back(static_cast<std::uint8_t>(p_ids.front()));
    for (std::size_t digit = 0; digit < evaluation_key.digits.size(); ++digit) {
        if (evaluation_key.rns_layout.key_digits[digit].size() != 1
            || evaluation_key.digits[digit].size() != 2) {
            throw std::invalid_argument(
                "CKKS software KeySwitch requires singleton SEAL RNS digits");
        }
        for (const PreparedPolynomial& component : evaluation_key.digits[digit]) {
            if (component.degree != operand.components.front().degree
                || component.modulus_ids != full_ids
                || component.limbs.size() != full_ids.size()) {
                throw std::invalid_argument(
                    "CKKS evaluation-key digit has an invalid Q|P shape");
            }
        }
    }
}

std::vector<std::uint32_t> CkksSoftwareExecutor::transform_limb(
    const std::vector<std::uint32_t>& words,
    std::size_t degree,
    std::uint8_t modulus_id,
    const std::vector<PreparedCanonicalTwiddles>& tables,
    bool inverse) const
{
    if (words.size() != degree) {
        throw std::invalid_argument("CKKS transform limb has an invalid degree");
    }
    const std::uint32_t q = memory_.modulus(modulus_id);
    const auto& prepared = find_tables(tables, modulus_id);
    if (prepared.modulus != q) {
        throw std::invalid_argument("canonical NTT table modulus mismatch");
    }
    hpu::model::HardwareNttModel model(
        degree, q, hpu::model::pow_mod(prepared.canonical_psi, 2, q));
    if (inverse) {
        hpu::model::InverseNttTables inverse_tables;
        inverse_tables.stages.reserve(prepared.inverse_stages.size());
        for (const auto& span : prepared.inverse_stages) {
            inverse_tables.stages.push_back(memory_.read(span, degree / 2));
        }
        inverse_tables.post_scale = memory_.read(
            prepared.post_untwist_scale, degree);
        return model.inverse(words, inverse_tables);
    }

    std::vector<std::vector<std::uint32_t>> forward_tables;
    forward_tables.reserve(prepared.forward_stages.size());
    for (const auto& span : prepared.forward_stages) {
        forward_tables.push_back(memory_.read(span, degree / 2));
    }
    const auto pre_twist = memory_.read(prepared.pre_twist, degree);
    auto coefficients = words;
    for (std::size_t index = 0; index < degree; ++index) {
        if (coefficients[index] >= q) {
            throw std::invalid_argument("CKKS coefficient is not reduced modulo q");
        }
        coefficients[index] = multiply_mod(
            coefficients[index], pre_twist[bit_reverse(index, degree)], q);
    }
    return model.forward(coefficients, forward_tables);
}

void CkksSoftwareExecutor::key_switch(
    const PreparedRnsObject& base_ciphertext,
    const PreparedRnsObject& switching_component,
    const PreparedEvaluationKey& evaluation_key,
    const PreparedKeySwitchConstants& constants,
    const PreparedRnsObject& output,
    const std::vector<PreparedCanonicalTwiddles>& tables)
{
    key_switch_impl(
        base_ciphertext, switching_component, evaluation_key, constants,
        output, tables, false);
}

void CkksSoftwareExecutor::key_switch_impl(
    const PreparedRnsObject& base_ciphertext,
    const PreparedRnsObject& switching_component,
    const PreparedEvaluationKey& evaluation_key,
    const PreparedKeySwitchConstants& constants,
    const PreparedRnsObject& output,
    const std::vector<PreparedCanonicalTwiddles>& tables,
    bool switching_is_coefficient)
{
    validate_object(base_ciphertext, 2);
    validate_object(switching_component, 1);
    validate_object(output, 2);
    require_same_level(base_ciphertext, switching_component, output);
    if (!compatible_scales(base_ciphertext.scale, switching_component.scale)
        || !compatible_scales(base_ciphertext.scale, output.scale)
        || base_ciphertext.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || output.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || base_ciphertext.key_domain != 1 || output.key_domain != 1
        || switching_component.domain != (switching_is_coefficient
            ? hpu::runtime::PolynomialDomain::coefficient
            : hpu::runtime::PolynomialDomain::canonical_ntt_physical)
        || (!switching_is_coefficient && switching_component.key_domain != 1)) {
        throw std::invalid_argument(
            "CKKS KeySwitch has incompatible scale/representation metadata");
    }
    validate_evaluation_key(evaluation_key, switching_component);

    const std::size_t degree = switching_component.components[0].degree;
    const auto& q_ids = evaluation_key.rns_layout.q_mod_ids;
    const std::uint8_t p_id = static_cast<std::uint8_t>(
        evaluation_key.rns_layout.p_mod_ids.front());
    std::vector<std::uint8_t> full_ids;
    full_ids.reserve(q_ids.size() + 1);
    for (int id : q_ids) {
        full_ids.push_back(static_cast<std::uint8_t>(id));
    }
    full_ids.push_back(p_id);

    constexpr std::uint32_t format_magic = 0x4b535731U;
    const auto constant_words = memory_.read(
        constants.values, 5 + q_ids.size() * 2);
    if (constants.data_parms_id != switching_component.parms_id
        || constants.chain_index != switching_component.chain_index
        || constant_words[0] != format_magic
        || constant_words[1] != p_id
        || constant_words[2] != memory_.modulus(p_id)
        || constant_words[3] != (memory_.modulus(p_id) >> 1U)
        || constant_words[4] != q_ids.size()) {
        throw std::invalid_argument("invalid HPU_MEM KeySwitch constants");
    }
    for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
        const std::uint32_t q = memory_.modulus(
            static_cast<std::uint8_t>(q_ids[basis]));
        if (constant_words[5 + basis * 2]
                != static_cast<std::uint32_t>(q_ids[basis])
            || constant_words[6 + basis * 2]
                != hpu::model::inverse_mod_prime(
                    memory_.modulus(p_id) % q, q)) {
            throw std::invalid_argument("invalid HPU_MEM inverse-P constant");
        }
    }

    // Accumulators are [key component][Q|P limb][physical NTT word]. One
    // source digit is streamed at a time, matching the <=5 live-polynomial
    // hardware schedule rather than materializing every ModUp digit at once.
    std::vector<std::vector<std::vector<std::uint32_t>>> accumulators(
        2, std::vector<std::vector<std::uint32_t>>(
            full_ids.size(), std::vector<std::uint32_t>(degree, 0)));
    const auto& switching = switching_component.components[0];
    for (std::size_t digit = 0; digit < evaluation_key.digits.size(); ++digit) {
        const int source_id = evaluation_key.rns_layout.key_digits[digit].front();
        const auto source_found = std::find(
            switching.modulus_ids.begin(), switching.modulus_ids.end(), source_id);
        if (source_found == switching.modulus_ids.end()) {
            throw std::invalid_argument("KeySwitch digit source is absent from active Q");
        }
        const std::size_t source_basis = static_cast<std::size_t>(
            source_found - switching.modulus_ids.begin());
        const auto source_words = memory_.read(
            switching.limbs[source_basis], degree);
        const auto source_coefficients = switching_is_coefficient
            ? source_words
            : transform_limb(
                source_words, degree, static_cast<std::uint8_t>(source_id),
                tables, true);
        if (switching_is_coefficient
            && std::any_of(
                source_coefficients.begin(), source_coefficients.end(),
                [&](std::uint32_t value) {
                    return value >= memory_.modulus(
                        static_cast<std::uint8_t>(source_id));
                })) {
            throw std::invalid_argument(
                "coefficient-domain KeySwitch source is not reduced");
        }

        for (std::size_t target_basis = 0;
             target_basis < full_ids.size(); ++target_basis) {
            const std::uint8_t target_id = full_ids[target_basis];
            const std::uint32_t target_modulus = memory_.modulus(target_id);
            std::vector<std::uint32_t> converted(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                converted[index] = static_cast<std::uint32_t>(
                    source_coefficients[index] % target_modulus);
            }
            const auto digit_ntt = transform_limb(
                converted, degree, target_id, tables, false);
            for (std::size_t component = 0; component < 2; ++component) {
                const auto key_words = memory_.read(
                    evaluation_key.digits[digit][component].limbs[target_basis],
                    degree);
                auto& accumulator = accumulators[component][target_basis];
                for (std::size_t index = 0; index < degree; ++index) {
                    accumulator[index] = add_mod(
                        accumulator[index],
                        multiply_mod(
                            digit_ntt[index], key_words[index], target_modulus),
                        target_modulus);
                }
            }
        }
    }

    const std::uint32_t p = constant_words[2];
    const std::uint32_t p_half = constant_words[3];
    for (std::size_t component = 0; component < 2; ++component) {
        auto p_coefficients = transform_limb(
            accumulators[component].back(), degree, p_id, tables, true);
        for (std::uint32_t& coefficient : p_coefficients) {
            coefficient = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(coefficient) + p_half) % p);
        }

        for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
            const std::uint8_t q_id = static_cast<std::uint8_t>(q_ids[basis]);
            const std::uint32_t q = memory_.modulus(q_id);
            std::vector<std::uint32_t> centered_p(degree);
            const std::uint32_t p_half_mod_q = p_half % q;
            for (std::size_t index = 0; index < degree; ++index) {
                centered_p[index] = subtract_mod(
                    p_coefficients[index] % q, p_half_mod_q, q);
            }
            const auto centered_p_ntt = transform_limb(
                centered_p, degree, q_id, tables, false);
            const std::uint32_t inverse_p = constant_words[6 + basis * 2];
            std::vector<std::uint32_t> result(degree);
            const auto base = memory_.read(
                base_ciphertext.components[component].limbs[basis], degree);
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t switched = multiply_mod(
                    subtract_mod(
                        accumulators[component][basis][index],
                        centered_p_ntt[index], q),
                    inverse_p, q);
                result[index] = add_mod(base[index], switched, q);
            }
            memory_.write(output.components[component].limbs[basis], result);
        }
    }
}

void CkksSoftwareExecutor::relinearize(
    const PreparedRnsObject& tensor,
    const PreparedEvaluationKey& relinearization_key,
    const PreparedKeySwitchConstants& constants,
    const PreparedRnsObject& output,
    const std::vector<PreparedCanonicalTwiddles>& tables)
{
    validate_object(tensor, 3);
    validate_object(output, 2);
    if (tensor.parms_id != output.parms_id
        || !compatible_scales(tensor.scale, output.scale)) {
        throw std::invalid_argument("CKKS Relinearize changed level or scale");
    }
    PreparedRnsObject base = tensor;
    base.components.resize(2);
    PreparedRnsObject switching = tensor;
    switching.components = {tensor.components[2]};
    key_switch(
        base, switching, relinearization_key, constants, output, tables);
}

void CkksSoftwareExecutor::rescale(
    const PreparedRnsObject& input,
    const PreparedRescaleConstants& constants,
    const PreparedRnsObject& output,
    const std::vector<PreparedCanonicalTwiddles>& tables)
{
    if (input.components.empty()
        || input.components.size() != output.components.size()) {
        throw std::invalid_argument(
            "CKKS Rescale requires matching nonempty component counts");
    }
    validate_object(input, input.components.size());
    validate_object(output, output.components.size());
    const auto source_data = context_.get_context_data(input.parms_id);
    const auto destination_data = source_data
        ? source_data->next_context_data() : nullptr;
    if (!destination_data
        || output.parms_id != destination_data->parms_id()
        || constants.source_parms_id != input.parms_id
        || constants.destination_parms_id != output.parms_id
        || constants.source_chain_index != input.chain_index
        || constants.destination_chain_index != output.chain_index
        || input.components.front().limbs.size()
            != output.components.front().limbs.size() + 1) {
        throw std::invalid_argument(
            "CKKS Rescale operands/constants are not adjacent Q levels");
    }

    const std::size_t retained_count = output.components.front().limbs.size();
    constexpr std::uint32_t format_magic = 0x52534331U;
    const auto constant_words = memory_.read(
        constants.values, 5 + retained_count * 2);
    const auto& source_ids = input.components.front().modulus_ids;
    const auto& destination_ids = output.components.front().modulus_ids;
    const std::uint8_t dropped_id = source_ids.back();
    const std::uint32_t q_last = memory_.modulus(dropped_id);
    if (constant_words[0] != format_magic
        || constant_words[1] != dropped_id
        || constant_words[2] != q_last
        || constant_words[3] != (q_last >> 1U)
        || constant_words[4] != retained_count
        || !std::equal(
            destination_ids.begin(), destination_ids.end(),
            source_ids.begin())
        || !compatible_scales(
            input.scale / static_cast<double>(q_last), output.scale)) {
        throw std::invalid_argument("invalid HPU_MEM CKKS Rescale constants");
    }
    for (std::size_t basis = 0; basis < retained_count; ++basis) {
        const std::uint32_t q = memory_.modulus(destination_ids[basis]);
        if (constant_words[5 + basis * 2] != destination_ids[basis]
            || constant_words[6 + basis * 2]
                != hpu::model::inverse_mod_prime(q_last % q, q)) {
            throw std::invalid_argument("invalid HPU_MEM inverse-q_last constant");
        }
    }

    const std::size_t degree = input.components.front().degree;
    const std::uint32_t half = constant_words[3];
    for (std::size_t component = 0; component < input.components.size(); ++component) {
        auto rounded_last = transform_limb(
            memory_.read(input.components[component].limbs.back(), degree),
            degree, dropped_id, tables, true);
        for (std::uint32_t& coefficient : rounded_last) {
            coefficient = static_cast<std::uint32_t>(
                (static_cast<std::uint64_t>(coefficient) + half) % q_last);
        }

        for (std::size_t basis = 0; basis < retained_count; ++basis) {
            const std::uint8_t q_id = destination_ids[basis];
            const std::uint32_t q = memory_.modulus(q_id);
            const std::uint32_t half_mod_q = half % q;
            std::vector<std::uint32_t> correction(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                correction[index] = subtract_mod(
                    rounded_last[index] % q, half_mod_q, q);
            }
            const auto correction_ntt = transform_limb(
                correction, degree, q_id, tables, false);
            const auto source = memory_.read(
                input.components[component].limbs[basis], degree);
            const std::uint32_t inverse_q_last =
                constant_words[6 + basis * 2];
            std::vector<std::uint32_t> result(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                result[index] = multiply_mod(
                    subtract_mod(source[index], correction_ntt[index], q),
                    inverse_q_last, q);
            }
            memory_.write(output.components[component].limbs[basis], result);
        }
    }
}

void CkksSoftwareExecutor::rotate(
    const PreparedRnsObject& input,
    std::uint32_t galois_element,
    const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedRnsObject& coefficient_workspace,
    const PreparedRnsObject& output)
{
    validate_object(input, 2);
    validate_object(coefficient_workspace, 2);
    validate_object(output, 2);
    require_same_level(input, coefficient_workspace, output);
    const std::size_t degree = input.components.front().degree;
    const std::uint64_t ring_order = 2ULL * degree;
    if ((galois_element & 1U) == 0U || galois_element >= ring_order
        || !compatible_scales(input.scale, coefficient_workspace.scale)
        || !compatible_scales(input.scale, output.scale)
        || input.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || input.key_domain != 1
        || coefficient_workspace.domain
            != hpu::runtime::PolynomialDomain::coefficient
        || coefficient_workspace.key_domain != galois_element
        || output.domain
            != hpu::runtime::PolynomialDomain::canonical_ntt_physical
        || output.key_domain != 1) {
        throw std::invalid_argument(
            "CKKS Rotate has invalid element/scale/representation metadata");
    }

    for (std::size_t component = 0; component < 2; ++component) {
        const auto& source = input.components[component];
        const auto& workspace = coefficient_workspace.components[component];
        for (std::size_t basis = 0; basis < source.limbs.size(); ++basis) {
            const std::uint8_t mod_id = source.modulus_ids[basis];
            const std::uint32_t q = memory_.modulus(mod_id);
            const auto& fused = find_fused_tables(fused_tables, mod_id);
            const auto& canonical = find_tables(canonical_tables, mod_id);
            if (fused.modulus != q || canonical.modulus != q
                || fused.canonical_psi != canonical.canonical_psi
                || hpu::model::pow_mod(
                    fused.modified_psi, galois_element, q)
                    != fused.canonical_psi) {
                throw std::invalid_argument(
                    "modified-root Rotate table does not match k or canonical psi");
            }
            hpu::model::HardwareNttModel model(
                degree, q,
                hpu::model::pow_mod(fused.modified_psi, 2, q));
            hpu::model::InverseNttTables inverse_tables;
            inverse_tables.stages.reserve(fused.inverse_stages.size());
            for (const auto& span : fused.inverse_stages) {
                inverse_tables.stages.push_back(memory_.read(span, degree / 2));
            }
            inverse_tables.post_scale = memory_.read(
                fused.post_untwist_scale, degree);
            const auto transformed = model.inverse(
                memory_.read(source.limbs[basis], degree), inverse_tables);
            memory_.write(workspace.limbs[basis], transformed);
        }
    }

    // sigma_k(c0) is the base; sigma_k(c1) is switched from key domain k
    // back to the canonical secret-key domain. The coefficient workspace is
    // the only state needed if fused INTT and KeySwitch cross a kernel boundary.
    for (std::size_t basis = 0;
         basis < output.components.front().limbs.size(); ++basis) {
        const std::uint8_t mod_id = output.components[0].modulus_ids[basis];
        memory_.write(
            output.components[0].limbs[basis],
            transform_limb(
                memory_.read(
                    coefficient_workspace.components[0].limbs[basis], degree),
                degree, mod_id, canonical_tables, false));
        memory_.write(
            output.components[1].limbs[basis],
            std::vector<std::uint32_t>(degree, 0));
    }
    PreparedRnsObject switching = coefficient_workspace;
    switching.components = {coefficient_workspace.components[1]};
    key_switch_impl(
        output, switching, galois_key, constants, output,
        canonical_tables, true);
}

void CkksSoftwareExecutor::rotate_slots(
    const PreparedRnsObject& input,
    int steps,
    const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedRnsObject& coefficient_workspace,
    const PreparedRnsObject& output)
{
    const std::size_t degree = input.components.empty()
        ? 0
        : input.components.front().degree;
    rotate(
        input,
        hpu::scheme::ckks::rotation_galois_element(degree, steps),
        galois_key, constants, fused_tables, canonical_tables,
        coefficient_workspace, output);
}

void CkksSoftwareExecutor::conjugate(
    const PreparedRnsObject& input,
    const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedRnsObject& coefficient_workspace,
    const PreparedRnsObject& output)
{
    const std::size_t degree = input.components.empty()
        ? 0
        : input.components.front().degree;
    rotate(
        input,
        hpu::scheme::ckks::conjugation_galois_element(degree),
        galois_key, constants, fused_tables, canonical_tables,
        coefficient_workspace, output);
}

void CkksSoftwareExecutor::transform(
    const PreparedRnsObject& input,
    const PreparedRnsObject& output,
    const std::vector<PreparedCanonicalTwiddles>& tables,
    bool inverse)
{
    if (input.components.empty()) {
        throw std::invalid_argument("CKKS transform needs at least one component");
    }
    validate_object(input, input.components.size());
    validate_object(output, input.components.size());
    if (input.parms_id != output.parms_id
        || !compatible_scales(input.scale, output.scale)
        || input.key_domain != output.key_domain
        || input.domain != (inverse
            ? hpu::runtime::PolynomialDomain::canonical_ntt_physical
            : hpu::runtime::PolynomialDomain::coefficient)
        || output.domain != (inverse
            ? hpu::runtime::PolynomialDomain::coefficient
            : hpu::runtime::PolynomialDomain::canonical_ntt_physical)) {
        throw std::invalid_argument(
            "CKKS transform has incompatible level/scale/representation metadata");
    }

    for (std::size_t component = 0; component < input.components.size(); ++component) {
        const auto& source = input.components[component];
        const auto& destination = output.components[component];
        for (std::size_t basis = 0; basis < source.limbs.size(); ++basis) {
            const std::uint8_t mod_id = source.modulus_ids[basis];
            const auto transformed = transform_limb(
                memory_.read(source.limbs[basis], source.degree),
                source.degree, mod_id, tables, inverse);
            memory_.write(destination.limbs[basis], transformed);
        }
    }
}

void CkksSoftwareExecutor::forward_ntt(
    const PreparedRnsObject& coefficient,
    const PreparedRnsObject& canonical_ntt,
    const std::vector<PreparedCanonicalTwiddles>& tables)
{
    transform(coefficient, canonical_ntt, tables, false);
}

void CkksSoftwareExecutor::inverse_ntt(
    const PreparedRnsObject& canonical_ntt,
    const PreparedRnsObject& coefficient,
    const std::vector<PreparedCanonicalTwiddles>& tables)
{
    transform(canonical_ntt, coefficient, tables, true);
}

HpuRnsPolynomial CkksSoftwareExecutor::export_component(
    const PreparedRnsObject& object,
    std::size_t component) const
{
    validate_object(object, object.components.size());
    if (component >= object.components.size()) {
        throw std::out_of_range("CKKS software output component is out of range");
    }
    const auto data = context_.get_context_data(object.parms_id);
    const auto& polynomial = object.components[component];
    const auto& seal_moduli = data->parms().coeff_modulus();
    HpuRnsPolynomial result;
    result.degree = polynomial.degree;
    result.modulus_ids = polynomial.modulus_ids;
    result.moduli.reserve(seal_moduli.size());
    result.words.reserve(polynomial.degree * seal_moduli.size());
    for (std::size_t basis = 0; basis < seal_moduli.size(); ++basis) {
        const std::uint32_t modulus = memory_.modulus(
            polynomial.modulus_ids[basis]);
        if (modulus != seal_moduli[basis].value()) {
            throw std::logic_error("HPU modulus table differs from SEALContext");
        }
        result.moduli.push_back(modulus);
        const auto limb = memory_.read(
            polynomial.limbs[basis], polynomial.degree);
        result.words.insert(result.words.end(), limb.begin(), limb.end());
    }
    return result;
}

const hpu::runtime::HpuSoftwareExecutor&
CkksSoftwareExecutor::memory() const noexcept
{
    return memory_;
}

} // namespace hpu::seal_adapter
