#include "hpu/seal/bfv_software_executor.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "scheme/bfv/galois.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::size_t bit_reverse(std::size_t value, std::size_t degree)
{
    std::size_t result = 0;
    for (std::size_t width = degree; width > 1; width >>= 1U) {
        result = (result << 1U) | (value & 1U);
        value >>= 1U;
    }
    return result;
}

std::uint32_t add_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    const std::uint64_t sum = static_cast<std::uint64_t>(left) + right;
    return static_cast<std::uint32_t>(sum >= modulus ? sum - modulus : sum);
}

std::uint32_t subtract_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return left >= right
               ? left - right
               : static_cast<std::uint32_t>(static_cast<std::uint64_t>(left) + modulus - right);
}

std::uint32_t multiply_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) * right) % modulus);
}

const PreparedCanonicalTwiddles& find_tables(const std::vector<PreparedCanonicalTwiddles>& tables,
                                             std::uint8_t modulus_id)
{
    const auto found = std::find_if(tables.begin(), tables.end(), [&](const auto& table) {
        return table.modulus_id == modulus_id;
    });
    if (found == tables.end()) {
        throw std::invalid_argument("BFV software executor lacks canonical twiddles for MOD_ID");
    }
    return *found;
}

const PreparedFusedAutomorphismTwiddles& find_fused_tables(
    const std::vector<PreparedFusedAutomorphismTwiddles>& tables, std::uint8_t modulus_id)
{
    const auto found = std::find_if(tables.begin(), tables.end(), [&](const auto& table) {
        return table.modulus_id == modulus_id;
    });
    if (found == tables.end()) {
        throw std::invalid_argument("BFV software executor lacks fused twiddles for MOD_ID");
    }
    return *found;
}

std::string mod_id(const std::string& prefix, int modulus_id)
{
    return prefix + "/mod" + std::to_string(modulus_id);
}

} // namespace

BfvSoftwareExecutor::BfvSoftwareExecutor(const ::seal::SEALContext& context,
                                         const hpu::runtime::HpuMemImage& image)
    : image_(image), level_chain_(context), memory_(image)
{
    const auto key_data = context.key_context_data();
    if (!key_data || key_data->parms().scheme() != ::seal::scheme_type::bfv) {
        throw std::invalid_argument("BFV software executor requires a BFV SEALContext");
    }
    memory_.load_modulus_table(image.allocation("constants/modulus_table").span,
                               level_chain_.registry().modulus_table.size());
}

void BfvSoftwareExecutor::validate_object(const PreparedBfvRnsObject& object,
                                          std::size_t component_count,
                                          hpu::runtime::PolynomialDomain domain,
                                          std::uint64_t key_domain) const
{
    const auto& level = level_chain_.require(object.parms_id);
    if (object.chain_index != level.chain_index || object.components.size() != component_count ||
        object.domain != domain || object.key_domain != key_domain) {
        throw std::invalid_argument("prepared BFV object has invalid metadata or component count");
    }
    for (const auto& polynomial : object.components) {
        if (polynomial.degree != level_chain_.registry().poly_modulus_degree ||
            polynomial.limbs.size() != level.keyswitch_layout.q_mod_ids.size() ||
            polynomial.modulus_ids.size() != polynomial.limbs.size()) {
            throw std::invalid_argument("prepared BFV object has an invalid RNS shape");
        }
        for (std::size_t basis = 0; basis < polynomial.modulus_ids.size(); ++basis) {
            if (polynomial.modulus_ids[basis] != level.keyswitch_layout.q_mod_ids[basis]) {
                throw std::invalid_argument("prepared BFV object has an unstable MOD_ID order");
            }
        }
    }
}

BfvSoftwareExecutor::RnsPolynomial
BfvSoftwareExecutor::read_polynomial(const PreparedPolynomial& polynomial) const
{
    RnsPolynomial result;
    result.reserve(polynomial.limbs.size());
    for (const auto& limb : polynomial.limbs) {
        result.push_back(memory_.read(limb, polynomial.degree));
    }
    return result;
}

void BfvSoftwareExecutor::write_polynomial(const PreparedPolynomial& polynomial,
                                           const RnsPolynomial& words)
{
    if (words.size() != polynomial.limbs.size()) {
        throw std::invalid_argument("BFV software result has the wrong RNS limb count");
    }
    for (std::size_t basis = 0; basis < words.size(); ++basis) {
        if (words[basis].size() != polynomial.degree) {
            throw std::invalid_argument("BFV software result has the wrong polynomial degree");
        }
        memory_.write(polynomial.limbs[basis], words[basis]);
    }
}

std::uint32_t BfvSoftwareExecutor::constant_value(const std::string& id, std::size_t degree,
                                                  std::uint32_t modulus) const
{
    const auto words = memory_.read(image_.allocation(id).span, degree);
    if (words.empty() || words.front() >= modulus ||
        !std::all_of(words.begin(), words.end(),
                     [&](std::uint32_t word) { return word == words.front(); })) {
        throw std::invalid_argument("BFV HPU_MEM constant polynomial is invalid: " + id);
    }
    return words.front();
}

BfvSoftwareExecutor::Limb
BfvSoftwareExecutor::transform_limb(const Limb& words, std::size_t degree, std::uint8_t modulus_id,
                                    const std::vector<PreparedCanonicalTwiddles>& tables,
                                    bool inverse) const
{
    if (words.size() != degree) {
        throw std::invalid_argument("BFV transform limb has an invalid degree");
    }
    const std::uint32_t modulus = memory_.modulus(modulus_id);
    const auto& prepared = find_tables(tables, modulus_id);
    if (prepared.modulus != modulus) {
        throw std::invalid_argument("BFV canonical twiddle modulus mismatch");
    }
    hpu::model::HardwareNttModel model(degree, modulus,
                                       hpu::model::pow_mod(prepared.canonical_psi, 2, modulus));
    if (inverse) {
        hpu::model::InverseNttTables inverse_tables;
        inverse_tables.stages.reserve(prepared.inverse_stages.size());
        for (const auto& span : prepared.inverse_stages) {
            inverse_tables.stages.push_back(memory_.read(span, degree / 2));
        }
        inverse_tables.post_scale = memory_.read(prepared.post_untwist_scale, degree);
        return model.inverse(words, inverse_tables);
    }

    std::vector<std::vector<std::uint32_t>> forward_tables;
    forward_tables.reserve(prepared.forward_stages.size());
    for (const auto& span : prepared.forward_stages) {
        forward_tables.push_back(memory_.read(span, degree / 2));
    }
    const auto pre_twist = memory_.read(prepared.pre_twist, degree);
    Limb coefficients = words;
    for (std::size_t index = 0; index < degree; ++index) {
        if (coefficients[index] >= modulus) {
            throw std::invalid_argument("BFV transform input is not reduced modulo q");
        }
        coefficients[index] =
            multiply_mod(coefficients[index], pre_twist[bit_reverse(index, degree)], modulus);
    }
    return model.forward(coefficients, forward_tables);
}

BfvSoftwareExecutor::RnsPolynomial
BfvSoftwareExecutor::base_convert(const RnsPolynomial& input, const std::vector<int>& sources,
                                  const std::vector<int>& targets, const std::string& prefix,
                                  const std::string& inverse_prefix)
{
    if (input.size() != sources.size() || sources.empty() || targets.empty()) {
        throw std::invalid_argument("BFV software BConv has an invalid base shape");
    }
    const std::size_t degree = input.front().size();
    RnsPolynomial normalized(sources.size(), Limb(degree));
    const std::string& inverse_base = inverse_prefix.empty() ? prefix : inverse_prefix;
    for (std::size_t source = 0; source < sources.size(); ++source) {
        if (input[source].size() != degree) {
            throw std::invalid_argument("BFV software BConv input degrees differ");
        }
        const std::uint32_t modulus = memory_.modulus(static_cast<std::uint8_t>(sources[source]));
        const std::uint32_t inverse =
            constant_value(mod_id(inverse_base + "/qhat_inv", sources[source]), degree, modulus);
        for (std::size_t index = 0; index < degree; ++index) {
            normalized[source][index] = multiply_mod(input[source][index], inverse, modulus);
        }
    }

    RnsPolynomial result(targets.size(), Limb(degree, 0));
    for (std::size_t target = 0; target < targets.size(); ++target) {
        const std::uint32_t modulus = memory_.modulus(static_cast<std::uint8_t>(targets[target]));
        for (std::size_t source = 0; source < sources.size(); ++source) {
            const std::uint32_t factor = constant_value(
                prefix + "/qhat_mod_target/target" + std::to_string(targets[target]) + "/source" +
                    std::to_string(sources[source]),
                degree, modulus);
            for (std::size_t index = 0; index < degree; ++index) {
                result[target][index] = add_mod(
                    result[target][index],
                    multiply_mod(normalized[source][index] % modulus, factor, modulus), modulus);
            }
        }
    }
    return result;
}

void BfvSoftwareExecutor::ciphertext_binary(const PreparedBfvRnsObject& left,
                                            const PreparedBfvRnsObject& right,
                                            const PreparedBfvRnsObject& output,
                                            hpu::runtime::PointwiseOperation operation)
{
    validate_object(left, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(right, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    if (left.parms_id != right.parms_id || left.parms_id != output.parms_id ||
        operation == hpu::runtime::PointwiseOperation::multiply) {
        throw std::invalid_argument("BFV Add/Subtract operands or operation are invalid");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const auto& left_polynomial = left.components[component];
        const auto& right_polynomial = right.components[component];
        const auto& output_polynomial = output.components[component];
        for (std::size_t basis = 0; basis < left_polynomial.limbs.size(); ++basis) {
            memory_.pointwise(output_polynomial.limbs[basis], left_polynomial.limbs[basis],
                              right_polynomial.limbs[basis], left_polynomial.degree,
                              left_polynomial.modulus_ids[basis], operation);
        }
    }
}

void BfvSoftwareExecutor::add(const PreparedBfvRnsObject& left, const PreparedBfvRnsObject& right,
                              const PreparedBfvRnsObject& output)
{
    ciphertext_binary(left, right, output, hpu::runtime::PointwiseOperation::add);
}

void BfvSoftwareExecutor::subtract(const PreparedBfvRnsObject& left,
                                   const PreparedBfvRnsObject& right,
                                   const PreparedBfvRnsObject& output)
{
    ciphertext_binary(left, right, output, hpu::runtime::PointwiseOperation::subtract);
}

void BfvSoftwareExecutor::plaintext_binary(const PreparedBfvRnsObject& ciphertext,
                                           const PreparedBfvRnsObject& plaintext,
                                           const PreparedBfvRnsObject& output,
                                           hpu::runtime::PointwiseOperation operation)
{
    validate_object(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(plaintext, 1, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    if (ciphertext.parms_id != plaintext.parms_id || ciphertext.parms_id != output.parms_id ||
        operation == hpu::runtime::PointwiseOperation::multiply) {
        throw std::invalid_argument("BFV AddPlain/SubtractPlain operands or operation are invalid");
    }
    for (std::size_t basis = 0; basis < ciphertext.components[0].limbs.size(); ++basis) {
        memory_.pointwise(output.components[0].limbs[basis], ciphertext.components[0].limbs[basis],
                          plaintext.components[0].limbs[basis], ciphertext.components[0].degree,
                          ciphertext.components[0].modulus_ids[basis], operation);
        memory_.copy(output.components[1].limbs[basis], ciphertext.components[1].limbs[basis],
                     ciphertext.components[1].degree);
    }
}

void BfvSoftwareExecutor::add_plain(const PreparedBfvRnsObject& ciphertext,
                                    const PreparedBfvRnsObject& plaintext,
                                    const PreparedBfvRnsObject& output)
{
    plaintext_binary(ciphertext, plaintext, output, hpu::runtime::PointwiseOperation::add);
}

void BfvSoftwareExecutor::subtract_plain(const PreparedBfvRnsObject& ciphertext,
                                         const PreparedBfvRnsObject& plaintext,
                                         const PreparedBfvRnsObject& output)
{
    plaintext_binary(ciphertext, plaintext, output, hpu::runtime::PointwiseOperation::subtract);
}

void BfvSoftwareExecutor::multiply_plain(const PreparedBfvRnsObject& ciphertext,
                                         const PreparedBfvRnsObject& plaintext,
                                         const std::vector<PreparedCanonicalTwiddles>& tables,
                                         const PreparedBfvRnsObject& output)
{
    validate_object(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(plaintext, 1, hpu::runtime::PolynomialDomain::canonical_ntt_physical);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    if (ciphertext.parms_id != plaintext.parms_id || ciphertext.parms_id != output.parms_id) {
        throw std::invalid_argument("BFV MultiplyPlain operands are at different levels");
    }
    const std::size_t degree = level_chain_.registry().poly_modulus_degree;
    const auto plain = read_polynomial(plaintext.components[0]);
    for (std::size_t component = 0; component < 2; ++component) {
        const auto coefficients = read_polynomial(ciphertext.components[component]);
        RnsPolynomial result(coefficients.size(), Limb(degree));
        for (std::size_t basis = 0; basis < coefficients.size(); ++basis) {
            const std::uint8_t modulus_id = ciphertext.components[component].modulus_ids[basis];
            const std::uint32_t modulus = memory_.modulus(modulus_id);
            auto transformed =
                transform_limb(coefficients[basis], degree, modulus_id, tables, false);
            for (std::size_t index = 0; index < degree; ++index) {
                if (plain[basis][index] >= modulus) {
                    throw std::invalid_argument(
                        "BFV MultiplyPlain plaintext is not reduced modulo q");
                }
                transformed[index] = multiply_mod(transformed[index], plain[basis][index], modulus);
            }
            result[basis] = transform_limb(transformed, degree, modulus_id, tables, true);
        }
        write_polynomial(output.components[component], result);
    }
}

void BfvSoftwareExecutor::negate(const PreparedBfvRnsObject& ciphertext,
                                 const PreparedBfvRnsObject& output)
{
    validate_object(ciphertext, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    if (ciphertext.parms_id != output.parms_id) {
        throw std::invalid_argument("BFV Negate input and output are at different levels");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        auto result = read_polynomial(ciphertext.components[component]);
        for (std::size_t basis = 0; basis < result.size(); ++basis) {
            const std::uint32_t modulus =
                memory_.modulus(ciphertext.components[component].modulus_ids[basis]);
            for (auto& word : result[basis]) {
                if (word >= modulus) {
                    throw std::invalid_argument("BFV Negate input is not reduced modulo q");
                }
                word = word == 0 ? 0 : modulus - word;
            }
        }
        write_polynomial(output.components[component], result);
    }
}

void BfvSoftwareExecutor::mod_switch(const PreparedBfvRnsObject& input,
                                     const PreparedBfvModSwitchConstants& constants,
                                     const PreparedBfvRnsObject& output)
{
    validate_object(input, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    const auto& source = level_chain_.require(input.parms_id);
    const auto& destination = level_chain_.require(output.parms_id);
    if (!level_chain_.has_next(source.parms_id) ||
        level_chain_.next(source.parms_id).parms_id != destination.parms_id ||
        constants.source_parms_id != source.parms_id ||
        constants.destination_parms_id != destination.parms_id) {
        throw std::invalid_argument("BFV software ModSwitch requires matching adjacent levels");
    }

    constexpr std::uint32_t format_magic = 0x424d5331U;
    const std::size_t retained_count = destination.q_moduli.size();
    const auto words = memory_.read(constants.values, 5 + 2 * retained_count);
    const std::uint32_t q_last = source.q_moduli.back();
    const std::uint32_t half = q_last >> 1U;
    if (words[0] != format_magic ||
        words[1] != static_cast<std::uint32_t>(constants.dropped_mod_id) || words[2] != q_last ||
        words[3] != half || words[4] != retained_count) {
        throw std::invalid_argument("invalid compact BFV ModSwitch constants");
    }

    const std::size_t degree = level_chain_.registry().poly_modulus_degree;
    for (std::size_t component = 0; component < 2; ++component) {
        const auto source_words = read_polynomial(input.components[component]);
        RnsPolynomial result(retained_count, Limb(degree));
        const auto& dropped = source_words.back();
        for (std::size_t basis = 0; basis < retained_count; ++basis) {
            const std::uint32_t modulus = destination.q_moduli[basis];
            if (words[5 + 2 * basis] !=
                    static_cast<std::uint32_t>(destination.keyswitch_layout.q_mod_ids[basis]) ||
                words[6 + 2 * basis] != hpu::model::inverse_mod_prime(q_last % modulus, modulus)) {
                throw std::invalid_argument("invalid compact BFV ModSwitch inverse");
            }
            const std::uint32_t inverse = words[6 + 2 * basis];
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t rounded = static_cast<std::uint32_t>(
                    (static_cast<std::uint64_t>(dropped[index]) + half) % q_last);
                const std::uint32_t correction =
                    subtract_mod(rounded % modulus, half % modulus, modulus);
                result[basis][index] =
                    multiply_mod(subtract_mod(source_words[basis][index], correction, modulus),
                                 inverse, modulus);
            }
        }
        write_polynomial(output.components[component], result);
    }
}

void BfvSoftwareExecutor::multiply(const PreparedBfvRnsObject& left,
                                   const PreparedBfvRnsObject& right,
                                   const PreparedEvaluationKey& relinearization_key,
                                   const PreparedKeySwitchConstants& keyswitch_constants,
                                   const PreparedBfvMultiplyConstants& multiply_constants,
                                   const std::vector<PreparedCanonicalTwiddles>& tables,
                                   const PreparedBfvRnsObject& output)
{
    validate_object(left, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(right, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    if (left.parms_id != right.parms_id || left.parms_id != output.parms_id) {
        throw std::invalid_argument("BFV software Multiply operands are at different levels");
    }
    const auto& level = level_chain_.require(left.parms_id);
    const auto& q_ids = level.keyswitch_layout.q_mod_ids;
    const auto& b_ids = level.b_mod_ids;
    std::vector<int> bsk_ids = b_ids;
    bsk_ids.push_back(level.m_sk_mod_id);
    std::vector<int> contexts = q_ids;
    contexts.insert(contexts.end(), bsk_ids.begin(), bsk_ids.end());
    const std::size_t degree = level_chain_.registry().poly_modulus_degree;

    constexpr std::uint32_t multiply_magic = 0x42465631U;
    const auto compact =
        memory_.read(multiply_constants.values, 8 + 2 * q_ids.size() + 2 * b_ids.size());
    if (multiply_constants.data_parms_id != level.parms_id ||
        multiply_constants.chain_index != level.chain_index || compact[0] != multiply_magic ||
        compact[1] != degree || compact[2] != q_ids.size() || compact[3] != b_ids.size() ||
        compact[4] != static_cast<std::uint32_t>(level.m_sk_mod_id) ||
        compact[5] != static_cast<std::uint32_t>(level.plaintext_mod_id) ||
        compact[6] != level.m_sk || compact[7] != level.plaintext_modulus) {
        throw std::invalid_argument("invalid compact BFV Multiply constants");
    }
    for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
        if (compact[8 + 2 * basis] != static_cast<std::uint32_t>(q_ids[basis]) ||
            compact[9 + 2 * basis] != level.q_moduli[basis]) {
            throw std::invalid_argument("compact BFV Multiply Q base mismatch");
        }
    }
    const std::size_t b_offset = 8 + 2 * q_ids.size();
    for (std::size_t basis = 0; basis < b_ids.size(); ++basis) {
        if (compact[b_offset + 2 * basis] != static_cast<std::uint32_t>(b_ids[basis]) ||
            compact[b_offset + 2 * basis + 1] != level.b_moduli[basis]) {
            throw std::invalid_argument("compact BFV Multiply B base mismatch");
        }
    }

    const std::string multiply_prefix = multiply_constants.hardware_prefix;
    std::vector<RnsPolynomial> operands;
    operands.reserve(4);
    for (const auto* polynomial :
         {&left.components[0], &left.components[1], &right.components[0], &right.components[1]}) {
        const auto q_coefficients = read_polynomial(*polynomial);
        const auto bsk_coefficients =
            base_convert(q_coefficients, q_ids, bsk_ids, multiply_prefix + "/q_to_bsk");
        RnsPolynomial transformed;
        transformed.reserve(contexts.size());
        for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
            transformed.push_back(transform_limb(q_coefficients[basis], degree,
                                                 static_cast<std::uint8_t>(q_ids[basis]), tables,
                                                 false));
        }
        for (std::size_t basis = 0; basis < bsk_ids.size(); ++basis) {
            transformed.push_back(transform_limb(bsk_coefficients[basis], degree,
                                                 static_cast<std::uint8_t>(bsk_ids[basis]), tables,
                                                 false));
        }
        operands.push_back(std::move(transformed));
    }

    std::vector<RnsPolynomial> tensor(3, RnsPolynomial(contexts.size(), Limb(degree)));
    for (std::size_t basis = 0; basis < contexts.size(); ++basis) {
        const std::uint32_t modulus = memory_.modulus(static_cast<std::uint8_t>(contexts[basis]));
        for (std::size_t index = 0; index < degree; ++index) {
            tensor[0][basis][index] =
                multiply_mod(operands[0][basis][index], operands[2][basis][index], modulus);
            tensor[1][basis][index] =
                add_mod(multiply_mod(operands[0][basis][index], operands[3][basis][index], modulus),
                        multiply_mod(operands[1][basis][index], operands[2][basis][index], modulus),
                        modulus);
            tensor[2][basis][index] =
                multiply_mod(operands[1][basis][index], operands[3][basis][index], modulus);
        }
    }

    for (auto& component : tensor) {
        for (std::size_t basis = 0; basis < contexts.size(); ++basis) {
            const std::uint8_t context = static_cast<std::uint8_t>(contexts[basis]);
            const std::uint32_t modulus = memory_.modulus(context);
            component[basis] = transform_limb(component[basis], degree, context, tables, true);
            for (auto& word : component[basis]) {
                word = multiply_mod(word, level.plaintext_modulus % modulus, modulus);
            }
        }
    }

    std::vector<RnsPolynomial> scaled_tensor(3, RnsPolynomial(q_ids.size(), Limb(degree)));
    for (std::size_t component = 0; component < tensor.size(); ++component) {
        RnsPolynomial q_part(tensor[component].begin(),
                             tensor[component].begin() + static_cast<std::ptrdiff_t>(q_ids.size()));
        RnsPolynomial bsk_part(tensor[component].begin() +
                                   static_cast<std::ptrdiff_t>(q_ids.size()),
                               tensor[component].end());
        const auto converted = base_convert(q_part, q_ids, bsk_ids, multiply_prefix + "/q_to_bsk");
        RnsPolynomial fast_floor(bsk_ids.size(), Limb(degree));
        for (std::size_t basis = 0; basis < bsk_ids.size(); ++basis) {
            const std::uint32_t modulus =
                memory_.modulus(static_cast<std::uint8_t>(bsk_ids[basis]));
            const std::uint32_t inverse = constant_value(
                mod_id(multiply_prefix + "/fast_floor/q_inverse", bsk_ids[basis]), degree, modulus);
            for (std::size_t index = 0; index < degree; ++index) {
                fast_floor[basis][index] = multiply_mod(
                    subtract_mod(bsk_part[basis][index], converted[basis][index], modulus), inverse,
                    modulus);
            }
        }

        RnsPolynomial b_part(fast_floor.begin(),
                             fast_floor.begin() + static_cast<std::ptrdiff_t>(b_ids.size()));
        auto y = base_convert(b_part, b_ids, q_ids, multiply_prefix + "/b_to_q");
        const auto temp_msk =
            base_convert(b_part, b_ids, {level.m_sk_mod_id}, multiply_prefix + "/b_to_msk",
                         multiply_prefix + "/b_to_q");
        const std::uint32_t b_inverse =
            constant_value(mod_id(multiply_prefix + "/branchless/b_inverse", level.m_sk_mod_id),
                           degree, level.m_sk);
        RnsPolynomial alpha_msk(1, Limb(degree));
        for (std::size_t index = 0; index < degree; ++index) {
            alpha_msk[0][index] =
                multiply_mod(subtract_mod(temp_msk[0][index], fast_floor.back()[index], level.m_sk),
                             b_inverse, level.m_sk);
        }
        const auto alpha_q =
            base_convert(alpha_msk, {level.m_sk_mod_id}, q_ids, multiply_prefix + "/msk_to_q");
        for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
            const std::uint32_t modulus = level.q_moduli[basis];
            const std::uint32_t negative_b = constant_value(
                mod_id(multiply_prefix + "/branchless/negative_b", q_ids[basis]), degree, modulus);
            for (std::size_t index = 0; index < degree; ++index) {
                y[basis][index] =
                    add_mod(y[basis][index],
                            multiply_mod(alpha_q[basis][index], negative_b, modulus), modulus);
            }
        }
        scaled_tensor[component] = std::move(y);
    }

    key_switch_coefficients(scaled_tensor[2], scaled_tensor[0], &scaled_tensor[1], level,
                            relinearization_key, keyswitch_constants, tables, output);
}

void BfvSoftwareExecutor::key_switch_coefficients(
    const RnsPolynomial& switching, const RnsPolynomial& base0, const RnsPolynomial* base1,
    const BfvLevelDescriptor& level, const PreparedEvaluationKey& evaluation_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const std::vector<PreparedCanonicalTwiddles>& tables, const PreparedBfvRnsObject& output)
{
    const auto& q_ids = level.keyswitch_layout.q_mod_ids;
    const std::size_t degree = level_chain_.registry().poly_modulus_degree;
    if (level.keyswitch_layout.p_mod_ids.size() != 1 || switching.size() != q_ids.size() ||
        base0.size() != q_ids.size() || (base1 && base1->size() != q_ids.size())) {
        throw std::invalid_argument("BFV KeySwitch has an invalid single-P RNS shape");
    }
    const int p_id = level.keyswitch_layout.p_mod_ids.front();
    std::vector<int> full_ids = q_ids;
    full_ids.push_back(p_id);
    if (evaluation_key.data_parms_id != level.parms_id ||
        evaluation_key.chain_index != level.chain_index ||
        evaluation_key.rns_layout.q_mod_ids != q_ids ||
        evaluation_key.rns_layout.p_mod_ids != std::vector<int>{p_id} ||
        evaluation_key.rns_layout.key_digits.size() != q_ids.size() ||
        evaluation_key.digits.size() != q_ids.size()) {
        throw std::invalid_argument("BFV evaluation key does not match KeySwitch level");
    }
    std::vector<RnsPolynomial> accumulators(2, RnsPolynomial(full_ids.size(), Limb(degree, 0)));
    for (std::size_t digit = 0; digit < q_ids.size(); ++digit) {
        if (switching[digit].size() != degree || evaluation_key.digits[digit].size() != 2 ||
            evaluation_key.rns_layout.key_digits[digit] != std::vector<int>{q_ids[digit]}) {
            throw std::invalid_argument("BFV evaluation key digit shape is invalid");
        }
        for (std::size_t target = 0; target < full_ids.size(); ++target) {
            const std::uint8_t target_id = static_cast<std::uint8_t>(full_ids[target]);
            const std::uint32_t modulus = memory_.modulus(target_id);
            Limb converted(degree);
            for (std::size_t index = 0; index < degree; ++index) {
                converted[index] = switching[digit][index] % modulus;
            }
            const auto digit_ntt = transform_limb(converted, degree, target_id, tables, false);
            for (std::size_t key_component = 0; key_component < 2; ++key_component) {
                const auto& key_polynomial = evaluation_key.digits[digit][key_component];
                if (key_polynomial.degree != degree ||
                    key_polynomial.limbs.size() != full_ids.size() ||
                    key_polynomial.modulus_ids.size() != full_ids.size() ||
                    key_polynomial.modulus_ids[target] != target_id) {
                    throw std::invalid_argument("BFV evaluation key MOD_ID order is invalid");
                }
                const auto key_words = memory_.read(key_polynomial.limbs[target], degree);
                for (std::size_t index = 0; index < degree; ++index) {
                    accumulators[key_component][target][index] =
                        add_mod(accumulators[key_component][target][index],
                                multiply_mod(digit_ntt[index], key_words[index], modulus), modulus);
                }
            }
        }
    }
    for (auto& component : accumulators) {
        for (std::size_t basis = 0; basis < full_ids.size(); ++basis) {
            component[basis] = transform_limb(
                component[basis], degree, static_cast<std::uint8_t>(full_ids[basis]), tables, true);
        }
    }

    constexpr std::uint32_t keyswitch_magic = 0x424b5331U;
    const auto key_constants = memory_.read(keyswitch_constants.values, 5 + 2 * q_ids.size());
    const std::uint32_t p = memory_.modulus(static_cast<std::uint8_t>(p_id));
    const std::uint32_t half_p = p >> 1U;
    if (keyswitch_constants.data_parms_id != level.parms_id ||
        keyswitch_constants.chain_index != level.chain_index ||
        key_constants[0] != keyswitch_magic ||
        key_constants[1] != static_cast<std::uint32_t>(p_id) || key_constants[2] != p ||
        key_constants[3] != half_p || key_constants[4] != q_ids.size()) {
        throw std::invalid_argument("invalid compact BFV KeySwitch constants");
    }

    std::vector<RnsPolynomial> switched(2, RnsPolynomial(q_ids.size(), Limb(degree)));
    for (std::size_t key_component = 0; key_component < 2; ++key_component) {
        Limb rounded_p = accumulators[key_component].back();
        for (auto& word : rounded_p) {
            word = static_cast<std::uint32_t>((static_cast<std::uint64_t>(word) + half_p) % p);
        }
        for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
            const std::uint32_t modulus = level.q_moduli[basis];
            if (key_constants[5 + 2 * basis] != static_cast<std::uint32_t>(q_ids[basis]) ||
                key_constants[6 + 2 * basis] !=
                    hpu::model::inverse_mod_prime(p % modulus, modulus)) {
                throw std::invalid_argument("invalid compact BFV KeySwitch inverse-P constant");
            }
            const std::uint32_t inverse_p = key_constants[6 + 2 * basis];
            for (std::size_t index = 0; index < degree; ++index) {
                const std::uint32_t centered_p =
                    subtract_mod(rounded_p[index] % modulus, half_p % modulus, modulus);
                switched[key_component][basis][index] = multiply_mod(
                    subtract_mod(accumulators[key_component][basis][index], centered_p, modulus),
                    inverse_p, modulus);
            }
        }
    }

    RnsPolynomial output0 = base0;
    RnsPolynomial output1 = base1 ? *base1 : RnsPolynomial(q_ids.size(), Limb(degree, 0));
    for (std::size_t basis = 0; basis < q_ids.size(); ++basis) {
        const std::uint32_t modulus = level.q_moduli[basis];
        if (output0[basis].size() != degree || output1[basis].size() != degree) {
            throw std::invalid_argument("BFV KeySwitch base has an invalid degree");
        }
        for (std::size_t index = 0; index < degree; ++index) {
            output0[basis][index] =
                add_mod(output0[basis][index], switched[0][basis][index], modulus);
            output1[basis][index] =
                add_mod(output1[basis][index], switched[1][basis][index], modulus);
        }
    }
    write_polynomial(output.components[0], output0);
    write_polynomial(output.components[1], output1);
}

void BfvSoftwareExecutor::rotate(
    const PreparedBfvRnsObject& input, std::uint32_t galois_element,
    const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedBfvRnsObject& coefficient_workspace,
    const PreparedBfvRnsObject& output)
{
    validate_object(input, 2, hpu::runtime::PolynomialDomain::coefficient);
    validate_object(coefficient_workspace, 2, hpu::runtime::PolynomialDomain::coefficient,
                    galois_element);
    validate_object(output, 2, hpu::runtime::PolynomialDomain::coefficient);
    const std::size_t degree = level_chain_.registry().poly_modulus_degree;
    if (input.parms_id != coefficient_workspace.parms_id ||
        input.parms_id != output.parms_id || galois_element == 0 ||
        galois_element >= 2ULL * degree || (galois_element & 1U) == 0U) {
        throw std::invalid_argument("BFV Rotate has invalid level or Galois element");
    }
    const auto& level = level_chain_.require(input.parms_id);
    if (fused_tables.size() != level.keyswitch_layout.q_mod_ids.size()) {
        throw std::invalid_argument("BFV Rotate lacks fused twiddles for active Q");
    }
    for (std::size_t component = 0; component < 2; ++component) {
        const auto& source = input.components[component];
        const auto& workspace = coefficient_workspace.components[component];
        for (std::size_t basis = 0; basis < source.limbs.size(); ++basis) {
            const std::uint8_t modulus_id = source.modulus_ids[basis];
            const std::uint32_t modulus = memory_.modulus(modulus_id);
            const auto& canonical = find_tables(canonical_tables, modulus_id);
            const auto& fused = find_fused_tables(fused_tables, modulus_id);
            if (canonical.modulus != modulus || fused.modulus != modulus ||
                fused.canonical_psi != canonical.canonical_psi ||
                hpu::model::pow_mod(fused.modified_psi, galois_element, modulus) !=
                    fused.canonical_psi) {
                throw std::invalid_argument("BFV Rotate modified-root tables do not match k");
            }
            const auto coefficients = memory_.read(source.limbs[basis], degree);
            const auto transformed =
                transform_limb(coefficients, degree, modulus_id, canonical_tables, false);
            hpu::model::HardwareNttModel model(
                degree, modulus, hpu::model::pow_mod(fused.modified_psi, 2, modulus));
            hpu::model::InverseNttTables inverse_tables;
            inverse_tables.stages.reserve(fused.inverse_stages.size());
            for (const auto& span : fused.inverse_stages) {
                inverse_tables.stages.push_back(memory_.read(span, degree / 2));
            }
            inverse_tables.post_scale = memory_.read(fused.post_untwist_scale, degree);
            memory_.write(workspace.limbs[basis], model.inverse(transformed, inverse_tables));
        }
    }

    key_switch_coefficients(read_polynomial(coefficient_workspace.components[1]),
                            read_polynomial(coefficient_workspace.components[0]), nullptr, level,
                            galois_key, keyswitch_constants, canonical_tables, output);
}

void BfvSoftwareExecutor::rotate_rows(
    const PreparedBfvRnsObject& input, int steps, const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedBfvRnsObject& coefficient_workspace, const PreparedBfvRnsObject& output)
{
    rotate(input, hpu::scheme::bfv::row_rotation_galois_element(
                      level_chain_.registry().poly_modulus_degree, steps),
           galois_key, keyswitch_constants, fused_tables, canonical_tables,
           coefficient_workspace, output);
}

void BfvSoftwareExecutor::rotate_columns(
    const PreparedBfvRnsObject& input, const PreparedEvaluationKey& galois_key,
    const PreparedKeySwitchConstants& keyswitch_constants,
    const std::vector<PreparedFusedAutomorphismTwiddles>& fused_tables,
    const std::vector<PreparedCanonicalTwiddles>& canonical_tables,
    const PreparedBfvRnsObject& coefficient_workspace, const PreparedBfvRnsObject& output)
{
    rotate(input, hpu::scheme::bfv::column_rotation_galois_element(
                      level_chain_.registry().poly_modulus_degree),
           galois_key, keyswitch_constants, fused_tables, canonical_tables,
           coefficient_workspace, output);
}

HpuRnsPolynomial BfvSoftwareExecutor::export_component(const PreparedBfvRnsObject& object,
                                                       std::size_t component) const
{
    validate_object(object, object.components.size(), object.domain);
    if (component >= object.components.size()) {
        throw std::out_of_range("BFV software output component is out of range");
    }
    const auto& level = level_chain_.require(object.parms_id);
    const auto& polynomial = object.components[component];
    HpuRnsPolynomial result;
    result.degree = polynomial.degree;
    result.modulus_ids = polynomial.modulus_ids;
    result.moduli = level.q_moduli;
    for (const auto& limb : polynomial.limbs) {
        const auto words = memory_.read(limb, polynomial.degree);
        result.words.insert(result.words.end(), words.begin(), words.end());
    }
    return result;
}

const hpu::runtime::HpuSoftwareExecutor& BfvSoftwareExecutor::memory() const noexcept
{
    return memory_;
}

} // namespace hpu::seal_adapter
