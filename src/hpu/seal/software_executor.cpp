#include "hpu/seal/software_executor.hpp"

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
