#include "hpu/seal/application_image.hpp"
#include "hpu/seal/ckks_context.hpp"
#include "hpu/seal/ckks_metadata.hpp"

#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>

namespace {

void require(bool condition, const char* message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

template <typename Function>
void require_invalid_argument(Function action, const char* message)
{
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    throw std::runtime_error(message);
}

} // namespace

int main()
{
    try {
        hpu::seal_adapter::CkksContextSpec spec;
        spec.poly_modulus_degree = 128;
        spec.coeff_modulus_bits = {20, 20, 20, 20};
        const auto bundle = hpu::seal_adapter::create_ckks_context(spec);
        const hpu::seal_adapter::CkksLevelChain chain(*bundle.context);

        const auto& top = chain.top();
        const auto& next = chain.next(top.parms_id);
        const double scale = std::pow(2.0, 12);
        const hpu::seal_adapter::CkksValueMetadata left{
            top.parms_id, top.chain_index, scale};
        const hpu::seal_adapter::CkksValueMetadata right{
            top.parms_id, top.chain_index, scale};

        const auto preserved =
            hpu::seal_adapter::infer_ckks_preserving_metadata(chain, left);
        const auto added = hpu::seal_adapter::infer_ckks_add_sub_metadata(
            chain, left, right);
        const auto multiplied = hpu::seal_adapter::infer_ckks_multiply_metadata(
            chain, left, right);
        const auto rescaled = hpu::seal_adapter::infer_ckks_rescale_metadata(
            chain, multiplied);
        require(
            preserved.parms_id == top.parms_id
                && preserved.chain_index == top.chain_index
                && preserved.scale == scale
                && added.parms_id == top.parms_id
                && added.scale == scale,
            "preserving/Add metadata inference changed level or scale");
        require(
            multiplied.parms_id == top.parms_id
                && multiplied.scale == scale * scale,
            "Multiply metadata inference did not multiply scales");
        require(
            rescaled.parms_id == next.parms_id
                && rescaled.chain_index == next.chain_index
                && hpu::seal_adapter::ckks_scales_compatible(
                    rescaled.scale,
                    multiplied.scale / static_cast<double>(top.q_last)),
            "Rescale metadata inference did not move to the next Q level");

        hpu::seal_adapter::CkksApplicationImageBuilder builder(
            *bundle.context, 64);
        const auto reserved = builder.reserve_ciphertext(
            "output/inferred_rescale", rescaled, 2);
        require(
            reserved.metadata().parms_id == rescaled.parms_id
                && reserved.metadata().chain_index == rescaled.chain_index
                && reserved.metadata().scale == rescaled.scale
                && reserved.components.size() == 2
                && reserved.components.front().limbs.size()
                    == next.q_moduli.size(),
            "image builder did not reserve from inferred CKKS metadata");

        auto invalid_chain_index = left;
        invalid_chain_index.chain_index = next.chain_index;
        require_invalid_argument(
            [&] {
                hpu::seal_adapter::validate_ckks_metadata(
                    chain, invalid_chain_index, "test input");
            },
            "metadata accepted a chain_index inconsistent with parms_id");
        auto invalid_scale = left;
        invalid_scale.scale = 0.0;
        require_invalid_argument(
            [&] {
                hpu::seal_adapter::validate_ckks_metadata(
                    chain, invalid_scale, "test input");
            },
            "metadata accepted a zero scale");
        auto different_scale = right;
        different_scale.scale *= 2.0;
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::infer_ckks_add_sub_metadata(
                    chain, left, different_scale);
            },
            "Add/Sub metadata accepted incompatible scales");
        const hpu::seal_adapter::CkksValueMetadata next_level{
            next.parms_id, next.chain_index, scale};
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::infer_ckks_multiply_metadata(
                    chain, left, next_level);
            },
            "Multiply metadata accepted operands from different levels");
        auto huge_scale = left;
        huge_scale.scale = std::numeric_limits<double>::max();
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::infer_ckks_multiply_metadata(
                    chain, huge_scale, huge_scale);
            },
            "Multiply metadata accepted scale overflow");
        const auto& bottom = chain.bottom();
        const hpu::seal_adapter::CkksValueMetadata bottom_value{
            bottom.parms_id, bottom.chain_index, scale};
        require_invalid_argument(
            [&] {
                (void)hpu::seal_adapter::infer_ckks_rescale_metadata(
                    chain, bottom_value);
            },
            "Rescale metadata accepted a transition below the bottom level");

        std::cout << "SEAL CKKS metadata transition rules passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SEAL CKKS metadata test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
