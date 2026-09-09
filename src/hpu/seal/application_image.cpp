#include "hpu/seal/application_image.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "scheme/ckks/galois.hpp"
#include "hpu/seal/ntt_bridge.hpp"

#include <seal/util/ntt.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace hpu::seal_adapter {
namespace {

std::uint32_t narrow(std::uint64_t value, const char* role)
{
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument(role);
    }
    return static_cast<std::uint32_t>(value);
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

std::string stage_id(const std::string& prefix, std::size_t stage)
{
    return prefix + "/stage" + std::to_string(stage);
}

} // namespace

CkksApplicationImageBuilder::CkksApplicationImageBuilder(
    const ::seal::SEALContext& context,
    std::uint64_t capacity_lines)
    : context_(context), image_(capacity_lines),
      level_chain_(context)
{}

hpu::runtime::HpuMemSpan CkksApplicationImageBuilder::add_modulus_table()
{
    if (modulus_table_added_) {
        throw std::logic_error("the application modulus table was already prepared");
    }
    const auto key_data = context_.key_context_data();
    if (!key_data) {
        throw std::invalid_argument("SEALContext has no key context");
    }
    std::vector<std::uint32_t> words;
    words.reserve(key_data->parms().coeff_modulus().size() * 4);
    for (const ::seal::Modulus& seal_modulus : key_data->parms().coeff_modulus()) {
        const std::uint32_t modulus = narrow(
            seal_modulus.value(), "SEAL modulus exceeds the HPU uint32 ABI");
        if (modulus < 65537) {
            throw std::invalid_argument("HPU modulus must be at least 65537");
        }
        const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        const std::uint64_t quotient = maximum / modulus;
        const std::uint64_t remainder = maximum % modulus;
        const std::uint64_t mu = quotient + (remainder + 1 >= modulus ? 1 : 0);
        if ((mu >> 48U) != 0) {
            throw std::invalid_argument("Barrett mu exceeds the HPU 48-bit ABI");
        }
        words.push_back(modulus);
        words.push_back(static_cast<std::uint32_t>(mu));
        words.push_back(static_cast<std::uint32_t>((mu >> 32U) & 0xffffU));
        words.push_back(0);
    }
    const auto allocation = image_.add(
        "constants/modulus_table", words,
        hpu::runtime::AllocationKind::modulus_table, true);
    modulus_table_added_ = true;
    return allocation.span;
}

std::vector<PreparedCanonicalTwiddles>
CkksApplicationImageBuilder::add_canonical_twiddles()
{
    if (canonical_twiddles_added_) {
        throw std::logic_error("canonical twiddles were already prepared");
    }
    const auto key_data = context_.key_context_data();
    if (!key_data) {
        throw std::invalid_argument("SEALContext has no key context");
    }
    const std::size_t degree = key_data->parms().poly_modulus_degree();
    const auto& moduli = key_data->parms().coeff_modulus();
    const ::seal::util::NTTTables* seal_tables = key_data->small_ntt_tables();
    std::vector<PreparedCanonicalTwiddles> result;
    result.reserve(moduli.size());

    for (std::size_t basis = 0; basis < moduli.size(); ++basis) {
        if (basis > std::numeric_limits<std::uint8_t>::max()) {
            throw std::invalid_argument("SEAL context exceeds HPU MOD_ID width");
        }
        PreparedCanonicalTwiddles prepared;
        prepared.modulus_id = static_cast<std::uint8_t>(basis);
        prepared.modulus = narrow(
            moduli[basis].value(), "SEAL modulus exceeds the HPU uint32 ABI");
        const std::uint32_t psi = narrow(
            seal_tables[basis].get_root(), "SEAL NTT root exceeds the HPU ABI");
        prepared.canonical_psi = psi;
        const std::string prefix = "constants/twiddle/canonical/mod"
            + std::to_string(basis);

        std::vector<std::uint32_t> pre_twist(degree);
        for (std::size_t position = 0; position < degree; ++position) {
            pre_twist[position] = hpu::model::pow_mod(
                psi, bit_reverse(position, degree), prepared.modulus);
        }
        prepared.pre_twist = image_.add(
            prefix + "/ntt/pre_twist", pre_twist,
            hpu::runtime::AllocationKind::twiddle, true).span;

        hpu::model::HardwareNttModel model(
            degree, prepared.modulus,
            hpu::model::pow_mod(psi, 2, prepared.modulus));
        const auto forward = model.forward_twiddles();
        for (std::size_t stage = 0; stage < forward.size(); ++stage) {
            prepared.forward_stages.push_back(image_.add(
                stage_id(prefix + "/ntt", stage), forward[stage],
                hpu::runtime::AllocationKind::twiddle, true).span);
        }
        const auto inverse = model.inverse_twiddles();
        for (std::size_t stage = 0; stage < inverse.stages.size(); ++stage) {
            prepared.inverse_stages.push_back(image_.add(
                stage_id(prefix + "/intt", stage), inverse.stages[stage],
                hpu::runtime::AllocationKind::twiddle, true).span);
        }
        std::vector<std::uint32_t> post(degree);
        const std::uint32_t inverse_psi = hpu::model::inverse_mod_prime(
            psi, prepared.modulus);
        for (std::size_t position = 0; position < degree; ++position) {
            const std::uint32_t untwist = hpu::model::pow_mod(
                inverse_psi, bit_reverse(position, degree), prepared.modulus);
            post[position] = multiply_mod(
                inverse.post_scale[position], untwist, prepared.modulus);
        }
        prepared.post_untwist_scale = image_.add(
            prefix + "/intt/post_untwist_scale", post,
            hpu::runtime::AllocationKind::twiddle, true).span;
        result.push_back(std::move(prepared));
    }
    canonical_twiddles_added_ = true;
    return result;
}

PreparedPolynomial CkksApplicationImageBuilder::add_polynomial(
    std::string id,
    const HpuRnsPolynomial& polynomial,
    hpu::runtime::AllocationKind kind,
    bool read_only)
{
    if (polynomial.degree == 0 || polynomial.moduli.empty()
        || polynomial.moduli.size() != polynomial.modulus_ids.size()
        || polynomial.words.size() != polynomial.degree * polynomial.moduli.size()) {
        throw std::invalid_argument("invalid HPU RNS polynomial shape");
    }
    PreparedPolynomial result;
    result.id = std::move(id);
    result.degree = polynomial.degree;
    result.modulus_ids = polynomial.modulus_ids;
    result.limbs.reserve(polynomial.moduli.size());
    for (std::size_t basis = 0; basis < polynomial.moduli.size(); ++basis) {
        const auto first = polynomial.words.begin()
            + static_cast<std::ptrdiff_t>(basis * polynomial.degree);
        const std::vector<std::uint32_t> limb(first, first + polynomial.degree);
        result.limbs.push_back(image_.add(
            result.id + "/mod" + std::to_string(polynomial.modulus_ids[basis]),
            limb, kind, read_only).span);
    }
    return result;
}

PreparedRnsObject CkksApplicationImageBuilder::add_ciphertext(
    std::string id,
    const ::seal::Ciphertext& ciphertext)
{
    const CkksLevelDescriptor& level = require_level(ciphertext.parms_id());
    PreparedRnsObject result;
    result.id = std::move(id);
    result.parms_id = ciphertext.parms_id();
    result.chain_index = level.chain_index;
    result.scale = ciphertext.scale();
    for (std::size_t component = 0; component < ciphertext.size(); ++component) {
        result.components.push_back(add_polynomial(
            result.id + "/c" + std::to_string(component),
            ciphertext_component_to_hpu(ciphertext, component, context_),
            hpu::runtime::AllocationKind::ciphertext, true));
    }
    return result;
}

PreparedRnsObject CkksApplicationImageBuilder::add_plaintext(
    std::string id,
    const ::seal::Plaintext& plaintext)
{
    const CkksLevelDescriptor& level = require_level(plaintext.parms_id());
    PreparedRnsObject result;
    result.id = std::move(id);
    result.parms_id = plaintext.parms_id();
    result.chain_index = level.chain_index;
    result.scale = plaintext.scale();
    result.components.push_back(add_polynomial(
        result.id + "/c0", plaintext_to_hpu(plaintext, context_),
        hpu::runtime::AllocationKind::plaintext, true));
    return result;
}

PreparedEvaluationKey CkksApplicationImageBuilder::add_evaluation_key(
    std::string id,
    const std::vector<HpuKeySwitchDigit>& digits,
    const CkksLevelDescriptor& level)
{
    PreparedEvaluationKey result;
    result.id = std::move(id);
    result.data_parms_id = level.parms_id;
    result.chain_index = level.chain_index;
    result.rns_layout = level.rns_layout;
    result.digits.resize(digits.size());
    for (std::size_t digit = 0; digit < digits.size(); ++digit) {
        result.digits[digit].push_back(add_polynomial(
            result.id + "/d" + std::to_string(digit) + "/c0",
            digits[digit].key_component_0,
            hpu::runtime::AllocationKind::evaluation_key, true));
        result.digits[digit].push_back(add_polynomial(
            result.id + "/d" + std::to_string(digit) + "/c1",
            digits[digit].key_component_1,
            hpu::runtime::AllocationKind::evaluation_key, true));
    }
    return result;
}

PreparedEvaluationKey CkksApplicationImageBuilder::add_relinearization_key(
    std::string id,
    const ::seal::RelinKeys& keys,
    const CkksLevelDescriptor& level)
{
    const CkksLevelDescriptor& authoritative = require_level(level.parms_id);
    return add_evaluation_key(
        std::move(id), relinearization_key_to_hpu(
            keys, context_, authoritative), authoritative);
}

PreparedKeySwitchConstants CkksApplicationImageBuilder::add_keyswitch_constants(
    std::string id,
    const CkksLevelDescriptor& level)
{
    constexpr std::uint32_t format_magic = 0x4b535731U; // "KSW1"
    const CkksLevelDescriptor& authoritative = require_level(level.parms_id);
    if (authoritative.special_moduli.size() != 1
        || authoritative.rns_layout.p_mod_ids.size() != 1) {
        throw std::invalid_argument(
            "CKKS software KeySwitch constants require one special prime");
    }
    const std::uint32_t p = authoritative.special_moduli.front();
    std::vector<std::uint32_t> words{
        format_magic,
        static_cast<std::uint32_t>(authoritative.rns_layout.p_mod_ids.front()),
        p,
        p >> 1U,
        static_cast<std::uint32_t>(authoritative.q_moduli.size())
    };
    words.reserve(words.size() + authoritative.q_moduli.size() * 2);
    for (std::size_t basis = 0; basis < authoritative.q_moduli.size(); ++basis) {
        const std::uint32_t q = authoritative.q_moduli[basis];
        words.push_back(static_cast<std::uint32_t>(
            authoritative.rns_layout.q_mod_ids[basis]));
        words.push_back(hpu::model::inverse_mod_prime(p % q, q));
    }
    PreparedKeySwitchConstants result;
    result.data_parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.values = image_.add(
        std::move(id), words,
        hpu::runtime::AllocationKind::constant, true).span;
    return result;
}

PreparedRescaleConstants CkksApplicationImageBuilder::add_rescale_constants(
    std::string id,
    const CkksLevelDescriptor& source_level)
{
    constexpr std::uint32_t format_magic = 0x52534331U; // "RSC1"
    const CkksLevelDescriptor& source = require_level(source_level.parms_id);
    if (source.q_moduli.size() < 2
        || !level_chain_.has_next(source.parms_id)) {
        throw std::invalid_argument("CKKS Rescale source has no next data level");
    }
    const CkksLevelDescriptor& destination = level_chain_.next(source.parms_id);
    if (destination.q_moduli.size() + 1 != source.q_moduli.size()
        || !std::equal(
            destination.q_moduli.begin(), destination.q_moduli.end(),
            source.q_moduli.begin())
        || !std::equal(
            destination.rns_layout.q_mod_ids.begin(),
            destination.rns_layout.q_mod_ids.end(),
            source.rns_layout.q_mod_ids.begin())) {
        throw std::logic_error("CKKS Rescale levels are not a drop-last Q chain");
    }
    const std::uint32_t q_last = source.q_moduli.back();
    std::vector<std::uint32_t> words{
        format_magic,
        static_cast<std::uint32_t>(source.rns_layout.q_mod_ids.back()),
        q_last,
        q_last >> 1U,
        static_cast<std::uint32_t>(destination.q_moduli.size())
    };
    words.reserve(words.size() + destination.q_moduli.size() * 2);
    for (std::size_t basis = 0; basis < destination.q_moduli.size(); ++basis) {
        const std::uint32_t q = destination.q_moduli[basis];
        words.push_back(static_cast<std::uint32_t>(
            destination.rns_layout.q_mod_ids[basis]));
        words.push_back(hpu::model::inverse_mod_prime(q_last % q, q));
    }
    PreparedRescaleConstants result;
    result.source_parms_id = source.parms_id;
    result.destination_parms_id = destination.parms_id;
    result.source_chain_index = source.chain_index;
    result.destination_chain_index = destination.chain_index;
    result.values = image_.add(
        std::move(id), words,
        hpu::runtime::AllocationKind::constant, true).span;
    return result;
}

PreparedEvaluationKey CkksApplicationImageBuilder::add_galois_key(
    std::string id,
    const ::seal::GaloisKeys& keys,
    std::uint32_t galois_element,
    const CkksLevelDescriptor& level)
{
    const CkksLevelDescriptor& authoritative = require_level(level.parms_id);
    return add_evaluation_key(
        std::move(id), galois_key_to_hpu(
        keys, galois_element, context_, authoritative), authoritative);
}

PreparedEvaluationKey CkksApplicationImageBuilder::add_rotation_key(
    std::string id,
    const ::seal::GaloisKeys& keys,
    int steps,
    const CkksLevelDescriptor& level)
{
    const auto data = context_.get_context_data(level.parms_id);
    if (!data) {
        throw std::invalid_argument("rotation-key level is absent from SEALContext");
    }
    return add_galois_key(
        std::move(id), keys,
        hpu::scheme::ckks::rotation_galois_element(
            data->parms().poly_modulus_degree(), steps),
        level);
}

PreparedEvaluationKey CkksApplicationImageBuilder::add_conjugation_key(
    std::string id,
    const ::seal::GaloisKeys& keys,
    const CkksLevelDescriptor& level)
{
    const auto data = context_.get_context_data(level.parms_id);
    if (!data) {
        throw std::invalid_argument(
            "conjugation-key level is absent from SEALContext");
    }
    return add_galois_key(
        std::move(id), keys,
        hpu::scheme::ckks::conjugation_galois_element(
            data->parms().poly_modulus_degree()),
        level);
}

std::vector<PreparedFusedAutomorphismTwiddles>
CkksApplicationImageBuilder::add_fused_automorphism_twiddles(
    std::string id,
    std::uint32_t galois_element,
    const CkksLevelDescriptor& level)
{
    const CkksLevelDescriptor& authoritative = require_level(level.parms_id);
    const auto tables = create_fused_inverse_automorphism_tables(
        authoritative.parms_id, galois_element, context_);
    if (tables.size() != authoritative.rns_layout.q_mod_ids.size()) {
        throw std::logic_error("fused automorphism table count does not match active Q");
    }
    std::vector<PreparedFusedAutomorphismTwiddles> result;
    result.reserve(tables.size());
    for (std::size_t basis = 0; basis < tables.size(); ++basis) {
        PreparedFusedAutomorphismTwiddles prepared;
        prepared.modulus_id = static_cast<std::uint8_t>(
            authoritative.rns_layout.q_mod_ids[basis]);
        prepared.modulus = tables[basis].modulus;
        prepared.canonical_psi = tables[basis].canonical_psi;
        prepared.modified_psi = tables[basis].modified_psi;
        const std::string prefix = "constants/twiddle/" + id + "/mod"
            + std::to_string(prepared.modulus_id) + "/intt";
        for (std::size_t stage = 0; stage < tables[basis].stages.size(); ++stage) {
            prepared.inverse_stages.push_back(image_.add(
                stage_id(prefix, stage), tables[basis].stages[stage],
                hpu::runtime::AllocationKind::twiddle, true).span);
        }
        prepared.post_untwist_scale = image_.add(
            prefix + "/post_untwist_scale",
            tables[basis].post_untwist_scale,
            hpu::runtime::AllocationKind::twiddle, true).span;
        result.push_back(std::move(prepared));
    }
    return result;
}

std::vector<PreparedFusedAutomorphismTwiddles>
CkksApplicationImageBuilder::add_rotation_twiddles(
    std::string id,
    int steps,
    const CkksLevelDescriptor& level)
{
    const auto data = context_.get_context_data(level.parms_id);
    if (!data) {
        throw std::invalid_argument(
            "rotation-twiddle level is absent from SEALContext");
    }
    return add_fused_automorphism_twiddles(
        std::move(id),
        hpu::scheme::ckks::rotation_galois_element(
            data->parms().poly_modulus_degree(), steps),
        level);
}

std::vector<PreparedFusedAutomorphismTwiddles>
CkksApplicationImageBuilder::add_conjugation_twiddles(
    std::string id,
    const CkksLevelDescriptor& level)
{
    const auto data = context_.get_context_data(level.parms_id);
    if (!data) {
        throw std::invalid_argument(
            "conjugation-twiddle level is absent from SEALContext");
    }
    return add_fused_automorphism_twiddles(
        std::move(id),
        hpu::scheme::ckks::conjugation_galois_element(
            data->parms().poly_modulus_degree()),
        level);
}

PreparedRnsObject CkksApplicationImageBuilder::reserve_ciphertext(
    std::string id,
    const CkksLevelDescriptor& level,
    std::size_t component_count,
    double scale,
    hpu::runtime::PolynomialDomain domain,
    std::uint64_t key_domain)
{
    const CkksLevelDescriptor& authoritative = require_level(level.parms_id);
    return reserve_ciphertext(
        std::move(id),
        CkksValueMetadata{
            authoritative.parms_id, authoritative.chain_index, scale},
        component_count, domain, key_domain);
}

PreparedRnsObject CkksApplicationImageBuilder::reserve_ciphertext(
    std::string id,
    const CkksValueMetadata& metadata,
    std::size_t component_count,
    hpu::runtime::PolynomialDomain domain,
    std::uint64_t key_domain)
{
    validate_ckks_metadata(level_chain_, metadata, "reserved CKKS ciphertext");
    const CkksLevelDescriptor& authoritative = require_level(metadata.parms_id);
    const auto data = context_.get_context_data(authoritative.parms_id);
    if (!data || component_count == 0) {
        throw std::invalid_argument("invalid reserved CKKS ciphertext shape");
    }
    PreparedRnsObject result;
    result.id = std::move(id);
    result.parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.scale = metadata.scale;
    result.domain = domain;
    result.key_domain = key_domain;
    const std::size_t degree = data->parms().poly_modulus_degree();
    for (std::size_t component = 0; component < component_count; ++component) {
        PreparedPolynomial polynomial;
        polynomial.id = result.id + "/c" + std::to_string(component);
        polynomial.degree = degree;
        for (int mod_id : authoritative.rns_layout.q_mod_ids) {
            polynomial.modulus_ids.push_back(static_cast<std::uint8_t>(mod_id));
            polynomial.limbs.push_back(image_.reserve(
                polynomial.id + "/mod" + std::to_string(mod_id), degree,
                hpu::runtime::AllocationKind::output).span);
        }
        result.components.push_back(std::move(polynomial));
    }
    return result;
}

const hpu::runtime::HpuMemImage&
CkksApplicationImageBuilder::image() const noexcept
{
    return image_;
}

const CkksLevelChain& CkksApplicationImageBuilder::level_chain() const noexcept
{
    return level_chain_;
}

const std::vector<CkksLevelDescriptor>&
CkksApplicationImageBuilder::levels() const noexcept
{
    return level_chain_.levels();
}

const CkksLevelDescriptor& CkksApplicationImageBuilder::require_level(
    ::seal::parms_id_type parms_id) const
{
    return level_chain_.require(parms_id);
}

void register_rns_object(
    hpu::runtime::Application& application,
    const PreparedRnsObject& object,
    bool required_output)
{
    for (const PreparedPolynomial& component : object.components) {
        if (component.modulus_ids.size() != component.limbs.size()) {
            throw std::invalid_argument("prepared RNS object has inconsistent limbs");
        }
        for (std::size_t basis = 0; basis < component.limbs.size(); ++basis) {
            hpu::runtime::ObjectState state;
            state.backing = component.limbs[basis];
            state.level = object.chain_index;
            state.modulus_ids = {component.modulus_ids[basis]};
            state.domain = object.domain;
            state.key_domain = object.key_domain;
            state.required_output = required_output;
            application.register_object(
                component.id + "/mod" + std::to_string(component.modulus_ids[basis]),
                std::move(state));
        }
    }
}

} // namespace hpu::seal_adapter
