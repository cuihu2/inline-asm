#include "hpu/seal/bfv_application_image.hpp"

#include "hpu/model/hardware_ntt.hpp"
#include "hpu/seal/evaluation_key.hpp"
#include "scheme/bfv/galois.hpp"

#include <seal/util/numth.h>

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

std::uint32_t multiply_mod(std::uint32_t left, std::uint32_t right, std::uint32_t modulus)
{
    return static_cast<std::uint32_t>((static_cast<std::uint64_t>(left) * right) % modulus);
}

std::string stage_id(const std::string& prefix, std::size_t stage)
{
    return prefix + "/stage" + std::to_string(stage);
}

std::string mod_id(const std::string& prefix, int modulus_id)
{
    return prefix + "/mod" + std::to_string(modulus_id);
}

std::uint32_t modulus(const BfvLevelRegistry& registry, int modulus_id)
{
    if (modulus_id < 0 || static_cast<std::size_t>(modulus_id) >= registry.modulus_table.size()) {
        throw std::logic_error("BFV layout references an absent MOD_ID");
    }
    return registry.modulus_table[static_cast<std::size_t>(modulus_id)];
}

void add_constant_polynomial(hpu::runtime::HpuMemImage& image, std::size_t degree,
                             const std::string& id, std::uint32_t value, std::size_t& count)
{
    image.add(id, std::vector<std::uint32_t>(degree, value), hpu::runtime::AllocationKind::constant,
              true);
    ++count;
}

void add_bconv_constants(hpu::runtime::HpuMemImage& image, std::size_t degree,
                         const BfvLevelRegistry& registry, const std::string& prefix,
                         const std::vector<int>& sources, const std::vector<int>& targets,
                         std::size_t& count, bool include_source_inverses = true)
{
    if (sources.empty() || targets.empty()) {
        throw std::invalid_argument("BFV BConv needs nonempty source and target bases");
    }
    if (include_source_inverses) {
        for (int source : sources) {
            const std::uint32_t source_modulus = modulus(registry, source);
            std::uint32_t source_hat = 1;
            for (int other : sources) {
                if (other != source) {
                    source_hat = multiply_mod(source_hat, modulus(registry, other) % source_modulus,
                                              source_modulus);
                }
            }
            add_constant_polynomial(image, degree, mod_id(prefix + "/qhat_inv", source),
                                    hpu::model::inverse_mod_prime(source_hat, source_modulus),
                                    count);
        }
    }
    for (int target : targets) {
        const std::uint32_t target_modulus = modulus(registry, target);
        for (int source : sources) {
            std::uint32_t source_hat = 1;
            for (int other : sources) {
                if (other != source) {
                    source_hat = multiply_mod(source_hat, modulus(registry, other) % target_modulus,
                                              target_modulus);
                }
            }
            add_constant_polynomial(image, degree,
                                    prefix + "/qhat_mod_target/target" + std::to_string(target) +
                                        "/source" + std::to_string(source),
                                    source_hat, count);
        }
    }
}

std::uint32_t product_mod(const BfvLevelRegistry& registry, const std::vector<int>& factors,
                          std::uint32_t target_modulus)
{
    std::uint32_t result = 1;
    for (int factor : factors) {
        result = multiply_mod(result, modulus(registry, factor) % target_modulus, target_modulus);
    }
    return result;
}

} // namespace

BfvApplicationImageBuilder::BfvApplicationImageBuilder(const ::seal::SEALContext& context,
                                                       std::uint64_t capacity_lines)
    : context_(context), image_(capacity_lines), level_chain_(context)
{
}

hpu::runtime::HpuMemSpan BfvApplicationImageBuilder::add_modulus_table()
{
    if (modulus_table_added_) {
        throw std::logic_error("the BFV application modulus table was already prepared");
    }
    std::vector<std::uint32_t> words;
    words.reserve(registry().modulus_table.size() * 4);
    for (std::uint32_t value : registry().modulus_table) {
        if (value < 65537) {
            throw std::invalid_argument("HPU BFV modulus must be at least 65537");
        }
        const std::uint64_t maximum = std::numeric_limits<std::uint64_t>::max();
        const std::uint64_t quotient = maximum / value;
        const std::uint64_t remainder = maximum % value;
        const std::uint64_t mu = quotient + (remainder + 1 >= value ? 1 : 0);
        if ((mu >> 48U) != 0) {
            throw std::invalid_argument("BFV Barrett mu exceeds the HPU 48-bit ABI");
        }
        words.push_back(value);
        words.push_back(static_cast<std::uint32_t>(mu));
        words.push_back(static_cast<std::uint32_t>((mu >> 32U) & 0xffffU));
        words.push_back(0);
    }
    const auto allocation = image_.add("constants/modulus_table", words,
                                       hpu::runtime::AllocationKind::modulus_table, true);
    modulus_table_added_ = true;
    return allocation.span;
}

std::vector<PreparedCanonicalTwiddles> BfvApplicationImageBuilder::add_canonical_twiddles()
{
    if (canonical_twiddles_added_) {
        throw std::logic_error("BFV canonical twiddles were already prepared");
    }
    const std::size_t degree = registry().poly_modulus_degree;
    const int plaintext_id = level_chain_.top().plaintext_mod_id;
    std::vector<PreparedCanonicalTwiddles> result;
    result.reserve(registry().modulus_table.size() - 1);

    for (std::size_t index = 0; index < registry().modulus_table.size(); ++index) {
        const int current_id = static_cast<int>(index);
        if (current_id == plaintext_id) {
            continue;
        }
        const std::uint32_t current_modulus = registry().modulus_table[index];
        std::uint64_t root = 0;
        if (!::seal::util::try_minimal_primitive_root(static_cast<std::uint64_t>(2 * degree),
                                                      ::seal::Modulus(current_modulus), root)) {
            throw std::logic_error("BFV evaluator modulus has no primitive 2N-th root");
        }

        PreparedCanonicalTwiddles prepared;
        prepared.modulus_id = static_cast<std::uint8_t>(index);
        prepared.modulus = current_modulus;
        prepared.canonical_psi = narrow(root, "BFV NTT root exceeds the HPU uint32 ABI");
        const std::string prefix = "constants/twiddle/canonical/mod" + std::to_string(index);

        std::vector<std::uint32_t> pre_twist(degree);
        for (std::size_t position = 0; position < degree; ++position) {
            pre_twist[position] = hpu::model::pow_mod(
                prepared.canonical_psi, bit_reverse(position, degree), current_modulus);
        }
        prepared.pre_twist = image_
                                 .add(prefix + "/ntt/pre_twist", pre_twist,
                                      hpu::runtime::AllocationKind::twiddle, true)
                                 .span;

        hpu::model::HardwareNttModel model(
            degree, current_modulus,
            hpu::model::pow_mod(prepared.canonical_psi, 2, current_modulus));
        const auto forward = model.forward_twiddles();
        for (std::size_t stage = 0; stage < forward.size(); ++stage) {
            prepared.forward_stages.push_back(image_
                                                  .add(stage_id(prefix + "/ntt", stage),
                                                       forward[stage],
                                                       hpu::runtime::AllocationKind::twiddle, true)
                                                  .span);
        }
        const auto inverse = model.inverse_twiddles();
        for (std::size_t stage = 0; stage < inverse.stages.size(); ++stage) {
            prepared.inverse_stages.push_back(image_
                                                  .add(stage_id(prefix + "/intt", stage),
                                                       inverse.stages[stage],
                                                       hpu::runtime::AllocationKind::twiddle, true)
                                                  .span);
        }
        std::vector<std::uint32_t> post(degree);
        const std::uint32_t inverse_psi =
            hpu::model::inverse_mod_prime(prepared.canonical_psi, current_modulus);
        for (std::size_t position = 0; position < degree; ++position) {
            const std::uint32_t untwist =
                hpu::model::pow_mod(inverse_psi, bit_reverse(position, degree), current_modulus);
            post[position] = multiply_mod(inverse.post_scale[position], untwist, current_modulus);
        }
        prepared.post_untwist_scale = image_
                                          .add(prefix + "/intt/post_untwist_scale", post,
                                               hpu::runtime::AllocationKind::twiddle, true)
                                          .span;
        result.push_back(std::move(prepared));
    }
    canonical_twiddles_added_ = true;
    return result;
}

PreparedPolynomial BfvApplicationImageBuilder::add_polynomial(std::string id,
                                                              const HpuRnsPolynomial& polynomial,
                                                              hpu::runtime::AllocationKind kind,
                                                              bool read_only)
{
    if (polynomial.degree == 0 || polynomial.moduli.empty() ||
        polynomial.moduli.size() != polynomial.modulus_ids.size() ||
        polynomial.words.size() != polynomial.degree * polynomial.moduli.size()) {
        throw std::invalid_argument("invalid BFV HPU RNS polynomial shape");
    }
    PreparedPolynomial result;
    result.id = std::move(id);
    result.degree = polynomial.degree;
    result.modulus_ids = polynomial.modulus_ids;
    for (std::size_t basis = 0; basis < polynomial.moduli.size(); ++basis) {
        const auto first =
            polynomial.words.begin() + static_cast<std::ptrdiff_t>(basis * polynomial.degree);
        result.limbs.push_back(
            image_
                .add(result.id + "/mod" + std::to_string(polynomial.modulus_ids[basis]),
                     std::vector<std::uint32_t>(first, first + polynomial.degree), kind, read_only)
                .span);
    }
    return result;
}

PreparedBfvRnsObject
BfvApplicationImageBuilder::add_ciphertext(std::string id, const ::seal::Ciphertext& ciphertext)
{
    const BfvLevelDescriptor& level = require_level(ciphertext.parms_id());
    PreparedBfvRnsObject result;
    result.id = std::move(id);
    result.parms_id = level.parms_id;
    result.chain_index = level.chain_index;
    result.domain = hpu::runtime::PolynomialDomain::coefficient;
    for (std::size_t component = 0; component < ciphertext.size(); ++component) {
        result.components.push_back(
            add_polynomial(result.id + "/c" + std::to_string(component),
                           bfv_ciphertext_component_to_hpu(ciphertext, component, context_),
                           hpu::runtime::AllocationKind::ciphertext, true));
    }
    return result;
}

PreparedBfvRnsObject BfvApplicationImageBuilder::add_add_subtract_plaintext(
    std::string id, const ::seal::Plaintext& plaintext, const BfvLevelDescriptor& level)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    PreparedBfvRnsObject result;
    result.id = std::move(id);
    result.parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.domain = hpu::runtime::PolynomialDomain::coefficient;
    result.components.push_back(add_polynomial(
        result.id + "/c0",
        bfv_add_subtract_plaintext_to_hpu(plaintext, authoritative.parms_id, context_),
        hpu::runtime::AllocationKind::plaintext, true));
    return result;
}

PreparedBfvRnsObject BfvApplicationImageBuilder::add_multiply_plaintext(
    std::string id, const ::seal::Plaintext& plaintext, const BfvLevelDescriptor& level)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    PreparedBfvRnsObject result;
    result.id = std::move(id);
    result.parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.domain = hpu::runtime::PolynomialDomain::canonical_ntt_physical;
    result.components.push_back(
        add_polynomial(result.id + "/c0",
                       bfv_multiply_plaintext_to_hpu(plaintext, authoritative.parms_id, context_),
                       hpu::runtime::AllocationKind::plaintext, true));
    return result;
}

PreparedEvaluationKey BfvApplicationImageBuilder::add_evaluation_key(
    std::string id, const std::vector<HpuKeySwitchDigit>& digits, const BfvLevelDescriptor& level)
{
    PreparedEvaluationKey result;
    result.id = std::move(id);
    result.data_parms_id = level.parms_id;
    result.chain_index = level.chain_index;
    result.rns_layout = level.keyswitch_layout;
    result.digits.resize(digits.size());
    for (std::size_t digit = 0; digit < digits.size(); ++digit) {
        result.digits[digit].push_back(add_polynomial(
            result.id + "/d" + std::to_string(digit) + "/c0", digits[digit].key_component_0,
            hpu::runtime::AllocationKind::evaluation_key, true));
        result.digits[digit].push_back(add_polynomial(
            result.id + "/d" + std::to_string(digit) + "/c1", digits[digit].key_component_1,
            hpu::runtime::AllocationKind::evaluation_key, true));
    }
    return result;
}

PreparedBfvRnsObject BfvApplicationImageBuilder::reserve_ciphertext(
    std::string id, const BfvLevelDescriptor& level, std::size_t component_count,
    hpu::runtime::PolynomialDomain domain, std::uint64_t key_domain)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    if (component_count == 0) {
        throw std::invalid_argument("invalid reserved BFV ciphertext shape");
    }
    PreparedBfvRnsObject result;
    result.id = std::move(id);
    result.parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.domain = domain;
    result.key_domain = key_domain;
    const std::size_t degree = registry().poly_modulus_degree;
    for (std::size_t component = 0; component < component_count; ++component) {
        PreparedPolynomial polynomial;
        polynomial.id = result.id + "/c" + std::to_string(component);
        polynomial.degree = degree;
        for (int mod_id : authoritative.keyswitch_layout.q_mod_ids) {
            polynomial.modulus_ids.push_back(static_cast<std::uint8_t>(mod_id));
            polynomial.limbs.push_back(image_
                                           .reserve(polynomial.id + "/mod" + std::to_string(mod_id),
                                                    degree, hpu::runtime::AllocationKind::output)
                                           .span);
        }
        result.components.push_back(std::move(polynomial));
    }
    return result;
}

PreparedEvaluationKey
BfvApplicationImageBuilder::add_relinearization_key(std::string id, const ::seal::RelinKeys& keys,
                                                    const BfvLevelDescriptor& level)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    return add_evaluation_key(
        std::move(id), relinearization_key_to_hpu(keys, context_, authoritative), authoritative);
}

PreparedEvaluationKey BfvApplicationImageBuilder::add_galois_key(
    std::string id, const ::seal::GaloisKeys& keys, std::uint32_t galois_element,
    const BfvLevelDescriptor& level)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    return add_evaluation_key(std::move(id),
                              galois_key_to_hpu(keys, galois_element, context_, authoritative),
                              authoritative);
}

PreparedEvaluationKey BfvApplicationImageBuilder::add_row_rotation_key(
    std::string id, const ::seal::GaloisKeys& keys, int steps, const BfvLevelDescriptor& level)
{
    return add_galois_key(
        std::move(id), keys,
        hpu::scheme::bfv::row_rotation_galois_element(registry().poly_modulus_degree, steps),
        level);
}

PreparedEvaluationKey BfvApplicationImageBuilder::add_column_rotation_key(
    std::string id, const ::seal::GaloisKeys& keys, const BfvLevelDescriptor& level)
{
    return add_galois_key(
        std::move(id), keys,
        hpu::scheme::bfv::column_rotation_galois_element(registry().poly_modulus_degree), level);
}

std::vector<PreparedFusedAutomorphismTwiddles>
BfvApplicationImageBuilder::add_fused_automorphism_twiddles(
    std::string id, std::uint32_t galois_element, const BfvLevelDescriptor& level)
{
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    const auto tables =
        create_fused_inverse_automorphism_tables(authoritative.parms_id, galois_element, context_);
    if (tables.size() != authoritative.keyswitch_layout.q_mod_ids.size()) {
        throw std::logic_error("BFV fused automorphism table count does not match active Q");
    }
    std::vector<PreparedFusedAutomorphismTwiddles> result;
    result.reserve(tables.size());
    for (std::size_t basis = 0; basis < tables.size(); ++basis) {
        PreparedFusedAutomorphismTwiddles prepared;
        prepared.modulus_id =
            static_cast<std::uint8_t>(authoritative.keyswitch_layout.q_mod_ids[basis]);
        prepared.modulus = tables[basis].modulus;
        prepared.canonical_psi = tables[basis].canonical_psi;
        prepared.modified_psi = tables[basis].modified_psi;
        const std::string prefix = "constants/twiddle/" + id + "/mod" +
                                   std::to_string(prepared.modulus_id) + "/intt";
        prepared.id = prefix;
        for (std::size_t stage = 0; stage < tables[basis].stages.size(); ++stage) {
            prepared.inverse_stages.push_back(
                image_
                    .add(stage_id(prefix, stage), tables[basis].stages[stage],
                         hpu::runtime::AllocationKind::twiddle, true)
                    .span);
        }
        prepared.post_untwist_scale =
            image_
                .add(prefix + "/post_untwist_scale", tables[basis].post_untwist_scale,
                     hpu::runtime::AllocationKind::twiddle, true)
                .span;
        result.push_back(std::move(prepared));
    }
    return result;
}

std::vector<PreparedFusedAutomorphismTwiddles>
BfvApplicationImageBuilder::add_row_rotation_twiddles(std::string id, int steps,
                                                      const BfvLevelDescriptor& level)
{
    return add_fused_automorphism_twiddles(
        std::move(id),
        hpu::scheme::bfv::row_rotation_galois_element(registry().poly_modulus_degree, steps),
        level);
}

std::vector<PreparedFusedAutomorphismTwiddles>
BfvApplicationImageBuilder::add_column_rotation_twiddles(std::string id,
                                                         const BfvLevelDescriptor& level)
{
    return add_fused_automorphism_twiddles(
        std::move(id),
        hpu::scheme::bfv::column_rotation_galois_element(registry().poly_modulus_degree), level);
}

PreparedKeySwitchConstants
BfvApplicationImageBuilder::add_keyswitch_constants(std::string id, const BfvLevelDescriptor& level)
{
    constexpr std::uint32_t format_magic = 0x424b5331U; // "BKS1"
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    if (!hpu::is_seal_single_p_rns_decomposition_layout(
            static_cast<int>(registry().poly_modulus_degree), authoritative.keyswitch_layout)) {
        throw std::invalid_argument(
            "BFV application image requires the SEAL single-P KeySwitch layout");
    }
    const int p_id = authoritative.keyswitch_layout.p_mod_ids.front();
    const std::uint32_t p = modulus(registry(), p_id);
    std::vector<std::uint32_t> words{format_magic, static_cast<std::uint32_t>(p_id), p, p >> 1U,
                                     static_cast<std::uint32_t>(authoritative.q_moduli.size())};
    for (std::size_t basis = 0; basis < authoritative.q_moduli.size(); ++basis) {
        const int q_id = authoritative.keyswitch_layout.q_mod_ids[basis];
        const std::uint32_t q = modulus(registry(), q_id);
        words.push_back(static_cast<std::uint32_t>(q_id));
        words.push_back(hpu::model::inverse_mod_prime(p % q, q));
    }

    PreparedKeySwitchConstants result;
    result.id = id;
    result.data_parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.values = image_.add(id, words, hpu::runtime::AllocationKind::constant, true).span;
    result.hardware_prefix = id + "/hardware";
    const std::size_t degree = registry().poly_modulus_degree;
    const auto add_constant = [&](const std::string& name, std::uint32_t value) {
        add_constant_polynomial(image_, degree, name, value,
                                result.hardware_constant_polynomial_count);
    };
    const auto reserve_workspace = [&](const std::string& name) {
        image_.reserve(name, degree, hpu::runtime::AllocationKind::workspace);
        ++result.hardware_workspace_polynomial_count;
    };

    std::vector<int> full_contexts = authoritative.keyswitch_layout.q_mod_ids;
    full_contexts.push_back(p_id);
    for (std::size_t digit = 0; digit < authoritative.keyswitch_layout.key_digits.size(); ++digit) {
        const auto& sources = authoritative.keyswitch_layout.key_digits[digit];
        std::vector<int> targets;
        for (int context : full_contexts) {
            if (std::find(sources.begin(), sources.end(), context) == sources.end()) {
                targets.push_back(context);
            }
        }
        add_bconv_constants(image_, degree, registry(),
                            result.hardware_prefix + "/modup/d" + std::to_string(digit), sources,
                            targets, result.hardware_constant_polynomial_count);
    }

    const std::uint32_t half_p = p >> 1U;
    for (int context : full_contexts) {
        add_constant(mod_id(result.hardware_prefix + "/half", context),
                     half_p % modulus(registry(), context));
    }
    add_bconv_constants(image_, degree, registry(), result.hardware_prefix + "/moddown", {p_id},
                        authoritative.keyswitch_layout.q_mod_ids,
                        result.hardware_constant_polynomial_count);
    for (int q_id : authoritative.keyswitch_layout.q_mod_ids) {
        const std::uint32_t q = modulus(registry(), q_id);
        add_constant(mod_id(result.hardware_prefix + "/moddown/p_inverse", q_id),
                     hpu::model::inverse_mod_prime(p % q, q));
    }

    const std::string workspace_prefix = result.hardware_prefix + "/workspace";
    for (int context : full_contexts) {
        reserve_workspace(mod_id(workspace_prefix + "/modup", context));
    }
    for (int component = 0; component < 2; ++component) {
        for (int context : full_contexts) {
            reserve_workspace(
                mod_id(workspace_prefix + "/accumulator/c" + std::to_string(component), context));
        }
    }
    reserve_workspace(workspace_prefix + "/bconv/normalized0");
    for (int q_id : authoritative.keyswitch_layout.q_mod_ids) {
        reserve_workspace(mod_id(workspace_prefix + "/moddown/correction", q_id));
    }
    return result;
}

PreparedBfvMultiplyConstants
BfvApplicationImageBuilder::add_multiply_constants(std::string id, const BfvLevelDescriptor& level)
{
    constexpr std::uint32_t format_magic = 0x42465631U; // "BFV1"
    const BfvLevelDescriptor& authoritative = require_level(level.parms_id);
    const auto& q_ids = authoritative.keyswitch_layout.q_mod_ids;
    const auto& b_ids = authoritative.b_mod_ids;
    if (q_ids.empty() || b_ids.empty() || authoritative.m_sk_mod_id < 0 ||
        authoritative.plaintext_mod_id < 0) {
        throw std::invalid_argument("BFV level lacks BEHZ modulus identities");
    }
    std::vector<int> bsk_ids = b_ids;
    bsk_ids.push_back(authoritative.m_sk_mod_id);

    std::vector<std::uint32_t> words{format_magic,
                                     static_cast<std::uint32_t>(registry().poly_modulus_degree),
                                     static_cast<std::uint32_t>(q_ids.size()),
                                     static_cast<std::uint32_t>(b_ids.size()),
                                     static_cast<std::uint32_t>(authoritative.m_sk_mod_id),
                                     static_cast<std::uint32_t>(authoritative.plaintext_mod_id),
                                     authoritative.m_sk,
                                     authoritative.plaintext_modulus};
    for (int q_id : q_ids) {
        words.push_back(static_cast<std::uint32_t>(q_id));
        words.push_back(modulus(registry(), q_id));
    }
    for (int b_id : b_ids) {
        words.push_back(static_cast<std::uint32_t>(b_id));
        words.push_back(modulus(registry(), b_id));
    }

    PreparedBfvMultiplyConstants result;
    result.id = id;
    result.data_parms_id = authoritative.parms_id;
    result.chain_index = authoritative.chain_index;
    result.q_mod_ids = q_ids;
    result.b_mod_ids = b_ids;
    result.m_sk_mod_id = authoritative.m_sk_mod_id;
    result.plaintext_mod_id = authoritative.plaintext_mod_id;
    result.values = image_.add(id, words, hpu::runtime::AllocationKind::constant, true).span;
    result.hardware_prefix = id + "/hardware";
    const std::size_t degree = registry().poly_modulus_degree;
    const auto add_constant = [&](const std::string& name, std::uint32_t value) {
        add_constant_polynomial(image_, degree, name, value,
                                result.hardware_constant_polynomial_count);
    };

    add_bconv_constants(image_, degree, registry(), result.hardware_prefix + "/q_to_bsk", q_ids,
                        bsk_ids, result.hardware_constant_polynomial_count);

    std::vector<int> q_bsk_ids = q_ids;
    q_bsk_ids.insert(q_bsk_ids.end(), bsk_ids.begin(), bsk_ids.end());
    for (int context : q_bsk_ids) {
        add_constant(mod_id(result.hardware_prefix + "/t", context),
                     authoritative.plaintext_modulus % modulus(registry(), context));
    }

    for (int context : bsk_ids) {
        const std::uint32_t target = modulus(registry(), context);
        add_constant(mod_id(result.hardware_prefix + "/fast_floor/q_inverse", context),
                     hpu::model::inverse_mod_prime(product_mod(registry(), q_ids, target), target));
    }

    add_bconv_constants(image_, degree, registry(), result.hardware_prefix + "/b_to_q", b_ids,
                        q_ids, result.hardware_constant_polynomial_count);
    add_bconv_constants(image_, degree, registry(), result.hardware_prefix + "/b_to_msk", b_ids,
                        {authoritative.m_sk_mod_id}, result.hardware_constant_polynomial_count,
                        false);

    const std::uint32_t m_sk = authoritative.m_sk;
    add_constant(
        mod_id(result.hardware_prefix + "/branchless/b_inverse", authoritative.m_sk_mod_id),
        hpu::model::inverse_mod_prime(product_mod(registry(), b_ids, m_sk), m_sk));
    add_bconv_constants(image_, degree, registry(), result.hardware_prefix + "/msk_to_q",
                        {authoritative.m_sk_mod_id}, q_ids,
                        result.hardware_constant_polynomial_count);
    for (int q_id : q_ids) {
        const std::uint32_t q = modulus(registry(), q_id);
        const std::uint32_t b_mod_q = product_mod(registry(), b_ids, q);
        add_constant(mod_id(result.hardware_prefix + "/branchless/negative_b", q_id),
                     b_mod_q == 0 ? 0 : q - b_mod_q);
    }

    const auto reserve_workspace = [&](const std::string& name) {
        image_.reserve(name, degree, hpu::runtime::AllocationKind::workspace);
        ++result.hardware_workspace_polynomial_count;
    };
    const std::string workspace_prefix = result.hardware_prefix + "/workspace";
    const std::size_t normalized_count = std::max(q_ids.size(), b_ids.size());
    for (std::size_t index = 0; index < normalized_count; ++index) {
        reserve_workspace(workspace_prefix + "/bconv/normalized" + std::to_string(index));
    }
    for (int input = 0; input < 4; ++input) {
        for (int context : q_bsk_ids) {
            reserve_workspace(
                mod_id(workspace_prefix + "/input/i" + std::to_string(input), context));
        }
    }
    for (int component = 0; component < 3; ++component) {
        for (int context : q_bsk_ids) {
            reserve_workspace(
                mod_id(workspace_prefix + "/tensor/c" + std::to_string(component), context));
        }
        for (int context : bsk_ids) {
            reserve_workspace(mod_id(
                workspace_prefix + "/fast_floor/converted/c" + std::to_string(component), context));
        }
        for (int context : q_ids) {
            reserve_workspace(
                mod_id(workspace_prefix + "/branchless/y/c" + std::to_string(component), context));
            reserve_workspace(mod_id(
                workspace_prefix + "/branchless/alpha/c" + std::to_string(component), context));
        }
        reserve_workspace(
            mod_id(workspace_prefix + "/branchless/alpha/c" + std::to_string(component),
                   authoritative.m_sk_mod_id));
    }
    return result;
}

PreparedBfvModSwitchConstants BfvApplicationImageBuilder::add_mod_switch_constants(
    std::string id, const BfvLevelDescriptor& source_level, std::size_t component_capacity)
{
    constexpr std::uint32_t format_magic = 0x424d5331U; // "BMS1"
    const BfvLevelDescriptor& source = require_level(source_level.parms_id);
    if (component_capacity == 0 || source.q_moduli.size() < 2 ||
        !level_chain_.has_next(source.parms_id)) {
        throw std::invalid_argument("BFV ModSwitch source has no next data level");
    }
    const BfvLevelDescriptor& destination = level_chain_.next(source.parms_id);
    if (destination.q_moduli.size() + 1 != source.q_moduli.size() ||
        !std::equal(destination.q_moduli.begin(), destination.q_moduli.end(),
                    source.q_moduli.begin()) ||
        !std::equal(destination.keyswitch_layout.q_mod_ids.begin(),
                    destination.keyswitch_layout.q_mod_ids.end(),
                    source.keyswitch_layout.q_mod_ids.begin())) {
        throw std::logic_error("BFV ModSwitch levels are not a drop-last Q chain");
    }

    const int dropped_id = source.keyswitch_layout.q_mod_ids.back();
    const std::uint32_t q_last = source.q_moduli.back();
    std::vector<std::uint32_t> words{format_magic, static_cast<std::uint32_t>(dropped_id), q_last,
                                     q_last >> 1U,
                                     static_cast<std::uint32_t>(destination.q_moduli.size())};
    for (std::size_t basis = 0; basis < destination.q_moduli.size(); ++basis) {
        const std::uint32_t q = destination.q_moduli[basis];
        words.push_back(static_cast<std::uint32_t>(destination.keyswitch_layout.q_mod_ids[basis]));
        words.push_back(hpu::model::inverse_mod_prime(q_last % q, q));
    }

    PreparedBfvModSwitchConstants result;
    result.id = id;
    result.source_parms_id = source.parms_id;
    result.destination_parms_id = destination.parms_id;
    result.source_chain_index = source.chain_index;
    result.destination_chain_index = destination.chain_index;
    result.dropped_mod_id = dropped_id;
    result.values = image_.add(id, words, hpu::runtime::AllocationKind::constant, true).span;
    result.hardware_prefix = id + "/hardware";
    result.hardware_component_capacity = component_capacity;
    const std::size_t degree = registry().poly_modulus_degree;
    const auto add_constant = [&](const std::string& name, std::uint32_t value) {
        add_constant_polynomial(image_, degree, name, value,
                                result.hardware_constant_polynomial_count);
    };
    const auto reserve_workspace = [&](const std::string& name) {
        image_.reserve(name, degree, hpu::runtime::AllocationKind::workspace);
        ++result.hardware_workspace_polynomial_count;
    };

    const std::uint32_t half = q_last >> 1U;
    for (std::size_t basis = 0; basis < source.q_moduli.size(); ++basis) {
        add_constant(
            mod_id(result.hardware_prefix + "/half", source.keyswitch_layout.q_mod_ids[basis]),
            half % source.q_moduli[basis]);
    }
    const std::string moddown_prefix = result.hardware_prefix + "/moddown";
    add_constant(mod_id(moddown_prefix + "/qhat_inv", dropped_id), 1);
    for (std::size_t basis = 0; basis < destination.q_moduli.size(); ++basis) {
        const int target_id = destination.keyswitch_layout.q_mod_ids[basis];
        add_constant(moddown_prefix + "/qhat_mod_target/target" + std::to_string(target_id) +
                         "/source" + std::to_string(dropped_id),
                     1);
        add_constant(mod_id(moddown_prefix + "/p_inverse", target_id),
                     hpu::model::inverse_mod_prime(q_last % destination.q_moduli[basis],
                                                   destination.q_moduli[basis]));
    }

    const std::string workspace_prefix = result.hardware_prefix + "/workspace";
    for (std::size_t component = 0; component < component_capacity; ++component) {
        for (int context : source.keyswitch_layout.q_mod_ids) {
            reserve_workspace(
                mod_id(workspace_prefix + "/rounded/c" + std::to_string(component), context));
        }
    }
    reserve_workspace(workspace_prefix + "/bconv/normalized0");
    for (int context : destination.keyswitch_layout.q_mod_ids) {
        reserve_workspace(mod_id(workspace_prefix + "/moddown/correction", context));
    }
    return result;
}

const hpu::runtime::HpuMemImage& BfvApplicationImageBuilder::image() const noexcept
{
    return image_;
}

const BfvLevelChain& BfvApplicationImageBuilder::level_chain() const noexcept
{
    return level_chain_;
}

const BfvLevelRegistry& BfvApplicationImageBuilder::registry() const noexcept
{
    return level_chain_.registry();
}

const std::vector<BfvLevelDescriptor>& BfvApplicationImageBuilder::levels() const noexcept
{
    return level_chain_.levels();
}

const BfvLevelDescriptor&
BfvApplicationImageBuilder::require_level(::seal::parms_id_type parms_id) const
{
    return level_chain_.require(parms_id);
}

void register_bfv_rns_object(hpu::runtime::Application& application,
                             const PreparedBfvRnsObject& object, bool required_output)
{
    for (const PreparedPolynomial& component : object.components) {
        if (component.modulus_ids.size() != component.limbs.size()) {
            throw std::invalid_argument("prepared BFV RNS object has inconsistent limbs");
        }
        for (std::size_t basis = 0; basis < component.limbs.size(); ++basis) {
            hpu::runtime::ObjectState state;
            state.backing = component.limbs[basis];
            state.level = object.chain_index;
            state.modulus_ids = {component.modulus_ids[basis]};
            state.domain = object.domain;
            state.key_domain = object.key_domain;
            state.required_output = required_output;
            application.register_object(component.id + "/mod" +
                                            std::to_string(component.modulus_ids[basis]),
                                        std::move(state));
        }
    }
}

} // namespace hpu::seal_adapter
