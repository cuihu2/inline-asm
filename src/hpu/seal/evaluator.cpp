#include "hpu/seal/evaluator.hpp"

#include "hpu/seal/application_delivery.hpp"
#include "hpu/seal/bfv_operation_codegen.hpp"
#include "hpu/seal/bfv_operation_relocation.hpp"
#include "hpu/seal/bfv_software_executor.hpp"
#include "hpu/seal/bgv_software_executor.hpp"
#include "hpu/seal/operation_codegen.hpp"
#include "hpu/seal/operation_relocation.hpp"
#include "hpu/seal/software_executor.hpp"
#include "scheme/bgv/basic_arithmetic.hpp"
#include "scheme/bgv/ciphertext_multiply.hpp"
#include "scheme/bgv/modswitch.hpp"
#include "scheme/ckks/galois.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <functional>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace hpu::seal_adapter {
namespace detail {
enum class FrontendKind {
    input, scale_view, add, sub, multiply, square, negate,
    add_plain, sub_plain, multiply_plain, relinearize, rescale,
    mod_switch, rotate_vector, conjugate, rotate_rows, rotate_columns
};

struct FrontendValue {
    FrontendKind kind = FrontendKind::input;
    std::string id;
    ::seal::parms_id_type parms_id{};
    std::size_t components = 0;
    double scale = 1.0;
    std::uint64_t correction_factor = 1;
    std::vector<std::size_t> inputs;
    std::size_t plain = 0;
    int rotation_steps = 0;
    std::shared_ptr<const ::seal::Ciphertext> imported;
    std::shared_ptr<const ::seal::RelinKeys> relin_keys;
    std::shared_ptr<const ::seal::GaloisKeys> galois_keys;
};
struct FrontendPlaintext {
    std::string id;
    std::shared_ptr<const ::seal::Plaintext> imported;
};
struct FrontendState {
    explicit FrontendState(const ::seal::SEALContext& source) : context(source) {}
    ::seal::SEALContext context;
    std::vector<FrontendValue> values;
    std::vector<FrontendPlaintext> plains;
    std::vector<std::pair<std::string, std::size_t>> outputs;
    std::vector<std::shared_ptr<const ::seal::RelinKeys>> relin_keys;
    std::vector<std::shared_ptr<const ::seal::GaloisKeys>> galois_keys;
    std::set<std::string> names;
    std::size_t next_value = 0;
};
struct CompiledFrontend {
    std::shared_ptr<FrontendState> owner;
    hpu::runtime::HpuMemImage image{1};
    hpu::delivery::ApplicationPackageRequest request;
    std::vector<::seal::Ciphertext> oracles;
    std::size_t node_count = 0;
    std::string resource_report;
    bool verified = false;
};
} // namespace detail
namespace {
using Kind = detail::FrontendKind;
using Value = detail::FrontendValue;
using State = detail::FrontendState;

::seal::scheme_type scheme(const State& state)
{ return state.context.key_context_data()->parms().scheme(); }

void valid_name(const std::string& id)
{
    if (id.empty()) throw std::invalid_argument("frontend value name is empty");
    bool segment_start = true;
    for (unsigned char c : id) {
        if (c == '/') {
            if (segment_start) throw std::invalid_argument("frontend name contains an empty segment");
            segment_start = true;
        } else {
            if ((segment_start && !std::isalpha(c) && c != '_') ||
                (!segment_start && !std::isalnum(c) && c != '_'))
                throw std::invalid_argument("frontend name must contain identifier path segments");
            segment_start = false;
        }
    }
    if (segment_start) throw std::invalid_argument("frontend name ends in a slash");
    if (id == "output" || id.compare(0, 9, "frontend/") == 0)
        throw std::invalid_argument("frontend name is reserved");
}

bool same_ciphertext(const ::seal::Ciphertext& a, const ::seal::Ciphertext& b)
{
    const auto count = a.size() * a.poly_modulus_degree() * a.coeff_modulus_size();
    return a.parms_id() == b.parms_id() && a.size() == b.size() &&
        a.poly_modulus_degree() == b.poly_modulus_degree() &&
        a.coeff_modulus_size() == b.coeff_modulus_size() &&
        a.is_ntt_form() == b.is_ntt_form() && a.scale() == b.scale() &&
        a.correction_factor() == b.correction_factor() &&
        (!count || std::equal(a.data(), a.data() + count, b.data()));
}

template<class Key>
std::shared_ptr<const Key> intern_key(
    const Key& keys, std::vector<std::shared_ptr<const Key>>& registry,
    const ::seal::SEALContext& context)
{
    if (!::seal::is_valid_for(keys, context))
        throw std::invalid_argument("frontend evaluation key is invalid for its context");
    for (const auto& existing : registry) {
        if (keys.parms_id() != existing->parms_id() || keys.data().size() != existing->data().size())
            continue;
        bool equal = true;
        for (std::size_t i = 0; equal && i < keys.data().size(); ++i) {
            equal = keys.data()[i].size() == existing->data()[i].size();
            for (std::size_t j = 0; equal && j < keys.data()[i].size(); ++j)
                equal = same_ciphertext(keys.data()[i][j].data(), existing->data()[i][j].data());
        }
        if (equal) return existing;
    }
    auto snapshot = std::make_shared<const Key>(keys);
    registry.push_back(snapshot);
    return snapshot;
}

void require_components(const Value& value, std::size_t count)
{
    if (value.components != count)
        throw std::invalid_argument("frontend operation does not support this component count");
}

std::size_t commit(State& state, Value value)
{
    value.id = "frontend/value_" + std::to_string(state.next_value++);
    const auto result = state.values.size();
    state.values.push_back(std::move(value));
    return result;
}

void valid_scale(const State& state, const ::seal::parms_id_type& parms, double scale)
{
    auto level = state.context.get_context_data(parms);
    if (!level || !std::isfinite(scale) || scale <= 0 ||
        std::log2(scale) >= level->total_coeff_modulus_bit_count())
        throw std::invalid_argument("frontend CKKS scale is invalid or exceeds the active modulus");
}

std::size_t physical_origin(const State& state, std::size_t index)
{
    while (state.values.at(index).kind == Kind::scale_view)
        index = state.values.at(index).inputs.front();
    return index;
}

// Output roots are logical handles. Metadata views share the physical value,
// while repeated labels for that value must not duplicate deployment goldens.
std::vector<std::size_t> output_indices(const State& state)
{
    std::vector<std::size_t> roots;
    for (const auto& output : state.outputs) roots.push_back(output.second);
    if (roots.empty()) {
        std::size_t last = state.values.size();
        for (std::size_t i = state.values.size(); i > 0; --i) {
            const auto kind = state.values[i - 1].kind;
            if (kind != Kind::input && kind != Kind::scale_view) {
                last = i - 1;
                break;
            }
        }
        if (last != state.values.size()) {
            // Use the latest metadata view of that computation, rather than a
            // later import or a view of an unrelated, earlier computation.
            for (std::size_t i = state.values.size(); i > last; --i) {
                if (physical_origin(state, i - 1) == last) {
                    roots.push_back(i - 1);
                    break;
                }
            }
        }
    }
    if (roots.empty()) throw std::invalid_argument("frontend application has no computation");
    return roots;
}

std::vector<std::string> exported_prefixes(
    const State& state, const std::vector<std::string>& physical_ids)
{
    std::vector<std::string> prefixes;
    for (const auto index : output_indices(state)) {
        const auto& prefix = physical_ids.at(index);
        if (std::find(prefixes.begin(), prefixes.end(), prefix) == prefixes.end())
            prefixes.push_back(prefix);
    }
    return prefixes;
}

std::string json_string(const std::string& text)
{
    // Names are restricted to identifier paths; no escaping is needed here.
    return '"' + text + '"';
}

void check_metadata(const State& state, const Value& value, const ::seal::Ciphertext& oracle)
{
    if (value.parms_id != oracle.parms_id() || value.components != oracle.size() ||
        value.correction_factor != oracle.correction_factor() ||
        oracle.is_ntt_form() != (scheme(state) != ::seal::scheme_type::bfv) ||
        std::abs(value.scale - oracle.scale()) >
            1e-12 * std::max(value.scale, oracle.scale()))
        throw std::runtime_error("frontend inferred metadata differs from SEAL oracle: " + value.id);
}

std::vector<::seal::Ciphertext> execute_oracle(const State& state)
{
    ::seal::Evaluator evaluator(state.context);
    std::vector<::seal::Ciphertext> result;
    result.reserve(state.values.size());
    for (const auto& value : state.values) {
        ::seal::Ciphertext output;
        if (value.kind == Kind::input) output = *value.imported;
        else {
            const auto& a = result.at(value.inputs.front());
            switch (value.kind) {
            case Kind::scale_view: output = a; output.scale() = value.scale; break;
            case Kind::add: evaluator.add(a, result.at(value.inputs[1]), output); break;
            case Kind::sub: evaluator.sub(a, result.at(value.inputs[1]), output); break;
            case Kind::multiply: evaluator.multiply(a, result.at(value.inputs[1]), output); break;
            case Kind::square: evaluator.square(a, output); break;
            case Kind::negate: evaluator.negate(a, output); break;
            case Kind::add_plain: evaluator.add_plain(a, *state.plains.at(value.plain).imported, output); break;
            case Kind::sub_plain: evaluator.sub_plain(a, *state.plains.at(value.plain).imported, output); break;
            case Kind::multiply_plain: evaluator.multiply_plain(a, *state.plains.at(value.plain).imported, output); break;
            case Kind::relinearize: evaluator.relinearize(a, *value.relin_keys, output); break;
            case Kind::rescale: evaluator.rescale_to_next(a, output); break;
            case Kind::mod_switch: evaluator.mod_switch_to_next(a, output); break;
            case Kind::rotate_vector: evaluator.rotate_vector(a, value.rotation_steps, *value.galois_keys, output); break;
            case Kind::conjugate: evaluator.complex_conjugate(a, *value.galois_keys, output); break;
            case Kind::rotate_rows: evaluator.rotate_rows(a, value.rotation_steps, *value.galois_keys, output); break;
            case Kind::rotate_columns: evaluator.rotate_columns(a, *value.galois_keys, output); break;
            case Kind::input: break;
            }
        }
        check_metadata(state, value, output);
        result.push_back(std::move(output));
    }
    return result;
}

template<class Map, class Factory>
typename Map::mapped_type& cached(Map& map, const typename Map::key_type& key, Factory factory)
{
    auto found = map.find(key);
    if (found == map.end()) found = map.emplace(key, factory()).first;
    return found->second;
}

std::string level_tag(const ::seal::SEALContext& context, const ::seal::parms_id_type& id)
{ return "level_" + std::to_string(context.get_context_data(id)->chain_index()); }

std::uint32_t galois_element(const State& state, const Value& value)
{
    const auto degree = state.context.key_context_data()->parms().poly_modulus_degree();
    return value.kind == Kind::conjugate || value.kind == Kind::rotate_columns
        ? hpu::scheme::ckks::conjugation_galois_element(degree)
        : hpu::scheme::ckks::rotation_galois_element(degree, value.rotation_steps);
}
} // namespace

Ciphertext::Ciphertext(std::shared_ptr<State> owner, std::size_t index)
    : owner_(std::move(owner)), index_(index) {}
bool Ciphertext::valid() const noexcept { return owner_ && index_ < owner_->values.size(); }
const std::string& Ciphertext::value_id() const
{ if (!valid()) throw std::invalid_argument("empty frontend ciphertext"); return owner_->values[index_].id; }
::seal::parms_id_type Ciphertext::parms_id() const { value_id(); return owner_->values[index_].parms_id; }
std::size_t Ciphertext::size() const { value_id(); return owner_->values[index_].components; }
double Ciphertext::scale() const { value_id(); return owner_->values[index_].scale; }
std::uint64_t Ciphertext::correction_factor() const { value_id(); return owner_->values[index_].correction_factor; }

Plaintext::Plaintext(std::shared_ptr<State> owner, std::size_t index)
    : owner_(std::move(owner)), index_(index) {}
bool Plaintext::valid() const noexcept { return owner_ && index_ < owner_->plains.size(); }
const std::string& Plaintext::value_id() const
{ if (!valid()) throw std::invalid_argument("empty frontend plaintext"); return owner_->plains[index_].id; }
::seal::parms_id_type Plaintext::parms_id() const { value_id(); return owner_->plains[index_].imported->parms_id(); }
double Plaintext::scale() const { value_id(); return owner_->plains[index_].imported->scale(); }

ApplicationBuilder::ApplicationBuilder(const ::seal::SEALContext& context)
{
    if (!context.parameters_set() || !context.key_context_data() ||
        (context.key_context_data()->parms().scheme() != ::seal::scheme_type::ckks &&
         context.key_context_data()->parms().scheme() != ::seal::scheme_type::bfv &&
         context.key_context_data()->parms().scheme() != ::seal::scheme_type::bgv))
        throw std::invalid_argument("frontend requires a valid CKKS, BFV, or BGV context");
    const auto degree = context.key_context_data()->parms().poly_modulus_degree();
    if (degree < 128 || degree > 65536 || (degree & (degree - 1)))
        throw std::invalid_argument("frontend HPU degree must be a power of two in [128,65536]");
    state_ = std::make_shared<State>(context);
}

Ciphertext ApplicationBuilder::import_ciphertext(std::string id, const ::seal::Ciphertext& input)
{
    valid_name(id);
    if (!::seal::is_valid_for(input, state_->context) || (input.size() != 2 && input.size() != 3) ||
        input.is_ntt_form() != (scheme(*state_) != ::seal::scheme_type::bfv))
        throw std::invalid_argument("frontend input ciphertext has invalid metadata, domain, or shape");
    if (state_->names.count(id)) throw std::invalid_argument("frontend name is duplicated");
    Value value;
    value.id = id; value.parms_id = input.parms_id(); value.components = input.size();
    value.scale = input.scale(); value.correction_factor = input.correction_factor();
    for (const auto& existing : state_->values)
        if (existing.imported && same_ciphertext(input, *existing.imported)) {
            value.imported = existing.imported; break;
        }
    if (!value.imported) value.imported = std::make_shared<const ::seal::Ciphertext>(input);
    const auto index = state_->values.size();
    state_->values.push_back(std::move(value));
    state_->names.insert(id);
    return Ciphertext(state_, index);
}

Plaintext ApplicationBuilder::import_plaintext(std::string id, const ::seal::Plaintext& input)
{
    valid_name(id);
    if (!::seal::is_valid_for(input, state_->context) ||
        input.is_ntt_form() != (scheme(*state_) == ::seal::scheme_type::ckks))
        throw std::invalid_argument("frontend plaintext has invalid metadata or domain");
    if (state_->names.count(id)) throw std::invalid_argument("frontend name is duplicated");
    std::shared_ptr<const ::seal::Plaintext> captured;
    for (const auto& existing : state_->plains) {
        const auto& a = *existing.imported;
        if (a.parms_id() == input.parms_id() && a.scale() == input.scale() &&
            a.coeff_count() == input.coeff_count() &&
            (!a.coeff_count() || std::equal(a.data(), a.data() + a.coeff_count(), input.data()))) {
            captured = existing.imported; break;
        }
    }
    if (!captured) captured = std::make_shared<const ::seal::Plaintext>(input);
    const auto index = state_->plains.size();
    state_->plains.push_back({id, std::move(captured)});
    state_->names.insert(id);
    return Plaintext(state_, index);
}

Evaluator ApplicationBuilder::evaluator() { return Evaluator(*this); }
const ::seal::SEALContext& ApplicationBuilder::context() const { return state_->context; }
void ApplicationBuilder::mark_output(std::string id, const Ciphertext& value)
{
    valid_name(id);
    if (value.owner_ != state_ || !value.valid())
        throw std::invalid_argument("frontend output belongs to another application");
    if (state_->values[physical_origin(*state_, value.index_)].kind == Kind::input)
        throw std::invalid_argument("frontend marked output must be produced by an operation");
    for (const auto& output : state_->outputs)
        if (output.first == id) throw std::invalid_argument("frontend output label is duplicated");
    state_->outputs.emplace_back(std::move(id), value.index_);
}

Evaluator::Evaluator(ApplicationBuilder& application) : state_(application.state_) {}
std::size_t Evaluator::require(const Ciphertext& value) const
{
    if (value.owner_ != state_ || !value.valid())
        throw std::invalid_argument("frontend ciphertext belongs to another application or is empty");
    return value.index_;
}
std::size_t Evaluator::require(const Plaintext& value) const
{
    if (value.owner_ != state_ || !value.valid())
        throw std::invalid_argument("frontend plaintext belongs to another application or is empty");
    return value.index_;
}

void Evaluator::binary(int raw_kind, const Ciphertext& a, const Ciphertext& b, Ciphertext& dest)
{
    const auto ai = require(a), bi = require(b);
    const auto left = state_->values[ai], right = state_->values[bi];
    require_components(left, 2); require_components(right, 2);
    if (left.parms_id != right.parms_id)
        throw std::invalid_argument("frontend binary operands require matching levels");
    Value value = left;
    value.imported.reset(); value.kind = static_cast<Kind>(raw_kind); value.inputs = {ai, bi};
    const bool multiply = value.kind == Kind::multiply;
    value.components = multiply ? 3 : 2;
    if (scheme(*state_) == ::seal::scheme_type::ckks) {
        if (!multiply && !ckks_scales_compatible(left.scale, right.scale))
            throw std::invalid_argument("frontend CKKS add/sub requires matching scales; use explicit set_scale");
        value.scale = multiply ? left.scale * right.scale : left.scale;
        valid_scale(*state_, value.parms_id, value.scale);
    } else if (scheme(*state_) == ::seal::scheme_type::bgv) {
        const auto t = state_->context.key_context_data()->parms().plain_modulus().value();
        value.correction_factor = multiply
            ? hpu::scheme::bgv::multiply_correction_factor(left.correction_factor, right.correction_factor, t)
            : hpu::scheme::bgv::balance_correction_factors(left.correction_factor, right.correction_factor, t).output_factor;
    } else if (multiply && state_->context.get_context_data(left.parms_id)->parms().coeff_modulus().size() < 2)
        throw std::invalid_argument("frontend BFV multiply requires at least two active Q moduli");
    dest = Ciphertext(state_, commit(*state_, std::move(value)));
}

void Evaluator::unary(int raw_kind, const Ciphertext& a, Ciphertext& dest)
{
    const auto ai = require(a);
    Value value = state_->values[ai];
    value.imported.reset(); value.kind = static_cast<Kind>(raw_kind); value.inputs = {ai};
    if (value.kind == Kind::rescale) {
        if (scheme(*state_) != ::seal::scheme_type::ckks)
            throw std::invalid_argument("rescale_to_next requires CKKS");
        if (value.components != 2 && value.components != 3)
            throw std::invalid_argument("frontend rescale supports two/three components");
    } else {
        require_components(value, 2);
        if (value.kind == Kind::negate && scheme(*state_) == ::seal::scheme_type::bgv)
            throw std::invalid_argument("BGV negate is not yet supported by the operation plan");
        if (value.kind == Kind::mod_switch && scheme(*state_) == ::seal::scheme_type::ckks)
            throw std::invalid_argument("CKKS mod_switch_to_next is not yet supported by the operation plan");
    }
    if (value.kind == Kind::square) {
        value.components = 3;
        if (scheme(*state_) == ::seal::scheme_type::ckks) {
            value.scale *= value.scale;
            valid_scale(*state_, value.parms_id, value.scale);
        } else if (scheme(*state_) == ::seal::scheme_type::bgv)
            value.correction_factor = hpu::scheme::bgv::multiply_correction_factor(value.correction_factor,
                value.correction_factor, state_->context.key_context_data()->parms().plain_modulus().value());
        else if (state_->context.get_context_data(value.parms_id)->parms().coeff_modulus().size() < 2)
            throw std::invalid_argument("frontend BFV square requires at least two active Q moduli");
    }
    if (value.kind == Kind::rescale || value.kind == Kind::mod_switch) {
        const auto source = state_->context.get_context_data(value.parms_id);
        if (!source->next_context_data()) throw std::invalid_argument("frontend ciphertext has no next level");
        if (value.kind == Kind::rescale)
            value.scale /= source->parms().coeff_modulus().back().value();
        if (scheme(*state_) == ::seal::scheme_type::bgv)
            value.correction_factor = hpu::scheme::bgv::modswitch_correction_factor(value.correction_factor,
                source->parms().coeff_modulus().back().value(), source->parms().plain_modulus().value());
        value.parms_id = source->next_context_data()->parms_id();
    }
    dest = Ciphertext(state_, commit(*state_, std::move(value)));
}

void Evaluator::plain(int raw_kind, const Ciphertext& a, const Plaintext& p, Ciphertext& dest)
{
    const auto ai = require(a), pi = require(p);
    Value value = state_->values[ai];
    require_components(value, 2);
    const auto& plain = *state_->plains[pi].imported;
    value.imported.reset(); value.kind = static_cast<Kind>(raw_kind); value.inputs = {ai}; value.plain = pi;
    if (scheme(*state_) == ::seal::scheme_type::ckks) {
        if (plain.parms_id() != value.parms_id)
            throw std::invalid_argument("frontend CKKS plaintext and ciphertext levels differ");
        if (value.kind == Kind::multiply_plain) value.scale *= plain.scale();
        else if (!ckks_scales_compatible(value.scale, plain.scale()))
            throw std::invalid_argument("frontend CKKS plaintext addition requires matching scales");
        valid_scale(*state_, value.parms_id, value.scale);
    }
    dest = Ciphertext(state_, commit(*state_, std::move(value)));
}

#define BINARY(method, kind) void Evaluator::method(const Ciphertext& a, const Ciphertext& b, Ciphertext& out) { binary(static_cast<int>(Kind::kind), a, b, out); }
BINARY(add, add)
BINARY(sub, sub)
BINARY(multiply, multiply)
#undef BINARY
#define UNARY(method, kind) void Evaluator::method(const Ciphertext& a, Ciphertext& out) { unary(static_cast<int>(Kind::kind), a, out); }
UNARY(square, square)
UNARY(negate, negate)
UNARY(rescale_to_next, rescale)
UNARY(mod_switch_to_next, mod_switch)
#undef UNARY
#define PLAIN(method, kind) void Evaluator::method(const Ciphertext& a, const Plaintext& p, Ciphertext& out) { plain(static_cast<int>(Kind::kind), a, p, out); }
PLAIN(add_plain, add_plain)
PLAIN(sub_plain, sub_plain)
PLAIN(multiply_plain, multiply_plain)
#undef PLAIN

void Evaluator::relinearize(const Ciphertext& a, const ::seal::RelinKeys& keys, Ciphertext& dest)
{
    const auto ai = require(a);
    Value value = state_->values[ai];
    require_components(value, 3);
    if (!keys.has_key(2)) throw std::invalid_argument("frontend relinearization key is missing");
    value.relin_keys = intern_key(keys, state_->relin_keys, state_->context);
    value.imported.reset(); value.kind = Kind::relinearize; value.inputs = {ai}; value.components = 2;
    dest = Ciphertext(state_, commit(*state_, std::move(value)));
}

void Evaluator::rotation(int raw_kind, const Ciphertext& a, int steps,
                         const ::seal::GaloisKeys& keys, Ciphertext& dest)
{
    const auto ai = require(a);
    Value value = state_->values[ai];
    require_components(value, 2);
    value.kind = static_cast<Kind>(raw_kind); value.inputs = {ai}; value.rotation_steps = steps;
    const bool ckks_op = value.kind == Kind::rotate_vector || value.kind == Kind::conjugate;
    if (ckks_op != (scheme(*state_) == ::seal::scheme_type::ckks))
        throw std::invalid_argument("frontend rotation interface does not match the encryption scheme");
    if (!ckks_op && !state_->context.first_context_data()->qualifiers().using_batching)
        throw std::invalid_argument("frontend integer rotation requires batching parameters");
    if ((value.kind == Kind::rotate_vector || value.kind == Kind::rotate_rows) && steps == 0)
        throw std::invalid_argument("frontend zero rotation is not an operation; retain the input handle");
    const auto element = galois_element(*state_, value);
    if (!keys.has_key(element)) throw std::invalid_argument("frontend requested Galois key is missing");
    value.galois_keys = intern_key(keys, state_->galois_keys, state_->context);
    value.imported.reset();
    dest = Ciphertext(state_, commit(*state_, std::move(value)));
}

void Evaluator::rotate_vector(const Ciphertext& a, int steps, const ::seal::GaloisKeys& k, Ciphertext& out)
{ rotation(static_cast<int>(Kind::rotate_vector), a, steps, k, out); }
void Evaluator::complex_conjugate(const Ciphertext& a, const ::seal::GaloisKeys& k, Ciphertext& out)
{ rotation(static_cast<int>(Kind::conjugate), a, 0, k, out); }
void Evaluator::rotate_rows(const Ciphertext& a, int steps, const ::seal::GaloisKeys& k, Ciphertext& out)
{ rotation(static_cast<int>(Kind::rotate_rows), a, steps, k, out); }
void Evaluator::rotate_columns(const Ciphertext& a, const ::seal::GaloisKeys& k, Ciphertext& out)
{ rotation(static_cast<int>(Kind::rotate_columns), a, 0, k, out); }

void Evaluator::set_scale(Ciphertext& a, double scale)
{
    const auto ai = require(a);
    if (scheme(*state_) != ::seal::scheme_type::ckks)
        throw std::invalid_argument("frontend set_scale requires CKKS");
    Value value = state_->values[ai];
    valid_scale(*state_, value.parms_id, scale);
    value.kind = Kind::scale_view; value.inputs = {ai}; value.scale = scale; value.imported.reset();
    a = Ciphertext(state_, commit(*state_, std::move(value)));
}

namespace {
bool requires_twiddles(const State& state)
{
    for (const auto& value : state.values) {
        switch (value.kind) {
        case Kind::relinearize: case Kind::rescale:
        case Kind::rotate_vector: case Kind::conjugate:
        case Kind::rotate_rows: case Kind::rotate_columns:
            return true;
        case Kind::multiply: case Kind::square: case Kind::multiply_plain:
            if (scheme(state) == ::seal::scheme_type::bfv) return true;
            break;
        default: break;
        }
    }
    return false;
}

void compile_ckks(const State& state, const std::string& stem,
                  std::uint64_t capacity, detail::CompiledFrontend& data,
                  std::vector<std::string>& physical_ids)
{
    CkksApplicationImageBuilder builder(state.context, capacity);
    builder.add_modulus_table();
    const auto tables = requires_twiddles(state) ? builder.add_canonical_twiddles()
        : std::vector<PreparedCanonicalTwiddles>{};
    CkksOperationPlan plan(builder);
    std::vector<PreparedRnsObject> prepared(state.values.size());
    std::map<const ::seal::Ciphertext*, PreparedRnsObject> inputs;
    std::map<const ::seal::Plaintext*, PreparedRnsObject> plains;
    std::map<std::string, PreparedKeySwitchConstants> switches;
    std::map<std::string, PreparedRescaleConstants> rescales;
    std::map<std::string, std::size_t> rescale_capacity;
    std::map<std::string, PreparedEvaluationKey> keys;
    std::map<std::string, std::vector<PreparedFusedAutomorphismTwiddles>> rotations;
    std::vector<std::function<void(CkksSoftwareExecutor&)>> execute;
    std::vector<::seal::Ciphertext> oracles;
    // One resource per source level supports every rescale at that level.
    // Determine the largest tensor shape before allocating its workspaces.
    for (const auto& value : state.values) {
        if (value.kind != Kind::rescale) continue;
        const auto tag = level_tag(state.context, state.values.at(value.inputs[0]).parms_id);
        rescale_capacity[tag] = std::max(rescale_capacity[tag], value.components);
    }
    const auto key_name = [](const void* pointer, const auto& registry) {
        for (std::size_t i = 0; i < registry.size(); ++i)
            if (registry[i].get() == pointer) return std::to_string(i);
        throw std::logic_error("frontend key is missing from snapshot registry");
    };
    for (std::size_t i = 0; i < state.values.size(); ++i) {
        const auto& value = state.values[i];
        if (value.kind == Kind::input) {
            prepared[i] = cached(inputs, value.imported.get(), [&] {
                return builder.add_ciphertext(value.id, *value.imported);
            });
        } else if (value.kind == Kind::scale_view) {
            prepared[i] = prepared.at(value.inputs[0]);
            prepared[i].scale = value.scale;
        } else {
            const auto a = prepared.at(value.inputs[0]);
            PreparedRnsObject output;
            const auto step = "node_" + std::to_string(execute.size());
            const auto& level = builder.level_chain().require(a.parms_id);
            const auto tag = level_tag(state.context, a.parms_id);
            switch (value.kind) {
            case Kind::add: case Kind::sub: case Kind::multiply: {
                const auto b = prepared.at(value.inputs[1]);
                if (value.kind == Kind::add) {
                    output = plan.append_add(step, a, b, value.id);
                    execute.push_back([a, b, output](auto& e) { e.add(a, b, output); });
                } else if (value.kind == Kind::sub) {
                    output = plan.append_subtract(step, a, b, value.id);
                    execute.push_back([a, b, output](auto& e) { e.subtract(a, b, output); });
                } else {
                    output = plan.append_multiply(step, a, b, value.id);
                    execute.push_back([a, b, output](auto& e) { e.multiply(a, b, output); });
                }
                break;
            }
            case Kind::square:
                output = plan.append_square(step, a, value.id);
                execute.push_back([a, output](auto& e) { e.square(a, output); });
                break;
            case Kind::negate:
                output = plan.append_negate(step, a, value.id);
                execute.push_back([a, output](auto& e) { e.negate(a, output); });
                break;
            case Kind::add_plain: case Kind::sub_plain: case Kind::multiply_plain: {
                const auto& plain = state.plains.at(value.plain);
                const auto p = cached(plains, plain.imported.get(), [&] {
                    return builder.add_plaintext(plain.id, *plain.imported);
                });
                if (value.kind == Kind::add_plain) {
                    output = plan.append_add_plain(step, a, p, value.id);
                    execute.push_back([a, p, output](auto& e) { e.add_plain(a, p, output); });
                } else if (value.kind == Kind::sub_plain) {
                    output = plan.append_subtract_plain(step, a, p, value.id);
                    execute.push_back([a, p, output](auto& e) { e.subtract_plain(a, p, output); });
                } else {
                    output = plan.append_multiply_plain(step, a, p, value.id);
                    execute.push_back([a, p, output](auto& e) { e.multiply_plain(a, p, output); });
                }
                break;
            }
            case Kind::relinearize: {
                const std::string id = "frontend/keys/relin_" + key_name(value.relin_keys.get(), state.relin_keys) + '/' + tag;
                const auto key = cached(keys, id, [&] { return builder.add_relinearization_key(id, *value.relin_keys, level); });
                const auto constants = cached(switches, tag, [&] {
                    return builder.add_keyswitch_constants("frontend/constants/keyswitch/" + tag, level);
                });
                output = plan.append_relinearize(step, a, key, constants, value.id);
                execute.push_back([a, key, constants, output, &tables](auto& e) { e.relinearize(a, key, constants, output, tables); });
                break;
            }
            case Kind::rescale: {
                const auto constants = cached(rescales, tag, [&] {
                    return builder.add_rescale_constants("frontend/constants/rescale/" + tag,
                        level, rescale_capacity.at(tag));
                });
                output = plan.append_rescale(step, a, constants, value.id);
                execute.push_back([a, constants, output, &tables](auto& e) { e.rescale(a, constants, output, tables); });
                break;
            }
            case Kind::rotate_vector: case Kind::conjugate: {
                const auto element = galois_element(state, value);
                const auto rotation_id = tag + "/element_" + std::to_string(element);
                const std::string key_id = "frontend/keys/galois_" + key_name(value.galois_keys.get(), state.galois_keys) + '/' + rotation_id;
                const auto key = cached(keys, key_id, [&] { return builder.add_galois_key(key_id, *value.galois_keys, element, level); });
                const auto constants = cached(switches, tag, [&] {
                    return builder.add_keyswitch_constants("frontend/constants/keyswitch/" + tag, level);
                });
                const auto fused = cached(rotations, rotation_id, [&] {
                    return builder.add_fused_automorphism_twiddles("frontend/twiddles/" + rotation_id, element, level);
                });
                const auto workspace = builder.reserve_ciphertext(value.id + "/workspace", a.metadata(), 2,
                    hpu::runtime::PolynomialDomain::coefficient, element, hpu::runtime::AllocationKind::workspace);
                if (value.kind == Kind::rotate_vector) {
                    const auto steps = value.rotation_steps;
                    output = plan.append_rotate_slots(step, a, steps, key, constants, fused, workspace, value.id);
                    execute.push_back([a, steps, key, constants, fused, workspace, output, &tables](auto& e) {
                        e.rotate_slots(a, steps, key, constants, fused, tables, workspace, output);
                    });
                } else {
                    output = plan.append_conjugate(step, a, key, constants, fused, workspace, value.id);
                    execute.push_back([a, key, constants, fused, workspace, output, &tables](auto& e) {
                        e.conjugate(a, key, constants, fused, tables, workspace, output);
                    });
                }
                break;
            }
            default: throw std::logic_error("unexpected CKKS frontend operation");
            }
            prepared[i] = std::move(output);
            oracles.push_back(data.oracles.at(i));
        }
        physical_ids[i] = prepared[i].id;
    }
    builder.trim_capacity_to_used_lines();
    CkksSoftwareExecutor executor(state.context, builder.image());
    for (const auto& task : execute) task(executor);
    const auto lowered = lower_ckks_operation_plan(plan, state.context);
    const auto relocation = build_ckks_relocation_schedule(lowered, builder.image(), state.context);
    if (!relocation.complete()) throw std::runtime_error("frontend CKKS relocation is incomplete");
    const auto runtime = lower_ckks_runtime_program(lowered, relocation);
    const auto artifacts = render_ckks_runtime_artifacts(stem, runtime, builder.image().capacity_lines());
    data.request = make_ckks_application_package(stem, state.context, lowered, runtime, artifacts,
        builder.image(), oracles, executor.memory().words(), exported_prefixes(state, physical_ids));
    data.image = builder.image();
    data.request.initial_image = &data.image;
    data.node_count = execute.size();
}

void compile_bfv(const State& state, const std::string& stem,
                 std::uint64_t capacity, detail::CompiledFrontend& data,
                 std::vector<std::string>& physical_ids)
{
    BfvApplicationImageBuilder builder(state.context, capacity);
    builder.add_modulus_table();
    const auto tables = requires_twiddles(state) ? builder.add_canonical_twiddles()
        : std::vector<PreparedCanonicalTwiddles>{};
    BfvOperationPlan plan(builder);
    std::vector<PreparedBfvRnsObject> prepared(state.values.size());
    std::map<const ::seal::Ciphertext*, PreparedBfvRnsObject> inputs;
    std::map<std::string, PreparedBfvRnsObject> plains;
    std::map<std::string, PreparedKeySwitchConstants> switches;
    std::map<std::string, PreparedBfvMultiplyConstants> multiplies;
    std::map<std::string, PreparedBfvModSwitchConstants> modswitches;
    std::map<std::string, PreparedEvaluationKey> keys;
    std::map<std::string, std::vector<PreparedFusedAutomorphismTwiddles>> rotations;
    std::vector<std::function<void(BfvSoftwareExecutor&)>> execute;
    std::vector<::seal::Ciphertext> oracles;
    const auto key_name = [](const void* pointer, const auto& registry) {
        for (std::size_t i = 0; i < registry.size(); ++i)
            if (registry[i].get() == pointer) return std::to_string(i);
        throw std::logic_error("frontend key is missing from snapshot registry");
    };
    for (std::size_t i = 0; i < state.values.size(); ++i) {
        const auto& value = state.values[i];
        if (value.kind == Kind::input) {
            prepared[i] = cached(inputs, value.imported.get(), [&] {
                return builder.add_ciphertext(value.id, *value.imported);
            });
        } else {
            const auto a = prepared.at(value.inputs[0]);
            PreparedBfvRnsObject output;
            const auto step = "node_" + std::to_string(execute.size());
            const auto& level = builder.level_chain().require(a.parms_id);
            const auto tag = level_tag(state.context, a.parms_id);
            switch (value.kind) {
            case Kind::add: case Kind::sub: {
                const auto b = prepared.at(value.inputs[1]);
                if (value.kind == Kind::add) {
                    output = plan.append_add(step, a, b, value.id);
                    execute.push_back([a, b, output](auto& e) { e.add(a, b, output); });
                } else {
                    output = plan.append_subtract(step, a, b, value.id);
                    execute.push_back([a, b, output](auto& e) { e.subtract(a, b, output); });
                }
                break;
            }
            case Kind::multiply: case Kind::square: {
                const auto b = value.kind == Kind::square ? a : prepared.at(value.inputs[1]);
                const auto constants = cached(multiplies, tag, [&] {
                    return builder.add_multiply_constants("frontend/constants/multiply/" + tag, level);
                });
                output = plan.append_multiply(step, a, b, constants, value.id);
                execute.push_back([a, b, constants, output, &tables](auto& e) { e.multiply(a, b, constants, tables, output); });
                break;
            }
            case Kind::negate:
                output = plan.append_negate(step, a, value.id);
                execute.push_back([a, output](auto& e) { e.negate(a, output); });
                break;
            case Kind::add_plain: case Kind::sub_plain: case Kind::multiply_plain: {
                const auto& plain = state.plains.at(value.plain);
                std::size_t identity = 0;
                while (state.plains[identity].imported != plain.imported) ++identity;
                const std::string variant = std::string(value.kind == Kind::multiply_plain ? "multiply/" : "add_sub/") + tag;
                const std::string id = "frontend/plains/plain_" + std::to_string(identity) + '/' + variant;
                const auto p = cached(plains, id, [&] {
                    return value.kind == Kind::multiply_plain
                        ? builder.add_multiply_plaintext(id, *plain.imported, level)
                        : builder.add_add_subtract_plaintext(id, *plain.imported, level);
                });
                if (value.kind == Kind::add_plain) {
                    output = plan.append_add_plain(step, a, p, value.id);
                    execute.push_back([a, p, output](auto& e) { e.add_plain(a, p, output); });
                } else if (value.kind == Kind::sub_plain) {
                    output = plan.append_subtract_plain(step, a, p, value.id);
                    execute.push_back([a, p, output](auto& e) { e.subtract_plain(a, p, output); });
                } else {
                    output = plan.append_multiply_plain(step, a, p, value.id);
                    execute.push_back([a, p, output, &tables](auto& e) { e.multiply_plain(a, p, tables, output); });
                }
                break;
            }
            case Kind::relinearize: {
                const std::string id = "frontend/keys/relin_" + key_name(value.relin_keys.get(), state.relin_keys) + '/' + tag;
                const auto key = cached(keys, id, [&] { return builder.add_relinearization_key(id, *value.relin_keys, level); });
                const auto constants = cached(switches, tag, [&] {
                    return builder.add_keyswitch_constants("frontend/constants/keyswitch/" + tag, level);
                });
                output = plan.append_relinearize(step, a, key, constants, value.id);
                execute.push_back([a, key, constants, output, &tables](auto& e) { e.relinearize(a, key, constants, tables, output); });
                break;
            }
            case Kind::mod_switch: {
                const auto constants = cached(modswitches, tag, [&] {
                    return builder.add_mod_switch_constants("frontend/constants/modswitch/" + tag, level);
                });
                output = plan.append_mod_switch(step, a, constants, value.id);
                execute.push_back([a, constants, output](auto& e) { e.mod_switch(a, constants, output); });
                break;
            }
            case Kind::rotate_rows: case Kind::rotate_columns: {
                const auto element = galois_element(state, value);
                const auto rotation_id = tag + "/element_" + std::to_string(element);
                const std::string key_id = "frontend/keys/galois_" + key_name(value.galois_keys.get(), state.galois_keys) + '/' + rotation_id;
                const auto key = cached(keys, key_id, [&] { return builder.add_galois_key(key_id, *value.galois_keys, element, level); });
                const auto constants = cached(switches, tag, [&] {
                    return builder.add_keyswitch_constants("frontend/constants/keyswitch/" + tag, level);
                });
                const auto fused = cached(rotations, rotation_id, [&] {
                    return builder.add_fused_automorphism_twiddles("frontend/twiddles/" + rotation_id, element, level);
                });
                const auto workspace = builder.reserve_ciphertext(value.id + "/workspace", level, 2,
                    hpu::runtime::PolynomialDomain::coefficient, element, hpu::runtime::AllocationKind::workspace);
                if (value.kind == Kind::rotate_rows) {
                    const auto steps = value.rotation_steps;
                    output = plan.append_rotate_rows(step, a, steps, key, constants, fused, workspace, value.id);
                    execute.push_back([a, steps, key, constants, fused, workspace, output, &tables](auto& e) {
                        e.rotate_rows(a, steps, key, constants, fused, tables, workspace, output);
                    });
                } else {
                    output = plan.append_rotate_columns(step, a, key, constants, fused, workspace, value.id);
                    execute.push_back([a, key, constants, fused, workspace, output, &tables](auto& e) {
                        e.rotate_columns(a, key, constants, fused, tables, workspace, output);
                    });
                }
                break;
            }
            default: throw std::logic_error("unexpected BFV frontend operation");
            }
            prepared[i] = std::move(output);
            oracles.push_back(data.oracles.at(i));
        }
        physical_ids[i] = prepared[i].id;
    }
    builder.trim_capacity_to_used_lines();
    BfvSoftwareExecutor executor(state.context, builder.image());
    for (const auto& task : execute) task(executor);
    const auto lowered = lower_bfv_operation_plan(plan, state.context);
    const auto relocation = build_bfv_relocation_schedule(lowered, builder.image(), state.context);
    if (!relocation.complete()) throw std::runtime_error("frontend BFV relocation is incomplete");
    const auto runtime = lower_bfv_runtime_program(lowered, relocation);
    const auto artifacts = render_bfv_runtime_artifacts(stem, runtime, builder.image().capacity_lines());
    data.request = make_bfv_application_package(stem, state.context, lowered, runtime, artifacts,
        builder.image(), oracles, executor.memory().words(), exported_prefixes(state, physical_ids));
    data.image = builder.image();
    data.request.initial_image = &data.image;
    data.node_count = execute.size();
}

void compile_bgv(const State& state, const std::string& stem,
                 std::uint64_t capacity, detail::CompiledFrontend& data,
                 std::vector<std::string>& physical_ids)
{
    BgvOperationPlan plan(state.context);
    std::vector<BgvPlannedValue> prepared(state.values.size());
    std::map<const ::seal::Ciphertext*, BgvPlannedValue> inputs;
    std::vector<::seal::Ciphertext> oracles;
    for (std::size_t i = 0; i < state.values.size(); ++i) {
        const auto& value = state.values[i];
        if (value.kind == Kind::input) {
            prepared[i] = cached(inputs, value.imported.get(), [&] {
                return plan.add_ciphertext(value.id, *value.imported);
            });
        } else {
            const auto a = prepared.at(value.inputs[0]);
            const auto step = "node_" + std::to_string(oracles.size());
            switch (value.kind) {
            case Kind::add: prepared[i] = plan.append_add(step, a, prepared.at(value.inputs[1]), value.id); break;
            case Kind::sub: prepared[i] = plan.append_subtract(step, a, prepared.at(value.inputs[1]), value.id); break;
            case Kind::multiply: prepared[i] = plan.append_multiply(step, a, prepared.at(value.inputs[1]), value.id); break;
            case Kind::square: prepared[i] = plan.append_multiply(step, a, a, value.id); break;
            case Kind::add_plain: prepared[i] = plan.append_add_plain(step, a, *state.plains.at(value.plain).imported, value.id); break;
            case Kind::sub_plain: prepared[i] = plan.append_subtract_plain(step, a, *state.plains.at(value.plain).imported, value.id); break;
            case Kind::multiply_plain: prepared[i] = plan.append_multiply_plain(step, a, *state.plains.at(value.plain).imported, value.id); break;
            case Kind::relinearize: prepared[i] = plan.append_relinearize(step, a, *value.relin_keys, value.id); break;
            case Kind::mod_switch: prepared[i] = plan.append_modswitch_to_next(step, a, value.id); break;
            case Kind::rotate_rows: prepared[i] = plan.append_rotate_rows(step, a, value.rotation_steps, *value.galois_keys, value.id); break;
            case Kind::rotate_columns: prepared[i] = plan.append_rotate_columns(step, a, *value.galois_keys, value.id); break;
            default: throw std::logic_error("unexpected BGV frontend operation");
            }
            oracles.push_back(data.oracles.at(i));
        }
    }
    const auto output_index = output_indices(state).back();
    plan.set_output(prepared.at(output_index));
    for (std::size_t i = 0; i < prepared.size(); ++i)
        physical_ids[i] = plan.allocation_prefix(prepared[i]);
    auto application = plan.lower(capacity);
    BgvSoftwareExecutor executor(state.context, application.image);
    executor.execute(plan);
    data.request = make_bgv_application_package(stem, state.context, plan, application,
        oracles, executor.memory().words(), exported_prefixes(state, physical_ids));
    data.image = std::move(application.image);
    data.request.initial_image = &data.image;
    data.node_count = oracles.size();
}

void add_frontend_graph(const State& state, const std::vector<std::string>& physical_ids,
                        detail::CompiledFrontend& data)
{
    auto& graph = data.request.operation_graph_json;
    const auto final_index = output_indices(state).back();
    const auto final_marker = graph.rfind(",\"final_output\":");
    if (final_marker == std::string::npos) throw std::logic_error("frontend delivery graph has no final output");
    graph.resize(final_marker);
    std::ostringstream out;
    out << std::setprecision(17);
    out << ",\"final_output\":" << json_string(physical_ids.at(final_index))
        << ",\"frontend\":\"seal_evaluator\",\"metadata_views\":[";
    bool first = true;
    for (std::size_t i = 0; i < state.values.size(); ++i) {
        const auto& value = state.values[i];
        if (value.kind != Kind::scale_view) continue;
        if (!first) out << ',';
        first = false;
        out << "{\"id\":" << json_string(value.id) << ",\"kind\":\"set_scale\",\"input\":"
            << json_string(state.values.at(value.inputs[0]).id) << ",\"physical_output\":"
            << json_string(physical_ids.at(i)) << ",\"scale\":" << value.scale << '}';
    }
    out << "],\"marked_outputs\":[";
    if (state.outputs.empty())
        out << "{\"id\":\"result\",\"value\":" << json_string(state.values.at(final_index).id)
            << ",\"physical_output\":" << json_string(physical_ids.at(final_index))
            << ",\"scale\":" << state.values.at(final_index).scale << '}';
    else for (std::size_t i = 0; i < state.outputs.size(); ++i) {
        if (i) out << ',';
        const auto index = state.outputs[i].second;
        out << "{\"id\":" << json_string(state.outputs[i].first)
            << ",\"value\":" << json_string(state.values.at(index).id)
            << ",\"physical_output\":" << json_string(physical_ids.at(index))
            << ",\"scale\":" << state.values.at(index).scale << '}';
    }
    out << "]}\n";
    graph += out.str();
}
} // namespace

CompiledApplication ApplicationBuilder::compile(const std::string& stem, CompileOptions options) const
{
    // A frozen graph copy prevents later builder changes from changing this
    // program. Native inputs and keys were already captured on import/use.
    const State snapshot = *state_;
    std::size_t operations = 0;
    for (const auto& value : snapshot.values)
        if (value.kind != Kind::input && value.kind != Kind::scale_view) ++operations;
    if (!operations) throw std::invalid_argument("frontend application has no computation");
    const auto final_index = output_indices(snapshot).back();
    if (snapshot.values.at(physical_origin(snapshot, final_index)).kind == Kind::input)
        throw std::invalid_argument("frontend final output must originate from a computation");
    auto data = std::make_shared<detail::CompiledFrontend>();
    data->owner = state_;
    data->oracles = execute_oracle(snapshot);
    std::vector<std::string> physical_ids(snapshot.values.size());
    switch (scheme(snapshot)) {
    case ::seal::scheme_type::ckks: compile_ckks(snapshot, stem, options.capacity_lines, *data, physical_ids); break;
    case ::seal::scheme_type::bfv: compile_bfv(snapshot, stem, options.capacity_lines, *data, physical_ids); break;
    case ::seal::scheme_type::bgv: compile_bgv(snapshot, stem, options.capacity_lines, *data, physical_ids); break;
    default: throw std::logic_error("frontend scheme is invalid");
    }
    add_frontend_graph(snapshot, physical_ids, *data);
    data->resource_report = detail::finalize_frontend_package(data->request, data->image,
        options.optimize_resources, options.require_instruction_verification,
        options.instruction_ntt_contract, options.profile_execution);
    data->verified = true;
    return CompiledApplication(std::move(data));
}

CompiledApplication::CompiledApplication(std::shared_ptr<const detail::CompiledFrontend> data)
    : data_(std::move(data)) {}
const hpu::delivery::ApplicationPackageRequest& CompiledApplication::package() const { return data_->request; }
hpu::delivery::ApplicationPackageReport CompiledApplication::write(const std::filesystem::path& directory) const
{ return hpu::delivery::write_application_package(directory, data_->request); }
const ::seal::Ciphertext& CompiledApplication::oracle_result(const Ciphertext& value) const
{
    if (value.owner_ != data_->owner || value.index_ >= data_->oracles.size())
        throw std::invalid_argument("frontend value does not belong to this compiled snapshot");
    return data_->oracles.at(value.index_);
}
std::size_t CompiledApplication::node_count() const noexcept { return data_->node_count; }
bool CompiledApplication::verified() const noexcept { return data_->verified; }
bool CompiledApplication::instruction_verified() const noexcept
{
    return data_->request.oracle_report_json.find("\"host_instruction_model_verified\":true") != std::string::npos;
}
const std::string& CompiledApplication::resource_report_json() const { return data_->resource_report; }

} // namespace hpu::seal_adapter
