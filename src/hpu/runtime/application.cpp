#include "hpu/runtime/application.hpp"

#include <stdexcept>
#include <utility>

namespace hpu::runtime {
namespace {

void validate_span(const HpuMemSpan& span, const char* role)
{
    if (span.line_count == 0 || span.line_offset + span.line_count < span.line_offset) {
        throw std::invalid_argument(std::string(role) + " has an invalid HPU_MEM span");
    }
}

} // namespace

void Application::register_object(std::string id, ObjectState state)
{
    require_open();
    if (id.empty()) {
        throw std::invalid_argument("HPU object id cannot be empty");
    }
    validate_span(state.backing, "object");
    if (state.resident_slot) {
        throw std::invalid_argument("objects must be registered before they become resident");
    }
    if (!objects_.emplace(std::move(id), std::move(state)).second) {
        throw std::invalid_argument("duplicate HPU object id");
    }
}

void Application::load_modulus_table(HpuMemSpan table)
{
    require_open();
    validate_span(table, "modulus table");
    if (modulus_table_) {
        throw std::logic_error("modulus table may only be dload'd once per application");
    }
    modulus_table_ = table;
    events_.push_back({EventKind::load_modulus_table, "modulus_table"});
}

void Application::load_object(const std::string& id, std::uint8_t slot)
{
    require_open();
    if (!modulus_table_) {
        throw std::logic_error("load the complete modulus table before polynomial objects");
    }
    if (slot >= kRegularBankCount) {
        throw std::out_of_range("regular-bank slot must be in [0, 4]");
    }
    for (const auto& entry : objects_) {
        if (entry.second.resident_slot == slot) {
            throw std::logic_error("regular-bank slot is already occupied");
        }
    }
    ObjectState& state = mutable_object(id);
    if (state.resident_slot) {
        throw std::logic_error("object is already resident");
    }
    state.resident_slot = slot;
    state.dirty = false;
    events_.push_back({EventKind::load_object, id});
}

void Application::run_kernel(
    std::string kernel,
    const std::vector<std::string>& written_objects)
{
    require_open();
    if (kernel.empty()) {
        throw std::invalid_argument("kernel name cannot be empty");
    }
    for (const std::string& id : written_objects) {
        ObjectState& state = mutable_object(id);
        if (!state.resident_slot) {
            throw std::logic_error("kernel output must remain resident in a regular bank");
        }
        state.dirty = true;
        state.stored_after_write = false;
    }
    events_.push_back({EventKind::kernel, std::move(kernel)});
}

void Application::set_representation(
    const std::string& id,
    PolynomialDomain domain,
    std::size_t level,
    std::vector<std::uint8_t> modulus_ids,
    std::uint64_t key_domain)
{
    require_open();
    ObjectState& state = mutable_object(id);
    if (!state.resident_slot) {
        throw std::logic_error("only a resident object can change representation");
    }
    if (modulus_ids.empty()) {
        throw std::invalid_argument("an active polynomial needs at least one modulus");
    }
    state.domain = domain;
    state.level = level;
    state.modulus_ids = std::move(modulus_ids);
    state.key_domain = key_domain;
    state.dirty = true;
    state.stored_after_write = false;
}

void Application::store_object(const std::string& id)
{
    require_open();
    ObjectState& state = mutable_object(id);
    if (!state.resident_slot) {
        throw std::logic_error("cannot dstore a non-resident object");
    }
    state.dirty = false;
    state.stored_after_write = true;
    events_.push_back({EventKind::store_object, id});
}

void Application::release_object(const std::string& id)
{
    require_open();
    ObjectState& state = mutable_object(id);
    if (!state.resident_slot) {
        throw std::logic_error("object is not resident");
    }
    if (state.dirty) {
        throw std::logic_error("dirty object must be dstore'd before release");
    }
    state.resident_slot.reset();
    events_.push_back({EventKind::release_object, id});
}

void Application::finish()
{
    require_open();
    for (const auto& entry : objects_) {
        const ObjectState& state = entry.second;
        if (state.required_output && (state.dirty || !state.stored_after_write)) {
            throw std::logic_error(
                "required output '" + entry.first + "' must be dstore'd before psync");
        }
    }
    events_.push_back({EventKind::psync, {}});
    finished_ = true;
}

const ObjectState& Application::object(const std::string& id) const
{
    const auto found = objects_.find(id);
    if (found == objects_.end()) {
        throw std::out_of_range("unknown HPU object: " + id);
    }
    return found->second;
}

const std::vector<Event>& Application::events() const noexcept { return events_; }
bool Application::finished() const noexcept { return finished_; }

ObjectState& Application::mutable_object(const std::string& id)
{
    const auto found = objects_.find(id);
    if (found == objects_.end()) {
        throw std::out_of_range("unknown HPU object: " + id);
    }
    return found->second;
}

void Application::require_open() const
{
    if (finished_) {
        throw std::logic_error("HPU application has already emitted its final psync");
    }
}

} // namespace hpu::runtime
