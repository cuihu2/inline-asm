#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace hpu::runtime {

constexpr std::size_t kRegularBankCount = 5;

struct HpuMemSpan {
    std::uint64_t line_offset = 0;
    std::uint64_t line_count = 0;
};

enum class PolynomialDomain {
    coefficient,
    canonical_ntt_physical
};

struct ObjectState {
    HpuMemSpan backing;
    std::optional<std::uint8_t> resident_slot;
    std::size_t level = 0;
    std::vector<std::uint8_t> modulus_ids;
    PolynomialDomain domain = PolynomialDomain::coefficient;

    // 1 means the canonical secret-key domain s(X). A Rotate transform changes
    // this to k until the corresponding Galois KeySwitch completes.
    std::uint64_t key_domain = 1;
    bool dirty = false;
    bool required_output = false;
    bool stored_after_write = false;
};

enum class EventKind {
    load_modulus_table,
    load_object,
    kernel,
    store_object,
    release_object,
    psync
};

struct Event {
    EventKind kind;
    std::string object_or_kernel;
};

// Platform-independent application-lifetime state machine. It deliberately has
// no Linux driver/userspace dependency: a future backend translates the event
// stream into MMIO/ioctl/custom-instruction operations.
class Application {
public:
    void register_object(std::string id, ObjectState state);
    void load_modulus_table(HpuMemSpan table);
    void load_object(const std::string& id, std::uint8_t slot);
    void run_kernel(
        std::string kernel,
        const std::vector<std::string>& written_objects);
    void set_representation(
        const std::string& id,
        PolynomialDomain domain,
        std::size_t level,
        std::vector<std::uint8_t> modulus_ids,
        std::uint64_t key_domain = 1);
    void store_object(const std::string& id);
    void release_object(const std::string& id);

    // finish() is the only operation that emits psync. It first requires every
    // required output to have been dstore'd to its HPU_MEM backing span.
    void finish();

    const ObjectState& object(const std::string& id) const;
    const std::vector<Event>& events() const noexcept;
    bool finished() const noexcept;

private:
    ObjectState& mutable_object(const std::string& id);
    void require_open() const;

    std::unordered_map<std::string, ObjectState> objects_;
    std::vector<Event> events_;
    std::optional<HpuMemSpan> modulus_table_;
    bool finished_ = false;
};

} // namespace hpu::runtime
