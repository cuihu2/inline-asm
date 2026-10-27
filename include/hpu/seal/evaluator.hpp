#pragma once

#include "hpu/delivery/application_package.hpp"
#include "hpu/model/instruction_executor.hpp"

#include <seal/seal.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

namespace hpu::seal_adapter {
namespace detail {
struct FrontendState;
struct CompiledFrontend;
// Shared compiler/delivery adapter. Executes after functional verification.
std::string finalize_frontend_package(
    hpu::delivery::ApplicationPackageRequest& request,
    hpu::runtime::HpuMemImage& image, bool optimize_resources,
    bool require_instruction_verification,
    hpu::model::InstructionNttContract instruction_ntt_contract =
        hpu::model::InstructionNttContract::raw_bit_reversed_coefficients,
    bool profile_execution = false);
}

class ApplicationBuilder;
class Evaluator;
class CompiledApplication;

// Handles identify immutable logical values. Copying a handle preserves the
// value; an inplace operation only rebinds its destination handle.
class Ciphertext {
public:
    Ciphertext() = default;
    bool valid() const noexcept;
    const std::string& value_id() const;
    ::seal::parms_id_type parms_id() const;
    std::size_t size() const;
    double scale() const;
    std::uint64_t correction_factor() const;
private:
    friend class ApplicationBuilder;
    friend class Evaluator;
    friend class CompiledApplication;
    Ciphertext(std::shared_ptr<detail::FrontendState> owner, std::size_t index);
    std::shared_ptr<detail::FrontendState> owner_;
    std::size_t index_ = 0;
};

class Plaintext {
public:
    Plaintext() = default;
    bool valid() const noexcept;
    const std::string& value_id() const;
    ::seal::parms_id_type parms_id() const;
    double scale() const;
private:
    friend class ApplicationBuilder;
    friend class Evaluator;
    Plaintext(std::shared_ptr<detail::FrontendState> owner, std::size_t index);
    std::shared_ptr<detail::FrontendState> owner_;
    std::size_t index_ = 0;
};

struct CompileOptions {
    // Construction limit. The emitted image is trimmed to actual usage.
    std::uint64_t capacity_lines = 1ULL << 24;
    bool optimize_resources = true;
    // Strict compilation requires final instruction-model words to match.
    // False allows explicit diagnostic export while retaining the failure.
    bool require_instruction_verification = true;
    // Selects a documented host model contract, not a hardware ABI change.
    hpu::model::InstructionNttContract instruction_ntt_contract =
        hpu::model::InstructionNttContract::raw_bit_reversed_coefficients;
    // One continuous interval: opportunistic entry preload, normal execution
    // including required DMA, and exclusion of existing trailing writebacks.
    bool profile_execution = false;
};

class CompiledApplication {
public:
    const hpu::delivery::ApplicationPackageRequest& package() const;
    hpu::delivery::ApplicationPackageReport write(const std::filesystem::path& directory) const;
    const ::seal::Ciphertext& oracle_result(const Ciphertext& value) const;
    std::size_t node_count() const noexcept;
    // SEAL metadata and every functional SoftwareExecutor output word passed.
    // Encoded instruction diagnostics have a separate status below.
    bool verified() const noexcept;
    bool instruction_verified() const noexcept;
    const std::string& resource_report_json() const;
private:
    friend class ApplicationBuilder;
    explicit CompiledApplication(std::shared_ptr<const detail::CompiledFrontend> data);
    std::shared_ptr<const detail::CompiledFrontend> data_;
};

class ApplicationBuilder {
public:
    explicit ApplicationBuilder(const ::seal::SEALContext& context);
    ApplicationBuilder(const ApplicationBuilder&) = delete;
    ApplicationBuilder& operator=(const ApplicationBuilder&) = delete;
    ApplicationBuilder(ApplicationBuilder&&) noexcept = default;
    ApplicationBuilder& operator=(ApplicationBuilder&&) noexcept = default;

    Ciphertext import_ciphertext(std::string id, const ::seal::Ciphertext& input);
    Plaintext import_plaintext(std::string id, const ::seal::Plaintext& input);
    Evaluator evaluator();
    void mark_output(std::string id, const Ciphertext& value);
    CompiledApplication compile(const std::string& stem, CompileOptions options = {}) const;
    const ::seal::SEALContext& context() const;
private:
    friend class Evaluator;
    std::shared_ptr<detail::FrontendState> state_;
};

// Methods record a graph; native SEAL Evaluator execution happens only inside
// compile() as the independent oracle. No implicit rescale/relinearize occurs.
class Evaluator {
public:
    explicit Evaluator(ApplicationBuilder& application);
    void add(const Ciphertext&, const Ciphertext&, Ciphertext& destination);
    void sub(const Ciphertext&, const Ciphertext&, Ciphertext& destination);
    void multiply(const Ciphertext&, const Ciphertext&, Ciphertext& destination);
    void square(const Ciphertext&, Ciphertext& destination);
    void negate(const Ciphertext&, Ciphertext& destination);
    void add_plain(const Ciphertext&, const Plaintext&, Ciphertext& destination);
    void sub_plain(const Ciphertext&, const Plaintext&, Ciphertext& destination);
    void multiply_plain(const Ciphertext&, const Plaintext&, Ciphertext& destination);
    void relinearize(const Ciphertext&, const ::seal::RelinKeys&, Ciphertext& destination);
    void rescale_to_next(const Ciphertext&, Ciphertext& destination);
    void mod_switch_to_next(const Ciphertext&, Ciphertext& destination);
    void rotate_vector(const Ciphertext&, int steps, const ::seal::GaloisKeys&, Ciphertext& destination);
    void complex_conjugate(const Ciphertext&, const ::seal::GaloisKeys&, Ciphertext& destination);
    void rotate_rows(const Ciphertext&, int steps, const ::seal::GaloisKeys&, Ciphertext& destination);
    void rotate_columns(const Ciphertext&, const ::seal::GaloisKeys&, Ciphertext& destination);
    void set_scale(Ciphertext& value, double scale);

    void add_inplace(Ciphertext& a, const Ciphertext& b) { add(a, b, a); }
    void sub_inplace(Ciphertext& a, const Ciphertext& b) { sub(a, b, a); }
    void multiply_inplace(Ciphertext& a, const Ciphertext& b) { multiply(a, b, a); }
    void square_inplace(Ciphertext& a) { square(a, a); }
    void negate_inplace(Ciphertext& a) { negate(a, a); }
    void add_plain_inplace(Ciphertext& a, const Plaintext& b) { add_plain(a, b, a); }
    void sub_plain_inplace(Ciphertext& a, const Plaintext& b) { sub_plain(a, b, a); }
    void multiply_plain_inplace(Ciphertext& a, const Plaintext& b) { multiply_plain(a, b, a); }
    void relinearize_inplace(Ciphertext& a, const ::seal::RelinKeys& k) { relinearize(a, k, a); }
    void rescale_to_next_inplace(Ciphertext& a) { rescale_to_next(a, a); }
    void mod_switch_to_next_inplace(Ciphertext& a) { mod_switch_to_next(a, a); }
    void rotate_vector_inplace(Ciphertext& a, int s, const ::seal::GaloisKeys& k) { rotate_vector(a, s, k, a); }
    void complex_conjugate_inplace(Ciphertext& a, const ::seal::GaloisKeys& k) { complex_conjugate(a, k, a); }
    void rotate_rows_inplace(Ciphertext& a, int s, const ::seal::GaloisKeys& k) { rotate_rows(a, s, k, a); }
    void rotate_columns_inplace(Ciphertext& a, const ::seal::GaloisKeys& k) { rotate_columns(a, k, a); }
private:
    void binary(int kind, const Ciphertext&, const Ciphertext&, Ciphertext&);
    void unary(int kind, const Ciphertext&, Ciphertext&);
    void plain(int kind, const Ciphertext&, const Plaintext&, Ciphertext&);
    void rotation(int kind, const Ciphertext&, int steps, const ::seal::GaloisKeys&, Ciphertext&);
    std::size_t require(const Ciphertext&) const;
    std::size_t require(const Plaintext&) const;
    std::shared_ptr<detail::FrontendState> state_;
};

} // namespace hpu::seal_adapter
