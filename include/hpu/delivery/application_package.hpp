#pragma once

#include "hpu/runtime/application.hpp"
#include "hpu/runtime/memory_image.hpp"
#include "instruction.hpp"
#include "executable.hpp"
#include "hpu/compiler/operator_resources.hpp"
#include <memory>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace hpu::delivery {

// The application-package writer is POSIX-only in v1 because publication uses
// mkdtemp(3), chmod(2), and same-filesystem rename(2) semantics.
constexpr std::uint32_t kApplicationPackageSchemaVersion = 1;

enum class SchemeKind { ckks, bfv, bgv };

enum class OutputDomain {
    coefficient,
    // Physical coefficient buffers use physical[j] = natural[BR_logN(j)].
    coefficient_bit_reversed,
    canonical_ntt_physical
};

struct ProducerIdentity {
    std::string repository;
    std::string commit;
    std::string worktree_state;
};

struct ProgramArtifacts {
    std::string stem;
    std::string assembly;
    std::vector<hpu::EncodedInstruction> instructions;
    std::string header;
    std::string source;
    std::string resolved_dma_manifest;
    std::vector<hpu::runtime::HpuMemSpan> ordered_dma_spans;
    // In-memory compilation inputs; neither is serialized into package v1.
    std::shared_ptr<const hpu::resource::OperatorProgram> operator_program;
    std::vector<hpu::compiler::ResolvedDma> resource_dma;
    // The common exporter must not schedule an already compiled stream again.
    bool resources_compiled = false;
    // Serialized in memory/abi.json and checked against final DMA bindings.
    hpu::compiler::DmaCachePolicy dma_cache_policy =
        hpu::compiler::DmaCachePolicy::preserve;
    bool profile_execution = false;
    std::optional<hpu::ExecutionProfileWindow> execution_profile;
};

struct VerifiedOutputLimb {
    std::string object_id;
    std::size_t component = 0;
    std::uint8_t modulus_id = 0;
    std::uint32_t modulus = 0;
    OutputDomain domain = OutputDomain::canonical_ntt_physical;
    hpu::runtime::HpuMemSpan destination;
    std::size_t word_count = 0;
    std::vector<std::uint32_t> golden_words;
};

struct SemanticReport {
    std::string media_type;
    std::string contents;
};

struct ApplicationPackageRequest {
    SchemeKind scheme = SchemeKind::ckks;
    std::string case_name;
    ProducerIdentity producer;
    const hpu::runtime::HpuMemImage* initial_image = nullptr;
    ProgramArtifacts program;
    std::vector<VerifiedOutputLimb> outputs;
    std::string parameters_json;
    std::string operation_graph_json;
    std::string oracle_report_json;
    std::optional<SemanticReport> semantic_report;
};

struct ApplicationPackageReport {
    std::filesystem::path root;
    std::vector<std::string> files;
    std::uint64_t image_fnv1a64 = 0;
};

void validate_application_package_request(
    const ApplicationPackageRequest& request);

ApplicationPackageReport write_application_package(
    const std::filesystem::path& output_root,
    const ApplicationPackageRequest& request);

void validate_application_package_on_disk(
    const std::filesystem::path& package_root);

} // namespace hpu::delivery
