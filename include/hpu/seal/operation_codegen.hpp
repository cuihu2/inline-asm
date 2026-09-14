#pragma once

#include "hpu/seal/operation_plan.hpp"

#include <seal/seal.h>

#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct CkksLoweredOperation {
    CkksOperationStep operation;
    std::string body_asm;
};

struct CkksLoweredProgram {
    std::string body_asm;
    std::vector<CkksLoweredOperation> operations;
};

// Selects an existing CKKS kernel body for every explicit plan step. Object
// and resource IDs remain in the per-operation manifest for a later relocation
// backend; the assembly body retains the current generic DMA operand ABI.
CkksLoweredProgram lower_ckks_operation_plan(
    const CkksOperationPlan& plan,
    const ::seal::SEALContext& context,
    bool append_psync = true,
    bool manage_modulus_table = true);

} // namespace hpu::seal_adapter
