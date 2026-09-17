#pragma once

#include "hpu/seal/bfv_operation_plan.hpp"

#include <seal/seal.h>

#include <string>
#include <vector>

namespace hpu::seal_adapter {

struct BfvLoweredOperation {
    BfvOperationStep operation;
    std::string body_asm;
};

struct BfvLoweredProgram {
    std::string body_asm;
    std::vector<BfvLoweredOperation> operations;
};

BfvLoweredProgram lower_bfv_operation_plan(const BfvOperationPlan& plan,
                                           const ::seal::SEALContext& context,
                                           bool append_psync = true,
                                           bool manage_modulus_table = true);

} // namespace hpu::seal_adapter
