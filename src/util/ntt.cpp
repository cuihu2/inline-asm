#include "util/ntt.hpp"
#include "util/hpu_asm.hpp"
#include "util/validation.hpp"

#include <cmath>
#include <sstream>
#include <string>

namespace {

bool valid_object(int object)
{
    return object >= 0 && object <= 7;
}

bool valid_transform_objects(int data_obj, int scratch_obj, int twiddle_obj)
{
    return valid_object(data_obj) && valid_object(scratch_obj)
        && valid_object(twiddle_obj) && data_obj != scratch_obj
        && data_obj != twiddle_obj && scratch_obj != twiddle_obj;
}

bool valid_complete_transform_objects(
    int data_obj, int scratch_obj, int twiddle_obj, int mod_ctx_obj)
{
    return valid_transform_objects(data_obj, scratch_obj, twiddle_obj)
        && valid_object(mod_ctx_obj) && mod_ctx_obj != data_obj
        && mod_ctx_obj != scratch_obj && mod_ctx_obj != twiddle_obj;
}

} // namespace

std::string generate_hpu_ntt_body_asm(
    int N,
    int obj_poly,
    int scratch_obj,
    int twiddle_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!hpu::is_valid_ntt_size(N)) {
        asm_code << "        // Invalid config: require power-of-two 128 <= N <= 65536\n";
        return asm_code.str();
    }
    if (!valid_transform_objects(obj_poly, scratch_obj, twiddle_obj)) {
        asm_code << "        // Invalid config: data, scratch, and twiddle must be distinct p0..p7 objects\n";
        return asm_code.str();
    }

    const int logN = static_cast<int>(std::log2(static_cast<double>(N)));

    int source_obj = obj_poly;

    asm_code << "        // modulus table is loaded by the enclosing complete program\n";
    // 假设调用方已经加载过密文模数
    // Negacyclic NTT = pointwise pre-twist followed by a cyclic NTT.
    asm_code << "\n        // Negacyclic pre-twist: explicit PMUL by psi^bit_reverse(position)\n";
    asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
    if (logN % 2 == 0) {
        asm_code << hpu::pmul(obj_poly, obj_poly, twiddle_obj);
    } else {
        asm_code << hpu::pmul(scratch_obj, obj_poly, twiddle_obj);
        asm_code << hpu::pfree(obj_poly);
        source_obj = scratch_obj;
    }
    asm_code << hpu::pfree(twiddle_obj);

    // Every transform stage is explicitly out-of-place. The source is freed
    // after the destination has been produced so the two slots can ping-pong.
    for (int stage = 0; stage < logN; ++stage) {
        const int destination_obj =
            source_obj == obj_poly ? scratch_obj : obj_poly;
        asm_code << "\n        // ==========================================\n";
        asm_code << "        // Stage " << stage << " (Stage-level pntt)\n";
        asm_code << "        // ==========================================\n";
        asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
        asm_code << hpu::pntt(
            destination_obj, source_obj, twiddle_obj, stage, 0);
        asm_code << hpu::pfree(source_obj);
        asm_code << hpu::pfree(twiddle_obj);
        source_obj = destination_obj;
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }

    asm_code << "\n        // Final result object slot: " << hpu::pobj(obj_poly) << "\n";
    return asm_code.str();
}

std::string generate_hpu_intt_body_asm(
    int N,
    int obj_poly,
    int scratch_obj,
    int twiddle_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!hpu::is_valid_ntt_size(N)) {
        asm_code << "        // Invalid config: require power-of-two 128 <= N <= 65536\n";
        return asm_code.str();
    }
    if (!valid_transform_objects(obj_poly, scratch_obj, twiddle_obj)) {
        asm_code << "        // Invalid config: data, scratch, and twiddle must be distinct p0..p7 objects\n";
        return asm_code.str();
    }

    const int logN = static_cast<int>(std::log2(static_cast<double>(N)));

    int source_obj = obj_poly;

    asm_code << "        // modulus table is loaded by the enclosing complete program\n";
    // 假设调用方已经加载过密文模数

    for (int stage = 0; stage < logN; ++stage) {
        const int destination_obj =
            source_obj == obj_poly ? scratch_obj : obj_poly;
        asm_code << "\n        // ==========================================\n";
        asm_code << "        // Stage " << stage << " (Stage-level pintt)\n";
        asm_code << "        // ==========================================\n";
        asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
        asm_code << hpu::pintt(
            destination_obj, source_obj, twiddle_obj, stage, 0);
        asm_code << hpu::pfree(source_obj);
        asm_code << hpu::pfree(twiddle_obj);
        source_obj = destination_obj;
    }

    // The PE butterfly does not implicitly normalize or apply the inverse twist.
    asm_code << "\n        // INTT normalize and inverse-twist: explicit PMUL by N^-1 * psi^-bit_reverse(position)\n";
    asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
    asm_code << hpu::pmul(obj_poly, source_obj, twiddle_obj);
    if (source_obj != obj_poly) {
        asm_code << hpu::pfree(source_obj);
    }
    asm_code << hpu::pfree(twiddle_obj);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    asm_code << "\n        // Final result object slot: " << hpu::pobj(obj_poly) << "\n";
    return asm_code.str();
}

std::string generate_hpu_ntt_asm(
    int N,
    int obj_poly,
    int scratch_obj,
    int twiddle_obj,
    int mod_ctx_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    asm_code << "void hpu_ntt_N" << N << "(void) {\n";

    if (!hpu::is_valid_ntt_size(N)) {
        asm_code << "    // Invalid config: require power-of-two 128 <= N <= 65536\n";
        asm_code << "}\n";
        return asm_code.str();
    }
    if (!valid_complete_transform_objects(
            obj_poly, scratch_obj, twiddle_obj, mod_ctx_obj)) {
        asm_code << "    // Invalid config: data, scratch, twiddle, and mod context must be distinct p0..p7 objects\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << hpu::dload(mod_ctx_obj, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    asm_code << hpu::pmodld(0);
    asm_code << hpu::dload(obj_poly, hpu::DataType::poly);
    asm_code << generate_hpu_ntt_body_asm(
        N,
        obj_poly,
        scratch_obj,
        twiddle_obj,
        false);
    asm_code << hpu::dstore(obj_poly, 1);
    asm_code << hpu::pfree(mod_ctx_obj);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    asm_code << "\n        // 结束\n";
    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";
    
    return asm_code.str();
}

std::string generate_hpu_intt_asm(
    int N,
    int obj_poly,
    int scratch_obj,
    int twiddle_obj,
    int mod_ctx_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    asm_code << "void hpu_intt_N" << N << "(void) {\n";

    if (!hpu::is_valid_ntt_size(N)) {
        asm_code << "    // Invalid config: require power-of-two 128 <= N <= 65536\n";
        asm_code << "}\n";
        return asm_code.str();
    }
    if (!valid_complete_transform_objects(
            obj_poly, scratch_obj, twiddle_obj, mod_ctx_obj)) {
        asm_code << "    // Invalid config: data, scratch, twiddle, and mod context must be distinct p0..p7 objects\n";
        asm_code << "}\n";
        return asm_code.str();
    }

    asm_code << "    __asm__ volatile(\n";
    asm_code << hpu::dload(mod_ctx_obj, hpu::DataType::mod_ctx,
                           hpu::DloadFlag::small_bank);
    asm_code << hpu::pmodld(0);
    asm_code << hpu::dload(obj_poly, hpu::DataType::poly);
    asm_code << generate_hpu_intt_body_asm(
        N,
        obj_poly,
        scratch_obj,
        twiddle_obj,
        false);
    asm_code << hpu::dstore(obj_poly, 1);
    asm_code << hpu::pfree(mod_ctx_obj);
    if (append_psync) {
        asm_code << hpu::psync();
    }
    asm_code << "\n        // 结束\n";
    asm_code << "        : \n";
    asm_code << "        : \n";
    asm_code << "        : \"memory\"\n";
    asm_code << "    );\n";
    asm_code << "}\n";
    
    return asm_code.str();
}
