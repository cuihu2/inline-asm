#include "util/ntt.hpp"
#include "util/hpu_asm.hpp"

#include <cmath>
#include <sstream>
#include <string>

namespace {

bool is_power_of_two(int x)
{
    return x > 0 && (x & (x - 1)) == 0;
}

} // namespace

std::string generate_hpu_ntt_body_asm(
    int N,
    int obj_poly,
    int twiddle_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!is_power_of_two(N) || !hpu::fits_ntt_object(N)) {
        asm_code << "        // Invalid config: require power-of-two 128 <= N <= 65536\n";
        return asm_code.str();
    }

    const int logN = static_cast<int>(std::log2(static_cast<double>(N)));

    int data_obj = obj_poly;

    asm_code << "        // modulus table is loaded by the enclosing complete program\n";
    // 假设调用方已经加载过密文模数
    // Negacyclic NTT = pointwise pre-twist followed by a cyclic NTT.
    asm_code << "\n        // Negacyclic pre-twist: explicit PMUL by psi^i\n";
    asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
    asm_code << hpu::pmul(data_obj, data_obj, twiddle_obj);
    asm_code << hpu::pfree(twiddle_obj);

    // obj_poly 是稳定的逻辑对象；控制器为每个 stage 执行物理 out-of-place，
    // 完成后提交新 base。stage 配对由 stream_ctrl 地址与 lane 调度完成。
    for (int stage = 0; stage < logN; ++stage) {
        asm_code << "\n        // ==========================================\n";
        asm_code << "        // Stage " << stage << " (Stage-level pntt)\n";
        asm_code << "        // ==========================================\n";
        asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
        asm_code << hpu::pntt(data_obj, twiddle_obj, stage, 0);
        asm_code << hpu::pfree(twiddle_obj);
    }

    if (append_psync) {
        asm_code << hpu::psync();
    }

    asm_code << "\n        // Final result object slot: " << hpu::pobj(data_obj) << "\n";
    return asm_code.str();
}

std::string generate_hpu_intt_body_asm(
    int N,
    int obj_poly,
    int twiddle_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    if (!is_power_of_two(N) || !hpu::fits_ntt_object(N)) {
        asm_code << "        // Invalid config: require power-of-two 128 <= N <= 65536\n";
        return asm_code.str();
    }

    const int logN = static_cast<int>(std::log2(static_cast<double>(N)));

    int data_obj = obj_poly;

    asm_code << "        // modulus table is loaded by the enclosing complete program\n";
    // 假设调用方已经加载过密文模数

    // obj_poly 是稳定的逻辑对象；控制器为每个 stage 执行物理 out-of-place，
    // 完成后提交新 base。stage 配对由 stream_ctrl 地址与 lane 调度完成。
    for (int stage = 0; stage < logN; ++stage) {
        asm_code << "\n        // ==========================================\n";
        asm_code << "        // Stage " << stage << " (Stage-level pintt)\n";
        asm_code << "        // ==========================================\n";
        asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
        asm_code << hpu::pintt(data_obj, twiddle_obj, stage, 0);
        asm_code << hpu::pfree(twiddle_obj);
    }

    // The PE butterfly does not implicitly normalize or apply the inverse twist.
    asm_code << "\n        // INTT normalize and inverse-twist: explicit PMUL by N^-1 * psi^-i\n";
    asm_code << hpu::dload(twiddle_obj, hpu::DataType::poly);
    asm_code << hpu::pmul(data_obj, data_obj, twiddle_obj);
    asm_code << hpu::pfree(twiddle_obj);

    if (append_psync) {
        asm_code << hpu::psync();
    }

    asm_code << "\n        // Final result object slot: " << hpu::pobj(data_obj) << "\n";
    return asm_code.str();
}

std::string generate_hpu_ntt_asm(
    int N,
    int obj_poly,
    int twiddle_obj,
    int mod_ctx_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    asm_code << "void hpu_ntt_N" << N << "(void) {\n";

    if (!is_power_of_two(N) || !hpu::fits_ntt_object(N)) {
        asm_code << "    // Invalid config: require power-of-two 128 <= N <= 65536\n";
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
    int twiddle_obj,
    int mod_ctx_obj,
    bool append_psync)
{
    std::ostringstream asm_code;

    asm_code << "void hpu_intt_N" << N << "(void) {\n";

    if (!is_power_of_two(N) || !hpu::fits_ntt_object(N)) {
        asm_code << "    // Invalid config: require power-of-two 128 <= N <= 65536\n";
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
