#pragma once

#include <string>
#include <sstream>

namespace hpu {

// Frozen CPU/HPU custom1 ABI.  The executable runtime binds a different
// line_offset/line_count pair before each DMA word, but every encoded DMA
// instruction names the same two architectural registers.
inline constexpr const char* kDmaOffsetRegister = "x10";
inline constexpr const char* kDmaCountRegister = "x11";

inline constexpr int kRegularBankCount = 5;
inline constexpr int kRegularBankLines = 1024;
inline constexpr int kHpuWordsPerLine = 64;
inline constexpr int kNttRegisterCount = 128;
inline constexpr int kSmallBankId = 5;
inline constexpr int kSmallBankLines = 32;
inline constexpr int kModTableBaseLine = 0x1400;
inline constexpr int kModContextsPerLine = 16;
inline constexpr int kPhysicalModContexts = kSmallBankLines * kModContextsPerLine;
inline constexpr int kModIdBits = 8;
inline constexpr int kMaxModContexts =
    kPhysicalModContexts < (1 << kModIdBits)
        ? kPhysicalModContexts
        : (1 << kModIdBits);

inline constexpr int hpu_lines_for_words(int words) {
    return words > 0
        ? words / kHpuWordsPerLine + (words % kHpuWordsPerLine != 0 ? 1 : 0)
        : 0;
}

inline constexpr bool fits_regular_object(int words) {
    return words > 0 && hpu_lines_for_words(words) <= kRegularBankLines;
}

inline constexpr bool fits_ntt_object(int words) {
    return words >= kNttRegisterCount && fits_regular_object(words);
}

static_assert(fits_regular_object(65536));
static_assert(!fits_regular_object(65537));
static_assert(fits_ntt_object(128));
static_assert(!fits_ntt_object(64));

inline std::string pobj(int id) {
    return "p" + std::to_string(id);
}

// ==========================================
// 外部访存类指令 (custom1)
// ==========================================

enum class DataType {
    seg = 0,
    poly = 1,
    mod_ctx = 2
};

enum class DloadFlag {
    regular_bank = 0,
    small_bank = 1
};

inline std::string dload(
    const std::string& rs1,
    const std::string& rs2,
    int pdst,
    DataType load_type,
    DloadFlag flag = DloadFlag::regular_bank) {
    std::ostringstream ss;
    ss << "        \"dload " << rs1 << ", " << rs2 << ", " << pobj(pdst) << ", "
       << static_cast<int>(load_type) << ", " << static_cast<int>(flag) << " \\n\\t\"\n";
    return ss.str();
}

inline std::string dstore(const std::string& rs1, const std::string& rs2, int psrc, int rel) {
    std::ostringstream ss;
    ss << "        \"dstore " << rs1 << ", " << rs2 << ", " << pobj(psrc) << ", " << rel << " \\n\\t\"\n";
    return ss.str();
}

inline std::string dload(
    int pdst,
    DataType load_type,
    DloadFlag flag = DloadFlag::regular_bank) {
    return dload(kDmaOffsetRegister, kDmaCountRegister, pdst, load_type, flag);
}

inline std::string dstore(int psrc, int rel) {
    return dstore(kDmaOffsetRegister, kDmaCountRegister, psrc, rel);
}

// ==========================================
// 内部执行类指令 (custom0)
// ==========================================

// --- AR3 格式：三对象基础算术类 ---
// 汇编显式给出 pdst、psrc1 和 OP2；pmul/pmac 的整数 OP2 会设置 MODE[0]
inline std::string padd(int pdst, int psrc1, int psrc2) {
    std::ostringstream ss;
    ss << "        \"padd " << pobj(pdst) << ", " << pobj(psrc1) << ", " << pobj(psrc2) << " \\n\\t\"\n";
    return ss.str();
}

inline std::string psub(int pdst, int psrc1, int psrc2) {
    std::ostringstream ss;
    ss << "        \"psub " << pobj(pdst) << ", " << pobj(psrc1) << ", " << pobj(psrc2) << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pmul(int pdst, int psrc1, int psrc2) {
    std::ostringstream ss;
    ss << "        \"pmul " << pobj(pdst) << ", " << pobj(psrc1) << ", " << pobj(psrc2) << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pmul_imm(int pdst, int psrc1, int cimm8) {
    std::ostringstream ss;
    ss << "        \"pmul " << pobj(pdst) << ", " << pobj(psrc1) << ", " << cimm8 << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pmac(int pdst, int psrc1, int psrc2) {
    std::ostringstream ss;
    ss << "        \"pmac " << pobj(pdst) << ", " << pobj(psrc1) << ", " << pobj(psrc2) << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pmac_imm(int pdst, int psrc1, int cimm8) {
    std::ostringstream ss;
    ss << "        \"pmac " << pobj(pdst) << ", " << pobj(psrc1) << ", " << cimm8 << " \\n\\t\"\n";
    return ss.str();
}

// --- STG 格式：stage / transform 执行类 ---
// 语义：第一个对象为逻辑数据对象，第二个对象为 twiddle 对象。
// 控制器在保持逻辑对象号不变的情况下执行 out-of-place 并提交新的物理 base。
inline std::string pntt(int pdata, int ptwiddle, int stage, int mode = 0, int flag = 0) {
    std::ostringstream ss;
    ss << "        \"pntt " << pobj(pdata) << ", " << pobj(ptwiddle) << ", " << stage
       << ", " << mode << ", " << flag << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pintt(int pdata, int ptwiddle, int stage, int mode = 0, int flag = 0) {
    std::ostringstream ss;
    ss << "        \"pintt " << pobj(pdata) << ", " << pobj(ptwiddle) << ", " << stage
       << ", " << mode << ", " << flag << " \\n\\t\"\n";
    return ss.str();
}

// --- MOD/CFG 格式：模上下文选择与对象控制 ---
inline std::string pmodld(int mod_id) {
    std::ostringstream ss;
    ss << "        \"pmodld " << mod_id << " \\n\\t\"\n";
    return ss.str();
}

inline std::string pfree(int idx0) {
    std::ostringstream ss;
    ss << "        \"pfree " << pobj(idx0) << " \\n\\t\"\n";
    return ss.str();
}

// --- SYNC 格式：完整程序结束后通知 CPU；不用于 DMA 一致性 ---
inline std::string psync() {
    return "        \"psync \\n\\t\"\n";
}

} // namespace hpu
