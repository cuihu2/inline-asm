#pragma once

#include <cstdint>
#include <string>

namespace hpu {

enum class Format {
    kAR3,
    kSTG,
    kMOD,
    kCFG,
    kSYNC,
    kDMA,
};

enum class Mnemonic {
    kPadd,
    kPsub,
    kPmul,
    kPmac,
    kPntt,
    kPintt,
    kPmodld,
    kPfree,
    kPsync,
    kDload,
    kDstore,
};

struct Instruction {
    Mnemonic mnemonic {};

    // 汇编操作数字段，而非所有格式中固定不变的物理位段。
    // STG: pdst=pdata，编码到 [27:25] 和 [24:22]；psrc1=ptwiddle，
    // 编码到 [16:14]。[21:17] 保留为 0；AR3 的字段含义不变。
    int pdst = -1;
    int psrc1 = -1;
    int psrc2 = -1;
    int imm8 = -1;

    int idx0 = -1;
    int idx1 = -1;
    int mod_id = -1;
    std::uint8_t mode = 0;
    std::uint8_t flag = 0;
    std::uint16_t cfg = 0;
    std::uint8_t tag = 0;

    int rs1 = -1;
    int rs2 = -1;
    std::uint8_t obj_id = 0;
    std::uint8_t type = 0;
    std::uint8_t dma_flag = 0;
};

struct EncodedInstruction {
    Instruction instruction;
    std::uint32_t word = 0;
    std::uint32_t command26 = 0;
    std::string normalized_asm;
};

std::string to_string(Mnemonic mnemonic);
std::string to_string(const Instruction& instruction);
Format instruction_format(Mnemonic mnemonic);

}  // namespace hpu
