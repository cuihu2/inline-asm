#include "instruction.hpp"

#include <sstream>
#include <stdexcept>

namespace hpu {
namespace {

std::string format_pobj(int value) {
    return "p" + std::to_string(value);
}

std::string format_xreg(int value) {
    return "x" + std::to_string(value);
}

}  // namespace

std::string to_string(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::kPadd: return "padd";
        case Mnemonic::kPsub: return "psub";
        case Mnemonic::kPmul: return "pmul";
        case Mnemonic::kPmac: return "pmac";
        case Mnemonic::kPntt: return "pntt";
        case Mnemonic::kPintt: return "pintt";
        case Mnemonic::kPmodld: return "pmodld";
        case Mnemonic::kPfree: return "pfree";
        case Mnemonic::kPsync: return "psync";
        case Mnemonic::kDload: return "dload";
        case Mnemonic::kDstore: return "dstore";
    }

    throw std::runtime_error("unknown mnemonic");
}

Format instruction_format(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::kPadd:
        case Mnemonic::kPsub:
        case Mnemonic::kPmul:
        case Mnemonic::kPmac:
            return Format::kAR3;

        case Mnemonic::kPntt:
        case Mnemonic::kPintt:
            return Format::kSTG;

        case Mnemonic::kPmodld:
            return Format::kMOD;

        case Mnemonic::kPfree:
            return Format::kCFG;

        case Mnemonic::kPsync:
            return Format::kSYNC;

        case Mnemonic::kDload:
        case Mnemonic::kDstore:
            return Format::kDMA;
    }

    throw std::runtime_error("unknown format for mnemonic");
}

std::string to_string(const Instruction& instruction) {
    std::ostringstream oss;
    oss << to_string(instruction.mnemonic);

    switch (instruction_format(instruction.mnemonic)) {
        case Format::kAR3:
            oss << ' ' << format_pobj(instruction.pdst)
                << ", " << format_pobj(instruction.psrc1)
                << ", ";
            if (instruction.imm8 >= 0) {
                oss << instruction.imm8;
            } else {
                oss << format_pobj(instruction.psrc2);
            }
            break;

        case Format::kSTG:
            oss << ' ' << format_pobj(instruction.pdst)
                << ", " << format_pobj(instruction.psrc1)
                << ", " << format_pobj(instruction.psrc2)
                << ", " << instruction.idx0
                << ", " << static_cast<int>(instruction.mode)
                << ", " << static_cast<int>(instruction.flag);
            break;

        case Format::kMOD:
            oss << ' ' << instruction.mod_id;
            break;

        case Format::kCFG:
            oss << ' ' << format_pobj(instruction.idx0);
            break;

        case Format::kSYNC:
            break;

        case Format::kDMA:
            oss << ' ' << format_xreg(instruction.rs1)
                << ", " << format_xreg(instruction.rs2)
                << ", " << format_pobj(instruction.obj_id)
                << ", " << static_cast<int>(instruction.type);
            if (instruction.mnemonic == Mnemonic::kDload) {
                oss << ", " << static_cast<int>(instruction.dma_flag);
            }
            break;
    }

    return oss.str();
}

}  // namespace hpu
