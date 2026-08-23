#include "executable.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace hpu {
namespace {

std::string hex_word(std::uint32_t word) {
    std::ostringstream output;
    output << "0x" << std::uppercase << std::hex << std::setw(8)
           << std::setfill('0') << word;
    return output.str();
}

std::string csv_field(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size() + 2);
    escaped.push_back('"');
    for (const char ch : value) {
        if (ch == '"') {
            escaped.push_back('"');
        }
        escaped.push_back(ch);
    }
    escaped.push_back('"');
    return escaped;
}

}  // namespace

std::string c_identifier(std::string value) {
    if (value.empty()) {
        throw std::runtime_error("empty program name");
    }
    for (char& ch : value) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '_') {
            ch = '_';
        }
    }
    if (std::isdigit(static_cast<unsigned char>(value.front()))) {
        value.insert(value.begin(), '_');
    }
    return value;
}

std::vector<DmaRelocation> collect_dma_relocations(
    const std::vector<EncodedInstruction>& encoded) {
    std::vector<DmaRelocation> relocations;
    for (std::size_t instruction_index = 0;
         instruction_index < encoded.size(); ++instruction_index) {
        const auto& instruction = encoded[instruction_index].instruction;
        if (instruction_format(instruction.mnemonic) != Format::kDMA) {
            continue;
        }
        if (instruction.rs1 != 10 || instruction.rs2 != 11) {
            throw std::runtime_error(
                "executable DMA instruction does not use the frozen x10/x11 ABI");
        }
        relocations.push_back(DmaRelocation{
            instruction_index,
            relocations.size(),
            instruction.mnemonic,
            instruction.obj_id,
            instruction.type,
            instruction.dma_flag,
        });
    }
    return relocations;
}

void validate_executable_program(
    const std::vector<EncodedInstruction>& encoded) {
    bool live[8]{};
    int modulus_table_object = -1;
    std::size_t psync_count = 0;
    auto require_live = [&](int object, std::size_t instruction_index,
                            const char* role) {
        if (object < 0 || object > 7 || !live[object]) {
            throw std::runtime_error(
                "object p" + std::to_string(object) + " is not live as " + role
                + " at instruction " + std::to_string(instruction_index));
        }
    };

    for (std::size_t index = 0; index < encoded.size(); ++index) {
        const auto& instruction = encoded[index].instruction;
        switch (instruction.mnemonic) {
        case Mnemonic::kDload:
            if (live[instruction.obj_id]) {
                throw std::runtime_error(
                    "dload overwrites live object p"
                    + std::to_string(instruction.obj_id) + " at instruction "
                    + std::to_string(index));
            }
            live[instruction.obj_id] = true;
            if (instruction.type == 2 && instruction.dma_flag == 1)
                modulus_table_object = instruction.obj_id;
            break;
        case Mnemonic::kDstore:
            require_live(instruction.obj_id, index, "dstore source");
            if (instruction.type == 1) {
                live[instruction.obj_id] = false;
                if (modulus_table_object == instruction.obj_id)
                    modulus_table_object = -1;
            }
            break;
        case Mnemonic::kPadd:
        case Mnemonic::kPsub:
        case Mnemonic::kPmul:
        case Mnemonic::kPmac:
            require_live(instruction.psrc1, index, "arithmetic source 1");
            if (instruction.imm8 < 0)
                require_live(instruction.psrc2, index, "arithmetic source 2");
            if (instruction.mnemonic == Mnemonic::kPmac)
                require_live(instruction.pdst, index, "accumulator destination");
            live[instruction.pdst] = true;
            break;
        case Mnemonic::kPntt:
        case Mnemonic::kPintt:
            require_live(instruction.pdst, index, "transform data");
            require_live(instruction.psrc1, index, "transform twiddle");
            break;
        case Mnemonic::kPmodld:
            if (modulus_table_object < 0) {
                throw std::runtime_error(
                    "pmodld has no live small-bank modulus table at instruction "
                    + std::to_string(index));
            }
            break;
        case Mnemonic::kPfree:
            require_live(instruction.idx0, index, "pfree target");
            live[instruction.idx0] = false;
            if (modulus_table_object == instruction.idx0)
                modulus_table_object = -1;
            break;
        case Mnemonic::kPsync:
            ++psync_count;
            if (index + 1 != encoded.size()) {
                throw std::runtime_error("psync is not the terminal instruction");
            }
            break;
        }
    }
    if (psync_count != 1) {
        throw std::runtime_error("executable program must contain one terminal psync");
    }
    for (int object = 0; object < 8; ++object) {
        if (live[object]) {
            throw std::runtime_error(
                "object p" + std::to_string(object)
                + " remains live after terminal psync");
        }
    }
}

std::string render_executable_header(
    const std::string& stem,
    std::size_t dma_count) {
    const std::string id = c_identifier(stem);
    std::string guard = "HPU_PROGRAM_" + id + "_H";
    for (char& ch : guard) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }

    std::ostringstream output;
    output << "#ifndef " << guard << "\n#define " << guard << "\n\n"
           << "#include <stddef.h>\n#include <stdint.h>\n\n"
           << "#ifndef HPU_DMA_SPAN_T_DEFINED\n"
           << "#define HPU_DMA_SPAN_T_DEFINED\n"
           << "typedef struct hpu_dma_span {\n"
           << "    uint32_t line_offset;\n"
           << "    uint32_t line_count;\n"
           << "} hpu_dma_span_t;\n"
           << "#endif\n\n"
           << "#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n"
           << "enum { HPU_PROGRAM_";
    for (char ch : id) {
        output << static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    output << "_DMA_COUNT = " << dma_count << " };\n"
           << "int hpu_program_" << id
           << "(const hpu_dma_span_t *spans, size_t span_count);\n\n"
           << "#ifdef __cplusplus\n}\n#endif\n\n"
           << "#endif\n";
    return output.str();
}

std::string render_executable_source(
    const std::string& stem,
    const std::vector<EncodedInstruction>& encoded) {
    validate_executable_program(encoded);
    const std::string id = c_identifier(stem);
    const auto relocations = collect_dma_relocations(encoded);
    std::ostringstream output;
    output << "/* Generated file: fixed HPU instruction words plus per-DMA relocation. */\n"
           << "#include \"" << stem << ".h\"\n\n"
           << "enum { HPU_MEM_LINE_COUNT = " << kHpuMemLineCount
           << ", HPU_SMALL_BANK_LINE_COUNT = " << kSmallBankLineCount << " };\n\n"
           << "int hpu_program_" << id
           << "(const hpu_dma_span_t *spans, size_t span_count) {\n"
           << "    if (span_count != HPU_PROGRAM_";
    for (char ch : id) {
        output << static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    output << "_DMA_COUNT || (span_count != 0 && spans == NULL)) return -1;\n"
           << "    for (size_t i = 0; i < span_count; ++i) {\n"
           << "        if (spans[i].line_count == 0 ||\n"
           << "            spans[i].line_offset >= HPU_MEM_LINE_COUNT ||\n"
           << "            spans[i].line_count > HPU_MEM_LINE_COUNT - spans[i].line_offset)\n"
           << "            return -2;\n"
           << "    }\n";

    std::size_t dma_index = 0;
    for (std::size_t instruction_index = 0;
         instruction_index < encoded.size(); ++instruction_index) {
        const auto& item = encoded[instruction_index];
        const auto& instruction = item.instruction;
        output << "    /* " << instruction_index << ": "
               << item.normalized_asm << " */\n";
        if (instruction_format(instruction.mnemonic) == Format::kDMA) {
            if (instruction.mnemonic == Mnemonic::kDload
                && instruction.dma_flag != 0) {
                output << "    if (spans[" << dma_index
                       << "].line_count > HPU_SMALL_BANK_LINE_COUNT) return -3;\n";
            }
            output << "#if defined(__riscv)\n"
                   << "    {\n"
                   << "        register uintptr_t hpu_rs1 __asm__(\"x10\") = "
                   << "(uintptr_t)spans[" << dma_index << "].line_offset;\n"
                   << "        register uintptr_t hpu_rs2 __asm__(\"x11\") = "
                   << "(uintptr_t)spans[" << dma_index << "].line_count;\n";
            output << "        __asm__ volatile(\".word " << hex_word(item.word)
                   << "\" : : \"r\"(hpu_rs1), \"r\"(hpu_rs2) : \"memory\");\n"
                   << "    }\n"
                   << "#endif\n";
            ++dma_index;
        } else {
            output << "#if defined(__riscv)\n"
                   << "    __asm__ volatile(\".word " << hex_word(item.word)
                   << "\" : : : \"memory\");\n"
                   << "#endif\n";
        }
    }
    output << "#if !defined(__riscv)\n"
           << "    return -4;\n"
           << "#else\n"
           << "    return 0;\n"
           << "#endif\n"
           << "}\n";
    return output.str();
}

std::string render_dma_manifest(
    const std::vector<EncodedInstruction>& encoded) {
    const auto relocations = collect_dma_relocations(encoded);
    std::ostringstream output;
    output << "instruction_index,dma_index,direction,obj_id,type_or_release,flag,"
              "rs1,rs2,word_hex,normalized_asm\n";
    for (const auto& relocation : relocations) {
        const auto& item = encoded[relocation.instruction_index];
        output << relocation.instruction_index << ',' << relocation.dma_index << ','
               << to_string(relocation.direction) << ','
               << static_cast<unsigned>(relocation.object_id) << ','
               << static_cast<unsigned>(relocation.type_or_release) << ','
               << static_cast<unsigned>(relocation.flag) << ",x10,x11,"
               << hex_word(item.word) << ',' << csv_field(item.normalized_asm) << '\n';
    }
    return output.str();
}

}  // namespace hpu
