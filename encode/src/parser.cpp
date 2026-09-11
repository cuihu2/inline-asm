#include "parser.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace hpu {
namespace {

std::string trim(std::string value) {
    auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string strip_inline_comments(std::string line) {
    auto erase_from = [&](std::size_t pos) {
        if (pos != std::string::npos) {
            line.erase(pos);
        }
    };

    erase_from(line.find("//"));
    erase_from(line.find('#'));
    erase_from(line.find(';'));

    const auto block_begin = line.find("/*");
    if (block_begin != std::string::npos) {
        const auto block_end = line.find("*/", block_begin + 2);
        if (block_end != std::string::npos) {
            line.erase(block_begin, block_end - block_begin + 2);
        } else {
            line.erase(block_begin);
        }
    }

    return line;
}

std::string unescape_quoted(std::string_view quoted) {
    std::string out;
    out.reserve(quoted.size());
    bool escaping = false;
    for (char ch : quoted) {
        if (escaping) {
            switch (ch) {
                case 'n':
                case 'r':
                case 't':
                    break;
                case '\\':
                case '"':
                    out.push_back(ch);
                    break;
                default:
                    out.push_back(ch);
                    break;
            }
            escaping = false;
            continue;
        }

        if (ch == '\\') {
            escaping = true;
            continue;
        }

        out.push_back(ch);
    }
    return out;
}

bool is_generated_cpp_function_boundary(const std::string& line) {
    return line.rfind("void ", 0) == 0 &&
           line.find("(void)") != std::string::npos &&
           !line.empty() &&
           line.back() == '{';
}

bool is_inline_asm_boundary_line(const std::string& line) {
    return line == "__asm__ volatile(" || line == "asm volatile(" ||
           line == ");" || line == "(" || line == ")" ||
           line == "{" || line == "}" || line == ":" ||
           line == "," || line == ": \"memory\"" ||
           is_generated_cpp_function_boundary(line);
}

std::string normalize_line(std::string_view raw_line) {
    std::string line = trim(strip_inline_comments(std::string(raw_line)));
    if (line.empty()) {
        return {};
    }

    if (is_inline_asm_boundary_line(line)) {
        return {};
    }

    const auto first_quote = line.find('"');
    const auto last_quote = line.rfind('"');
    if (first_quote != std::string::npos && last_quote != first_quote) {
        line = trim(unescape_quoted(line.substr(first_quote + 1, last_quote - first_quote - 1)));
    }

    line = trim(line);
    if (is_inline_asm_boundary_line(line)) {
        return {};
    }

    return line;
}

std::vector<std::string> split_operands(const std::string& operand_text) {
    std::vector<std::string> operands;
    std::string current;
    std::stringstream ss(operand_text);
    while (std::getline(ss, current, ',')) {
        current = trim(current);
        if (!current.empty()) {
            operands.push_back(current);
        }
    }
    return operands;
}

int parse_base0_int(const std::string& token, const std::string& field_name) {
    std::size_t consumed = 0;
    int value = 0;
    try {
        value = std::stoi(token, &consumed, 0);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid integer for " + field_name + ": " + token);
    }

    if (consumed != token.size()) {
        throw std::runtime_error("invalid integer for " + field_name + ": " + token);
    }
    return value;
}

int parse_pobj(const std::string& token, const std::string& field_name) {
    if (token.size() < 2 || token.front() != 'p') {
        throw std::runtime_error("invalid object slot for " + field_name + ": " + token);
    }
    const int value = parse_base0_int(token.substr(1), field_name);
    if (value < 0 || value > 7) {
        throw std::runtime_error("object slot out of range for " + field_name + ": " + token);
    }
    return value;
}

int parse_xreg(const std::string& token, const std::string& field_name) {
    if (token.size() < 2 || token.front() != 'x') {
        throw std::runtime_error("invalid register for " + field_name + ": " + token);
    }
    const int value = parse_base0_int(token.substr(1), field_name);
    if (value < 0 || value > 31) {
        throw std::runtime_error("register out of range for " + field_name + ": " + token);
    }
    return value;
}

void expect_operand_count(const std::vector<std::string>& operands,
                          std::size_t expected,
                          const std::string& mnemonic) {
    if (operands.size() != expected) {
        throw std::runtime_error("unexpected operand count for " + mnemonic);
    }
}

Instruction parse_ar3(Mnemonic mnemonic,
                      const std::vector<std::string>& operands) {
    expect_operand_count(operands, 3, to_string(mnemonic));

    Instruction instruction {};
    instruction.mnemonic = mnemonic;
    instruction.pdst = parse_pobj(operands[0], "pdst");
    instruction.psrc1 = parse_pobj(operands[1], "psrc1");
    if (!operands[2].empty() && operands[2].front() == 'p') {
        instruction.psrc2 = parse_pobj(operands[2], "psrc2");
    } else {
        if (mnemonic != Mnemonic::kPmul && mnemonic != Mnemonic::kPmac) {
            throw std::runtime_error("only pmul/pmac support cimm8");
        }
        instruction.imm8 = parse_base0_int(operands[2], "cimm8");
    }
    return instruction;
}

Instruction parse_stg(Mnemonic mnemonic, const std::vector<std::string>& operands) {
    expect_operand_count(operands, 6, to_string(mnemonic));

    Instruction instruction {};
    instruction.mnemonic = mnemonic;
    instruction.pdst = parse_pobj(operands[0], "pdst");
    instruction.psrc1 = parse_pobj(operands[1], "psrc1");
    instruction.psrc2 = parse_pobj(operands[2], "ptwiddle");
    instruction.idx0 = parse_base0_int(operands[3], "stage");
    instruction.mode = static_cast<std::uint8_t>(parse_base0_int(operands[4], "mode"));
    instruction.flag = static_cast<std::uint8_t>(parse_base0_int(operands[5], "flag"));
    return instruction;
}

Instruction parse_mod(const std::vector<std::string>& operands) {
    expect_operand_count(operands, 1, "pmodld");

    Instruction instruction {};
    instruction.mnemonic = Mnemonic::kPmodld;
    instruction.mod_id = parse_base0_int(operands[0], "mod_id");
    return instruction;
}

Instruction parse_cfg(Mnemonic mnemonic, const std::vector<std::string>& operands) {
    Instruction instruction {};
    instruction.mnemonic = mnemonic;

    expect_operand_count(operands, 1, "pfree");
    instruction.idx0 = parse_pobj(operands[0], "idx0");
    instruction.idx1 = 0;
    instruction.cfg = 0;
    return instruction;
}

Instruction parse_sync(const std::vector<std::string>& operands) {
    expect_operand_count(operands, 0, "psync");

    Instruction instruction {};
    instruction.mnemonic = Mnemonic::kPsync;
    return instruction;
}

Instruction parse_dma(Mnemonic mnemonic, const std::vector<std::string>& operands) {
    expect_operand_count(operands, mnemonic == Mnemonic::kDload ? 5 : 4,
                         to_string(mnemonic));

    Instruction instruction {};
    instruction.mnemonic = mnemonic;
    instruction.rs1 = parse_xreg(operands[0], "rs1");
    instruction.rs2 = parse_xreg(operands[1], "rs2");
    instruction.obj_id = static_cast<std::uint8_t>(parse_pobj(operands[2], "obj_id"));
    instruction.type = static_cast<std::uint8_t>(
        parse_base0_int(
            operands[3],
            mnemonic == Mnemonic::kDload ? "load_type" : "rel"));
    if (mnemonic == Mnemonic::kDload) {
        instruction.dma_flag =
            static_cast<std::uint8_t>(parse_base0_int(operands[4], "small_bank"));
    }
    return instruction;
}

}  // namespace

Instruction parse_instruction_line(std::string_view line) {
    const std::string normalized = normalize_line(line);
    if (normalized.empty()) {
        throw std::runtime_error("empty instruction line");
    }

    const auto split = normalized.find_first_of(" \t");
    const std::string mnemonic = to_lower(normalized.substr(0, split));
    const std::string operand_text = split == std::string::npos ? std::string() : normalized.substr(split + 1);
    const std::vector<std::string> operands = split_operands(operand_text);

    if (mnemonic == "padd") return parse_ar3(Mnemonic::kPadd, operands);
    if (mnemonic == "psub") return parse_ar3(Mnemonic::kPsub, operands);
    if (mnemonic == "pmul") return parse_ar3(Mnemonic::kPmul, operands);
    if (mnemonic == "pmac") return parse_ar3(Mnemonic::kPmac, operands);

    if (mnemonic == "pntt") return parse_stg(Mnemonic::kPntt, operands);
    if (mnemonic == "pintt") return parse_stg(Mnemonic::kPintt, operands);
    if (mnemonic == "pmodld") return parse_mod(operands);
    if (mnemonic == "pfree") return parse_cfg(Mnemonic::kPfree, operands);

    if (mnemonic == "psync") return parse_sync(operands);

    if (mnemonic == "dload") return parse_dma(Mnemonic::kDload, operands);
    if (mnemonic == "dstore") return parse_dma(Mnemonic::kDstore, operands);

    throw std::runtime_error("unsupported mnemonic: " + mnemonic);
}

std::vector<Instruction> parse_source(std::string_view source) {
    std::vector<Instruction> instructions;
    std::stringstream ss{std::string(source)};
    std::string line;
    while (std::getline(ss, line)) {
        const std::string normalized = normalize_line(line);
        if (normalized.empty()) {
            continue;
        }
        instructions.push_back(parse_instruction_line(normalized));
    }
    return instructions;
}

}  // namespace hpu
