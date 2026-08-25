"""Independent decoder for the HPU custom0/custom1 instruction words."""

from __future__ import annotations

from dataclasses import dataclass


__all__ = [
    "Instruction",
    "decode_instruction",
    "expected_command26",
    "parse_asm_instruction",
    "parse_instruction_word",
]

_CUSTOM0_OPCODE = 0x0B
_CUSTOM1_OPCODE = 0x2B

_ARITHMETIC_MNEMONICS = {
    0x0: "padd",
    0x1: "psub",
    0x2: "pmul",
    0x3: "pmac",
}

_STAGE_MNEMONICS = {
    0x4: "pntt",
    0x5: "pintt",
}


@dataclass(frozen=True, slots=True)
class Instruction:
    mnemonic: str
    word: int
    pdst: int | None = None
    psrc1: int | None = None
    psrc2: int | None = None
    imm8: int | None = None
    stage: int | None = None
    mode: int | None = None
    flag: int | None = None
    mod_id: int | None = None
    rs1: int | None = None
    rs2: int | None = None
    obj_id: int | None = None
    type_or_release: int | None = None
    dma_flag: int | None = None


def _ensure_reserved_zero(word: int, allowed_mask: int, format_name: str) -> None:
    reserved = word & (~allowed_mask & 0xFFFFFFFF)
    if reserved:
        raise ValueError(
            f"{format_name} reserved bits must be zero: 0x{reserved:08X}"
        )


def _validate_instruction_word(word: int) -> None:
    if isinstance(word, bool) or not isinstance(word, int):
        raise ValueError("instruction word must be an integer")
    if not 0 <= word <= 0xFFFFFFFF:
        raise ValueError("instruction word must fit in unsigned 32 bits")


def parse_instruction_word(text: str) -> int:
    """Parse one textual 32-bit instruction in binary or hexadecimal form."""
    if not isinstance(text, str):
        raise ValueError("instruction word must be text")
    token = text.strip()
    if len(token) == 32 and all(character in "01" for character in token):
        return int(token, 2)
    if token.lower().startswith("0b"):
        digits = token[2:]
        if 1 <= len(digits) <= 32 and all(
            character in "01" for character in digits
        ):
            return int(digits, 2)
    if token.lower().startswith("0x"):
        digits = token[2:]
        if 1 <= len(digits) <= 8 and all(
            character in "0123456789abcdefABCDEF" for character in digits
        ):
            return int(digits, 16)
    raise ValueError(
        "instruction word must be binary text or 0x-prefixed hex"
    )


def _parse_int(token: str, field_name: str, minimum: int, maximum: int) -> int:
    try:
        value = int(token, 0)
    except ValueError as error:
        raise ValueError(f"invalid integer for {field_name}: {token}") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{field_name} must be in range {minimum}..{maximum}")
    return value


def _parse_pobj(token: str, field_name: str) -> int:
    if not token.startswith("p"):
        raise ValueError(f"{field_name} must be p0..p7")
    return _parse_int(token[1:], field_name, 0, 7)


def _parse_xreg(token: str, field_name: str) -> int:
    if not token.startswith("x"):
        raise ValueError(f"{field_name} must be x0..x31")
    return _parse_int(token[1:], field_name, 0, 31)


def parse_asm_instruction(source: str) -> Instruction:
    """Parse and independently encode one textual HPU instruction."""

    if not isinstance(source, str):
        raise ValueError("assembly instruction must be text")
    line = source
    for marker in ("//", "#", ";"):
        line = line.split(marker, 1)[0]
    line = line.strip().lower()
    if not line:
        raise ValueError("assembly instruction is empty")
    mnemonic, separator, operand_text = line.partition(" ")
    operands = [item.strip() for item in operand_text.split(",") if item.strip()]

    arithmetic_opcodes = {"padd": 0, "psub": 1, "pmul": 2, "pmac": 3}
    if mnemonic in arithmetic_opcodes:
        if len(operands) != 3:
            raise ValueError(f"{mnemonic} requires three operands")
        pdst = _parse_pobj(operands[0], "pdst")
        psrc1 = _parse_pobj(operands[1], "psrc1")
        if operands[2].startswith("p"):
            operand2 = _parse_pobj(operands[2], "psrc2")
            mode = 0
        else:
            if mnemonic not in {"pmul", "pmac"}:
                raise ValueError(f"{mnemonic} does not support cimm8")
            operand2 = _parse_int(operands[2], "cimm8", 0, 255)
            mode = 1
        word = (
            (arithmetic_opcodes[mnemonic] << 28)
            | (pdst << 25)
            | (psrc1 << 22)
            | (operand2 << 14)
            | (mode << 8)
            | _CUSTOM0_OPCODE
        )
        return decode_instruction(word)

    if mnemonic in {"pntt", "pintt"}:
        if len(operands) != 5:
            raise ValueError(f"{mnemonic} requires five operands")
        opcode = 4 if mnemonic == "pntt" else 5
        word = (
            (opcode << 28)
            | (_parse_pobj(operands[0], "pdata") << 25)
            | (_parse_pobj(operands[1], "ptwiddle") << 22)
            | (_parse_int(operands[2], "stage", 0, 15) << 10)
            | (_parse_int(operands[3], "mode", 0, 3) << 8)
            | (_parse_int(operands[4], "flag", 0, 1) << 7)
            | _CUSTOM0_OPCODE
        )
        return decode_instruction(word)

    if mnemonic == "pmodld":
        if len(operands) != 1:
            raise ValueError("pmodld requires one MOD_ID")
        word = (6 << 28) | (_parse_int(operands[0], "mod_id", 0, 255) << 14) | _CUSTOM0_OPCODE
        return decode_instruction(word)
    if mnemonic == "pfree":
        if len(operands) != 1:
            raise ValueError("pfree requires one object")
        word = (8 << 28) | (_parse_pobj(operands[0], "object") << 22) | _CUSTOM0_OPCODE
        return decode_instruction(word)
    if mnemonic == "psync":
        if operands or separator and operand_text.strip():
            raise ValueError("psync has no operands")
        return decode_instruction((7 << 28) | _CUSTOM0_OPCODE)

    if mnemonic in {"dload", "dstore"}:
        expected = 5 if mnemonic == "dload" else 4
        if len(operands) != expected:
            raise ValueError(f"{mnemonic} requires {expected} operands")
        rs1 = _parse_xreg(operands[0], "rs1")
        rs2 = _parse_xreg(operands[1], "rs2")
        obj_id = _parse_pobj(operands[2], "obj_id")
        type_or_release = _parse_int(
            operands[3],
            "load_type" if mnemonic == "dload" else "release",
            0,
            2 if mnemonic == "dload" else 1,
        )
        flag = _parse_int(operands[4], "small_bank", 0, 1) if mnemonic == "dload" else 0
        direction = 0 if mnemonic == "dload" else 1
        word = (
            (rs2 << 20)
            | (rs1 << 15)
            | (direction << 14)
            | (type_or_release << 12)
            | (obj_id << 9)
            | (flag << 8)
            | _CUSTOM1_OPCODE
        )
        return decode_instruction(word)
    raise ValueError(f"unsupported HPU mnemonic: {mnemonic}")


def decode_instruction(word: int) -> Instruction:
    """Decode one validated 32-bit HPU instruction word."""
    _validate_instruction_word(word)
    opcode = word & 0x7F
    operation = (word >> 28) & 0xF
    if opcode == _CUSTOM0_OPCODE and operation in _ARITHMETIC_MNEMONICS:
        if word & (0xF << 10):
            raise ValueError("AR3 STAGE4 reserved bits must be zero")
        mode = (word >> 8) & 0x3
        immediate_mode = mode & 0x1
        operand2 = (word >> 14) & 0xFF
        mnemonic = _ARITHMETIC_MNEMONICS[operation]
        if not immediate_mode and operand2 > 7:
            raise ValueError("AR3 object operand has nonzero reserved bits")
        if immediate_mode and mnemonic not in ("pmul", "pmac"):
            raise ValueError("only pmul/pmac support cimm8")
        return Instruction(
            mnemonic=mnemonic,
            word=word,
            pdst=(word >> 25) & 0x7,
            psrc1=(word >> 22) & 0x7,
            psrc2=operand2 if not immediate_mode else None,
            imm8=operand2 if immediate_mode else None,
            mode=mode,
            flag=(word >> 7) & 0x1,
        )
    if opcode == _CUSTOM0_OPCODE and operation in _STAGE_MNEMONICS:
        if word & (0xFF << 14):
            raise ValueError("STG reserved bits must be zero")
        return Instruction(
            mnemonic=_STAGE_MNEMONICS[operation],
            word=word,
            pdst=(word >> 25) & 0x7,
            psrc1=(word >> 22) & 0x7,
            stage=(word >> 10) & 0xF,
            mode=(word >> 8) & 0x3,
            flag=(word >> 7) & 0x1,
        )
    if opcode == _CUSTOM0_OPCODE and operation == 0x6:
        _ensure_reserved_zero(
            word,
            (0xF << 28) | (0xFF << 14) | 0x7F,
            "MOD",
        )
        return Instruction(
            mnemonic="pmodld",
            word=word,
            mod_id=(word >> 14) & 0xFF,
        )
    if opcode == _CUSTOM0_OPCODE and operation == 0x7:
        _ensure_reserved_zero(word, (0xF << 28) | 0x7F, "SYNC")
        return Instruction(mnemonic="psync", word=word)
    if opcode == _CUSTOM0_OPCODE and operation == 0x8:
        _ensure_reserved_zero(
            word,
            (0xF << 28) | (0x7 << 22) | 0x7F,
            "PFREE",
        )
        return Instruction(
            mnemonic="pfree",
            word=word,
            obj_id=(word >> 22) & 0x7,
        )
    if opcode == _CUSTOM1_OPCODE:
        _ensure_reserved_zero(
            word,
            (0x1F << 20)
            | (0x1F << 15)
            | (0x1 << 14)
            | (0x3 << 12)
            | (0x7 << 9)
            | (0x1 << 8)
            | 0x7F,
            "DMA",
        )
        direction = (word >> 14) & 0x1
        type_or_release = (word >> 12) & 0x3
        dma_flag = (word >> 8) & 0x1
        if direction == 0 and type_or_release > 2:
            raise ValueError("dload type must be in range 0..2")
        if direction == 1 and type_or_release > 1:
            raise ValueError("dstore release must be in range 0..1")
        if direction == 1 and dma_flag != 0:
            raise ValueError("dstore SMALL_BANK flag must be zero")
        return Instruction(
            mnemonic="dstore" if direction else "dload",
            word=word,
            rs1=(word >> 15) & 0x1F,
            rs2=(word >> 20) & 0x1F,
            obj_id=(word >> 9) & 0x7,
            type_or_release=type_or_release,
            dma_flag=dma_flag,
        )
    raise ValueError(f"unsupported HPU instruction word: 0x{word:08X}")


def expected_command26(word: int) -> int:
    """Return the 26-bit HPU command produced by the frozen precode ABI."""
    decode_instruction(word)
    opcode = word & 0x7F
    if opcode == _CUSTOM0_OPCODE:
        return word >> 7
    if opcode == _CUSTOM1_OPCODE:
        direction = (word >> 14) & 0x1
        raw_type = (word >> 12) & 0x3
        encoded_type = raw_type << 1 if direction else raw_type
        obj_id = (word >> 9) & 0x7
        dma_flag = (word >> 8) & 0x1
        return (
            (1 << 25)
            | (dma_flag << 10)
            | (obj_id << 3)
            | (encoded_type << 1)
            | direction
        )
    raise ValueError(f"instruction is not custom0/custom1: 0x{word:08X}")
