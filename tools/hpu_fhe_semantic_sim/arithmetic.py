"""Pure functional semantics for HPU polynomial arithmetic instructions."""

from array import array
from collections.abc import Sequence


def apply_arithmetic(
    op: str,
    dst: Sequence[int] | None,
    src1: Sequence[int],
    src2_or_imm: Sequence[int] | int,
    q: int,
) -> array:
    """Apply one HPU arithmetic instruction and return canonical residues."""

    if not 2 <= q <= 0xFFFF_FFFF:
        raise ValueError("modulus q must fit the uint32 HPU coefficient ABI")
    if op not in {"padd", "psub", "pmul", "pmac"}:
        raise ValueError(f"unsupported arithmetic operation: {op}")
    if isinstance(src2_or_imm, int):
        if op not in {"pmul", "pmac"}:
            raise ValueError(f"{op} does not support an immediate operand")
        if not 0 <= src2_or_imm <= 255:
            raise ValueError("cimm8 must be in the range 0..255")
    elif len(src1) != len(src2_or_imm):
        raise ValueError("source objects must have equal lengths")
    if op == "pmac" and (dst is None or len(dst) != len(src1)):
        raise ValueError("pmac requires an equally sized accumulator destination")

    if op == "pmac":
        if dst is None:
            raise ValueError("pmac requires an accumulator destination")
        products = apply_arithmetic("pmul", None, src1, src2_or_imm, q)
        return array("I", (
            (accumulator + product) % q
            for accumulator, product in zip(dst, products, strict=True)
        ))
    if op == "pmul":
        if isinstance(src2_or_imm, int):
            return array("I", ((left * src2_or_imm) % q for left in src1))
        return array("I", (
            (left * right) % q
            for left, right in zip(src1, src2_or_imm, strict=True)
        ))
    if op == "psub":
        return array("I", (
            (left - right) % q
            for left, right in zip(src1, src2_or_imm, strict=True)
        ))
    return array("I", (
        (left + right) % q
        for left, right in zip(src1, src2_or_imm, strict=True)
    ))
