"""Shared HPU ABI constants and fail-closed input validation helpers."""

from __future__ import annotations

from collections.abc import Mapping, Set
import re
from typing import Any


__all__ = [
    "BARRETT_MU_BITS",
    "LINE_BYTES",
    "MAX_MOD_CONTEXTS",
    "MIN_PE_MODULUS",
    "NTT_REGISTER_COUNT",
    "REGULAR_BANK_LINES",
    "SMALL_BANK_LINES",
    "UINT32_MAX",
    "WORDS_PER_LINE",
    "has_mod_context_capacity",
    "is_power_of_two",
    "is_prime",
    "is_valid_ntt_size",
    "parse_shape",
    "require_fields",
    "require_int",
    "require_mapping",
    "require_safe_name",
    "require_text",
    "require_uint32",
    "shape_words",
]

LINE_BYTES = 256
WORDS_PER_LINE = LINE_BYTES // 4
NTT_REGISTER_COUNT = 128
REGULAR_BANK_LINES = 1024
SMALL_BANK_LINES = 32
_MOD_CONTEXT_WORDS = 4
_MOD_CONTEXTS_PER_LINE = WORDS_PER_LINE // _MOD_CONTEXT_WORDS
_MOD_ID_BITS = 8
_PHYSICAL_MOD_CONTEXTS = SMALL_BANK_LINES * _MOD_CONTEXTS_PER_LINE
MAX_MOD_CONTEXTS = min(_PHYSICAL_MOD_CONTEXTS, 1 << _MOD_ID_BITS)
MIN_PE_MODULUS = 65537
UINT32_MAX = (1 << 32) - 1
BARRETT_MU_BITS = 48

_SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


def is_power_of_two(value: int) -> bool:
    """Return whether *value* is a positive, non-boolean power of two."""

    return type(value) is int and value > 0 and (value & (value - 1)) == 0


def is_valid_ntt_size(value: int) -> bool:
    """Check the frozen 128-register and 1024-line regular-bank limits."""

    return (
        is_power_of_two(value)
        and value >= NTT_REGISTER_COUNT
        and (value + WORDS_PER_LINE - 1) // WORDS_PER_LINE <= REGULAR_BANK_LINES
    )


def has_mod_context_capacity(
    num_q: int,
    num_p: int = 0,
    reserved_contexts: int = 0,
) -> bool:
    """Check the physical table and 8-bit MOD_ID capacity without overflow."""

    if not all(type(value) is int for value in (num_q, num_p, reserved_contexts)):
        return False
    return (
        num_q > 0
        and num_p >= 0
        and reserved_contexts >= 0
        and reserved_contexts <= MAX_MOD_CONTEXTS
        and num_q <= MAX_MOD_CONTEXTS - reserved_contexts
        and num_p <= MAX_MOD_CONTEXTS - reserved_contexts - num_q
    )


def is_prime(value: int) -> bool:
    """Return whether *value* is prime using the same bounded trial division as main."""

    if type(value) is not int or value < 2:
        return False
    if value & 1 == 0:
        return value == 2
    divisor = 3
    while divisor <= value // divisor:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")
    return value


def require_fields(
    value: Mapping[str, Any],
    name: str,
    required: Set[str],
    optional: Set[str] | None = None,
) -> None:
    allowed = set(required) | (set(optional) if optional is not None else set())
    fields = set(value)
    missing = set(required) - fields
    unknown = fields - allowed
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")


def require_int(
    value: Any,
    name: str,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return value


def require_uint32(value: Any, name: str) -> int:
    return require_int(value, name, 0, UINT32_MAX)


def require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value.strip()


def require_safe_name(value: Any, name: str) -> str:
    text = require_text(value, name)
    if _SAFE_NAME.fullmatch(text) is None or text in {".", ".."}:
        raise ValueError(f"{name} must be a safe file-name component")
    return text


def parse_shape(value: Any, name: str) -> tuple[int, ...]:
    if type(value) is int:
        dimensions = (value,)
    elif isinstance(value, list):
        dimensions = tuple(value)
    else:
        raise ValueError(f"{name} must be an integer or a list of integers")
    if not dimensions:
        raise ValueError(f"{name} must contain at least one dimension")
    for dimension in dimensions:
        if type(dimension) is not int or dimension <= 0:
            raise ValueError(f"{name} dimensions must be positive integers")
    return dimensions


def shape_words(shape: tuple[int, ...]) -> int:
    words = 1
    for dimension in shape:
        words *= dimension
    return words
