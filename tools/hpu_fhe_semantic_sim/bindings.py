"""Strict DMA relocation parsing and explicit artifact binding.

The inline-asm delivery contains two independent facts:

* ``dma_relocation_manifest.csv`` describes each custom1 instruction; and
* ``hardware/line_map.csv`` describes addressable artifacts in HPU_MEM.

There is intentionally no name-based join between them.  A caller must supply
one :class:`DmaArtifactAssignment` for every relocation before a semantic run
can obtain concrete line offsets and counts.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Mapping, Sequence

from .isa import decode_instruction, parse_asm_instruction
from .validation import REGULAR_BANK_LINES, SMALL_BANK_LINES, WORDS_PER_LINE


__all__ = [
    "ArtifactSpan",
    "BindingValidationError",
    "DmaArtifactAssignment",
    "DmaRelocation",
    "ResolvedDmaBinding",
    "load_dma_relocations",
    "load_dma_assignments_json",
    "normalize_manifest_path",
    "resolve_dma_bindings",
]


_RELOCATION_FIELDS = (
    "instruction_index",
    "dma_index",
    "direction",
    "obj_id",
    "type_or_release",
    "flag",
    "rs1",
    "rs2",
    "word_hex",
    "normalized_asm",
)
_UNSIGNED_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_WORD_HEX = re.compile(r"0x[0-9A-Fa-f]{8}\Z")


class BindingValidationError(ValueError):
    """The relocation or its explicit artifact assignment is malformed."""


@dataclass(frozen=True, slots=True)
class ArtifactSpan:
    """One validated row from the delivery's HPU_MEM line map."""

    relative_path: str
    binary_path: Path
    readable_path: Path | None
    role: str
    shape: str
    address_byte: int
    line_offset: int
    line_count: int
    payload_words: int
    payload_bytes: int
    padded_words: int
    padded_bytes: int


@dataclass(frozen=True, slots=True)
class DmaRelocation:
    """One DMA instruction whose x10/x11 span still needs binding."""

    instruction_index: int
    dma_index: int
    direction: str
    obj_id: int
    type_or_release: int
    flag: int
    rs1: int
    rs2: int
    word: int
    normalized_asm: str


@dataclass(frozen=True, slots=True)
class DmaArtifactAssignment:
    """An explicit, auditable mapping from one DMA to one line-map artifact."""

    dma_index: int
    artifact_path: str
    artifact_line_offset: int
    line_count: int
    domain: str


@dataclass(frozen=True, slots=True)
class ResolvedDmaBinding:
    """A relocation joined to an explicitly selected delivery artifact."""

    dma_index: int
    instruction_index: int
    direction: str
    line_offset: int
    line_count: int
    obj_id: int
    type_or_release: int
    flag: int
    payload_words: int
    artifact_line_offset: int
    domain: str
    role: str
    artifact_path: str
    binary_path: Path
    readable_path: Path | None

    def as_semantic_dict(self) -> dict[str, object]:
        """Return the field layout consumed by the existing semantic runner."""

        return {
            "dma_index": self.dma_index,
            "instruction_index": self.instruction_index,
            "direction": self.direction,
            "line_offset": self.line_offset,
            "line_count": self.line_count,
            "obj_id": self.obj_id,
            "type_or_release": self.type_or_release,
            "flag": self.flag,
            "payload_words": self.payload_words,
            "artifact_line_offset": self.artifact_line_offset,
            "domain": self.domain,
            "role": self.role,
            "artifact_path": self.artifact_path,
            "expected_artifact": None,
        }


def normalize_manifest_path(value: str, field_name: str = "path") -> str:
    """Validate a portable, package-relative POSIX path without resolving it."""

    if not isinstance(value, str) or not value:
        raise BindingValidationError(f"{field_name} must be nonempty text")
    if "\x00" in value or "\\" in value:
        raise BindingValidationError(
            f"{field_name} must be a POSIX path without NUL or backslash"
        )
    if value.startswith("/") or value.endswith("/") or "//" in value:
        raise BindingValidationError(f"{field_name} must be a normalized relative path")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise BindingValidationError(f"{field_name} may not contain '.' or '..'")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value:
        raise BindingValidationError(f"{field_name} must be a normalized relative path")
    return value


def load_dma_assignments_json(
    path: str | Path,
) -> tuple[DmaArtifactAssignment, ...]:
    """Load the explicit DMA-to-artifact join used by delivery validation."""

    manifest_path = Path(path)
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BindingValidationError(
            f"cannot read DMA assignment manifest {manifest_path}: {error}"
        ) from error
    if not isinstance(document, dict) or set(document) != {
        "format_version",
        "assignments",
    }:
        raise BindingValidationError(
            "DMA assignment manifest fields must be format_version and assignments"
        )
    if type(document["format_version"]) is not int or document["format_version"] != 1:
        raise BindingValidationError("DMA assignment manifest requires format_version 1")
    raw_assignments = document["assignments"]
    if not isinstance(raw_assignments, list):
        raise BindingValidationError("DMA assignment manifest assignments must be a list")

    assignments: list[DmaArtifactAssignment] = []
    for index, raw in enumerate(raw_assignments):
        if not isinstance(raw, dict) or set(raw) != {
            "dma_index",
            "artifact_path",
            "artifact_line_offset",
            "line_count",
            "domain",
        }:
            raise BindingValidationError(
                f"DMA assignment {index} fields must be dma_index, artifact_path, "
                "artifact_line_offset, line_count, and domain"
            )
        dma_index = raw["dma_index"]
        if type(dma_index) is not int or dma_index < 0:
            raise BindingValidationError(
                f"DMA assignment {index} dma_index must be a nonnegative integer"
            )
        artifact_path = normalize_manifest_path(
            raw["artifact_path"],
            f"DMA assignment {index} artifact_path",
        )
        artifact_line_offset = raw["artifact_line_offset"]
        line_count = raw["line_count"]
        if type(artifact_line_offset) is not int or artifact_line_offset < 0:
            raise BindingValidationError(
                f"DMA assignment {index} artifact_line_offset must be nonnegative"
            )
        if type(line_count) is not int or line_count <= 0:
            raise BindingValidationError(
                f"DMA assignment {index} line_count must be positive"
            )
        domain = raw["domain"]
        if not isinstance(domain, str) or not domain or domain != domain.strip():
            raise BindingValidationError(
                f"DMA assignment {index} domain must be nonempty trimmed text"
            )
        assignments.append(
            DmaArtifactAssignment(
                dma_index,
                artifact_path,
                artifact_line_offset,
                line_count,
                domain,
            )
        )
    return tuple(assignments)


def _parse_uint(value: str | None, field_name: str) -> int:
    if value is None or _UNSIGNED_DECIMAL.fullmatch(value) is None:
        raise BindingValidationError(f"{field_name} must be an unsigned decimal integer")
    return int(value, 10)


def _read_csv(path: Path) -> tuple[dict[str, str], ...]:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != _RELOCATION_FIELDS:
                raise BindingValidationError(
                    "dma relocation manifest has an unexpected CSV header"
                )
            rows: list[dict[str, str]] = []
            for line_number, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise BindingValidationError(
                        f"dma relocation manifest row {line_number} has the wrong column count"
                    )
                rows.append(row)
    except OSError as error:
        raise BindingValidationError(
            f"cannot read DMA relocation manifest {path}: {error}"
        ) from error
    if not rows:
        raise BindingValidationError("dma relocation manifest must not be empty")
    return tuple(rows)


def load_dma_relocations(
    path: str | Path,
    instruction_words: Sequence[int],
) -> tuple[DmaRelocation, ...]:
    """Parse and cross-check the relocation CSV against the encoded program."""

    manifest_path = Path(path)
    decoded_program = []
    try:
        decoded_program = [decode_instruction(word) for word in instruction_words]
    except ValueError as error:
        raise BindingValidationError(f"program contains an invalid instruction: {error}") from error
    dma_instruction_indices = [
        index
        for index, instruction in enumerate(decoded_program)
        if instruction.mnemonic in {"dload", "dstore"}
    ]
    rows = _read_csv(manifest_path)
    if len(rows) != len(dma_instruction_indices):
        raise BindingValidationError(
            "DMA relocation row count does not match custom1 instruction count"
        )

    relocations: list[DmaRelocation] = []
    for expected_dma_index, (row, expected_instruction_index) in enumerate(
        zip(rows, dma_instruction_indices, strict=True)
    ):
        instruction_index = _parse_uint(row["instruction_index"], "instruction_index")
        dma_index = _parse_uint(row["dma_index"], "dma_index")
        obj_id = _parse_uint(row["obj_id"], "obj_id")
        type_or_release = _parse_uint(row["type_or_release"], "type_or_release")
        flag = _parse_uint(row["flag"], "flag")
        if instruction_index != expected_instruction_index:
            raise BindingValidationError(
                f"DMA {expected_dma_index} points at instruction {instruction_index}, "
                f"expected {expected_instruction_index}"
            )
        if dma_index != expected_dma_index:
            raise BindingValidationError(
                f"DMA indices must be contiguous from zero; found {dma_index} at row "
                f"{expected_dma_index}"
            )
        if row["rs1"] != "x10" or row["rs2"] != "x11":
            raise BindingValidationError("delivery DMA relocations must use x10/x11")
        if _WORD_HEX.fullmatch(row["word_hex"]) is None:
            raise BindingValidationError("word_hex must contain exactly eight hexadecimal digits")
        word = int(row["word_hex"], 16)
        if word != instruction_words[instruction_index]:
            raise BindingValidationError(
                f"DMA {dma_index} word does not match program instruction {instruction_index}"
            )
        instruction = decoded_program[instruction_index]
        expected_direction = instruction.mnemonic
        expected_flag = instruction.dma_flag or 0
        if (
            row["direction"] != expected_direction
            or obj_id != instruction.obj_id
            or type_or_release != instruction.type_or_release
            or flag != expected_flag
            or instruction.rs1 != 10
            or instruction.rs2 != 11
        ):
            raise BindingValidationError(
                f"DMA {dma_index} metadata does not match its encoded instruction"
            )
        normalized_asm = row["normalized_asm"]
        try:
            asm_instruction = parse_asm_instruction(normalized_asm)
        except ValueError as error:
            raise BindingValidationError(
                f"DMA {dma_index} normalized_asm is invalid: {error}"
            ) from error
        if asm_instruction.word != word:
            raise BindingValidationError(
                f"DMA {dma_index} normalized_asm does not encode to word_hex"
            )
        relocations.append(
            DmaRelocation(
                instruction_index=instruction_index,
                dma_index=dma_index,
                direction=expected_direction,
                obj_id=obj_id,
                type_or_release=type_or_release,
                flag=flag,
                rs1=10,
                rs2=11,
                word=word,
                normalized_asm=normalized_asm,
            )
        )
    return tuple(relocations)


def resolve_dma_bindings(
    relocations: Sequence[DmaRelocation],
    artifacts: Sequence[ArtifactSpan] | Mapping[str, ArtifactSpan],
    assignments: Sequence[DmaArtifactAssignment],
) -> tuple[ResolvedDmaBinding, ...]:
    """Resolve every DMA using only caller-supplied artifact assignments.

    Missing, extra, duplicate, or unknown assignments are rejected.  The
    resolver never infers an artifact from a role, object id, direction, or
    neighboring instruction.
    """

    if isinstance(artifacts, Mapping):
        artifact_by_path = dict(artifacts)
    else:
        artifact_by_path: dict[str, ArtifactSpan] = {}
        for artifact in artifacts:
            path = normalize_manifest_path(artifact.relative_path, "artifact relative_path")
            if path in artifact_by_path:
                raise BindingValidationError(f"duplicate line-map artifact: {path}")
            artifact_by_path[path] = artifact

    relocation_by_index: dict[int, DmaRelocation] = {}
    for expected_index, relocation in enumerate(relocations):
        if relocation.dma_index != expected_index or relocation.dma_index in relocation_by_index:
            raise BindingValidationError("relocations must have unique contiguous DMA indices")
        relocation_by_index[relocation.dma_index] = relocation

    assignment_by_index: dict[int, DmaArtifactAssignment] = {}
    for assignment in assignments:
        if type(assignment.dma_index) is not int or assignment.dma_index < 0:
            raise BindingValidationError("assignment dma_index must be a nonnegative integer")
        if assignment.dma_index in assignment_by_index:
            raise BindingValidationError(
                f"duplicate artifact assignment for DMA {assignment.dma_index}"
            )
        artifact_path = normalize_manifest_path(
            assignment.artifact_path,
            f"DMA {assignment.dma_index} artifact_path",
        )
        if not isinstance(assignment.domain, str) or not assignment.domain.strip():
            raise BindingValidationError(
                f"DMA {assignment.dma_index} domain must be nonempty text"
            )
        if assignment.domain != assignment.domain.strip():
            raise BindingValidationError(
                f"DMA {assignment.dma_index} domain may not have surrounding whitespace"
            )
        assignment_by_index[assignment.dma_index] = DmaArtifactAssignment(
            dma_index=assignment.dma_index,
            artifact_path=artifact_path,
            artifact_line_offset=assignment.artifact_line_offset,
            line_count=assignment.line_count,
            domain=assignment.domain,
        )

    expected_indices = set(relocation_by_index)
    actual_indices = set(assignment_by_index)
    missing = sorted(expected_indices - actual_indices)
    extra = sorted(actual_indices - expected_indices)
    if missing or extra:
        details = []
        if missing:
            details.append("missing DMA indices " + ",".join(map(str, missing)))
        if extra:
            details.append("unknown DMA indices " + ",".join(map(str, extra)))
        raise BindingValidationError("explicit DMA assignments are incomplete: " + "; ".join(details))

    resolved: list[ResolvedDmaBinding] = []
    for dma_index in range(len(relocation_by_index)):
        relocation = relocation_by_index[dma_index]
        assignment = assignment_by_index[dma_index]
        artifact = artifact_by_path.get(assignment.artifact_path)
        if artifact is None:
            raise BindingValidationError(
                f"DMA {dma_index} names an artifact absent from line_map.csv: "
                f"{assignment.artifact_path}"
            )
        if artifact.line_count <= 0 or artifact.payload_words <= 0:
            raise BindingValidationError(
                f"DMA {dma_index} artifact has an invalid line span"
            )
        if artifact.payload_words > artifact.line_count * WORDS_PER_LINE:
            raise BindingValidationError(
                f"DMA {dma_index} artifact payload exceeds its line span"
            )
        if (
            type(assignment.artifact_line_offset) is not int
            or assignment.artifact_line_offset < 0
            or type(assignment.line_count) is not int
            or assignment.line_count <= 0
            or assignment.artifact_line_offset >= artifact.line_count
            or assignment.line_count
            > artifact.line_count - assignment.artifact_line_offset
        ):
            raise BindingValidationError(
                f"DMA {dma_index} assigned subspan is outside its artifact"
            )
        is_mod_ctx_dma = relocation.direction == "dload" and relocation.type_or_release == 2
        is_mod_ctx_assignment = (
            artifact.relative_path == "constants/mod_ctx.u32.bin"
            and assignment.domain == "mod_ctx"
        )
        if relocation.direction == "dload" and relocation.flag != int(is_mod_ctx_dma):
            raise BindingValidationError(
                f"DMA {dma_index} DLOAD type and small-bank flag disagree"
            )
        if is_mod_ctx_dma != is_mod_ctx_assignment:
            raise BindingValidationError(
                f"DMA {dma_index} mod-context instruction and artifact binding disagree"
            )
        if is_mod_ctx_dma:
            if (
                assignment.artifact_line_offset != 0
                or assignment.line_count != artifact.line_count
                or assignment.line_count > SMALL_BANK_LINES
            ):
                raise BindingValidationError(
                    f"DMA {dma_index} must load the complete modulus table within "
                    f"{SMALL_BANK_LINES} small-bank lines"
                )
        elif assignment.line_count > REGULAR_BANK_LINES:
            raise BindingValidationError(
                f"DMA {dma_index} regular-bank span exceeds {REGULAR_BANK_LINES} lines"
            )
        payload_start = assignment.artifact_line_offset * WORDS_PER_LINE
        payload_words = min(
            assignment.line_count * WORDS_PER_LINE,
            max(0, artifact.payload_words - payload_start),
        )
        if payload_words <= 0:
            raise BindingValidationError(
                f"DMA {dma_index} assigned subspan contains no artifact payload"
            )
        resolved.append(
            ResolvedDmaBinding(
                dma_index=dma_index,
                instruction_index=relocation.instruction_index,
                direction=relocation.direction,
                line_offset=artifact.line_offset + assignment.artifact_line_offset,
                line_count=assignment.line_count,
                obj_id=relocation.obj_id,
                type_or_release=relocation.type_or_release,
                flag=relocation.flag,
                payload_words=payload_words,
                artifact_line_offset=assignment.artifact_line_offset,
                domain=assignment.domain,
                role=artifact.role,
                artifact_path=artifact.relative_path,
                binary_path=artifact.binary_path,
                readable_path=artifact.readable_path,
            )
        )
    return tuple(resolved)
