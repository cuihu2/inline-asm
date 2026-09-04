"""Read and validate one delivery produced by the inline-asm main pipeline.

This module consumes an existing ``outputs/<case>`` directory.  It never
regenerates moduli, twiddles, DDR placement, or DMA artifact assignments.
Callers may use :meth:`DeliveryPackage.resolve_dma_bindings` only after they
have supplied an explicit assignment for every relocation.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, replace
import json
from pathlib import Path
import re
import struct
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .bindings import (
    ArtifactSpan,
    BindingValidationError,
    DmaArtifactAssignment,
    DmaRelocation,
    ResolvedDmaBinding,
    load_dma_relocations,
    normalize_manifest_path,
    resolve_dma_bindings,
)
from .isa import decode_instruction, expected_command26, parse_instruction_word
from .validation import (
    BARRETT_MU_BITS,
    LINE_BYTES,
    MAX_MOD_CONTEXTS,
    MIN_PE_MODULUS,
    NTT_REGISTER_COUNT,
    UINT32_MAX,
    WORDS_PER_LINE,
    has_mod_context_capacity,
    is_prime,
    is_valid_ntt_size,
)


__all__ = [
    "DeliveryPackage",
    "DeliveryValidationError",
    "ModContextRecord",
    "TwiddleRecord",
    "load_delivery_package",
]


_LINE_MAP_FIELDS = (
    "path",
    "role",
    "shape",
    "address_byte",
    "line_offset",
    "line_count",
    "payload_words",
    "payload_bytes",
    "padded_words",
    "padded_bytes",
)
_MOD_CONTEXT_FIELDS = (
    "context_index",
    "modulus",
    "modulus_hex",
    "barrett_mu48_hex",
    "record_word_offset",
    "line_offset",
    "line_word_offset",
    "record_words",
)
_TWIDDLE_FIELDS = (
    "direction",
    "basis_index",
    "modulus",
    "phase",
    "stage",
    "value_count",
    "batch_count",
    "twiddles_per_batch",
    "first_value",
    "recurrence_step",
    "path",
    "line_offset",
    "line_count",
)
_HARDWARE_MANIFEST_FIELDS = (
    "path",
    "readable_path",
    "role",
    "shape",
    "payload_words",
    "padded_words",
    "line_offset",
    "line_count",
    "payload_fnv1a64",
    "image_fnv1a64",
)
_UNSIGNED_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_SIGNED_DECIMAL = re.compile(r"(?:0|-?[1-9][0-9]*)\Z")
_HEX = re.compile(r"0x[0-9A-Fa-f]+\Z")
_SAFE_CASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
_COMPARE_CHUNK_BYTES = 1024 * 1024


class DeliveryValidationError(ValueError):
    """A required delivery file or a cross-file invariant is invalid."""


@dataclass(frozen=True, slots=True)
class ModContextRecord:
    context_index: int
    modulus: int
    barrett_mu: int
    record_word_offset: int
    line_offset: int
    line_word_offset: int
    record_words: int


@dataclass(frozen=True, slots=True)
class TwiddleRecord:
    direction: str
    basis_index: int
    modulus: int
    phase: str
    stage: int
    value_count: int
    batch_count: int
    twiddles_per_batch: int
    first_value: int
    recurrence_step: int
    artifact_path: str
    binary_path: Path
    line_offset: int
    line_count: int


@dataclass(frozen=True, slots=True)
class DeliveryPackage:
    """A validated but deliberately unresolved main-pipeline delivery."""

    case_name: str
    case_root: Path
    test_data_root: Path
    hardware_root: Path
    params: Mapping[str, Any]
    abi: Mapping[str, Any]
    hpu_mem_config: Mapping[str, Any]
    hpu_mem_image: Path
    line_bytes: int
    line_count: int
    artifacts: tuple[ArtifactSpan, ...]
    artifact_index: Mapping[str, ArtifactSpan]
    mod_contexts: tuple[ModContextRecord, ...]
    twiddles: tuple[TwiddleRecord, ...]
    instruction_words: tuple[int, ...]
    command_words: tuple[int, ...]
    relocations: tuple[DmaRelocation, ...]

    def artifact(self, relative_path: str) -> ArtifactSpan:
        """Return one artifact by its exact line-map path."""

        try:
            path = normalize_manifest_path(relative_path, "artifact path")
        except BindingValidationError as error:
            raise DeliveryValidationError(str(error)) from error
        artifact = self.artifact_index.get(path)
        if artifact is None:
            raise DeliveryValidationError(f"artifact is absent from line_map.csv: {path}")
        return artifact

    def resolve_dma_bindings(
        self,
        assignments: Sequence[DmaArtifactAssignment],
    ) -> tuple[ResolvedDmaBinding, ...]:
        """Join relocations only through the supplied explicit assignments."""

        try:
            return resolve_dma_bindings(
                self.relocations,
                self.artifact_index,
                assignments,
            )
        except BindingValidationError as error:
            raise DeliveryValidationError(str(error)) from error


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise DeliveryValidationError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise DeliveryValidationError(f"{label} must contain one JSON object")
    return value


def _require_int(
    value: Any,
    field_name: str,
    minimum: int | None = None,
) -> int:
    if type(value) is not int:
        raise DeliveryValidationError(f"{field_name} must be an integer")
    if minimum is not None and value < minimum:
        raise DeliveryValidationError(f"{field_name} must be at least {minimum}")
    return value


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise DeliveryValidationError(f"{field_name} must be nonempty trimmed text")
    return value


def _parse_uint(value: str | None, field_name: str) -> int:
    if value is None or _UNSIGNED_DECIMAL.fullmatch(value) is None:
        raise DeliveryValidationError(f"{field_name} must be an unsigned decimal integer")
    return int(value, 10)


def _parse_int(value: str | None, field_name: str) -> int:
    if value is None or _SIGNED_DECIMAL.fullmatch(value) is None:
        raise DeliveryValidationError(f"{field_name} must be a decimal integer")
    return int(value, 10)


def _parse_hex(value: Any, field_name: str, maximum: int | None = None) -> int:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise DeliveryValidationError(f"{field_name} must be 0x-prefixed hexadecimal text")
    parsed = int(value, 16)
    if maximum is not None and parsed > maximum:
        raise DeliveryValidationError(f"{field_name} exceeds its allowed range")
    return parsed


def _read_csv_exact(
    path: Path,
    fields: tuple[str, ...],
    label: str,
    *,
    allow_empty: bool = False,
) -> tuple[dict[str, str], ...]:
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if tuple(reader.fieldnames or ()) != fields:
                raise DeliveryValidationError(f"{label} has an unexpected CSV header")
            rows: list[dict[str, str]] = []
            for line_number, row in enumerate(reader, 2):
                if None in row or any(value is None for value in row.values()):
                    raise DeliveryValidationError(
                        f"{label} row {line_number} has the wrong column count"
                    )
                rows.append(row)
    except OSError as error:
        raise DeliveryValidationError(f"cannot read {label} {path}: {error}") from error
    if not rows and not allow_empty:
        raise DeliveryValidationError(f"{label} must not be empty")
    return tuple(rows)


def _required_file(path: Path, root: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DeliveryValidationError(f"missing {label}: {path}") from error
    if not resolved.is_file() or not resolved.is_relative_to(root):
        raise DeliveryValidationError(f"{label} must be a file inside {root}")
    return resolved


def _resolve_manifest_file(root: Path, value: str, field_name: str) -> tuple[str, Path]:
    try:
        relative = normalize_manifest_path(value, field_name)
    except BindingValidationError as error:
        raise DeliveryValidationError(str(error)) from error
    return relative, _required_file(root / relative, root, field_name)


def _validate_params_and_abi(
    params: dict[str, Any],
    abi: dict[str, Any],
) -> tuple[int, tuple[int, ...], bool]:
    if params.get("format_version") not in {1, 2}:
        raise DeliveryValidationError("params.json requires format_version 1 or 2")
    if abi.get("format_version") != 1:
        raise DeliveryValidationError("abi.json requires format_version 1")
    n = _require_int(params.get("N"), "params.N", NTT_REGISTER_COUNT)
    if not is_valid_ntt_size(n):
        raise DeliveryValidationError("params.N is outside the frozen NTT object limits")
    if _require_int(abi.get("N"), "abi.N", NTT_REGISTER_COUNT) != n:
        raise DeliveryValidationError("params.N and abi.N disagree")
    modulus_count = _require_int(abi.get("modulus_count"), "abi.modulus_count", 1)
    if not has_mod_context_capacity(modulus_count):
        raise DeliveryValidationError("abi.modulus_count exceeds the MOD_ID capacity")
    if abi.get("coefficient_bits") != 32 or abi.get("byte_order") != "little-endian":
        raise DeliveryValidationError("abi requires little-endian uint32 coefficients")
    if abi.get("line_bytes") != LINE_BYTES or abi.get("line_words") != WORDS_PER_LINE:
        raise DeliveryValidationError("abi requires 64 words per 256-byte line")
    sideband = abi.get("custom1_sideband")
    if not isinstance(sideband, dict):
        raise DeliveryValidationError("abi.custom1_sideband must be an object")
    if (
        sideband.get("rs1_value") != "HPU_MEM line offset"
        or sideband.get("rs2_value") != "line count"
        or sideband.get("unit_bytes") != LINE_BYTES
        or sideband.get("line_count_must_be_nonzero") is not True
    ):
        raise DeliveryValidationError("abi custom1 x10/x11 line sideband is not frozen")
    mod_ctx = abi.get("mod_ctx")
    if not isinstance(mod_ctx, dict):
        raise DeliveryValidationError("abi.mod_ctx must be an object")
    expected_mod_ctx = {
        "record_words": 4,
        "dload_type": 2,
        "dload_flag0_small_bank": 1,
        "small_bank_id": 5,
        "small_bank_lines": 32,
        "contexts_per_line": 16,
        "mod_id_bits": 8,
        "max_contexts": MAX_MOD_CONTEXTS,
        "mu_bits": BARRETT_MU_BITS,
        "reserved_bits": 48,
    }
    for key, expected in expected_mod_ctx.items():
        if mod_ctx.get(key) != expected:
            raise DeliveryValidationError(f"abi.mod_ctx.{key} must equal {expected}")
    if _parse_hex(mod_ctx.get("mod_table_base_line"), "abi.mod_table_base_line") != 0x1400:
        raise DeliveryValidationError("abi mod-table base must be line 0x1400")
    q_min = _require_int(mod_ctx.get("q_min"), "abi.mod_ctx.q_min", 2)
    q_max = _require_int(mod_ctx.get("q_max"), "abi.mod_ctx.q_max", q_min)
    if q_min != MIN_PE_MODULUS or q_max != UINT32_MAX:
        raise DeliveryValidationError("abi.mod_ctx q range disagrees with the frozen PE range")

    if isinstance(params.get("moduli"), list):
        raw_moduli = params["moduli"]
    elif isinstance(params.get("q"), list) and isinstance(params.get("p"), list):
        raw_moduli = list(params["q"]) + list(params["p"])
        if len(raw_moduli) + 1 == modulus_count and "plaintext_modulus" in params:
            raw_moduli.append(params["plaintext_modulus"])
    else:
        raise DeliveryValidationError("params.json must provide moduli or q/p arrays")
    moduli = tuple(
        _require_int(value, f"params modulus {index}", q_min)
        for index, value in enumerate(raw_moduli)
    )
    if len(moduli) != modulus_count:
        raise DeliveryValidationError("params modulus count and abi.modulus_count disagree")
    if (
        len(set(moduli)) != len(moduli)
        or any(value > q_max or not is_prime(value) for value in moduli)
    ):
        raise DeliveryValidationError(
            "params moduli must be distinct prime values in the frozen PE range"
        )
    includes_twiddles = abi.get("twiddle_images_included")
    if type(includes_twiddles) is not bool:
        raise DeliveryValidationError("abi.twiddle_images_included must be boolean")
    if includes_twiddles:
        twiddle = abi.get("twiddle")
        if not isinstance(twiddle, dict):
            raise DeliveryValidationError("abi.twiddle is required when twiddle images are included")
        if (
            twiddle.get("stage_payload_words") != n // 2
            or twiddle.get("stage_payload_lines")
            != (n // 2 + WORDS_PER_LINE - 1) // WORDS_PER_LINE
        ):
            raise DeliveryValidationError("abi twiddle stage geometry does not match N")
    elif "twiddle" in abi:
        raise DeliveryValidationError("abi.twiddle must be absent when twiddle images are omitted")
    return n, moduli, includes_twiddles


def _expected_twiddle_basis_indices(
    params: Mapping[str, Any],
    moduli: tuple[int, ...],
) -> set[int]:
    expected = set(range(len(moduli)))
    if "t_mod_id" not in params:
        return expected

    t_mod_id = _require_int(params["t_mod_id"], "params.t_mod_id", 0)
    if t_mod_id >= len(moduli):
        raise DeliveryValidationError("params.t_mod_id is outside the modulus table")

    if "plaintext_modulus" in params:
        plaintext_modulus = _require_int(
            params["plaintext_modulus"],
            "params.plaintext_modulus",
            MIN_PE_MODULUS,
        )
        if moduli[t_mod_id] != plaintext_modulus:
            raise DeliveryValidationError(
                "params.t_mod_id does not identify params.plaintext_modulus"
            )
    else:
        if (
            params.get("scheme") != "BFV"
            or params.get("context_order") != "Q|Pks|B|m_sk|t"
            or t_mod_id != len(moduli) - 1
        ):
            raise DeliveryValidationError(
                "params.plaintext_modulus may be omitted only for the terminal "
                "BFV Q|Pks|B|m_sk|t context"
            )

    expected.remove(t_mod_id)
    return expected


def _declared_inverse_twiddle_profiles(
    params: Mapping[str, Any],
    test_data_root: Path,
) -> frozenset[str]:
    if params.get("operation") != "auto":
        return frozenset()

    layout_path = test_data_root / "AUTO_LAYOUT.json"
    if not layout_path.exists():
        return frozenset()
    layout_path = _required_file(layout_path, test_data_root, "AUTO_LAYOUT.json")
    layout = _load_json_object(layout_path, "AUTO_LAYOUT.json")
    profile = _require_text(
        layout.get("inverse_twiddle_profile"),
        "AUTO_LAYOUT.inverse_twiddle_profile",
    )
    if _SAFE_CASE.fullmatch(profile) is None or profile in {"ntt", "intt"}:
        raise DeliveryValidationError(
            "AUTO_LAYOUT.inverse_twiddle_profile is not a safe custom profile name"
        )
    return frozenset({profile})


def _validate_hpu_mem_config(config: dict[str, Any]) -> tuple[int, int, int, str]:
    if config.get("format_version") != 1:
        raise DeliveryValidationError("hpu_mem_config.json requires format_version 1")
    if config.get("status") != "HOST_WINDOW_AND_CSR_ABI_READY":
        raise DeliveryValidationError("hpu_mem_config status is not ready")
    try:
        image = normalize_manifest_path(config.get("image"), "hpu_mem_config.image")
    except BindingValidationError as error:
        raise DeliveryValidationError(str(error)) from error
    line_bytes = _require_int(config.get("line_bytes"), "hpu_mem_config.line_bytes", 1)
    words_per_line = _require_int(
        config.get("words_per_line"), "hpu_mem_config.words_per_line", 1
    )
    if line_bytes != LINE_BYTES or words_per_line != WORDS_PER_LINE:
        raise DeliveryValidationError("hpu_mem_config requires 64 words per 256-byte line")
    size_lines = _require_int(config.get("size_lines"), "hpu_mem_config.size_lines", 1)
    size_bytes = _require_int(config.get("size_bytes"), "hpu_mem_config.size_bytes", 1)
    if size_bytes != size_lines * line_bytes:
        raise DeliveryValidationError("hpu_mem_config size_bytes does not match size_lines")
    base = _parse_hex(config.get("base_address"), "hpu_mem_config.base_address", (1 << 40) - 1)
    if _parse_hex(config.get("base_lo"), "hpu_mem_config.base_lo", 0xFFFFFFFF) != (base & 0xFFFFFFFF):
        raise DeliveryValidationError("hpu_mem_config.base_lo does not match base_address")
    if _parse_hex(config.get("base_hi"), "hpu_mem_config.base_hi", 0xFF) != (base >> 32):
        raise DeliveryValidationError("hpu_mem_config.base_hi does not match base_address")
    end = _parse_hex(
        config.get("end_address_exclusive"),
        "hpu_mem_config.end_address_exclusive",
        (1 << 40),
    )
    if end != base + size_bytes:
        raise DeliveryValidationError("hpu_mem_config end address does not match its window")

    expected_csrs = (
        (0x00, "HPU_MEM_BASE_LO"),
        (0x04, "HPU_MEM_BASE_HI"),
        (0x08, "HPU_MEM_SIZE_LINES_LO"),
        (0x0C, "HPU_MEM_SIZE_LINES_HI"),
        (0x10, "HPU_MEM_COMMIT"),
        (0x14, "HPU_STATUS"),
        (0x18, "HPU_FAULT_STATUS"),
    )
    csr_rows = config.get("csr_offsets")
    if not isinstance(csr_rows, list) or len(csr_rows) != len(expected_csrs):
        raise DeliveryValidationError("hpu_mem_config.csr_offsets has the wrong shape")
    for row, (expected_offset, expected_name) in zip(csr_rows, expected_csrs, strict=True):
        if not isinstance(row, dict):
            raise DeliveryValidationError("each CSR description must be an object")
        if (
            _parse_hex(row.get("offset"), f"CSR {expected_name} offset") != expected_offset
            or row.get("name") != expected_name
        ):
            raise DeliveryValidationError(f"CSR map does not match {expected_name}")
    sequence = config.get("programming_sequence")
    if not isinstance(sequence, list) or [row.get("csr") for row in sequence if isinstance(row, dict)] != [
        "HPU_MEM_BASE_LO",
        "HPU_MEM_BASE_HI",
        "HPU_MEM_SIZE_LINES_LO",
        "HPU_MEM_SIZE_LINES_HI",
        "HPU_MEM_COMMIT",
        "HPU_STATUS",
    ]:
        raise DeliveryValidationError("hpu_mem_config programming sequence is incomplete")
    return base, line_bytes, size_lines, image


def _read_line_map(
    path: Path,
    hardware_root: Path,
    base_address: int,
    line_bytes: int,
    size_lines: int,
) -> tuple[ArtifactSpan, ...]:
    rows = _read_csv_exact(path, _LINE_MAP_FIELDS, "line_map.csv")
    artifacts: list[ArtifactSpan] = []
    seen_paths: set[str] = set()
    expected_line_offset = 0
    for row_number, row in enumerate(rows, 1):
        relative_path, binary_path = _resolve_manifest_file(
            hardware_root,
            row["path"],
            f"line_map row {row_number} path",
        )
        if relative_path in seen_paths:
            raise DeliveryValidationError(f"line_map contains duplicate path {relative_path}")
        seen_paths.add(relative_path)
        if not relative_path.endswith(".u32.bin"):
            raise DeliveryValidationError("line_map artifacts must use the .u32.bin suffix")
        role = _require_text(row["role"], f"line_map {relative_path} role")
        shape = _require_text(row["shape"], f"line_map {relative_path} shape")
        address_byte = _parse_hex(row["address_byte"], f"line_map {relative_path} address_byte")
        line_offset = _parse_uint(row["line_offset"], f"line_map {relative_path} line_offset")
        line_count = _parse_uint(row["line_count"], f"line_map {relative_path} line_count")
        payload_words = _parse_uint(row["payload_words"], f"line_map {relative_path} payload_words")
        payload_bytes = _parse_uint(row["payload_bytes"], f"line_map {relative_path} payload_bytes")
        padded_words = _parse_uint(row["padded_words"], f"line_map {relative_path} padded_words")
        padded_bytes = _parse_uint(row["padded_bytes"], f"line_map {relative_path} padded_bytes")
        if line_count == 0 or payload_words == 0:
            raise DeliveryValidationError(f"line_map {relative_path} has an empty span")
        if line_offset != expected_line_offset:
            raise DeliveryValidationError("line_map spans must be ordered, contiguous, and start at zero")
        if address_byte != base_address + line_offset * line_bytes:
            raise DeliveryValidationError(f"line_map {relative_path} address does not match line offset")
        if (
            payload_bytes != payload_words * 4
            or padded_words != line_count * WORDS_PER_LINE
            or padded_bytes != padded_words * 4
            or payload_words > padded_words
        ):
            raise DeliveryValidationError(f"line_map {relative_path} has inconsistent byte geometry")
        if binary_path.stat().st_size != padded_bytes:
            raise DeliveryValidationError(f"line_map {relative_path} file size does not match padded_bytes")
        expected_line_offset += line_count
        artifacts.append(
            ArtifactSpan(
                relative_path=relative_path,
                binary_path=binary_path,
                readable_path=None,
                role=role,
                shape=shape,
                address_byte=address_byte,
                line_offset=line_offset,
                line_count=line_count,
                payload_words=payload_words,
                payload_bytes=payload_bytes,
                padded_words=padded_words,
                padded_bytes=padded_bytes,
            )
        )
    if expected_line_offset != size_lines:
        raise DeliveryValidationError("line_map does not cover the complete HPU_MEM image")
    return tuple(artifacts)


def _attach_readable_paths(
    hardware_root: Path,
    artifacts: tuple[ArtifactSpan, ...],
    image_relative_path: str,
) -> tuple[ArtifactSpan, ...]:
    manifest_path = hardware_root / "hardware_manifest.csv"
    if not manifest_path.exists():
        return artifacts
    manifest_path = _required_file(manifest_path, hardware_root, "hardware_manifest.csv")
    rows = _read_csv_exact(
        manifest_path,
        _HARDWARE_MANIFEST_FIELDS,
        "hardware_manifest.csv",
    )
    artifact_by_path = {artifact.relative_path: artifact for artifact in artifacts}
    seen: set[str] = set()
    readable_by_path: dict[str, Path] = {}
    for row_number, row in enumerate(rows, 1):
        try:
            row_path = normalize_manifest_path(row["path"], f"hardware manifest row {row_number} path")
        except BindingValidationError as error:
            raise DeliveryValidationError(str(error)) from error
        if row_path in seen:
            raise DeliveryValidationError(f"hardware_manifest contains duplicate path {row_path}")
        seen.add(row_path)
        if row_path == image_relative_path:
            if row["readable_path"]:
                raise DeliveryValidationError("complete HPU_MEM image must not claim a readable_path")
            continue
        artifact = artifact_by_path.get(row_path)
        if artifact is None:
            raise DeliveryValidationError(
                f"hardware_manifest path is absent from line_map.csv: {row_path}"
            )
        if (
            row["role"] != artifact.role
            or row["shape"] != artifact.shape
            or _parse_uint(row["payload_words"], f"manifest {row_path} payload_words")
            != artifact.payload_words
            or _parse_uint(row["padded_words"], f"manifest {row_path} padded_words")
            != artifact.padded_words
            or _parse_uint(row["line_offset"], f"manifest {row_path} line_offset")
            != artifact.line_offset
            or _parse_uint(row["line_count"], f"manifest {row_path} line_count")
            != artifact.line_count
        ):
            raise DeliveryValidationError(
                f"hardware_manifest metadata disagrees with line_map for {row_path}"
            )
        readable_value = row["readable_path"]
        if not readable_value.endswith(".dec.txt"):
            raise DeliveryValidationError(
                f"hardware_manifest readable_path must name decimal text for {row_path}"
            )
        _, readable_path = _resolve_manifest_file(
            hardware_root,
            readable_value,
            f"hardware manifest {row_path} readable_path",
        )
        readable_by_path[row_path] = readable_path
    expected_paths = set(artifact_by_path) | {image_relative_path}
    if seen != expected_paths:
        missing = sorted(expected_paths - seen)
        raise DeliveryValidationError(
            "hardware_manifest does not describe every HPU_MEM artifact: " + ", ".join(missing)
        )
    return tuple(
        replace(artifact, readable_path=readable_by_path[artifact.relative_path])
        for artifact in artifacts
    )


def _compare_artifacts_to_image(image: Path, artifacts: Sequence[ArtifactSpan]) -> None:
    try:
        with image.open("rb") as image_stream:
            for artifact in artifacts:
                image_stream.seek(artifact.line_offset * LINE_BYTES)
                with artifact.binary_path.open("rb") as artifact_stream:
                    remaining = artifact.padded_bytes
                    while remaining:
                        count = min(remaining, _COMPARE_CHUNK_BYTES)
                        standalone = artifact_stream.read(count)
                        in_image = image_stream.read(count)
                        if len(standalone) != count or standalone != in_image:
                            raise DeliveryValidationError(
                                f"HPU_MEM image slice disagrees with {artifact.relative_path}"
                            )
                        remaining -= count
    except OSError as error:
        raise DeliveryValidationError(f"cannot compare HPU_MEM artifact images: {error}") from error


def _read_mod_contexts(
    path: Path,
    moduli: tuple[int, ...],
    abi: Mapping[str, Any],
    artifacts: Mapping[str, ArtifactSpan],
    hpu_mem_image: Path,
) -> tuple[ModContextRecord, ...]:
    rows = _read_csv_exact(path, _MOD_CONTEXT_FIELDS, "mod_ctx_map.csv")
    if len(rows) != len(moduli):
        raise DeliveryValidationError("mod_ctx_map row count does not match params moduli")
    mod_artifact = artifacts.get("constants/mod_ctx.u32.bin")
    if mod_artifact is None:
        raise DeliveryValidationError("line_map is missing constants/mod_ctx.u32.bin")
    mod_ctx_abi = abi["mod_ctx"]
    q_min = mod_ctx_abi["q_min"]
    q_max = mod_ctx_abi["q_max"]
    records: list[ModContextRecord] = []
    try:
        with hpu_mem_image.open("rb") as image:
            for expected_index, (row, expected_modulus) in enumerate(
                zip(rows, moduli, strict=True)
            ):
                context_index = _parse_uint(row["context_index"], "mod_ctx context_index")
                modulus = _parse_uint(row["modulus"], "mod_ctx modulus")
                modulus_hex = _parse_hex(row["modulus_hex"], "mod_ctx modulus_hex", 0xFFFFFFFF)
                mu = _parse_hex(
                    row["barrett_mu48_hex"],
                    "mod_ctx barrett_mu48_hex",
                    (1 << BARRETT_MU_BITS) - 1,
                )
                record_word_offset = _parse_uint(row["record_word_offset"], "mod_ctx record_word_offset")
                line_offset = _parse_uint(row["line_offset"], "mod_ctx line_offset")
                line_word_offset = _parse_uint(row["line_word_offset"], "mod_ctx line_word_offset")
                record_words = _parse_uint(row["record_words"], "mod_ctx record_words")
                expected_record_word = expected_index * 4
                if (
                    context_index != expected_index
                    or modulus != expected_modulus
                    or modulus_hex != modulus
                    or not q_min <= modulus <= q_max
                    or mu != (1 << 64) // modulus
                    or record_word_offset != expected_record_word
                    or record_words != 4
                    or line_offset
                    != mod_artifact.line_offset + expected_record_word // WORDS_PER_LINE
                    or line_word_offset != expected_record_word % WORDS_PER_LINE
                ):
                    raise DeliveryValidationError(
                        f"mod_ctx_map row {expected_index} does not match the frozen ABI"
                    )
                image.seek((line_offset * WORDS_PER_LINE + line_word_offset) * 4)
                raw = image.read(16)
                if len(raw) != 16:
                    raise DeliveryValidationError("mod_ctx record exceeds HPU_MEM image")
                q_word, mu_low, mu_high_reserved, reserved = struct.unpack("<IIII", raw)
                actual_mu = mu_low | ((mu_high_reserved & 0xFFFF) << 32)
                if (
                    q_word != modulus
                    or actual_mu != mu
                    or mu_high_reserved >> 16
                    or reserved
                ):
                    raise DeliveryValidationError(
                        f"HPU_MEM mod_ctx record {expected_index} disagrees with mod_ctx_map"
                    )
                records.append(
                    ModContextRecord(
                        context_index=context_index,
                        modulus=modulus,
                        barrett_mu=mu,
                        record_word_offset=record_word_offset,
                        line_offset=line_offset,
                        line_word_offset=line_word_offset,
                        record_words=record_words,
                    )
                )
    except OSError as error:
        raise DeliveryValidationError(f"cannot read mod_ctx records: {error}") from error
    return tuple(records)


def _read_twiddles(
    path: Path,
    n: int,
    moduli: tuple[int, ...],
    expected_basis_indices: set[int],
    artifacts: Mapping[str, ArtifactSpan],
    declared_inverse_profiles: frozenset[str] = frozenset(),
) -> tuple[TwiddleRecord, ...]:
    rows = _read_csv_exact(path, _TWIDDLE_FIELDS, "twiddle_map.csv")
    records: list[TwiddleRecord] = []
    seen: set[tuple[str, int, str, int]] = set()
    seen_artifact_paths: set[str] = set()
    log_n = n.bit_length() - 1
    for row_number, row in enumerate(rows, 1):
        direction = row["direction"]
        phase = row["phase"]
        if direction not in {"ntt", "intt"} | declared_inverse_profiles:
            raise DeliveryValidationError(f"twiddle row {row_number} has an invalid direction")
        basis_index = _parse_uint(row["basis_index"], f"twiddle row {row_number} basis_index")
        if basis_index >= len(moduli):
            raise DeliveryValidationError(f"twiddle row {row_number} basis_index is out of range")
        modulus = _parse_uint(row["modulus"], f"twiddle row {row_number} modulus")
        stage = _parse_int(row["stage"], f"twiddle row {row_number} stage")
        value_count = _parse_uint(row["value_count"], f"twiddle row {row_number} value_count")
        batch_count = _parse_uint(row["batch_count"], f"twiddle row {row_number} batch_count")
        twiddles_per_batch = _parse_uint(
            row["twiddles_per_batch"], f"twiddle row {row_number} twiddles_per_batch"
        )
        first_value = _parse_hex(row["first_value"], f"twiddle row {row_number} first_value", 0xFFFFFFFF)
        recurrence_step = _parse_hex(
            row["recurrence_step"],
            f"twiddle row {row_number} recurrence_step",
            0xFFFFFFFF,
        )
        try:
            artifact_path = normalize_manifest_path(
                row["path"], f"twiddle row {row_number} path"
            )
        except BindingValidationError as error:
            raise DeliveryValidationError(str(error)) from error
        stage_name = f"stage_{stage:02d}" if stage >= 0 else phase
        expected_path = (
            f"constants/twiddle/{direction}/basis_{basis_index:02d}/"
            f"{stage_name}.u32.bin"
        )
        if artifact_path != expected_path:
            raise DeliveryValidationError(
                f"twiddle row {row_number} path does not match its profile and geometry"
            )
        artifact = artifacts.get(artifact_path)
        if artifact is None:
            raise DeliveryValidationError(
                f"twiddle row {row_number} path is absent from line_map.csv"
            )
        line_offset = _parse_uint(row["line_offset"], f"twiddle row {row_number} line_offset")
        line_count = _parse_uint(row["line_count"], f"twiddle row {row_number} line_count")
        if (
            modulus != moduli[basis_index]
            or line_offset != artifact.line_offset
            or line_count != artifact.line_count
            or value_count != artifact.payload_words
        ):
            raise DeliveryValidationError(
                f"twiddle row {row_number} disagrees with mod_ctx or line_map"
            )
        if phase == "butterfly":
            if (
                not 0 <= stage < log_n
                or value_count != n // 2
                or batch_count != n // NTT_REGISTER_COUNT
                or twiddles_per_batch != WORDS_PER_LINE
            ):
                raise DeliveryValidationError(
                    f"twiddle row {row_number} has invalid butterfly geometry"
                )
        elif phase == "pre_twist":
            if direction != "ntt" or stage != -1 or (value_count, batch_count, twiddles_per_batch) != (n, 1, n):
                raise DeliveryValidationError(
                    f"twiddle row {row_number} has invalid pre-twist geometry"
                )
        elif phase == "post_untwist_scale":
            if (
                direction not in {"intt"} | declared_inverse_profiles
                or stage != -1
                or (value_count, batch_count, twiddles_per_batch) != (n, 1, n)
            ):
                raise DeliveryValidationError(
                    f"twiddle row {row_number} has invalid post-factor geometry"
                )
        else:
            raise DeliveryValidationError(f"twiddle row {row_number} has an unknown phase")
        identity = (direction, basis_index, phase, stage)
        if identity in seen:
            raise DeliveryValidationError(f"twiddle_map contains duplicate entry {identity}")
        if artifact_path in seen_artifact_paths:
            raise DeliveryValidationError(
                f"twiddle_map references artifact {artifact_path} more than once"
            )
        seen.add(identity)
        seen_artifact_paths.add(artifact_path)
        records.append(
            TwiddleRecord(
                direction=direction,
                basis_index=basis_index,
                modulus=modulus,
                phase=phase,
                stage=stage,
                value_count=value_count,
                batch_count=batch_count,
                twiddles_per_batch=twiddles_per_batch,
                first_value=first_value,
                recurrence_step=recurrence_step,
                artifact_path=artifact_path,
                binary_path=artifact.binary_path,
                line_offset=line_offset,
                line_count=line_count,
            )
        )
    expected_identities: set[tuple[str, int, str, int]] = set()
    for basis_index in expected_basis_indices:
        expected_identities.add(("ntt", basis_index, "pre_twist", -1))
        expected_identities.add(("intt", basis_index, "post_untwist_scale", -1))
        for stage in range(log_n):
            expected_identities.add(("ntt", basis_index, "butterfly", stage))
            expected_identities.add(("intt", basis_index, "butterfly", stage))
        for profile in declared_inverse_profiles:
            expected_identities.add(
                (profile, basis_index, "post_untwist_scale", -1)
            )
            for stage in range(log_n):
                expected_identities.add((profile, basis_index, "butterfly", stage))
    if seen != expected_identities:
        raise DeliveryValidationError(
            "twiddle_map does not contain the complete per-basis NTT/INTT schedule"
        )
    expected_artifact_paths = {
        artifact_path
        for artifact_path in artifacts
        if artifact_path.startswith("constants/twiddle/")
    }
    if seen_artifact_paths != expected_artifact_paths:
        raise DeliveryValidationError(
            "twiddle_map and line_map disagree on the complete twiddle artifact set"
        )
    return tuple(records)


def _read_program(inst32_path: Path, cmd26_path: Path) -> tuple[tuple[int, ...], tuple[int, ...]]:
    try:
        inst32_lines = inst32_path.read_text(encoding="ascii").splitlines()
        cmd26_lines = cmd26_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise DeliveryValidationError(f"cannot read encoded program: {error}") from error
    words: list[int] = []
    for line_number, line in enumerate(inst32_lines, 1):
        if not line:
            continue
        if line != line.strip():
            raise DeliveryValidationError(f"inst32 line {line_number} has surrounding whitespace")
        try:
            word = parse_instruction_word(line)
            decode_instruction(word)
        except ValueError as error:
            raise DeliveryValidationError(f"inst32 line {line_number}: {error}") from error
        words.append(word)
    if not words:
        raise DeliveryValidationError("inst32 program must not be empty")
    commands: list[int] = []
    for line_number, line in enumerate(cmd26_lines, 1):
        if len(line) != 26 or any(character not in "01" for character in line):
            raise DeliveryValidationError(
                f"cmd26 line {line_number} must contain exactly 26 binary digits"
            )
        commands.append(int(line, 2))
    if len(commands) != len(words):
        raise DeliveryValidationError("cmd26 and inst32 instruction counts differ")
    for index, (command, word) in enumerate(zip(commands, words, strict=True)):
        try:
            expected = expected_command26(word)
        except ValueError as error:
            raise DeliveryValidationError(f"instruction {index}: {error}") from error
        if command != expected:
            raise DeliveryValidationError(f"cmd26 instruction {index} does not match inst32")
    return tuple(words), tuple(commands)


def load_delivery_package(case_directory: str | Path) -> DeliveryPackage:
    """Load one current-main ``outputs/<case>`` package and validate its ABI."""

    try:
        case_root = Path(case_directory).resolve(strict=True)
    except OSError as error:
        raise DeliveryValidationError(f"delivery case directory does not exist: {case_directory}") from error
    if not case_root.is_dir():
        raise DeliveryValidationError("delivery case path must be a directory")
    case_name = case_root.name
    if _SAFE_CASE.fullmatch(case_name) is None:
        raise DeliveryValidationError("delivery case directory has an unsafe name")
    test_data_root = _required_file(
        case_root / "test_data" / "params.json",
        case_root,
        "params.json",
    ).parent
    hardware_root = test_data_root / "hardware"
    try:
        hardware_root = hardware_root.resolve(strict=True)
    except OSError as error:
        raise DeliveryValidationError("missing test_data/hardware directory") from error
    if not hardware_root.is_dir() or not hardware_root.is_relative_to(case_root):
        raise DeliveryValidationError("hardware directory must stay inside the delivery case")

    params_path = _required_file(test_data_root / "params.json", case_root, "params.json")
    abi_path = _required_file(hardware_root / "abi.json", case_root, "abi.json")
    config_path = _required_file(
        hardware_root / "hpu_mem_config.json", case_root, "hpu_mem_config.json"
    )
    line_map_path = _required_file(hardware_root / "line_map.csv", case_root, "line_map.csv")
    mod_ctx_path = _required_file(
        hardware_root / "mod_ctx_map.csv", case_root, "mod_ctx_map.csv"
    )
    inst32_path = _required_file(case_root / f"{case_name}.inst32", case_root, "inst32")
    cmd26_path = _required_file(case_root / f"{case_name}.cmd26", case_root, "cmd26")
    relocation_path = _required_file(
        case_root / "dma_relocation_manifest.csv",
        case_root,
        "dma_relocation_manifest.csv",
    )

    params = _load_json_object(params_path, "params.json")
    abi = _load_json_object(abi_path, "abi.json")
    config = _load_json_object(config_path, "hpu_mem_config.json")
    n, moduli, includes_twiddles = _validate_params_and_abi(params, abi)
    expected_twiddle_basis_indices = _expected_twiddle_basis_indices(params, moduli)
    inverse_twiddle_profiles = _declared_inverse_twiddle_profiles(
        params,
        test_data_root,
    )
    base_address, line_bytes, line_count, image_relative_path = _validate_hpu_mem_config(config)
    if line_bytes != abi["line_bytes"]:
        raise DeliveryValidationError("abi and hpu_mem_config line sizes disagree")
    hpu_mem_image = _resolve_manifest_file(
        hardware_root,
        image_relative_path,
        "hpu_mem_config.image",
    )[1]
    if hpu_mem_image.stat().st_size != line_count * line_bytes:
        raise DeliveryValidationError("HPU_MEM image size does not match hpu_mem_config")

    artifacts = _read_line_map(
        line_map_path,
        hardware_root,
        base_address,
        line_bytes,
        line_count,
    )
    artifacts = _attach_readable_paths(
        hardware_root,
        artifacts,
        image_relative_path,
    )
    artifact_index = {artifact.relative_path: artifact for artifact in artifacts}
    _compare_artifacts_to_image(hpu_mem_image, artifacts)
    mod_contexts = _read_mod_contexts(
        mod_ctx_path,
        moduli,
        abi,
        artifact_index,
        hpu_mem_image,
    )

    twiddle_path = hardware_root / "twiddle_map.csv"
    if includes_twiddles:
        twiddle_path = _required_file(twiddle_path, hardware_root, "twiddle_map.csv")
        twiddles = _read_twiddles(
            twiddle_path,
            n,
            moduli,
            expected_twiddle_basis_indices,
            artifact_index,
            inverse_twiddle_profiles,
        )
    else:
        if twiddle_path.exists():
            raise DeliveryValidationError(
                "twiddle_map.csv is present although abi says twiddle images are omitted"
            )
        twiddles = ()

    instruction_words, command_words = _read_program(inst32_path, cmd26_path)
    try:
        relocations = load_dma_relocations(relocation_path, instruction_words)
    except BindingValidationError as error:
        raise DeliveryValidationError(str(error)) from error

    return DeliveryPackage(
        case_name=case_name,
        case_root=case_root,
        test_data_root=test_data_root,
        hardware_root=hardware_root,
        params=MappingProxyType(params),
        abi=MappingProxyType(abi),
        hpu_mem_config=MappingProxyType(config),
        hpu_mem_image=hpu_mem_image,
        line_bytes=line_bytes,
        line_count=line_count,
        artifacts=artifacts,
        artifact_index=MappingProxyType(artifact_index),
        mod_contexts=mod_contexts,
        twiddles=twiddles,
        instruction_words=instruction_words,
        command_words=command_words,
        relocations=relocations,
    )
