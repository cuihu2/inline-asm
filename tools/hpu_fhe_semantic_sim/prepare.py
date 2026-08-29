"""Prepare deterministic HPU semantic-simulator input packages."""

from __future__ import annotations

from array import array
import csv
from dataclasses import dataclass
import json
import mmap
from pathlib import Path
import random
import struct
from typing import Any, Mapping

from .arithmetic import apply_arithmetic
from .artifacts import read_u32, write_u32
from .isa import decode_instruction, expected_command26, parse_instruction_word
from .ntt import (
    bit_reverse_index,
    find_ntt_prime,
    find_primitive_2n_root,
    generate_hardware_intt_twiddles,
    generate_hardware_ntt_twiddles,
    hardware_ntt_layout,
    logical_negacyclic_ntt,
)
from .validation import (
    BARRETT_MU_BITS,
    LINE_BYTES,
    MIN_PE_MODULUS,
    UINT32_MAX,
    WORDS_PER_LINE,
    has_mod_context_capacity,
    is_valid_ntt_size,
    parse_shape,
    require_fields,
    require_int,
    require_mapping,
    require_safe_name,
    require_text,
    shape_words,
)


__all__ = ["prepare_case"]

_POISON_WORD = 0xA5A5A5A5


@dataclass(slots=True)
class _Artifact:
    token: str
    relative_path: Path | None
    role: str
    source: str
    domain: str
    shape: tuple[int, ...]
    modulus_index: int | None
    payload_words: int
    values: array[int] | None
    line_offset: int | None = None
    line_count: int | None = None

    @property
    def is_output(self) -> bool:
        return self.relative_path is None


def _resolve_source_path(base_dir: Path, value: Any, name: str) -> Path:
    text = require_text(value, name)
    path = Path(text)
    if not path.is_absolute():
        path = base_dir / path
    if not path.is_file():
        raise ValueError(f"{name} does not name an existing file: {path}")
    return path


def _array_u32(values: Any) -> array[int]:
    result = array("I")
    for index, value in enumerate(values):
        if type(value) is not int or not 0 <= value <= UINT32_MAX:
            raise ValueError(f"artifact word {index} must fit uint32")
        result.append(value)
    return result


def _read_program(path: Path) -> tuple[bytes, list[int]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"inst32 program must be ASCII text: {path}") from error
    words: list[int] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        token = raw_line.strip()
        if not token:
            continue
        try:
            word = parse_instruction_word(token)
            decode_instruction(word)
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
        words.append(word)
    if not words:
        raise ValueError("inst32 program must contain at least one instruction")
    return raw, words


def _read_cmd26(path: Path, expected: list[int]) -> bytes:
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"cmd26 program must be ASCII text: {path}") from error
    commands: list[int] = []
    line_numbers: list[int] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        token = raw_line.strip()
        if not token:
            continue
        if len(token) != 26 or any(character not in "01" for character in token):
            raise ValueError(f"{path}:{line_number}: cmd26 must contain 26 binary digits")
        commands.append(int(token, 2))
        line_numbers.append(line_number)
    if len(commands) != len(expected):
        raise ValueError(
            f"cmd26 instruction count {len(commands)} does not match inst32 count {len(expected)}"
        )
    for index, (actual, expected_command) in enumerate(
        zip(commands, expected, strict=True)
    ):
        if actual != expected_command:
            raise ValueError(
                f"{path}:{line_numbers[index]}: cmd26 0x{actual:07X} "
                f"does not match expected 0x{expected_command:07X}"
            )
    return raw


def _generate_moduli(config: Mapping[str, Any], n: int) -> list[dict[str, int]]:
    require_fields(config, "moduli", {"source", "count"}, {"start"})
    if config["source"] != "generated":
        raise ValueError("moduli.source must be generated")
    count = require_int(config["count"], "moduli.count", 1)
    if not has_mod_context_capacity(count):
        raise ValueError("moduli.count exceeds the 8-bit MOD_ID space")
    start = require_int(config.get("start", MIN_PE_MODULUS), "moduli.start", 2)
    start = max(start, MIN_PE_MODULUS)
    values: list[dict[str, int]] = []
    next_start = start
    for index in range(count):
        q = find_ntt_prime(next_start, 2 * n)
        if q > UINT32_MAX:
            raise ValueError("generated modulus exceeds the 32-bit PE range")
        psi = find_primitive_2n_root(q, n)
        mu = (1 << 64) // q
        if mu >= 1 << BARRETT_MU_BITS:
            raise ValueError("generated Barrett reciprocal exceeds 48 bits")
        values.append(
            {
                "index": index,
                "q": q,
                "psi": psi,
                "omega": psi * psi % q,
                "mu": mu,
            }
        )
        next_start = q + 1
    return values


def _generate_input_words(word_count: int, q: int, rng: random.Random) -> array[int]:
    result = array("I")
    for boundary in (0, 1, q - 1):
        if len(result) == word_count:
            return result
        result.append(boundary)
    while len(result) < word_count:
        result.append(rng.randrange(q))
    return result


def _mod_context_words(moduli: list[dict[str, int]]) -> array[int]:
    values = array("I")
    for modulus in moduli:
        mu = modulus["mu"]
        values.extend(
            (
                modulus["q"],
                mu & UINT32_MAX,
                (mu >> 32) & 0xFFFF,
                0,
            )
        )
    return values


def _constant_artifacts(
    n: int,
    moduli: list[dict[str, int]],
) -> list[_Artifact]:
    artifacts = [
        _Artifact(
            token="mod_contexts",
            relative_path=Path("constants/mod_contexts.u32.bin"),
            role="mod_contexts",
            source="generated",
            domain="mod_ctx",
            shape=(len(moduli), 4),
            modulus_index=None,
            payload_words=4 * len(moduli),
            values=_mod_context_words(moduli),
        )
    ]
    for modulus in moduli:
        basis_index = modulus["index"]
        q = modulus["q"]
        psi = modulus["psi"]
        omega = modulus["omega"]
        if basis_index == 0:
            prefix = Path("constants")
            token_prefix = ""
        else:
            prefix = Path("constants") / f"basis_{basis_index:02d}"
            token_prefix = f"basis_{basis_index}:"

        pre_twist = _array_u32(
            pow(psi, bit_reverse_index(position, n), q) for position in range(n)
        )
        artifacts.append(
            _Artifact(
                token=token_prefix + "ntt_pre_twist",
                relative_path=prefix / "ntt_pre_twist.u32.bin",
                role="ntt_pre_twist",
                source="generated",
                domain="coefficient_bitrev",
                shape=(n,),
                modulus_index=basis_index,
                payload_words=n,
                values=pre_twist,
            )
        )

        for stage, stage_values in enumerate(
            generate_hardware_ntt_twiddles(n, omega, q)
        ):
            artifacts.append(
                _Artifact(
                    token=token_prefix + f"ntt_stage_{stage}",
                    relative_path=prefix / f"ntt_stage_{stage}.u32.bin",
                    role=f"ntt_stage_{stage}",
                    source="generated",
                    domain="twiddle",
                    shape=(n // 2,),
                    modulus_index=basis_index,
                    payload_words=n // 2,
                    values=_array_u32(stage_values),
                )
            )

        for stage, stage_values in enumerate(
            generate_hardware_intt_twiddles(n, omega, q)
        ):
            artifacts.append(
                _Artifact(
                    token=token_prefix + f"intt_stage_{stage}",
                    relative_path=prefix / f"intt_stage_{stage}.u32.bin",
                    role=f"intt_stage_{stage}",
                    source="generated",
                    domain="twiddle",
                    shape=(n // 2,),
                    modulus_index=basis_index,
                    payload_words=n // 2,
                    values=_array_u32(stage_values),
                )
            )

        n_inverse = pow(n, -1, q)
        psi_inverse = pow(psi, -1, q)
        post_factor = _array_u32(
            n_inverse
            * pow(psi_inverse, bit_reverse_index(position, n), q)
            % q
            for position in range(n)
        )
        artifacts.append(
            _Artifact(
                token=token_prefix + "intt_post_factor",
                relative_path=prefix / "intt_post_factor.u32.bin",
                role="intt_post_factor",
                source="generated",
                domain="pintt_complete",
                shape=(n,),
                modulus_index=basis_index,
                payload_words=n,
                values=post_factor,
            )
        )
    return artifacts


def _input_artifacts(
    raw_inputs: Any,
    moduli: list[dict[str, int]],
    rng: random.Random,
    case_dir: Path,
    operation: str,
    n: int,
) -> tuple[list[_Artifact], list[_Artifact], list[dict[str, Any]]]:
    if not isinstance(raw_inputs, list) or not raw_inputs:
        raise ValueError("inputs must be a nonempty list")
    artifacts: list[_Artifact] = []
    oracle_artifacts: list[_Artifact] = []
    resolved_inputs: list[dict[str, Any]] = []
    names: set[str] = set()
    for input_index, raw_value in enumerate(raw_inputs):
        value = require_mapping(raw_value, f"inputs[{input_index}]")
        require_fields(
            value,
            f"inputs[{input_index}]",
            {"name", "source", "shape", "domain", "modulus_index"},
            {"path"},
        )
        name = require_safe_name(value["name"], f"inputs[{input_index}].name")
        if name in names:
            raise ValueError(f"duplicate input name: {name}")
        names.add(name)
        if name in {
            "mod_contexts",
            "ntt_pre_twist",
            "intt_post_factor",
        } or name.startswith(("ntt_stage_", "intt_stage_", "output:")):
            raise ValueError(f"input name collides with a reserved artifact: {name}")
        source = require_text(value["source"], f"inputs[{input_index}].source")
        shape = parse_shape(value["shape"], f"inputs[{input_index}].shape")
        domain = require_text(value["domain"], f"inputs[{input_index}].domain")
        modulus_index = require_int(
            value["modulus_index"],
            f"inputs[{input_index}].modulus_index",
            0,
        )
        if modulus_index >= len(moduli):
            raise ValueError("input modulus_index is outside generated moduli")
        payload_words = shape_words(shape)
        if source == "generated":
            if "path" in value:
                raise ValueError("generated input must not provide path")
            input_values = _generate_input_words(
                payload_words,
                moduli[modulus_index]["q"],
                rng,
            )
        elif source == "file":
            if "path" not in value:
                raise ValueError("file input requires path")
            source_path = _resolve_source_path(
                case_dir,
                value["path"],
                f"inputs[{input_index}].path",
            )
            input_values = read_u32(source_path)
            if len(input_values) != payload_words:
                raise ValueError(
                    f"file input {name} has {len(input_values)} words, expected {payload_words}"
                )
            q = moduli[modulus_index]["q"]
            for word_index, input_word in enumerate(input_values):
                if input_word >= q:
                    raise ValueError(
                        f"file input {name} word {word_index} is outside [0,q)"
                    )
        else:
            raise ValueError("input source must be generated or file")
        relative_path = Path("inputs") / f"{name}.u32.bin"
        if operation in {"ntt", "intt"}:
            if payload_words != n:
                raise ValueError(f"operation {operation} requires an N-word input")
            logical_path = Path("inputs") / f"{name}.logical.u32.bin"
            logical_artifact = _Artifact(
                token=f"logical_input:{name}",
                relative_path=logical_path,
                role=f"logical_input:{name}",
                source=source,
                domain=domain,
                shape=shape,
                modulus_index=modulus_index,
                payload_words=payload_words,
                values=input_values,
            )
            if operation == "ntt":
                physical_values = _array_u32(
                    input_values[bit_reverse_index(position, n)]
                    for position in range(n)
                )
                physical_domain = "coefficient_bitrev"
            else:
                layout = hardware_ntt_layout(n)
                physical_values = _array_u32(
                    input_values[layout[position]] for position in range(n)
                )
                physical_domain = "ntt_physical"
            oracle_artifacts.append(logical_artifact)
            artifacts.append(logical_artifact)
        else:
            logical_path = relative_path
            physical_values = input_values
            physical_domain = domain
        artifact = _Artifact(
            token=name,
            relative_path=relative_path,
            role=f"input:{name}",
            source=source,
            domain=physical_domain,
            shape=shape,
            modulus_index=modulus_index,
            payload_words=payload_words,
            values=physical_values,
        )
        artifacts.append(artifact)
        if operation not in {"ntt", "intt"}:
            oracle_artifacts.append(artifact)
        resolved_inputs.append(
            {
                "name": name,
                "source": source,
                "path": relative_path.as_posix(),
                "physical_path": relative_path.as_posix(),
                "logical_path": logical_path.as_posix(),
                "shape": list(shape),
                "domain": domain,
                "physical_domain": physical_domain,
                "modulus_index": modulus_index,
                "payload_words": payload_words,
            }
        )
    return artifacts, oracle_artifacts, resolved_inputs


def _resolve_bindings(
    raw_bindings: Any,
    instructions: list[Any],
    artifacts: list[_Artifact],
    n: int,
) -> tuple[list[dict[str, Any]], list[_Artifact]]:
    if not isinstance(raw_bindings, list):
        raise ValueError("dma_bindings must be a list")
    dma_indices = [
        index
        for index, instruction in enumerate(instructions)
        if instruction.mnemonic in {"dload", "dstore"}
    ]
    if len(raw_bindings) != len(dma_indices):
        raise ValueError("dma_bindings must cover every custom1 instruction")
    artifact_by_token = {artifact.token: artifact for artifact in artifacts}
    resolved: list[dict[str, Any]] = []
    allocated: list[_Artifact] = []
    next_line = 0

    for dma_index, (raw_value, expected_instruction_index) in enumerate(
        zip(raw_bindings, dma_indices, strict=True)
    ):
        value = require_mapping(raw_value, f"dma_bindings[{dma_index}]")
        require_fields(
            value,
            f"dma_bindings[{dma_index}]",
            {
                "instruction_index",
                "direction",
                "obj_id",
                "type_or_release",
                "flag",
                "artifact",
            },
            {"payload_words"},
        )
        instruction_index = require_int(
            value["instruction_index"],
            f"dma_bindings[{dma_index}].instruction_index",
            0,
        )
        if instruction_index != expected_instruction_index:
            raise ValueError("dma_bindings must follow custom1 program order")
        instruction = instructions[instruction_index]
        direction = require_text(
            value["direction"], f"dma_bindings[{dma_index}].direction"
        )
        obj_id = require_int(value["obj_id"], f"dma_bindings[{dma_index}].obj_id")
        type_or_release = require_int(
            value["type_or_release"],
            f"dma_bindings[{dma_index}].type_or_release",
        )
        flag = require_int(value["flag"], f"dma_bindings[{dma_index}].flag")
        if (
            direction != instruction.mnemonic
            or obj_id != instruction.obj_id
            or type_or_release != instruction.type_or_release
            or flag != instruction.dma_flag
        ):
            raise ValueError(
                f"dma_bindings[{dma_index}] does not match instruction {instruction_index}"
            )
        token = require_text(
            value["artifact"], f"dma_bindings[{dma_index}].artifact"
        )
        if direction == "dload":
            if token not in artifact_by_token:
                raise ValueError(f"unknown DLOAD artifact: {token}")
            artifact = artifact_by_token[token]
            payload_words = artifact.payload_words
            if "payload_words" in value and require_int(
                value["payload_words"],
                f"dma_bindings[{dma_index}].payload_words",
                1,
            ) != payload_words:
                raise ValueError("DLOAD payload_words must equal the artifact size")
        else:
            if not token.startswith("output:"):
                raise ValueError("DSTORE artifact must use output:name")
            output_name = require_safe_name(
                token.removeprefix("output:"),
                f"dma_bindings[{dma_index}].artifact output name",
            )
            token = "output:" + output_name
            payload_words = require_int(
                value.get("payload_words", n),
                f"dma_bindings[{dma_index}].payload_words",
                1,
            )
            artifact = artifact_by_token.get(token)
            if artifact is None:
                artifact = _Artifact(
                    token=token,
                    relative_path=None,
                    role=token,
                    source="poison",
                    domain="raw",
                    shape=(payload_words,),
                    modulus_index=None,
                    payload_words=payload_words,
                    values=None,
                )
                artifact_by_token[token] = artifact
                artifacts.append(artifact)
            elif artifact.payload_words != payload_words:
                raise ValueError("reused output artifact has inconsistent payload_words")

        if artifact.line_offset is None:
            artifact.line_offset = next_line
            artifact.line_count = (
                artifact.payload_words + WORDS_PER_LINE - 1
            ) // WORDS_PER_LINE
            next_line += artifact.line_count
            allocated.append(artifact)
        resolved.append(
            {
                "dma_index": dma_index,
                "instruction_index": instruction_index,
                "direction": direction,
                "line_offset": artifact.line_offset,
                "line_count": artifact.line_count,
                "obj_id": obj_id,
                "type_or_release": type_or_release,
                "flag": flag,
                "payload_words": payload_words,
                "domain": artifact.domain,
                "role": artifact.role,
                "artifact_path": (
                    artifact.relative_path.as_posix()
                    if artifact.relative_path is not None
                    else None
                ),
                "expected_artifact": None,
            }
        )
    return resolved, allocated


def _build_oracle(
    operation: str,
    input_artifacts: list[_Artifact],
    moduli: list[dict[str, int]],
    resolved_bindings: list[dict[str, Any]],
    artifacts: list[_Artifact],
) -> dict[str, Any]:
    supported = {"padd", "psub", "pmul", "pmac", "ntt", "intt"}
    if operation not in supported:
        raise ValueError(
            "operation requires an external oracle; supported generated oracles are "
            + ", ".join(sorted(supported))
        )
    required_inputs = 3 if operation == "pmac" else 1 if operation in {"ntt", "intt"} else 2
    if len(input_artifacts) != required_inputs:
        raise ValueError(f"operation {operation} requires {required_inputs} inputs")
    modulus_indices = {artifact.modulus_index for artifact in input_artifacts}
    if len(modulus_indices) != 1 or None in modulus_indices:
        raise ValueError("oracle inputs must use one common modulus_index")
    modulus_index = next(iter(modulus_indices))
    if modulus_index is None:
        raise ValueError("oracle modulus_index is unresolved")
    modulus = moduli[modulus_index]
    q = modulus["q"]
    values = [artifact.values for artifact in input_artifacts]
    if any(item is None for item in values):
        raise ValueError("oracle input artifact has no payload")
    input_values = [item for item in values if item is not None]

    if operation == "pmac":
        expected = apply_arithmetic(
            operation,
            input_values[0],
            input_values[1],
            input_values[2],
            q,
        )
        final_domain = input_artifacts[0].domain
    elif operation in {"padd", "psub", "pmul"}:
        expected = apply_arithmetic(
            operation,
            None,
            input_values[0],
            input_values[1],
            q,
        )
        final_domain = input_artifacts[0].domain
    else:
        expected = _array_u32(
            logical_negacyclic_ntt(
                input_values[0],
                modulus["psi"],
                q,
                inverse=operation == "intt",
            )
        )
        final_domain = "ntt_physical" if operation == "ntt" else "pintt_complete"

    dstore_bindings = [
        binding for binding in resolved_bindings if binding["direction"] == "dstore"
    ]
    if not dstore_bindings:
        raise ValueError("generated oracle requires a DSTORE output binding")
    final_binding = dstore_bindings[-1]
    if final_binding["payload_words"] != len(expected):
        raise ValueError(
            "final DSTORE payload_words does not match generated oracle result"
        )
    output_token = final_binding["role"]
    if not output_token.startswith("output:"):
        raise ValueError("final DSTORE role does not identify output:name")
    output_name = require_safe_name(
        output_token.removeprefix("output:"),
        "final output name",
    )
    expected_path = Path("expected") / f"{output_name}.u32.bin"
    final_binding["expected_artifact"] = expected_path.as_posix()
    final_binding["domain"] = final_domain
    for artifact in artifacts:
        if artifact.token == output_token:
            artifact.domain = final_domain
            break
    artifacts.append(
        _Artifact(
            token=f"expected:{output_name}",
            relative_path=expected_path,
            role=f"expected:{operation}",
            source="oracle",
            domain=final_domain,
            shape=(len(expected),),
            modulus_index=modulus_index,
            payload_words=len(expected),
            values=_array_u32(expected),
        )
    )
    oracle: dict[str, Any] = {
        "operation": operation,
        "inputs": [
            artifact.relative_path.as_posix()
            for artifact in input_artifacts
            if artifact.relative_path is not None
        ],
        "modulus": q,
        "expected_artifact": expected_path.as_posix(),
        "final_domain": final_domain,
    }
    if operation in {"ntt", "intt"}:
        oracle["psi"] = modulus["psi"]
    return oracle


def _write_bytes_exclusive(path: Path, content: bytes) -> None:
    with path.open("xb") as output:
        output.write(content)


def _write_text_exclusive(path: Path, content: str) -> None:
    with path.open("x", encoding="utf-8", newline="") as output:
        output.write(content)


def _write_ddr(
    path: Path,
    line_count: int,
    allocated: list[_Artifact],
    output_root: Path,
) -> None:
    total_bytes = line_count * LINE_BYTES
    with path.open("x+b") as output:
        output.truncate(total_bytes)
        if total_bytes == 0:
            return
        with mmap.mmap(output.fileno(), total_bytes, access=mmap.ACCESS_WRITE) as image:
            for artifact in allocated:
                if artifact.line_offset is None or artifact.line_count is None:
                    raise RuntimeError(f"artifact has no allocated DDR span: {artifact.token}")
                start = artifact.line_offset * LINE_BYTES
                span_bytes = artifact.line_count * LINE_BYTES
                if artifact.is_output:
                    poison = struct.pack("<I", _POISON_WORD) * (
                        artifact.line_count * WORDS_PER_LINE
                    )
                    image[start : start + span_bytes] = poison
                    continue
                if artifact.relative_path is None:
                    raise RuntimeError(f"input artifact has no file path: {artifact.token}")
                raw = (output_root / artifact.relative_path).read_bytes()
                if len(raw) != artifact.payload_words * 4 or len(raw) > span_bytes:
                    raise ValueError(f"artifact size mismatch: {artifact.token}")
                image[start : start + len(raw)] = raw
            image.flush()


def _write_manifest(path: Path, artifacts: list[_Artifact]) -> None:
    fields = (
        "artifact",
        "role",
        "path",
        "source",
        "domain",
        "shape",
        "modulus_index",
        "payload_words",
        "line_offset",
        "line_count",
    )
    with path.open("x", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for artifact in artifacts:
            writer.writerow(
                {
                    "artifact": artifact.token,
                    "role": artifact.role,
                    "path": (
                        artifact.relative_path.as_posix()
                        if artifact.relative_path is not None
                        else ""
                    ),
                    "source": artifact.source,
                    "domain": artifact.domain,
                    "shape": "x".join(str(item) for item in artifact.shape),
                    "modulus_index": (
                        artifact.modulus_index
                        if artifact.modulus_index is not None
                        else ""
                    ),
                    "payload_words": artifact.payload_words,
                    "line_offset": (
                        artifact.line_offset if artifact.line_offset is not None else ""
                    ),
                    "line_count": (
                        artifact.line_count if artifact.line_count is not None else ""
                    ),
                }
            )


def prepare_case(case_path: str | Path, output_dir: str | Path) -> Path:
    """Validate one case and create a new deterministic simulator input package."""
    source_case_path = Path(case_path)
    output_root = Path(output_dir)
    if output_root.exists():
        raise FileExistsError(f"prepare output already exists: {output_root}")
    try:
        raw_case = json.loads(source_case_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read case JSON {source_case_path}: {error}") from error
    case = require_mapping(raw_case, "case")
    require_fields(
        case,
        "case",
        {
            "schema_version",
            "case_name",
            "operation",
            "N",
            "seed",
            "program",
            "memory",
            "moduli",
            "inputs",
            "dma_bindings",
            "checkpoint_policy",
        },
    )
    if type(case["schema_version"]) is not int or case["schema_version"] != 1:
        raise ValueError("schema_version must be 1")
    case_name = require_text(case["case_name"], "case_name")
    operation = require_text(case["operation"], "operation").lower()
    n = require_int(case["N"], "N")
    if not is_valid_ntt_size(n):
        raise ValueError(
            "N must be a supported power of two in the range 128..65536"
        )
    seed = require_int(case["seed"], "seed")
    checkpoint_policy = require_text(
        case["checkpoint_policy"], "checkpoint_policy"
    )

    program = require_mapping(case["program"], "program")
    require_fields(program, "program", {"inst32"}, {"cmd26"})
    inst32_source = _resolve_source_path(
        source_case_path.parent, program["inst32"], "program.inst32"
    )
    inst32_content, instruction_words = _read_program(inst32_source)
    instructions = [decode_instruction(word) for word in instruction_words]
    expected_commands = [expected_command26(word) for word in instruction_words]
    generated_cmd26 = "".join(
        f"{command:026b}\n" for command in expected_commands
    ).encode("ascii")
    if "cmd26" in program:
        cmd26_source = _resolve_source_path(
            source_case_path.parent,
            program["cmd26"],
            "program.cmd26",
        )
        cmd26_content = _read_cmd26(cmd26_source, expected_commands)
    else:
        cmd26_content = generated_cmd26

    memory = require_mapping(case["memory"], "memory")
    require_fields(memory, "memory", {"line_bytes", "line_count"})
    if type(memory["line_bytes"]) is not int or memory["line_bytes"] != LINE_BYTES:
        raise ValueError("memory.line_bytes must be 256")

    moduli = _generate_moduli(require_mapping(case["moduli"], "moduli"), n)
    rng = random.Random(seed)
    input_artifacts, oracle_input_artifacts, resolved_inputs = _input_artifacts(
        case["inputs"],
        moduli,
        rng,
        source_case_path.parent,
        operation,
        n,
    )
    artifacts = input_artifacts + _constant_artifacts(n, moduli)
    resolved_bindings, allocated = _resolve_bindings(
        case["dma_bindings"], instructions, artifacts, n
    )
    oracle = _build_oracle(
        operation,
        oracle_input_artifacts,
        moduli,
        resolved_bindings,
        artifacts,
    )
    required_lines = sum(artifact.line_count or 0 for artifact in allocated)
    raw_line_count = memory["line_count"]
    if raw_line_count == "auto":
        line_count = required_lines
    else:
        line_count = require_int(raw_line_count, "memory.line_count", 1)
        if line_count < required_lines:
            raise ValueError(
                f"memory.line_count {line_count} is smaller than required {required_lines}"
            )

    output_root.mkdir(parents=True, exist_ok=False)
    (output_root / "inputs").mkdir()
    (output_root / "constants").mkdir()
    _write_bytes_exclusive(output_root / "program.inst32", inst32_content)
    _write_bytes_exclusive(output_root / "program.cmd26", cmd26_content)
    for artifact in artifacts:
        if artifact.relative_path is None:
            continue
        destination = output_root / artifact.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        if artifact.values is None:
            raise RuntimeError(f"artifact has no payload: {artifact.token}")
        write_u32(destination, artifact.values)

    _write_ddr(output_root / "ddr_before.u32.bin", line_count, allocated, output_root)
    bindings_document = {"format_version": 1, "bindings": resolved_bindings}
    _write_text_exclusive(
        output_root / "semantic_bindings.json",
        json.dumps(bindings_document, indent=2) + "\n",
    )
    _write_manifest(output_root / "input_manifest.csv", artifacts)

    resolved_case = {
        "schema_version": 1,
        "case_name": case_name,
        "operation": operation,
        "N": n,
        "seed": seed,
        "model": "SEMANTIC_MODEL",
        "arithmetic": "EXACT_MOD_Q",
        "timing": "SEQUENTIAL_ARCHITECTURAL",
        "program": {"inst32": "program.inst32", "cmd26": "program.cmd26"},
        "memory": {
            "line_bytes": LINE_BYTES,
            "line_count": line_count,
            "image": "ddr_before.u32.bin",
            "ddr_before": "ddr_before.u32.bin",
        },
        "moduli": {
            "source": "generated",
            "count": len(moduli),
            "values": moduli,
        },
        "inputs": resolved_inputs,
        "dma_bindings": resolved_bindings,
        "bindings": "semantic_bindings.json",
        "semantic_bindings": "semantic_bindings.json",
        "input_manifest": "input_manifest.csv",
        "oracle": oracle,
        "checkpoint_policy": checkpoint_policy,
    }
    resolved_path = output_root / "case_resolved.json"
    _write_text_exclusive(
        resolved_path,
        json.dumps(resolved_case, indent=2) + "\n",
    )
    return resolved_path
