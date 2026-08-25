"""Resolved-case execution and dual physical/logical result generation."""

from __future__ import annotations

from array import array
import csv
import json
from pathlib import Path
import sys
from typing import Any

from .arithmetic import apply_arithmetic
from .artifacts import (
    ArtifactBinding,
    ArtifactWorkspace,
    diff_files,
    load_bindings_json,
    preview_hex,
    read_u32,
    write_u32,
)
from .isa import (
    decode_instruction,
    expected_command26,
    parse_asm_instruction,
    parse_instruction_word,
)
from .machine import MachineState, SimulationError, execute_step
from .ntt import (
    bit_reverse_index,
    generate_hardware_intt_twiddles,
    generate_hardware_ntt_twiddles,
    hardware_ntt_layout,
    logical_negacyclic_ntt,
    p_inverse_permute,
    p_permute,
    pintt_stage,
    pntt_stage,
)


def _load_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _resolve(base: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def _load_program(path: Path) -> list[Any]:
    instructions: list[Any] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        try:
            instructions.append(decode_instruction(parse_instruction_word(text)))
        except ValueError as error:
            raise ValueError(f"{path}:{line_number}: {error}") from error
    if not instructions:
        raise ValueError("program contains no instructions")
    return instructions


def _load_command26(path: Path) -> list[int]:
    commands: list[int] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith("#"):
            continue
        if len(text) == 26 and set(text) <= {"0", "1"}:
            commands.append(int(text, 2))
        elif text.lower().startswith("0x") and 1 <= len(text[2:]) <= 7:
            commands.append(int(text, 16))
        else:
            raise ValueError(f"{path}:{line_number}: invalid 26-bit command")
    return commands


def _write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def _write_trace(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _logical_mapping(word_count: int, domain: str) -> list[int]:
    if domain == "ntt_physical":
        return hardware_ntt_layout(word_count)
    if domain in {"coefficient_bitrev", "pintt_complete"}:
        return [bit_reverse_index(position, word_count) for position in range(word_count)]
    return list(range(word_count))


def _physical_to_logical(physical: array, domain: str) -> tuple[array, list[int]]:
    mapping = _logical_mapping(len(physical), domain)
    logical = array("I", [0] * len(physical))
    for physical_index, logical_index in enumerate(mapping):
        logical[logical_index] = physical[physical_index]
    return logical, mapping


def _stage_batches(n: int, forward_stage: int) -> list[list[int]]:
    m = 1 << forward_stage
    if m < 128:
        return [list(range(base, base + 128)) for base in range(0, n, 128)]
    batches: list[list[int]] = []
    for group in range(0, n, 2 * m):
        for offset in range(0, m, 64):
            positions: list[int] = []
            for lane in range(64):
                positions.extend((group + offset + lane, group + m + offset + lane))
            batches.append(positions)
    return batches


def _advance_stage_labels_and_locate(
    labels: list[int],
    n: int,
    forward_stage: int,
    direction: str,
    mismatch_physical: int | None,
) -> tuple[list[int], dict[str, Any] | None]:
    updated = list(labels)
    diagnostic = None
    for batch_index, positions in enumerate(_stage_batches(n, forward_stage)):
        loaded = [labels[position] for position in positions]
        if direction == "pntt":
            stored = p_permute(loaded)
        else:
            stored = p_inverse_permute(loaded)
        for local_index, position in enumerate(positions):
            updated[position] = stored[local_index]
        if mismatch_physical is None or mismatch_physical not in positions:
            continue
        output_register = positions.index(mismatch_physical)
        if direction == "pntt":
            butterfly_register = ((output_register << 1) & 0x7F) | (output_register >> 6)
            pair_labels = loaded
        else:
            butterfly_register = output_register
            pair_labels = stored
        lane_index = butterfly_register // 2
        pair_begin = 2 * lane_index
        diagnostic = {
            "batch_index": batch_index,
            "lane_index": lane_index,
            "logical_pair": [pair_labels[pair_begin], pair_labels[pair_begin + 1]],
            "logical_index": pair_labels[pair_begin],
        }
    return updated, diagnostic


def _first_array_mismatch(actual: Any, expected: Any) -> int | None:
    for index, (actual_word, expected_word) in enumerate(
        zip(actual, expected, strict=True)
    ):
        if actual_word != expected_word:
            return index
    return None


def _compute_oracle(oracle: dict[str, Any], base: Path) -> array:
    operation = oracle.get("operation")
    input_paths = oracle.get("inputs", [])
    if not isinstance(input_paths, list):
        raise ValueError("oracle.inputs must be a list")
    inputs = [read_u32(_resolve(base, path)) for path in input_paths]
    q = oracle.get("modulus")
    if operation in {"padd", "psub", "pmul", "pmac"}:
        if not isinstance(q, int):
            raise ValueError("arithmetic oracle requires an integer modulus")
        if operation == "pmac":
            if len(inputs) != 3:
                raise ValueError("pmac oracle requires accumulator,src1,src2")
            return apply_arithmetic(operation, inputs[0], inputs[1], inputs[2], q)
        if len(inputs) != 2:
            raise ValueError(f"{operation} oracle requires two input artifacts")
        return apply_arithmetic(operation, None, inputs[0], inputs[1], q)
    if operation in {"ntt", "intt"}:
        if len(inputs) != 1 or not isinstance(q, int) or not isinstance(oracle.get("psi"), int):
            raise ValueError("NTT oracle requires one input,modulus,and psi")
        return array(
            "I",
            logical_negacyclic_ntt(
                inputs[0],
                oracle["psi"],
                q,
                inverse=operation == "intt",
            ),
        )
    expected = oracle.get("expected_artifact")
    if expected is None:
        raise ValueError(f"unsupported oracle operation: {operation}")
    return read_u32(_resolve(base, expected))


def _write_mapping(path: Path, mapping: list[int]) -> None:
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("physical_index", "logical_index"))
        writer.writerows(enumerate(mapping))


def _write_ddr_diff(path: Path, before_path: Path, after_path: Path) -> None:
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("word_index", "line_offset", "word_in_line", "before", "after"))
        word_base = 0
        chunk_bytes = 4 * 1024 * 1024
        with before_path.open("rb") as before_stream, after_path.open("rb") as after_stream:
            while True:
                before_raw = before_stream.read(chunk_bytes)
                after_raw = after_stream.read(chunk_bytes)
                if not before_raw:
                    break
                before_words = array("I")
                after_words = array("I")
                before_words.frombytes(before_raw)
                after_words.frombytes(after_raw)
                if sys.byteorder != "little":
                    before_words.byteswap()
                    after_words.byteswap()
                for local_index, (before, after) in enumerate(
                    zip(before_words, after_words, strict=True)
                ):
                    if before == after:
                        continue
                    word_index = word_base + local_index
                    writer.writerow(
                        (
                            word_index,
                            word_index // 64,
                            word_index % 64,
                            f"0x{before:08x}",
                            f"0x{after:08x}",
                        )
                    )
                word_base += len(before_words)


def _write_full_hex(binary_path: Path, text_path: Path) -> None:
    word_index = 0
    with binary_path.open("rb") as source, text_path.open(
        "x", encoding="utf-8", newline="\n"
    ) as output:
        while raw := source.read(4 * 1024 * 1024):
            words = array("I")
            words.frombytes(raw)
            if sys.byteorder != "little":
                words.byteswap()
            for row_start in range(0, len(words), 8):
                row = words[row_start : row_start + 8]
                output.write(
                    f"{word_index + row_start:08x}: "
                    + " ".join(f"0x{value:08x}" for value in row)
                    + "\n"
                )
            word_index += len(words)


def _write_mismatch_window(
    path: Path,
    actual: Any,
    expected: Any,
    mismatch_index: int,
    radius: int = 8,
) -> None:
    begin = max(0, mismatch_index - radius)
    end = min(len(actual), len(expected), mismatch_index + radius + 1)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write("index,actual,expected,match\n")
        for index in range(begin, end):
            stream.write(
                f"{index},0x{actual[index]:08x},0x{expected[index]:08x},"
                f"{int(actual[index] == expected[index])}\n"
            )


def step_case(
    state_path: str | Path,
    instruction_text: str,
    output_dir: str | Path,
) -> dict[str, Any]:
    """Execute one instruction from an explicit object-state manifest."""

    manifest_path = Path(state_path)
    base = manifest_path.parent
    manifest = _load_json_object(manifest_path)
    if manifest.get("schema_version") != 1:
        raise ValueError("step state requires schema_version 1")
    n = manifest.get("N")
    if not isinstance(n, int) or n <= 0:
        raise ValueError("step state N must be a positive integer")
    stripped_instruction = instruction_text.strip()
    instruction = (
        parse_asm_instruction(stripped_instruction)
        if stripped_instruction and stripped_instruction[0].isalpha()
        else decode_instruction(parse_instruction_word(stripped_instruction))
    )
    output = Path(output_dir)
    output.mkdir(exist_ok=False)
    (output / "objects").mkdir()
    workspace: ArtifactWorkspace | None = None
    binding: ArtifactBinding | None = None
    if instruction.mnemonic in {"dload", "dstore"}:
        memory = manifest.get("memory")
        if not isinstance(memory, dict) or "image" not in memory:
            raise ValueError("step DMA requires memory.image")
        raw_binding = manifest.get("binding")
        if not isinstance(raw_binding, dict):
            raise ValueError("step DMA requires one binding object")
        binding = ArtifactBinding.from_dict(raw_binding, base_dir=base)
        workspace = ArtifactWorkspace.create(
            _resolve(base, memory["image"]),
            output / "ddr",
        )
    state = MachineState(n=n, memory=workspace)
    context = manifest.get("active_context")
    if context is not None:
        if not isinstance(context, dict):
            raise ValueError("active_context must be an object")
        state.active_mod_id = context.get("mod_id")
        state.active_q = context.get("q")
        state.active_mu = context.get("mu")
    objects = manifest.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("objects must be a list")
    seen_slots: set[int] = set()
    modulus_table_slots: list[int] = []
    for item in objects:
        if not isinstance(item, dict):
            raise ValueError("each object state must be an object")
        slot = item.get("slot")
        if not isinstance(slot, int) or not 0 <= slot <= 7 or slot in seen_slots:
            raise ValueError(f"invalid or repeated object slot: {slot}")
        seen_slots.add(slot)
        words = read_u32(_resolve(base, item["path"]))
        state.set_object(
            slot,
            words,
            data_type=item.get("data_type", 1),
            domain=item.get("domain", "raw"),
            role=item.get("role", ""),
            line_count=item.get("line_count"),
        )
        if item.get("data_type", 1) == 2:
            modulus_table_slots.append(slot)
    if len(modulus_table_slots) > 1:
        raise ValueError("step state contains multiple modulus tables")
    if modulus_table_slots:
        state.modulus_table_object = modulus_table_slots[0]

    try:
        record = execute_step(state, instruction, binding)
    finally:
        if workspace is not None:
            workspace.close()
    for slot, obj in enumerate(state.objects):
        if obj.allocated:
            write_u32(output / "objects" / f"p{slot}.u32.bin", obj.data)
    _write_trace(output / "trace.jsonl", [record])
    summary = {
        "schema_version": 1,
        "model": "SEMANTIC_MODEL",
        "arithmetic_model": "EXACT_MOD_Q",
        "timing_model": "SEQUENTIAL_ARCHITECTURAL",
        "status": "PASS",
        "instruction": f"0x{instruction.word:08x}",
        "mnemonic": instruction.mnemonic,
        "changed_object": record["changed_object"],
        "active_mod_id": state.active_mod_id,
        "active_q": state.active_q,
    }
    _write_json(output / "summary.json", summary)
    return summary


def run_case(
    case_path: str | Path,
    output_dir: str | Path,
    *,
    emit_full_hex: bool = False,
) -> dict[str, Any]:
    """Execute one resolved case and emit DDR plus independent logical results."""

    resolved_path = Path(case_path)
    base = resolved_path.parent
    case = _load_json_object(resolved_path)
    if case.get("schema_version") != 1:
        raise ValueError("resolved case requires schema_version 1")
    n = case.get("N")
    if not isinstance(n, int) or n <= 0:
        raise ValueError("resolved case N must be a positive integer")
    program_section = case.get("program")
    memory_section = case.get("memory")
    if not isinstance(program_section, dict) or not isinstance(memory_section, dict):
        raise ValueError("resolved case requires program and memory objects")
    if memory_section.get("line_bytes") != 256:
        raise ValueError("DDR line size must be 256 bytes")
    program_path = _resolve(base, program_section["inst32"])
    memory_path = _resolve(base, memory_section["image"])
    bindings_path = _resolve(base, case["bindings"])
    instructions = _load_program(program_path)
    bindings = load_bindings_json(bindings_path)
    binding_by_instruction = {binding.instruction_index: binding for binding in bindings}
    if len(binding_by_instruction) != len(bindings):
        raise ValueError("DMA binding instruction indices must be unique")

    oracle = case.get("oracle")
    if not isinstance(oracle, dict):
        raise ValueError("resolved case requires an oracle object")
    oracle_operation = oracle.get("operation")
    stage_expected: array | None = None
    stage_tables: list[list[int]] | None = None
    stage_labels: list[int] | None = None
    next_transform_stage = 0
    stage_mismatch: dict[str, Any] | None = None
    expected_mismatch_stage: array | None = None
    actual_mismatch_stage: array | None = None
    if oracle_operation in {"ntt", "intt"}:
        oracle_inputs = oracle.get("inputs")
        q = oracle.get("modulus")
        psi = oracle.get("psi")
        if (
            not isinstance(oracle_inputs, list)
            or len(oracle_inputs) != 1
            or not isinstance(q, int)
            or not isinstance(psi, int)
        ):
            raise ValueError("NTT oracle requires one logical input,modulus,and psi")
        logical_input = read_u32(_resolve(base, oracle_inputs[0]))
        if len(logical_input) != n:
            raise ValueError("NTT oracle input length does not equal N")
        omega = psi * psi % q
        if oracle_operation == "ntt":
            stage_expected = array(
                "I",
                (
                    logical_input[bit_reverse_index(position, n)]
                    * pow(psi, bit_reverse_index(position, n), q)
                    % q
                    for position in range(n)
                ),
            )
            stage_tables = generate_hardware_ntt_twiddles(n, omega, q)
            stage_labels = list(range(n))
        else:
            layout = hardware_ntt_layout(n)
            stage_expected = array("I", (logical_input[layout[position]] for position in range(n)))
            stage_tables = generate_hardware_intt_twiddles(n, omega, q)
            stage_labels = layout

    cmd26_name = program_section.get("cmd26")
    if cmd26_name is not None:
        commands = _load_command26(_resolve(base, cmd26_name))
        expected = [expected_command26(instruction.word) for instruction in instructions]
        if commands != expected:
            raise ValueError("cmd26 file does not match independently decoded inst32")

    output = Path(output_dir)
    workspace = ArtifactWorkspace.create(memory_path, output)
    for name in ("dstore", "logical", "physical", "mapping", "checkpoints"):
        (output / name).mkdir()
    state = MachineState(n=n, memory=workspace)
    records: list[dict[str, Any]] = []
    last_dstore: tuple[ArtifactBinding, array] | None = None
    try:
        for index, instruction in enumerate(instructions):
            binding = binding_by_instruction.get(index)
            if instruction.mnemonic in {"dload", "dstore"} and binding is None:
                raise SimulationError(
                    "MISSING_DMA_BINDING",
                    f"instruction {index} has no resolved binding",
                    instruction_index=index,
                )
            expected_after_stage: array | None = None
            if instruction.mnemonic in {"pntt", "pintt"} and stage_expected is not None:
                expected_mnemonic = "pntt" if oracle_operation == "ntt" else "pintt"
                if instruction.mnemonic != expected_mnemonic or instruction.stage != next_transform_stage:
                    raise SimulationError(
                        "UNEXPECTED_NTT_STAGE",
                        f"expected {expected_mnemonic} stage {next_transform_stage}",
                        instruction_index=index,
                    )
                data_before = state.objects[instruction.pdst].data
                pre_stage_mismatch = _first_array_mismatch(data_before, stage_expected)
                if pre_stage_mismatch is not None and stage_mismatch is None:
                    stage_mismatch = {
                        "phase": "stage_input",
                        "instruction_index": index,
                        "stage": instruction.stage,
                        "physical_index": pre_stage_mismatch,
                        "logical_index": (
                            bit_reverse_index(pre_stage_mismatch, n)
                            if oracle_operation == "ntt"
                            else hardware_ntt_layout(n)[pre_stage_mismatch]
                        ),
                        "actual": data_before[pre_stage_mismatch],
                        "expected": stage_expected[pre_stage_mismatch],
                    }
                if stage_tables is None:
                    raise RuntimeError("NTT stage tables were not initialized")
                q = oracle["modulus"]
                expected_after_stage = (
                    pntt_stage(stage_expected, stage_tables[instruction.stage], instruction.stage, q)
                    if instruction.mnemonic == "pntt"
                    else pintt_stage(stage_expected, stage_tables[instruction.stage], instruction.stage, q)
                )
            record = execute_step(state, instruction, binding)
            records.append(record)
            if instruction.mnemonic in {"pntt", "pintt"}:
                checkpoint = output / "checkpoints" / (
                    f"{instruction.mnemonic}_stage_{instruction.stage:02d}_"
                    f"instruction_{index:06d}.u32.bin"
                )
                write_u32(checkpoint, state.objects[instruction.pdst].data)
                if expected_after_stage is not None:
                    actual_stage = state.objects[instruction.pdst].data
                    physical_mismatch = _first_array_mismatch(actual_stage, expected_after_stage)
                    forward_stage = (
                        instruction.stage
                        if instruction.mnemonic == "pntt"
                        else n.bit_length() - 2 - instruction.stage
                    )
                    if stage_labels is None:
                        raise RuntimeError("NTT stage labels were not initialized")
                    stage_labels, diagnostic = _advance_stage_labels_and_locate(
                        stage_labels,
                        n,
                        forward_stage,
                        instruction.mnemonic,
                        physical_mismatch,
                    )
                    if physical_mismatch is not None and stage_mismatch is None:
                        stage_mismatch = {
                            "phase": "stage_output",
                            "instruction_index": index,
                            "stage": instruction.stage,
                            "forward_stage": forward_stage,
                            "physical_index": physical_mismatch,
                            "actual": actual_stage[physical_mismatch],
                            "expected": expected_after_stage[physical_mismatch],
                            **(diagnostic or {}),
                        }
                        expected_mismatch_stage = expected_after_stage
                        actual_mismatch_stage = array("I", actual_stage)
                    stage_expected = expected_after_stage
                    next_transform_stage += 1
            if instruction.mnemonic == "dstore":
                if binding is None:
                    raise SimulationError(
                        "MISSING_DMA_BINDING",
                        f"instruction {index} has no DSTORE binding",
                        instruction_index=index,
                    )
                words = workspace.read_words(
                    binding.line_offset,
                    binding.line_count,
                    binding.payload_words,
                )
                write_u32(output / "dstore" / f"dma_{binding.dma_index:06d}.u32.bin", words)
                last_dstore = (binding, words)
        if not state.program_complete:
            raise SimulationError("MISSING_TERMINAL_PSYNC", "program has no terminal psync")
        if any(obj.allocated for obj in state.objects):
            live = [index for index, obj in enumerate(state.objects) if obj.allocated]
            raise SimulationError("LIVE_OBJECTS_AFTER_PSYNC", f"objects remain live: {live}")
        if last_dstore is None:
            raise SimulationError("NO_DSTORE_RESULT", "program produced no DSTORE result")
    except SimulationError as error:
        failure = {
            "code": error.code,
            "message": str(error),
            "instruction_index": (
                error.instruction_index
                if error.instruction_index is not None
                else state.instruction_index
            ),
        }
        records.append(
            {
                "model": "SEMANTIC_MODEL",
                "arithmetic_model": "EXACT_MOD_Q",
                "timing_model": "SEQUENTIAL_ARCHITECTURAL",
                "instruction_index": failure["instruction_index"],
                "dma_index": state.dma_index,
                "mnemonic": (
                    instructions[failure["instruction_index"]].mnemonic
                    if isinstance(failure["instruction_index"], int)
                    and 0 <= failure["instruction_index"] < len(instructions)
                    else None
                ),
                "status": "ERROR",
                "error": failure,
            }
        )
        workspace.close()
        failures = output / "failures"
        failures.mkdir()
        _write_json(failures / "first_mismatch.json", failure)
        with (failures / "first_mismatch_window.hex.txt").open(
            "x", encoding="utf-8", newline="\n"
        ) as stream:
            stream.write(f"{failure['code']}: {failure['message']}\n")
        _write_trace(output / "trace.jsonl", records)
        difference = diff_files(
            output / "ddr_before.u32.bin",
            output / "ddr_after.u32.bin",
        )
        _write_ddr_diff(
            output / "ddr_diff.csv",
            output / "ddr_before.u32.bin",
            output / "ddr_after.u32.bin",
        )
        summary = {
            "schema_version": 1,
            "case_name": case.get("case_name", resolved_path.stem),
            "model": "SEMANTIC_MODEL",
            "arithmetic_model": "EXACT_MOD_Q",
            "timing_model": "SEQUENTIAL_ARCHITECTURAL",
            "status": "ERROR",
            "instruction_count": len(instructions),
            "executed_instructions": len(records) - 1,
            "dma_count": len(bindings),
            "error": failure,
            "ddr": {
                "size_bytes": difference.size_bytes,
                "changed_words": difference.changed_words,
                "before_checksum": difference.before_checksum,
                "after_checksum": difference.after_checksum,
            },
        }
        _write_json(output / "summary.json", summary)
        return summary
    finally:
        workspace.close()

    binding, physical = last_dstore
    physical_path = output / "physical" / "final_result.u32.bin"
    write_u32(physical_path, physical)
    domain = oracle.get("final_domain", binding.domain)
    logical_view, mapping = _physical_to_logical(physical, domain)
    expected_logical = _compute_oracle(oracle, base)
    expected_artifact_name = oracle.get("expected_artifact")
    if expected_artifact_name is not None:
        packaged_expected = read_u32(_resolve(base, expected_artifact_name))
        if packaged_expected != expected_logical:
            raise ValueError("packaged expected artifact disagrees with the independent oracle")
    write_u32(output / "logical" / "actual_from_physical.u32.bin", logical_view)
    logical_path = output / "logical" / "final_result.u32.bin"
    write_u32(logical_path, expected_logical)
    preview_path = output / "logical" / "final_result.preview.hex.txt"
    with preview_path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(preview_hex(logical_path, word_count=min(32, len(expected_logical))))
        stream.write("\n")
    if emit_full_hex:
        _write_full_hex(logical_path, output / "logical" / "final_result.hex.txt")
        _write_full_hex(physical_path, output / "physical" / "final_result.hex.txt")
    _write_mapping(output / "mapping" / "physical_to_logical.csv", mapping)

    first_mismatch = stage_mismatch
    if first_mismatch is None:
        inverse_mapping = {logical: physical for physical, logical in enumerate(mapping)}
        for index, (actual, expected) in enumerate(
            zip(logical_view, expected_logical, strict=False)
        ):
            if actual != expected:
                first_mismatch = {
                    "phase": "final_result",
                    "logical_index": index,
                    "physical_index": inverse_mapping.get(index),
                    "actual": actual,
                    "expected": expected,
                }
                break
    if len(logical_view) != len(expected_logical) and first_mismatch is None:
        first_mismatch = {
            "logical_index": min(len(logical_view), len(expected_logical)),
            "actual_words": len(logical_view),
            "expected_words": len(expected_logical),
        }

    difference = diff_files(output / "ddr_before.u32.bin", output / "ddr_after.u32.bin")
    _write_ddr_diff(
        output / "ddr_diff.csv",
        output / "ddr_before.u32.bin",
        output / "ddr_after.u32.bin",
    )
    _write_trace(output / "trace.jsonl", records)
    summary = {
        "schema_version": 1,
        "case_name": case.get("case_name", resolved_path.stem),
        "model": "SEMANTIC_MODEL",
        "arithmetic_model": "EXACT_MOD_Q",
        "timing_model": "SEQUENTIAL_ARCHITECTURAL",
        "status": "PASS" if first_mismatch is None else "FAIL",
        "instruction_count": len(instructions),
        "dma_count": len(bindings),
        "ddr": {
            "size_bytes": difference.size_bytes,
            "changed_words": difference.changed_words,
            "first_changed_word": difference.first_changed_word,
            "last_changed_word": difference.last_changed_word,
            "before_checksum": difference.before_checksum,
            "after_checksum": difference.after_checksum,
        },
        "result_words": len(physical),
        "first_mismatch": first_mismatch,
    }
    _write_json(output / "summary.json", summary)
    if first_mismatch is not None:
        failures = output / "failures"
        failures.mkdir()
        _write_json(failures / "first_mismatch.json", first_mismatch)
        if expected_mismatch_stage is not None and actual_mismatch_stage is not None:
            write_u32(failures / "expected_stage.u32.bin", expected_mismatch_stage)
            write_u32(failures / "actual_stage.u32.bin", actual_mismatch_stage)
            _write_mismatch_window(
                failures / "first_mismatch_window.hex.txt",
                actual_mismatch_stage,
                expected_mismatch_stage,
                first_mismatch["physical_index"],
            )
        else:
            _write_mismatch_window(
                failures / "first_mismatch_window.hex.txt",
                logical_view,
                expected_logical,
                first_mismatch["logical_index"],
            )
    return summary
