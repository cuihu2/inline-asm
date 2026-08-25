"""Sequential architectural state for the independent HPU semantic model."""

from __future__ import annotations

from array import array
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable

from .arithmetic import apply_arithmetic


MODEL_NAME = "SEMANTIC_MODEL"
ARITHMETIC_MODEL = "EXACT_MOD_Q"
TIMING_MODEL = "SEQUENTIAL_ARCHITECTURAL"


class SimulationError(RuntimeError):
    """A fail-closed semantic validation error."""

    def __init__(self, code: str, message: str, *, instruction_index: int | None = None):
        super().__init__(message)
        self.code = code
        self.instruction_index = instruction_index


@dataclass
class ObjectState:
    allocated: bool = False
    valid: bool = False
    busy: bool = False
    data_type: int | None = None
    line_count: int = 0
    payload_words: int = 0
    domain: str = "raw"
    role: str = ""
    data: array = field(default_factory=lambda: array("I"))
    physical_generation: int = 0

    def clear(self) -> None:
        self.allocated = False
        self.valid = False
        self.busy = False
        self.data_type = None
        self.line_count = 0
        self.payload_words = 0
        self.domain = "raw"
        self.role = ""
        self.data = array("I")
        self.physical_generation = 0


@dataclass
class MachineState:
    n: int
    memory: Any | None = None
    objects: list[ObjectState] = field(
        default_factory=lambda: [ObjectState() for _ in range(8)]
    )
    active_mod_id: int | None = None
    active_q: int | None = None
    active_mu: int | None = None
    modulus_table_object: int | None = None
    instruction_index: int = 0
    dma_index: int = 0
    program_complete: bool = False
    trace: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.n <= 0:
            raise ValueError("N must be positive")

    def set_object(
        self,
        slot: int,
        words: Iterable[int],
        *,
        data_type: int = 1,
        domain: str = "raw",
        role: str = "",
        line_count: int | None = None,
    ) -> None:
        _require_slot(slot)
        data = array("I", words)
        lines = line_count if line_count is not None else (len(data) + 63) // 64
        self.objects[slot] = ObjectState(
            allocated=True,
            valid=True,
            data_type=data_type,
            line_count=lines,
            payload_words=len(data),
            domain=domain,
            role=role,
            data=data,
        )


def _require_slot(slot: int | None) -> int:
    if slot is None or not 0 <= slot <= 7:
        raise SimulationError("INVALID_OBJECT_SLOT", f"invalid object slot: {slot}")
    return slot


def _require_live(state: MachineState, slot: int | None, role: str) -> ObjectState:
    index = _require_slot(slot)
    obj = state.objects[index]
    if not obj.allocated or not obj.valid:
        raise SimulationError(
            "OBJECT_NOT_LIVE",
            f"p{index} is not live as {role}",
            instruction_index=state.instruction_index,
        )
    return obj


def _checksum_words(words: array) -> str:
    value = 0xCBF29CE484222325
    for byte in words.tobytes():
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return f"0x{value:016x}"


def _validate_dma_binding(state: MachineState, instruction: Any, binding: Any | None) -> Any:
    if binding is None:
        raise SimulationError(
            "MISSING_DMA_BINDING",
            f"{instruction.mnemonic} requires a resolved DMA binding",
            instruction_index=state.instruction_index,
        )
    if state.memory is None:
        raise SimulationError("MISSING_DDR_IMAGE", "DMA execution requires a DDR workspace")
    expected = {
        "dma_index": state.dma_index,
        "instruction_index": state.instruction_index,
        "direction": instruction.mnemonic,
        "obj_id": instruction.obj_id,
        "type_or_release": instruction.type_or_release,
        "flag": instruction.dma_flag or 0,
    }
    for field_name, expected_value in expected.items():
        actual = getattr(binding, field_name, None)
        if actual != expected_value:
            raise SimulationError(
                "DMA_BINDING_MISMATCH",
                f"binding {field_name}={actual!r}, expected {expected_value!r}",
                instruction_index=state.instruction_index,
            )
    if instruction.rs1 != 10 or instruction.rs2 != 11:
        raise SimulationError("INVALID_DMA_REGISTERS", "executable DMA must use x10/x11")
    if binding.line_count <= 0 or binding.payload_words <= 0:
        raise SimulationError("INVALID_DMA_SPAN", "DMA line_count and payload_words must be positive")
    if binding.payload_words > binding.line_count * 64:
        raise SimulationError("INVALID_DMA_SPAN", "DMA payload exceeds its line span")
    return binding


def _execute_arithmetic(state: MachineState, instruction: Any) -> int:
    expected_mode = 1 if instruction.imm8 is not None else 0
    if instruction.mode not in (None, expected_mode) or instruction.flag not in (None, 0):
        raise SimulationError(
            "UNSUPPORTED_AR3_MODE_FLAG",
            f"{instruction.mnemonic} requires mode={expected_mode},flag=0",
            instruction_index=state.instruction_index,
        )
    if state.active_q is None:
        raise SimulationError(
            "NO_ACTIVE_MODULUS",
            "arithmetic instruction requires an active modulus",
            instruction_index=state.instruction_index,
        )
    src1 = _require_live(state, instruction.psrc1, "arithmetic source 1")
    src2 = None
    if instruction.imm8 is None:
        src2 = _require_live(state, instruction.psrc2, "arithmetic source 2")
        if src1.payload_words != src2.payload_words or src1.domain != src2.domain:
            raise SimulationError(
                "OBJECT_LAYOUT_MISMATCH",
                "arithmetic sources have different lengths or domains",
                instruction_index=state.instruction_index,
            )
    dst_slot = _require_slot(instruction.pdst)
    old_dst = None
    if instruction.mnemonic == "pmac":
        old_dst = _require_live(state, dst_slot, "pmac accumulator")
        if old_dst.payload_words != src1.payload_words or old_dst.domain != src1.domain:
            raise SimulationError(
                "OBJECT_LAYOUT_MISMATCH",
                "pmac accumulator has a different length or domain",
                instruction_index=state.instruction_index,
            )

    q = state.active_q
    right: Any = src2.data if src2 is not None else instruction.imm8
    if any(value >= q for value in src1.data):
        raise SimulationError("NON_CANONICAL_RESIDUE", "source 1 contains a value outside [0,q)")
    if src2 is not None and any(value >= q for value in src2.data):
        raise SimulationError("NON_CANONICAL_RESIDUE", "source 2 contains a value outside [0,q)")
    if old_dst is not None and any(value >= q for value in old_dst.data):
        raise SimulationError("NON_CANONICAL_RESIDUE", "pmac accumulator contains a value outside [0,q)")
    result = apply_arithmetic(
        instruction.mnemonic,
        old_dst.data if old_dst is not None else None,
        src1.data,
        right,
        q,
    )

    generation = state.objects[dst_slot].physical_generation + 1
    state.set_object(
        dst_slot,
        result,
        data_type=src1.data_type if src1.data_type is not None else 1,
        domain=src1.domain,
        role="arithmetic_result",
        line_count=src1.line_count,
    )
    state.objects[dst_slot].physical_generation = generation
    return dst_slot


def execute_step(state: MachineState, instruction: Any, binding: Any | None = None) -> dict[str, Any]:
    """Execute one decoded instruction to its architectural completion point."""

    if state.program_complete:
        raise SimulationError(
            "PROGRAM_ALREADY_COMPLETE",
            "no instruction may execute after psync",
            instruction_index=state.instruction_index,
        )
    record_dma_index = state.dma_index
    changed_object: int | None = None
    changed_ddr_span: dict[str, int] | None = None
    stage_detail: dict[str, int] | None = None
    before_checksum: str | None = None
    before_payload_words = 0
    before_slot = getattr(instruction, "pdst", None)
    if before_slot is None and instruction.mnemonic in {"pfree", "dstore"}:
        before_slot = getattr(instruction, "obj_id", None)
    if before_slot is not None and 0 <= before_slot <= 7:
        obj = state.objects[before_slot]
        if obj.allocated:
            before_checksum = _checksum_words(obj.data)
            before_payload_words = obj.payload_words

    if instruction.mnemonic in {"padd", "psub", "pmul", "pmac"}:
        changed_object = _execute_arithmetic(state, instruction)
    elif instruction.mnemonic == "pfree":
        slot = _require_slot(instruction.obj_id)
        obj = _require_live(state, slot, "pfree target")
        if obj.busy:
            raise SimulationError(
                "OBJECT_BUSY",
                f"p{slot} is busy",
                instruction_index=state.instruction_index,
            )
        obj.clear()
        if state.modulus_table_object == slot:
            state.modulus_table_object = None
        changed_object = slot
    elif instruction.mnemonic == "psync":
        state.program_complete = True
    elif instruction.mnemonic == "pmodld":
        if state.modulus_table_object is None:
            raise SimulationError(
                "NO_MODULUS_TABLE",
                "pmodld requires one live small-bank modulus table",
                instruction_index=state.instruction_index,
            )
        table = _require_live(state, state.modulus_table_object, "modulus table")
        mod_id = instruction.mod_id
        if mod_id is None or not 0 <= mod_id <= 255:
            raise SimulationError("INVALID_MOD_ID", f"invalid MOD_ID: {mod_id}")
        base = mod_id * 4
        if base + 4 > table.payload_words:
            raise SimulationError(
                "MOD_CONTEXT_OUT_OF_RANGE",
                f"MOD_ID {mod_id} exceeds the loaded modulus table",
                instruction_index=state.instruction_index,
            )
        q, mu_low, mu_high_reserved, reserved = table.data[base : base + 4]
        mu = mu_low | ((mu_high_reserved & 0xFFFF) << 32)
        if not 65537 <= q <= 0xFFFFFFFF:
            raise SimulationError("INVALID_MODULUS", f"modulus is outside the PE range: {q}")
        if (mu_high_reserved >> 16) != 0 or reserved != 0:
            raise SimulationError("MOD_CONTEXT_RESERVED_BITS", "modulus context reserved bits are nonzero")
        if mu >= (1 << 48) or mu != (1 << 64) // q:
            raise SimulationError("INVALID_BARRETT_MU", "modulus context mu does not equal floor(2^64/q)")
        state.active_mod_id = mod_id
        state.active_q = q
        state.active_mu = mu
    elif instruction.mnemonic == "dload":
        binding = _validate_dma_binding(state, instruction, binding)
        slot = _require_slot(instruction.obj_id)
        if state.objects[slot].allocated:
            raise SimulationError(
                "DLOAD_OVERWRITES_LIVE_OBJECT",
                f"dload overwrites live object p{slot}",
                instruction_index=state.instruction_index,
            )
        load_type = instruction.type_or_release
        flag = instruction.dma_flag
        if load_type == 2:
            if flag != 1 or binding.line_count > 32:
                raise SimulationError(
                    "INVALID_MOD_CONTEXT_DLOAD",
                    "mod_ctx dload requires small-bank flag and at most 32 lines",
                )
            if state.modulus_table_object is not None:
                raise SimulationError("AMBIGUOUS_MODULUS_TABLE", "a modulus table is already live")
        elif flag != 0:
            raise SimulationError("INVALID_SMALL_BANK_REQUEST", "ordinary data cannot request Bank 5")
        words = state.memory.read_words(
            binding.line_offset,
            binding.line_count,
            binding.payload_words,
        )
        state.set_object(
            slot,
            words,
            data_type=load_type,
            domain=binding.domain,
            role=binding.role,
            line_count=binding.line_count,
        )
        if load_type == 2:
            state.modulus_table_object = slot
        state.dma_index += 1
        changed_object = slot
    elif instruction.mnemonic == "dstore":
        binding = _validate_dma_binding(state, instruction, binding)
        slot = _require_slot(instruction.obj_id)
        obj = _require_live(state, slot, "dstore source")
        if obj.busy:
            raise SimulationError("OBJECT_BUSY", f"p{slot} is busy")
        if obj.line_count != binding.line_count or obj.payload_words != binding.payload_words:
            raise SimulationError(
                "DSTORE_SPAN_MISMATCH",
                "dstore span must exactly match the source object",
                instruction_index=state.instruction_index,
            )
        state.memory.write_words(binding.line_offset, binding.line_count, obj.data)
        changed_ddr_span = {
            "line_offset": binding.line_offset,
            "line_count": binding.line_count,
            "payload_words": binding.payload_words,
        }
        state.dma_index += 1
        changed_object = slot
        if instruction.type_or_release == 1:
            obj.clear()
            if state.modulus_table_object == slot:
                state.modulus_table_object = None
    elif instruction.mnemonic in {"pntt", "pintt"}:
        if state.active_q is None:
            raise SimulationError("NO_ACTIVE_MODULUS", "NTT stage requires an active modulus")
        if instruction.mode != 0 or instruction.flag != 0:
            raise SimulationError(
                "UNSUPPORTED_STG_MODE_FLAG",
                "only mode=0,flag=0 has frozen execution semantics",
            )
        stage = instruction.stage
        log_n = state.n.bit_length() - 1
        if state.n < 128 or state.n & (state.n - 1) or stage is None or not 0 <= stage < log_n:
            raise SimulationError("INVALID_NTT_STAGE", f"stage {stage} is invalid for N={state.n}")
        data_slot = _require_slot(instruction.pdst)
        data_obj = _require_live(state, data_slot, "transform data")
        twiddle_obj = _require_live(state, instruction.psrc1, "transform twiddle")
        if data_obj.payload_words != state.n:
            raise SimulationError("INVALID_NTT_DATA_LENGTH", "NTT data object must contain N words")
        if twiddle_obj.payload_words != state.n // 2:
            raise SimulationError("INVALID_TWIDDLE_LENGTH", "stage twiddle object must contain N/2 words")
        generation = data_obj.physical_generation + 1
        if instruction.mnemonic == "pntt":
            from .ntt import pntt_stage

            result = pntt_stage(data_obj.data, twiddle_obj.data, stage, state.active_q)
            domain = "ntt_physical" if stage + 1 == log_n else f"pntt_stage_{stage}"
            forward_stage = stage
        else:
            from .ntt import pintt_stage

            result = pintt_stage(data_obj.data, twiddle_obj.data, stage, state.active_q)
            domain = "pintt_complete" if stage + 1 == log_n else f"pintt_stage_{stage}"
            forward_stage = log_n - 1 - stage
        state.set_object(
            data_slot,
            result,
            data_type=data_obj.data_type if data_obj.data_type is not None else 1,
            domain=domain,
            role=data_obj.role,
            line_count=data_obj.line_count,
        )
        state.objects[data_slot].physical_generation = generation
        changed_object = data_slot
        stage_detail = {
            "stage": stage,
            "forward_stage": forward_stage,
            "batch_count": state.n // 128,
            "twiddle_words": state.n // 2,
        }
    else:
        raise SimulationError(
            "UNSUPPORTED_INSTRUCTION",
            f"semantic execution is not implemented for {instruction.mnemonic}",
            instruction_index=state.instruction_index,
        )

    after_checksum = None
    changed_object_span = None
    if changed_object is not None and state.objects[changed_object].allocated:
        after_checksum = _checksum_words(state.objects[changed_object].data)
        changed_object_span = {
            "start_word": 0,
            "word_count": state.objects[changed_object].payload_words,
        }
    elif changed_object is not None and before_payload_words:
        changed_object_span = {"start_word": 0, "word_count": before_payload_words}
    record = {
        "model": MODEL_NAME,
        "arithmetic_model": ARITHMETIC_MODEL,
        "timing_model": TIMING_MODEL,
        "instruction_index": state.instruction_index,
        "dma_index": record_dma_index,
        "word": f"0x{instruction.word:08x}",
        "mnemonic": instruction.mnemonic,
        "decoded_operands": (
            {
                key: value
                for key, value in asdict(instruction).items()
                if key not in {"word", "mnemonic"} and value is not None
            }
            if is_dataclass(instruction)
            else {}
        ),
        "active_mod_id": state.active_mod_id,
        "active_q": state.active_q,
        "active_mu": state.active_mu,
        "changed_object": changed_object,
        "changed_object_span": changed_object_span,
        "before_checksum": before_checksum,
        "after_checksum": after_checksum,
        "changed_ddr_span": changed_ddr_span,
        "stage_detail": stage_detail,
        "live_objects": [index for index, obj in enumerate(state.objects) if obj.allocated],
        "status": "PASS",
    }
    state.trace.append(record)
    state.instruction_index += 1
    return record


def execute_program(
    state: MachineState,
    instructions: Iterable[Any],
    bindings: Iterable[Any] | None = None,
    *,
    require_terminal_psync: bool = True,
) -> list[dict[str, Any]]:
    binding_iter = iter(bindings or ())
    current_binding = next(binding_iter, None)
    records: list[dict[str, Any]] = []
    for instruction in instructions:
        binding = None
        if instruction.mnemonic in {"dload", "dstore"}:
            binding = current_binding
            current_binding = next(binding_iter, None)
        records.append(execute_step(state, instruction, binding))
    if current_binding is not None:
        raise SimulationError("UNUSED_DMA_BINDING", "DMA bindings remain after program execution")
    if require_terminal_psync and not state.program_complete:
        raise SimulationError("MISSING_TERMINAL_PSYNC", "program has no terminal psync")
    return records
