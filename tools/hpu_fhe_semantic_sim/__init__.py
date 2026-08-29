"""Independent HPU FHE instruction semantic simulator."""

from .bindings import (
    DmaArtifactAssignment,
    ResolvedDmaBinding,
    load_dma_assignments_json,
)
from .delivery import DeliveryPackage, DeliveryValidationError, load_delivery_package
from .isa import (
    Instruction,
    decode_instruction,
    expected_command26,
    parse_asm_instruction,
    parse_instruction_word,
)
from .machine import MachineState, ObjectState, SimulationError, execute_program, execute_step
from .prepare import prepare_case
from .runner import run_case, step_case

__all__ = [
    "Instruction",
    "DeliveryPackage",
    "DeliveryValidationError",
    "DmaArtifactAssignment",
    "MachineState",
    "ObjectState",
    "SimulationError",
    "ResolvedDmaBinding",
    "decode_instruction",
    "execute_program",
    "execute_step",
    "expected_command26",
    "load_dma_assignments_json",
    "load_delivery_package",
    "parse_asm_instruction",
    "parse_instruction_word",
    "prepare_case",
    "run_case",
    "step_case",
]
