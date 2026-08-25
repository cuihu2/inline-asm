"""Command-line interface for the HPU FHE semantic simulator."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Sequence


TRACE_COMPARE_FIELDS = (
    "model",
    "arithmetic_model",
    "timing_model",
    "instruction_index",
    "dma_index",
    "word",
    "mnemonic",
    "decoded_operands",
    "active_mod_id",
    "active_q",
    "active_mu",
    "live_objects",
    "changed_object",
    "changed_object_span",
    "before_checksum",
    "after_checksum",
    "changed_ddr_span",
    "stage_detail",
    "status",
)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: trace row must be an object")
            rows.append(value)
    return rows


def compare_trace_files(left_path: Path, right_path: Path) -> dict[str, Any]:
    left = _read_jsonl(Path(left_path))
    right = _read_jsonl(Path(right_path))
    limit = max(len(left), len(right))
    for index in range(limit):
        if index >= len(left) or index >= len(right):
            return {
                "equal": False,
                "record_count": min(len(left), len(right)),
                "first_mismatch": {
                    "record_index": index,
                    "reason": "record_count",
                    "left_count": len(left),
                    "right_count": len(right),
                },
            }
        differences = {
            field: {"left": left[index].get(field), "right": right[index].get(field)}
            for field in TRACE_COMPARE_FIELDS
            if left[index].get(field) != right[index].get(field)
        }
        if differences:
            return {
                "equal": False,
                "record_count": index,
                "first_mismatch": {
                    "record_index": index,
                    "differences": differences,
                    "left": left[index],
                    "right": right[index],
                },
            }
    return {"equal": True, "record_count": len(left), "first_mismatch": None}


def _compare_command(args: argparse.Namespace) -> int:
    result = compare_trace_files(Path(args.left), Path(args.right))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["equal"] else 1


def _prepare_command(args: argparse.Namespace) -> int:
    from .prepare import prepare_case

    resolved_path = prepare_case(Path(args.case), Path(args.output_dir))
    print(resolved_path)
    return 0


def _step_command(args: argparse.Namespace) -> int:
    from .runner import step_case

    instruction = args.asm if args.asm is not None else args.inst32
    summary = step_case(Path(args.state), instruction, Path(args.output_dir))
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def _run_command(args: argparse.Namespace) -> int:
    from .runner import run_case

    summary = run_case(
        Path(args.case),
        Path(args.output_dir),
        emit_full_hex=args.emit_full_hex,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"] == "PASS" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hpu_fhe_semantic_sim")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare", help="prepare a resolved DDR case")
    prepare_parser.add_argument("--case", required=True)
    prepare_parser.add_argument("--output-dir", required=True)
    prepare_parser.set_defaults(handler=_prepare_command)

    step_parser = subparsers.add_parser("step", help="execute one instruction from explicit state")
    step_parser.add_argument("--state", required=True)
    instruction_group = step_parser.add_mutually_exclusive_group(required=True)
    instruction_group.add_argument("--inst32")
    instruction_group.add_argument("--asm")
    step_parser.add_argument("--output-dir", required=True)
    step_parser.set_defaults(handler=_step_command)

    run_parser = subparsers.add_parser("run", help="execute a resolved instruction program")
    run_parser.add_argument("--case", required=True)
    run_parser.add_argument("--output-dir", required=True)
    run_parser.add_argument("--emit-full-hex", action="store_true")
    run_parser.set_defaults(handler=_run_command)

    compare_parser = subparsers.add_parser("compare", help="compare two JSONL traces")
    compare_parser.add_argument("--left", required=True)
    compare_parser.add_argument("--right", required=True)
    compare_parser.set_defaults(handler=_compare_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (OSError, RuntimeError, ValueError) as error:
        print(
            json.dumps(
                {"status": "ERROR", "error_type": type(error).__name__, "message": str(error)},
                ensure_ascii=False,
            ),
            file=sys.stderr,
        )
        return 2
