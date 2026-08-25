from __future__ import annotations

from array import array
import json
from pathlib import Path
import tempfile
import unittest

from tools.hpu_fhe_semantic_sim.artifacts import read_u32, write_u32
from tools.hpu_fhe_semantic_sim.ntt import (
    bit_reverse_index,
    hardware_ntt_layout,
    logical_negacyclic_ntt,
)
from tools.hpu_fhe_semantic_sim.prepare import prepare_case
from tools.hpu_fhe_semantic_sim.runner import run_case


def _write_inst32(path: Path, words: list[int]) -> None:
    path.write_text(
        "".join(f"{word:032b}\n" for word in words),
        encoding="ascii",
    )


def _write_cmd26(path: Path, commands: list[int]) -> None:
    path.write_text(
        "".join(f"{command:026b}\n" for command in commands),
        encoding="ascii",
    )


def _write_generated_case(root: Path) -> Path:
    inst32_path = root / "source.inst32"
    _write_inst32(
        inst32_path,
        [
            0x00B5292B,  # dload mod_contexts into p4
            0x00B5102B,  # dload input into p0
            0x00B5502B,  # dstore p0 with release
            0x7000000B,  # psync
        ],
    )
    case_path = root / "case.json"
    case_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_name": "n128_generated",
                "operation": "ntt",
                "N": 128,
                "seed": 20260825,
                "program": {"inst32": str(inst32_path)},
                "memory": {"line_bytes": 256, "line_count": "auto"},
                "moduli": {"source": "generated", "count": 1, "start": 65537},
                "inputs": [
                    {
                        "name": "a",
                        "source": "generated",
                        "shape": [128],
                        "domain": "coefficient",
                        "modulus_index": 0,
                    }
                ],
                "dma_bindings": [
                    {
                        "instruction_index": 0,
                        "direction": "dload",
                        "obj_id": 4,
                        "type_or_release": 2,
                        "flag": 1,
                        "artifact": "mod_contexts",
                    },
                    {
                        "instruction_index": 1,
                        "direction": "dload",
                        "obj_id": 0,
                        "type_or_release": 1,
                        "flag": 0,
                        "artifact": "a",
                    },
                    {
                        "instruction_index": 2,
                        "direction": "dstore",
                        "obj_id": 0,
                        "type_or_release": 1,
                        "flag": 0,
                        "artifact": "output:result",
                        "payload_words": 128,
                    },
                ],
                "checkpoint_policy": "trace_and_changed_spans",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return case_path


def _write_pmul_case(root: Path) -> Path:
    inst32_path = root / "pmul.inst32"
    _write_inst32(
        inst32_path,
        [
            0x00B5292B,
            0x6000000B,
            0x00B5102B,
            0x00B5122B,
            0x2400400B,
            0x8000000B,
            0x8040000B,
            0x00B5542B,
            0x8100000B,
            0x7000000B,
        ],
    )
    case_path = root / "pmul_case.json"
    case_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_name": "pmul_generated",
                "operation": "pmul",
                "N": 128,
                "seed": 20260826,
                "program": {"inst32": inst32_path.name},
                "memory": {"line_bytes": 256, "line_count": "auto"},
                "moduli": {"source": "generated", "count": 1},
                "inputs": [
                    {
                        "name": name,
                        "source": "generated",
                        "shape": [128],
                        "domain": "coefficient",
                        "modulus_index": 0,
                    }
                    for name in ("left", "right")
                ],
                "dma_bindings": [
                    {
                        "instruction_index": 0,
                        "direction": "dload",
                        "obj_id": 4,
                        "type_or_release": 2,
                        "flag": 1,
                        "artifact": "mod_contexts",
                    },
                    {
                        "instruction_index": 2,
                        "direction": "dload",
                        "obj_id": 0,
                        "type_or_release": 1,
                        "flag": 0,
                        "artifact": "left",
                    },
                    {
                        "instruction_index": 3,
                        "direction": "dload",
                        "obj_id": 1,
                        "type_or_release": 1,
                        "flag": 0,
                        "artifact": "right",
                    },
                    {
                        "instruction_index": 7,
                        "direction": "dstore",
                        "obj_id": 2,
                        "type_or_release": 1,
                        "flag": 0,
                        "artifact": "output:product",
                        "payload_words": 128,
                    },
                ],
                "checkpoint_policy": "trace_and_changed_spans",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return case_path


def _encode_dload(obj_id: int, load_type: int, flag: int = 0) -> int:
    return (
        (11 << 20)
        | (10 << 15)
        | (load_type << 12)
        | (obj_id << 9)
        | (flag << 8)
        | 0x2B
    )


def _encode_pntt(data_obj: int, twiddle_obj: int, stage: int) -> int:
    return (
        (0x4 << 28)
        | (data_obj << 25)
        | (twiddle_obj << 22)
        | (stage << 10)
        | 0x0B
    )


def _encode_pintt(data_obj: int, twiddle_obj: int, stage: int) -> int:
    return (
        (0x5 << 28)
        | (data_obj << 25)
        | (twiddle_obj << 22)
        | (stage << 10)
        | 0x0B
    )


def _write_ntt_case(root: Path) -> Path:
    words = [
        _encode_dload(4, 2, 1),
        0x6000000B,
        _encode_dload(0, 1),
        _encode_dload(1, 1),
        0x2400400B,
        0x8000000B,
        0x8040000B,
    ]
    bindings = [
        {
            "instruction_index": 0,
            "direction": "dload",
            "obj_id": 4,
            "type_or_release": 2,
            "flag": 1,
            "artifact": "mod_contexts",
        },
        {
            "instruction_index": 2,
            "direction": "dload",
            "obj_id": 0,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "input",
        },
        {
            "instruction_index": 3,
            "direction": "dload",
            "obj_id": 1,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "ntt_pre_twist",
        },
    ]
    for stage in range(7):
        instruction_index = len(words)
        words.extend(
            [
                _encode_dload(3, 1),
                _encode_pntt(2, 3, stage),
                (0x8 << 28) | (3 << 22) | 0x0B,
            ]
        )
        bindings.append(
            {
                "instruction_index": instruction_index,
                "direction": "dload",
                "obj_id": 3,
                "type_or_release": 1,
                "flag": 0,
                "artifact": f"ntt_stage_{stage}",
            }
        )
    dstore_index = len(words)
    words.extend([0x00B5542B, 0x8100000B, 0x7000000B])
    bindings.append(
        {
            "instruction_index": dstore_index,
            "direction": "dstore",
            "obj_id": 2,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "output:ntt_result",
            "payload_words": 128,
        }
    )

    inst32_path = root / "ntt.inst32"
    _write_inst32(inst32_path, words)
    case_path = root / "ntt_case.json"
    case_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_name": "ntt_generated",
                "operation": "ntt",
                "N": 128,
                "seed": 20260827,
                "program": {"inst32": inst32_path.name},
                "memory": {"line_bytes": 256, "line_count": "auto"},
                "moduli": {"source": "generated", "count": 1},
                "inputs": [
                    {
                        "name": "input",
                        "source": "generated",
                        "shape": [128],
                        "domain": "coefficient",
                        "modulus_index": 0,
                    }
                ],
                "dma_bindings": bindings,
                "checkpoint_policy": "trace_and_changed_spans",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return case_path


def _write_intt_case(root: Path) -> Path:
    words = [
        _encode_dload(4, 2, 1),
        0x6000000B,
        _encode_dload(2, 1),
    ]
    bindings = [
        {
            "instruction_index": 0,
            "direction": "dload",
            "obj_id": 4,
            "type_or_release": 2,
            "flag": 1,
            "artifact": "mod_contexts",
        },
        {
            "instruction_index": 2,
            "direction": "dload",
            "obj_id": 2,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "input",
        },
    ]
    for stage in range(7):
        instruction_index = len(words)
        words.extend(
            [
                _encode_dload(3, 1),
                _encode_pintt(2, 3, stage),
                (0x8 << 28) | (3 << 22) | 0x0B,
            ]
        )
        bindings.append(
            {
                "instruction_index": instruction_index,
                "direction": "dload",
                "obj_id": 3,
                "type_or_release": 1,
                "flag": 0,
                "artifact": f"intt_stage_{stage}",
            }
        )
    post_load_index = len(words)
    words.extend(
        [
            _encode_dload(1, 1),
            0x2480400B,
            (0x8 << 28) | (1 << 22) | 0x0B,
        ]
    )
    bindings.append(
        {
            "instruction_index": post_load_index,
            "direction": "dload",
            "obj_id": 1,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "intt_post_factor",
        }
    )
    dstore_index = len(words)
    words.extend([0x00B5542B, 0x8100000B, 0x7000000B])
    bindings.append(
        {
            "instruction_index": dstore_index,
            "direction": "dstore",
            "obj_id": 2,
            "type_or_release": 1,
            "flag": 0,
            "artifact": "output:intt_result",
            "payload_words": 128,
        }
    )
    inst32_path = root / "intt.inst32"
    _write_inst32(inst32_path, words)
    case_path = root / "intt_case.json"
    case_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_name": "intt_generated",
                "operation": "intt",
                "N": 128,
                "seed": 20260828,
                "program": {"inst32": inst32_path.name},
                "memory": {"line_bytes": 256, "line_count": "auto"},
                "moduli": {"source": "generated", "count": 1},
                "inputs": [
                    {
                        "name": "input",
                        "source": "generated",
                        "shape": [128],
                        "domain": "NTT",
                        "modulus_index": 0,
                    }
                ],
                "dma_bindings": bindings,
                "checkpoint_policy": "trace_and_changed_spans",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return case_path


class PrepareCaseTests(unittest.TestCase):
    def test_generated_n128_case_is_complete_and_reproducible(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_generated_"))
        case_path = _write_generated_case(root)
        first_output = root / "prepared_first"
        second_output = root / "prepared_second"

        first_resolved_path = prepare_case(case_path, first_output)
        second_resolved_path = prepare_case(case_path, second_output)

        self.assertEqual(first_resolved_path, first_output / "case_resolved.json")
        self.assertTrue(first_resolved_path.is_file())
        resolved = json.loads(first_resolved_path.read_text(encoding="utf-8"))
        modulus = resolved["moduli"]["values"][0]
        q = modulus["q"]
        psi = modulus["psi"]
        self.assertEqual(q % (2 * 128), 1)
        self.assertEqual(pow(psi, 128, q), q - 1)
        self.assertEqual(pow(psi, 256, q), 1)
        self.assertEqual(resolved["memory"]["line_bytes"], 256)
        self.assertEqual(resolved["memory"]["line_count"], 5)
        self.assertEqual(resolved["memory"]["image"], "ddr_before.u32.bin")
        self.assertEqual(resolved["bindings"], "semantic_bindings.json")

        input_record = resolved["inputs"][0]
        first_logical = read_u32(first_output / input_record["logical_path"])
        first_physical = read_u32(first_output / input_record["physical_path"])
        second_logical = read_u32(second_output / input_record["logical_path"])
        second_physical = read_u32(second_output / input_record["physical_path"])
        self.assertIsInstance(first_logical, array)
        self.assertEqual(len(first_logical), 128)
        self.assertEqual(first_logical[:3].tolist(), [0, 1, q - 1])
        self.assertTrue(all(0 <= value < q for value in first_logical))
        self.assertEqual(
            first_physical.tolist(),
            [first_logical[bit_reverse_index(index, 128)] for index in range(128)],
        )
        self.assertEqual(first_logical, second_logical)
        self.assertEqual(first_physical, second_physical)
        expected_path = first_output / "expected" / "result.u32.bin"
        expected = read_u32(expected_path)
        self.assertEqual(
            expected.tolist(),
            logical_negacyclic_ntt(first_logical.tolist(), psi, q),
        )
        self.assertEqual(
            resolved["oracle"],
            {
                "operation": "ntt",
                "inputs": ["inputs/a.logical.u32.bin"],
                "modulus": q,
                "psi": psi,
                "expected_artifact": "expected/result.u32.bin",
                "final_domain": "ntt_physical",
            },
        )

        expected_constant_paths = [
            "constants/mod_contexts.u32.bin",
            "constants/ntt_pre_twist.u32.bin",
            *(f"constants/ntt_stage_{stage}.u32.bin" for stage in range(7)),
            *(f"constants/intt_stage_{stage}.u32.bin" for stage in range(7)),
            "constants/intt_post_factor.u32.bin",
        ]
        for relative_path in expected_constant_paths:
            with self.subTest(relative_path=relative_path):
                first_path = first_output / relative_path
                second_path = second_output / relative_path
                self.assertTrue(first_path.is_file())
                self.assertEqual(first_path.read_bytes(), second_path.read_bytes())

        self.assertEqual(
            (first_output / "program.inst32").read_bytes(),
            (root / "source.inst32").read_bytes(),
        )
        self.assertTrue((first_output / "program.cmd26").is_file())
        self.assertTrue((first_output / "input_manifest.csv").is_file())

        bindings_document = json.loads(
            (first_output / "semantic_bindings.json").read_text(encoding="utf-8")
        )
        bindings = bindings_document["bindings"]
        self.assertEqual(
            [(item["line_offset"], item["line_count"]) for item in bindings],
            [(0, 1), (1, 2), (3, 2)],
        )
        self.assertEqual(bindings[0]["artifact_path"], "constants/mod_contexts.u32.bin")
        self.assertEqual(bindings[1]["artifact_path"], "inputs/a.u32.bin")
        self.assertIsNone(bindings[2]["artifact_path"])
        self.assertEqual(bindings[2]["expected_artifact"], "expected/result.u32.bin")

        ddr_words = read_u32(first_output / "ddr_before.u32.bin")
        self.assertEqual(len(ddr_words), 5 * 64)
        self.assertEqual(
            ddr_words[3 * 64 : 5 * 64].tolist(),
            [0xA5A5A5A5] * 128,
        )
        self.assertEqual(
            (first_output / "ddr_before.u32.bin").read_bytes(),
            (second_output / "ddr_before.u32.bin").read_bytes(),
        )

    def test_file_input_is_validated_and_copied_into_the_package(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_file_input_"))
        case_path = _write_generated_case(root)
        external_path = root / "external_input.u32.bin"
        external_values = [(index * index + 3 * index + 1) % 65537 for index in range(128)]
        write_u32(external_path, external_values)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        case["inputs"][0].update(
            source="file",
            path=external_path.name,
        )
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        output = root / "prepared"

        prepare_case(case_path, output)

        resolved = json.loads(
            (output / "case_resolved.json").read_text(encoding="utf-8")
        )
        input_record = resolved["inputs"][0]
        logical_path = output / input_record["logical_path"]
        physical_path = output / input_record["physical_path"]
        self.assertEqual(logical_path.read_bytes(), external_path.read_bytes())
        logical_values = read_u32(logical_path)
        physical_values = read_u32(physical_path)
        self.assertEqual(
            physical_values.tolist(),
            [logical_values[bit_reverse_index(index, 128)] for index in range(128)],
        )
        bindings = json.loads(
            (output / "semantic_bindings.json").read_text(encoding="utf-8")
        )["bindings"]
        ddr_words = read_u32(output / "ddr_before.u32.bin")
        input_binding = bindings[1]
        begin = input_binding["line_offset"] * 64
        self.assertEqual(
            ddr_words[begin : begin + input_binding["payload_words"]].tolist(),
            physical_values.tolist(),
        )

    def test_file_input_rejects_wrong_shape_and_noncanonical_residues(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_bad_file_input_"))
        case_path = _write_generated_case(root)
        external_path = root / "external_input.u32.bin"
        case = json.loads(case_path.read_text(encoding="utf-8"))
        case["inputs"][0].update(source="file", path=external_path.name)
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")

        write_u32(external_path, range(127))
        wrong_shape_output = root / "wrong_shape"
        with self.assertRaises(ValueError):
            prepare_case(case_path, wrong_shape_output)
        self.assertFalse(wrong_shape_output.exists())

        external_path = root / "noncanonical.u32.bin"
        write_u32(external_path, [65537, *range(1, 128)])
        case["inputs"][0]["path"] = external_path.name
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        noncanonical_output = root / "noncanonical"
        with self.assertRaises(ValueError):
            prepare_case(case_path, noncanonical_output)
        self.assertFalse(noncanonical_output.exists())

    def test_supplied_cmd26_is_cross_checked_before_copying(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_cmd26_"))
        case_path = _write_generated_case(root)
        cmd26_path = root / "source.cmd26"
        commands = [0x2000424, 0x2000002, 0x2000005, 0x0E00000]
        _write_cmd26(cmd26_path, commands)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        case["program"]["cmd26"] = cmd26_path.name
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        valid_output = root / "prepared_valid"

        prepare_case(case_path, valid_output)

        self.assertEqual(
            (valid_output / "program.cmd26").read_bytes(),
            cmd26_path.read_bytes(),
        )

        invalid_commands = commands.copy()
        invalid_commands[1] ^= 1
        _write_cmd26(root / "mismatched.cmd26", invalid_commands)
        case["program"]["cmd26"] = "mismatched.cmd26"
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        invalid_output = root / "prepared_invalid"
        with self.assertRaises(ValueError):
            prepare_case(case_path, invalid_output)
        self.assertFalse(invalid_output.exists())

    def test_fixed_memory_window_keeps_unused_lines_zero_filled(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_fixed_memory_"))
        case_path = _write_generated_case(root)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        case["memory"]["line_count"] = 8
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        output = root / "prepared"

        resolved_path = prepare_case(case_path, output)

        resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
        self.assertEqual(resolved["memory"]["line_count"], 8)
        ddr_words = read_u32(output / "ddr_before.u32.bin")
        self.assertEqual(len(ddr_words), 8 * 64)
        self.assertEqual(ddr_words[5 * 64 :].tolist(), [0] * (3 * 64))

    def test_existing_output_is_rejected_without_touching_its_contents(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_existing_output_"))
        case_path = _write_generated_case(root)
        output = root / "prepared"
        output.mkdir()
        sentinel = output / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            prepare_case(case_path, output)

        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        self.assertEqual(list(output.iterdir()), [sentinel])

    def test_prepared_pmul_case_runs_with_its_generated_oracle(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_pmul_runner_"))
        case_path = _write_pmul_case(root)
        prepared = root / "prepared"
        run_output = root / "run"

        resolved_path = prepare_case(case_path, prepared)
        summary = run_case(resolved_path, run_output)

        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(
            read_u32(run_output / "logical" / "final_result.u32.bin"),
            read_u32(prepared / "expected" / "product.u32.bin"),
        )

    def test_megabyte_inputs_drive_auto_sized_ddr_and_expected_output(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_megabyte_"))
        case_path = _write_pmul_case(root)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        words_per_input = 1024 * 1024 // 4
        for input_config in case["inputs"]:
            input_config["shape"] = [words_per_input]
        case["dma_bindings"][-1]["payload_words"] = words_per_input
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        output = root / "prepared"

        resolved_path = prepare_case(case_path, output)

        resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
        expected_lines = 1 + 3 * (words_per_input // 64)
        self.assertEqual(resolved["memory"]["line_count"], expected_lines)
        self.assertEqual((output / "inputs" / "left.u32.bin").stat().st_size, 1024 * 1024)
        self.assertEqual((output / "inputs" / "right.u32.bin").stat().st_size, 1024 * 1024)
        self.assertEqual(
            (output / "expected" / "product.u32.bin").stat().st_size,
            1024 * 1024,
        )
        self.assertEqual(
            (output / "ddr_before.u32.bin").stat().st_size,
            expected_lines * 256,
        )
        run_output = root / "run"
        summary = run_case(resolved_path, run_output)
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(
            (run_output / "physical" / "final_result.u32.bin").stat().st_size,
            1024 * 1024,
        )
        self.assertEqual(
            read_u32(run_output / "logical" / "actual_from_physical.u32.bin"),
            read_u32(output / "expected" / "product.u32.bin"),
        )

    def test_ntt_constant_binding_uses_artifact_order_and_line_padding(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_ntt_binding_"))
        case_path = _write_generated_case(root)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        _write_inst32(
            root / "source.inst32",
            [0x00B5292B, 0x00B5102B, 0x00B5162B, 0x00B5502B, 0x7000000B],
        )
        case["dma_bindings"].insert(
            2,
            {
                "instruction_index": 2,
                "direction": "dload",
                "obj_id": 3,
                "type_or_release": 1,
                "flag": 0,
                "artifact": "ntt_stage_0",
            },
        )
        case["dma_bindings"][3]["instruction_index"] = 3
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        output = root / "prepared"

        prepare_case(case_path, output)

        bindings = json.loads(
            (output / "semantic_bindings.json").read_text(encoding="utf-8")
        )["bindings"]
        self.assertEqual(
            [(item["line_offset"], item["line_count"]) for item in bindings],
            [(0, 1), (1, 2), (3, 1), (4, 2)],
        )
        stage_binding = bindings[2]
        self.assertEqual(stage_binding["artifact_path"], "constants/ntt_stage_0.u32.bin")
        stage_values = read_u32(output / stage_binding["artifact_path"])
        self.assertEqual(len(stage_values), 64)
        ddr_values = read_u32(output / "ddr_before.u32.bin")
        begin = stage_binding["line_offset"] * 64
        self.assertEqual(ddr_values[begin : begin + 64], stage_values)

    def test_prepared_n128_ntt_case_runs_to_the_logical_oracle(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_ntt_runner_"))
        case_path = _write_ntt_case(root)
        prepared = root / "prepared"
        run_output = root / "run"

        resolved_path = prepare_case(case_path, prepared)
        summary = run_case(resolved_path, run_output)

        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(
            read_u32(run_output / "logical" / "actual_from_physical.u32.bin"),
            read_u32(prepared / "expected" / "ntt_result.u32.bin"),
        )

    def test_prepared_n128_intt_case_runs_to_the_logical_oracle(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_intt_runner_"))
        prepared = root / "prepared"
        run_output = root / "run"

        resolved_path = prepare_case(_write_intt_case(root), prepared)
        summary = run_case(resolved_path, run_output)

        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(
            read_u32(run_output / "logical" / "actual_from_physical.u32.bin"),
            read_u32(prepared / "expected" / "intt_result.u32.bin"),
        )

    def test_corrupted_ntt_twiddle_reports_stage_batch_and_lane(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_ntt_corrupt_"))
        resolved_path = prepare_case(_write_ntt_case(root), root / "prepared")
        resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
        stage_binding = next(
            item
            for item in resolved["dma_bindings"]
            if item["role"] == "ntt_stage_0"
        )
        q = resolved["moduli"]["values"][0]["q"]
        ddr_path = root / "prepared" / "ddr_before.u32.bin"
        with ddr_path.open("r+b") as ddr:
            ddr.seek(stage_binding["line_offset"] * 256)
            original = int.from_bytes(ddr.read(4), "little")
            ddr.seek(stage_binding["line_offset"] * 256)
            ddr.write(((original + 1) % q).to_bytes(4, "little"))

        summary = run_case(resolved_path, root / "run")

        self.assertEqual(summary["status"], "FAIL")
        self.assertEqual(summary["first_mismatch"]["stage"], 0)
        self.assertEqual(summary["first_mismatch"]["batch_index"], 0)
        self.assertEqual(summary["first_mismatch"]["lane_index"], 0)
        self.assertIn("physical_index", summary["first_mismatch"])
        self.assertTrue((root / "run" / "failures" / "first_mismatch_window.hex.txt").is_file())

    def test_intt_input_is_mapped_from_logical_to_hardware_ntt_layout(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_prepare_intt_layout_"))
        case_path = _write_generated_case(root)
        case = json.loads(case_path.read_text(encoding="utf-8"))
        case["operation"] = "intt"
        case["inputs"][0]["domain"] = "ntt_logical"
        case_path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        output = root / "prepared"

        resolved_path = prepare_case(case_path, output)

        resolved = json.loads(resolved_path.read_text(encoding="utf-8"))
        input_record = resolved["inputs"][0]
        logical = read_u32(output / input_record["logical_path"])
        physical = read_u32(output / input_record["physical_path"])
        layout = hardware_ntt_layout(128)
        self.assertEqual(
            physical.tolist(),
            [logical[layout[position]] for position in range(128)],
        )
        self.assertEqual(input_record["physical_domain"], "ntt_physical")
        self.assertEqual(resolved["oracle"]["inputs"], [input_record["logical_path"]])
        self.assertEqual(resolved["oracle"]["final_domain"], "pintt_complete")


if __name__ == "__main__":
    unittest.main()
