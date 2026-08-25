import json
import tempfile
import unittest
from array import array
from pathlib import Path

from tools.hpu_fhe_semantic_sim.artifacts import read_u32, write_u32
from tools.hpu_fhe_semantic_sim.runner import run_case


class ResolvedProgramRunnerTest(unittest.TestCase):
    def test_run_writes_ddr_and_independent_logical_result(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_runner_"))
        q = 65537
        mu = (1 << 64) // q
        left = array("I", [0, 1, q - 1] + [index % q for index in range(3, 64)])
        right = array("I", [1, q - 1, 2] + [(3 * index + 1) % q for index in range(3, 64)])
        expected = array("I", [(a * b) % q for a, b in zip(left, right, strict=True)])
        mod_context = array("I", [q, mu & 0xFFFFFFFF, (mu >> 32) & 0xFFFF, 0])
        memory = array("I", [0] * (4 * 64))
        memory[0:4] = mod_context
        memory[64:128] = left
        memory[128:192] = right
        memory[192:256] = array("I", [0xA5A5A5A5] * 64)
        write_u32(root / "ddr.u32.bin", memory)
        write_u32(root / "left.u32.bin", left)
        write_u32(root / "right.u32.bin", right)
        write_u32(root / "expected.u32.bin", expected)

        words = [
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
        ]
        (root / "program.inst32").write_text(
            "".join(f"{word:032b}\n" for word in words), encoding="utf-8"
        )
        bindings = [
            {
                "dma_index": 0,
                "instruction_index": 0,
                "direction": "dload",
                "line_offset": 0,
                "line_count": 1,
                "obj_id": 4,
                "type_or_release": 2,
                "flag": 1,
                "payload_words": 4,
                "domain": "mod_ctx",
                "role": "mod_contexts",
            },
            {
                "dma_index": 1,
                "instruction_index": 2,
                "direction": "dload",
                "line_offset": 1,
                "line_count": 1,
                "obj_id": 0,
                "type_or_release": 1,
                "flag": 0,
                "payload_words": 64,
                "domain": "coefficient",
                "role": "left",
            },
            {
                "dma_index": 2,
                "instruction_index": 3,
                "direction": "dload",
                "line_offset": 2,
                "line_count": 1,
                "obj_id": 1,
                "type_or_release": 1,
                "flag": 0,
                "payload_words": 64,
                "domain": "coefficient",
                "role": "right",
            },
            {
                "dma_index": 3,
                "instruction_index": 7,
                "direction": "dstore",
                "line_offset": 3,
                "line_count": 1,
                "obj_id": 2,
                "type_or_release": 1,
                "flag": 0,
                "payload_words": 64,
                "domain": "coefficient",
                "role": "output",
                "expected_artifact": "expected.u32.bin",
            },
        ]
        (root / "bindings.json").write_text(json.dumps(bindings), encoding="utf-8")
        case = {
            "schema_version": 1,
            "case_name": "mm_e2e",
            "operation": "pmul",
            "N": 64,
            "program": {"inst32": "program.inst32"},
            "memory": {"image": "ddr.u32.bin", "line_bytes": 256, "line_count": 4},
            "bindings": "bindings.json",
            "oracle": {
                "operation": "pmul",
                "inputs": ["left.u32.bin", "right.u32.bin"],
                "modulus": q,
                "expected_artifact": "expected.u32.bin",
                "final_domain": "coefficient",
            },
        }
        case_path = root / "case_resolved.json"
        case_path.write_text(json.dumps(case), encoding="utf-8")
        output = root / "output"

        summary = run_case(case_path, output, emit_full_hex=True)

        after = read_u32(output / "ddr_after.u32.bin")
        self.assertEqual(list(after[192:256]), list(expected))
        self.assertEqual(
            list(read_u32(output / "logical" / "final_result.u32.bin")),
            list(expected),
        )
        self.assertEqual(
            list(read_u32(output / "physical" / "final_result.u32.bin")),
            list(expected),
        )
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["instruction_count"], len(words))
        self.assertTrue((output / "trace.jsonl").is_file())
        self.assertTrue((output / "ddr_diff.csv").is_file())
        self.assertTrue((output / "logical" / "final_result.hex.txt").is_file())

    def test_run_preserves_structured_first_failure(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_failure_"))
        write_u32(root / "ddr.u32.bin", [0] * 64)
        (root / "program.inst32").write_text(
            f"{0x8000000B:032b}\n{0x7000000B:032b}\n",
            encoding="utf-8",
        )
        (root / "bindings.json").write_text("[]\n", encoding="utf-8")
        case = {
            "schema_version": 1,
            "case_name": "invalid_free",
            "operation": "pmul",
            "N": 64,
            "program": {"inst32": "program.inst32"},
            "memory": {"image": "ddr.u32.bin", "line_bytes": 256, "line_count": 1},
            "bindings": "bindings.json",
            "oracle": {
                "operation": "pmul",
                "inputs": [],
                "modulus": 65537,
                "final_domain": "coefficient",
            },
        }
        case_path = root / "case.json"
        case_path.write_text(json.dumps(case), encoding="utf-8")
        output = root / "output"

        summary = run_case(case_path, output)

        self.assertEqual(summary["status"], "ERROR")
        self.assertEqual(summary["error"]["code"], "OBJECT_NOT_LIVE")
        self.assertEqual(summary["error"]["instruction_index"], 0)
        self.assertTrue((output / "failures" / "first_mismatch.json").is_file())
        self.assertTrue((output / "failures" / "first_mismatch_window.hex.txt").is_file())
        self.assertTrue((output / "trace.jsonl").is_file())


if __name__ == "__main__":
    unittest.main()
