import json
import tempfile
import unittest
from pathlib import Path

from tools.hpu_fhe_semantic_sim.cli import build_parser, compare_trace_files


class CompareTraceTest(unittest.TestCase):
    def test_validate_delivery_subcommand_accepts_an_optional_assignment_manifest(self) -> None:
        parser = build_parser()
        unresolved = parser.parse_args(
            ["validate-delivery", "--case-dir", "outputs/mm"]
        )
        resolved = parser.parse_args(
            [
                "validate-delivery",
                "--case-dir",
                "outputs/mm",
                "--assignments",
                "mm.assignments.json",
            ]
        )

        self.assertEqual(unresolved.case_dir, "outputs/mm")
        self.assertIsNone(unresolved.assignments)
        self.assertEqual(resolved.assignments, "mm.assignments.json")

    def test_identical_trace_files_compare_equal(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_compare_"))
        left = root / "left.jsonl"
        right = root / "right.jsonl"
        rows = [
            {"instruction_index": 0, "mnemonic": "padd", "changed_object": 2},
            {"instruction_index": 1, "mnemonic": "psync", "changed_object": None},
        ]
        payload = "".join(json.dumps(row) + "\n" for row in rows)
        left.write_text(payload, encoding="utf-8")
        right.write_text(payload, encoding="utf-8")

        result = compare_trace_files(left, right)

        self.assertTrue(result["equal"])
        self.assertEqual(result["record_count"], 2)
        self.assertIsNone(result["first_mismatch"])

    def test_state_or_stage_difference_is_reported(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_compare_mismatch_"))
        left = root / "left.jsonl"
        right = root / "right.jsonl"
        common = {
            "instruction_index": 3,
            "dma_index": 1,
            "word": "0x4040000b",
            "mnemonic": "pntt",
            "changed_object": 0,
            "status": "PASS",
        }
        left.write_text(
            json.dumps({**common, "decoded_operands": {"stage": 0}, "stage_detail": {"stage": 0}})
            + "\n",
            encoding="utf-8",
        )
        right.write_text(
            json.dumps({**common, "decoded_operands": {"stage": 1}, "stage_detail": {"stage": 1}})
            + "\n",
            encoding="utf-8",
        )

        result = compare_trace_files(left, right)

        self.assertFalse(result["equal"])
        self.assertIn("decoded_operands", result["first_mismatch"]["differences"])
        self.assertIn("stage_detail", result["first_mismatch"]["differences"])


if __name__ == "__main__":
    unittest.main()
