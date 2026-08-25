import json
import tempfile
import unittest
from pathlib import Path

from tools.hpu_fhe_semantic_sim.artifacts import read_u32, write_u32
from tools.hpu_fhe_semantic_sim.runner import step_case


class StepCaseTest(unittest.TestCase):
    def test_step_emits_changed_object_and_summary(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_step_"))
        write_u32(root / "a.u32.bin", [0, 1, 16, 9])
        write_u32(root / "b.u32.bin", [1, 16, 2, 12])
        state = {
            "schema_version": 1,
            "N": 4,
            "active_context": {"mod_id": 0, "q": 17, "mu": (1 << 64) // 17},
            "objects": [
                {"slot": 0, "path": "a.u32.bin", "data_type": 1, "domain": "coefficient", "role": "a"},
                {"slot": 1, "path": "b.u32.bin", "data_type": 1, "domain": "coefficient", "role": "b"},
            ],
        }
        state_path = root / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        output = root / "output"

        summary = step_case(state_path, "padd p2, p0, p1", output)

        self.assertEqual(list(read_u32(output / "objects" / "p2.u32.bin")), [1, 0, 1, 4])
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["changed_object"], 2)
        self.assertTrue((output / "trace.jsonl").is_file())

    def test_step_infers_the_loaded_modulus_table_for_pmodld(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_pmodld_step_"))
        q = 65537
        mu = (1 << 64) // q
        write_u32(root / "mod_ctx.u32.bin", [q, mu & 0xFFFFFFFF, (mu >> 32) & 0xFFFF, 0])
        state = {
            "schema_version": 1,
            "N": 128,
            "objects": [
                {
                    "slot": 4,
                    "path": "mod_ctx.u32.bin",
                    "data_type": 2,
                    "domain": "mod_ctx",
                    "role": "mod_contexts",
                }
            ],
        }
        state_path = root / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")

        summary = step_case(state_path, "0x6000000B", root / "output")

        self.assertEqual(summary["active_mod_id"], 0)
        self.assertEqual(summary["active_q"], q)

    def test_step_executes_dload_with_explicit_ddr_binding(self) -> None:
        root = Path(tempfile.mkdtemp(prefix="hpu_semantic_dload_step_"))
        write_u32(root / "ddr.u32.bin", list(range(64)))
        state = {
            "schema_version": 1,
            "N": 64,
            "memory": {"image": "ddr.u32.bin"},
            "binding": {
                "dma_index": 0,
                "instruction_index": 0,
                "direction": "dload",
                "line_offset": 0,
                "line_count": 1,
                "obj_id": 0,
                "type_or_release": 1,
                "flag": 0,
                "payload_words": 64,
                "domain": "coefficient",
                "role": "input",
            },
            "objects": [],
        }
        state_path = root / "state.json"
        state_path.write_text(json.dumps(state), encoding="utf-8")
        output = root / "output"

        summary = step_case(state_path, "0x00B5102B", output)

        self.assertEqual(list(read_u32(output / "objects" / "p0.u32.bin")), list(range(64)))
        self.assertEqual(summary["status"], "PASS")
        self.assertTrue((output / "ddr" / "ddr_after.u32.bin").is_file())


if __name__ == "__main__":
    unittest.main()
