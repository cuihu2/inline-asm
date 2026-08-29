from __future__ import annotations

import csv
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from tools.hpu_fhe_semantic_sim.bindings import (
    ArtifactSpan,
    BindingValidationError,
    DmaArtifactAssignment,
    DmaRelocation,
    load_dma_assignments_json,
    load_dma_relocations,
    normalize_manifest_path,
    resolve_dma_bindings,
)
from tools.hpu_fhe_semantic_sim.isa import parse_asm_instruction


class DeliveryBindingTests(unittest.TestCase):
    def test_relocations_require_an_explicit_assignment_for_every_dma(self) -> None:
        source = (
            "dload x10, x11, p0, 1, 0",
            "dstore x10, x11, p0, 1",
            "psync",
        )
        words = tuple(parse_asm_instruction(line).word for line in source)
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_bindings_") as temporary:
            manifest = Path(temporary) / "dma_relocation_manifest.csv"
            with manifest.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    (
                        "instruction_index",
                        "dma_index",
                        "direction",
                        "obj_id",
                        "type_or_release",
                        "flag",
                        "rs1",
                        "rs2",
                        "word_hex",
                        "normalized_asm",
                    )
                )
                writer.writerow((0, 0, "dload", 0, 1, 0, "x10", "x11", f"0x{words[0]:08X}", source[0]))
                writer.writerow((1, 1, "dstore", 0, 1, 0, "x10", "x11", f"0x{words[1]:08X}", source[1]))
            relocations = load_dma_relocations(manifest, words)

        artifacts = (
            ArtifactSpan(
                relative_path="images/input.u32.bin",
                binary_path=Path("/unused/input.u32.bin"),
                readable_path=None,
                role="input",
                shape="128",
                address_byte=0x10000000,
                line_offset=0,
                line_count=2,
                payload_words=128,
                payload_bytes=512,
                padded_words=128,
                padded_bytes=512,
            ),
            ArtifactSpan(
                relative_path="images/output.u32.bin",
                binary_path=Path("/unused/output.u32.bin"),
                readable_path=None,
                role="output",
                shape="128",
                address_byte=0x10000200,
                line_offset=2,
                line_count=2,
                payload_words=128,
                payload_bytes=512,
                padded_words=128,
                padded_bytes=512,
            ),
        )
        assignments = (
            DmaArtifactAssignment(0, "images/input.u32.bin", 1, 1, "coefficient"),
            DmaArtifactAssignment(1, "images/output.u32.bin", 0, 2, "coefficient"),
        )
        resolved = resolve_dma_bindings(relocations, artifacts, assignments)
        self.assertEqual([item.line_offset for item in resolved], [1, 2])
        self.assertEqual([item.line_count for item in resolved], [1, 2])
        self.assertEqual(resolved[0].artifact_line_offset, 1)
        self.assertEqual(resolved[1].as_semantic_dict()["direction"], "dstore")
        with self.assertRaisesRegex(BindingValidationError, "missing DMA indices 1"):
            resolve_dma_bindings(relocations, artifacts, assignments[:1])

    def test_manifest_paths_reject_escape_and_non_posix_forms(self) -> None:
        self.assertEqual(
            normalize_manifest_path("images/input.u32.bin"),
            "images/input.u32.bin",
        )
        for invalid in ("../input.bin", "/input.bin", "images\\input.bin", "images//input.bin"):
            with self.subTest(invalid=invalid), self.assertRaises(BindingValidationError):
                normalize_manifest_path(invalid)

    def test_assignment_manifest_is_strict_and_order_independent(self) -> None:
        document = {
            "format_version": 1,
            "assignments": [
                {
                    "dma_index": 1,
                    "artifact_path": "images/output.u32.bin",
                    "artifact_line_offset": 0,
                    "line_count": 2,
                    "domain": "coefficient",
                },
                {
                    "dma_index": 0,
                    "artifact_path": "images/input.u32.bin",
                    "artifact_line_offset": 1,
                    "line_count": 1,
                    "domain": "coefficient",
                },
            ],
        }
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_assignments_") as temporary:
            path = Path(temporary) / "assignments.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            assignments = load_dma_assignments_json(path)
            document["assignments"][0]["extra"] = True
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(BindingValidationError):
                load_dma_assignments_json(path)

        self.assertEqual([item.dma_index for item in assignments], [1, 0])

    def test_mod_context_dma_requires_the_small_bank_artifact_and_capacity(self) -> None:
        source = ("dload x10, x11, p4, 2, 1", "psync")
        words = tuple(parse_asm_instruction(line).word for line in source)
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_modctx_") as temporary:
            manifest = Path(temporary) / "dma_relocation_manifest.csv"
            with manifest.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(
                    (
                        "instruction_index", "dma_index", "direction", "obj_id",
                        "type_or_release", "flag", "rs1", "rs2", "word_hex",
                        "normalized_asm",
                    )
                )
                writer.writerow((0, 0, "dload", 4, 2, 1, "x10", "x11", f"0x{words[0]:08X}", source[0]))
            relocations = load_dma_relocations(manifest, words)

        mod_contexts = ArtifactSpan(
            relative_path="constants/mod_ctx.u32.bin",
            binary_path=Path("/unused/mod_ctx.u32.bin"),
            readable_path=None,
            role="mod contexts",
            shape="528x4",
            address_byte=0x10000000,
            line_offset=0,
            line_count=33,
            payload_words=33 * 64,
            payload_bytes=33 * 256,
            padded_words=33 * 64,
            padded_bytes=33 * 256,
        )
        with self.assertRaisesRegex(BindingValidationError, "small-bank lines"):
            resolve_dma_bindings(
                relocations,
                (mod_contexts,),
                (DmaArtifactAssignment(0, mod_contexts.relative_path, 0, 33, "mod_ctx"),),
            )
        with self.assertRaisesRegex(BindingValidationError, "mod-context instruction"):
            resolve_dma_bindings(
                relocations,
                (mod_contexts,),
                (DmaArtifactAssignment(0, mod_contexts.relative_path, 0, 1, "coefficient"),),
            )
        with self.assertRaisesRegex(BindingValidationError, "complete modulus table"):
            resolve_dma_bindings(
                relocations,
                (mod_contexts,),
                (DmaArtifactAssignment(0, mod_contexts.relative_path, 1, 1, "mod_ctx"),),
            )

        ordinary = replace(
            mod_contexts,
            relative_path="images/input.u32.bin",
            role="input",
            shape=str(1025 * 64),
            line_count=1025,
            payload_words=1025 * 64,
            payload_bytes=1025 * 256,
            padded_words=1025 * 64,
            padded_bytes=1025 * 256,
        )
        invalid_flag_relocation = DmaRelocation(
            0, 0, "dload", 0, 1, 1, 10, 11, 0, "dload x10, x11, p0, 1, 1"
        )
        with self.assertRaisesRegex(BindingValidationError, "type and small-bank flag"):
            resolve_dma_bindings(
                (invalid_flag_relocation,),
                (ordinary,),
                (DmaArtifactAssignment(0, ordinary.relative_path, 0, 1, "coefficient"),),
            )
        invalid_mod_flag_relocation = DmaRelocation(
            0, 0, "dload", 4, 2, 0, 10, 11, 0, "dload x10, x11, p4, 2, 0"
        )
        with self.assertRaisesRegex(BindingValidationError, "type and small-bank flag"):
            resolve_dma_bindings(
                (invalid_mod_flag_relocation,),
                (mod_contexts,),
                (DmaArtifactAssignment(0, mod_contexts.relative_path, 0, 33, "mod_ctx"),),
            )
        regular_relocation = DmaRelocation(
            0, 0, "dload", 0, 1, 0, 10, 11, 0, "dload x10, x11, p0, 1, 0"
        )
        with self.assertRaisesRegex(BindingValidationError, "regular-bank span"):
            resolve_dma_bindings(
                (regular_relocation,),
                (ordinary,),
                (DmaArtifactAssignment(0, ordinary.relative_path, 0, 1025, "coefficient"),),
            )


if __name__ == "__main__":
    unittest.main()
