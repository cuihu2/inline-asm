from __future__ import annotations

import json
import hashlib
import struct
import tempfile
import unittest
from array import array
from pathlib import Path

from tools.hpu_fhe_semantic_sim.artifacts import (
    ArtifactBinding,
    ArtifactDiff,
    ArtifactWorkspace,
    IO_CHUNK_BYTES,
    checksum_file,
    diff_files,
    load_bindings_json,
    preview_hex,
    read_u32,
    write_u32,
)


class PersistentTemporaryDirectory:
    """Create an isolated test directory without recursively deleting it."""

    def __enter__(self) -> str:
        self.name = tempfile.mkdtemp(prefix="hpu_semantic_artifact_")
        return self.name

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        return False


def valid_binding_dict() -> dict[str, object]:
    return {
        "dma_index": 0,
        "instruction_index": 3,
        "direction": "dload",
        "line_offset": 17,
        "line_count": 2,
        "obj_id": 4,
        "type_or_release": 2,
        "flag": 1,
        "payload_words": 8,
        "domain": "mod_ctx",
        "role": "Q modulus table",
        "artifact_path": "constants/mod_ctx.u32.bin",
        "expected_artifact": None,
    }


class ArtifactBindingTests(unittest.TestCase):
    def test_from_dict_resolves_optional_artifact_paths_from_base_dir(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            base_dir = Path(temporary_directory)
            binding = ArtifactBinding.from_dict(
                valid_binding_dict(),
                base_dir=base_dir,
            )

        self.assertEqual(binding.dma_index, 0)
        self.assertEqual(binding.instruction_index, 3)
        self.assertEqual(binding.direction, "dload")
        self.assertEqual(binding.payload_words, 8)
        self.assertEqual(binding.domain, "mod_ctx")
        self.assertEqual(binding.role, "Q modulus table")
        self.assertEqual(
            binding.artifact_path,
            base_dir / "constants/mod_ctx.u32.bin",
        )
        self.assertIsNone(binding.expected_artifact)

    def test_from_dict_rejects_schema_errors(self) -> None:
        missing = valid_binding_dict()
        del missing["line_count"]
        unknown = valid_binding_dict()
        unknown["surprise"] = 1
        boolean_integer = valid_binding_dict()
        boolean_integer["dma_index"] = True
        bad_path = valid_binding_dict()
        bad_path["artifact_path"] = 17

        for invalid in (missing, unknown, boolean_integer, bad_path):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ArtifactBinding.from_dict(invalid)

    def test_from_dict_rejects_invalid_dma_semantics(self) -> None:
        invalid_updates = (
            {"dma_index": -1},
            {"instruction_index": -1},
            {"direction": "upload"},
            {"line_offset": -1},
            {"line_count": 0},
            {"obj_id": 8},
            {"type_or_release": 3},
            {"flag": 0},  # mod_ctx DLOAD must select the small bank.
            {"payload_words": 0},
            {"payload_words": 129},
            {"domain": ""},
            {"artifact_path": ""},
        )
        for update in invalid_updates:
            invalid = valid_binding_dict()
            invalid.update(update)
            with self.subTest(update=update):
                with self.assertRaises(ValueError):
                    ArtifactBinding.from_dict(invalid)

        invalid_dstore = valid_binding_dict()
        invalid_dstore.update(
            direction="dstore",
            type_or_release=1,
            flag=1,
        )
        with self.assertRaises(ValueError):
            ArtifactBinding.from_dict(invalid_dstore)

    def test_json_loader_builds_an_ordered_binding_tuple(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            base_dir = Path(temporary_directory)
            first = valid_binding_dict()
            second = valid_binding_dict()
            second.update(
                dma_index=1,
                instruction_index=9,
                direction="dstore",
                line_offset=23,
                line_count=1,
                obj_id=2,
                type_or_release=1,
                flag=0,
                payload_words=64,
                domain="coefficient",
                role="result",
                artifact_path=None,
                expected_artifact="expected/result.u32.bin",
            )
            manifest_path = base_dir / "bindings.json"
            manifest_path.write_text(
                json.dumps({"format_version": 1, "bindings": [first, second]}),
                encoding="utf-8",
            )

            bindings = load_bindings_json(manifest_path)

        self.assertIsInstance(bindings, tuple)
        self.assertEqual([binding.dma_index for binding in bindings], [0, 1])
        self.assertEqual(bindings[1].direction, "dstore")
        self.assertEqual(
            bindings[1].expected_artifact,
            base_dir / "expected/result.u32.bin",
        )

    def test_json_loader_rejects_invalid_manifest_order_and_shape(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            base_dir = Path(temporary_directory)
            first = valid_binding_dict()
            bad_documents: tuple[object, ...] = (
                {"format_version": 2, "bindings": [first]},
                {"format_version": 1, "bindings": [first], "extra": True},
                {"format_version": 1, "bindings": "not-a-list"},
                [dict(first, dma_index=1)],
                [first, dict(first, dma_index=1)],
                [first, dict(first, dma_index=2, instruction_index=4)],
                7,
            )
            for index, document in enumerate(bad_documents):
                manifest_path = base_dir / f"invalid_{index}.json"
                manifest_path.write_text(json.dumps(document), encoding="utf-8")
                with self.subTest(document=document):
                    with self.assertRaises(ValueError):
                        load_bindings_json(manifest_path)

            malformed_path = base_dir / "malformed.json"
            malformed_path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_bindings_json(malformed_path)


class U32FileTests(unittest.TestCase):
    def test_little_endian_u32_round_trip_has_exact_bytes(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "words.u32.bin"
            write_u32(path, [0, 0x01020304, 0xFFFFFFFF])

            raw = path.read_bytes()
            words = read_u32(path)

        self.assertEqual(
            raw,
            b"\x00\x00\x00\x00\x04\x03\x02\x01\xff\xff\xff\xff",
        )
        self.assertIsInstance(words, array)
        self.assertEqual(words.typecode, "I")
        self.assertEqual(words.tolist(), [0, 0x01020304, 0xFFFFFFFF])

    def test_u32_io_rejects_malformed_values_and_existing_output(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            malformed = root / "malformed.u32.bin"
            malformed.write_bytes(b"\x00\x01\x02")
            with self.assertRaises(ValueError):
                read_u32(malformed)

            for index, invalid_values in enumerate(([-1], [1 << 32], [True])):
                with self.subTest(values=invalid_values):
                    with self.assertRaises(ValueError):
                        write_u32(root / f"invalid_{index}.u32.bin", invalid_values)

            existing = root / "existing.u32.bin"
            existing.write_bytes(b"sentinel")
            with self.assertRaises(FileExistsError):
                write_u32(existing, [1])
            self.assertEqual(existing.read_bytes(), b"sentinel")


class LargeFileInspectionTests(unittest.TestCase):
    def test_checksum_matches_sha256_across_the_four_mib_boundary(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "large.bin"
            content = b"A" * IO_CHUNK_BYTES + b"boundary-data"
            path.write_bytes(content)

            digest = checksum_file(path)

        self.assertEqual(IO_CHUNK_BYTES, 4 * 1024 * 1024)
        self.assertEqual(digest, hashlib.sha256(content).hexdigest())

    def test_diff_reports_word_changes_on_both_sides_of_a_chunk_boundary(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            before_path = root / "before.u32.bin"
            after_path = root / "after.u32.bin"
            content = bytearray(IO_CHUNK_BYTES + 8)
            before_path.write_bytes(content)
            first_index = IO_CHUNK_BYTES // 4 - 1
            second_index = IO_CHUNK_BYTES // 4 + 1
            struct.pack_into("<I", content, first_index * 4, 0x11223344)
            struct.pack_into("<I", content, second_index * 4, 0xAABBCCDD)
            after_path.write_bytes(content)

            difference = diff_files(before_path, after_path)
            expected_before_checksum = checksum_file(before_path)
            expected_after_checksum = checksum_file(after_path)

        self.assertIsInstance(difference, ArtifactDiff)
        self.assertFalse(difference.identical)
        self.assertEqual(difference.size_bytes, IO_CHUNK_BYTES + 8)
        self.assertEqual(difference.changed_words, 2)
        self.assertEqual(difference.first_changed_word, first_index)
        self.assertEqual(difference.last_changed_word, second_index)
        self.assertEqual(
            [(item.word_index, item.before, item.after) for item in difference.preview],
            [
                (first_index, 0, 0x11223344),
                (second_index, 0, 0xAABBCCDD),
            ],
        )
        self.assertEqual(difference.before_checksum, expected_before_checksum)
        self.assertEqual(difference.after_checksum, expected_after_checksum)

    def test_preview_hex_reads_a_bounded_word_window(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "preview.u32.bin"
            write_u32(path, range(12))

            preview = preview_hex(
                path,
                start_word=3,
                word_count=6,
                words_per_row=4,
            )

        self.assertEqual(
            preview,
            "00000003: 0x00000003 0x00000004 0x00000005 0x00000006\n"
            "00000007: 0x00000007 0x00000008",
        )

    def test_diff_and_preview_reject_incompatible_u32_files_and_ranges(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            one_word = root / "one_word.u32.bin"
            two_words = root / "two_words.u32.bin"
            malformed = root / "malformed.bin"
            write_u32(one_word, [1])
            write_u32(two_words, [1, 2])
            malformed.write_bytes(b"abc")

            with self.assertRaises(ValueError):
                diff_files(one_word, two_words)
            with self.assertRaises(ValueError):
                diff_files(malformed, malformed)
            with self.assertRaises(ValueError):
                preview_hex(one_word, start_word=2)
            with self.assertRaises(ValueError):
                preview_hex(one_word, words_per_row=0)


class ArtifactWorkspaceTests(unittest.TestCase):
    def test_create_makes_self_contained_before_and_after_snapshots(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.u32.bin"
            original_words = list(range(128))
            write_u32(source, original_words)
            original_bytes = source.read_bytes()
            output_dir = root / "run"

            workspace = ArtifactWorkspace.create(source, output_dir)
            try:
                self.assertEqual(
                    workspace.before_path,
                    output_dir / "ddr_before.u32.bin",
                )
                self.assertEqual(
                    workspace.after_path,
                    output_dir / "ddr_after.u32.bin",
                )
                self.assertEqual(workspace.before_path.read_bytes(), original_bytes)
                self.assertEqual(workspace.after_path.read_bytes(), original_bytes)
                self.assertEqual(source.read_bytes(), original_bytes)
            finally:
                workspace.close()

            self.assertTrue(workspace.before_path.exists())
            self.assertTrue(workspace.after_path.exists())

    def test_create_rejects_every_existing_output_path_without_cleanup(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.u32.bin"
            write_u32(source, [1, 2, 3, 4])

            existing_dir = root / "existing_dir"
            existing_dir.mkdir()
            sentinel = existing_dir / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                ArtifactWorkspace.create(source, existing_dir)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertEqual(list(existing_dir.iterdir()), [sentinel])

            existing_file = root / "existing_file"
            existing_file.write_text("keep-file", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                ArtifactWorkspace.create(source, existing_file)
            self.assertEqual(existing_file.read_text(encoding="utf-8"), "keep-file")

    def test_write_words_updates_the_current_image_read_by_later_loads(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.u32.bin"
            original_words = list(range(128))
            write_u32(source, original_words)
            workspace = ArtifactWorkspace.create(source, root / "run")
            try:
                self.assertEqual(
                    workspace.read_words(0, 1, payload_words=4).tolist(),
                    [0, 1, 2, 3],
                )

                stored_words = array("I", [0xFFFFFFFF, 0x01020304, 7, 9])
                workspace.write_words(1, 1, stored_words)

                self.assertEqual(
                    workspace.read_words(1, 1, payload_words=4).tolist(),
                    stored_words.tolist(),
                )
                self.assertEqual(
                    workspace.read_words(1, 1).tolist()[4:],
                    [0] * 60,
                )
                self.assertEqual(read_u32(workspace.before_path).tolist(), original_words)
            finally:
                workspace.close()

    def test_workspace_rejects_invalid_spans_and_keeps_snapshots_after_close(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "source.u32.bin"
            write_u32(source, range(64))
            workspace = ArtifactWorkspace.create(source, root / "run")

            with self.assertRaises(ValueError):
                workspace.read_words(-1, 1)
            with self.assertRaises(ValueError):
                workspace.read_words(0, 0)
            with self.assertRaises(ValueError):
                workspace.read_words(1, 1)
            with self.assertRaises(ValueError):
                workspace.read_words(0, 1, payload_words=65)
            with self.assertRaises(ValueError):
                workspace.write_words(0, 1, [])
            with self.assertRaises(ValueError):
                workspace.write_words(0, 1, range(65))

            workspace.close()
            workspace.close()
            self.assertTrue(workspace.before_path.exists())
            self.assertTrue(workspace.after_path.exists())
            with self.assertRaises(ValueError):
                workspace.read_words(0, 1)
            with self.assertRaises(ValueError):
                workspace.write_words(0, 1, [1])

    def test_invalid_source_does_not_create_an_output_directory(self) -> None:
        with PersistentTemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name, content in (("empty", b""), ("partial", b"abc")):
                source = root / f"{name}.bin"
                source.write_bytes(content)
                output_dir = root / f"{name}_run"
                with self.subTest(source=source):
                    with self.assertRaises(ValueError):
                        ArtifactWorkspace.create(source, output_dir)
                    self.assertFalse(output_dir.exists())


if __name__ == "__main__":
    unittest.main()
