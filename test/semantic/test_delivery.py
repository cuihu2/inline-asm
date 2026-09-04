from __future__ import annotations

import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest

from tools.hpu_fhe_semantic_sim.bindings import DmaArtifactAssignment
from tools.hpu_fhe_semantic_sim.bindings import ArtifactSpan
import tools.hpu_fhe_semantic_sim.delivery as delivery_module
from tools.hpu_fhe_semantic_sim.delivery import (
    DeliveryValidationError,
    load_delivery_package,
)
from tools.hpu_fhe_semantic_sim.isa import expected_command26, parse_asm_instruction


_CSR_ROWS = (
    ("0x00", "HPU_MEM_BASE_LO", "RW", "base[31:0]"),
    ("0x04", "HPU_MEM_BASE_HI", "RW", "base[39:32]"),
    ("0x08", "HPU_MEM_SIZE_LINES_LO", "RW", "size_lines[31:0]"),
    ("0x0c", "HPU_MEM_SIZE_LINES_HI", "RW", "size_lines[32]"),
    ("0x10", "HPU_MEM_COMMIT", "W1", "commit[0]"),
    ("0x14", "HPU_STATUS", "RO", "window_valid[0],hpu_busy[1],fault_valid[2]"),
    ("0x18", "HPU_FAULT_STATUS", "RO/W1C", "fault_valid[0],is_load[1],obj_id[6:4]"),
)


def _write_csv(path: Path, header: tuple[str, ...], rows: list[tuple[object, ...]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)


def _make_delivery(root: Path) -> Path:
    case = root / "mm"
    hardware = case / "test_data" / "hardware"
    images = hardware / "images"
    constants = hardware / "constants"
    images.mkdir(parents=True)
    constants.mkdir()

    n = 128
    modulus = 65537
    mu = (1 << 64) // modulus
    input_words = tuple(range(n))
    output_words = tuple((word + 1) % modulus for word in input_words)
    mod_words = (modulus, mu & 0xFFFFFFFF, (mu >> 32) & 0xFFFF, 0) + (0,) * 60
    input_bytes = struct.pack(f"<{n}I", *input_words)
    output_bytes = struct.pack(f"<{n}I", *output_words)
    mod_bytes = struct.pack("<64I", *mod_words)
    artifacts = (
        ("images/input.u32.bin", "input", "128", input_bytes, 0, 2, 128),
        ("images/expected.u32.bin", "expected", "128", output_bytes, 2, 2, 128),
        ("constants/mod_ctx.u32.bin", "mod contexts", "1x4", mod_bytes, 4, 1, 4),
    )
    for relative, _, _, content, _, _, _ in artifacts:
        destination = hardware / relative
        destination.write_bytes(content)
        destination.with_suffix(".dec.txt").write_text("decimal values\n", encoding="utf-8")
    (hardware / "hpu_mem_image.u32.bin").write_bytes(input_bytes + output_bytes + mod_bytes)

    (case / "test_data" / "params.json").write_text(
        json.dumps({"format_version": 1, "operation": "mm", "N": n, "moduli": [modulus]}),
        encoding="utf-8",
    )
    abi = {
        "format_version": 1,
        "N": n,
        "modulus_count": 1,
        "coefficient_bits": 32,
        "byte_order": "little-endian",
        "line_bytes": 256,
        "line_words": 64,
        "custom1_sideband": {
            "rs1_value": "HPU_MEM line offset",
            "rs2_value": "line count",
            "unit_bytes": 256,
            "line_count_must_be_nonzero": True,
        },
        "mod_ctx": {
            "record_words": 4,
            "dload_type": 2,
            "dload_flag0_small_bank": 1,
            "small_bank_id": 5,
            "small_bank_lines": 32,
            "mod_table_base_line": "0x00001400",
            "contexts_per_line": 16,
            "mod_id_bits": 8,
            "max_contexts": 256,
            "q_min": 65537,
            "q_max": 4294967295,
            "mu_bits": 48,
            "reserved_bits": 48,
        },
        "twiddle_images_included": False,
    }
    (hardware / "abi.json").write_text(json.dumps(abi), encoding="utf-8")
    base = 0x10000000
    config = {
        "format_version": 1,
        "status": "HOST_WINDOW_AND_CSR_ABI_READY",
        "image": "hpu_mem_image.u32.bin",
        "base_address": f"0x{base:016x}",
        "base_lo": f"0x{base:08x}",
        "base_hi": "0x00000000",
        "line_bytes": 256,
        "words_per_line": 64,
        "size_lines": 5,
        "size_bytes": 1280,
        "end_address_exclusive": f"0x{base + 1280:016x}",
        "csr_offsets": [
            {"offset": offset, "name": name, "access": access, "field": field}
            for offset, name, access, field in _CSR_ROWS
        ],
        "programming_sequence": [
            {"offset": "0x00", "csr": "HPU_MEM_BASE_LO", "value": f"0x{base:08x}"},
            {"offset": "0x04", "csr": "HPU_MEM_BASE_HI", "value": "0x00000000"},
            {"offset": "0x08", "csr": "HPU_MEM_SIZE_LINES_LO", "value": 5},
            {"offset": "0x0c", "csr": "HPU_MEM_SIZE_LINES_HI", "value": 0},
            {"offset": "0x10", "csr": "HPU_MEM_COMMIT", "value": 1},
            {"offset": "0x14", "csr": "HPU_STATUS", "action": "read"},
        ],
    }
    (hardware / "hpu_mem_config.json").write_text(json.dumps(config), encoding="utf-8")

    line_header = (
        "path", "role", "shape", "address_byte", "line_offset", "line_count",
        "payload_words", "payload_bytes", "padded_words", "padded_bytes",
    )
    line_rows = [
        (
            relative, role, shape, f"0x{base + line_offset * 256:016x}",
            line_offset, line_count, payload_words, payload_words * 4,
            line_count * 64, line_count * 256,
        )
        for relative, role, shape, _, line_offset, line_count, payload_words in artifacts
    ]
    _write_csv(hardware / "line_map.csv", line_header, line_rows)
    manifest_header = (
        "path", "readable_path", "role", "shape", "payload_words", "padded_words",
        "line_offset", "line_count", "payload_fnv1a64", "image_fnv1a64",
    )
    manifest_rows = [
        (
            relative, str(Path(relative).with_suffix(".dec.txt")), role, shape,
            payload_words, line_count * 64, line_offset, line_count, "unused", "unused",
        )
        for relative, role, shape, _, line_offset, line_count, payload_words in artifacts
    ]
    manifest_rows.append(("hpu_mem_image.u32.bin", "", "complete image", "", 320, 320, 0, 5, "unused", "unused"))
    _write_csv(hardware / "hardware_manifest.csv", manifest_header, manifest_rows)
    _write_csv(
        hardware / "mod_ctx_map.csv",
        (
            "context_index", "modulus", "modulus_hex", "barrett_mu48_hex",
            "record_word_offset", "line_offset", "line_word_offset", "record_words",
        ),
        [(0, modulus, f"0x{modulus:08x}", f"0x{mu:016x}", 0, 4, 0, 4)],
    )

    asm = (
        "dload x10, x11, p2, 2, 1",
        "pmodld 0",
        "dload x10, x11, p0, 1, 0",
        "dstore x10, x11, p0, 1",
        "pfree p2",
        "psync",
    )
    words = tuple(parse_asm_instruction(line).word for line in asm)
    (case / "mm.inst32").write_text("".join(f"{word:032b}\n" for word in words), encoding="ascii")
    (case / "mm.cmd26").write_text(
        "".join(f"{expected_command26(word):026b}\n" for word in words),
        encoding="ascii",
    )
    relocation_rows = []
    for dma_index, instruction_index in enumerate((0, 2, 3)):
        instruction = parse_asm_instruction(asm[instruction_index])
        relocation_rows.append(
            (
                instruction_index, dma_index, instruction.mnemonic, instruction.obj_id,
                instruction.type_or_release, instruction.dma_flag or 0, "x10", "x11",
                f"0x{instruction.word:08X}", asm[instruction_index],
            )
        )
    _write_csv(
        case / "dma_relocation_manifest.csv",
        (
            "instruction_index", "dma_index", "direction", "obj_id", "type_or_release",
            "flag", "rs1", "rs2", "word_hex", "normalized_asm",
        ),
        relocation_rows,
    )
    return case


class MainDeliveryTests(unittest.TestCase):
    def test_loads_main_package_and_only_resolves_explicit_dma_bindings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_") as temporary:
            case = _make_delivery(Path(temporary))
            delivery = load_delivery_package(case)
            self.assertEqual(delivery.case_name, "mm")
            self.assertEqual([record.modulus for record in delivery.mod_contexts], [65537])
            self.assertEqual(delivery.twiddles, ())
            self.assertTrue(
                delivery.artifact("images/input.u32.bin").readable_path.name.endswith(".dec.txt")
            )
            assignments = (
                DmaArtifactAssignment(0, "constants/mod_ctx.u32.bin", 0, 1, "mod_ctx"),
                DmaArtifactAssignment(1, "images/input.u32.bin", 0, 2, "coefficient"),
                DmaArtifactAssignment(2, "images/expected.u32.bin", 0, 2, "coefficient"),
            )
            resolved = delivery.resolve_dma_bindings(assignments)
            self.assertEqual([item.line_offset for item in resolved], [4, 0, 2])
            with self.assertRaisesRegex(DeliveryValidationError, "missing DMA indices 2"):
                delivery.resolve_dma_bindings(assignments[:2])

    def test_rejects_a_line_map_path_that_escapes_the_package(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_escape_") as temporary:
            case = _make_delivery(Path(temporary))
            line_map = case / "test_data" / "hardware" / "line_map.csv"
            contents = line_map.read_text(encoding="utf-8")
            line_map.write_text(
                contents.replace("images/input.u32.bin", "../input.u32.bin", 1),
                encoding="utf-8",
            )
            with self.assertRaises(DeliveryValidationError):
                load_delivery_package(case)

    def test_accepts_the_scheme_package_params_format_from_current_main(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_format2_") as temporary:
            case = _make_delivery(Path(temporary))
            params_path = case / "test_data" / "params.json"
            params = json.loads(params_path.read_text(encoding="utf-8"))
            params.update(
                {
                    "format_version": 2,
                    "scheme": "CKKS",
                    "input_domain": "host complex slots -> coefficient/RNS-Q",
                    "output_domain": "plaintext/NTT/Q",
                }
            )
            params_path.write_text(json.dumps(params), encoding="utf-8")

            delivery = load_delivery_package(case)

            self.assertEqual(delivery.params["format_version"], 2)
            self.assertEqual(delivery.params["scheme"], "CKKS")

    def test_accepts_terminal_bfv_t_context_without_repeated_plaintext_modulus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_bfv_t_") as temporary:
            case = _make_delivery(Path(temporary))
            params_path = case / "test_data" / "params.json"
            params = json.loads(params_path.read_text(encoding="utf-8"))
            params.update(
                {
                    "format_version": 2,
                    "scheme": "BFV",
                    "context_order": "Q|Pks|B|m_sk|t",
                    "t_mod_id": 0,
                }
            )
            params_path.write_text(json.dumps(params), encoding="utf-8")

            delivery = load_delivery_package(case)

            self.assertEqual(delivery.mod_contexts[0].modulus, 65537)

    def test_rejects_ambiguous_t_context_without_plaintext_modulus(self) -> None:
        params = {
            "format_version": 2,
            "scheme": "BGV",
            "context_order": "Q|P|t",
            "t_mod_id": 0,
        }
        with self.assertRaisesRegex(DeliveryValidationError, "may be omitted only"):
            delivery_module._expected_twiddle_basis_indices(params, (65537,))

    def test_rejects_main_validation_limit_violations(self) -> None:
        mutations = (
            ("NTT object limits", lambda params, abi: (params.update(N=131072), abi.update(N=131072))),
            ("prime values", lambda params, abi: params.update(moduli=[81921])),
            (
                "MOD_ID capacity",
                lambda params, abi: (
                    params.update(moduli=[65537] * 257),
                    abi.update(modulus_count=257),
                ),
            ),
            ("frozen PE range", lambda params, abi: abi["mod_ctx"].update(q_min=3)),
        )
        for expected_message, mutate in mutations:
            with self.subTest(expected_message=expected_message):
                with tempfile.TemporaryDirectory(prefix="hpu_delivery_limits_") as temporary:
                    case = _make_delivery(Path(temporary))
                    params_path = case / "test_data" / "params.json"
                    abi_path = case / "test_data" / "hardware" / "abi.json"
                    params = json.loads(params_path.read_text(encoding="utf-8"))
                    abi = json.loads(abi_path.read_text(encoding="utf-8"))
                    mutate(params, abi)
                    params_path.write_text(json.dumps(params), encoding="utf-8")
                    abi_path.write_text(json.dumps(abi), encoding="utf-8")
                    with self.assertRaisesRegex(DeliveryValidationError, expected_message):
                        load_delivery_package(case)

    def test_twiddle_map_must_cover_the_complete_line_map_schedule(self) -> None:
        n = 128
        modulus = 65537
        rows: list[tuple[object, ...]] = []
        artifacts: dict[str, ArtifactSpan] = {}
        line_offset = 0

        def add(
            direction: str,
            phase: str,
            stage: int,
            value_count: int,
            basis_index: int = 0,
        ) -> None:
            nonlocal line_offset
            line_count = (value_count + 63) // 64
            stage_name = f"stage_{stage:02d}" if stage >= 0 else phase
            path = (
                f"constants/twiddle/{direction}/basis_{basis_index:02d}/"
                f"{stage_name}.u32.bin"
            )
            batch_count = n // 128 if phase == "butterfly" else 1
            per_batch = 64 if phase == "butterfly" else n
            rows.append(
                (
                    direction, basis_index, modulus, phase, stage, value_count, batch_count,
                    per_batch, "0x00000001", "0x00000000", path, line_offset,
                    line_count,
                )
            )
            artifacts[path] = ArtifactSpan(
                relative_path=path,
                binary_path=Path("/unused") / path,
                readable_path=None,
                role="twiddle",
                shape=str(value_count),
                address_byte=0x10000000 + line_offset * 256,
                line_offset=line_offset,
                line_count=line_count,
                payload_words=value_count,
                payload_bytes=value_count * 4,
                padded_words=line_count * 64,
                padded_bytes=line_count * 256,
            )
            line_offset += line_count

        add("ntt", "pre_twist", -1, n)
        for stage in range(7):
            add("ntt", "butterfly", stage, n // 2)
        for stage in range(7):
            add("intt", "butterfly", stage, n // 2)
        add("intt", "post_untwist_scale", -1, n)

        with tempfile.TemporaryDirectory(prefix="hpu_delivery_twiddles_") as temporary:
            path = Path(temporary) / "twiddle_map.csv"
            _write_csv(path, delivery_module._TWIDDLE_FIELDS, rows)
            records = delivery_module._read_twiddles(path, n, (modulus,), {0}, artifacts)
            self.assertEqual(len(records), 16)
            _write_csv(path, delivery_module._TWIDDLE_FIELDS, rows[:-1])
            with self.assertRaisesRegex(DeliveryValidationError, "complete"):
                delivery_module._read_twiddles(path, n, (modulus,), {0}, artifacts)

            add("ntt", "pre_twist", -1, n, 1)
            for stage in range(7):
                add("ntt", "butterfly", stage, n // 2, 1)
            for stage in range(7):
                add("intt", "butterfly", stage, n // 2, 1)
            add("intt", "post_untwist_scale", -1, n, 1)
            _write_csv(path, delivery_module._TWIDDLE_FIELDS, rows)
            with self.assertRaisesRegex(DeliveryValidationError, "complete"):
                delivery_module._read_twiddles(
                    path,
                    n,
                    (modulus, modulus),
                    {0},
                    artifacts,
                )
            records = delivery_module._read_twiddles(
                path,
                n,
                (modulus, modulus),
                {0, 1},
                artifacts,
            )
            self.assertEqual(len(records), 32)

    def test_accepts_only_the_declared_auto_inverse_twiddle_profile(self) -> None:
        n = 128
        modulus = 65537
        rows: list[tuple[object, ...]] = []
        artifacts: dict[str, ArtifactSpan] = {}
        line_offset = 0

        def add(direction: str, phase: str, stage: int, value_count: int) -> None:
            nonlocal line_offset
            line_count = (value_count + 63) // 64
            stage_name = f"stage_{stage:02d}" if stage >= 0 else phase
            path = f"constants/twiddle/{direction}/basis_00/{stage_name}.u32.bin"
            batch_count = n // 128 if phase == "butterfly" else 1
            per_batch = 64 if phase == "butterfly" else n
            rows.append(
                (
                    direction, 0, modulus, phase, stage, value_count, batch_count,
                    per_batch, "0x00000001", "0x00000000", path, line_offset,
                    line_count,
                )
            )
            artifacts[path] = ArtifactSpan(
                relative_path=path,
                binary_path=Path("/unused") / path,
                readable_path=None,
                role="twiddle",
                shape=str(value_count),
                address_byte=0x10000000 + line_offset * 256,
                line_offset=line_offset,
                line_count=line_count,
                payload_words=value_count,
                payload_bytes=value_count * 4,
                padded_words=line_count * 64,
                padded_bytes=line_count * 256,
            )
            line_offset += line_count

        add("ntt", "pre_twist", -1, n)
        for stage in range(7):
            add("ntt", "butterfly", stage, n // 2)
        for stage in range(7):
            add("intt", "butterfly", stage, n // 2)
        add("intt", "post_untwist_scale", -1, n)
        for stage in range(7):
            add("auto_intt_g3", "butterfly", stage, n // 2)
        add("auto_intt_g3", "post_untwist_scale", -1, n)

        with tempfile.TemporaryDirectory(prefix="hpu_delivery_auto_twiddles_") as temporary:
            path = Path(temporary) / "twiddle_map.csv"
            _write_csv(path, delivery_module._TWIDDLE_FIELDS, rows)
            with self.assertRaisesRegex(DeliveryValidationError, "invalid direction"):
                delivery_module._read_twiddles(
                    path,
                    n,
                    (modulus,),
                    {0},
                    artifacts,
                )

            records = delivery_module._read_twiddles(
                path,
                n,
                (modulus,),
                {0},
                artifacts,
                frozenset({"auto_intt_g3"}),
            )
            self.assertEqual(len(records), 24)

    def test_reads_only_a_safe_auto_layout_profile_declaration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpu_delivery_auto_layout_") as temporary:
            test_data_root = Path(temporary)
            layout_path = test_data_root / "AUTO_LAYOUT.json"
            layout_path.write_text(
                json.dumps({"inverse_twiddle_profile": "auto_intt_g3"}),
                encoding="utf-8",
            )
            self.assertEqual(
                delivery_module._declared_inverse_twiddle_profiles(
                    {"operation": "auto"},
                    test_data_root,
                ),
                frozenset({"auto_intt_g3"}),
            )

            layout_path.write_text(
                json.dumps({"inverse_twiddle_profile": "../escape"}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DeliveryValidationError, "safe custom profile"):
                delivery_module._declared_inverse_twiddle_profiles(
                    {"operation": "auto"},
                    test_data_root,
                )


if __name__ == "__main__":
    unittest.main()
