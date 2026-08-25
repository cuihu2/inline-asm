import unittest

from tools.hpu_fhe_semantic_sim.isa import (
    decode_instruction,
    expected_command26,
    parse_asm_instruction,
    parse_instruction_word,
)


class DecodeInstructionTest(unittest.TestCase):
    def test_parses_all_assembly_formats_for_step_mode(self) -> None:
        cases = {
            "padd p2, p0, p1": 0x0400400B,
            "pmul p2, p0, 255": 0x243FC10B,
            "pntt p0, p3, 15, 0, 0": 0x40C03C0B,
            "pintt p0, p3, 15, 0, 0": 0x50C03C0B,
            "pmodld 255": 0x603FC00B,
            "pfree p4": 0x8100000B,
            "psync": 0x7000000B,
            "dload x10, x11, p4, 2, 1": 0x00B5292B,
            "dstore x10, x11, p2, 1": 0x00B5542B,
        }
        for source, word in cases.items():
            with self.subTest(source=source):
                self.assertEqual(parse_asm_instruction(source).word, word)
    def test_parses_binary_and_hex_instruction_text(self) -> None:
        word = 0x0400400B
        binary = f"{word:032b}"

        self.assertEqual(parse_instruction_word(binary), word)
        self.assertEqual(parse_instruction_word(f"0b{binary}"), word)
        self.assertEqual(parse_instruction_word("  0x0400400B\n"), word)

    def test_rejects_malformed_instruction_text(self) -> None:
        invalid_text = (
            "",
            "0" * 31,
            "0" * 32 + "1",
            "0b1021",
            "0x100000000",
            "0x0400400G",
        )

        for text in invalid_text:
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    parse_instruction_word(text)

    def test_rejects_values_outside_unsigned_32_bit_words(self) -> None:
        invalid_values = (-1, 1 << 32 | 0x0400400B, True, "0x0400400B")

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    decode_instruction(value)  # type: ignore[arg-type]

    def test_rejects_non_hpu_and_unknown_custom0_opcodes(self) -> None:
        invalid_words = (0x00000013, 0x9000000B)

        for word in invalid_words:
            with self.subTest(word=f"0x{word:08X}"):
                with self.assertRaises(ValueError):
                    decode_instruction(word)
                with self.assertRaises(ValueError):
                    expected_command26(word)

    def test_rejects_reserved_bits_in_each_instruction_format(self) -> None:
        invalid_words = {
            "ar3": 0x0400440B,
            "stg": 0x40C07C0B,
            "mod": 0x603FC08B,
            "sync": 0x7000008B,
            "pfree": 0x8300000B,
            "dma": 0x00B529AB,
        }

        for format_name, word in invalid_words.items():
            with self.subTest(format_name=format_name):
                with self.assertRaisesRegex(ValueError, "reserved"):
                    decode_instruction(word)

    def test_rejects_unsupported_arithmetic_and_dma_field_combinations(self) -> None:
        invalid_words = {
            "padd_immediate": 0x0400410B,
            "dload_type_3": 0x00B5302B,
            "dstore_release_2": 0x00B5642B,
            "dstore_small_bank": 0x00B5552B,
        }

        for case_name, word in invalid_words.items():
            with self.subTest(case_name=case_name):
                with self.assertRaises(ValueError):
                    decode_instruction(word)

    def test_decodes_frozen_padd_and_precodes_it(self) -> None:
        instruction = decode_instruction(0x0400400B)

        self.assertEqual(instruction.mnemonic, "padd")
        self.assertEqual(instruction.word, 0x0400400B)
        self.assertEqual(instruction.pdst, 2)
        self.assertEqual(instruction.psrc1, 0)
        self.assertEqual(instruction.psrc2, 1)
        self.assertIsNone(instruction.imm8)
        self.assertEqual(expected_command26(instruction.word), 0x0080080)

    def test_decodes_frozen_register_arithmetic_words(self) -> None:
        cases = (
            (0x1400400B, "psub", 0x0280080),
            (0x2400400B, "pmul", 0x0480080),
            (0x3400400B, "pmac", 0x0680080),
        )

        for word, mnemonic, command26 in cases:
            with self.subTest(mnemonic=mnemonic):
                instruction = decode_instruction(word)
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.pdst, 2)
                self.assertEqual(instruction.psrc1, 0)
                self.assertEqual(instruction.psrc2, 1)
                self.assertIsNone(instruction.imm8)
                self.assertEqual(instruction.mode, 0)
                self.assertEqual(instruction.flag, 0)
                self.assertEqual(expected_command26(word), command26)

    def test_preserves_encoder_supported_arithmetic_mode_bits(self) -> None:
        object_mode = decode_instruction(0x2400420B)
        self.assertEqual(object_mode.mnemonic, "pmul")
        self.assertEqual(object_mode.mode, 2)
        self.assertEqual(object_mode.psrc2, 1)
        self.assertIsNone(object_mode.imm8)

        immediate_mode = decode_instruction(0x243FC30B)
        self.assertEqual(immediate_mode.mnemonic, "pmul")
        self.assertEqual(immediate_mode.mode, 3)
        self.assertIsNone(immediate_mode.psrc2)
        self.assertEqual(immediate_mode.imm8, 255)

    def test_decodes_frozen_immediate_arithmetic_words(self) -> None:
        cases = (
            (0x243FC10B, "pmul", 0x0487F82),
            (0x343FC10B, "pmac", 0x0687F82),
        )

        for word, mnemonic, command26 in cases:
            with self.subTest(mnemonic=mnemonic):
                instruction = decode_instruction(word)
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.pdst, 2)
                self.assertEqual(instruction.psrc1, 0)
                self.assertIsNone(instruction.psrc2)
                self.assertEqual(instruction.imm8, 255)
                self.assertEqual(instruction.mode, 1)
                self.assertEqual(instruction.flag, 0)
                self.assertEqual(expected_command26(word), command26)

    def test_decodes_frozen_transform_stage_words(self) -> None:
        cases = (
            (0x40C03C0B, "pntt", 0x0818078),
            (0x50C03C0B, "pintt", 0x0A18078),
        )

        for word, mnemonic, command26 in cases:
            with self.subTest(mnemonic=mnemonic):
                instruction = decode_instruction(word)
                self.assertEqual(instruction.mnemonic, mnemonic)
                self.assertEqual(instruction.pdst, 0)
                self.assertEqual(instruction.psrc1, 3)
                self.assertEqual(instruction.stage, 15)
                self.assertEqual(instruction.mode, 0)
                self.assertEqual(instruction.flag, 0)
                self.assertEqual(expected_command26(word), command26)

    def test_decodes_frozen_configuration_and_lifecycle_words(self) -> None:
        pmodld = decode_instruction(0x603FC00B)
        self.assertEqual(pmodld.mnemonic, "pmodld")
        self.assertEqual(pmodld.mod_id, 255)
        self.assertEqual(expected_command26(pmodld.word), 0x0C07F80)

        pfree = decode_instruction(0x8100000B)
        self.assertEqual(pfree.mnemonic, "pfree")
        self.assertEqual(pfree.obj_id, 4)
        self.assertEqual(expected_command26(pfree.word), 0x1020000)

        psync = decode_instruction(0x7000000B)
        self.assertEqual(psync.mnemonic, "psync")
        self.assertEqual(psync.word, 0x7000000B)
        self.assertEqual(expected_command26(psync.word), 0x0E00000)

    def test_decodes_frozen_dma_words_and_precodes_semantic_fields(self) -> None:
        dload = decode_instruction(0x00B5292B)
        self.assertEqual(dload.mnemonic, "dload")
        self.assertEqual(dload.rs1, 10)
        self.assertEqual(dload.rs2, 11)
        self.assertEqual(dload.obj_id, 4)
        self.assertEqual(dload.type_or_release, 2)
        self.assertEqual(dload.dma_flag, 1)
        self.assertEqual(expected_command26(dload.word), 0x2000424)

        dstore = decode_instruction(0x00B5542B)
        self.assertEqual(dstore.mnemonic, "dstore")
        self.assertEqual(dstore.rs1, 10)
        self.assertEqual(dstore.rs2, 11)
        self.assertEqual(dstore.obj_id, 2)
        self.assertEqual(dstore.type_or_release, 1)
        self.assertEqual(dstore.dma_flag, 0)
        self.assertEqual(expected_command26(dstore.word), 0x2000015)


if __name__ == "__main__":
    unittest.main()
