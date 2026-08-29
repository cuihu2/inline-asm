from __future__ import annotations

import unittest

from tools.hpu_fhe_semantic_sim.validation import (
    LINE_BYTES,
    MAX_MOD_CONTEXTS,
    UINT32_MAX,
    WORDS_PER_LINE,
    has_mod_context_capacity,
    is_power_of_two,
    is_prime,
    is_valid_ntt_size,
    parse_shape,
    require_fields,
    require_int,
    require_mapping,
    require_safe_name,
    require_text,
    require_uint32,
    shape_words,
)


class AbiValidationTests(unittest.TestCase):
    def test_frozen_line_and_mod_context_capacity(self) -> None:
        self.assertEqual(LINE_BYTES, 256)
        self.assertEqual(WORDS_PER_LINE, 64)
        self.assertEqual(MAX_MOD_CONTEXTS, 256)
        self.assertTrue(has_mod_context_capacity(256))
        self.assertTrue(has_mod_context_capacity(252, 3, 1))
        self.assertFalse(has_mod_context_capacity(256, reserved_contexts=1))
        self.assertFalse(has_mod_context_capacity(253, 3, 1))
        self.assertFalse(has_mod_context_capacity(True))

    def test_power_of_two_and_ntt_size_limits_match_main(self) -> None:
        self.assertTrue(is_power_of_two(4096))
        self.assertFalse(is_power_of_two(4095))
        self.assertFalse(is_power_of_two(True))
        self.assertTrue(is_valid_ntt_size(128))
        self.assertTrue(is_valid_ntt_size(65536))
        self.assertFalse(is_valid_ntt_size(64))
        self.assertFalse(is_valid_ntt_size(131072))

    def test_prime_validation_rejects_nonprime_and_boolean_values(self) -> None:
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(65537))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(81921))
        self.assertFalse(is_prime(True))

    def test_json_object_and_field_validation_is_fail_closed(self) -> None:
        value = require_mapping({"required": 1, "optional": 2}, "record")
        require_fields(value, "record", {"required"}, {"optional"})
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            require_mapping([], "record")
        with self.assertRaisesRegex(ValueError, "missing fields: required"):
            require_fields({}, "record", {"required"})
        with self.assertRaisesRegex(ValueError, "unknown fields: extra"):
            require_fields({"required": 1, "extra": 2}, "record", {"required"})

    def test_scalar_and_name_validation_rejects_ambiguous_values(self) -> None:
        self.assertEqual(require_int(7, "value", 1, 8), 7)
        self.assertEqual(require_uint32(UINT32_MAX, "word"), UINT32_MAX)
        self.assertEqual(require_text("  value  ", "text"), "value")
        self.assertEqual(require_safe_name("case-01.bin", "name"), "case-01.bin")
        for value in (True, 0, 9):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    require_int(value, "value", 1, 8)
        with self.assertRaises(ValueError):
            require_uint32(UINT32_MAX + 1, "word")
        for name in ("", "../case", "a/b", ".", ".."):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    require_safe_name(name, "name")

    def test_shape_validation_and_word_count(self) -> None:
        self.assertEqual(parse_shape(128, "shape"), (128,))
        self.assertEqual(parse_shape([2, 4, 8], "shape"), (2, 4, 8))
        self.assertEqual(shape_words((2, 4, 8)), 64)
        for shape in ([], [2, 0], [2, True], "128"):
            with self.subTest(shape=shape):
                with self.assertRaises(ValueError):
                    parse_shape(shape, "shape")


if __name__ == "__main__":
    unittest.main()
