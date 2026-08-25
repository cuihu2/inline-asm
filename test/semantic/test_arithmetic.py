from array import array
import unittest

from tools.hpu_fhe_semantic_sim.arithmetic import apply_arithmetic


class ArithmeticSemanticsTests(unittest.TestCase):
    def test_arithmetic_accepts_sequences_and_returns_u32_array(self) -> None:
        result = apply_arithmetic(
            "padd",
            None,
            array("I", [1, 256]),
            array("I", [2, 2]),
            257,
        )

        self.assertIsInstance(result, array)
        self.assertEqual(result.typecode, "I")
        self.assertEqual(list(result), [3, 1])

    def test_padd_returns_canonical_residues(self) -> None:
        self.assertEqual(
            list(apply_arithmetic(
                "padd",
                None,
                [0, 256, 200],
                [1, 1, 100],
                257,
            )),
            [1, 0, 43],
        )

    def test_psub_wraps_negative_differences(self) -> None:
        self.assertEqual(
            list(apply_arithmetic(
                "psub",
                None,
                [0, 1, 256],
                [1, 256, 1],
                257,
            )),
            [256, 2, 255],
        )

    def test_pmul_accepts_an_object_or_cimm8(self) -> None:
        self.assertEqual(
            list(apply_arithmetic("pmul", None, [2, 128, 256], [3, 4, 256], 257)),
            [6, 255, 1],
        )
        self.assertEqual(
            list(apply_arithmetic("pmul", None, [2, 128, 256], 3, 257)),
            [6, 127, 254],
        )

    def test_pmac_reads_and_updates_the_accumulator_value(self) -> None:
        self.assertEqual(
            list(apply_arithmetic(
                "pmac",
                [10, 20, 30],
                [2, 128, 256],
                [3, 4, 256],
                257,
            )),
            [16, 18, 31],
        )
        self.assertEqual(
            list(apply_arithmetic("pmac", [10, 20, 30], [2, 128, 256], 3, 257)),
            [16, 147, 27],
        )

    def test_invalid_arithmetic_operands_fail_closed(self) -> None:
        invalid_calls = (
            lambda: apply_arithmetic("padd", None, [1], [2], 1),
            lambda: apply_arithmetic("padd", None, [1], [2], 0x1_0000_0001),
            lambda: apply_arithmetic("padd", None, [1, 2], [3], 257),
            lambda: apply_arithmetic("padd", None, [1], 3, 257),
            lambda: apply_arithmetic("pmul", None, [1], 256, 257),
            lambda: apply_arithmetic("pmac", None, [1], [2], 257),
            lambda: apply_arithmetic("unknown", None, [1], [2], 257),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()


if __name__ == "__main__":
    unittest.main()
