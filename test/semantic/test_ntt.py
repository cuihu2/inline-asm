from array import array
import unittest

from tools.hpu_fhe_semantic_sim.ntt import (
    bit_reverse_index,
    find_ntt_prime,
    find_primitive_2n_root,
    generate_hardware_intt_twiddles,
    generate_hardware_ntt_twiddles,
    hardware_ntt_layout,
    is_prime,
    is_primitive_2n_root,
    logical_cyclic_ntt,
    logical_negacyclic_ntt,
    p_inverse_permute,
    pintt_stage,
    pntt_stage,
    p_permute,
)


class NttSemanticsTests(unittest.TestCase):
    def test_bit_reverse_index_uses_the_full_power_of_two_width(self) -> None:
        self.assertEqual(bit_reverse_index(0, 128), 0)
        self.assertEqual(bit_reverse_index(1, 128), 64)
        self.assertEqual(bit_reverse_index(3, 128), 96)
        self.assertEqual(bit_reverse_index(127, 128), 127)

    def test_p_network_and_inverse_restore_all_128_registers(self) -> None:
        registers = list(range(128))
        permuted = p_permute(registers)

        self.assertEqual(permuted[1], 2)
        self.assertEqual(permuted[64], 1)
        self.assertEqual(p_inverse_permute(permuted), registers)

    def test_prime_and_primitive_root_helpers_validate_n_128(self) -> None:
        q = find_ntt_prime(250, 256)
        psi = find_primitive_2n_root(q, 128)

        self.assertEqual(q, 257)
        self.assertTrue(is_prime(q))
        self.assertFalse(is_prime(255))
        self.assertTrue(is_primitive_2n_root(psi, 128, q))
        self.assertEqual(pow(psi, 128, q), q - 1)
        self.assertEqual(pow(psi, 256, q), 1)

    def test_invalid_ntt_parameters_fail_closed(self) -> None:
        invalid_calls = (
            lambda: bit_reverse_index(0, 127),
            lambda: p_permute([0] * 127),
            lambda: generate_hardware_ntt_twiddles(64, 1, 257),
            lambda: generate_hardware_ntt_twiddles(128, 1, 257),
            lambda: generate_hardware_intt_twiddles(128, 1, 257),
            lambda: logical_cyclic_ntt([0] * 128, 1, 257),
            lambda: pntt_stage([0] * 128, [1] * 63, 0, 257),
            lambda: pntt_stage([0] * 128, [1] * 64, 0, 0x1_0000_0001),
            lambda: pntt_stage([257] + [0] * 127, [1] * 64, 0, 257),
            lambda: pntt_stage([0] * 128, [257] + [1] * 63, 0, 257),
            lambda: pintt_stage([257] + [0] * 127, [1] * 64, 0, 257),
            lambda: pintt_stage([0] * 128, [1] * 64, 7, 257),
        )
        for call in invalid_calls:
            with self.subTest(call=call), self.assertRaises(ValueError):
                call()

    def test_logical_cyclic_ntt_round_trip_at_n_128(self) -> None:
        q = 257
        psi = find_primitive_2n_root(q, 128)
        omega = pow(psi, 2, q)
        values = [(17 * index + 3) % q for index in range(128)]

        transformed = logical_cyclic_ntt(values, omega, q)
        restored = logical_cyclic_ntt(transformed, omega, q, inverse=True)

        self.assertEqual(restored, values)

    def test_logical_negacyclic_ntt_round_trip_at_n_128(self) -> None:
        q = 257
        psi = find_primitive_2n_root(q, 128)
        values = [(index * index + 5 * index + 7) % q for index in range(128)]

        transformed = logical_negacyclic_ntt(values, psi, q)
        restored = logical_negacyclic_ntt(transformed, psi, q, inverse=True)

        self.assertEqual(restored, values)

    def test_forward_hardware_twiddle_tables_cover_every_stage_and_lane(self) -> None:
        q = 257
        psi = find_primitive_2n_root(q, 128)
        tables = generate_hardware_ntt_twiddles(128, psi * psi % q, q)

        self.assertEqual(len(tables), 7)
        self.assertTrue(all(len(stage) == 64 for stage in tables))
        self.assertEqual(tables[0], [1] * 64)
        self.assertTrue(all(0 <= value < q for stage in tables for value in stage))

    def test_inverse_hardware_twiddles_cover_the_dual_schedule(self) -> None:
        q = 257
        psi = find_primitive_2n_root(q, 128)
        tables = generate_hardware_intt_twiddles(128, psi * psi % q, q)

        self.assertEqual(len(tables), 7)
        self.assertTrue(all(len(stage) == 64 for stage in tables))
        self.assertTrue(all(0 <= value < q for stage in tables for value in stage))

    def test_pntt_stage_consumes_the_supplied_twiddle_values(self) -> None:
        values = array("I", [0] * 128)
        values[0] = 5
        values[1] = 7
        twiddles = array("I", [1] * 64)
        twiddles[0] = 3

        result = pntt_stage(values, twiddles, stage=0, q=257)

        expected = [0] * 128
        expected[0] = 26
        expected[64] = 241
        self.assertIsInstance(result, array)
        self.assertEqual(result.typecode, "I")
        self.assertEqual(list(result), expected)

    def test_pintt_stage_consumes_the_supplied_dual_schedule_twiddles(self) -> None:
        values = array("I", [0] * 128)
        values[0] = 5
        values[64] = 7
        twiddles = array("I", [1] * 64)
        twiddles[0] = 3

        result = pintt_stage(values, twiddles, inverse_stage=0, q=257)

        expected = [0] * 128
        expected[0] = 26
        expected[1] = 241
        self.assertIsInstance(result, array)
        self.assertEqual(result.typecode, "I")
        self.assertEqual(list(result), expected)

    def test_hardware_pntt_pipeline_matches_logical_negacyclic_ntt(self) -> None:
        n = 128
        q = 257
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        logical_input = [(11 * index * index + 7 * index + 5) % q for index in range(n)]
        physical = [
            logical_input[bit_reverse_index(position, n)]
            * pow(psi, bit_reverse_index(position, n), q)
            % q
            for position in range(n)
        ]

        for stage, twiddles in enumerate(generate_hardware_ntt_twiddles(n, omega, q)):
            physical = pntt_stage(physical, twiddles, stage, q)

        logical_output = logical_negacyclic_ntt(logical_input, psi, q)
        layout = hardware_ntt_layout(n)
        self.assertEqual(list(physical), [logical_output[index] for index in layout])

    def test_hardware_layout_handles_interleaved_batches_at_n_256(self) -> None:
        n = 256
        q = find_ntt_prime(2 * n + 1, 2 * n)
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        logical_input = [(31 * index + 9) % q for index in range(n)]
        physical = array(
            "I",
            (
                logical_input[bit_reverse_index(position, n)]
                * pow(psi, bit_reverse_index(position, n), q)
                % q
                for position in range(n)
            ),
        )

        for stage, twiddles in enumerate(generate_hardware_ntt_twiddles(n, omega, q)):
            physical = pntt_stage(physical, twiddles, stage, q)

        logical_output = logical_negacyclic_ntt(logical_input, psi, q)
        layout = hardware_ntt_layout(n)
        self.assertEqual(sorted(layout), list(range(n)))
        self.assertEqual(list(physical), [logical_output[index] for index in layout])

        for inverse_stage, twiddles in enumerate(
            generate_hardware_intt_twiddles(n, omega, q)
        ):
            physical = pintt_stage(physical, twiddles, inverse_stage, q)
        n_inverse = pow(n, -1, q)
        psi_inverse = pow(psi, -1, q)
        restored = [
            physical[position]
            * n_inverse
            * pow(psi_inverse, bit_reverse_index(position, n), q)
            % q
            for position in range(n)
        ]
        self.assertEqual(
            restored,
            [logical_input[bit_reverse_index(position, n)] for position in range(n)],
        )

    def test_hardware_pntt_pintt_round_trip_restores_coefficients(self) -> None:
        n = 128
        q = 257
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        logical_input = [(19 * index + 23) % q for index in range(n)]
        physical = array(
            "I",
            (
                logical_input[bit_reverse_index(position, n)]
                * pow(psi, bit_reverse_index(position, n), q)
                % q
                for position in range(n)
            ),
        )

        for stage, twiddles in enumerate(generate_hardware_ntt_twiddles(n, omega, q)):
            physical = pntt_stage(physical, twiddles, stage, q)
        for inverse_stage, twiddles in enumerate(
            generate_hardware_intt_twiddles(n, omega, q)
        ):
            physical = pintt_stage(physical, twiddles, inverse_stage, q)

        n_inverse = pow(n, -1, q)
        psi_inverse = pow(psi, -1, q)
        restored = [
            physical[position]
            * n_inverse
            * pow(psi_inverse, bit_reverse_index(position, n), q)
            % q
            for position in range(n)
        ]
        expected = [logical_input[bit_reverse_index(position, n)] for position in range(n)]
        self.assertEqual(restored, expected)

    def test_hardware_pointwise_path_matches_schoolbook_negacyclic_convolution(self) -> None:
        n = 128
        q = 257
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        left = [0] * n
        right = [0] * n
        left[0], left[1], left[127] = 3, 5, 7
        right[0], right[2], right[127] = 11, 13, 17

        def hardware_forward(values: list[int]) -> array:
            physical = array(
                "I",
                (
                    values[bit_reverse_index(position, n)]
                    * pow(psi, bit_reverse_index(position, n), q)
                    % q
                    for position in range(n)
                ),
            )
            for stage, twiddles in enumerate(
                generate_hardware_ntt_twiddles(n, omega, q)
            ):
                physical = pntt_stage(physical, twiddles, stage, q)
            return physical

        left_ntt = hardware_forward(left)
        right_ntt = hardware_forward(right)
        product = array("I", (a * b % q for a, b in zip(left_ntt, right_ntt)))
        for inverse_stage, twiddles in enumerate(
            generate_hardware_intt_twiddles(n, omega, q)
        ):
            product = pintt_stage(product, twiddles, inverse_stage, q)

        actual = [0] * n
        n_inverse = pow(n, -1, q)
        psi_inverse = pow(psi, -1, q)
        for position, value in enumerate(product):
            coefficient_index = bit_reverse_index(position, n)
            actual[coefficient_index] = (
                value
                * n_inverse
                * pow(psi_inverse, coefficient_index, q)
                % q
            )

        expected = [0] * n
        for left_index, left_value in enumerate(left):
            for right_index, right_value in enumerate(right):
                degree = left_index + right_index
                product_value = left_value * right_value
                if degree < n:
                    expected[degree] = (expected[degree] + product_value) % q
                else:
                    expected[degree - n] = (
                        expected[degree - n] - product_value
                    ) % q
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()
