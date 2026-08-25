import unittest
from array import array
from types import SimpleNamespace

from tools.hpu_fhe_semantic_sim.isa import Instruction
from tools.hpu_fhe_semantic_sim.machine import MachineState, SimulationError, execute_step
from tools.hpu_fhe_semantic_sim.ntt import (
    find_primitive_2n_root,
    generate_hardware_intt_twiddles,
    generate_hardware_ntt_twiddles,
    pintt_stage,
    pntt_stage,
)


class FakeMemory:
    def __init__(self, words: list[int]) -> None:
        self.words = array("I", words)

    def read_words(self, line_offset: int, line_count: int, payload_words: int | None = None):
        begin = line_offset * 64
        count = line_count * 64 if payload_words is None else payload_words
        return array("I", self.words[begin : begin + count])

    def write_words(self, line_offset: int, line_count: int, words):
        begin = line_offset * 64
        padded = array("I", words)
        padded.extend([0] * (line_count * 64 - len(padded)))
        self.words[begin : begin + line_count * 64] = padded


class MachineArithmeticTest(unittest.TestCase):
    def test_padd_updates_destination_with_active_modulus(self) -> None:
        state = MachineState(n=4)
        state.active_mod_id = 0
        state.active_q = 17
        state.set_object(0, array("I", [0, 1, 16, 9]), domain="coefficient")
        state.set_object(1, array("I", [1, 16, 2, 12]), domain="coefficient")

        record = execute_step(
            state,
            Instruction(mnemonic="padd", word=0x0400400B, pdst=2, psrc1=0, psrc2=1),
        )

        self.assertEqual(list(state.objects[2].data), [1, 0, 1, 4])
        self.assertEqual(record["instruction_index"], 0)
        self.assertEqual(record["changed_object"], 2)
        self.assertEqual(record["active_q"], 17)

    def test_arithmetic_rejects_unfrozen_mode_or_flag(self) -> None:
        state = MachineState(n=4)
        state.active_q = 17
        state.set_object(0, [1, 2, 3, 4], domain="coefficient")
        state.set_object(1, [4, 3, 2, 1], domain="coefficient")

        for mode, flag in ((2, 0), (0, 1)):
            with self.subTest(mode=mode, flag=flag):
                with self.assertRaises(SimulationError) as context:
                    execute_step(
                        state,
                        Instruction(
                            mnemonic="padd",
                            word=0x0400400B,
                            pdst=2,
                            psrc1=0,
                            psrc2=1,
                            mode=mode,
                            flag=flag,
                        ),
                    )
                self.assertEqual(context.exception.code, "UNSUPPORTED_AR3_MODE_FLAG")

    def test_pfree_releases_a_live_object(self) -> None:
        state = MachineState(n=4)
        state.set_object(4, array("I", [17, 1, 0, 0]), data_type=2, domain="mod_ctx")

        record = execute_step(
            state,
            Instruction(mnemonic="pfree", word=0x8100000B, obj_id=4),
        )

        self.assertFalse(state.objects[4].allocated)
        self.assertEqual(state.objects[4].payload_words, 0)
        self.assertEqual(state.objects[4].physical_generation, 0)

    def test_psync_marks_program_complete(self) -> None:
        state = MachineState(n=4)

        record = execute_step(
            state,
            Instruction(mnemonic="psync", word=0x7000000B),
        )

        self.assertTrue(state.program_complete)
        self.assertEqual(record["status"], "PASS")

    def test_pmodld_activates_q32_mu48_context(self) -> None:
        q = 65537
        mu = (1 << 64) // q
        state = MachineState(n=128)
        state.set_object(
            4,
            array("I", [q, mu & 0xFFFFFFFF, (mu >> 32) & 0xFFFF, 0]),
            data_type=2,
            domain="mod_ctx",
        )
        state.modulus_table_object = 4

        execute_step(
            state,
            Instruction(mnemonic="pmodld", word=0x6000000B, mod_id=0),
        )

        self.assertEqual(state.active_mod_id, 0)
        self.assertEqual(state.active_q, q)
        self.assertEqual(state.active_mu, mu)

    def test_dload_reads_the_resolved_ddr_span(self) -> None:
        memory = FakeMemory(list(range(128)))
        state = MachineState(n=64, memory=memory)
        binding = SimpleNamespace(
            dma_index=0,
            instruction_index=0,
            direction="dload",
            obj_id=0,
            type_or_release=1,
            flag=0,
            line_offset=1,
            line_count=1,
            payload_words=64,
            domain="coefficient",
            role="input",
        )

        record = execute_step(
            state,
            Instruction(
                mnemonic="dload",
                word=0x00B5002B,
                rs1=10,
                rs2=11,
                obj_id=0,
                type_or_release=1,
                dma_flag=0,
            ),
            binding,
        )

        self.assertEqual(list(state.objects[0].data), list(range(64, 128)))
        self.assertEqual(record["dma_index"], 0)
        self.assertEqual(state.dma_index, 1)

    def test_dstore_writes_ddr_and_releases_the_object(self) -> None:
        memory = FakeMemory([0] * 128)
        state = MachineState(n=64, memory=memory)
        state.set_object(2, array("I", range(64)), domain="coefficient")
        binding = SimpleNamespace(
            dma_index=0,
            instruction_index=0,
            direction="dstore",
            obj_id=2,
            type_or_release=1,
            flag=0,
            line_offset=1,
            line_count=1,
            payload_words=64,
            domain="coefficient",
            role="output",
        )

        record = execute_step(
            state,
            Instruction(
                mnemonic="dstore",
                word=0x00B5542B,
                rs1=10,
                rs2=11,
                obj_id=2,
                type_or_release=1,
                dma_flag=0,
            ),
            binding,
        )

        self.assertEqual(list(memory.words[64:128]), list(range(64)))
        self.assertEqual(record["dma_index"], 0)
        self.assertFalse(state.objects[2].allocated)
        self.assertEqual(state.dma_index, 1)

    def test_pntt_executes_one_physical_stage(self) -> None:
        n = 128
        q = 65537
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        twiddles = generate_hardware_ntt_twiddles(n, omega, q)[0]
        values = [index % q for index in range(n)]
        expected = pntt_stage(values, twiddles, 0, q)
        state = MachineState(n=n)
        state.active_mod_id = 0
        state.active_q = q
        state.set_object(0, values, domain="coefficient_bitrev")
        state.set_object(1, twiddles, domain="twiddle", role="ntt_stage_0")

        execute_step(
            state,
            Instruction(
                mnemonic="pntt",
                word=0x4040000B,
                pdst=0,
                psrc1=1,
                stage=0,
                mode=0,
                flag=0,
            ),
        )

        self.assertEqual(list(state.objects[0].data), list(expected))
        self.assertEqual(state.objects[0].domain, "pntt_stage_0")
        self.assertEqual(state.objects[0].physical_generation, 1)

    def test_pintt_executes_one_dual_schedule_stage(self) -> None:
        n = 128
        q = 65537
        psi = find_primitive_2n_root(q, n)
        omega = psi * psi % q
        twiddles = generate_hardware_intt_twiddles(n, omega, q)[0]
        values = [index % q for index in range(n)]
        expected = pintt_stage(values, twiddles, 0, q)
        state = MachineState(n=n)
        state.active_mod_id = 0
        state.active_q = q
        state.set_object(0, values, domain="ntt_physical")
        state.set_object(1, twiddles, domain="twiddle", role="intt_stage_0")

        execute_step(
            state,
            Instruction(
                mnemonic="pintt",
                word=0x5040000B,
                pdst=0,
                psrc1=1,
                stage=0,
                mode=0,
                flag=0,
            ),
        )

        self.assertEqual(list(state.objects[0].data), list(expected))
        self.assertEqual(state.objects[0].domain, "pintt_stage_0")


if __name__ == "__main__":
    unittest.main()
