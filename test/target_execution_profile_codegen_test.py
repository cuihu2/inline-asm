#!/usr/bin/env python3
"""Check the single-window wrapper on host C and actual RV32/RV64 CPU code.

The CPU interpreter checks custom HPU words and simulates completion events;
HPU mathematics remains covered by the existing instruction-model tests.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from target_dma_codegen_test import Cpu, Elf, tool_environment


STEM = "execution_profile_fixture"


def host_check(root):
    compiler = shutil.which("cc") or shutil.which("gcc")
    assert compiler, "a host C compiler is required"
    harness = root / "host.c"
    harness.write_text(
        f'#include "{STEM}.h"\n#include "other_profile.h"\n'
        "static int calls;\n"
        "static uint64_t clock_hook(void *user) { (void)user; ++calls; return 42; }\n"
        "static int wait_hook(void *user, size_t sync) { (void)user; (void)sync; ++calls; return 0; }\n"
        "int main(void) {\n"
        "    hpu_execution_profile_sample_t sample = { 1, 2, 1 };\n"
        "    const hpu_execution_profile_hooks_t hooks = { 0, clock_hook, wait_hook };\n"
        f"    if (hpu_run_{STEM}() != -5 || hpu_program_{STEM}(0, 0) != -5) return 1;\n"
        f"    if (hpu_run_{STEM}_profiled(0, &sample) != -1 || sample.valid) return 2;\n"
        f"    if (hpu_run_{STEM}_profiled(&hooks, 0) != -1) return 3;\n"
        f"    if (hpu_run_{STEM}_profiled(&hooks, &sample) != -4 || calls) return 4;\n"
        "    if (sample.valid || sample.start_cycles || sample.end_cycles) return 5;\n"
        "    return 0;\n}\n")
    executable = root / "host"
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    str(harness), str(root / f"{STEM}.c"), "-o", str(executable)],
                   check=True, capture_output=True, text=True)
    subprocess.run([str(executable)], check=True)
    print("Single-window wrapper host: unsupported execution and invalid arguments rejected", flush=True)


def target_harness():
    return (
        f'#include "{STEM}.h"\n#include "other_profile.h"\n'
        "volatile unsigned hardware_completed;\n"
        "static unsigned waits, clocks;\n"
        "static int failed;\n"
        "static int fail_sync = -1;\n"
        "static uint64_t ticks;\n"
        "static hpu_execution_profile_sample_t sample;\n"
        "static uint64_t clock_hook(void *user) {\n"
        "    (void)user; ticks += 17;\n"
        "    if (hardware_completed != (clocks == 0 ? 1 : 3)) failed = 1;\n"
        "    ++clocks;\n"
        '    __asm__ volatile("li x10, 12345\\n\\tli x11, 54321" : : : "x10", "x11", "memory");\n'
        "    return ticks;\n}\n"
        "static int wait_hook(void *user, size_t sync) {\n"
        "    (void)user;\n"
        "    if (sync != waits || hardware_completed != sync + 1) failed = 1;\n"
        "    ++waits; ticks += 100;\n"
        '    __asm__ volatile("li x10, 9876\\n\\tli x11, 6789" : : : "x10", "x11", "memory");\n'
        "    return (int)sync == fail_sync ? -123 : 0;\n}\n"
        "static const hpu_execution_profile_hooks_t hooks = { 0, clock_hook, wait_hook };\n"
        "int profile_success(void) {\n"
        f"    if (hpu_run_{STEM}_profiled(&hooks, &sample) != 0 || failed || waits != 4) return 1;\n"
        "    if (!sample.valid || clocks != 2 || sample.start_cycles != 117 ||\n"
        "        sample.end_cycles != 334 || sample.end_cycles - sample.start_cycles != 217) return 2;\n"
        "    return 0;\n}\n"
        "static int abort_at(int sync) {\n"
        "    fail_sync = sync;\n"
        f"    if (hpu_run_{STEM}_profiled(&hooks, &sample) != -123 || failed || waits != (unsigned)sync + 1) return 3;\n"
        "    if (sample.valid || clocks != (sync == 0 ? 0 : (sync == 3 ? 2 : 1))) return 4;\n"
        "    if (sample.start_cycles != (sync == 0 ? 0 : 117) ||\n"
        "        sample.end_cycles != (sync == 3 ? 334 : 0)) return 5;\n"
        "    return 0;\n}\n"
        "int profile_abort_preload(void) { return abort_at(0); }\n"
        "int profile_abort_middle(void) { return abort_at(1); }\n"
        "int profile_abort_end(void) { return abort_at(2); }\n"
        "int profile_abort_drain(void) { return abort_at(3); }\n")


class ProfileCpu(Cpu):
    def __init__(self, image, words, dma, psync):
        super().__init__(image, words, dma)
        self.hardware_completed = image.symbols["hardware_completed"][0]
        self.psync = psync

    def custom(self, word):
        super().custom(word)
        if word == self.psync:
            completed = self.memory(self.hardware_completed, 4)
            self.memory(self.hardware_completed, 4, completed + 1)


def target_check(root, compiler):
    environment = tool_environment(compiler)
    include = subprocess.check_output([str(compiler), "-print-file-name=include"],
                                      env=environment, text=True).strip()
    harness = root / "target.c"
    harness.write_text(target_harness())
    words = [int(word) for word in (root / "words.txt").read_text().splitlines()]
    dma = [tuple(map(int, line.split(","))) for line in (root / "dma.csv").read_text().splitlines()]
    cases = (("profile_success", 17, 6), ("profile_abort_preload", 5, 3),
             ("profile_abort_middle", 10, 5), ("profile_abort_end", 14, 5),
             ("profile_abort_drain", 17, 6))
    for bits, abi in ((32, "ilp32"), (64, "lp64")):
        for optimization in ("-O0", "-O2"):
            for entry, word_count, dma_count in cases:
                executable = root / f"{entry}-rv{bits}-{optimization[1:]}.elf"
                subprocess.run([
                    str(compiler), f"-march=rv{bits}im", f"-mabi={abi}", optimization,
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
                    "-fno-stack-protector", "-fno-pie", "-no-pie", "-nostdlib", "-nostdinc",
                    "-isystem", include, f"-B{compiler.parent}/", "-Wl,--no-relax",
                    "-Wl,--build-id=none", f"-Wl,-e,{entry}", "-Wl,-Ttext=0x10000",
                    str(harness), str(root / f"{STEM}.c"), "-o", str(executable)],
                    env=environment, check=True, capture_output=True, text=True)
                image = Elf(executable)
                ProfileCpu(image, words[:word_count], dma[:dma_count], words[4]).run(
                    check_setting_count=False)
                print(f"Single-window wrapper RV{bits} {optimization} {entry}: PASS", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generator", type=Path, required=True)
    parser.add_argument("--cc", type=Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="hpu-execution-profile-codegen-") as directory:
        root = Path(directory)
        subprocess.run([str(arguments.generator.resolve()), "--emit-fixtures", str(root)], check=True)
        host_check(root)
        found = shutil.which("riscv64-linux-gnu-gcc") or shutil.which("riscv64-unknown-elf-gcc")
        compiler = arguments.cc or (Path(found) if found else None)
        if compiler and compiler.is_file():
            target_check(root, compiler.resolve())
        else:
            print("RISC-V portion skipped: configure --cc to check actual target wrappers")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(error.stderr or str(error), file=sys.stderr)
        sys.exit(1)
