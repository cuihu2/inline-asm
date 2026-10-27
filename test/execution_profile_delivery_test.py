#!/usr/bin/env python3
"""Compare a continuous execution-profile package with its ordinary delivery."""

import argparse
import csv
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from target_dma_codegen_test import tool_environment


def run(command, **kwargs):
    return subprocess.run([str(value) for value in command], check=True, **kwargs)


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def golden(package, descriptor):
    return {
        (row["object_id"], row["component"], row["modulus_id"],
         row["modulus"], row["domain"]): (package / row["path"]).read_bytes()
        for row in rows(package / descriptor["golden_manifest"])
    }


def dma_statistics(package, descriptor):
    dma = rows(package / descriptor["dma_relocation_manifest"])
    return dma, sum(int(row["line_count"]) * 256 for row in dma)


def compile_generated_source(root, source, descriptor, compiler):
    """Check the actual generated C, independently of the codegen fixture."""
    if compiler:
        environment = tool_environment(compiler)
        include = subprocess.check_output(
            [str(compiler), "-print-file-name=include"], text=True,
            env=environment).strip()
        for bits, abi in ((32, "ilp32"), (64, "lp64")):
            run([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-ffreestanding", "-nostdinc", "-isystem", include,
                 f"-march=rv{bits}im", f"-mabi={abi}", "-c", source,
                 "-o", root / f"profile-rv{bits}.o"],
                env=environment, stdout=subprocess.DEVNULL)

    host_cc = shutil.which("cc")
    if not host_cc:
        print("Host C compile skipped: no cc executable available", flush=True)
        return
    header = Path(descriptor["program_header"]).name
    identifier = re.sub(r"[^A-Za-z0-9_]", "_", source.stem)
    harness = root / "host.c"
    harness.write_text(f'''#include "{header}"
static unsigned callbacks;
static uint64_t read_cycles(void *user) {{ (void)user; ++callbacks; return 1; }}
static int wait_complete(void *user, size_t index) {{
    (void)user; (void)index; ++callbacks; return 0;
}}
int main(void) {{
    hpu_execution_profile_sample_t sample = {{ 7, 9, 1 }};
    hpu_execution_profile_hooks_t hooks = {{ 0, read_cycles, wait_complete }};
    if (hpu_run_{identifier}() != -5) return 1;
    if (hpu_program_{identifier}(0, 0) != -5) return 2;
    if (hpu_run_{identifier}_profiled(0, &sample) != -1) return 3;
    if (sample.valid || sample.start_cycles || sample.end_cycles) return 4;
    if (hpu_run_{identifier}_profiled(&hooks, &sample) != -4) return 5;
    if (sample.valid || sample.start_cycles || sample.end_cycles || callbacks) return 6;
    return 0;
}}
''')
    executable = root / "host"
    run([host_cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
         "-I", source.parent, source, harness, "-o", executable])
    run([executable])


def check_case(root, arguments):
    normal, profile = root / "ordinary", root / "profile"
    example_args = (["--case", arguments.kernel] if arguments.kernel else
                    ["--degree", "8192", "--data-moduli", "4", "--seed", "0"])
    for destination, extra in ((normal, []), (profile, ["--profile-execution"])):
        run([arguments.example, *example_args, *extra, "--emit-dir", destination],
            stdout=subprocess.DEVNULL)
        run([arguments.validator, destination], stdout=subprocess.DEVNULL)

    ordinary = json.loads((normal / "package.json").read_text())
    descriptor = json.loads((profile / "package.json").read_text())
    assert "execution_profile_manifest" not in ordinary
    assert descriptor["execution_profile_manifest"] == "profiling/execution_window.csv"
    assert golden(normal, ordinary) == golden(profile, descriptor), "golden payloads changed"
    assert json.loads((normal / ordinary["parameters"]).read_text()) == json.loads(
        (profile / descriptor["parameters"]).read_text()), "mathematical parameters changed"
    if arguments.scheme:
        assert descriptor["scheme"] == ordinary["scheme"] == arguments.scheme

    report = json.loads((profile / descriptor["oracle_report"]).read_text())
    assert report["host_instruction_model_verified"] is True
    assert report["optimization_equivalence_verified"] is True
    timing = report["execution_profile"]
    assert timing["enabled"] is True and timing["window_count"] == 1
    assert timing["timing_measured"] is False
    assert timing["includes_residual_dma"] is True

    words = [int(line, 2) for line in
             (profile / descriptor["program_inst32"]).read_text().splitlines()]
    window_rows = rows(profile / descriptor["execution_profile_manifest"])
    assert len(window_rows) == 1, "profiling must have exactly one continuous window"
    window = window_rows[0]
    assert list(window) == ["begin_instruction", "end_instruction",
                            "arithmetic_instruction_count", "dload_count", "dstore_count"]
    begin, end = int(window["begin_instruction"]), int(window["end_instruction"])
    assert 0 < begin < end < len(words)
    assert words[begin - 1] == words[end] == 0x7000005b, "missing completion PSYNC boundary"

    def arithmetic(word):
        return word & 0x7f == 0x5b and word >> 28 <= 5

    arithmetic_indices = {index for index, word in enumerate(words) if arithmetic(word)}
    assert arithmetic_indices and all(begin <= index < end for index in arithmetic_indices)
    assert int(window["arithmetic_instruction_count"]) == len(arithmetic_indices)

    ordinary_dma, ordinary_bytes = dma_statistics(normal, ordinary)
    dma, dma_bytes = dma_statistics(profile, descriptor)
    assert len(dma) <= len(ordinary_dma), "profiling increased DMA count"
    assert dma_bytes <= ordinary_bytes, "profiling increased actual DMA bytes"
    assert timing["unprofiled_dma_bytes"] == ordinary_bytes
    assert timing["unprofiled_dma_count"] == len(ordinary_dma)
    assert report["compiler_resources"]["dma_bytes"] == dma_bytes
    ordinary_report = json.loads((normal / ordinary["oracle_report"]).read_text())
    for field in ("spills", "reloads"):
        assert report["compiler_resources"][field] <= ordinary_report["compiler_resources"][field], \
            f"profiling increased {field}"
    assert len(dma) == sum(word & 0x7f == 0x2b for word in words)
    prefix_loads = body_loads = body_stores = suffix_stores = 0
    for row in dma:
        index = int(row["instruction_index"])
        assert int(row["word_hex"], 16) == words[index]
        assert row["direction"] in ("dload", "dstore")
        is_load = row["direction"] == "dload"
        if index < begin:
            assert is_load, "a writeback unexpectedly preceded all arithmetic"
            prefix_loads += 1
        elif index < end:
            body_loads += int(is_load)
            body_stores += int(not is_load)
        else:
            assert not is_load, "a load unexpectedly followed all arithmetic"
            suffix_stores += 1
    assert prefix_loads > 0 and suffix_stores > 0
    # Residual DMA is explicitly counted, never rejected as a profiling error.
    assert int(window["dload_count"]) == timing["window_dload_count"] == body_loads
    assert int(window["dstore_count"]) == timing["window_dstore_count"] == body_stores
    assert timing["prefix_dload_count"] == prefix_loads
    assert timing["suffix_dstore_count"] == suffix_stores

    source = profile / descriptor["program_source"]
    text = source.read_text()
    assert [int(word, 16) for word in re.findall(r"\.word (0x[0-9A-Fa-f]+)", text)] == words
    assert text.count("hooks->read_cycles(hooks->user)") == 2
    assert text.count("sample->start_cycles = hooks->read_cycles") == 1
    assert text.count("sample->end_cycles = hooks->read_cycles") == 1
    compile_generated_source(root, source, descriptor, arguments.cc)
    name = arguments.kernel or arguments.scheme
    print(f"{name}: one continuous window; prefix loads={prefix_loads}, "
          f"timed loads/stores={body_loads}/{body_stores}, trailing stores={suffix_stores}; "
          f"DMA {ordinary_bytes} -> {dma_bytes} bytes, "
          f"{len(ordinary_dma)} -> {len(dma)} operations; golden unchanged", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", type=Path, required=True)
    parser.add_argument("--validator", type=Path, required=True)
    kind = parser.add_mutually_exclusive_group(required=True)
    kind.add_argument("--scheme", choices=("ckks", "bfv", "bgv"))
    kind.add_argument("--kernel", choices=("cmult", "ntt", "intt"))
    parser.add_argument("--cc", type=Path)
    arguments = parser.parse_args()
    arguments.example = arguments.example.resolve()
    arguments.validator = arguments.validator.resolve()
    if arguments.cc:
        arguments.cc = arguments.cc.resolve()
    with tempfile.TemporaryDirectory(prefix="hpu-execution-profile-delivery-") as directory:
        check_case(Path(directory), arguments)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
