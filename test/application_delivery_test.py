#!/usr/bin/env python3
"""Exercise real scheme adapters, package emission and the standalone consumer validator."""

import csv
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile


def rows(path):
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def main():
    example, validator, scheme = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="hpu-delivery-test-") as root:
        package = Path(root) / "package"
        subprocess.run([example, "--emit-dir", str(package)], check=True)
        subprocess.run([validator, str(package)], check=True)
        # Parse metadata with an independent JSON implementation as well.
        for path in package.rglob("*.json"):
            json.loads(path.read_text())
        descriptor = json.loads((package / "package.json").read_text())
        assert descriptor["scheme"] == scheme
        assert descriptor["schema_version"] == 1
        parameters = json.loads((package / descriptor["parameters"]).read_text())
        assert parameters["scheme"] == scheme
        assert parameters["poly_modulus_degree"] > 0
        graph = json.loads((package / descriptor["operation_graph"]).read_text())
        assert graph["operations"] and graph["final_output"]
        report = json.loads((package / descriptor["oracle_report"]).read_text())
        assert report["hardware_verified"] is False
        assert report["rtl_verified"] is False
        assert report["instruction_execution_verified"] is False
        assert report["verification_schema_version"] == 1
        assert report["overall_status"] == "pass"
        assert report["oracle_verified"] is True
        assert report["golden_matches_oracle"] is True
        assert report["checks"][0] == {
            "name": "seal_oracle_to_golden", "required": True,
            "status": "pass"}
        assert report["checks"][1]["name"] == "host_software_model_to_oracle"
        assert report["checks"][1]["required"] is False
        assert report["checks"][1]["status"] == (
            "pass" if scheme != "bgv" else "not_run")
        assert report["model_verified"] == (True if scheme != "bgv" else None)
        assert report["raw_physical_words_equal"] == (True if scheme != "bgv" else None)
        golden = rows(package / descriptor["golden_manifest"])
        memory = rows(package / descriptor["memory_manifest"])
        outputs = {(r["line_offset"], r["line_count"]) for r in memory if r["kind"] == "output"}
        assert outputs == {(r["line_offset"], r["line_count"]) for r in golden}
        assert report["verified_limb_count"] == len(golden)
        assert {op["golden_object_id"] for op in graph["operations"]} == {r["object_id"] for r in golden}
        image = (package / descriptor["image"]).read_bytes()
        for limb in golden:
            assert limb["domain"] == ("coefficient" if scheme == "bfv" else "canonical_ntt_physical")
            begin = int(limb["line_offset"]) * 256
            length = int(limb["line_count"]) * 256
            assert not any(image[begin:begin + length]), "golden was preloaded into startup image"
            raw = (package / limb["path"]).read_bytes()
            assert len(raw) == length
            assert all(word < int(limb["modulus"]) for (word,) in struct.iter_unpack("<I", raw))
        assert (package / descriptor["program_source"]).is_file()
        assert (package / descriptor["semantic_report"]).is_file()
        dma = rows(package / descriptor["dma_relocation_manifest"])
        assert dma and len(dma[0]) == 14
        if scheme == "bgv" and "plain_chain" in example:
            sys.dont_write_bytecode = True
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
            from generate_application_package import generate
            (package / "unused-extra-file").write_text("unexpected stale member")
            # Validator refuses extra members; regeneration cannot erase them.
            try:
                generate(example, validator, package)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("publisher accepted an invalid existing package")
            (package / "unused-extra-file").unlink()
            generate(example, validator, package)
            subprocess.run([validator, str(package)], check=True)
        golden_file = package / golden[0]["path"]
        corrupted = bytearray(golden_file.read_bytes())
        corrupted[0] ^= 1
        golden_file.write_bytes(corrupted)
        result = subprocess.run([validator, str(package)], capture_output=True)
        assert result.returncode != 0, "validator accepted corrupted golden bytes"
    print(f"{scheme} application delivery integration PASS")


if __name__ == "__main__":
    main()
