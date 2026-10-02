#!/usr/bin/env python3
"""Build a fresh package, validate it, then publish to a managed output path."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def generate(example, validator, output, example_args=()):
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError(f"package destination must not be a symlink: {output}")
    # Only previously validated application packages can be replaced. In
    # particular, do not delete an arbitrary user's directory or a legacy pack.
    if output.exists():
        subprocess.run([validator, str(output)], check=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix=f".{output.name}.build-", dir=output.parent))
    backup = scratch / "previous"
    published = False
    try:
        staging = scratch / "package"
        subprocess.run([example, *example_args, "--emit-dir", str(staging)], check=True)
        subprocess.run([validator, str(staging)], check=True)
        if output.exists():
            # Recheck after generation, before touching any existing directory.
            subprocess.run([validator, str(output)], check=True)
            old = json.loads((output / "package.json").read_text())
            new = json.loads((staging / "package.json").read_text())
            if any(old[key] != new[key] for key in ("case_name", "scheme")):
                raise ValueError("refusing to replace a different application package")
            os.rename(output, backup)
        try:
            os.rename(staging, output)
            published = True
        except BaseException:
            if backup.exists():
                os.rename(backup, output)
            raise
    finally:
        if backup.exists() and not published:
            # If restoring the old package itself failed, retain the only
            # copy outside the normal temporary-directory cleanup path.
            print(f"Previous package retained at: {backup}", file=sys.stderr)
        else:
            shutil.rmtree(scratch)
    print(f"Application package ready: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--example", required=True)
    parser.add_argument("--validator", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--example-arg", action="append", default=[])
    args = parser.parse_args()
    generate(args.example, args.validator, args.output, args.example_arg)
