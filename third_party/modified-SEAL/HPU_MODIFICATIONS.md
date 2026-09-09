# HPU modifications to SEAL v4.4.4

This directory is a source-vendored variant of Microsoft SEAL v4.4.4. Its
upstream identity is recorded in `HPU_BASELINE.md`; it is intentionally not a
Git submodule and is versioned by the parent Inline-asm repository.

## BFV comparison-free variant

The local variant adds two independent, opt-in SEAL build options:

- `SEAL_EXPERIMENTAL_BFV_NO_SMRQ`: replaces the BFV input conversion through
  `m_tilde` and `SmMRq` with an unreduced `q -> Bsk` fast conversion.
- `SEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK`: enlarges the auxiliary base and uses
  a comparison-free Shenoy-Kumaresan correction.

Inline-asm enables both options when `HPU_ENABLE_SEAL_INTEGRATION=ON`. A direct
build of this vendored SEAL tree leaves both options OFF unless they are
explicitly requested, preserving the upstream default behavior.

## Changed implementation and validation files

- `native/src/seal/evaluator.cpp`: selects the no-SmMRq BFV multiply/square
  input path.
- `native/src/seal/util/rns.{h,cpp}`: implements the unreduced conversion,
  branchless SK correction, and auxiliary-base sizing bounds.
- `CMakeLists.txt`, `cmake/SEALConfig.cmake.in`, and
  `native/src/seal/util/config.h.in`: define and export the feature switches.
- `native/tests/seal/util/rns.cpp`: unit coverage for the new conversions and
  bounds.
- `native/tests/seal/bfv_no_smrq_diagnostics.cpp`: deterministic BFV depth,
  noise, and timing diagnostics.
- `tools/analyze_no_smrq_diagnostics.py`: compares diagnostic CSV output.
- `docs/bfv-hpu-comparison-free-base-conversion.md`: algorithm, proof
  obligations, HPU mapping, and measured validation results.

Generated CSV results, editor state, and the original `D:/SEAL/.git` history
are deliberately excluded. Future changes to this variant must update this
file and the parent project documentation in the same Inline-asm commit.

## Standalone validation

```bash
cmake -S third_party/modified-SEAL -B build-modified-seal-self \
  -DSEAL_BUILD_TESTS=ON \
  -DSEAL_BUILD_BFV_NO_SMRQ_DIAGNOSTICS=ON \
  -DSEAL_EXPERIMENTAL_BFV_NO_SMRQ=ON \
  -DSEAL_EXPERIMENTAL_BFV_BRANCHLESS_SK=ON
cmake --build build-modified-seal-self -j
./build-modified-seal-self/bin/sealtest --gtest_color=no

# Optional extended N=32768 depth sweep; this is not part of the default
# functional gate.
SEAL_NO_SMRQ_RUN_N32768_SWEEP=1 \
  ./build-modified-seal-self/bin/sealtest \
    --gtest_filter=BFVNoSmrqDiagnostics.N32768BatchingDepthSweep
```
