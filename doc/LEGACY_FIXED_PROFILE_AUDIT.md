# Legacy fixed-profile audit

## Scope

The original delivery pipeline is driven by `config/fhe_test.conf` and emits a
preselected suite from three executable entry points:

- `inline_asm_codegen`
- `inline_asm_encode_outputs`
- `hpu_reference_vectors`

Its default `N=4096, Q=4, P=3, B=6, dnum=2` values are functional fixtures,
not a supported production CKKS profile. `hpu_delivery` remains available as
an explicit compatibility target, but its valid reference tests are registered
only with `HPU_ENABLE_LEGACY_FIXED_PROFILE_TESTS=ON`.

The optional `hpu_seal_differential_test` also consumes artifacts from that
pipeline. It checks scheme-level fixture semantics through `seal::Evaluator`;
it is not evidence that an HPU instruction stream executed correctly.

## Still-default tests

Fixed integers inside focused unit tests are shape vectors, not application
profiles. They remain default when they test a parameterized API or invariant:

- hardware NTT mathematical correctness, including N=65536;
- CKKS kernel transform/order/count invariants;
- multi-level global MOD_ID and Q/P layout behavior;
- runtime residency, dstore-before-psync, and HPU_MEM layout;
- SEALContext-derived CKKS objects, keys, levels, and twiddles;
- invalid configuration rejection and instruction encoder behavior.

New CKKS application code must obtain degree, active Q, P, digit selection,
and modulus IDs from `SEALContext`/`CkksLevelDescriptor`. It must not read the
legacy demo profile or copy its P/dnum values into a production API.

## Numeric audit

The reference generator uses `unsigned __int128` as a self-contained CRT
accumulator. GCC 8 with strict `-std=c++17` does not reliably specialize
`std::numeric_limits` for this extension. All unsigned-128 maximum checks now
use `static_cast<unsigned __int128>(-1)`. Other narrowing checks use standard
fixed-width integer limits and are unaffected.
