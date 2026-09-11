# HPU NTT RTL fixtures

These files are the minimal reproducible subset extracted from the hardware
team's `third_party/ntt_run_data` package dated 2026-09-10.

- `rtl_pntt/` contains the 512-word PNTT stage-0 input, twiddle image, and RTL
  dump comparison.
- `rtl_pintt/` contains the independent 512-word PINTT stage-0 and stage-1
  inputs, stage-1 twiddle image, and RTL dump comparisons.
- `full_n512/` contains the prime-field full transform input, each stage's
  physical memory state, final physical/logical outputs, and inverse
  lazy-scale twiddle stream.

The RTL slice modulus `0xFFFFFFFE` is non-prime and qualifies only loader,
butterfly, P/P^-1, and writeback behavior. FHE convolution semantics are tested
separately with the prime modulus from `full_n512/`.
