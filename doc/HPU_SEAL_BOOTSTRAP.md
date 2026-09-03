# HPU + Microsoft SEAL CKKS Bootstrap

## Scope

This bootstrap keeps Microsoft SEAL as the host-side CKKS authority and uses the
HPU for selected evaluator kernels. The first functional target is:

1. SEALContext, KeyGenerator, CKKSEncoder and Encryptor on the CPU.
2. HPU ciphertext multiply, relinearization and independent rescale.
3. SEAL Decryptor and CKKSEncoder::decode for differential checking.

The target degree is `N=65536`. Smaller degrees remain useful for unit tests but
must not define the integration ABI. Every data modulus and special/key modulus
must fit the HPU uint32 coefficient and modulus ABI.

Security qualification is intentionally deferred. The bootstrap creates the
`N=65536` context with `seal::sec_level_type::none`; this is a functional choice,
not a security claim.

## Frozen dependency

`third_party/SEAL` is pinned to Microsoft SEAL `v4.4.4`, commit:

```text
96ae20db6649bc7c24e9a34994bedd70f4951f60
```

CMake rejects any other submodule commit when SEAL integration is enabled. A
future repository fork can replace the URL in `.gitmodules`, but it must start
from this commit. This project does not plan compatibility work for later SEAL
versions.

## Hardware NTT authority

`hpu::model::HardwareNttModel` is the C++ port of
`autotest/hw_ntt_intt_complete.py`:

- 128 registers and 64 fixed butterfly lanes;
- forward `load -> BF -> P -> store`;
- reverse-stage inverse `load -> P^-1 -> fixed BF -> store`;
- the exact sequential/interleaved loader schedule;
- physical NTT layout after every P network;
- data-independent lazy inverse scale tags.

The raw increasing-m DIT hardware schedule consumes coefficients in bit-reversed
memory order. `HardwareNttModel::forward` and `inverse` expose a mathematical
API, so they explicitly convert between normal coefficient order and that
hardware boundary order. The test suite compares the physical result, after the
reported P-network layout permutation, with an independent mathematical NTT and
checks `NTT(delta_1)[k] = omega^k`; round-trip alone is not accepted as proof of
NTT correctness.

The inverse stage tables contain `w_bf = alpha / beta`. The final pointwise
factor is not merely `N^-1`: it is `lazy_scale[position]^-1 * N^-1`, followed by
the CKKS inverse twist. The hardware package generator now emits the combined
factor.

The model also implements both modified-root automorphism identities from
`toy_fhe_auto.py`. Both APIs return the canonical HPU NTT physical domain. The
first runtime version therefore forbids a kernel boundary in the middle of a
modified-root transform; only the resulting Galois key domain needs to survive
until KeySwitch.

`hpu::seal_adapter::ciphertext_component_to_hpu` implements the first exact
SEAL bridge. It uses the pinned SEAL inverse NTT to recover canonical
coefficients and then runs the HPU negacyclic model, rather than assuming that
SEAL and HPU share an evaluation-point order. The reverse bridge is tested for
exact word equality on an encrypted CKKS ciphertext.

`hpu::seal_adapter::relinearization_key_to_hpu` converts SEAL's `s^2`
relinearization key from the key context into the same physical Q/P layout. It
derives the digit and special-modulus counts from `SEALContext`/`RelinKeys`; the
old demo values `P=3` and `dnum=2` are not embedded in this bridge. The API never
accepts a `SecretKey`, so secret material cannot accidentally enter HPU_MEM
through this preprocessing path.

## First CKKS application stream

`hpu::scheme::ckks::generate_ciphertext_multiply_body_asm` is now the formal
SEAL-facing stream rather than a wrapper around the coefficient-input demo. Its
contract is:

1. both two-component inputs already use canonical HPU NTT physical order;
2. tensor multiplication remains in that domain, so the old four input NTTs
   are not emitted;
3. the three tensor components cross to coefficients once because the first
   functional KeySwitch/ModDown and Rescale path is coefficient-domain;
4. independent Rescale drops `q_last`, after which only the two final limbs over
   `Q_without_last` are transformed back to canonical HPU NTT order;
5. the complete q/mu table is loaded to the small bank once, nested operators
   reuse it, required results are dstore'd, and one terminal `psync` completes
   the application.

The codegen regression test counts every PNTT/PINTT stage, so reintroducing the
four input transforms is a test failure. Standalone operator demos keep their
existing table-management behavior through default arguments.

## Runtime boundary

`hpu::runtime::Application` is platform-independent. It records the invariants
that remain valid whether the Linux backend becomes a userspace MMIO library or
a kernel driver:

- the complete q/mu table is dload'd to the small bank once per application;
- at most regular-bank slots `0..4` are used;
- a polynomial may remain resident and dirty across multiple kernels;
- an object is not forced through dstore/dload at every kernel boundary;
- every required final output must be dstore'd to HPU_MEM before completion;
- `finish()` emits the application's only `psync`.

The eventual Linux backend should consume this state/event layer rather than
putting ioctl/MMIO details into CKKS or scheduling code.

## Linux build and tests

Initialize the frozen dependency:

```bash
git submodule update --init --recursive
git -C third_party/SEAL rev-parse HEAD
```

Build and run the hardware model/runtime tests without SEAL:

```bash
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j
ctest --test-dir build -R 'hpu_(hardware_ntt_model|runtime_application)_test' \
  --output-on-failure
```

The NTT test includes cyclic and negacyclic round trips, both fused
automorphism forms, and an actual `N=65536` case.

Build the pinned CKKS integration and its `N=65536`, uint32-modulus context test:

```bash
cmake -S . -B build-seal \
  -DBUILD_TESTING=ON \
  -DHPU_ENABLE_SEAL_INTEGRATION=ON
cmake --build build-seal -j --target \
  hpu_hardware_ntt_model_test \
  hpu_runtime_application_test \
  hpu_ckks_application_codegen_test \
  hpu_seal_ckks_context_test
ctest --test-dir build-seal \
  -R 'hpu_(hardware_ntt_model|runtime_application|ckks_application_codegen|seal_ckks_context)_test' \
  --output-on-failure
```

Generate the full-size reference profile separately because it is much larger
than the default demo package:

```bash
cmake -S . -B build-n65536 \
  -DHPU_TEST_CONFIG="$PWD/config/ckks_hpu_seal.conf"
cmake --build build-n65536 -j --target hpu_reference_vectors
./build-n65536/test/reference/hpu_reference_vectors \
  ./build-n65536/n65536-reference \
  --config ./config/ckks_hpu_seal.conf
```

Do not treat a successful host run as RTL qualification. Target execution still
needs the generated HPU_MEM image, relocation plan, final dstore results,
FAULT/IRQ status and external monitor evidence.
