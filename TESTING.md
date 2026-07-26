# TESTING.md — test tiers and upstream traceability

Three tiers, with different purposes and different gates. Tier 2 is the one written
alongside the code; tier 3 is what licenses the claim in the README.

**Upstream reference:** `bitcoin-core/secp256k1` **v0.7.1**. All line and function
references below are against that tag. Pin any new reference to a tag, never to `master`.

The checkout is not vendored and its location is per-machine — `TODO.md` has the clone and
build recipe. One checkout supplies four things: the differential oracle's `libsecp256k1.a`,
the Wycheproof JSON corpora, the BIP327 MuSig2 vectors, and `tests.c` for Strategy A.

**Vector tables are generated, not hand-typed.** `tools/gen_wycheproof_vectors.py` and
`tools/gen_bip327_vectors.py` transcribe the upstream JSON and C header into Odin tables.
Regenerating must reproduce those files byte for byte; that is the check that they were not
edited, which `CLAUDE.md` forbids. The BIP327 generator parses the C initializers
structurally rather than scraping hex, so a shape change upstream is a parse error here
instead of a silently wrong table.

---

## Tier 1 — Class A portable vectors (hard gate)

Language-agnostic published vectors: Wycheproof ECDSA JSON, BIP340 CSV, BIP327 MuSig2,
ECDH, plus serialization round-trips. Passing these is what "the crypto is correct" means.
100% required to close a phase.

Vectors are **not vendored** — see `DEVELOPMENT.md` §0.5. They are fetched into a
gitignored `vectors/` directory so a submodule consumer does not clone megabytes of JSON.
Vectors are used unmodified; never invent or edit one.

## Where tests live

In a parallel `tests/` tree, one package per module — **never** inside the package under
test. Odin compiles `_test.odin` files into ordinary builds, so an in-package test would
pull `core:testing` into every consumer of this library. See `DEVELOPMENT.md` §0.5.

```sh
odin test tests/ -all-packages          # everything
odin test tests/field/                  # one module
```

Tests therefore see only a package's exported surface. Since `field`, `scalar` and friends
are internal to the library, their exports already are the surface upstream's `tests.c`
reaches into, so nothing is lost.

## Tier 2 — Class B mirrored-upstream Odin tests (written alongside the code)

Odin `@(test)` procedures that mirror upstream's `tests.c` **function by function**, using
the same names for direct traceability. These call internal functions directly and cover
what black-box vectors cannot see: magnitude bookkeeping, normalization edge cases,
representation invariants, and the `*_verify` layer under `-debug`.

Naming convention: upstream `run_field_misc` → Odin `test_run_field_misc` in the package
that owns the code. When upstream's test is randomized over `COUNT` iterations, mirror
that structure and seed deterministically so failures reproduce.

**These do not replace tier 3.** They are written first because tier 3 cannot run until
the C ABI shim exists in Phase 9. Until then the README claim is precisely "passes an Odin
suite mirroring upstream's", never "passes libsecp256k1's tests".

## Tier 3 — Strategy A and the differential oracle (Phase 9)

Two separate things, and only one of them is done.

**The differential oracle — ✅ running, zero divergences.** `tests/oracle` feeds identical
fuzzed inputs to this implementation and to upstream libsecp256k1 through the quarantined
`oracle` FFI package, and demands byte-identical output. Currently covering: secret-key
validity, public-key derivation and serialization (both encodings), public-key parsing and
tweaking, ECDSA signing (exact signature match, so RFC6979 and low-S are both pinned),
verification verdicts on fuzzed blobs, DER serialization, Schnorr signing and verification,
x-only keys and parity, ECDH, recoverable signatures and recovery, ellswift decoding, and
tagged hashes.

```sh
./oracle/link-lib.sh /path/to/libsecp256k1.a     # once
odin test tests/oracle/ -define:FUZZ_COUNT=2000
```

The library must be built with all modules enabled; the recovery module in particular is
off in some default builds. `oracle/libsecp256k1.a` is gitignored and the `oracle` package
is not reachable from any library package — verified by building every library package with
the archive absent.

**Strategy A linking — ❌ not done.** A thin C shim exposing this implementation's symbols
under the C ABI, linked against the *actual* upstream `src/tests.c` and
`src/tests_exhaustive.c`. Until that exists, the honest claim is "byte-identical to
libsecp256k1 on fuzzed inputs", **not** "passes libsecp256k1's tests".

---

## Traceability map

Status: `—` not started · `wip` in progress · `✅` mirrored and green · `n/a` not applicable
to this implementation. Tier 3 column tracks whether the real upstream test links and
passes in Phase 9.

### Field (Phase 1)

| upstream `tests.c` | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_field_convert` | `test_run_field_convert` | `field` | ✅ | — |
| `run_field_be32_overflow` | `test_run_field_be32_overflow` | `field` | ✅ | — |
| `run_field_half` | `test_run_field_half` | `field` | ✅ | — |
| `run_field_misc` | `test_run_field_misc` | `field` | ✅ | — |
| `run_fe_mul` | `test_run_fe_mul` | `field` | ✅ | — |
| `run_sqr` | `test_run_sqr` | `field` | ✅ | — |
| `run_sqrt` | `test_run_sqrt` | `field` | ✅ | — |
| `run_inverse_tests` | `test_run_inverse_tests` | `field` | ✅ | — |
| `run_modinv_tests` | `test_run_modinv_tests` | `field`, `modinv` | ✅ | — |
| `run_int128_tests` | — | — | n/a | n/a |

Tests with no upstream counterpart, covering ground upstream reaches only incidentally:

| Odin test | package | covers | status |
|---|---|---|---|
| `test_fe_mul_known_answers` | `field` | products against independently computed vectors | ✅ |
| `test_fe_sqr_known_answers` | `field` | squares against independently computed vectors | ✅ |
| `test_fe_modulus_is_p` | `field` | that the modulus is p and not merely some ring | ✅ |
| `test_beta_is_cube_root_of_unity` | `field` | the endomorphism constant | ✅ |
| `test_field_normalize_boundaries` | `field` | reduction exactly at the p boundary | ✅ |
| `test_field_normalize_magnitudes` | `field` | normalization at every magnitude 0..31 | ✅ |
| `test_is_square_var` | `field` | quadratic-residue testing | ✅ |
| `test_jacobi_agrees_with_euler` | `modinv` | Jacobi symbols against squares | ✅ |

The known-answer vectors exist because the algebraic property tests — commutativity,
associativity, distributivity — hold in *any* commutative ring and would pass unchanged
against the wrong modulus. Property tests alone cannot pin the field down; these do.

`run_int128_tests` is not applicable: it exercises upstream's `secp256k1_uint128` shim,
which exists to emulate `__int128` on compilers that lack it. Odin's `u128` is a native
type on every target, so there is no shim to test. The arithmetic it protects is covered
by `test_run_fe_mul` and `test_run_sqr`.

### Scalar (Phase 2)

| upstream `tests.c` | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_scalar_tests` | `test_run_scalar_tests` | `scalar` | ✅ | — |
| `run_scalar_set_b32_seckey_tests` | `test_run_scalar_set_b32_seckey_tests` | `scalar` | ✅ | — |
| `run_inverse_tests` (scalar half) | `test_run_inverse_tests` | `scalar` | ✅ | — |

Tests with no upstream counterpart:

| Odin test | package | covers | status |
|---|---|---|---|
| `test_scalar_mul_known_answers` | `scalar` | products against independent vectors | ✅ |
| `test_scalar_inverse_known_answers` | `scalar` | inverses against independent vectors | ✅ |
| `test_scalar_modulus_is_n` | `scalar` | that the modulus is n, not merely some ring | ✅ |
| `test_scalar_is_high_and_low_s` | `scalar` | the low-S boundary at exactly n/2 | ✅ |
| `test_scalar_get_bits` | `scalar` | bit extraction against the serialized form | ✅ |
| `test_scalar_split_lambda` | `scalar` | GLV decomposition and its 2^128 bounds | ✅ |

### Group (Phase 3)

| upstream `tests.c` | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_ge` | `test_run_ge` | `group` | ✅ | — |
| `run_gej` | `test_run_gej` | `group` | ✅ | — |
| `run_group_decompress` | `test_run_group_decompress` | `group` | ✅ | — |
| `run_ec_combine` | `test_run_ec_combine` | `group` | ✅ | — |
| `tests_exhaustive.c` (group law) | `test_exhaustive_*` | `group` | ✅ | — |

Tests with no upstream counterpart:

| Odin test | package | covers | status |
|---|---|---|---|
| `test_generator_is_on_curve` | `group` | the configured generator satisfies y^2=x^3+b | ✅ |
| `test_generator_has_expected_order` | `group` | order*G is infinity and no smaller multiple is | ✅ |
| `test_add_ge_degenerate_case` | `group` | y1=-y2 with x1!=x2, the unified formula's hard case | ✅ |
| `test_add_ge_opposite_points` | `group` | the other branch of the same selector | ✅ |
| `test_ge_set_all_gej` | `group` | batched inversion, with and without infinities | ✅ |
| `test_ge_x_frac_on_curve` | `group` | the fraction form against direct evaluation | ✅ |

The exhaustive tests run only under `-define:EXHAUSTIVE_ORDER=7|13|199` and are inert
otherwise. They enumerate the entire group and check the addition law for **every ordered
pair** through all three addition routines — at order 199 that is roughly 40k additions per
formula. Run all three orders; each selects a different generator, so this is also what
validates the curve constants in `params`.

`test_add_ge_degenerate_case` exists because of a mutation that survived: replacing the
degenerate-case conditional move in `gej_add_ge` with a constant `false` passed the entire
suite. The case needs y1 = -y2 with x1 != x2, which random sampling never produces and the
exhaustive walk does not reach either. It has to be constructed deliberately, from
Q = (beta*x, -y).

### ecmult (Phase 4)

| upstream `tests.c` | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_wnaf` | `test_run_wnaf` | `ecmult` | ✅ | — |
| `run_ecmult_chain` | `test_run_ecmult_chain` | `ecmult` | ✅ | — |
| `run_ecmult_const_tests` | `test_ecmult_engines_agree` | `ecmult` | ✅ | — |
| `run_ecmult_constants` | `test_run_ecmult_constants` | `ecmult` | ✅ | — |
| `run_ecmult_pre_g` | `test_run_ecmult_pre_g` | `ecmult` | ✅ | — |
| `run_point_times_order` | `test_run_point_times_order` | `ecmult` | ✅ | — |
| `run_endomorphism_tests` | `test_run_endomorphism_tests` | `ecmult` | ✅ | — |
| `run_ecmult_gen_blind` | `test_run_ecmult_gen_blind` | `ecmult` | ✅ | — |
| `run_ecmult_near_split_bound` | `test_run_ecmult_near_split_bound` | `ecmult` | — | — |
| `run_ecmult_multi_tests` | — | — | n/a | n/a |

Tests with no upstream counterpart:

| Odin test | package | covers | status |
|---|---|---|---|
| `test_ecmult_engines_agree` | `ecmult` | all three engines against an independent ladder | ✅ |
| `test_ecmult_edge_cases` | `ecmult` | zero, one, infinity and negated scalars | ✅ |
| `test_run_ecmult_gen_table` | `ecmult` | every comb entry is a valid non-infinite point | ✅ |

`run_ecmult_multi_tests` is not applicable: it exercises the Strauss and Pippenger batch
algorithms, which operate over upstream's scratch-space allocator. `CLAUDE.md` requires
allocation-free hot paths, so this implementation provides only the simple
multiply-and-sum `ecmult_multi_var`, and there is no scratch machinery to test.

`run_ecmult_gen_blind` is deferred to Phase 5: seeded blinding needs RFC6979 HMAC-SHA256
from the `hash` package. Until then `ecmult_gen` runs unblinded, which `TRUST.md` records.

**Table verification replaces byte-identical regeneration.** Upstream ships its generator
tables as a checked-in multi-megabyte C source file and tests that regeneration reproduces
it byte for byte. This implementation computes the tables at package initialization
instead — nothing is vendored, so a submodule consumer clones nothing extra and no blob can
drift from the code. `test_run_ecmult_pre_g` and `test_run_ecmult_gen_table` verify each
entry against an independently computed multiple of G, which is a stronger statement than
byte-equality with a stored blob.

### Hashing, context, infrastructure (Phase 5)

| upstream `tests.c` | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_sha256_known_output_tests` | `test_run_sha256_known_output_tests` | `hash` | ✅ | — |
| `run_sha256_counter_tests` | `test_run_sha256_counter_tests` | `hash` | ✅ | — |
| `run_hmac_sha256_tests` | `test_run_hmac_sha256_tests` | `hash` | ✅ | — |
| `run_rfc6979_hmac_sha256_tests` | `test_run_rfc6979_hmac_sha256_tests` | `hash` | ✅ | — |
| `run_tagged_sha256_tests` | `test_run_tagged_sha256_tests` | `hash` | ✅ | — |
| `run_proper_context_tests` | `test_run_proper_context_tests` | `ctx` | ✅ | — |
| `run_static_context_tests` | `test_run_static_context_tests` | `ctx` | ✅ | — |
| `run_ec_illegal_argument_tests` | `test_run_ec_illegal_argument_tests` | `ctx` | ✅ | — |
| `run_selftest_tests` | `test_run_selftest_tests` | `ctx` | ✅ | — |
| `run_cmov_tests` | `test_run_cmov_tests` | `field`, `scalar`, `group` | — | — |
| `run_hsort_tests` | `test_run_hsort_tests` | `util` | — | — |
| `run_ctz_tests` | `test_run_ctz_tests` | `util` | — | — |
| `run_secp256k1_memczero_test` | `test_run_memczero` | `util` | — | — |
| `run_secp256k1_is_zero_array_test` | `test_run_is_zero_array` | `util` | — | — |
| `run_secp256k1_byteorder_tests` | `test_run_byteorder_tests` | `util` | — | — |
| `run_xoshiro256pp_tests` | `test_run_xoshiro256pp_tests` | `testutil` | — | — |
| `run_scratch_tests` | — | — | n/a | n/a |
| `run_deprecated_context_flags_test` | — | — | n/a | n/a |

`run_scratch_tests` covers upstream's scratch-space allocator, which exists for
`ecmult_multi`'s heap strategy; this implementation is allocation-free per `CLAUDE.md`, so
there is no scratch space to test. `run_deprecated_context_flags_test` covers C API flags
deprecated before v0.7.1 that this implementation never exposes. Both omissions are
deliberate; revisit if Phase 9 tier 3 linking requires the symbols to exist.

### Signing modules (Phases 6–7)

| upstream test | Odin mirror | package | tier 2 | tier 3 |
|---|---|---|---|---|
| `run_ecdsa_sign_verify` | `test_run_ecdsa_sign_verify` | `ecdsa` | ✅ | — |
| `run_ecdsa_end_to_end` | `test_run_ecdsa_end_to_end` | `ecdsa` | ✅ | — |
| `run_ecdsa_der_parse` | `test_run_ecdsa_der_parse` | `ecdsa` | — | — |
| `run_ecdsa_edge_cases` | `test_run_ecdsa_edge_cases` | `ecdsa` | ✅ | — |
| `run_ecdsa_wycheproof` | `test_run_ecdsa_wycheproof` | `ecdsa` | — | — |
| `run_ec_pubkey_parse_test` | `test_run_ec_pubkey_parse_test` | `extrakeys` | — | — |
| `run_eckey_edge_case_test` | `test_run_eckey_edge_case_test` | `extrakeys` | — | — |
| `run_eckey_negate_test` | `test_run_eckey_negate_test` | `extrakeys` | — | — |
| `run_pubkey_comparison` | `test_run_pubkey_comparison` | `extrakeys` | — | — |
| `run_pubkey_sort` | `test_run_pubkey_sort` | `extrakeys` | — | — |
| `run_random_pubkeys` | `test_run_random_pubkeys` | `extrakeys` | — | — |
| `modules/recovery/tests_impl.h` | recovery tests | `recovery` | ✅ | — |
| `modules/ecdh/tests_impl.h` | ecdh tests | `ecdh` | ✅ | — |
| `modules/schnorrsig/tests_impl.h` | schnorr tests | `schnorr` | ✅ | — |
| `modules/extrakeys/tests_impl.h` | extrakeys tests | `extrakeys` | ✅ | — |
| `modules/ellswift/tests_impl.h` | ellswift tests | `ellswift` | ✅ | — |
| `modules/musig/tests_impl.h` | musig tests | `musig` | — | — |

### Constant-time (Phase 8)

| upstream | Odin | tier 2 | tier 3 |
|---|---|---|---|
| `src/ctime_tests.c` | `ct_tests/` | built ✅ | **cannot run here** |

The harness exists and exercises six secret paths — `pubkey_create`, `ecdsa.sign`,
`schnorr.sign`, `ecdh`, `privkey_tweak_add`, and MuSig2 `nonce_gen` + `partial_sign` —
marking secrets undefined and declassifying each published output with a stated
justification.

```sh
./ct_tests/build.sh --valgrind
valgrind --error-exitcode=1 ./ct_tests.bin
```

**The memory-checker route cannot run on macOS ARM64.** Verified rather than assumed:
`brew install valgrind` refuses with "Linux is required for this software", and clang
rejects `-fsanitize=memory` for `arm64-apple-darwin`. Run that route on Linux or in CI.

**A statistical timing test runs everywhere and is currently clean:**

```sh
odin run ct_tests/ -o:speed -define:DUDECT=true
```

dudect-style (Reparaz/Balasch/Verbauwhede, DATE 2017): time each operation with a fixed
secret and with a random one, interleaved, and apply Welch's t-test. All five measured
paths score |t| < 2.0 against a threshold of 10.

The test is **validated by injection**, which is the only way to trust a negative result:

| injected leak | functional suite | differential oracle | dudect |
|---|---|---|---|
| ECDH uses variable-time `ecmult` | passes | passes | **\|t\| = 20.2** |
| ECDSA branches on secret parity | passes | passes | **\|t\| = 44.2** |

Both leaks are invisible to every other test in this project. That is the whole argument
for Phase 8 existing, demonstrated rather than asserted.

It bounds rather than proves: a negative result means no leak was detected at this sample
size on this machine, and it cannot see leaks that never reach wall-clock time. valgrind
remains the gate for `ct-verified`.

The harness **exits 2 rather than 0 when no checker is compiled in**. A constant-time test
that silently verifies nothing is worse than no test, because it produces a green result
that means nothing — so this failure mode is loud by construction.

---

## Benchmarks

Upstream ships `src/bench.c` (public API), `src/bench_internal.c` (field, scalar, group,
ecmult primitives), and `src/bench_ecmult.c`. Mirror all three under `bench/`, reporting
the **same operation names and `us/op` units** so a run of ours and a run of upstream's can
be diffed line by line.

A side-by-side mode runs each operation through the `oracle` FFI into the prebuilt
`libsecp256k1.a` in the same process, on the same inputs, and prints an Odin-vs-C ratio
column. That makes performance regressions as visible as correctness ones, and it reuses
the oracle machinery Phase 9 needs anyway.

`bench/` links C and therefore lives outside the library's import graph, same rule as
`oracle/` and `ct_tests/`. Field and scalar benchmarks can start as soon as Phases 1–2
land; the public-API benchmarks follow Phase 6.

Benchmarks are a **reporting tool, not a gate** — no phase is blocked on hitting a
performance target. Correctness and constant-time behaviour outrank speed every time; a
benchmark result never justifies weakening a `*_verify` check or taking a variable-time
path on secret data.

---

## What these tests structurally cannot catch

Mutation testing has been applied at each phase, and it found a real coverage gap in the
group layer. It also demonstrated the limit of the approach: replacing ECDH's
`ecmult_const` with the variable-time `ecmult` **passes the entire suite**. It must — the
two compute the same point, and differ only in whether the running time depends on the
secret scalar.

No functional test can detect that. A constant-time violation is invisible to any check
that only looks at outputs, which is why `CLAUDE.md` says "looks branchless" is not
evidence and why the Phase 8 valgrind harness is a gate rather than a nicety. Until it
runs, every `unverified` row in `TRUST.md` should be read as "correct, timing unknown".

## Exhaustive mode: current scope

`-define:EXHAUSTIVE_ORDER=7|13|199` currently works for `field`, `modinv`, `scalar` and
`group`. The **full tree does not build** in that mode, and the failure is real rather than
cosmetic:

```
ecmult/ecmult_gen.odin(208): runtime assertion: gen_compute_table: u*2 != gen
```

Upstream swaps the entire scalar representation under `EXHAUSTIVE_TEST_ORDER` — see
`scalar_low.h` / `scalar_low_impl.h`, where a scalar becomes a single `uint32` modulo the
small order and `split_lambda` becomes plain modular arithmetic. This implementation's
`scalar` package always works modulo the real n, so `scalar_half(1)` returns the inverse of
2 modulo the *real* n, and the comb table for `ecmult_gen` cannot be built on a
reduced-order curve.

The group-layer exhaustive tests pass at all three orders because they use no scalars at
all — every ordered pair through all three addition formulas, 15 tests per order.

Closing the rest means restructuring `scalar` (about 1,000 lines, with the 4x64 reduction
structure baked into `scalar_mul.odin` in roughly 57 places) around a swappable modulus.
That work is **not done**, and exhaustive coverage of `ecmult`, `ecdsa` and `schnorr` does
not exist.

Its priority dropped once the differential oracle landed. Exhaustive small-curve testing
and fuzzed differential testing target the same layers by different means, and for
`ecmult`/`ecdsa`/`schnorr` the oracle is arguably the stronger signal: it exercises the
*real* 256-bit curve against a reference implementation rather than a reduced-order
analogue. What exhaustive mode would still add uniquely is coverage of the degenerate group
cases *inside* those higher layers. That remains a genuine gap.

Worth noting: the invariant layer caught this. `gen_compute_table` asserts that its ladder
result really is half the generator, and that assertion fired rather than silently building
a wrong table.

## Running

```sh
odin test . -all-packages                    # everything
odin test . -all-packages -debug             # with *_verify invariants on — do this in CI
odin test . -define:EXHAUSTIVE_ORDER=13      # small-order exhaustive curve tests
odin test . -define:ODIN_TEST_NAMES=field.test_run_fe_mul    # a single test
```

Randomized tests take their iteration count from `COUNT`, mirroring upstream's
`-define:COUNT=64` knob. Raise it in CI.
