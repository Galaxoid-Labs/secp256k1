# TODO — closing the gap to "verified"

Written after an honest audit. The implementation is complete and the differential oracle
reports zero divergences, but several gates named in `DEVELOPMENT.md` have never run, and
some upstream test functions have no counterpart here at all.

**The current defensible claim** is: *passes 81 self-written tests including mirrors of 42
upstream test functions, byte-identical to libsecp256k1 across ~18,000 fuzzed inputs, and
passes the official BIP340 vectors.* It is **not** "passes libsecp256k1's tests" — that
requires Strategy A, item 5 below.

Everything in items 1–7 runs on macOS. Only items 8–9 need Linux.

---

## 1. BIP327 MuSig2 vectors — hard gate, Phase 7

**Why first:** MuSig2 is the highest-risk module in the project and has the least external
validation. It is also the cheapest to close.

Source is already local: `~/Development/secp256k1/src/modules/musig/vectors.h`, 135 cases
covering key aggregation (valid and error), nonce generation, and nonce aggregation.

- [ ] Transcribe the vectors into `tests/musig/` (unmodified — `CLAUDE.md` forbids editing them)
- [ ] Cover the error cases too; they check that invalid input is *rejected*
- [ ] Include the KeySort vectors, which live in `extrakeys/tests_impl.h` upstream

## 2. MuSig2 differential oracle coverage

**Why:** the oracle currently skips musig entirely. The riskiest module has zero
differential coverage.

- [ ] Bind the musig C API in `oracle/` (`musig_pubkey_agg`, `nonce_gen`, `nonce_agg`,
      `nonce_process`, `partial_sign`, `partial_sig_agg`, tweaks)
- [ ] Compare aggregate keys, nonces and partial signatures on fuzzed inputs
- [ ] Note: nonce generation is deterministic given the same session id, so exact-match
      comparison should be possible rather than round-trip only

## 3. Wycheproof ECDSA — hard gate, Phase 6

**463 cases, 301 of them expected-invalid.** Already vendored at
`~/Development/secp256k1/src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json`.

These are *chosen* adversarial inputs — malleability, DER edge cases, boundary values —
which random fuzzing will not find. The 301 invalid cases matter more than the 162 valid
ones: they check what we *reject*.

- [ ] Parse the JSON at build time or transcribe to an Odin table
- [ ] Run through `signature_parse_der` + `verify`, asserting the expected verdict
- [ ] Expect failures on first run; each is a real finding

## 4. Wycheproof ECDH

**752 cases**, at `~/Development/secp256k1/src/wycheproof/ecdh_secp256k1_test.json`.

- [ ] Same approach as item 3

## 5. Strategy A — link upstream's actual `tests.c`

**This is the item that licenses the headline claim.** `CLAUDE.md` is explicit: do not say
"passes libsecp256k1's tests" until this links and passes.

`tests.c` is 7,851 lines and reaches past the public API into **118 distinct internal
symbols** (`secp256k1_fe_*`, `scalar_*`, `ge_*`, `gej_*`, `ecmult_*`, `modinv*`).

- [ ] Create `csuite/` — a second, wider export surface exposing those internals under the
      C ABI, test-only and never shipped (distinct from `capi/`, per `DEVELOPMENT.md` §0.5)
- [ ] Match upstream's struct layouts exactly, or the tests will read garbage
- [ ] Link and run `tests.c`
- [ ] Then `tests_exhaustive.c` — but that needs item 6 first

## 6. `scalar_low` for exhaustive mode

Upstream swaps the whole scalar representation under `EXHAUSTIVE_TEST_ORDER`: a scalar
becomes a single `uint32` mod the small order and `split_lambda` becomes plain modular
arithmetic. Ours is always 4x64 mod the real n, so the full tree does not build in
exhaustive mode.

- [ ] Add a `when params.EXHAUSTIVE_ORDER > 0` alternative `Scalar` with the same API
- [ ] ~1,000 lines to restructure; the 4x64 reduction is baked into ~57 places in
      `scalar_mul.odin`
- [ ] Unblocks exhaustive `ecmult`/`ecdsa`/`schnorr`, and `tests_exhaustive.c`

## 7. The 21 unmirrored upstream test functions

No Odin counterpart exists for:

`run_ecdsa_der_parse`, `run_ecdsa_wycheproof` (item 3), `run_ec_pubkey_parse_test`,
`run_eckey_edge_case_test`, `run_eckey_negate_test`, `run_pubkey_comparison`,
`run_pubkey_sort`, `run_random_pubkeys`, `run_cmov_tests`, `run_hsort_tests`,
`run_ctz_tests`, `run_secp256k1_memczero_test`, `run_secp256k1_is_zero_array_test`,
`run_secp256k1_byteorder_tests`, `run_xoshiro256pp_tests`, `run_ecmult_near_split_bound`,
and `modules/musig/tests_impl.h` (items 1–2).

- [ ] Mirror them, or record why each is not applicable

---

## Needs Linux

## 8. Constant-time verification under valgrind — the `ct-verified` gate

**This is the only item that can move a symbol from `unverified` to `ct-verified`.**

Confirmed unavailable on macOS ARM64, not assumed: `brew install valgrind` refuses with
"Linux is required for this software", and clang rejects `-fsanitize=memory` for
`arm64-apple-darwin`.

The harness is already written and exercises six secret paths. On a Linux box:

```sh
./ct_tests/build.sh --valgrind
valgrind --error-exitcode=1 ./ct_tests.bin
```

- [ ] Run it; fix anything it reports
- [ ] Extend coverage to the remaining secret paths (musig tweaks, keypair operations)
- [ ] Update `TRUST.md` — this is what flips the table

The statistical (dudect) test runs on macOS and is currently clean, but it measures
wall-clock time and cannot see leaks that never reach the clock. It is evidence, not the
gate.

## 9. x86-64 benchmarks and differential run

Every performance figure so far is ARM64, where upstream ships **no** assembly. On x86-64
upstream enables hand-written assembly for the scalar reduction, so the comparison is
materially different and has never been measured.

- [ ] Re-run `bench/` and `tests/oracle/` on x86-64
- [ ] Report both architectures separately; do not average them

---

## Suggested order

1, 2 → 3, 4 → 7 → 6 → 5, with 8 as soon as a Linux box is available (it is independent of
everything else and is the single biggest gap in the trust story).
