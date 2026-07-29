# CLAUDE.md — secp256k1 (pure-Odin)

Read this in full before touching code, every session. The phased build plan lives in
`DEVELOPMENT.md`; this file is the standing law that applies across all phases.

## What this is

This project — package name `secp256k1` — is a from-scratch, pure-Odin implementation of the
secp256k1 elliptic curve, targeting full functional parity with `bitcoin-core/secp256k1` and
a complete pass of its test corpus. It is an **educational project held to production
standards**. That means the rigor of real crypto engineering with none of the consequences of
shipping — and one hard rule that never bends:

> Unaudited hand-rolled crypto never guards real value. Nothing here is for real keys,
> real funds, or production use. "Treat it as if it were used" is a discipline for *how we
> build*, not a licence to deploy.

**Naming:** `secp256k1` refers to *this* Odin implementation; **libsecp256k1** refers to the
upstream C library, which appears here only as a differential-testing oracle.

## Prime directive: NO SHORTCUTS

This overrides convenience, speed, and your own instinct to reach for a library. Concretely:

- **Hand-write all arithmetic.** Derive the field (5×52) and scalar (4×64) code yourself.
  No fiat-crypto translation, no generated arithmetic, no bignum dependency (no GMP, no
  `core:math/big` for the hot path). Understand every reduction and every magnitude bound.
- **No vendored tables.** Write the `precompute_ecmult{,_gen}` generator programs in Odin.
  Regeneration from scratch must reproduce byte-identical tables; that reproduction is a test.
- **Field backend.** The 5×52 representation with `u128` intermediates *is* the reference
  implementation (upstream's `field_5x52_int128`); it is not a shortcut. Unlike C, Odin's
  `u128` is available on every target, so you do **not** need C's `__int128`-absent fallback.
  A second backend (the separate 32-bit `10×26` field) is optional parity work, not required —
  see Phase 10. Don't invent a non-`int128` 5×52 path; upstream doesn't have one.
- **Strategy A testing.** Link the *actual* upstream `tests.c` / `tests_exhaustive.c` /
  module tests against this implementation's symbols via a thin C shim. Portable vectors run on top; they
  do not replace linking the real suite. No translated stand-in suite.
- **No stubs left in a "done" phase.** A phase is closed only when its gate (see
  `DEVELOPMENT.md`) is 100% green — vectors *and* internal invariants.

If a task tempts you toward a shortcut, stop and flag it rather than taking it.

## The C library is an oracle, not a fallback

The existing libsecp256k1 (via `foreign` FFI) exists in this repo for exactly one reason:
**differential testing**. Feed identical inputs to this implementation and to libsecp256k1; assert byte-identical
output. It is never a runtime fallback and never signs/derives anything we ship. When the two
disagree, that divergence is the bug — chase down *why* (unnormalized magnitude, skipped
low-S, endomorphism sign, wrong parity), don't paper over it.

## Trust model

Track every public symbol in `TRUST.md` with one of two states:

- `unverified` — correct on vectors but not yet cleared by the constant-time harness.
- `ct-verified` — zero valgrind CT findings across its secret paths (Phase 8).

Public-data paths (verify, recovery, ellswift decode, key/address derivation) are
`ct-verified` trivially once their vectors pass — they have no secrets to leak. Secret paths
(ecdsa sign, schnorr sign, ecdh, musig) stay `unverified` until the harness clears them.
MuSig2 signing is the last to graduate and its nonce handling is the highest-risk code here.

## Constant-time rules (secret-dependent code)

Applies to any path touching a secret key, nonce, or secret scalar:

- No `if` / `switch` / early-return branching on secret data. Use constant-time selects
  (`cmov`-style helpers), not control flow.
- No secret-indexed memory access (no table lookups indexed by secret bits without a
  constant-time scan).
- Secret scalar multiplies use `ecmult_const`, never the variable-time `ecmult`/wNAF path.
- Blind `ecmult_gen`; honour `context_randomize`.
- Zero secret buffers after use (explicit wipe that the optimizer can't elide).
- Every secret path gets a `ctime_tests` entry (Phase 8). "Looks branchless" is not
  evidence — valgrind is.

## Odin conventions (dev-2026-06)

- **Layout:** root package `secp256k1` (public API), one sub-package per module — `field`,
  `scalar`, `group`, `ecmult`, `hash`, `context`, `ecdsa`, `schnorr`, `ecdh`, `recovery`,
  `extrakeys`, `ellswift`, `musig`. Imports read `import "secp256k1/field"` etc. Shared curve
  constants live in one place, config-swappable (see below). The name collision with the C
  library is prose-only — in code, our project is package `secp256k1` and the C reference is
  reached solely through the quarantined `oracle` package (below); they never mix.
- **`hash/` declares `package secp_hash`, not `package hash`.** Odin requires package names to
  be globally unique within a build, and `core:hash` claims that name. A consumer linking this
  library alongside anything that reaches `core:hash` — `core:compress/gzip` and
  `core:compress/zlib` both import it, so any HTTP client with transparent decompression does —
  otherwise fails to compile with "Duplicate declaration of 'package hash'". The directory is
  still `hash/` and importers alias it back (`import hash "../hash"`), so every call site still
  reads `hash.sha256_*`. Do not rename it back; the collision is not hypothetical and was found
  by a downstream consumer.
- **Naming:** `Ada_Case` types (`Field_Elem`, `Scalar`, `Ge`, `Gej`), `snake_case` procs
  (`fe_normalize`, `scalar_mul`, `ge_add`).
- **Errors:** enum error values + `or_return`. No panics in library paths; validation
  routes through the illegal-argument callback system, matching upstream behaviour.
- **Allocation:** hot paths are **allocation-free** (upstream guarantees no runtime heap
  allocation — match it). Fixed-size structs and `[dynamic; N]T` where a bounded buffer is
  needed; no `context.allocator` calls inside field/scalar/group/ecmult.
- **Config:** curve parameters and backend selection via `-define:` + `when`. The curve
  order MUST be compile-time swappable (`when EXHAUSTIVE_ORDER > 0`) for the exhaustive tests.
- **Internal invariants:** `fe_verify` / `scalar_verify` / `ge_verify` compiled under
  `when ODIN_DEBUG` (or a `-define:` flag), asserting representation/magnitude bounds. Run
  the randomized tests with these on.
- **FFI:** the C `libsecp256k1` oracle is bound with `foreign import` + `foreign` blocks in a
  single `oracle` package, imported only by test code. It is the *only* package that links C.

## Build & test

```
odin build . -o:speed                      # release build
odin test  . -all-packages                 # full unit + property + vector suite
odin test  . -define:ODIN_DEBUG=true       # run with internal *_verify invariants on
odin test  . -define:EXHAUSTIVE_ORDER=13   # exhaustive small-order curve tests
```

Constant-time harness (Phase 8), runs the instrumented binary under valgrind:
```
odin build ct_tests/ -debug -o:none
valgrind --error-exitcode=1 ./ct_tests     # any secret-dependent branch/load => fail
```

Differential oracle (Phase 9): the `oracle` test package must report zero divergences.

## Definition of done (per symbol)

1. Class A vectors pass 100% (Wycheproof / BIP340 / BIP327 / ECDH, as applicable).
2. Internal invariants (`*_verify`) hold across randomized runs with debug on.
3. Differential oracle: byte-identical to C on fuzzed inputs.
4. If it touches secrets: a `ctime_tests` entry exists and valgrind is clean → mark
   `ct-verified` in `TRUST.md`.

Only then is it done. Not before.

## Guardrails — do NOT

- Do not add a bignum or crypto dependency to satisfy an arithmetic gap. Implement it.
- Do not vendor or hardcode precomputed tables. Generate them.
- Do not use a variable-time path for secret data because it's simpler.
- Do not weaken or delete a `*_verify` check to make a test pass. The check found a real bug.
- Do not invent or edit test vectors. Vectors come from Wycheproof and the BIPs, unmodified.
- Do not treat the C oracle as a fallback or copy its output into this implementation.
- Do not claim "passes libsecp256k1's tests" unless the real upstream suite links and passes
  (Strategy A). Otherwise say precisely what passed.

## Reference material

- Spec: BIP340 (Schnorr), BIP327 (MuSig2), BIP324 (ellswift transport), RFC6979 (ECDSA nonces).
- Mirror source: `bitcoin-core/secp256k1` — `src/field_5x52_*`, `src/scalar_4x64_*`,
  `src/group_impl.h`, `src/ecmult*`, and each `src/modules/*`.
- Phase plan and gates: `DEVELOPMENT.md` in this repo.
