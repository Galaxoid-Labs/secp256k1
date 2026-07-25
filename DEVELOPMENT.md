# secp256k1 — Pure-Odin port of libsecp256k1

A from-scratch Odin implementation of Bitcoin's secp256k1 library, targeting full
functional parity with `bitcoin-core/secp256k1` **and** complete pass of its test
corpus.

**Naming convention in this doc:** `secp256k1` (or "this implementation") is the Odin
project; **libsecp256k1** is the upstream C reference used only as a differential oracle.

---

## 0. Non-negotiable design decisions (make these before writing arithmetic)

These are load-bearing. Changing them later means rewriting the field/scalar core and
every test that touches internal representation.

### 0.1 Representation parity — the fork in the road

"Pass libsecp256k1's tests completely" has two readings, and they demand different
internal designs. Pick one **now**:

- **Strategy A — representation-identical + C shim.** Mirror the C internals byte-for-byte:
  field as 5×52-bit limbs with the same `magnitude`/`normalized` discipline, scalar as
  4×64, identical `ge`/`gej` layout. Expose a thin C ABI so the *actual upstream*
  `tests.c` / `tests_exhaustive.c` link against Odin symbols and exercise them directly.
  This is the ONLY way "passes libsecp256k1's literal tests" is strictly true.
  Cost: no freedom to pick a nicer representation; you inherit their magnitude bookkeeping.

- **Strategy B — translate the suite.** Design the representation as you like, port
  `tests.c` into Odin `testing`. Faithful in spirit, nicer codebase. But the claim
  becomes "passes an Odin port of the suite," not "passes libsecp256k1's tests." Be
  precise about which claim ships in the README.

**Recommendation: Strategy A throughout.** Representation-identical core *and* link the
actual upstream `tests.c`, `tests_exhaustive.c`, and module tests against Odin symbols
wherever they exist. The portable Class A vectors run *on top* of that — they don't replace
linking the real suite. No translated-suite substitution anywhere.

### 0.2 Curve constants must be compile-time swappable

`tests_exhaustive.c` reparameterizes the curve to a tiny order to test *every* group
element. Gate the curve constants behind a config value (`when EXHAUSTIVE_ORDER > 0`) from
day one. Retrofitting this later is miserable.

### 0.3 Constant-time is a property you VERIFY, not one you intend

Every secret-dependent branch or secret-indexed load is a side channel. The discipline:
`cmov`-style selects instead of `if` on secrets, no secret array indices, blinded
`ecmult_gen`. This is verified in Phase 8 via valgrind, not asserted by reading the code.

### 0.4 The C library is your oracle, not your fallback

This is an educational build held to production standards — so the pure-Odin path is the
whole deliverable, secret-key operations included. The existing C library is kept for one
purpose: a **differential-testing oracle** (Phase 9) — feed identical inputs to both, assert
byte-identical output. It is *not* a production fallback here; the point is to build the
secret paths yourself, MuSig2 included.

Keep a `TRUST.md` table tracking each symbol's verification status: `ct-verified` (cleared
the Phase 8 harness) vs `unverified`. "Verified" means it meets *this project's* bar, not
that it's audited. Orthogonal to everything else: unaudited hand-rolled crypto should never
guard real value — "treat as if used" is a discipline for how you build, not a licence to
point it at real keys.

### 0.5 Distribution model — submodule now, `core:crypto` maybe later

This ships as a **library consumed via git submodule**, with a longer-term hope of being
proposed for Odin's `core:crypto`. Both goals constrain the layout, and they pull in
opposite directions, so the resolution is recorded here.

**Repository layout.** Packages live at the repository root; there is **no `src/`
directory**. The root directory is package `secp256k1`; sub-packages are sibling
directories (`params/`, `field/`, `scalar/`, …). Odin resolves quoted imports relative to
the importing file, so a consumer who checks this out as `their-project/secp256k1/` writes
`import "secp256k1"` and `import "secp256k1/field"` with no collection configuration. The
**checkout directory name is part of the public import path** — say so in the README.

**Keep C linkage off every consumer path.** `oracle/` (the libsecp256k1 FFI), the Strategy A
C shim, and `ct_tests/` must never be reachable from the import graph of the library
packages. A consumer whose build wanders into them gets a link error for a library they
never asked for. Verify this holds for `odin test` run from a *parent* directory, not just
from this repo.

**Tests live in a parallel `tests/` tree, never inside the packages they exercise.**
Odin does *not* exclude `_test.odin` files from ordinary builds — verified empirically, not
assumed — so a test file inside `field/` would drag `core:testing` into every consumer's
build of this library. Odin's own `core/` has zero in-package test files for the same
reason; everything lives under its top-level `tests/`. Matching that convention is also
what a `core:crypto` submission would require.

	tests/
	├── tests.odin          package tests; @require-imports every child
	├── field/              package test_field
	└── modinv/             package test_modinv

Run with `odin test tests/ -all-packages`. The consequence is that tests may only use a
package's *exported* surface. That costs nothing here: `field`, `scalar`, `group` and the
rest are internal to the library — the public API is the root `secp256k1` package — so
their exports already are the internal surface upstream's `tests.c` reaches into. Keep it
that way: do not add `@(private)` to something a test needs to see.

**Test corpora are not vendored.** Wycheproof JSON alone is multiple megabytes; BIP340 and
BIP327 add more. Vendoring them would make every consumer clone the whole corpus to obtain
a few thousand lines of arithmetic. The corpus is fetched into a gitignored `vectors/`
directory by a script, or attached as a nested submodule. See `TESTING.md`.

**What upstreaming to `core:crypto` would actually mean.** Odin core already ships
`core:crypto/ecdsa` and `core:crypto/ecdh` on top of `core:crypto/_weierstrass`, which
supports secp256r1 and secp384r1 through explicit `proc` groups. Its field arithmetic comes
from `core:crypto/_fiat` — **fiat-crypto generated, Montgomery domain**. Fitting into
`_weierstrass` would therefore require exactly the generated arithmetic the prime directive
forbids, and would discard the 5×52 magnitude discipline that Strategy A exists to
preserve. So the only viable path is proposing a **standalone `core:crypto/secp256k1`**,
justified by the large curve-specific surface (BIP340, BIP327, ellswift, recovery) that
`_weierstrass` has no notion of. Nothing about Phases 1–9 changes either way.

**Layered API.** Strategy A is *defined* by mirroring libsecp256k1's internals and C API —
context objects, `context_randomize`, illegal-argument callbacks, a C ABI. That is
precisely what makes it un-idiomatic for core, whose crypto packages are flat,
allocation-free, slice-based, and have no context or callback machinery. These stack rather
than conflict:

- **Core (Phases 1–9, as specced).** Strict parity: sub-packages, magnitude bookkeeping,
  contexts, callbacks, C shim. The upstream suite links against this. Unchanged.
- **Facade (root package `secp256k1`).** A thin, zero-cost, idiomatic Odin surface —
  `sign(priv, msg) -> (Signature, Error)`, no context threading, `mem.zero_explicit` for
  wiping, `crypto.rand_bytes` for entropy. This is what a submodule consumer touches and
  what a core proposal would carry.

Build the facade after the core is green. Design the sub-package APIs knowing it sits on
top, so nothing forces context state into places it does not belong.

**Examples mirror upstream's.** Upstream ships `examples/{ecdsa,ecdh,schnorr,ellswift,
musig}.c`. Port each to a runnable Odin package under `examples/`, keeping the same
structure so the two can be read side by side. They are written against the facade, which
makes them a standing check that the idiomatic surface is actually usable. Each lands with
the phase that enables it; none may appear in the library's import graph.

**C-compatible library is a shipped deliverable, not test scaffolding.** The library also
builds as a C-ABI shared and static library, so Rust, Python, Go, Zig, Swift and anything
else with an FFI can link it. This unifies with Strategy A rather than competing with it —
the C ABI was already required to link upstream's tests. There are two distinct export
surfaces and they must not be conflated:

- **`capi/` — the public ABI, shipped.** `@(export) proc "c"` wrappers whose signatures,
  struct layouts, and semantics match libsecp256k1's `include/secp256k1*.h`, so existing C
  consumers can link against it as a drop-in.

  ```
  odin build capi/ -build-mode:shared -o:speed    # .dylib / .so / .dll
  odin build capi/ -build-mode:static -o:speed    # .a
  ```

  Headers are **hand-written to match the documented ABI**, not copied from upstream. That
  keeps the repository uniformly BSD-3 and keeps the header an honest statement of what
  this implementation guarantees. Upstream's headers are the specification being matched,
  and a test asserts struct sizes and alignments agree.

- **`csuite/` — internal symbols, test-only, never shipped.** Upstream's `tests.c` reaches
  past the public API into `secp256k1_fe_mul`, `secp256k1_scalar_*`, `secp256k1_ge_*` and
  friends. Linking it therefore needs a *second*, much wider export surface covering
  internals. This one exists only to satisfy Phase 9 and must never appear in a released
  artifact.

Entry points crossing the C boundary use `proc "c"` and establish a context only if they
need one; the arithmetic packages are `contextless` and allocation-free, so most do not.
Since a C caller can pass anything, every `capi/` entry point validates its arguments
through the illegal-argument callback rather than trusting them.

**Licence: BSD-3-Clause**, matching Odin core, so upstreaming needs no relicensing
conversation. This is an independent implementation; upstream libsecp256k1 (MIT) is used
only as an oracle and as the source of the test corpus, and none of its code is
incorporated.

---

## Testing model (applies to every phase)

Two classes of test, gated differently:

- **Class A — portable vectors (hard gate, 100% required to close a phase):**
  Wycheproof ECDSA JSON, BIP340 CSV, BIP327 MuSig2 vectors, ECDH vectors, serialization
  round-trips, algebraic property tests. Language-agnostic. Passing = crypto is correct.

- **Class B — internal-invariant tests (Strategy A):**
  Randomized identity tests calling internal functions, plus the `*_verify` invariant
  layer (`fe_verify`, `scalar_verify`, `ge_verify`) compiled as `when ODIN_DEBUG`
  assertions. These catch representation/magnitude bugs the black-box vectors can't see.

A phase is "done" only when its Class A vectors are 100% green AND its Class B invariants
hold under randomized runs with `ODIN_DEBUG` on.

---

## Phase 1 — Field arithmetic (`fe`)

- 5×52 limb representation with `u128` for the 64×64→128 products. This **is** the reference
  implementation (upstream's `field_5x52_int128`), not a shortcut. Odin's `u128` is available
  on every target, so no `__int128`-absent fallback is needed. A separate 32-bit `10×26`
  field is optional parity work only (Phase 10); do not build a non-`int128` 5×52 variant —
  upstream has none.
- `magnitude`/`normalized` tracking; `normalize`, `normalize_weak`, `normalizes_to_zero`.
- add, mul, sqr, negate, half; `inv` (via `inv_var` + constant-time `inv`).
- **`sqrt`** via `a^((p+1)/4)` (p ≡ 3 mod 4) — needed by Schnorr `lift_x`; verify by squaring.
- `fe_verify` invariant checks under `ODIN_DEBUG`.

**Gate:** field property tests (inverse round-trip, mul associativity/distributivity,
sqrt∘sqr), magnitude bounds match C after each op.

## Phase 2 — Scalar arithmetic (`scalar`)

- 4×64 representation, reduction mod n (n has no special form — the harder reduction).
- add, mul, negate, inverse, `is_zero`, `is_high` (low-S normalization for BIP62/malleability).
- GLV split scaffolding (λ decomposition) — used later by `ecmult`.
- `scalar_verify` under `ODIN_DEBUG`.

**Gate:** scalar property tests; low-S vectors.

## Phase 3 — Group operations (`ge` / `gej`)

- Affine `ge`, Jacobian `gej`; `add`, `double`, mixed add, `neg`, `is_infinity`.
- `set_xo_var` / `lift_x` (uses Phase 1 `sqrt`), even-y parity helpers.
- Match C's group magnitude limits exactly (Strategy A). `ge_verify` under `ODIN_DEBUG`.

**Gate:** on-curve checks, add/double identities, **exhaustive tests over a small-order
curve** (needs 0.2 in place).

## Phase 4 — Multiplication engines (`ecmult`, `ecmult_gen`)

- `ecmult` (a·G + b·P) with GLV endomorphism + wNAF — variable-time, for verification.
- `ecmult_const` — constant-time scalar·point, for ECDH and any secret multiply.
- `ecmult_gen` with precomputed generator tables **and blinding**.
- Write the table-generation programs in Odin (equivalents of `precompute_ecmult{,_gen}`).
  No vendored or pre-baked tables — the generators are part of the build and part of what
  you're reproducing. Regenerating from scratch must reproduce byte-identical tables.

**Gate:** `k·G` vs known vectors; `ecmult_const` agrees with `ecmult` on public inputs.

## Phase 5 — Context, hashing, callbacks, infrastructure

- `secp256k1_context`: creation flags, `context_randomize` (covert-channel blinding seed).
- Illegal-argument + error callback system (settable, no-crash validation on every public fn).
- SHA256, HMAC-SHA256, RFC6979 deterministic nonce generator.
- Tagged-hash helper: `SHA256(SHA256(tag)‖SHA256(tag)‖m)`, with the three BIP340 tag
  midstates precomputed.

**Gate:** SHA256/HMAC vectors, RFC6979 vectors, callback-fires-on-bad-input tests.

## Phase 6 — Core signing modules

Dependency order matters; each is a hard gate before the next.

1. **extrakeys** — x-only pubkey + keypair types. (Schnorr/MuSig depend on it.)
2. **ecdsa** — sign (RFC6979), verify, low-S; DER + compact serialization.
   *Gate:* **Wycheproof full pass.**
3. **recovery** — recoverable sig + pubkey recovery (recovery-id byte).
   *Gate:* recovery vectors + round-trip against ecdsa.
4. **ecdh** — `ecmult_const` then hash; default and custom hashfp.
   *Gate:* ECDH vectors. (Secret multiply → `unverified` until Phase 8 CT-clears it.)
5. **schnorrsig** — BIP340. Secret conditional negations for even-y on both `d` and `k`
   (constant-time selects). aux_rand masking. Sign-then-verify self-check before return.
   *Gate:* **BIP340 CSV full pass**, including the invalid/verify-should-fail rows.

## Phase 7 — Advanced modules

- **ellswift** — ElligatorSwift map (curve↔uniform-64-bytes) for BIP324 v2 transport;
  x-only ECDH over encoded keys. New, self-contained math with its own edge cases.
  *Gate:* ellswift vectors + decode∘encode consistency.
- **musig** — MuSig2 / BIP-327. The largest and highest-consequence piece:
  - key aggregation with second-key coefficient (anti-rogue-key), key sorting, x-only + plain tweaks with parity bookkeeping.
  - two-round nonces; binding coefficient `b` (anti-Wagner). 
  - **Nonce-reuse resistance is a design constraint, not a test:** replicate the
    single-use secnonce API shape (zero-after-use, session-id-seeded generation). A
    MuSig2 that "works" but permits nonce reuse silently leaks secret keys.
  *Gate:* **BIP327 vectors full pass**; dedicated ctime tests in Phase 8. Last symbol to
  reach `ct-verified`; treat its nonce handling as the highest-risk code in the project.

## Phase 8 — Constant-time verification harness

The part that makes secret-key paths trustworthy. Portable to Odin because valgrind
operates on the native binary:

- Build an instrumented target; mark secret buffers UNDEFINED (valgrind client requests
  via a small C shim), run each secret-dependent op, fail on any secret-dependent branch/load.
- `declassify` (`MAKE_MEM_DEFINED`) on legitimately-public outputs (signatures, pubkeys).
- Port the upstream `ctime_tests.c` coverage: ecdsa sign, schnorr sign, ecdh, ec ops on
  secret keys, and — explicitly — the musig secnonce/nonce-point paths.
- (MSan-based CT is the harder route; Odin's LLVM backend doesn't cleanly expose the
  instrumentation, so lean on valgrind.)

**Gate:** zero valgrind CT findings across all secret paths → those symbols flip from
`unverified` to `ct-verified` in `TRUST.md`.

## Phase 9 — Suite parity & CI

- Wire the full Class A corpus (Wycheproof, BIP340, BIP327, ECDH) into CI as a blocking gate.
- Exhaustive tests over small-order curve in CI.
- (Strategy A) Link the thin C shim against upstream `tests.c` / `tests_exhaustive.c` and
  run them against Odin symbols — the literal "passes libsecp256k1's tests" claim.
- Differential fuzzing: same random inputs into this implementation and libsecp256k1 via FFI; assert
  byte-identical outputs. This is the strongest correctness signal you can get cheaply.

## Phase 10 — Assembly kernel (OPTIONAL, and narrow)

Reality check on the C library's asm, re-verified against the v0.7.1 tree in this repo
(supersedes an earlier, partly incorrect note here):

- **Field 5×52 — no assembly.** `field_5x52_impl.h` contains no `USE_ASM_X86_64` path;
  it relies entirely on the compiler's `__int128`. Our `u128` backend therefore *is* the
  reference implementation, not a stand-in for asm.
- **Scalar 4×64 — x86-64 assembly still exists.** `scalar_4x64_impl.h` has two
  `USE_ASM_X86_64` blocks, in `scalar_reduce_512` and `scalar_mul_512`, and
  `CMakeLists.txt` enables it by default on x86-64 (`SECP256K1_ASM=AUTO`). It was *not*
  removed. Our pure-Odin scalar is thus competing against hand-written asm on x86-64,
  though not on ARM64, where upstream falls back to the same C we mirror.
- **ARM32 `10×26` field** — `src/asm/field_10x26_arm.s`, the only external assembly file,
  and upstream marks it experimental.

Consequences: benchmark comparisons on x86-64 are Odin-vs-asm for scalar operations and
Odin-vs-C everywhere else — report the target architecture alongside any ratio, or the
numbers mislead. On ARM64 (this development machine) every comparison is Odin-vs-C.

This phase remains optional. Porting the ARM32 kernel applies solely to the 32-bit field
backend, which only exists if `10×26` is implemented at all. An x86-64 scalar kernel is a
separate, also-optional exercise, and would need the same differential and CT re-verification.

If pursued: implement the 32-bit `10×26` field first, then its ARM32 kernel in Odin inline
`#asm`, guarded by config `when`, with a differential gate against the pure `10×26` path and
CT re-verification. Do this only after Phases 1–9 are fully green.

---

## Sequencing summary

```
0 decisions ─► 1 fe ─► 2 scalar ─► 3 ge/gej ─► 4 ecmult ─► 5 ctx/hash/cb
                                                               │
        ┌──────────────────────────────────────────────────────┘
        ▼
6 extrakeys ─► ecdsa ─► recovery ─► ecdh ─► schnorrsig
        │
        ▼
7 ellswift, musig ──► 8 CT harness ──► 9 full-suite parity + CI
```

Public-data paths (verify, recovery, ellswift decode, address/key derivation) are
`ct-verified` trivially — no secrets to leak — once their Class A vectors pass. Secret-key
paths stay `unverified` until the Phase 8 CT harness clears them; MuSig2 signing is the last
to graduate. The C library rides alongside the whole way as the differential oracle, never
as a fallback.
