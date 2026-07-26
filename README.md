# secp256k1

A from-scratch, pure-Odin implementation of the secp256k1 elliptic curve, targeting
functional parity with [`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1).

> **Provided as is.** This library comes without warranty of any kind, express or implied,
> and has not been independently audited. [`TRUST.md`](TRUST.md) records the verification
> status of every public symbol — what has been checked, how, and what has not.

**Status:** all modules implemented — field, scalar, group, ecmult, hash, context, ECDSA,
recovery, ECDH, extrakeys, Schnorr (BIP340), ellswift (BIP324) and MuSig2 (BIP327).

105 tests pass in release and `-debug`, the differential oracle reports **zero divergences**
from libsecp256k1 across thousands of fuzzed inputs on both ARM64 and x86-64 — now including
MuSig2, which previously had none. Performance on x86-64 is **1.04× of C** in aggregate,
including the cost of the constant-time work; see [Performance](#performance).

Published vector corpora now run as hard gates:

| corpus | cases | result |
|---|---:|---|
| Wycheproof ECDSA (bitcoin variant) | 463 | all pass — 301 of them expected-invalid |
| Wycheproof ECDH | 752 | all pass — 473 valid, 49 invalid, 230 "acceptable" |
| BIP340 Schnorr | — | all pass |
| Exhaustive small-curve (orders 7, 13, 199) | entire group | all pass |
| BIP327 MuSig2 — every vector group in `vectors.h` | 38 | all pass |

Adding them, and extending the differential oracle to MuSig2 and ellswift, found six more real defects that every existing test had missed:

- **The strict DER parser accepted long-form length encoding.** DER requires the shortest
  encoding, so `0x81 0x45` is not a legal synonym for `0x45`. A non-unique signature
  encoding is a malleability vector. Caught by 3 of the 301 invalid Wycheproof cases.
- **MuSig2 nonce generation did not implement BIP327.** It was an invented scheme that
  omitted the `MuSig/aux` step and, more importantly, **never hashed the signer's public
  key** — which BIP327 binds in specifically so that two signers sharing entropy cannot
  derive the same nonce. A shared nonce in MuSig2 leaks both secret keys. Nothing caught it
  because every signer computed the same wrong value, so the round-trip test passed. Now
  matches the specification's vectors byte for byte.
- **`ecmult_const` was wrong for every input on the exhaustive curves.** Its `K` constant
  was stubbed to zero, with a note that small-order scalar arithmetic did not exist yet.
  Building that arithmetic (`scalar_low.odin`) and enumerating the group found it in the
  first run.
- **BIP324 `ellswift_xdh` selected the wrong peer key.** `party` says which side *we* are,
  so party A must decode `ell_b64`; this implementation had the two the wrong way round.
  Two instances of it talking to each other still agreed, and the symmetry self-test even
  encoded the inverted convention, so only a comparison against C could see it. Reverting
  the fix produces 768 oracle errors while the ellswift suite stays green.
- **`ellswift_create` derived its randomness with the wrong framing.** The specification
  hashes `seckey || zero32 [|| aux]`; this substituted `aux` *for* the zeros. The output is
  a valid encoding that no other implementation reproduces — and an encoding verifies
  against itself either way.
- **MuSig2 `partial_sign` accepted a zeroed secret nonce.** The `valid` flag caught ordinary
  reuse, but not a secnonce zeroed by another route. Signing with k = 0 makes s = e*d and
  hands the secret key to anyone who sees the partial signature.

**The constant-time gate is clean.** The Phase 8 harness runs under valgrind on
Linux/x86-64 and reports **0 errors from 0 contexts** at both `-o:none` and `-o:speed`. The
ten secret paths it exercises — `pubkey_create`, `ecdsa.sign`, `schnorr.sign`, `ecdh`,
`privkey_tweak_add`, MuSig2 `nonce_gen`/`partial_sign`, keypair creation and x-only tweak,
the MuSig2 aggregate-key tweaks, recoverable signing, and `ellswift.create`/`xdh` — are
marked `ct-verified` in `TRUST.md`. Per-symbol attribution within those paths is
deliberately not claimed; `TRUST.md` explains why.

The harness is validated by injection rather than assumed. Swapping ECDH's constant-time
multiply for the variable-time one — a genuine key-recovery leak — produces 19 error
contexts, while **all 105 functional tests pass and the differential oracle still reports
zero divergences**. That is the sharpest available statement of what this gate catches and
what correctness testing structurally cannot.

Getting there was not a formality. It found:

- **`ecmult_gen`'s constant-time table scan compiled into a branch.** The `cmov` helpers are
  written as branch-free mask arithmetic, but at `-o:speed` LLVM recognized the idiom and
  rewrote the whole scan back into *compare the index, branch, load only the matching
  entry* — reintroducing exactly the secret-dependent branch and secret-indexed load the
  scan exists to prevent. Fixed with a volatile barrier on the mask (upstream's
  `volatile int vflag` serves the same purpose). Confirmed by disassembly, not inspection.
- **Five short-circuit operators on secret data.** `scalar_set_b32_seckey`,
  `fe_normalizes_to_zero`, `ecdh`, and `ecdsa_sig_sign` used `&&`/`||` where upstream
  deliberately uses bitwise `&`/`|`, making the second operand's evaluation conditional on
  the first. `ecdsa_sig_sign` also branched on the low-S flag to set the recovery id.
- **`pubkey_create` and `ecdsa.sign` early-returned on an invalid secret key**, instead of
  substituting a valid scalar and doing identical work either way as upstream does. Note
  what upstream deliberately does *not* do here: it never declassifies key validity, because
  publishing that bit narrows the key's range.
- **`CHECK` evaluated its argument even with the invariant layer compiled out.** Odin
  evaluates call arguments eagerly, so `CHECK(!fe_normalizes_to_zero_var(s))` ran a
  variable-time routine on `gej_rescale`'s blinding factor in every build; only the
  optimizer removed it, and only at `-o:speed`. Upstream's `VERIFY_CHECK` is a macro and
  never evaluates its condition.
- **`keypair_create` erased the keypair behind an `if`** on a flag that folds in key
  validity — the very bit the rest of the routine takes care not to leak. Upstream uses a
  constant-time `memczero` there, which now exists as `ct.czero`.
- **`Ge.infinity` was a 1-byte `bool` against upstream's 4-byte `int`.** Sizes and offsets
  agreed, so nothing failed to link, but a struct allocated by C and written by Odin kept
  C's stack garbage in the upper three bytes — and C then read a nonzero `int` for a point
  that was not at infinity. Found the first time C actually read one of these structs, via
  `csuite`. Now `b32`.

Every one of these passes the full functional suite and the differential oracle. No test
that checks *what* the code computes can see any of them.

## Install

This library is consumed as a git submodule. Clone it into your Odin project so the
directory is named `secp256k1`:

```sh
git submodule add https://github.com/<you>/secp256k1 secp256k1
```

```
your-project/
├── main.odin
└── secp256k1/          <-- this repo; the directory name is part of the import path
    ├── field/
    ├── scalar/
    └── ...
```

Odin resolves quoted imports relative to the importing file's directory, so from
`main.odin`:

```odin
package main

import "secp256k1"          // high-level API
import "secp256k1/field"    // low-level field arithmetic, if you want it
```

Renaming the checkout directory changes the import path. If you prefer to vendor it
elsewhere, use a collection instead:

```sh
odin build . -collection:lib=./third_party
```
```odin
import "lib:secp256k1"
```

## Layout

Packages live at the repository root — there is no `src/` directory.

| Path | Package | Contents |
|---|---|---|
| `.` | `secp256k1` | Public API |
| `params/` | `params` | Curve constants, compile-time configuration |
| `field/` | `field` | 5×52 field arithmetic mod p |
| `scalar/` | `scalar` | 4×64 scalar arithmetic mod n; one-word under `EXHAUSTIVE_ORDER` |
| `ct/` | `ct` | Constant-time support: declassification hook and `czero`; the hook compiles away by default |
| `group/` | `group` | Affine and Jacobian group operations |
| `ecmult/` | `ecmult` | Scalar multiplication engines |

Test-only directories (`oracle/`, `ct_tests/`, `csuite/`) link C and are never reachable
from a normal build of the library. Consumers only ever compile the packages above.

`csuite/` exports the field, scalar and group internals under the C ABI with upstream's
struct layouts, so C test code can reach past the public API. `./csuite/build.sh` builds it
and runs two C suites: a layout check verified from both directions, and **upstream's own
test bodies**, lifted verbatim from `tests.c` by `tools/extract_upstream_tests.py` and
compiled against a header shim.

**Eighteen upstream suites** currently run and pass, covering field, scalar, group, ecmult,
the constant-time selects, and ECDSA sign/verify. Inverting `fe_cmov`'s masks produces
1,292,801 upstream assertion failures, so they are not vacuous — and they found a real
defect in the C surface: `csuite` was handing C a zeroed generator, because `GENERATOR` is
filled by an Odin `@(init)` procedure that never runs when a C program links the static
library.

This licenses precisely one claim: *runs upstream's test bodies against this
implementation*. **Not** "passes libsecp256k1's tests" — `tests.c` `#include`s the entire C
library rather than linking one, so the unmodified file cannot be linked against any other
implementation. The assertions are upstream's and unmodified; the include block is not. See
`TODO.md` item 5.

## Use from other languages

The library also builds as a C-ABI shared or static library, so anything with an FFI can
link it. Signatures and struct layouts match libsecp256k1's public headers, making it a
drop-in for existing C consumers.

```sh
odin build capi/ -build-mode:shared -o:speed    # .dylib / .so / .dll
odin build capi/ -build-mode:static -o:speed    # .a
```

Headers are in `capi/include/`, hand-written to match the documented ABI.

## Performance

Benchmarked side by side with libsecp256k1 in the same process, on identical inputs, via
the `oracle` FFI. Ratios below 1.00 are faster than C.

**Report the architecture with any figure, and never average the two.** On x86-64 upstream
enables hand-written assembly for the scalar reduction, so that comparison is Odin-vs-asm
for scalar work and Odin-vs-C elsewhere. On ARM64 upstream ships no assembly and every
comparison is Odin-vs-C. Both are measured below, separately.

**ARM64** — Apple silicon (Darwin/arm64), 20,000 iterations per operation, `-o:speed`.
**Stale:** measured before the Phase 8 constant-time fixes and not re-measurable on this
machine. Expect it to have moved in the same direction as x86-64 below — roughly +1–6% on
the signing paths. Re-run on a Mac before quoting it.

| operation | odin µs | c µs | ratio |
|---|---:|---:|---:|
| `ec_pubkey_create` | 12.65 | 13.45 | **0.94×** |
| `schnorrsig_sign` | 13.68 | 14.49 | **0.94×** |
| `ecdsa_sign` | 20.19 | 20.35 | **0.99×** |
| `ecdh` | 27.85 | 27.31 | 1.02× |
| `ecdsa_verify` | 24.26 | 23.08 | 1.05× |
| `schnorrsig_verify` | 24.40 | 23.15 | 1.05× |
| **aggregate** | | | **1.01×** |

**x86-64** — Linux/amd64, 20,000 iterations per operation, `-o:speed`, against an upstream
v0.7.1 build with its assembly enabled:

| operation | odin µs | c µs | ratio |
|---|---:|---:|---:|
| `ec_pubkey_create` | 10.15 | 10.17 | **1.00×** |
| `schnorrsig_sign` | 10.92 | 10.97 | **1.00×** |
| `ecdsa_sign` | 14.89 | 14.61 | 1.02× |
| `ecdsa_verify` | 19.64 | 18.49 | 1.06× |
| `schnorrsig_verify` | 19.58 | 18.54 | 1.06× |
| `ecdh` | 23.33 | 21.52 | 1.08× |
| **aggregate** | | | **1.04×** |

One complete run, not a per-row best; three consecutive runs put the aggregate at
1.04–1.05× and each row within ±0.02. Both signing paths and key generation are now at
parity; the remaining gap is concentrated in verification and ECDH.

**These figures include the constant-time work, and it cost something.** Measured before the
Phase 8 fixes, the aggregate was 1.03× and `schnorrsig_sign` was 0.96×; it is now 1.02×, a
real ~6% regression on that operation. The causes are all deliberate: the volatile barriers
on the `cmov` helpers, `pubkey_create`/`ecdsa.sign`/`keypair_create` doing uniform work
instead of returning early on an invalid key, and the bitwise `&`/`|` replacements that
force both operands to be evaluated. Buying branch-freedom with a few percent is the trade
this project is supposed to make, so the cost is reported rather than excluded — but it is a
cost, not a rounding error.

Reproduce with:

```sh
./oracle/link-lib.sh /path/to/libsecp256k1.a
./bench/run.sh -define:ITERS=20000
```

### Start-up cost

Throughput figures are steady-state and hide something they structurally cannot show. The
variable-time engine needs 1 MB of generator tables. Building them takes about 12 ms, which a
long-running service never notices and a short-lived process is dominated by — a CLI that
signs once and verifies once would spend more time building tables than doing cryptography.

**The tables are therefore embedded in the binary by default**, the same answer
libsecp256k1 reaches: it commits `precomputed_ecmult.c`, a generated C source file holding
the table as a `static const` array, so the table is emitted into `.rodata` at compile time
and the loader maps it straight from the binary. No computation, and no copy — pages fault
in as they are touched.

| sign + verify, one process | time | binary |
|---|---:|---:|
| tables embedded (default) | **1 ms** | 1.37 MB |
| `-define:SECP256K1_EMBED_TABLES=false` | 8 ms | 331 KB |

Odin has no arbitrary compile-time execution, so the compiler cannot *compute* the table.
`precompute_ecmult/` generates `ecmult/pre_g.bin` and `#load` embeds it, reinterpreted in
place rather than copied. Steady-state throughput is identical either way — this buys
start-up, not throughput.

Turn it off for a big-endian target, to save the 1 MB, or to check the two paths agree. It
is also disabled automatically under `EXHAUSTIVE_ORDER` or a non-default
`ECMULT_WINDOW_SIZE`, since the blob holds real-curve points at the default window size.

`ecmult/pre_g.bin` is generated but **committed**, because `#load` resolves at compile time
and a fresh clone has to build. `tests/ecmult` recomputes all 16,384 entries from the curve
definition and compares them in both modes, so a stale or corrupted blob fails loudly rather
than quietly serving wrong points. For scale, upstream commits 2.55 MB of generated C for
the same purpose.

`bench/micro` breaks the operations into their components — field primitives, point
arithmetic, wNAF, hashing — which is how the two largest wins above were located rather
than guessed at.

## Requirements

- Odin `dev-2026-06` or newer.
- No dependencies. No `core:math/big`, no vendored tables, no C at runtime.

## Building and testing

```sh
odin test tests/ -all-packages              # full suite
odin test tests/ -all-packages -debug       # with the internal *_verify invariants on
odin test tests/exhaustive/ -define:EXHAUSTIVE_ORDER=13     # enumerate an entire small group

./oracle/link-lib.sh /path/to/libsecp256k1.a   # once, for the next two
odin test tests/oracle/ -define:FUZZ_COUNT=2000            # differential vs C
./bench/run.sh                                             # benchmarks vs C

./ct_tests/build.sh --valgrind && valgrind --error-exitcode=1 ./ct_tests.bin
```

The constant-time harness needs Linux (valgrind has no macOS ARM64 port) and the valgrind
headers — `valgrind-devel` on Fedora, `valgrind` on Debian. It builds the library with
`-define:SECP256K1_VERIFY=false`: the internal invariant checks branch on field values by
design, so leaving them in buries real findings under hundreds of false positives. Upstream
builds `ctime_tests.c` without `VERIFY` for the same reason.

Examples mirroring upstream's:

```sh
odin run examples/ecdsa
odin run examples/schnorr
odin run examples/ecdh
```

See `TESTING.md` for the three test tiers and the traceability map against upstream's
`tests.c`.

## License

MIT, © Galaxoid Labs. See `LICENSE`.

The same license upstream libsecp256k1 uses, which keeps this implementation drop-in
compatible for anyone already vendoring that.

This is an independent implementation. Upstream libsecp256k1 is used in this repository
only as a differential-testing oracle and as the source of the test corpus; no upstream
code is incorporated.
