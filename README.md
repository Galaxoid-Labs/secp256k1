# secp256k1

A from-scratch, pure-Odin implementation of the secp256k1 elliptic curve, targeting
functional parity with [`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1).

> **Provided as is.** This library comes without warranty of any kind, express or implied,
> and has not been independently audited. [`TRUST.md`](TRUST.md) records the verification
> status of every public symbol — what has been checked, how, and what has not.

**Status:** all modules implemented — field, scalar, group, ecmult, hash, context, ECDSA,
recovery, ECDH, extrakeys, Schnorr (BIP340), ellswift (BIP324) and MuSig2 (BIP327).

| check | result |
|---|---|
| Test suite (release and `-debug`) | 105 pass |
| Differential oracle vs libsecp256k1 | zero divergences, ARM64 and x86-64 |
| Wycheproof ECDSA / ECDH | 463 / 752 pass |
| BIP340 Schnorr, BIP327 MuSig2 | all vector groups pass |
| Exhaustive small-curve (orders 7, 13, 199) | entire group enumerated |
| Constant-time harness (valgrind) | 0 findings across 10 secret paths |
| Upstream `tests.c` bodies | 18 suites pass — see [`TODO.md`](TODO.md) item 5 |
| Performance vs C | 0.98–1.05×, see [Performance](#performance) |

Getting there found eighteen real defects the existing suite could not see — a constant-time
table scan LLVM had rewritten into a branch, a MuSig2 nonce derivation that did not implement
BIP327, a BIP324 handshake that decoded the wrong peer key. Each is recorded with its cause
in [`TODO.md`](TODO.md) and [`TRUST.md`](TRUST.md).

## Install

Consumed as a git submodule. Clone it so the directory is named `secp256k1`:

```sh
git submodule add https://github.com/<you>/secp256k1 secp256k1
```

Odin resolves quoted imports relative to the importing file, so from `main.odin`:

```odin
import "secp256k1"          // high-level API
import "secp256k1/field"    // low-level field arithmetic, if you want it
```

Renaming the checkout changes the import path. To vendor it elsewhere use a collection:
`odin build . -collection:lib=./third_party`, then `import "lib:secp256k1"`.

## Layout

Packages live at the repository root; there is no `src/`.

| Path | Contents |
|---|---|
| `.` | Public API |
| `params/` | Curve constants, compile-time configuration |
| `field/` | 5×52 field arithmetic mod p |
| `scalar/` | 4×64 scalar arithmetic mod n; one-word under `EXHAUSTIVE_ORDER` |
| `group/` | Affine and Jacobian group operations |
| `ecmult/` | Scalar multiplication engines |
| `ct/` | Constant-time support; compiles away by default |

`oracle/`, `ct_tests/` and `csuite/` link C and are never reachable from a normal build.
`csuite/` exports the internals under upstream's struct layouts so upstream's own test bodies
can run against this implementation; `./csuite/build.sh` builds and runs them.

## Use from other languages

The library also builds as a C-ABI shared or static library:

```sh
odin build capi/ -build-mode:shared -o:speed    # .dylib / .so / .dll
odin build capi/ -build-mode:static -o:speed    # .a
```

Headers are in `capi/include/`, matching libsecp256k1's documented ABI.

## Performance

Benchmarked side by side with libsecp256k1 in the same process on identical inputs, 20,000
iterations per operation. Ratios below 1.00 are faster than C.

**x86-64, both sides at default `-O2`:**

| operation | odin µs | c µs | ratio |
|---|---:|---:|---:|
| `ec_pubkey_create` | 9.87 | 9.93 | **0.99×** |
| `schnorrsig_sign` | 10.65 | 10.69 | **1.00×** |
| `ecdsa_verify` | 19.15 | 18.28 | 1.05× |
| `schnorrsig_verify` | 19.10 | 18.11 | 1.05× |
| `ecdsa_sign` | 15.29 | 14.46 | 1.06× |
| `ecdh` | 22.70 | 20.98 | 1.08× |
| **aggregate** | | | **1.05×** |

**x86-64, both tuned** (`-microarch:native` / `-march=native`):

| operation | odin µs | c µs | ratio |
|---|---:|---:|---:|
| `ecdsa_verify` | 18.34 | 19.24 | **0.95×** |
| `schnorrsig_verify` | 18.49 | 19.24 | **0.96×** |
| `ec_pubkey_create` | 9.53 | 9.97 | **0.96×** |
| `schnorrsig_sign` | 10.25 | 10.65 | **0.96×** |
| `ecdh` | 22.39 | 22.34 | **1.00×** |
| `ecdsa_sign` | 14.70 | 13.96 | 1.05× |
| **aggregate** | | | **0.98×** |

Tuned, both verify paths and key generation come out ahead of C and ECDH is at parity.
`ecdsa_sign` is the one consistent laggard; the scalar inversion and RFC6979 derivation that
distinguish it from Schnorr signing have not yet been profiled apart.

**Report the architecture, and never average two.** On x86-64 upstream enables hand-written
assembly for scalar reduction, so that comparison is Odin-vs-asm for scalar work and
Odin-vs-C elsewhere; on ARM64 upstream ships none. **The ARM64 figures are stale** — they
predate the constant-time fixes and cannot be re-measured on this machine; see `TODO.md`.

These numbers include the cost of the constant-time work, which is real: `schnorrsig_sign`
moved from 0.96× to 1.00× over the course of those fixes.

### Start-up

Throughput figures are steady-state and hide this. The variable-time engine needs 1 MB of
generator tables; building them costs ~12 ms, which a long-running service never notices and
a short-lived process is dominated by.

**The tables are therefore embedded by default**, the same answer libsecp256k1 reaches — it
commits a generated C file holding the table as `static const`, so it lands in `.rodata` and
the loader maps it from the binary.

| sign + verify, one process | time | binary |
|---|---:|---:|
| embedded (default) | **1 ms** | 1.37 MB |
| `-define:SECP256K1_EMBED_TABLES=false` | 8 ms | 331 KB |

Odin has no compile-time execution, so the compiler cannot *compute* the table.
`precompute_ecmult/` generates `ecmult/pre_g.bin` and `#load` embeds it, reinterpreted in
place rather than copied. The blob is committed because `#load` resolves at compile time, and
`tests/ecmult` recomputes all 16,384 entries and compares — in both modes — so a stale one
fails loudly. Embedding disables itself under `EXHAUSTIVE_ORDER` or a non-default
`ECMULT_WINDOW_SIZE`.

## Requirements

- Odin `dev-2026-06` or newer.
- No dependencies. No `core:math/big`, no bignum library, no C at runtime.

## Building and testing

```sh
odin test tests/ -all-packages              # full suite
odin test tests/ -all-packages -debug       # with the internal *_verify invariants on
odin test tests/exhaustive/ -define:EXHAUSTIVE_ORDER=13     # enumerate an entire small group

./oracle/link-lib.sh /path/to/libsecp256k1.a   # once, for the next two
odin test tests/oracle/ -define:FUZZ_COUNT=2000            # differential vs C
./bench/run.sh -define:ITERS=20000                         # benchmarks vs C

./ct_tests/build.sh --valgrind && valgrind --error-exitcode=1 ./ct_tests.bin
./csuite/build.sh                                          # upstream test bodies, via C
```

The constant-time harness needs Linux (valgrind has no macOS ARM64 port) and the valgrind
headers — `valgrind-devel` on Fedora, `valgrind` on Debian. It builds with
`-define:SECP256K1_VERIFY=false`, because the invariant checks branch on field values by
design and would bury real findings; upstream builds `ctime_tests.c` without `VERIFY` for the
same reason.

Examples: `odin run examples/ecdsa`, `examples/schnorr`, `examples/ecdh`.

See [`TESTING.md`](TESTING.md) for the test tiers and traceability against upstream's
`tests.c`.

## License

MIT, © Galaxoid Labs. See `LICENSE` — the same license as upstream libsecp256k1.

This is an independent implementation. Upstream libsecp256k1 appears in this repository only
as a differential-testing oracle and as the source of test corpora; no upstream code is
incorporated.
