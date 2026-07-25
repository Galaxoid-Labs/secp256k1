# secp256k1

A from-scratch, pure-Odin implementation of the secp256k1 elliptic curve, targeting
functional parity with [`bitcoin-core/secp256k1`](https://github.com/bitcoin-core/secp256k1).

> **Not for real value.** This is an educational project held to production standards.
> Unaudited hand-rolled cryptography must never guard real keys or real funds. "Treat it
> as if it were used" is a discipline for *how this is built*, not a licence to deploy it.

**Status:** all modules implemented — field, scalar, group, ecmult, hash, context, ECDSA,
recovery, ECDH, extrakeys, Schnorr (BIP340), ellswift (BIP324) and MuSig2 (BIP327).

81 tests pass in release and `-debug`, and the differential oracle reports **zero
divergences** from libsecp256k1 across thousands of fuzzed inputs.

**Every symbol is still `unverified`.** The Phase 8 constant-time harness is built but
cannot run on macOS ARM64 (no valgrind port), so nothing is `ct-verified`. See `TRUST.md`.

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
| `scalar/` | `scalar` | 4×64 scalar arithmetic mod n |
| `group/` | `group` | Affine and Jacobian group operations |
| `ecmult/` | `ecmult` | Scalar multiplication engines |

Test-only directories (`oracle/`, `ct_tests/`, `csuite/`) link C and are never reachable
from a normal build of the library. Consumers only ever compile the packages above.

## Use from other languages

The library also builds as a C-ABI shared or static library, so anything with an FFI can
link it. Signatures and struct layouts match libsecp256k1's public headers, making it a
drop-in for existing C consumers.

```sh
odin build capi/ -build-mode:shared -o:speed    # .dylib / .so / .dll
odin build capi/ -build-mode:static -o:speed    # .a
```

Headers are in `capi/include/`, hand-written to match the documented ABI.

## Requirements

- Odin `dev-2026-06` or newer.
- No dependencies. No `core:math/big`, no vendored tables, no C at runtime.

## Building and testing

```sh
odin test tests/ -all-packages              # full suite
odin test tests/ -all-packages -debug       # with the internal *_verify invariants on
odin test tests/group/ -debug -define:EXHAUSTIVE_ORDER=13   # exhaustive small-order curve

./oracle/link-lib.sh /path/to/libsecp256k1.a   # once, for the next two
odin test tests/oracle/ -define:FUZZ_COUNT=2000            # differential vs C
./bench/run.sh                                             # benchmarks vs C

./ct_tests/build.sh --valgrind && valgrind --error-exitcode=1 ./ct_tests.bin
```

Examples mirroring upstream's:

```sh
odin run examples/ecdsa
odin run examples/schnorr
odin run examples/ecdh
```

See `TESTING.md` for the three test tiers and the traceability map against upstream's
`tests.c`.

## Licence

BSD-3-Clause. See `LICENSE`.

This is an independent implementation. Upstream libsecp256k1 (MIT) is used in this
repository only as a differential-testing oracle and as the source of the test corpus;
no upstream code is incorporated.
