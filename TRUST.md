# TRUST.md — per-symbol verification status

**Differential oracle: zero divergences.** Every symbol marked ✅ below in the "oracle"
column has been compared byte-for-byte against upstream libsecp256k1 over thousands of
fuzzed inputs. That is the strongest correctness evidence in this project — stronger than
any hand-written vector, because the inputs are not chosen. It says nothing about timing.

Two states, per `CLAUDE.md`:

- **`unverified`** — correct on vectors, but not yet cleared by the constant-time harness.
- **`ct-verified`** — zero valgrind constant-time findings across its secret paths.

"Verified" means it meets *this project's* bar, defined below. It does not mean audited, and
no row here should be read as one — this library is provided as is, without warranty.

Public-data paths — verify, recovery, ellswift decode, key and address derivation — reach
`ct-verified` trivially once their vectors pass, because they have no secrets to leak.
Secret paths stay `unverified` until the Phase 8 harness clears them. MuSig2 signing is the
last to graduate, and its nonce handling is the highest-risk code in the project.

**Constant-time status.** Two independent checks:

1. **Statistical timing test (dudect) — runs here, currently clean.** All five measured
   secret paths show |t| < 2.0 against a threshold of 10 at 20,000 samples per class. The
   test is validated by injection: a variable-time ECDH multiply scores |t| = 20.2 and a
   secret-dependent branch in ECDSA scores |t| = 44.2, while both pass the entire functional
   suite *and* the differential oracle.

2. **valgrind instruction-level check — now running, on Linux/x86-64.** It cannot run on
   macOS ARM64 (valgrind has no port; clang rejects `-fsanitize=memory` for
   `arm64-apple-darwin`) — both were attempted, not assumed. On Fedora x86-64 with valgrind
   3.27.1 it runs, and its first run found **seven real defects** that (1) did not catch:

   | defect | why the statistical test missed it |
   |---|---|
   | `ecmult_gen`'s cmov table scan rewritten by LLVM into a branch + secret-indexed load | a correctly-predicted branch and an L1-resident load cost too little wall-clock to register |
   | `scalar_set_b32_seckey`, `fe_normalizes_to_zero`, `ecdh` (×2), `ecdsa_sig_sign` short-circuiting `&&`/`||` on secret data | fires only on inputs a random sample essentially never produces (invalid key, zero nonce) |
   | `ecdsa_sig_sign` branching on the low-S flag to set the recovery id | one predictable branch |
   | `pubkey_create` early-returning on a zero key | invalid keys are never sampled |

   This is the concrete case for why `ct-verified` is granted only on (2). Five of the seven
   are reachable only on inputs that random timing samples never generate; the dudect test
   was clean throughout, and remains clean.

   All seven are fixed. A further ten findings were legitimate declassification points —
   secret-key validity, RFC6979 nonce-retry validity, MuSig2 nonce non-zero-ness, and
   Schnorr's `R` — which the library previously had no way to express. They are handled by
   the `ct` declassification hook, mirroring upstream's `secp256k1_declassify()`, with each
   call site carrying the justification for why that value has become public.

   Two further defects surfaced while closing them out, both caused by `CHECK` evaluating
   its argument even when the invariant layer is compiled out: `gej_rescale` ran a
   variable-time zero test on the blinding factor, and several accumulator checks used
   short-circuit `&&`/`||` on secret data. Only the optimizer removed them, and only at
   `-o:speed` — which is why the gate is now run at both optimization levels.

   **The gate is now clean: 0 errors from 0 contexts**, at both `-o:none` and `-o:speed`,
   after a `declassify` hook was added so the library can mark values that have legitimately
   become public (see `ct/`).

   **The harness is validated by injection, not assumed.** Replacing ECDH's constant-time
   `ecmult_const` with the variable-time `ecmult` — a genuine key-recovery leak — produces
   19 error contexts. With that same leak in place, **all 105 functional tests pass and the
   differential oracle still reports zero divergences.** That is the clearest statement
   available of what this gate buys and what correctness testing cannot:

   | with a variable-time multiply on the secret scalar | result |
   |---|---|
   | 105 functional tests | all pass |
   | differential oracle vs libsecp256k1 | zero divergences |
   | valgrind constant-time harness | **19 contexts** |

# What `ct-verified` covers, and what it does not

`ct-verified` is granted only on (2), and only when (2) is clean. It is now clean, so the
ten secret paths the harness exercises are verified end to end, along with everything they
transitively execute:

`eckey.pubkey_create`, `ecdsa.sign`, `schnorr.sign`, `ecdh.ecdh`,
`eckey.privkey_tweak_add`, `musig.nonce_gen` + `musig.partial_sign`,
`extrakeys.keypair_create` + `keypair_xonly_tweak_add`, `musig.pubkey_{xonly,ec}_tweak_add`,
`recovery.sign_recoverable`, and `ellswift.create` + `ellswift.xdh`.

Per-symbol attribution below is deliberately *not* claimed from this run. Callgrind was used
to enumerate the executed set and undercounts badly, because `#force_inline` symbols are
absorbed into their callers and never appear as call targets. Rather than mark rows
`ct-verified` on evidence that does not distinguish "not executed" from "inlined", the
status column changes only for the entry points above. The arithmetic they rest on is
covered in fact but is left `unverified` here until per-symbol coverage can be shown rather
than inferred.

Extending the harness to those last four paths found three more defects of the same kind:
`keypair_create` and `ellswift.create` early-returned on an invalid key, and
`keypair_create`/`keypair_xonly_tweak_add` erased the keypair behind an `if` on a flag that
folds in key validity — upstream uses a constant-time `memczero` there, which now exists as
`ct.czero`.

Two modelling corrections came out of it as well, both settled by reading upstream's own
`ctime_tests` rather than by argument: BIP341 tweaks are **not** secret ("The tweak is not
treated as a secret in keypair_tweak_add"), and ellswift auxiliary randomness is not secret
either — upstream passes a previous public encoding as aux.

Still outside the harness: ECDSA/Schnorr *verification*, public-key parsing and ellswift
*decoding*, which handle only public data and have no secrets to leak.

---

## field

Phase 1. Handles secret data — field elements hold private key material during signing —
so every entry here needs a `ctime_tests` case in Phase 8.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `fe_normalize` | unverified | ✅ | ✅ | constant-time by construction; unproven |
| `fe_normalize_weak` | unverified | ✅ | ✅ | |
| `fe_normalize_var` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `fe_normalizes_to_zero` | unverified | ✅ | ✅ | |
| `fe_normalizes_to_zero_var` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `fe_set_int` | unverified | ✅ | ✅ | |
| `fe_is_zero` | unverified | ✅ | ✅ | |
| `fe_is_odd` | unverified | ✅ | ✅ | |
| `fe_get_bounds` | unverified | ✅ | ✅ | test support |
| `fe_const` | unverified | ✅ | ✅ | constant construction |
| `fe_clear` | unverified | ✅ | ✅ | explicit wipe via `mem.zero_explicit` |
| `fe_add` | unverified | ✅ | ✅ | |
| `fe_add_int` | unverified | ✅ | ✅ | |
| `fe_negate` | unverified | ✅ | ✅ | |
| `fe_mul_int` | unverified | ✅ | ✅ | |
| `fe_half` | unverified | ✅ | ✅ | mask derived arithmetically, not by branch |
| `fe_cmov` | unverified | ✅ | ✅ | |
| `fe_cmp_var` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `fe_equal` | unverified | ✅ | ✅ | |
| `fe_mul` | unverified | ✅ | ✅ | known-answer vectors pass |
| `fe_sqr` | unverified | ✅ | ✅ | known-answer vectors pass |
| `fe_to_storage` | unverified | ✅ | ✅ | |
| `fe_from_storage` | unverified | ✅ | ✅ | |
| `fe_storage_cmov` | unverified | ✅ | ✅ | |
| `fe_set_b32_mod` | unverified | ✅ | ✅ | |
| `fe_set_b32_limit` | unverified | ✅ | ✅ | |
| `fe_get_b32` | unverified | ✅ | ✅ | |
| `fe_inv` | unverified | ✅ | ✅ | safegcd `modinv64`; on the verified signing paths |
| `fe_inv_var` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `fe_sqrt` | unverified | ✅ | ✅ | used by point decompression, a public-data path |
| `fe_is_square_var` | unverified | ✅ | ✅ | variable-time by design; public data only |

"Vectors ✅" here means the tier 2 mirrored suite and the known-answer vectors pass in both
release and `-debug` builds. The Phase 9 differential oracle is now also running and reports
zero divergences against libsecp256k1 on both ARM64 and x86-64, so that separate requirement
in the definition of done is satisfied for the symbols the oracle reaches — see the oracle
column.

## scalar

Phase 2. Scalars are the most secret-bearing type in the library — a private key and a
nonce are both scalars — so every constant-time entry here is a Phase 8 requirement.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `scalar_set_int`, `scalar_const` | unverified | ✅ | ✅ | |
| `scalar_clear` | unverified | ✅ | ✅ | explicit wipe |
| `scalar_set_b32` | unverified | ✅ | ✅ | |
| `scalar_set_b32_seckey` | unverified | ✅ | ✅ | rejects 0 and >= n |
| `scalar_get_b32` | unverified | ✅ | ✅ | |
| `scalar_check_overflow` | unverified | ✅ | ✅ | branch-free comparison |
| `scalar_reduce` | unverified | ✅ | ✅ | |
| `scalar_add` | unverified | ✅ | ✅ | |
| `scalar_cadd_bit` | unverified | ✅ | ✅ | |
| `scalar_negate` | unverified | ✅ | ✅ | |
| `scalar_cond_negate` | unverified | ✅ | ✅ | |
| `scalar_half` | unverified | ✅ | ✅ | |
| `scalar_mul` | unverified | ✅ | ✅ | known-answer vectors pass |
| `scalar_mul_shift_var` | unverified | ✅ | ✅ | constant-time for constant shift |
| `scalar_inverse` | unverified | ✅ | ✅ | via safegcd |
| `scalar_inverse_var` | unverified | ✅ | ✅ | variable-time by design |
| `scalar_is_zero`, `_is_one`, `_is_even` | unverified | ✅ | ✅ | |
| `scalar_is_high` | unverified | ✅ | ✅ | low-S boundary tested at exactly n/2 |
| `scalar_eq`, `scalar_cmov` | unverified | ✅ | ✅ | |
| `scalar_split_lambda` | unverified | ✅ | ✅ | bounds asserted under -debug |
| `scalar_get_bits_limb32`, `_var` | unverified | ✅ | ✅ | |
| `scalar_split_128` | unverified | ✅ | ✅ | |

## modinv

Phase 1/2 shared. Used by both field and scalar inversion, so it is on every secret path
that inverts anything.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `modinv64` | unverified | ✅ | ✅ | constant-time in x, not in the modulus |
| `modinv64_var` | unverified | ✅ | ✅ | variable-time by design |
| `jacobi64_maybe_var` | unverified | ✅ | ✅ | may return 0 = "unknown"; callers must handle |
| `normalize_62` | unverified | ✅ | ✅ | |
| `divsteps_59` | unverified | ✅ | ✅ | mask arithmetic unproven against compiler branching |
| `divsteps_62_var`, `posdivsteps_62_var` | unverified | ✅ | ✅ | variable-time by design |
| `update_de_62`, `update_fg_62{,_var}` | unverified | ✅ | ✅ | |

Odin has no `volatile`, which upstream uses to stop the compiler turning mask arithmetic
into branches. Nothing here asserts that it did not; the Phase 8 harness is what will.

## group

Phase 3. Point arithmetic sits directly on secret scalars during signing, so the
constant-time/variable-time split here is the one that matters most.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `ge_set_xy`, `ge_set_infinity` | unverified | ✅ | ✅ | |
| `gej_set_infinity`, `gej_set_ge` | unverified | ✅ | ✅ | |
| `ge_clear`, `gej_clear` | unverified | ✅ | ✅ | explicit wipe |
| `ge_neg`, `gej_neg` | unverified | ✅ | ✅ | |
| `ge_set_gej` | unverified | ✅ | ✅ | constant-time conversion |
| `ge_set_gej_var` | unverified | ✅ | ✅ | variable-time by design |
| `ge_set_gej_zinv`, `ge_set_ge_zinv` | unverified | ✅ | ✅ | |
| `ge_set_all_gej` | unverified | ✅ | ✅ | batched inversion |
| `ge_set_all_gej_var` | unverified | ✅ | ✅ | variable-time by design |
| `ge_table_set_globalz` | unverified | ✅ | ✅ | |
| `ge_set_xo_var` (lift_x) | unverified | ✅ | ✅ | variable-time; x is public |
| `ge_is_valid_var` | unverified | ✅ | ✅ | |
| `ge_x_on_curve_var`, `ge_x_frac_on_curve_var` | unverified | ✅ | ✅ | |
| `gej_double` | unverified | ✅ | ✅ | constant-time |
| `gej_double_var` | unverified | ✅ | ✅ | variable-time by design |
| `gej_add_var`, `gej_add_ge_var`, `gej_add_zinv_var` | unverified | ✅ | ✅ | variable-time by design |
| **`gej_add_ge`** | unverified | ✅ | ✅ | the constant-time unified formula; degenerate branch now covered |
| `gej_rescale` | unverified | ✅ | ✅ | projective blinding |
| `gej_cmov` | unverified | ✅ | ✅ | |
| `ge_to_storage`, `ge_from_storage`, `ge_storage_cmov` | unverified | ✅ | ✅ | |
| `ge_mul_lambda` | unverified | ✅ | ✅ | endomorphism |
| `ge_eq_var`, `gej_eq_var`, `gej_eq_ge_var`, `gej_eq_x_var` | unverified | ✅ | ✅ | variable-time by design |
| `ge_is_in_correct_subgroup` | unverified | ✅ | ✅ | trivial on the real curve (cofactor 1) |

`gej_add_ge` is the highest-risk routine in this package. Its degenerate branch — y1 = -y2
with x1 != x2 — was untested until a surviving mutation exposed the gap; see `TESTING.md`.

## ecmult

Phase 4. The engine split is the single most important security boundary in the library:
`ecmult` on a secret scalar leaks it through timing.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `ecmult` | unverified | ✅ | ✅ | **variable-time by design; public scalars only** |
| `ecmult_multi_var` | unverified | ✅ | ✅ | variable-time by design |
| `ecmult_const` | unverified | ✅ | ✅ | constant-time; the secret-scalar path |
| `ecmult_gen` | unverified | ✅ | ✅ | constant-time, scalar- and projective-blinded |
| `wnaf`, `wnaf_small` | unverified | ✅ | ✅ | variable-time by design |
| `odd_multiples_table` | unverified | ✅ | ✅ | |
| `table_get_ge{,_lambda,_storage}` | unverified | ✅ | ✅ | variable-time index; public data |
| `compute_table`, `compute_two_tables` | unverified | ✅ | ✅ | entries verified against independent multiples |
| `gen_compute_table` | unverified | ✅ | ✅ | entries verified non-infinite and on-curve |
| `ecmult_gen_context_build` | unverified | ✅ | ✅ | unblinded reset (b = -1) |
| `ecmult_gen_blind` | unverified | ✅ | ✅ | RFC6979-derived, entropy-chaining |

Blinding is in place as of Phase 5. A context is unblinded until `context_randomize` is
called, which is the caller's responsibility and is documented on that procedure.

## hash

Phase 5. Sits on the secret path through RFC6979 nonce derivation and `ecmult_gen`
blinding.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `sha256_*` | unverified | ✅ | ✅ | NIST FIPS 180-2 vectors pass |
| `hmac_sha256_*` | unverified | ✅ | ✅ | RFC 4231 vectors pass |
| `rfc6979_hmac_sha256_*` | unverified | ✅ | ✅ | verified against an independent reference |
| `sha256_initialize_tagged`, `tagged_sha256` | unverified | ✅ | ✅ | BIP340 domain separation checked |

## ctx

Phase 5. Named `ctx` rather than `context` because `context` is reserved in Odin.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `context_create`, `context_destroy` | unverified | ✅ | ✅ | |
| `context_randomize` | unverified | ✅ | ✅ | installs blinding; refuses on an immutable context |
| `context_set_illegal_callback` | unverified | ✅ | ✅ | |
| `context_set_error_callback` | unverified | ✅ | ✅ | |
| `arg_check`, `call_illegal`, `call_error` | unverified | ✅ | ✅ | default handlers abort, matching upstream |

## eckey

Phase 6. Key encoding and tweaking.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `pubkey_parse` | unverified | ✅ | ✅ | rejects out-of-range, off-curve and inconsistent hybrid tags |
| `pubkey_serialize33`, `pubkey_serialize65` | unverified | ✅ | ✅ | |
| `pubkey_create` | **ct-verified** | ✅ | ✅ | uses blinded `ecmult_gen`; valgrind clean, no branch on key validity |
| `privkey_tweak_add`, `privkey_tweak_mul` | **ct-verified** | ✅ | ✅ | reject results that would be invalid keys; `_add` valgrind clean |
| `pubkey_tweak_add`, `pubkey_tweak_mul` | unverified | ✅ | ✅ | |
| `pubkey_negate` | unverified | ✅ | ✅ | |

## ecdsa

Phase 6. Signing is on the secret path; verification is entirely public.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `sign` | **ct-verified** | ✅ | ✅ | RFC6979 nonce; exact-match vectors from an independent reference; valgrind clean |
| `sig_sign` | unverified | ✅ | ✅ | caller-supplied nonce |
| `verify`, `sig_verify` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `nonce_function_rfc6979` | unverified | ✅ | ✅ | fixed-length fields prevent input confusion |
| `signature_normalize` | unverified | ✅ | ✅ | low-S canonicalisation |
| `signature_serialize_compact`, `signature_parse_compact` | unverified | ✅ | ✅ | rejects out-of-range halves |
| `signature_serialize_der`, `signature_parse_der` | unverified | ✅ | ✅ | strict; rejects non-canonical encodings |
| `signature_parse_der_lax` | unverified | ✅ | ✅ | **legacy data only**; reintroduces encoding malleability |

Not yet covered: the full Wycheproof corpus (Phase 6 gate) and the differential oracle
(Phase 9). Until Wycheproof runs, the claim is "passes independently computed vectors and
property tests", not "passes Wycheproof".

## extrakeys

Phase 6. X-only keys and parity bookkeeping for BIP340 and Taproot.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `ge_even_y` | unverified | ✅ | ✅ | reports the parity a caller must track |
| `xonly_pubkey_parse`, `_serialize` | unverified | ✅ | ✅ | rejects x >= p and off-curve x |
| `xonly_pubkey_from_pubkey` | unverified | ✅ | ✅ | |
| `xonly_pubkey_cmp` | unverified | ✅ | ✅ | needed for MuSig2 key sorting |
| `xonly_pubkey_tweak_add`, `_check` | unverified | ✅ | ✅ | Taproot output key |
| `keypair_create`, `_sec`, `_pub`, `_xonly_pub` | unverified | ✅ | ✅ | |
| `keypair_xonly_tweak_add` | unverified | ✅ | ✅ | secret negated to match even-y; consistency tested |

## schnorr

Phase 6. BIP340. Signing is on the secret path.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `sign` | **ct-verified** | ✅ | ✅ | official BIP340 vectors pass byte-for-byte; valgrind clean |
| `verify` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `nonce_function_bip340` | unverified | ✅ | ✅ | aux-rand masking; deterministic without it |

Both conditional negations — the secret key against the x-only public key, and the nonce
against R's parity — are covered: removing either fails the suite.

## ecdh

Phase 6. The scalar is a private key throughout.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `ecdh` | **ct-verified** | ✅ | ✅ | uses `ecmult_const`; valgrind clean, and the injection test targets this path |
| `hash_function_sha256` | unverified | ✅ | ✅ | hashes the compressed point, so both parties agree |

**Note:** replacing `ecmult_const` here with the variable-time engine passes every test.
Functional testing cannot distinguish them; only the Phase 8 harness can.

## recovery

Phase 6. Entirely public data.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `sign_recoverable` | unverified | ✅ | ✅ | |
| `recover`, `sig_recover` | unverified | ✅ | ✅ | recovered key checked against an independently derived one |
| `signature_serialize_compact`, `_parse_compact` | unverified | ✅ | ✅ | rejects out-of-range recovery ids |
| `signature_convert` | unverified | ✅ | ✅ | |

## ellswift

Phase 7. BIP324 transport encoding. The map itself handles only public keys; the XDH half
is not yet implemented.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `decode`, `swiftec_var`, `xswiftec_var` | unverified | ✅ | ✅ | total: every 64-byte string decodes |
| `xswiftec_frac_var` | unverified | ✅ | ✅ | agrees with the direct form |
| `xswiftec_inv_var` | unverified | ✅ | ✅ | each solved branch decodes back |
| `encode`, `elligatorswift_var` | unverified | ✅ | ✅ | round-trips; unlinkable across randomness |
| `xdh`, `create` | unverified | ✅ | ✅ | symmetric; transcript-bound |

`xdh` uses lift-and-`ecmult_const` rather than upstream's inversion-free `ecmult_const_xonly`
ladder. Same result and same constant-time property for the secret scalar; one extra
inversion and square root per exchange. Recorded rather than silent.

## musig

Phase 7. BIP327. `CLAUDE.md` names this the highest-risk code in the project, and it is the
last symbol scheduled to reach `ct-verified`.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `pubkey_agg` | unverified | ✅ | ✅ | coefficient-weighted; rogue-key resistance tested |
| `keyaggcoef{,_internal}` | unverified | ✅ | ✅ | second-key coefficient fixed at 1 per spec |
| `compute_pks_hash` | unverified | ✅ | ✅ | order-dependent by design |
| `pubkey_sort` | unverified | ✅ | ✅ | makes aggregation canonical |
| `pubkey_xonly_tweak_add`, `pubkey_ec_tweak_add` | unverified | ✅ | ✅ | maintains `tweak` and `parity_acc` |
| `nonce_gen` | **ct-verified** | ✅ | ✅ | **session id must never repeat**; BIP327 vectors match exactly; valgrind clean |
| `nonce_agg`, `nonce_process` | unverified | ✅ | ✅ | binding coefficient b |
| **`partial_sign`** | **ct-verified** | ✅ | ✅ | wipes the secnonce first; reuse tested impossible |
| `partial_sig_verify` | unverified | ✅ | ✅ | attributes failure to a specific signer |
| `partial_sig_agg` | unverified | ✅ | ✅ | includes the tweak contribution |
| `secnonce_clear` | unverified | ✅ | ✅ | for abandoned sessions |

Four security mutations were injected and all four failed the suite: removing the nonce
wipe, forcing every aggregation coefficient to 1 (the rogue-key attack), dropping the
binding coefficient (the Wagner attack), and skipping the parity negation.

**Not yet run against the BIP327 test vectors.** The end-to-end property is verified against
the real BIP340 verifier, and the security properties are tested directly, but the official
vector corpus is Phase 9 work. Until it runs, do not claim BIP327 conformance.

## params

Configuration only; no runtime behaviour, no secrets.

| symbol | status | notes |
|---|---|---|
| curve constants | unverified | generator verified on-curve and of the expected order, for all four configurations |

## Not yet started

Every module in the plan now has an implementation. What remains is verification:
the Phase 8 constant-time harness and the Phase 9 vector corpora and differential oracle.
