# TRUST.md — per-symbol verification status

Two states, per `CLAUDE.md`:

- **`unverified`** — correct on vectors, but not yet cleared by the constant-time harness.
- **`ct-verified`** — zero valgrind constant-time findings across its secret paths.

"Verified" means it meets *this project's* bar. It does not mean audited. Regardless of
what any row below says: **unaudited hand-rolled cryptography must never guard real
value.**

Public-data paths — verify, recovery, ellswift decode, key and address derivation — reach
`ct-verified` trivially once their vectors pass, because they have no secrets to leak.
Secret paths stay `unverified` until the Phase 8 harness clears them. MuSig2 signing is the
last to graduate, and its nonce handling is the highest-risk code in the project.

**Phase 8 blocker:** the harness as specced runs valgrind, which has no working macOS
ARM64 port. Resolve before Phase 8 (Linux container, CI-only CT verification, or revisit
MSan). Until then no symbol can legitimately reach `ct-verified`, and none below claims to.

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
| `fe_inv` | not implemented | — | — | needs safegcd `modinv64` |
| `fe_inv_var` | not implemented | — | — | needs safegcd `modinv64_var` |
| `fe_sqrt` | not implemented | — | — | a^((p+1)/4) addition chain |
| `fe_is_square_var` | not implemented | — | — | needs `jacobi64_maybe_var` |

"Vectors ✅" here means the tier 2 mirrored suite and the known-answer vectors pass in both
release and `-debug` builds. It does **not** yet mean the Phase 9 differential oracle
agrees with libsecp256k1 byte for byte, which is a separate requirement in the definition
of done and is not satisfied for any symbol yet.

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
| `pubkey_create` | unverified | ✅ | ✅ | uses blinded `ecmult_gen` |
| `privkey_tweak_add`, `privkey_tweak_mul` | unverified | ✅ | ✅ | reject results that would be invalid keys |
| `pubkey_tweak_add`, `pubkey_tweak_mul` | unverified | ✅ | ✅ | |
| `pubkey_negate` | unverified | ✅ | ✅ | |

## ecdsa

Phase 6. Signing is on the secret path; verification is entirely public.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `sign` | unverified | ✅ | ✅ | RFC6979 nonce; exact-match vectors from an independent reference |
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
| `sign` | unverified | ✅ | ✅ | official BIP340 vectors pass byte-for-byte |
| `verify` | unverified | ✅ | ✅ | variable-time by design; public data only |
| `nonce_function_bip340` | unverified | ✅ | ✅ | aux-rand masking; deterministic without it |

Both conditional negations — the secret key against the x-only public key, and the nonce
against R's parity — are covered: removing either fails the suite.

## ecdh

Phase 6. The scalar is a private key throughout.

| symbol | status | vectors | invariants | notes |
|---|---|---|---|---|
| `ecdh` | unverified | ✅ | ✅ | uses `ecmult_const`; symmetry tested |
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
| `nonce_gen` | unverified | ✅ | ✅ | **session id must never repeat** |
| `nonce_agg`, `nonce_process` | unverified | ✅ | ✅ | binding coefficient b |
| **`partial_sign`** | unverified | ✅ | ✅ | wipes the secnonce first; reuse tested impossible |
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
