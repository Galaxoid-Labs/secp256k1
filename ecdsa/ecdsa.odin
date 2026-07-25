/*
ECDSA signing and verification over secp256k1.

Mirrors upstream's `ecdsa_impl.h` and the signing entry points in `secp256k1.c`.

# The two rules that matter

**Nonces are deterministic.** The per-signature nonce k is derived from the private key and
the message by RFC6979, never drawn from an RNG. A repeated k across two signatures reveals
the private key by simple algebra, and a biased k leaks it over many signatures. Making k a
pure function of (key, message) removes both failure modes, and makes signatures
reproducible.

**Signatures are low-S.** For any valid (r, s), the pair (r, n-s) is equally valid. Leaving
that choice free makes signatures malleable — a third party can alter the encoding without
invalidating it, which changes a Bitcoin transaction's txid. Signing therefore always
normalizes s to the lower of the two, and `signature_normalize` lets a verifier canonicalise
one it received.

# What is secret and what is not

Signing touches the private key and the nonce, so it uses `ecmult_gen` (constant-time,
blinded) and the constant-time scalar inverse. Verification touches only public data — the
signature, message and public key — so it uses the variable-time engine and inverse
throughout, which is both faster and perfectly safe.
*/
package ecdsa

import "core:mem"
import "../ecmult"
import "../field"
import "../group"
import "../hash"
import "../scalar"

/*
An ECDSA signature, held as the scalar pair (r, s).

This is the internal representation; `signature_serialize_compact` and
`signature_serialize_der` produce the wire formats.
*/
Signature :: struct {
	r, s: scalar.Scalar,
}

/*
Signs a message hash with a secret key, using an explicitly supplied nonce.

Returns false in the cryptographically unreachable cases where r or s comes out zero.
Callers should use `sign` instead, which derives the nonce and retries; this exists for
tests and for callers implementing an alternative nonce scheme.

When `recid` is non-nil it receives the recovery id, which lets a verifier recover the
public key from the signature.
*/
sig_sign :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	sig: ^Signature,
	seckey: ^scalar.Scalar,
	message: ^scalar.Scalar,
	nonce: ^scalar.Scalar,
	recid: ^int,
) -> bool {
	// R = k*G, and r is R.x reduced mod n.
	rp: group.Gej
	ecmult.ecmult_gen(ctx, &rp, nonce)

	r: group.Ge
	group.ge_set_gej(&r, &rp)
	field.fe_normalize(&r.x)
	field.fe_normalize(&r.y)

	b: [32]u8
	field.fe_get_b32(&b, &r.x)
	overflow := scalar.scalar_set_b32(&sig.r, &b)

	if recid != nil {
		// The overflow bit distinguishes R.x >= n, which is cryptographically
		// unreachable: it would require finding a point whose x exceeds the order, about
		// 1 in 2^127.
		recid^ = (int(overflow) << 1) | int(field.fe_is_odd(&r.y))
	}

	// s = (m + r*d) / k
	n: scalar.Scalar
	scalar.scalar_mul(&n, &sig.r, seckey)
	scalar.scalar_add(&n, &n, message)
	scalar.scalar_inverse(&sig.s, nonce)
	scalar.scalar_mul(&sig.s, &sig.s, &n)

	scalar.scalar_clear(&n)
	group.gej_clear(&rp)
	group.ge_clear(&r)

	// Normalize to low-S, so the signature is not malleable.
	high := scalar.scalar_is_high(&sig.s)
	scalar.scalar_cond_negate(&sig.s, high)
	if recid != nil && high {
		recid^ ~= 1
	}

	// r can only be zero if R.x = n exactly, which is as unreachable as the overflow
	// case above.
	return !scalar.scalar_is_zero(&sig.r) && !scalar.scalar_is_zero(&sig.s)
}

/*
Verifies a signature against a message hash and public key.

Variable-time throughout: every input is public.
*/
sig_verify :: proc "contextless" (
	sig: ^Signature,
	pubkey: ^group.Ge,
	message: ^scalar.Scalar,
) -> bool {
	ensure_init()

	if scalar.scalar_is_zero(&sig.r) || scalar.scalar_is_zero(&sig.s) {
		return false
	}

	// u1 = m/s, u2 = r/s, then check that (u1*G + u2*P).x == r.
	sn, u1, u2: scalar.Scalar
	scalar.scalar_inverse_var(&sn, &sig.s)
	scalar.scalar_mul(&u1, &sn, message)
	scalar.scalar_mul(&u2, &sn, &sig.r)

	pubkeyj: group.Gej
	group.gej_set_ge(&pubkeyj, pubkey)

	pr: group.Gej
	ecmult.ecmult(&pr, &pubkeyj, &u2, &u1)
	if group.gej_is_infinity(&pr) {
		return false
	}

	// Comparing x directly avoids the inversion a full affine conversion would need.
	//
	// r came from R.x reduced mod n, so recovering the candidate x means undoing that
	// reduction: x is either r, or r + n when r + n is still below p. Both must be tried.
	c: [32]u8
	scalar.scalar_get_b32(&c, &sig.r)

	xr: field.Field_Elem
	// r < n < p, so this always succeeds.
	_ = field.fe_set_b32_limit(&xr, &c)

	if group.gej_eq_x_var(&xr, &pr) {
		return true
	}

	// If x + n would reach p there is no second candidate. `xr` came from
	// `fe_set_b32_limit` and is therefore already normalized, as `fe_cmp_var` requires.
	if field.fe_cmp_var(&xr, &P_MINUS_ORDER) >= 0 {
		return false
	}

	field.fe_add(&xr, &ORDER_AS_FE)
	return group.gej_eq_x_var(&xr, &pr)
}

/*
The group order n as a field element, and p - n.

Both are built from their eight-word forms at initialization rather than written as 5x52
limbs, so there is no hand-computed representation to get wrong. n < p, so n is a valid
field element.
*/
@(private)
ORDER_AS_FE: field.Field_Elem

/*
The same two constants, exported for `recovery`, which reconstructs R from r and therefore
needs the identical reduction logic. Exposing them rather than duplicating the literals
keeps the two in step.
*/
ORDER_AS_FE_PUB: field.Field_Elem
P_MINUS_ORDER_PUB: field.Field_Elem

/*
p - n: the smallest x for which x + n would not fit below p, and therefore the threshold
above which there is no second candidate to test.
*/
@(private)
P_MINUS_ORDER: field.Field_Elem

@(private)
constants_ready: bool

/*
Builds the verification constants if they have not been built yet. Idempotent; see
`group.ensure_init`.
*/
ensure_init :: proc "contextless" () {
	if constants_ready {
		return
	}
	init_constants()
	constants_ready = true
}

@(init, private)
init_constants :: proc "contextless" () {
	ORDER_AS_FE = field.fe_const(
		0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
		0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364141,
	)
	P_MINUS_ORDER = field.fe_const(
		0, 0, 0, 1,
		0x45512319, 0x50b75fc4, 0x402da172, 0x2fc9baee,
	)
	ORDER_AS_FE_PUB = ORDER_AS_FE
	P_MINUS_ORDER_PUB = P_MINUS_ORDER
	constants_ready = true
}

/*
Derives a nonce by RFC6979, mirroring upstream's `nonce_function_rfc6979`.

The generator is keyed with the private key, the message reduced mod n, and optionally 32
bytes of extra entropy and a 16-byte algorithm tag. Every component has a fixed length, so
no combination of inputs can be confused with another — which is what stops, say, a longer
message from colliding with a message plus extra data.

`counter` selects which output to take, so a caller that must reject a candidate nonce can
ask for the next one.
*/
nonce_function_rfc6979 :: proc "contextless" (
	nonce32: ^[32]u8,
	msg32: ^[32]u8,
	key32: ^[32]u8,
	algo16: ^[16]u8,
	data: ^[32]u8,
	counter: uint,
) {
	keydata: [112]u8
	offset := 0

	// Reduce the message mod n first, so that two messages differing only above n cannot
	// produce different nonces for what is arithmetically the same signing input.
	msg: scalar.Scalar
	scalar.scalar_set_b32(&msg, msg32)
	msgmod32: [32]u8
	scalar.scalar_get_b32(&msgmod32, &msg)

	copy(keydata[offset:], key32[:]); offset += 32
	copy(keydata[offset:], msgmod32[:]); offset += 32
	if data != nil {
		copy(keydata[offset:], data[:]); offset += 32
	}
	if algo16 != nil {
		copy(keydata[offset:], algo16[:]); offset += 16
	}

	rng: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng, keydata[:offset])
	for _ in 0 ..= counter {
		hash.rfc6979_hmac_sha256_generate(&rng, nonce32[:])
	}

	mem.zero_explicit(&keydata, size_of(keydata))
	mem.zero_explicit(&msgmod32, size_of(msgmod32))
	hash.rfc6979_hmac_sha256_clear(&rng)
}

/*
Signs a 32-byte message hash with a 32-byte secret key.

The nonce is derived by RFC6979 and retried with an incremented counter in the
astronomically unlikely event that it is out of range or yields a degenerate signature.
Returns false only if the secret key is invalid.

`extra_entropy` is optional additional input to the nonce derivation. It does not need to
be secret or unpredictable; supplying it changes the signature, which is occasionally
useful for grinding a low-r signature.
*/
sign :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	sig: ^Signature,
	msg32: ^[32]u8,
	seckey32: ^[32]u8,
	extra_entropy: ^[32]u8 = nil,
	recid: ^int = nil,
) -> bool {
	sec: scalar.Scalar
	if !scalar.scalar_set_b32_seckey(&sec, seckey32) {
		scalar.scalar_clear(&sec)
		return false
	}

	msg: scalar.Scalar
	scalar.scalar_set_b32(&msg, msg32)

	nonce32: [32]u8
	non: scalar.Scalar
	ok := false

	for counter: uint = 0; counter < 32; counter += 1 {
		nonce_function_rfc6979(&nonce32, msg32, seckey32, nil, extra_entropy, counter)

		// A nonce at or above n, or zero, must be rejected rather than reduced: reducing
		// would bias the distribution.
		if !scalar.scalar_set_b32_seckey(&non, &nonce32) {
			continue
		}
		if sig_sign(ctx, sig, &sec, &msg, &non, recid) {
			ok = true
			break
		}
	}

	mem.zero_explicit(&nonce32, size_of(nonce32))
	scalar.scalar_clear(&non)
	scalar.scalar_clear(&sec)
	scalar.scalar_clear(&msg)
	return ok
}

/*
Verifies a signature over a 32-byte message hash against a public key.

Rejects a signature whose s is high, so that only the canonical low-S form is accepted. Use
`signature_normalize` first to accept either form.
*/
verify :: proc "contextless" (sig: ^Signature, msg32: ^[32]u8, pubkey: ^group.Ge) -> bool {
	if scalar.scalar_is_high(&sig.s) {
		return false
	}

	msg: scalar.Scalar
	scalar.scalar_set_b32(&msg, msg32)
	return sig_verify(sig, pubkey, &msg)
}

/*
Converts a signature to its canonical low-S form.

Returns whether the input was high-S, that is whether anything changed. `sig_out` may alias
`sig_in`.
*/
signature_normalize :: proc "contextless" (sig_out: ^Signature, sig_in: ^Signature) -> bool {
	high := scalar.scalar_is_high(&sig_in.s)
	sig_out^ = sig_in^
	if high {
		scalar.scalar_negate(&sig_out.s, &sig_out.s)
	}
	return high
}
