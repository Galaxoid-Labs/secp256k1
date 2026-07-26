/*
BIP340 Schnorr signatures.

Mirrors upstream's `modules/schnorrsig/main_impl.h`.

# The scheme

A signature is 64 bytes: `r` (the x coordinate of R = k*G) followed by `s`, with

	e = tagged_hash("BIP0340/challenge", r || pk || m)
	s = k + e*d   (mod n)

and verification checking that s*G - e*P has x equal to r and **even y**. Both the public
key and R are x-only, which is what makes signatures 64 bytes rather than 65 and removes
the parity choice that would otherwise be malleable.

# Where the parity traps are

Two independent conditional negations, and getting either wrong produces signatures that
silently fail to verify:

  - **The secret key.** The public key is x-only, so it denotes the even-y point. If the
    point derived from d has odd y, then d is the discrete log of the *wrong* point and
    must be negated.
  - **The nonce.** R is also x-only. If R has odd y, k must be negated so that the s in the
    signature corresponds to the R the verifier will reconstruct.

The first is on secret data and uses a constant-time negation. The second branches on R,
which is public — it becomes half the signature — so branching there is safe and is what
upstream does after an explicit declassify.

# Nonce derivation

The nonce is a tagged hash of the secret key masked with auxiliary randomness, the public
key, and the message. The masking is what makes the scheme safe against both a bad RNG and
a fully deterministic one: with no aux randomness the nonce is a pure function of key and
message, and with aux randomness it additionally resists fault and differential attacks.
Feeding the public key in binds the nonce to the key, so the same key material under a
different key cannot produce a colliding nonce.
*/
package schnorr

import "core:mem"
import "../ct"
import "../ecmult"
import "../extrakeys"
import "../field"
import "../group"
import "../hash"
import "../scalar"

/*
The BIP340 algorithm tag used in nonce derivation.
*/
@(private)
BIP340_ALGO := [16]u8 {
	'B', 'I', 'P', '0', '3', '4', '0', '/',
	'n', 'o', 'n', 'c', 'e', 0, 0, 0,
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("BIP0340/nonce", ...).

The tag prefix occupies exactly one 64-byte block, so its compression can be done once at
build time rather than on every signature. The values are checked against a live
computation by `tests/schnorr`.
*/
@(private)
sha256_tagged_nonce :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0x46615b35,
		0xf4bfbff7,
		0x9f8dc671,
		0x83627ab3,
		0x60217180,
		0x57358661,
		0x21a29e54,
		0x68b07b4c,
	}
	sha.bytes = 64
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("BIP0340/aux", ...).
*/
@(private)
sha256_tagged_aux :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0x24dd3219,
		0x4eba7e70,
		0xca0fabb9,
		0x0fa3166d,
		0x3afbe4b1,
		0x4c44df97,
		0x4aac2739,
		0x249e850a,
	}
	sha.bytes = 64
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("BIP0340/challenge", ...).
*/
@(private)
sha256_tagged_challenge :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0x9cecba11,
		0x23925381,
		0x11679112,
		0xd1627e0f,
		0x97c87550,
		0x003cc765,
		0x90f61164,
		0x33e9b66a,
	}
	sha.bytes = 64
}

/*
tagged_hash("BIP0340/aux", 32 zero bytes), used when no auxiliary randomness is supplied.

Precomputed so the deterministic path costs no extra hashing.
*/
@(private)
ZERO_MASK := [32]u8 {
	84, 241, 105, 207, 201, 226, 229, 114,
	116, 128, 68, 31, 144, 186, 37, 196,
	136, 244, 97, 199, 11, 94, 165, 220,
	170, 247, 175, 105, 39, 10, 165, 20,
}

/*
Derives a BIP340 nonce.

`aux_rand32` is optional auxiliary randomness. It does not have to be secret or
high-quality: it is hashed into a mask applied to the secret key, so supplying it can only
help. Omitting it makes signing fully deterministic, which is also safe.
*/
nonce_function_bip340 :: proc "contextless" (
	nonce32: ^[32]u8,
	msg: []u8,
	key32: ^[32]u8,
	xonly_pk32: ^[32]u8,
	aux_rand32: ^[32]u8,
) {
	sha: hash.Sha256
	masked_key: [32]u8

	if aux_rand32 != nil {
		sha256_tagged_aux(&sha)
		hash.sha256_write(&sha, aux_rand32[:])
		hash.sha256_finalize(&sha, &masked_key)
		for i in 0 ..< 32 {
			masked_key[i] ~= key32[i]
		}
	} else {
		for i in 0 ..< 32 {
			masked_key[i] = key32[i] ~ ZERO_MASK[i]
		}
	}

	// Tagging with the algorithm name is what stops a nonce derived here from colliding
	// with one derived for a different scheme using the same key.
	sha256_tagged_nonce(&sha)
	hash.sha256_write(&sha, masked_key[:])
	hash.sha256_write(&sha, xonly_pk32[:])
	hash.sha256_write(&sha, msg)
	hash.sha256_finalize(&sha, nonce32)

	hash.sha256_clear(&sha)
	mem.zero_explicit(&masked_key, size_of(masked_key))
}

/*
Computes the BIP340 challenge scalar e = tagged_hash("BIP0340/challenge", r || pk || m).
*/
@(private)
challenge :: proc "contextless" (
	e: ^scalar.Scalar,
	r32: ^[32]u8,
	msg: []u8,
	pubkey32: ^[32]u8,
) {
	sha: hash.Sha256
	sha256_tagged_challenge(&sha)
	hash.sha256_write(&sha, r32[:])
	hash.sha256_write(&sha, pubkey32[:])
	hash.sha256_write(&sha, msg)

	buf: [32]u8
	hash.sha256_finalize(&sha, &buf)
	// The challenge is reduced mod n rather than rejected, as the spec requires.
	scalar.scalar_set_b32(e, &buf)
	hash.sha256_clear(&sha)
}

/*
Signs a message with a keypair, producing a 64-byte BIP340 signature.

`aux_rand32` is optional; see `nonce_function_bip340`. Returns false only if the derived
nonce is unusable, which is cryptographically unreachable.

The message may be any length. BIP340 originally fixed it at 32 bytes and was later
generalised; both are supported, and the length is part of the hashed input so a 32-byte
message cannot be confused with a longer one.
*/
sign :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	sig64: ^[64]u8,
	msg: []u8,
	keypair: ^extrakeys.Keypair,
	aux_rand32: ^[32]u8 = nil,
) -> bool {
	sk := keypair.seckey
	pk := keypair.pubkey

	// The public key is x-only, so it denotes the even-y point. If the point derived from
	// the secret has odd y, the secret must be negated to match. Constant-time: sk is
	// secret.
	field.fe_normalize_var(&pk.y)
	odd_pk := field.fe_is_odd(&pk.y)
	scalar.scalar_cond_negate(&sk, odd_pk)

	seckey: [32]u8
	scalar.scalar_get_b32(&seckey, &sk)

	pk_buf: [32]u8
	field.fe_normalize_var(&pk.x)
	field.fe_get_b32(&pk_buf, &pk.x)

	nonce32: [32]u8
	nonce_function_bip340(&nonce32, msg, &seckey, &pk_buf, aux_rand32)

	k: scalar.Scalar
	scalar.scalar_set_b32(&k, &nonce32)
	ok := !scalar.scalar_is_zero(&k)
	// Keep going with a dummy value so the failure path costs the same as the success
	// path; the result is zeroed at the end.
	scalar.scalar_cmov(&k, &scalar.ONE, !ok)

	rj: group.Gej
	ecmult.ecmult_gen(ctx, &rj, &k)
	r: group.Ge
	group.ge_set_gej(&r, &rj)

	// R is public — its x coordinate becomes half the signature — so branching on its
	// parity here leaks nothing. It has to be said explicitly for the constant-time harness,
	// which otherwise sees only that R was derived from a secret nonce. Upstream declassifies
	// exactly here, with the same justification.
	ct.declassify(&r, size_of(r))

	field.fe_normalize_var(&r.y)
	if field.fe_is_odd(&r.y) {
		scalar.scalar_negate(&k, &k)
	}

	field.fe_normalize_var(&r.x)
	r32 := (^[32]u8)(&sig64[0])
	field.fe_get_b32(r32, &r.x)

	// s = k + e*d
	e: scalar.Scalar
	challenge(&e, r32, msg, &pk_buf)
	scalar.scalar_mul(&e, &e, &sk)
	scalar.scalar_add(&e, &e, &k)
	s32 := (^[32]u8)(&sig64[32])
	scalar.scalar_get_b32(s32, &e)

	// Whether signing succeeded is returned to the caller, so it is public from here.
	ct.declassify(&ok, size_of(ok))
	if !ok {
		mem.zero_explicit(sig64, size_of(sig64))
	}

	scalar.scalar_clear(&k)
	scalar.scalar_clear(&sk)
	scalar.scalar_clear(&e)
	mem.zero_explicit(&seckey, size_of(seckey))
	mem.zero_explicit(&nonce32, size_of(nonce32))
	group.gej_clear(&rj)

	return ok
}

/*
Verifies a 64-byte BIP340 signature.

Entirely public data, so variable-time throughout.

Three things must hold, and all three matter: r must be a valid field element below p, s
must be below n, and the reconstructed point s*G - e*P must have x equal to r **and even
y**. Dropping the parity check would accept a second signature for every valid one.
*/
verify :: proc "contextless" (
	sig64: ^[64]u8,
	msg: []u8,
	pubkey: ^extrakeys.Xonly_Pubkey,
) -> bool {
	rx: field.Field_Elem
	r32 := (^[32]u8)(&sig64[0])
	if !field.fe_set_b32_limit(&rx, r32) {
		return false
	}

	s: scalar.Scalar
	s32 := (^[32]u8)(&sig64[32])
	if scalar.scalar_set_b32(&s, s32) {
		// s at or above n.
		return false
	}

	pk := pubkey.point
	if group.ge_is_infinity(&pk) {
		return false
	}

	buf: [32]u8
	field.fe_normalize_var(&pk.x)
	field.fe_get_b32(&buf, &pk.x)

	e: scalar.Scalar
	challenge(&e, r32, msg, &buf)

	// rj = s*G + (-e)*P
	scalar.scalar_negate(&e, &e)
	pkj: group.Gej
	group.gej_set_ge(&pkj, &pk)
	rj: group.Gej
	ecmult.ecmult(&rj, &pkj, &e, &s)

	r: group.Ge
	group.ge_set_gej_var(&r, &rj)
	if group.ge_is_infinity(&r) {
		return false
	}

	field.fe_normalize_var(&r.y)
	if field.fe_is_odd(&r.y) {
		return false
	}
	return field.fe_equal(&rx, &r.x)
}
