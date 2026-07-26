/*
secp256k1 — a pure-Odin implementation of the secp256k1 elliptic curve.

> **Not for real value.** This is an educational project held to production standards.
> Unaudited hand-rolled cryptography must never guard real keys or real funds.

This is the public API: an idiomatic Odin surface over the internal packages, which mirror
libsecp256k1's structure closely enough to be differentially tested against it. Callers
should use this package; the sub-packages are the implementation.

	import "secp256k1"

	ctx: secp256k1.Context
	secp256k1.init(&ctx)
	defer secp256k1.destroy(&ctx)

	pubkey, _ := secp256k1.pubkey_from_seckey(&ctx, seckey)
	sig, _    := secp256k1.ecdsa_sign(&ctx, msg_hash, seckey)
	valid     := secp256k1.ecdsa_verify(sig, msg_hash, pubkey)

# Randomize the context

`init` produces a working but *unblinded* context. Call `randomize` with good entropy
before any secret-key operation, and periodically thereafter — repeated calls accumulate
entropy rather than replacing it.
*/
package secp256k1

import "core:mem"
import "ecdh"
import "ecdsa"
import "eckey"
import "ecmult"
import "ellswift"
import "extrakeys"
import "group"
import "musig"
import "recovery"
import "scalar"
import "schnorr"

/*
The library version, as the single source of truth. The C header's `SECP256K1_VER_*` macros
and the README are derived from these; nothing else should carry a version number.

Semantics follow semver. While the major version is 0 the API may change between minor
versions — the trust model in `TRUST.md`, not the version number, is what says which symbols
are cleared for what.
*/
VERSION_MAJOR :: 0
VERSION_MINOR :: 1
VERSION_PATCH :: 0

/*
The version as a string, e.g. "0.1.0".

Odin has no compile-time integer-to-string, so this cannot be derived from the components
above; a test asserts the two agree rather than trusting them to be edited together.
*/
VERSION :: "0.1.0"

/*
Errors returned by this API.
*/
Error :: enum {
	None,
	/*
	A secret key was zero or at or above the group order.
	*/
	Invalid_Seckey,
	/*
	A public key could not be parsed, or is not on the curve.
	*/
	Invalid_Pubkey,
	/*
	A signature could not be parsed.
	*/
	Invalid_Signature,
	/*
	A tweak was out of range, or produced an invalid result.
	*/
	Invalid_Tweak,
	/*
	An output buffer was too small.
	*/
	Buffer_Too_Small,
	/*
	The operation failed for a reason that should not occur with valid inputs.
	*/
	Internal,
}

/*
Library context. Holds the blinding state for secret-key operations.
*/
Context :: struct {
	gen: ecmult.Ecmult_Gen_Context,
}

/*
A public key.
*/
Pubkey :: distinct group.Ge

/*
An x-only public key, as used by BIP340 and Taproot.
*/
Xonly_Pubkey :: distinct extrakeys.Xonly_Pubkey

/*
A secret key and its public key.
*/
Keypair :: distinct extrakeys.Keypair

/*
An ECDSA signature.
*/
Ecdsa_Signature :: distinct ecdsa.Signature

/*
An ECDSA signature carrying a recovery id.
*/
Recoverable_Signature :: distinct recovery.Recoverable_Signature

/*
A 64-byte BIP340 Schnorr signature.
*/
Schnorr_Signature :: distinct [64]u8

/*
Initializes a context.

The result is usable immediately but **unblinded**. Call `randomize` before any secret-key
operation.
*/
init :: proc "contextless" (ctx: ^Context) {
	ecmult.ecmult_gen_context_build(&ctx.gen)
}

/*
Zeroes a context's secret state.
*/
destroy :: proc "contextless" (ctx: ^Context) {
	ecmult.ecmult_gen_context_clear(&ctx.gen)
}

/*
Re-randomizes the context's blinding.

This protects secret-key operations against side channels that depend on intermediate
values. Supply good entropy; repeated calls accumulate it.
*/
randomize :: proc "contextless" (ctx: ^Context, seed: ^[32]u8) {
	ecmult.ecmult_gen_blind(&ctx.gen, seed)
}

/*
Reports whether a 32-byte string is a valid secret key: in [1, n).
*/
seckey_verify :: proc "contextless" (seckey: ^[32]u8) -> bool {
	s: scalar.Scalar
	ok := scalar.scalar_set_b32_seckey(&s, seckey)
	scalar.scalar_clear(&s)
	return ok
}

/*
Derives the public key for a secret key.
*/
pubkey_from_seckey :: proc "contextless" (
	ctx: ^Context,
	seckey: ^[32]u8,
) -> (
	pubkey: Pubkey,
	err: Error,
) {
	s: scalar.Scalar
	if !scalar.scalar_set_b32_seckey(&s, seckey) {
		scalar.scalar_clear(&s)
		return {}, .Invalid_Seckey
	}
	defer scalar.scalar_clear(&s)

	pk: group.Ge
	if !eckey.pubkey_create(&ctx.gen, &pk, &s) {
		return {}, .Internal
	}
	return Pubkey(pk), .None
}

/*
Parses a public key from its compressed (33-byte), uncompressed (65-byte) or hybrid
encoding.
*/
pubkey_parse :: proc "contextless" (input: []u8) -> (pubkey: Pubkey, err: Error) {
	pk: group.Ge
	if !eckey.pubkey_parse(&pk, input) {
		return {}, .Invalid_Pubkey
	}
	return Pubkey(pk), .None
}

/*
Serializes a public key in its 33-byte compressed form.
*/
pubkey_serialize :: proc "contextless" (pubkey: Pubkey) -> [33]u8 {
	out: [33]u8
	pk := group.Ge(pubkey)
	eckey.pubkey_serialize33(&pk, &out)
	return out
}

/*
Serializes a public key in its 65-byte uncompressed form.
*/
pubkey_serialize_uncompressed :: proc "contextless" (pubkey: Pubkey) -> [65]u8 {
	out: [65]u8
	pk := group.Ge(pubkey)
	eckey.pubkey_serialize65(&pk, &out)
	return out
}

/*
Signs a 32-byte message hash.

The nonce is derived deterministically per RFC6979, and s is normalized to its low form so
the signature is not malleable. Signing the same message with the same key always produces
the same signature.
*/
ecdsa_sign :: proc "contextless" (
	ctx: ^Context,
	msg_hash: ^[32]u8,
	seckey: ^[32]u8,
) -> (
	sig: Ecdsa_Signature,
	err: Error,
) {
	s: ecdsa.Signature
	if !ecdsa.sign(&ctx.gen, &s, msg_hash, seckey) {
		return {}, .Invalid_Seckey
	}
	return Ecdsa_Signature(s), .None
}

/*
Verifies an ECDSA signature.

Rejects high-S signatures. Use `ecdsa_normalize` first to accept either form.
*/
ecdsa_verify :: proc "contextless" (
	sig: Ecdsa_Signature,
	msg_hash: ^[32]u8,
	pubkey: Pubkey,
) -> bool {
	s := ecdsa.Signature(sig)
	pk := group.Ge(pubkey)
	return ecdsa.verify(&s, msg_hash, &pk)
}

/*
Converts a signature to its canonical low-S form, reporting whether anything changed.
*/
ecdsa_normalize :: proc "contextless" (sig: Ecdsa_Signature) -> (Ecdsa_Signature, bool) {
	in_sig := ecdsa.Signature(sig)
	out: ecdsa.Signature
	changed := ecdsa.signature_normalize(&out, &in_sig)
	return Ecdsa_Signature(out), changed
}

/*
Serializes a signature in the 64-byte compact form.
*/
ecdsa_serialize_compact :: proc "contextless" (sig: Ecdsa_Signature) -> [64]u8 {
	out: [64]u8
	s := ecdsa.Signature(sig)
	ecdsa.signature_serialize_compact(&out, &s)
	return out
}

/*
Parses a signature from the 64-byte compact form.
*/
ecdsa_parse_compact :: proc "contextless" (input: ^[64]u8) -> (Ecdsa_Signature, Error) {
	s: ecdsa.Signature
	if !ecdsa.signature_parse_compact(&s, input) {
		return {}, .Invalid_Signature
	}
	return Ecdsa_Signature(s), .None
}

/*
Serializes a signature as DER, returning the slice actually written.

`out` must have room for 72 bytes.
*/
ecdsa_serialize_der :: proc "contextless" (
	out: []u8,
	sig: Ecdsa_Signature,
) -> (
	[]u8,
	Error,
) {
	s := ecdsa.Signature(sig)
	n := ecdsa.signature_serialize_der(out, &s)
	if n == 0 {
		return nil, .Buffer_Too_Small
	}
	return out[:n], .None
}

/*
Parses a strictly DER-encoded signature, rejecting non-canonical encodings.
*/
ecdsa_parse_der :: proc "contextless" (input: []u8) -> (Ecdsa_Signature, Error) {
	s: ecdsa.Signature
	if !ecdsa.signature_parse_der(&s, input) {
		return {}, .Invalid_Signature
	}
	return Ecdsa_Signature(s), .None
}

/*
Signs a message hash, producing a signature from which the public key can be recovered.
*/
ecdsa_sign_recoverable :: proc "contextless" (
	ctx: ^Context,
	msg_hash: ^[32]u8,
	seckey: ^[32]u8,
) -> (
	Recoverable_Signature,
	Error,
) {
	r: recovery.Recoverable_Signature
	if !recovery.sign_recoverable(&ctx.gen, &r, msg_hash, seckey) {
		return {}, .Invalid_Seckey
	}
	return Recoverable_Signature(r), .None
}

/*
Recovers the public key that produced a recoverable signature.
*/
ecdsa_recover :: proc "contextless" (
	sig: Recoverable_Signature,
	msg_hash: ^[32]u8,
) -> (
	Pubkey,
	Error,
) {
	r := recovery.Recoverable_Signature(sig)
	pk: group.Ge
	if !recovery.recover(&pk, &r, msg_hash) {
		return {}, .Invalid_Signature
	}
	return Pubkey(pk), .None
}

/*
Creates a keypair from a secret key, for Schnorr signing.
*/
keypair_create :: proc "contextless" (
	ctx: ^Context,
	seckey: ^[32]u8,
) -> (
	Keypair,
	Error,
) {
	kp: extrakeys.Keypair
	if !extrakeys.keypair_create(&ctx.gen, &kp, seckey) {
		return {}, .Invalid_Seckey
	}
	return Keypair(kp), .None
}

/*
Zeroes a keypair's secret material.
*/
keypair_destroy :: proc "contextless" (kp: ^Keypair) {
	mem.zero_explicit(kp, size_of(Keypair))
}

/*
Extracts the x-only public key from a keypair, along with the parity that was removed.
*/
keypair_xonly_pubkey :: proc "contextless" (
	kp: ^Keypair,
) -> (
	pubkey: Xonly_Pubkey,
	parity: bool,
	err: Error,
) {
	k := extrakeys.Keypair(kp^)
	x: extrakeys.Xonly_Pubkey
	if !extrakeys.keypair_xonly_pub(&x, &parity, &k) {
		return {}, false, .Invalid_Seckey
	}
	return Xonly_Pubkey(x), parity, .None
}

/*
Parses a 32-byte x-only public key.
*/
xonly_pubkey_parse :: proc "contextless" (input: ^[32]u8) -> (Xonly_Pubkey, Error) {
	x: extrakeys.Xonly_Pubkey
	if !extrakeys.xonly_pubkey_parse(&x, input) {
		return {}, .Invalid_Pubkey
	}
	return Xonly_Pubkey(x), .None
}

/*
Serializes an x-only public key as its 32-byte x coordinate.
*/
xonly_pubkey_serialize :: proc "contextless" (pubkey: Xonly_Pubkey) -> [32]u8 {
	out: [32]u8
	x := extrakeys.Xonly_Pubkey(pubkey)
	extrakeys.xonly_pubkey_serialize(&out, &x)
	return out
}

/*
Signs a message with BIP340 Schnorr.

`aux_rand` is optional auxiliary randomness. It need not be secret; supplying it makes the
signature non-deterministic and adds resistance to fault attacks. Omitting it is safe and
makes signing reproducible.

The message may be any length.
*/
schnorr_sign :: proc "contextless" (
	ctx: ^Context,
	msg: []u8,
	kp: ^Keypair,
	aux_rand: ^[32]u8 = nil,
) -> (
	Schnorr_Signature,
	Error,
) {
	k := extrakeys.Keypair(kp^)
	sig: [64]u8
	if !schnorr.sign(&ctx.gen, &sig, msg, &k, aux_rand) {
		return {}, .Internal
	}
	return Schnorr_Signature(sig), .None
}

/*
Verifies a BIP340 Schnorr signature.
*/
schnorr_verify :: proc "contextless" (
	sig: Schnorr_Signature,
	msg: []u8,
	pubkey: Xonly_Pubkey,
) -> bool {
	s := transmute([64]u8)sig
	pk := extrakeys.Xonly_Pubkey(pubkey)
	return schnorr.verify(&s, msg, &pk)
}

/*
Computes an ECDH shared secret: SHA256 of the compressed shared point.

Both parties derive the same 32 bytes from opposite halves of the exchange.
*/
ecdh_shared_secret :: proc "contextless" (
	peer_pubkey: Pubkey,
	seckey: ^[32]u8,
) -> (
	secret: [32]u8,
	err: Error,
) {
	pk := group.Ge(peer_pubkey)
	if !ecdh.ecdh(secret[:], &pk, seckey) {
		return {}, .Invalid_Seckey
	}
	return secret, .None
}

/*
Encodes a public key as a 64-byte ElligatorSwift string, indistinguishable from random.

For the BIP324 v2 transport.
*/
ellswift_encode :: proc "contextless" (pubkey: Pubkey, rnd: ^[32]u8) -> [64]u8 {
	out: [64]u8
	pk := group.Ge(pubkey)
	ellswift.encode(&out, &pk, rnd)
	return out
}

/*
Decodes a 64-byte ElligatorSwift string to a public key.

Every 64-byte string decodes to some point, so this cannot fail.
*/
ellswift_decode :: proc "contextless" (ell: ^[64]u8) -> Pubkey {
	pk: group.Ge
	ellswift.decode(&pk, ell)
	return Pubkey(pk)
}

/*
Computes a BIP324 shared secret from both parties' ElligatorSwift encodings.

`party_a` selects whose secret key is supplied: true for the party whose encoding is
`ell_a`. Both sides must pass the encodings in the same order.
*/
ellswift_xdh :: proc "contextless" (
	ell_a: ^[64]u8,
	ell_b: ^[64]u8,
	seckey: ^[32]u8,
	party_a: bool,
) -> (
	secret: [32]u8,
	err: Error,
) {
	if !ellswift.xdh(secret[:], ell_a, ell_b, seckey, party_a) {
		return {}, .Invalid_Seckey
	}
	return secret, .None
}

/*
Aggregates public keys into a single MuSig2 x-only key.

Aggregation is order-dependent; call `musig_sort_pubkeys` first if participants must agree
on a key without agreeing on an order.
*/
musig_pubkey_agg :: proc "contextless" (
	pubkeys: []Pubkey,
	cache: ^musig.Keyagg_Cache,
) -> (
	Xonly_Pubkey,
	Error,
) {
	keys := transmute([]group.Ge)pubkeys
	agg: extrakeys.Xonly_Pubkey
	if !musig.pubkey_agg(&agg, cache, keys) {
		return {}, .Invalid_Pubkey
	}
	return Xonly_Pubkey(agg), .None
}

/*
Sorts public keys into the canonical order, making aggregation order-independent.
*/
musig_sort_pubkeys :: proc "contextless" (pubkeys: []Pubkey) {
	musig.pubkey_sort(transmute([]group.Ge)pubkeys)
}
