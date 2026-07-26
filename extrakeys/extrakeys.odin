/*
X-only public keys and keypairs, for BIP340 Schnorr signatures and Taproot.

Mirrors upstream's `modules/extrakeys/main_impl.h`.

# Why x-only

A curve point and its negation share an x coordinate. BIP340 exploits that: it serializes
only x, 32 bytes instead of 33, and defines the key to be the one with **even y**. That
saves a byte per key and removes the encoding choice that made ECDSA public keys malleable.

The cost is parity bookkeeping. Whenever a point is forced to even y, whether the original
had odd y must be remembered, because signing with the implied key requires negating the
secret scalar to match. Getting that wrong produces signatures that fail to verify — or, if
inconsistent between signing and tweaking, keys that cannot be spent from. Every routine
here that can flip parity reports it.
*/
package extrakeys

import "core:mem"
import "../ecmult"
import "../ct"
import "../eckey"
import "../field"
import "../group"
import "../scalar"

/*
An x-only public key: a curve point whose y is even, so only x need be stored.
*/
Xonly_Pubkey :: struct {
	point: group.Ge,
}

/*
A keypair: a secret scalar and its public point, cached together so signing does not have
to re-derive the point.
*/
Keypair :: struct {
	seckey: scalar.Scalar,
	pubkey: group.Ge,
}

/*
Forces a point to have even y, returning whether it had to be negated.

The returned parity is what a caller must track to keep a secret key consistent with the
x-only public key it implies.
*/
ge_even_y :: proc "contextless" (r: ^group.Ge) -> bool {
	field.fe_normalize_var(&r.y)
	if field.fe_is_odd(&r.y) {
		field.fe_negate(&r.y, &r.y, 1)
		field.fe_normalize_var(&r.y)
		return true
	}
	return false
}

/*
Parses an x-only public key from its 32-byte encoding.

Returns false if x is at or above p, or is not the x coordinate of any curve point.
*/
xonly_pubkey_parse :: proc "contextless" (pk: ^Xonly_Pubkey, input32: ^[32]u8) -> bool {
	x: field.Field_Elem
	if !field.fe_set_b32_limit(&x, input32) {
		return false
	}
	// The even-y point is the canonical one.
	if !group.ge_set_xo_var(&pk.point, &x, false) {
		return false
	}
	return true
}

/*
Writes an x-only public key as its 32-byte x coordinate.
*/
xonly_pubkey_serialize :: proc "contextless" (out32: ^[32]u8, pk: ^Xonly_Pubkey) {
	x := pk.point.x
	field.fe_normalize_var(&x)
	field.fe_get_b32(out32, &x)
}

/*
Converts a full public key to its x-only form, reporting whether y had to be negated.

A true parity means the original key's y was odd, so the x-only key represents the
*negation* of the input.
*/
xonly_pubkey_from_pubkey :: proc "contextless" (
	xonly: ^Xonly_Pubkey,
	pk_parity: ^bool,
	pubkey: ^group.Ge,
) -> bool {
	if group.ge_is_infinity(pubkey) {
		return false
	}

	pk := pubkey^
	parity := ge_even_y(&pk)
	if pk_parity != nil {
		pk_parity^ = parity
	}
	xonly.point = pk
	return true
}

/*
Compares two x-only public keys as their serialized forms.

Returns -1, 0 or 1. Used to sort keys, which MuSig2 key aggregation requires.
*/
xonly_pubkey_cmp :: proc "contextless" (a: ^Xonly_Pubkey, b: ^Xonly_Pubkey) -> int {
	ab, bb: [32]u8
	xonly_pubkey_serialize(&ab, a)
	xonly_pubkey_serialize(&bb, b)

	for i in 0 ..< 32 {
		if ab[i] < bb[i] {
			return -1
		}
		if ab[i] > bb[i] {
			return 1
		}
	}
	return 0
}

/*
Adds a tweak to an x-only public key, producing a full public key.

The result is a normal point, not x-only: tweaking generally changes the parity, and the
caller needs to know the actual point. This is the Taproot output-key computation.
*/
xonly_pubkey_tweak_add :: proc "contextless" (
	output: ^group.Ge,
	internal: ^Xonly_Pubkey,
	tweak32: ^[32]u8,
) -> bool {
	tweak: scalar.Scalar
	if scalar.scalar_set_b32(&tweak, tweak32) {
		// A tweak at or above n is invalid rather than reduced.
		return false
	}

	pk := internal.point
	if !eckey.pubkey_tweak_add(&pk, &tweak) {
		return false
	}
	output^ = pk
	return true
}

/*
Checks that a tweaked x-only key matches an expected serialization and parity.

This is the verification half of Taproot: given the internal key and the tweak, confirm
that they really produce the claimed output key. Comparing the serialized form rather than
the point is deliberate — it is what a verifier actually has.
*/
xonly_pubkey_tweak_add_check :: proc "contextless" (
	tweaked_pubkey32: ^[32]u8,
	tweaked_pk_parity: bool,
	internal: ^Xonly_Pubkey,
	tweak32: ^[32]u8,
) -> bool {
	pk: group.Ge
	if !xonly_pubkey_tweak_add(&pk, internal, tweak32) {
		return false
	}

	field.fe_normalize_var(&pk.x)
	field.fe_normalize_var(&pk.y)

	if field.fe_is_odd(&pk.y) != tweaked_pk_parity {
		return false
	}

	expected: [32]u8
	field.fe_get_b32(&expected, &pk.x)
	return expected == tweaked_pubkey32^
}

/*
Creates a keypair from a 32-byte secret key.

Returns false if the key is zero or at or above n.
*/
keypair_create :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	keypair: ^Keypair,
	seckey32: ^[32]u8,
) -> bool {
	mem.zero_explicit(keypair, size_of(Keypair))

	// No branch on key validity: substitute a valid scalar, do identical work, and fold the
	// flag in at the end. `eckey.pubkey_create` is structured the same way and for the same
	// reason — the validity of a secret key is itself secret, and upstream never
	// declassifies it.
	sk: scalar.Scalar
	valid := scalar.scalar_set_b32_seckey(&sk, seckey32)
	scalar.scalar_cmov(&sk, &scalar.ONE, !valid)

	pk: group.Ge
	created := eckey.pubkey_create(ctx, &pk, &sk)

	keypair.seckey = sk
	keypair.pubkey = pk
	scalar.scalar_clear(&sk)

	// Constant-time erase: `ok` folds in secret-key validity, so an `if` here would leak
	// exactly the bit the substitution above was there to protect. Upstream uses
	// `secp256k1_memczero` in the same place.
	ok := valid & created
	ct.czero(keypair, size_of(Keypair), !ok)
	return ok
}

/*
Extracts the secret key from a keypair.
*/
keypair_sec :: proc "contextless" (seckey32: ^[32]u8, keypair: ^Keypair) {
	sk := keypair.seckey
	scalar.scalar_get_b32(seckey32, &sk)
}

/*
Extracts the full public key from a keypair.
*/
keypair_pub :: proc "contextless" (pubkey: ^group.Ge, keypair: ^Keypair) {
	pubkey^ = keypair.pubkey
}

/*
Extracts the x-only public key from a keypair, reporting the parity that was removed.
*/
keypair_xonly_pub :: proc "contextless" (
	pubkey: ^Xonly_Pubkey,
	pk_parity: ^bool,
	keypair: ^Keypair,
) -> bool {
	return xonly_pubkey_from_pubkey(pubkey, pk_parity, &keypair.pubkey)
}

/*
Applies an x-only tweak to a keypair, keeping the secret and public halves consistent.

The secret key is negated first if the public point had odd y, so that it remains the
discrete log of the *even-y* point the x-only form denotes. Skipping that negation is the
classic Taproot bug: the resulting key looks right but cannot produce valid signatures.
*/
keypair_xonly_tweak_add :: proc "contextless" (keypair: ^Keypair, tweak32: ^[32]u8) -> bool {
	tweak: scalar.Scalar
	if scalar.scalar_set_b32(&tweak, tweak32) {
		return false
	}

	sk := keypair.seckey
	pk := keypair.pubkey

	// Force even y, negating the secret to match.
	if ge_even_y(&pk) {
		scalar.scalar_negate(&sk, &sk)
	}

	// Bitwise `&`, not `&&`: both tweaks must always be applied, so neither operand's
	// evaluation depends on the other's result.
	ok := eckey.privkey_tweak_add(&sk, &tweak)
	ok = eckey.pubkey_tweak_add(&pk, &tweak) & ok

	keypair.seckey = sk
	keypair.pubkey = pk
	scalar.scalar_clear(&sk)

	// As in `keypair_create`: erase without branching on the outcome.
	ct.czero(keypair, size_of(Keypair), !ok)
	return ok
}

/*
Zeroes a keypair's secret material.
*/
keypair_clear :: proc "contextless" (keypair: ^Keypair) {
	mem.zero_explicit(keypair, size_of(Keypair))
}
