/*
Public and secret key encoding, and key tweaking.

Sits between the group arithmetic and the signing modules: a public key is a curve point
and a secret key is a scalar, and this is where they acquire their wire formats and their
validity rules.

Mirrors upstream's `eckey_impl.h`.

# Encodings

	0x02 / 0x03 || x       33 bytes, compressed; the tag gives the parity of y
	0x04        || x || y  65 bytes, uncompressed
	0x06 / 0x07 || x || y  65 bytes, hybrid; the tag repeats the parity of y

Compressed is the only form worth producing. Uncompressed is accepted for compatibility,
and hybrid — which encodes y in full *and* states its parity — is accepted with the parity
checked for consistency, because an encoder that disagrees with itself is malformed input.
*/
package eckey

import "../ecmult"
import "../field"
import "../group"
import "../scalar"

/*
Public key tag bytes.
*/
TAG_PUBKEY_EVEN :: 0x02
TAG_PUBKEY_ODD :: 0x03
TAG_PUBKEY_UNCOMPRESSED :: 0x04
TAG_PUBKEY_HYBRID_EVEN :: 0x06
TAG_PUBKEY_HYBRID_ODD :: 0x07

/*
Parses a public key from its compressed, uncompressed or hybrid encoding.

Returns false for any malformed input: a wrong length, an unrecognised tag, a coordinate at
or above p, a point not on the curve, or a hybrid tag whose parity contradicts the y it
carries. Coordinates are rejected rather than reduced, since a value at or above p is not a
valid encoding of anything.
*/
pubkey_parse :: proc "contextless" (elem: ^group.Ge, pub: []u8) -> bool {
	if len(pub) == 33 && (pub[0] == TAG_PUBKEY_EVEN || pub[0] == TAG_PUBKEY_ODD) {
		x: field.Field_Elem
		xb := (^[32]u8)(&pub[1])
		if !field.fe_set_b32_limit(&x, xb) {
			return false
		}
		return group.ge_set_xo_var(elem, &x, pub[0] == TAG_PUBKEY_ODD)
	}

	if len(pub) == 65 &&
	   (pub[0] == TAG_PUBKEY_UNCOMPRESSED ||
			   pub[0] == TAG_PUBKEY_HYBRID_EVEN ||
			   pub[0] == TAG_PUBKEY_HYBRID_ODD) {
		x, y: field.Field_Elem
		xb := (^[32]u8)(&pub[1])
		yb := (^[32]u8)(&pub[33])
		if !field.fe_set_b32_limit(&x, xb) || !field.fe_set_b32_limit(&y, yb) {
			return false
		}
		group.ge_set_xy(elem, &x, &y)

		// A hybrid tag states the parity of y; if it disagrees with the y actually
		// present, the encoding is self-contradictory.
		if pub[0] == TAG_PUBKEY_HYBRID_EVEN || pub[0] == TAG_PUBKEY_HYBRID_ODD {
			if field.fe_is_odd(&y) != (pub[0] == TAG_PUBKEY_HYBRID_ODD) {
				return false
			}
		}
		return group.ge_is_valid_var(elem)
	}

	return false
}

/*
Writes a public key in its 33-byte compressed form.

The point must not be infinity, which is not a representable public key.
*/
pubkey_serialize33 :: proc "contextless" (elem: ^group.Ge, pub33: ^[33]u8) {
	field.fe_normalize_var(&elem.x)
	field.fe_normalize_var(&elem.y)
	pub33[0] = TAG_PUBKEY_ODD if field.fe_is_odd(&elem.y) else TAG_PUBKEY_EVEN
	x := (^[32]u8)(&pub33[1])
	field.fe_get_b32(x, &elem.x)
}

/*
Writes a public key in its 65-byte uncompressed form.
*/
pubkey_serialize65 :: proc "contextless" (elem: ^group.Ge, pub65: ^[65]u8) {
	field.fe_normalize_var(&elem.x)
	field.fe_normalize_var(&elem.y)
	pub65[0] = TAG_PUBKEY_UNCOMPRESSED
	x := (^[32]u8)(&pub65[1])
	y := (^[32]u8)(&pub65[33])
	field.fe_get_b32(x, &elem.x)
	field.fe_get_b32(y, &elem.y)
}

/*
Adds a tweak to a secret key.

Returns false if the result is zero, which is not a valid secret key. The caller must treat
that as failure rather than using the value.
*/
privkey_tweak_add :: proc "contextless" (key: ^scalar.Scalar, tweak: ^scalar.Scalar) -> bool {
	scalar.scalar_add(key, key, tweak)
	return !scalar.scalar_is_zero(key)
}

/*
Adds a tweak to a public key: P + tweak*G.

Returns false if the result is the point at infinity, which happens exactly when the tweak
is the negation of the key's discrete log.
*/
pubkey_tweak_add :: proc "contextless" (key: ^group.Ge, tweak: ^scalar.Scalar) -> bool {
	pt: group.Gej
	group.gej_set_ge(&pt, key)
	ecmult.ecmult(&pt, &pt, &scalar.ONE, tweak)

	if group.gej_is_infinity(&pt) {
		return false
	}
	group.ge_set_gej(key, &pt)
	return true
}

/*
Multiplies a secret key by a tweak.

Returns false if the tweak is zero, which would destroy the key.
*/
privkey_tweak_mul :: proc "contextless" (key: ^scalar.Scalar, tweak: ^scalar.Scalar) -> bool {
	ok := !scalar.scalar_is_zero(tweak)
	scalar.scalar_mul(key, key, tweak)
	return ok
}

/*
Multiplies a public key by a tweak.

Returns false if the tweak is zero.
*/
pubkey_tweak_mul :: proc "contextless" (key: ^group.Ge, tweak: ^scalar.Scalar) -> bool {
	if scalar.scalar_is_zero(tweak) {
		return false
	}

	pt: group.Gej
	group.gej_set_ge(&pt, key)
	ecmult.ecmult(&pt, &pt, tweak, &scalar.ZERO)
	group.ge_set_gej(key, &pt)
	return true
}

/*
Derives the public key for a secret key: P = d*G.

Uses the blinded constant-time generator multiply, since d is secret.
*/
pubkey_create :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	pub: ^group.Ge,
	seckey: ^scalar.Scalar,
) -> bool {
	// Never branch on the key. A zero scalar is rejected, but the rejection is made by
	// substituting a valid scalar and doing byte-for-byte identical work either way, so the
	// timing does not depend on the secret. The returned flag is public — a caller is told
	// whether its key was accepted — but it becomes public only after the uniform work is
	// done. This mirrors upstream's `secp256k1_ec_pubkey_create_helper`, which cmovs
	// `secp256k1_scalar_one` in on failure for the same reason.
	//
	// The old early return on `gej_is_infinity` is gone with it: for any scalar in [1, n)
	// the result cannot be infinity, and the substituted scalar is in range by construction,
	// so the check could only ever fire on the path that is already rejected.
	valid := !scalar.scalar_is_zero(seckey)

	s := seckey^
	scalar.scalar_cmov(&s, &scalar.ONE, !valid)

	pj: group.Gej
	ecmult.ecmult_gen(ctx, &pj, &s)
	group.ge_set_gej(pub, &pj)

	scalar.scalar_clear(&s)
	return valid
}

/*
Negates a public key, mirroring it across the x axis.
*/
pubkey_negate :: proc "contextless" (key: ^group.Ge) {
	group.ge_neg(key, key)
}
