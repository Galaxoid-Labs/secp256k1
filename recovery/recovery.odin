/*
Public key recovery from ECDSA signatures.

Mirrors upstream's `modules/recovery/main_impl.h`.

An ordinary ECDSA signature does not identify the signer; verification needs the public key
supplied alongside. A *recoverable* signature carries one extra piece of information — the
recovery id — which is enough to reconstruct the public key from the signature and message.
Bitcoin uses this for signed messages, where including the key would be redundant.

# The recovery id

Verification reconstructs R from r, but r is only R's x coordinate reduced mod n, so two
ambiguities exist:

  - **Parity.** Both (x, y) and (x, -y) have the same x, so bit 0 records which.
  - **Reduction.** R.x may have been at or above n before reduction, so bit 1 records
    whether n must be added back. This case is cryptographically unreachable with honest
    signers — roughly 1 in 2^127 — but the encoding allows it.

Recovery is entirely public: the signature, message and resulting key are all public data,
so this is variable-time throughout.
*/
package recovery

import "../ecdsa"
import "../ecmult"
import "../field"
import "../group"
import "../scalar"

/*
A recoverable signature: an ordinary signature plus the recovery id.
*/
Recoverable_Signature :: struct {
	sig:   ecdsa.Signature,
	recid: int,
}

/*
Signs a message, producing a recoverable signature.
*/
sign_recoverable :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	sig: ^Recoverable_Signature,
	msg32: ^[32]u8,
	seckey32: ^[32]u8,
	extra_entropy: ^[32]u8 = nil,
) -> bool {
	// The recovery id is written unconditionally rather than behind a branch on success:
	// `ecdsa.sign`'s result folds in secret-key validity, which is deliberately never
	// declassified, so branching on it here would leak what `sign` took care not to.
	recid: int
	ok := ecdsa.sign(ctx, &sig.sig, msg32, seckey32, extra_entropy, &recid)
	sig.recid = recid
	return ok
}

/*
Recovers the public key that produced a signature.

Returns false if the recovery id is out of range, if r or s is zero, or if the implied
point is not on the curve — any of which means the signature and id are inconsistent.
*/
recover :: proc "contextless" (
	pubkey: ^group.Ge,
	sig: ^Recoverable_Signature,
	msg32: ^[32]u8,
) -> bool {
	if sig.recid < 0 || sig.recid > 3 {
		return false
	}

	msg: scalar.Scalar
	scalar.scalar_set_b32(&msg, msg32)
	return sig_recover(pubkey, &sig.sig, &msg, sig.recid)
}

/*
Reconstructs the public key from the signature components.

	Q = r^-1 * (s*R - m*G)

where R is rebuilt from r and the recovery id.
*/
sig_recover :: proc "contextless" (
	pubkey: ^group.Ge,
	sig: ^ecdsa.Signature,
	message: ^scalar.Scalar,
	recid: int,
) -> bool {
	if scalar.scalar_is_zero(&sig.r) || scalar.scalar_is_zero(&sig.s) {
		return false
	}

	brx: [32]u8
	scalar.scalar_get_b32(&brx, &sig.r)

	fx: field.Field_Elem
	// r came from a scalar, so it is below n and certainly below p.
	if !field.fe_set_b32_limit(&fx, &brx) {
		return false
	}

	// Bit 1 says R.x was at or above n, so n must be added back.
	if recid & 2 != 0 {
		if field.fe_cmp_var(&fx, &ecdsa.P_MINUS_ORDER_PUB) >= 0 {
			return false
		}
		field.fe_add(&fx, &ecdsa.ORDER_AS_FE_PUB)
	}

	// Bit 0 gives the parity of R.y.
	x: group.Ge
	if !group.ge_set_xo_var(&x, &fx, recid & 1 != 0) {
		return false
	}

	xj: group.Gej
	group.gej_set_ge(&xj, &x)

	rn, u1, u2: scalar.Scalar
	scalar.scalar_inverse_var(&rn, &sig.r)
	scalar.scalar_mul(&u1, &rn, message)
	scalar.scalar_negate(&u1, &u1)
	scalar.scalar_mul(&u2, &rn, &sig.s)

	qj: group.Gej
	ecmult.ecmult(&qj, &xj, &u2, &u1)
	group.ge_set_gej_var(pubkey, &qj)

	return !group.gej_is_infinity(&qj)
}

/*
Writes a recoverable signature in the 64-byte compact form plus a separate recovery id.
*/
signature_serialize_compact :: proc "contextless" (
	out64: ^[64]u8,
	recid: ^int,
	sig: ^Recoverable_Signature,
) {
	ecdsa.signature_serialize_compact(out64, &sig.sig)
	recid^ = sig.recid
}

/*
Parses a recoverable signature from its compact form and recovery id.

Returns false if the recovery id is out of range or either half is at or above n.
*/
signature_parse_compact :: proc "contextless" (
	sig: ^Recoverable_Signature,
	in64: ^[64]u8,
	recid: int,
) -> bool {
	if recid < 0 || recid > 3 {
		return false
	}
	if !ecdsa.signature_parse_compact(&sig.sig, in64) {
		return false
	}
	sig.recid = recid
	return true
}

/*
Discards the recovery id, yielding an ordinary signature.
*/
signature_convert :: proc "contextless" (out: ^ecdsa.Signature, sig: ^Recoverable_Signature) {
	out^ = sig.sig
}
