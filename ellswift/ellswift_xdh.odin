/*
X-only ECDH over ElligatorSwift-encoded keys, for the BIP324 v2 transport handshake.

Mirrors upstream's `secp256k1_ellswift_xdh`.

The exchange runs directly on the 64-byte encodings rather than on decoded public keys, and
the resulting secret is hashed together with *both* encodings. That binding is what ties
the shared secret to the specific handshake transcript: an attacker who replays one side's
encoding into a different session gets a different secret.

# Implementation note

Upstream computes the shared x coordinate with `ecmult_const_xonly`, an x-only ladder that
consumes the peer's key as the fraction xn/xd produced by the decoder and never materialises
y. This implementation instead completes the fraction to an affine x, lifts it to a point,
and uses `ecmult_const`.

The two produce the same x coordinate. The constant-time properties that matter are also
the same: the secret scalar goes through `ecmult_const` either way, and the peer's key is
public, so the variable-time lift leaks nothing. The cost is one field inversion and one
square root per exchange, against upstream's inversion-free ladder — a real but modest
difference, on a path that already runs a full scalar multiplication.

Recorded here rather than buried: this is the one place the implementation strategy departs
from upstream, and a differential test against the C library will still agree byte for byte
because only the route differs, not the result.
*/
package ellswift

import "core:mem"
import "../ct"
import "../ecmult"
import "../field"
import "../group"
import "../hash"
import "../scalar"

/*
A hash function applied to the shared x coordinate and both encodings.

Returning false aborts the exchange.
*/
Xdh_Hash_Function :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> bool

/*
The BIP324 shared-secret hash: a tagged hash over both encodings and the shared x.

Hashing the encodings rather than the decoded keys binds the secret to the exact bytes that
appeared on the wire, so a peer cannot substitute a different encoding of the same key.
*/
xdh_hash_function_bip324 :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> bool {
	if len(output) < 32 {
		return false
	}

	sha: hash.Sha256
	tag := "bip324_ellswift_xonly_ecdh"
	hash.sha256_initialize_tagged(&sha, transmute([]u8)tag)
	hash.sha256_write(&sha, ell_a64[:])
	hash.sha256_write(&sha, ell_b64[:])
	hash.sha256_write(&sha, x32[:])

	out32 := (^[32]u8)(&output[0])
	hash.sha256_finalize(&sha, out32)
	hash.sha256_clear(&sha)
	return true
}

/*
The plain SHA256 shared-secret hash, matching upstream's `ellswift_xdh_hash_function_prefix`
default: SHA256(ell_a || ell_b || x).
*/
xdh_hash_function_prefix :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> bool {
	if len(output) < 32 {
		return false
	}

	sha: hash.Sha256
	hash.sha256_initialize(&sha)
	hash.sha256_write(&sha, ell_a64[:])
	hash.sha256_write(&sha, ell_b64[:])
	hash.sha256_write(&sha, x32[:])

	out32 := (^[32]u8)(&output[0])
	hash.sha256_finalize(&sha, out32)
	hash.sha256_clear(&sha)
	return true
}

/*
Computes a BIP324 shared secret from both parties' ElligatorSwift encodings.

`party` says which side we are, matching upstream: false for party A, whose encoding is
`ell_a64`, and true for party B, whose encoding is `ell_b64`. `seckey32` must be the secret
key for *that* party. Both sides pass the encodings in the same order regardless, which is
what makes the transcript binding symmetric.

Returns false if the secret key is zero or at or above n. As in `ecdh`, the computation runs
regardless with a substituted scalar, so an invalid key is not distinguishable by timing.
*/
xdh :: proc "contextless" (
	output: []u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	seckey32: ^[32]u8,
	party: bool,
	hashfp: Xdh_Hash_Function = nil,
	data: rawptr = nil,
) -> bool {
	fn := hashfp
	if fn == nil {
		fn = xdh_hash_function_bip324
	}

	// Decode the *peer's* key — the one that is not ours. `party` says which we are: false
	// means we are party A, so our key is `ell_a64` and the peer's is `ell_b64`; true is the
	// mirror. Getting this backwards still produces a shared secret, and two instances of
	// this implementation talking to each other still agree, so nothing short of a
	// cross-implementation comparison can see it. Public data, so variable-time is fine.
	theirs := ell_a64 if party else ell_b64
	u, tv: field.Field_Elem
	ub := (^[32]u8)(&theirs[0])
	tb := (^[32]u8)(&theirs[32])
	field.fe_set_b32_mod(&u, ub)
	field.fe_set_b32_mod(&tv, tb)

	their_point: group.Ge
	swiftec_var(&their_point, &u, &tv)

	// Load the secret key, substituting a valid one on failure so the work below is
	// identical either way.
	s: scalar.Scalar
	overflow := scalar.scalar_set_b32(&s, seckey32)
	// Bitwise `|`, never `||`: short-circuiting would branch on whether the secret key
	// overflowed.
	overflow |= scalar.scalar_is_zero(&s)
	scalar.scalar_cmov(&s, &scalar.ONE, overflow)

	// Constant-time in the secret scalar.
	res: group.Gej
	ecmult.ecmult_const(&res, &their_point, &s)

	shared: group.Ge
	group.ge_set_gej(&shared, &res)
	field.fe_normalize(&shared.x)

	sx: [32]u8
	field.fe_get_b32(&sx, &shared.x)

	ok := fn(output, &sx, ell_a64, ell_b64, data)

	mem.zero_explicit(&sx, size_of(sx))
	scalar.scalar_clear(&s)
	group.ge_clear(&shared)
	group.gej_clear(&res)

	// Bitwise `&`: `overflow` is secret-key-derived.
	return ok & !overflow
}

/*
Creates an ElligatorSwift-encoded public key directly from a secret key.

`aux_rnd32` supplies the entropy selecting among encodings; passing nil makes the encoding
deterministic in the secret key, which is acceptable but links repeated handshakes.
*/
create :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	ell64: ^[64]u8,
	seckey32: ^[32]u8,
	aux_rnd32: ^[32]u8 = nil,
) -> bool {
	// Never branch on key validity; substitute a valid scalar and do identical work either
	// way, folding the flag in at the end. Same structure as `eckey.pubkey_create`, and the
	// same reason: the validity of a secret key is itself secret.
	s: scalar.Scalar
	is_valid := scalar.scalar_set_b32_seckey(&s, seckey32)
	scalar.scalar_cmov(&s, &scalar.ONE, !is_valid)

	pj: group.Gej
	ecmult.ecmult_gen(ctx, &pj, &s)
	p: group.Ge
	group.ge_set_gej(&p, &pj)

	// The encoding of a public key is published on the wire, and the ElligatorSwift encoder
	// below is deliberately variable-time in the point. Upstream declassifies here with the
	// same note: "not constant time in produced pubkey".
	ct.declassify(&p, size_of(p))

	// The randomness is derived from the secret key and the optional aux input, so a
	// caller with no entropy source still gets a usable encoding.
	hasher: hash.Sha256
	tag := "secp256k1_ellswift_create"
	hash.sha256_initialize_tagged(&hasher, transmute([]u8)tag)
	hash.sha256_write(&hasher, seckey32[:])

	// The 32 zero bytes are unconditional, and the aux input is appended *after* them when
	// present. Writing aux in place of the zeros instead would make the state for
	// `create(sk, aux)` differ from upstream's for the same inputs, producing a valid but
	// non-interoperable encoding — and nothing would have caught it, because the encoding
	// verifies against itself either way. Upstream: H(privkey || "\x00"*32 [|| auxrnd32]).
	zeros: [32]u8
	hash.sha256_write(&hasher, zeros[:])

	// The secret key is absorbed at this point, so the state is no longer secret and the
	// variable-time encoder below may branch on values derived from it. Upstream
	// declassifies here with the note "private key is hashed now".
	ct.declassify(&hasher, size_of(hasher))

	if aux_rnd32 != nil {
		hash.sha256_write(&hasher, aux_rnd32[:])
	}

	u_out := (^[32]u8)(&ell64[0])
	tv: field.Field_Elem
	elligatorswift_var(u_out, &tv, &p, &hasher)

	t_out := (^[32]u8)(&ell64[32])
	field.fe_normalize_var(&tv)
	field.fe_get_b32(t_out, &tv)

	hash.sha256_clear(&hasher)
	scalar.scalar_clear(&s)
	group.ge_clear(&p)
	group.gej_clear(&pj)
	return is_valid
}
