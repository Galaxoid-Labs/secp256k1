/*
Elliptic-curve Diffie-Hellman.

Mirrors upstream's `modules/ecdh/main_impl.h`.

The shared secret is not the point itself but a hash of it. That matters: the raw x
coordinate is not uniformly distributed over 256-bit strings, so feeding it directly into a
symmetric key would leak structure. Hashing also binds the parity of y, so the two parties
cannot disagree about which of ±P they computed.

The scalar here is a private key, so the multiplication uses `ecmult_const`. Using the
variable-time engine would leak the key through timing — this is the single most important
line in the file.
*/
package ecdh

import "core:mem"
import "../ecmult"
import "../field"
import "../group"
import hash "../hash"
import "../scalar"

/*
A hash function applied to the shared point.

`x32` and `y32` are the affine coordinates. Returning false aborts the exchange.
*/
Hash_Function :: proc "contextless" (output: []u8, x32: ^[32]u8, y32: ^[32]u8, data: rawptr) -> bool

/*
The default hash: SHA256(compressed-point-prefix || x).

Equivalent to hashing the 33-byte compressed encoding of the shared point, which is what
makes the result independent of which party computed it.
*/
hash_function_sha256 :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	y32: ^[32]u8,
	data: rawptr,
) -> bool {
	if len(output) < 32 {
		return false
	}

	// The prefix byte is the compressed-point tag, so this hashes exactly the standard
	// 33-byte serialization.
	version := [1]u8{(y32[31] & 0x01) | 0x02}

	sha: hash.Sha256
	hash.sha256_initialize(&sha)
	hash.sha256_write(&sha, version[:])
	hash.sha256_write(&sha, x32[:])

	out32 := (^[32]u8)(&output[0])
	hash.sha256_finalize(&sha, out32)
	hash.sha256_clear(&sha)
	return true
}

/*
Computes a shared secret from a secret scalar and a peer's public point.

Returns false if the scalar is zero or at or above n. The computation runs regardless — a
dummy scalar is substituted so the failure path costs the same as the success path — and
only the return value differs, so an invalid key cannot be distinguished by timing.

Passing a nil `hashfp` selects `hash_function_sha256`.
*/
ecdh :: proc "contextless" (
	output: []u8,
	point: ^group.Ge,
	seckey32: ^[32]u8,
	hashfp: Hash_Function = nil,
	data: rawptr = nil,
) -> bool {
	fn := hashfp
	if fn == nil {
		fn = hash_function_sha256
	}

	s: scalar.Scalar
	overflow := scalar.scalar_set_b32(&s, seckey32)
	// Bitwise `|`, never `||`: short-circuiting here would branch on whether the secret key
	// overflowed. Both operands must always be evaluated.
	overflow |= scalar.scalar_is_zero(&s)
	// Substitute a valid scalar so the work below is identical either way.
	scalar.scalar_cmov(&s, &scalar.ONE, overflow)

	pt := point^
	res: group.Gej
	// Constant-time: `s` is a private key.
	ecmult.ecmult_const(&res, &pt, &s)
	group.ge_set_gej(&pt, &res)

	field.fe_normalize(&pt.x)
	field.fe_normalize(&pt.y)

	x, y: [32]u8
	field.fe_get_b32(&x, &pt.x)
	field.fe_get_b32(&y, &pt.y)

	ok := fn(output, &x, &y, data)

	mem.zero_explicit(&x, size_of(x))
	mem.zero_explicit(&y, size_of(y))
	scalar.scalar_clear(&s)
	group.ge_clear(&pt)
	group.gej_clear(&res)

	// Bitwise `&`: `overflow` is secret-key-derived, so this must not short-circuit.
	return ok & !overflow
}
