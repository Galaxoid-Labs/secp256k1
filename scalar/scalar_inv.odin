/*
Scalar inversion, and the GLV endomorphism decomposition.

Inversion delegates to the shared safegcd implementation in `modinv`, exactly as the field
does, but with n as the modulus. The decomposition splits a scalar k into k1 + lambda*k2
with both halves under 2^128 in absolute value, which halves the work in `ecmult` — it is
scaffolding here, consumed in Phase 4.

Mirrors upstream's `scalar_4x64_impl.h` inversion and `scalar_impl.h` `split_lambda`.
*/
package scalar

import "../modinv"
import "../params"

// The 4x64 representation is compiled only for the real curve. Under
// `-define:EXHAUSTIVE_ORDER=n` the whole scalar type is replaced by the single-word
// implementation in `scalar_low.odin`, which mirrors upstream's `scalar_low_impl.h`.
// Exactly one of the two is ever compiled.
when params.EXHAUSTIVE_ORDER == 0 {

/*
The group order n in signed 62-bit limbs, with its inverse mod 2^62.

Unlike the field prime, n has no compact closed form, so all five limbs carry real data.
*/
@(private)
MODINFO_SCALAR := modinv.Modinfo {
	modulus = {v = {0x3fd25e8cd0364141, 0x2abb739abd2280ee, -0x15, 0, 256}},
	modulus_inv62 = 0x34f20099aa774ec1,
}

/*
Converts a scalar into signed 62-bit limbs.
*/
@(private)
scalar_to_signed62 :: proc "contextless" (r: ^modinv.Signed62, a: ^Scalar) {
	scalar_verify(a)
	m62 := modinv.M62
	a0, a1, a2, a3 := a.d[0], a.d[1], a.d[2], a.d[3]

	r.v[0] = transmute(i64)(a0 & m62)
	r.v[1] = transmute(i64)((a0 >> 62 | a1 << 2) & m62)
	r.v[2] = transmute(i64)((a1 >> 60 | a2 << 4) & m62)
	r.v[3] = transmute(i64)((a2 >> 58 | a3 << 6) & m62)
	r.v[4] = transmute(i64)(a3 >> 56)
}

/*
Converts signed 62-bit limbs back into a scalar.

The input must be the normalized output of the safegcd routines: in [0, n) with every limb
in [0, 2^62).
*/
@(private)
scalar_from_signed62 :: proc "contextless" (r: ^Scalar, a: ^modinv.Signed62) {
	a0 := transmute(u64)a.v[0]
	a1 := transmute(u64)a.v[1]
	a2 := transmute(u64)a.v[2]
	a3 := transmute(u64)a.v[3]
	a4 := transmute(u64)a.v[4]

	CHECK(a0 >> 62 == 0, "scalar_from_signed62: limb 0 out of range")
	CHECK(a1 >> 62 == 0, "scalar_from_signed62: limb 1 out of range")
	CHECK(a2 >> 62 == 0, "scalar_from_signed62: limb 2 out of range")
	CHECK(a3 >> 62 == 0, "scalar_from_signed62: limb 3 out of range")
	CHECK(a4 >> 8 == 0, "scalar_from_signed62: limb 4 out of range")

	r.d[0] = a0 | a1 << 62
	r.d[1] = a1 >> 2 | a2 << 60
	r.d[2] = a2 >> 4 | a3 << 58
	r.d[3] = a3 >> 6 | a4 << 56

	scalar_verify(r)
}

/*
Sets r to the inverse of x modulo n, in constant time.

Zero inverts to zero; every other value has an inverse because n is prime.
*/
scalar_inverse :: proc "contextless" (r: ^Scalar, x: ^Scalar) {
	scalar_verify(x)
	when VERIFY {
		zero_in := scalar_is_zero(x)
	}

	s: modinv.Signed62
	scalar_to_signed62(&s, x)
	modinv.modinv64(&s, &MODINFO_SCALAR)
	scalar_from_signed62(r, &s)

	scalar_verify(r)
	when VERIFY {
		CHECK(scalar_is_zero(r) == zero_in, "scalar_inverse: zero-ness was not preserved")
	}
}

/*
Sets r to the inverse of x modulo n, in variable time.

Never call this on secret data.
*/
scalar_inverse_var :: proc "contextless" (r: ^Scalar, x: ^Scalar) {
	scalar_verify(x)
	when VERIFY {
		zero_in := scalar_is_zero(x)
	}

	s: modinv.Signed62
	scalar_to_signed62(&s, x)
	modinv.modinv64_var(&s, &MODINFO_SCALAR)
	scalar_from_signed62(r, &s)

	scalar_verify(r)
	when VERIFY {
		CHECK(scalar_is_zero(r) == zero_in, "scalar_inverse_var: zero-ness was not preserved")
	}
}

// Constants for the GLV decomposition.
//
// lambda and beta are both primitive cube roots of unity — lambda^3 == 1 (mod n) and
// beta^3 == 1 (mod p) — and since X^3 - 1 = (X - 1)(X^2 + X + 1), they are roots of
// X^2 + X + 1, so lambda^2 + lambda == -1 (mod n).
//
// The kernel of the map a + b*l -> a + b*lambda (mod n) is a lattice with reduced basis
// {a1 + b1*l, a2 + b2*l}. Given k, algorithm 3.74 of "Guide to Elliptic Curve
// Cryptography" computes c1 = round(b2*k/n) and c2 = round(-b1*k/n), then
// k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Working modulo n lets us compute r2
// directly and recover r1 = k - r2*lambda, so a1 and a2 are never needed.
//
// g1 and g2 replace the divisions by n with rounded multiplications:
//   d = a1*b2 - b1*a2   (which equals n here)
//   g1 = round(2^384 * b2/d)
//   g2 = round(2^384 * (-b1)/d)

@(private)
MINUS_B1 := Scalar{d = {0x6f547fa90abfe4c3, 0xe4437ed6010e8828, 0, 0}}

@(private)
MINUS_B2 := Scalar {
	d = {0xd765cda83db1562c, 0x8a280ac50774346d, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff},
}

@(private)
G1 := Scalar{d = {0xe893209a45dbb031, 0x3daa8a1471e8ca7f, 0xe86c90e49284eb15, 0x3086d221a7d46bcd}}

@(private)
G2 := Scalar{d = {0x1571b4ae8ac47f71, 0x221208ac9df506c6, 0x6f547fa90abfe4c4, 0xe4437ed6010e8828}}

/*
Splits k into r1 and r2 such that r1 + lambda*r2 == k (mod n), with both halves small.

"Small" means either r1 < 2^128 or -r1 mod n < 2^128, and likewise for r2 — the halves may
be represented as large scalars that are small in absolute value. `ecmult` exploits this to
run two 128-bit multiplications instead of one 256-bit one.

r1, r2 and k must be three distinct objects.
*/
scalar_split_lambda :: proc "contextless" (r1: ^Scalar, r2: ^Scalar, k: ^Scalar) {
	scalar_verify(k)
	CHECK(r1 != k, "scalar_split_lambda: r1 must not alias k")
	CHECK(r2 != k, "scalar_split_lambda: r2 must not alias k")
	CHECK(r1 != r2, "scalar_split_lambda: r1 must not alias r2")

	c1, c2: Scalar

	// Constant-time despite the name: the shift is a compile-time constant.
	scalar_mul_shift_var(&c1, k, &G1, 384)
	scalar_mul_shift_var(&c2, k, &G2, 384)
	scalar_mul(&c1, &c1, &MINUS_B1)
	scalar_mul(&c2, &c2, &MINUS_B2)
	scalar_add(r2, &c1, &c2)
	scalar_mul(r1, r2, &LAMBDA)
	scalar_negate(r1, r1)
	scalar_add(r1, r1, k)

	scalar_verify(r1)
	scalar_verify(r2)

	when VERIFY {
		split_lambda_verify(r1, r2, k)
	}
}

when VERIFY {
	/*
	Asserts that a decomposition really does reconstruct k and that both halves are
	small.

	The bounds are (a1 + a2 + 1)/2 and (-b1 + b2)/2 + 1, the tightest values the
	derivation guarantees. Getting this wrong would not break correctness of `ecmult`,
	only its constant-time claim and its speed, which is exactly the kind of silent
	regression an invariant check is for.
	*/
	@(private)
	split_lambda_verify :: proc "contextless" (r1: ^Scalar, r2: ^Scalar, k: ^Scalar) {
		// (a1 + a2 + 1)/2 = 0xa2a8918ca85bafe22016d0b917e4dd77
		k1_bound := [32]u8 {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0xa2, 0xa8, 0x91, 0x8c, 0xa8, 0x5b, 0xaf, 0xe2,
			0x20, 0x16, 0xd0, 0xb9, 0x17, 0xe4, 0xdd, 0x77,
		}
		// (-b1 + b2)/2 + 1 = 0x8a65287bd47179fb2be08846cea267ed
		k2_bound := [32]u8 {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x8a, 0x65, 0x28, 0x7b, 0xd4, 0x71, 0x79, 0xfb,
			0x2b, 0xe0, 0x88, 0x46, 0xce, 0xa2, 0x67, 0xed,
		}

		s: Scalar
		scalar_mul(&s, &LAMBDA, r2)
		scalar_add(&s, &s, r1)
		when VERIFY {
			CHECK(scalar_eq(&s, k), "split_lambda: r1 + lambda*r2 != k")
		}

		buf1, buf2: [32]u8

		scalar_negate(&s, r1)
		scalar_get_b32(&buf1, r1)
		scalar_get_b32(&buf2, &s)
		CHECK(
			bytes_less(&buf1, &k1_bound) || bytes_less(&buf2, &k1_bound),
			"split_lambda: r1 exceeds its bound",
		)

		scalar_negate(&s, r2)
		scalar_get_b32(&buf1, r2)
		scalar_get_b32(&buf2, &s)
		CHECK(
			bytes_less(&buf1, &k2_bound) || bytes_less(&buf2, &k2_bound),
			"split_lambda: r2 exceeds its bound",
		)
	}

	/*
	Compares two 32-byte big-endian values, returning whether a < b.
	*/
	@(private)
	bytes_less :: proc "contextless" (a: ^[32]u8, b: ^[32]u8) -> bool {
		for i in 0 ..< 32 {
			if a[i] != b[i] {
				return a[i] < b[i]
			}
		}
		return false
	}
}

}
