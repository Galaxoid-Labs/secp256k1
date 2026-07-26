/*
Modular inversion, square roots, and quadratic-residue testing in the field.

Inversion delegates to the shared safegcd implementation in the `modinv` package, which
needs the value in signed 62-bit limbs rather than the 5x52 form used everywhere else, so
most of this file is the conversion between the two representations.

Square roots use the fact that p = 3 (mod 4), which makes sqrt(a) = a^((p+1)/4) computable
by a fixed addition chain — no branching, and so constant-time for free.

Mirrors upstream's `field_5x52_impl.h` inversion section and `field_impl.h` sqrt.
*/
package field

import "../modinv"

/*
The field modulus in signed 62-bit limbs, with its inverse mod 2^62.

p = 2^256 - 2^32 - 977, so in signed62 form the bottom limb is -(2^32 + 977) and the top
limb carries the 2^256. Expressing it with a negative low limb is what keeps the
representation to five limbs.
*/
@(private)
MODINFO_FE := modinv.Modinfo {
	modulus = {v = {-0x1000003d1, 0, 0, 0, 256}},
	modulus_inv62 = 0x27c7f6e22ddacacf,
}

/*
Converts a normalized field element into signed 62-bit limbs.
*/
@(private)
fe_to_signed62 :: proc "contextless" (r: ^modinv.Signed62, a: ^Field_Elem) {
	m62 := u64(modinv.M62)
	a0, a1, a2, a3, a4 := a.n[0], a.n[1], a.n[2], a.n[3], a.n[4]

	r.v[0] = transmute(i64)((a0 | a1 << 52) & m62)
	r.v[1] = transmute(i64)((a1 >> 10 | a2 << 42) & m62)
	r.v[2] = transmute(i64)((a2 >> 20 | a3 << 32) & m62)
	r.v[3] = transmute(i64)((a3 >> 30 | a4 << 22) & m62)
	r.v[4] = transmute(i64)(a4 >> 40)
}

/*
Converts signed 62-bit limbs back into a field element.

The input must be the normalized output of the safegcd routines: in [0, p) with every limb
in [0, 2^62). On output r is normalized with magnitude 1.
*/
@(private)
fe_from_signed62 :: proc "contextless" (r: ^Field_Elem, a: ^modinv.Signed62) {
	a0 := transmute(u64)a.v[0]
	a1 := transmute(u64)a.v[1]
	a2 := transmute(u64)a.v[2]
	a3 := transmute(u64)a.v[3]
	a4 := transmute(u64)a.v[4]

	// safegcd returns a value in [0, modulus) with limbs below 2^62, and the modulus is
	// under 2^256, so the top limb must fit in 8 bits.
	CHECK(a0 >> 62 == 0, "fe_from_signed62: limb 0 out of range")
	CHECK(a1 >> 62 == 0, "fe_from_signed62: limb 1 out of range")
	CHECK(a2 >> 62 == 0, "fe_from_signed62: limb 2 out of range")
	CHECK(a3 >> 62 == 0, "fe_from_signed62: limb 3 out of range")
	CHECK(a4 >> 8 == 0, "fe_from_signed62: limb 4 out of range")

	r.n[0] = a0 & M52
	r.n[1] = (a0 >> 52 | a1 << 10) & M52
	r.n[2] = (a1 >> 42 | a2 << 20) & M52
	r.n[3] = (a2 >> 32 | a3 << 30) & M52
	r.n[4] = a3 >> 22 | a4 << 40

	when VERIFY {
		r.magnitude = 1
		r.normalized = true
	}
	fe_verify(r)
}

/*
Sets r to the modular inverse of a, in constant time.

Computes a^(p-2), which maps zero to zero and every other element to its inverse. On output
r is normalized with magnitude (a != 0).
*/
fe_inv :: proc "contextless" (r: ^Field_Elem, a: ^Field_Elem) {
	fe_verify(a)

	tmp := a^
	fe_normalize(&tmp)

	s: modinv.Signed62
	fe_to_signed62(&s, &tmp)
	modinv.modinv64(&s, &MODINFO_FE)
	fe_from_signed62(r, &s)

	when VERIFY {
		// The inverse of zero is zero, which has magnitude 0 rather than 1.
		r.magnitude = 1 if !fe_is_zero(r) else 0
	}
	fe_verify(r)
}

/*
Sets r to the modular inverse of a, in variable time.

Behaves identically to `fe_inv` but branches on the value. Never call this on secret data.
*/
fe_inv_var :: proc "contextless" (r: ^Field_Elem, a: ^Field_Elem) {
	fe_verify(a)

	tmp := a^
	fe_normalize_var(&tmp)

	s: modinv.Signed62
	fe_to_signed62(&s, &tmp)
	modinv.modinv64_var(&s, &MODINFO_FE)
	fe_from_signed62(r, &s)

	when VERIFY {
		r.magnitude = 1 if !fe_is_zero(r) else 0
	}
	fe_verify(r)
}

/*
Sets r to a square root of a, returning whether one exists.

Since p = 3 (mod 4), a^((p+1)/4) is a square root of a whenever a is a quadratic residue.
When it is not, sqrt(-a) exists instead, and this computes that and returns false. The
result is always itself a square, because (p+1)/4 is even.

`a` must have magnitude at most 8, and r must not alias a. On output r has magnitude 1 and
is not normalized.

The exponentiation is a fixed addition chain with no data-dependent control flow, so it is
constant-time. The final verification squares the result and compares, which is what turns
"probably a root" into a definite answer.
*/
fe_sqrt :: proc "contextless" (r: ^Field_Elem, a: ^Field_Elem) -> bool {
	fe_verify(a)
	fe_verify_magnitude(a, 8)
	CHECK(r != a, "fe_sqrt: r must not alias a")

	// (p+1)/4 in binary is three runs of ones, of lengths 2, 22 and 223. The chain builds
	// a^(2^n - 1) for each run; the names count run length, not exponent, so x2 is a^3.
	//   1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
	//
	// `fe_sqr` and `fe_mul` both permit the destination to alias their first operand,
	// which is what lets these accumulate in place.
	x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1: Field_Elem

	fe_sqr(&x2, a)
	fe_mul(&x2, &x2, a)

	fe_sqr(&x3, &x2)
	fe_mul(&x3, &x3, a)

	x6 = x3
	for _ in 0 ..< 3 {
		fe_sqr(&x6, &x6)
	}
	fe_mul(&x6, &x6, &x3)

	x9 = x6
	for _ in 0 ..< 3 {
		fe_sqr(&x9, &x9)
	}
	fe_mul(&x9, &x9, &x3)

	x11 = x9
	for _ in 0 ..< 2 {
		fe_sqr(&x11, &x11)
	}
	fe_mul(&x11, &x11, &x2)

	x22 = x11
	for _ in 0 ..< 11 {
		fe_sqr(&x22, &x22)
	}
	fe_mul(&x22, &x22, &x11)

	x44 = x22
	for _ in 0 ..< 22 {
		fe_sqr(&x44, &x44)
	}
	fe_mul(&x44, &x44, &x22)

	x88 = x44
	for _ in 0 ..< 44 {
		fe_sqr(&x88, &x88)
	}
	fe_mul(&x88, &x88, &x44)

	x176 = x88
	for _ in 0 ..< 88 {
		fe_sqr(&x176, &x176)
	}
	fe_mul(&x176, &x176, &x88)

	x220 = x176
	for _ in 0 ..< 44 {
		fe_sqr(&x220, &x220)
	}
	fe_mul(&x220, &x220, &x44)

	x223 = x220
	for _ in 0 ..< 3 {
		fe_sqr(&x223, &x223)
	}
	fe_mul(&x223, &x223, &x3)

	// Assemble the result with a sliding window over the three blocks.
	t1 = x223
	for _ in 0 ..< 23 {
		fe_sqr(&t1, &t1)
	}
	fe_mul(&t1, &t1, &x22)
	for _ in 0 ..< 6 {
		fe_sqr(&t1, &t1)
	}
	fe_mul(&t1, &t1, &x2)
	fe_sqr(&t1, &t1)
	fe_sqr(r, &t1)

	// Confirm it: if squaring the result does not reproduce a, then a was not a residue
	// and what we computed is sqrt(-a) instead.
	fe_sqr(&t1, r)
	ret := fe_equal(&t1, a)

	when VERIFY {
		if !ret {
			// The only other possibility is that we found a root of -a.
			fe_negate(&t1, &t1, 1)
			fe_normalize_var(&t1)
			when VERIFY {
				CHECK(fe_equal(&t1, a), "fe_sqrt: result is a root of neither a nor -a")
			}
		}
	}
	return ret
}

/*
Reports whether a is a square modulo p, in variable time.

Uses the Jacobi symbol, falling back to computing an actual square root when the symbol
routine fails to converge. Never call this on secret data.
*/
fe_is_square_var :: proc "contextless" (a: ^Field_Elem) -> bool {
	fe_verify(a)

	tmp := a^
	fe_normalize_var(&tmp)

	// The Jacobi routine cannot accept zero, and zero is a square.
	if fe_is_zero(&tmp) {
		return true
	}

	s: modinv.Signed62
	fe_to_signed62(&s, &tmp)
	jac := modinv.jacobi64_maybe_var(&s, &MODINFO_FE)

	if jac == 0 {
		// The symbol could not be computed within the iteration bound. This is extremely
		// rare with random input outside debug builds, where the bound is deliberately
		// low so this path is exercised. Fall back to a square root.
		dummy: Field_Elem
		return fe_sqrt(&dummy, &tmp)
	}

	return jac >= 0
}
