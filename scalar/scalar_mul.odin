/*
Scalar multiplication modulo n, and the three-stage reduction of a 512-bit product.

Because n is not close to a power of two, reduction cannot be a single fold like the
field's. Instead the 512-bit product is narrowed in stages using the complement
c = 2^256 - n, whose top limbs are small:

	512 bits -> 385 bits    m = l[0..3] + l[4..7] * c
	385 bits -> 258 bits    p = m[0..3] + m[4..6] * c
	258 bits -> 256 bits    r = p[0..3] + p[4] * c, then one conditional subtraction

Mirrors upstream's `scalar_4x64_impl.h`. Upstream additionally ships an x86-64 assembly
version of these two routines, enabled by default on that architecture; this is the
portable C path it falls back to elsewhere, and the two produce identical results.

# The accumulator

Upstream builds the product in a three-word accumulator (c0, c1, c2) via `muladd` /
`sumadd` macros. The same structure is kept here as `Acc`, rather than being rewritten
around `u128` carries, so that a differential failure against upstream can be localised to
the same step in both implementations.
*/
package scalar
import "../params"

// The 4x64 representation is compiled only for the real curve. Under
// `-define:EXHAUSTIVE_ORDER=n` the whole scalar type is replaced by the single-word
// implementation in `scalar_low.odin`, which mirrors upstream's `scalar_low_impl.h`.
// Exactly one of the two is ever compiled.
when params.EXHAUSTIVE_ORDER == 0 {

/*
A 192-bit accumulator: three 64-bit words, least significant first.

`hi` must never overflow; every routine below stays within that bound by construction, and
the `CHECK` calls assert it under `-debug`.
*/
@(private)
Acc :: struct {
	lo, mid, hi: u64,
}

/*
Adds a * b to the accumulator.
*/
@(private)
muladd :: #force_inline proc "contextless" (c: ^Acc, a, b: u64) {
	t := u128(a) * u128(b)
	th := u64(t >> 64) // at most 0xfffffffffffffffe
	tl := u64(t)

	c.lo += tl // overflow handled on the next line
	th += u64(c.lo < tl) // at most 0xffffffffffffffff
	c.mid += th // overflow handled on the next line
	c.hi += u64(c.mid < th) // never overflows by contract

	CHECK((c.mid >= th) | (c.hi != 0), "muladd: accumulator overflowed")
}

/*
Adds a * b to the accumulator, where the high word is known to stay zero.
*/
@(private)
muladd_fast :: #force_inline proc "contextless" (c: ^Acc, a, b: u64) {
	t := u128(a) * u128(b)
	th := u64(t >> 64)
	tl := u64(t)

	c.lo += tl
	th += u64(c.lo < tl)
	c.mid += th // never overflows by contract

	CHECK(c.mid >= th, "muladd_fast: accumulator overflowed")
}

/*
Adds a single word to the accumulator.
*/
@(private)
sumadd :: #force_inline proc "contextless" (c: ^Acc, a: u64) {
	c.lo += a
	over := u64(c.lo < a)
	c.mid += over
	c.hi += u64(c.mid < over)
}

/*
Adds a single word to the accumulator, where the high word is known to stay zero.
*/
@(private)
sumadd_fast :: #force_inline proc "contextless" (c: ^Acc, a: u64) {
	c.lo += a
	c.mid += u64(c.lo < a)

	CHECK((c.mid != 0) | (c.lo >= a), "sumadd_fast: accumulator overflowed")
	CHECK(c.hi == 0, "sumadd_fast: high word was not zero")
}

/*
Extracts the low word of the accumulator and shifts it down by 64 bits.
*/
@(private)
extract :: #force_inline proc "contextless" (c: ^Acc) -> u64 {
	n := c.lo
	c.lo = c.mid
	c.mid = c.hi
	c.hi = 0
	return n
}

/*
Extracts the low word and shifts down, where the high word is known to be zero.
*/
@(private)
extract_fast :: #force_inline proc "contextless" (c: ^Acc) -> u64 {
	n := c.lo
	c.lo = c.mid
	c.mid = 0
	CHECK(c.hi == 0, "extract_fast: high word was not zero")
	return n
}

/*
Computes the full 512-bit product of a and b into eight limbs.
*/
@(private)
scalar_mul_512 :: proc "contextless" (l8: ^[8]u64, a: ^Scalar, b: ^Scalar) {
	c := Acc{}

	muladd_fast(&c, a.d[0], b.d[0])
	l8[0] = extract_fast(&c)
	muladd(&c, a.d[0], b.d[1])
	muladd(&c, a.d[1], b.d[0])
	l8[1] = extract(&c)
	muladd(&c, a.d[0], b.d[2])
	muladd(&c, a.d[1], b.d[1])
	muladd(&c, a.d[2], b.d[0])
	l8[2] = extract(&c)
	muladd(&c, a.d[0], b.d[3])
	muladd(&c, a.d[1], b.d[2])
	muladd(&c, a.d[2], b.d[1])
	muladd(&c, a.d[3], b.d[0])
	l8[3] = extract(&c)
	muladd(&c, a.d[1], b.d[3])
	muladd(&c, a.d[2], b.d[2])
	muladd(&c, a.d[3], b.d[1])
	l8[4] = extract(&c)
	muladd(&c, a.d[2], b.d[3])
	muladd(&c, a.d[3], b.d[2])
	l8[5] = extract(&c)
	muladd_fast(&c, a.d[3], b.d[3])
	l8[6] = extract_fast(&c)

	CHECK(c.mid == 0, "scalar_mul_512: product exceeded 512 bits")
	l8[7] = c.lo
}

/*
Reduces a 512-bit value modulo n into r.
*/
@(private)
scalar_reduce_512 :: proc "contextless" (r: ^Scalar, l: ^[8]u64) {
	n0, n1, n2, n3 := l[4], l[5], l[6], l[7]

	// Stage 1: 512 bits down to 385.
	// m[0..6] = l[0..3] + n[0..3] * c
	c := Acc{lo = l[0]}
	muladd_fast(&c, n0, N_C_0)
	m0 := extract_fast(&c)
	sumadd_fast(&c, l[1])
	muladd(&c, n1, N_C_0)
	muladd(&c, n0, N_C_1)
	m1 := extract(&c)
	sumadd(&c, l[2])
	muladd(&c, n2, N_C_0)
	muladd(&c, n1, N_C_1)
	sumadd(&c, n0)
	m2 := extract(&c)
	sumadd(&c, l[3])
	muladd(&c, n3, N_C_0)
	muladd(&c, n2, N_C_1)
	sumadd(&c, n1)
	m3 := extract(&c)
	muladd(&c, n3, N_C_1)
	sumadd(&c, n2)
	m4 := extract(&c)
	sumadd_fast(&c, n3)
	m5 := extract_fast(&c)
	CHECK(c.lo <= 1, "scalar_reduce_512: stage 1 left more than one bit")
	m6 := c.lo

	// Stage 2: 385 bits down to 258.
	// p[0..4] = m[0..3] + m[4..6] * c
	c = Acc{lo = m0}
	muladd_fast(&c, m4, N_C_0)
	p0 := extract_fast(&c)
	sumadd_fast(&c, m1)
	muladd(&c, m5, N_C_0)
	muladd(&c, m4, N_C_1)
	p1 := extract(&c)
	sumadd(&c, m2)
	muladd(&c, m6, N_C_0)
	muladd(&c, m5, N_C_1)
	sumadd(&c, m4)
	p2 := extract(&c)
	sumadd_fast(&c, m3)
	muladd_fast(&c, m6, N_C_1)
	sumadd_fast(&c, m5)
	p3 := extract_fast(&c)
	p4 := c.lo + m6
	CHECK(p4 <= 2, "scalar_reduce_512: stage 2 left more than two bits")

	// Stage 3: 258 bits down to 256.
	// r[0..3] = p[0..3] + p[4] * c
	t := u128(p0)
	t += u128(N_C_0) * u128(p4)
	r.d[0] = u64(t); t >>= 64
	t += u128(p1)
	t += u128(N_C_1) * u128(p4)
	r.d[1] = u64(t); t >>= 64
	t += u128(p2)
	t += u128(p4)
	r.d[2] = u64(t); t >>= 64
	t += u128(p3)
	r.d[3] = u64(t)
	carry := u64(t >> 64)

	// One conditional subtraction of n finishes the job.
	scalar_reduce(r, carry + u64(scalar_check_overflow(r)))
	scalar_verify(r)
}

/*
Sets r to a * b modulo n.
*/
scalar_mul :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar) {
	scalar_verify(a)
	scalar_verify(b)

	l: [8]u64
	scalar_mul_512(&l, a, b)
	scalar_reduce_512(r, &l)

	scalar_verify(r)
}

/*
Sets r to (a * b) >> shift, rounded to nearest, where shift is at least 256.

Used by the GLV decomposition to approximate division by n with a multiplication. Named
`_var` upstream, but it is in fact constant-time whenever `shift` is a compile-time
constant, which is the only way it is called.
*/
scalar_mul_shift_var :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar, shift: uint) {
	scalar_verify(a)
	scalar_verify(b)
	CHECK(shift >= 256, "scalar_mul_shift_var: shift must be at least 256")

	l: [8]u64
	scalar_mul_512(&l, a, b)

	shiftlimbs := shift >> 6
	shiftlow := shift & 0x3f
	shifthigh := 64 - shiftlow

	r.d[0] =
		(l[0 + shiftlimbs] >> shiftlow |
					(l[1 + shiftlimbs] << shifthigh if shift < 448 && shiftlow != 0 else 0)) if shift < 512 else 0
	r.d[1] =
		(l[1 + shiftlimbs] >> shiftlow |
					(l[2 + shiftlimbs] << shifthigh if shift < 384 && shiftlow != 0 else 0)) if shift < 448 else 0
	r.d[2] =
		(l[2 + shiftlimbs] >> shiftlow |
					(l[3 + shiftlimbs] << shifthigh if shift < 320 && shiftlow != 0 else 0)) if shift < 384 else 0
	r.d[3] = (l[3 + shiftlimbs] >> shiftlow) if shift < 320 else 0

	// Round to nearest by adding the bit just below the shift point.
	scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1 == 1)

	scalar_verify(r)
}

}
