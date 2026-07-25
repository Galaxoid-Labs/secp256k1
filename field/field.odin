/*
Field arithmetic modulo p = 2^256 - 2^32 - 977, the secp256k1 field prime.

A field element is five 64-bit limbs in base 2^52, with `u128` intermediates for the
64x64->128 products. This is the reference representation, mirroring upstream's
`field_5x52` with `field_5x52_int128`; it is not a reduced-precision stand-in. Odin's
`u128` is native on every target, so upstream's `__int128`-absent fallback has no analogue
here and is deliberately absent.

The field prime is identical for every curve configuration in `params`, including the
reduced-order exhaustive curves, so this package takes no configuration.

# Magnitude and normalization

Limbs are allowed to exceed 2^52. How far they may exceed it is tracked by a field
element's *magnitude*, and whether the represented integer has been reduced below p is
tracked by its *normalized* flag. Both are bookkeeping that exists only under `-debug`
(see `VERIFY`), but the bounds they describe are load-bearing at all times: every
procedure below documents the magnitudes it accepts and produces, and exceeding them
silently overflows.

A field element f represents sum(i=0..4, f.n[i] << (i*52)) mod p.

	magnitude m requires:  n[i] <= 2 * m * (2^52 - 1)   for i = 0..3
	                       n[4] <= 2 * m * (2^48 - 1)

	normalized requires:   n[i] <= 2^52 - 1             for i = 0..3
	                       sum(i=0..4, n[i] << (i*52)) < p
	                       (together these imply n[4] <= 2^48 - 1)
*/
package field

import "base:runtime"
import "core:mem"

/*
Number of limbs in the representation.
*/
LIMBS :: 5

/*
Bits per limb.
*/
LIMB_BITS :: 52

/*
Mask selecting one full limb: 2^52 - 1.
*/
M52 :: 0x000f_ffff_ffff_ffff

/*
Mask selecting the top limb's 48 significant bits: 2^48 - 1.
*/
M48 :: 0x0000_ffff_ffff_ffff

/*
The reduction constant 2^256 mod p = 2^32 + 977.

A carry out of bit 256 is reduced by adding this multiple of it back into limb 0.
*/
R :: 0x1_000003d1

/*
R << 4, the form the multiplication inner loop needs where its accumulator is offset by
four bits.
*/
R_SHIFTED :: 0x10_00003d10

/*
Limb 0 of the field prime p. p's remaining limbs are all `M52`, except the top which is
`M48`.
*/
P0 :: 0x000f_ffff_efff_ffc2f & M52

/*
Whether magnitude and normalization bookkeeping is compiled in.

Upstream gates this on its `VERIFY` define. Here it follows `-debug`, so
`odin test . -debug` runs with the invariant layer active, matching the discipline in
DEVELOPMENT.md that randomized runs happen with invariants on.
*/
VERIFY :: ODIN_DEBUG

when VERIFY {
	/*
	A field element: five limbs in base 2^52, representing an integer modulo p.

	Under `-debug` the struct additionally carries its magnitude and normalized flag.
	Those fields do not exist in a release build, so code must never branch on them
	outside a `when VERIFY` block.
	*/
	Field_Elem :: struct {
		n:          [LIMBS]u64,
		/*
		How far limbs are permitted to exceed 2^52; see the package documentation.
		*/
		magnitude:  int,
		/*
		Whether the represented integer is known to be reduced below p.
		*/
		normalized: bool,
	}
} else {
	Field_Elem :: struct {
		n: [LIMBS]u64,
	}
}

/*
A field element in its packed 4x64 form, for storage in precomputed tables.

Always represents a normalized value and carries no magnitude bookkeeping, which is what
makes it half the size of a `Field_Elem` under `-debug`.
*/
Field_Storage :: struct {
	n: [4]u64,
}

/*
Internal invariant check, compiled away entirely unless `VERIFY` is set.

Mirrors upstream's `VERIFY_CHECK`. Never weaken or remove a failing check to make a test
pass; a firing check has found a real bug.
*/
@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "field invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(condition, message, loc)
	}
}

/*
Asserts that x fits in n bits. Mirrors upstream's `VERIFY_BITS`.
*/
@(private)
CHECK_BITS :: #force_inline proc "contextless" (
	x: u64,
	n: uint,
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(x >> n == 0, "field limb exceeds its bit bound", loc)
	}
}

/*
Asserts that a 128-bit accumulator fits in n bits. Mirrors upstream's `VERIFY_BITS_128`.
*/
@(private)
CHECK_BITS_128 :: #force_inline proc "contextless" (
	x: u128,
	n: uint,
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(x >> n == 0, "field accumulator exceeds its bit bound", loc)
	}
}

@(private)
ONE_LIMBS :: [LIMBS]u64{1, 0, 0, 0, 0}

/*
beta: the cube root of 1 modulo p that realises the secp256k1 endomorphism
lambda*(x,y) == (beta*x, y).
*/
@(private)
BETA_LIMBS :: [LIMBS]u64 {
	0x96c28719501ee,
	0x7512f58995c13,
	0xc3434e99cf049,
	0x07106e64479ea,
	0x07ae96a2b657c,
}

when VERIFY {
	/*
	The multiplicative identity, 1. Normalized, magnitude 1.
	*/
	@(rodata)
	ONE := Field_Elem{n = ONE_LIMBS, magnitude = 1, normalized = true}

	/*
	beta, the endomorphism constant. Normalized, magnitude 1.
	*/
	@(rodata)
	BETA := Field_Elem{n = BETA_LIMBS, magnitude = 1, normalized = true}
} else {
	@(rodata)
	ONE := Field_Elem{n = ONE_LIMBS}

	@(rodata)
	BETA := Field_Elem{n = BETA_LIMBS}
}

/*
Constructs a field element from eight big-endian 32-bit words, d7 most significant.

The result has magnitude 1, or 0 if the value is zero, and is normalized unless the value
is at least p. This is the constant-construction path; `set_b32_mod` is the runtime one.

Mirrors upstream's `SECP256K1_FE_CONST`.
*/
fe_const :: proc "contextless" (d7, d6, d5, d4, d3, d2, d1, d0: u32) -> (r: Field_Elem) {
	r.n[0] = u64(d0) | (u64(d1) & 0xf_ffff) << 32
	r.n[1] = u64(d1) >> 20 | u64(d2) << 12 | (u64(d3) & 0xff) << 44
	r.n[2] = u64(d3) >> 8 | (u64(d4) & 0xfff_ffff) << 24
	r.n[3] = u64(d4) >> 28 | u64(d5) << 4 | (u64(d6) & 0xffff) << 36
	r.n[4] = u64(d6) >> 16 | u64(d7) << 16

	when VERIFY {
		r.magnitude = 1 if (d7 | d6 | d5 | d4 | d3 | d2 | d1 | d0) != 0 else 0
		r.normalized = !(
			(d7 & d6 & d5 & d4 & d3 & d2) == 0xffff_ffff &&
				(d1 == 0xffff_ffff || (d1 == 0xffff_fffe && d0 >= 0xffff_fc2f)) \
		)
	}
	return
}

/*
Zeroes a field element so that secret material does not outlive its use.

The wipe is explicit and must not be elided by the optimizer.
*/
fe_clear :: proc "contextless" (a: ^Field_Elem) {
	mem.zero_explicit(a, size_of(Field_Elem))
}

/*
Sets r to a small non-negative integer.

`a` must be in [0, 0x7fff]. On output r is normalized with magnitude (a != 0).
*/
fe_set_int :: proc "contextless" (r: ^Field_Elem, a: u32) {
	CHECK(a <= 0x7fff, "fe_set_int: value out of range")
	r.n = {u64(a), 0, 0, 0, 0}
	when VERIFY {
		r.magnitude = 1 if a != 0 else 0
		r.normalized = true
	}
}

/*
Reports whether a is zero.

`a` must be normalized. For unnormalized input use `fe_normalizes_to_zero`, which does not
require reduction first but is slower.
*/
fe_is_zero :: proc "contextless" (a: ^Field_Elem) -> bool {
	fe_verify(a)
	when VERIFY {
		CHECK(a.normalized, "fe_is_zero: input must be normalized")
	}
	return (a.n[0] | a.n[1] | a.n[2] | a.n[3] | a.n[4]) == 0
}

/*
Reports whether a is odd.

`a` must be normalized.
*/
fe_is_odd :: proc "contextless" (a: ^Field_Elem) -> bool {
	fe_verify(a)
	when VERIFY {
		CHECK(a.normalized, "fe_is_odd: input must be normalized")
	}
	return a.n[0] & 1 == 1
}

/*
Sets r to the field element whose limbs sit exactly at the upper bound permitted by
magnitude m, so arithmetic on it runs as close to internal overflow as the representation
allows.

Normalized if and only if m == 0. Used by the tests to probe carry-propagation edges;
mirrors upstream's `secp256k1_fe_get_bounds`.
*/
fe_get_bounds :: proc "contextless" (r: ^Field_Elem, m: int) {
	CHECK(m >= 0 && m <= 32, "fe_get_bounds: magnitude out of range")
	limb := u64(M52) * 2 * u64(m)
	top := u64(M48) * 2 * u64(m)
	r.n = {limb, limb, limb, limb, top}
	when VERIFY {
		r.magnitude = m
		r.normalized = m == 0
	}
}
