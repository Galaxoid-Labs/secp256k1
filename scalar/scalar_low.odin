/*
Scalar arithmetic for the exhaustive-test curves.

Mirrors upstream's `scalar_low_impl.h`. Under `-define:EXHAUSTIVE_ORDER=n` the curve order
becomes a small prime (7, 13 or 199), so a scalar fits in a single `u32` and every operation
is plain modular arithmetic. That is not an optimization — it is what makes exhaustive
testing possible at all. With the real 256-bit order there is no way to enumerate every
scalar and check the group law over the whole group; with order 13 there are thirteen.

This file and the 4x64 implementation are mutually exclusive: each is wrapped in a `when` on
`EXHAUSTIVE_ORDER`, and exactly one is compiled. The public API is identical, so every
package above `scalar` builds unchanged in either mode.

# Constant-time status

None of this is constant-time, and it does not need to be: these curves exist only inside
the test suite and hold no secrets. `scalar_cmov` still uses mask arithmetic, because the
tests that exercise it are checking the *shape* of the operation and a branching cmov would
make that test vacuous.
*/
package scalar

import "core:mem"
import "../params"

when params.EXHAUSTIVE_ORDER > 0 {

	/*
	The small group order this build is compiled for.
	*/
	ORDER :: u32(params.EXHAUSTIVE_ORDER)

	/*
	A scalar modulo the small order, always held reduced into [0, ORDER).
	*/
	Scalar :: struct {
		d: u32,
	}

	/*
	The scalar 0.
	*/
	@(rodata)
	ZERO := Scalar{d = 0}

	/*
	The scalar 1.
	*/
	@(rodata)
	ONE := Scalar{d = 1}

	/*
	lambda for the exhaustive curve, from `params`.

	The real curve's lambda is a 256-bit constant tied to the actual group order and is
	meaningless here; the small curves carry their own.
	*/
	@(rodata)
	LAMBDA := Scalar{d = u32(params.EXHAUSTIVE_LAMBDA)}

	scalar_verify :: #force_inline proc "contextless" (a: ^Scalar, loc := #caller_location) {
		when VERIFY {
			runtime.assert_contextless(a.d < ORDER, "scalar_verify: value is not reduced", loc)
		}
	}

	scalar_clear :: proc "contextless" (a: ^Scalar) {
		mem.zero_explicit(a, size_of(Scalar))
	}

	scalar_set_int :: proc "contextless" (r: ^Scalar, v: u32) {
		r.d = v % ORDER
		scalar_verify(r)
	}

	/*
	Constructs a scalar from eight big-endian 32-bit words, reduced modulo the small order.

	Reducing rather than rejecting matters: callers write genuine 256-bit constants — the
	`ecmult_const` split offset of 2^128, for one — and those have a perfectly well-defined
	image in a small group. Horner's method over the words keeps every intermediate below
	`ORDER * 2^32`, which fits a u64 comfortably for any supported order.
	*/
	scalar_const :: proc "contextless" (d7, d6, d5, d4, d3, d2, d1, d0: u32) -> (r: Scalar) {
		words := [8]u32{d7, d6, d5, d4, d3, d2, d1, d0}
		acc := u64(0)
		for w in words {
			acc = ((acc << 32) + u64(w)) % u64(ORDER)
		}
		r.d = u32(acc)
		scalar_verify(&r)
		return
	}

	scalar_is_even :: proc "contextless" (a: ^Scalar) -> bool {
		scalar_verify(a)
		return a.d & 1 == 0
	}

	scalar_is_zero :: proc "contextless" (a: ^Scalar) -> bool {
		scalar_verify(a)
		return a.d == 0
	}

	scalar_is_one :: proc "contextless" (a: ^Scalar) -> bool {
		scalar_verify(a)
		return a.d == 1
	}

	scalar_is_high :: proc "contextless" (a: ^Scalar) -> bool {
		scalar_verify(a)
		return a.d > ORDER / 2
	}

	scalar_check_overflow :: proc "contextless" (a: ^Scalar) -> bool {
		return a.d >= ORDER
	}

	scalar_eq :: proc "contextless" (a: ^Scalar, b: ^Scalar) -> bool {
		scalar_verify(a)
		scalar_verify(b)
		return a.d == b.d
	}

	scalar_get_bits_limb32 :: proc "contextless" (a: ^Scalar, offset, count: uint) -> u32 {
		scalar_verify(a)
		CHECK((count > 0) & (count <= 32), "scalar_get_bits_limb32: count out of range")
		if offset < 32 {
			return (a.d >> offset) & (0xffff_ffff >> (32 - count))
		}
		return 0
	}

	scalar_get_bits_var :: proc "contextless" (a: ^Scalar, offset, count: uint) -> u32 {
		scalar_verify(a)
		return scalar_get_bits_limb32(a, offset, count)
	}

	scalar_add :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar) -> u64 {
		scalar_verify(a)
		scalar_verify(b)
		r.d = (a.d + b.d) % ORDER
		scalar_verify(r)
		return u64(r.d < b.d)
	}

	scalar_cadd_bit :: proc "contextless" (r: ^Scalar, bit: uint, flag: bool) {
		scalar_verify(r)
		if flag && bit < 32 {
			r.d += u32(1) << bit
		}
		scalar_verify(r)
	}

	scalar_negate :: proc "contextless" (r: ^Scalar, a: ^Scalar) {
		scalar_verify(a)
		r.d = a.d == 0 ? 0 : ORDER - a.d
		scalar_verify(r)
	}

	scalar_cond_negate :: proc "contextless" (r: ^Scalar, flag: bool) -> int {
		scalar_verify(r)
		if flag {
			scalar_negate(r, r)
		}
		scalar_verify(r)
		return flag ? -1 : 1
	}

	scalar_mul :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar) {
		scalar_verify(a)
		scalar_verify(b)
		// Widened before multiplying: ORDER is at most 199, but the product of two u32s
		// below it still needs 16 bits of headroom that u32 happens to have — using u64
		// makes that independent of the chosen order.
		r.d = u32((u64(a.d) * u64(b.d)) % u64(ORDER))
		scalar_verify(r)
	}

	scalar_half :: proc "contextless" (r: ^Scalar, a: ^Scalar) {
		scalar_verify(a)
		r.d = (a.d + ((~(a.d & 1) + 1) & ORDER)) >> 1
		scalar_verify(r)
	}

	scalar_cmov :: proc "contextless" (r: ^Scalar, a: ^Scalar, flag: bool) {
		scalar_verify(a)
		// Mask arithmetic, laundered exactly as the 4x64 version is. Nothing secret passes
		// through here, but a branching cmov would make the shared cmov test vacuous.
		mask1 := u32(ct_mask(flag))
		mask0 := ~mask1
		r.d = (r.d & mask0) | (a.d & mask1)
		scalar_verify(r)
	}

	scalar_set_b32 :: proc "contextless" (r: ^Scalar, b32: ^[32]u8) -> bool {
		over := false
		r.d = 0
		for i in 0 ..< 32 {
			r.d = (r.d * 0x100) + u32(b32[i])
			if r.d >= ORDER {
				over = true
				r.d %= ORDER
			}
		}
		scalar_verify(r)
		return over
	}

	scalar_set_b32_seckey :: proc "contextless" (r: ^Scalar, b32: ^[32]u8) -> bool {
		overflowed := scalar_set_b32(r, b32)
		return !overflowed & !scalar_is_zero(r)
	}

	scalar_get_b32 :: proc "contextless" (bin: ^[32]u8, a: ^Scalar) {
		scalar_verify(a)
		for i in 0 ..< 32 {
			bin[i] = 0
		}
		bin[28] = u8(a.d >> 24)
		bin[29] = u8(a.d >> 16)
		bin[30] = u8(a.d >> 8)
		bin[31] = u8(a.d)
	}

	scalar_inverse :: proc "contextless" (r: ^Scalar, x: ^Scalar) {
		scalar_verify(x)
		// Brute force over the whole group. Trivially fast at this size, and it makes the
		// inverse independent of the safegcd code so an exhaustive run can catch a bug in
		// it rather than sharing it.
		res := u32(0)
		for i in 0 ..< ORDER {
			if (u64(i) * u64(x.d)) % u64(ORDER) == 1 {
				res = i
				break
			}
		}
		// Zero means the scalar was not invertible, which for a prime order can only happen
		// for zero itself — or means the configured order is composite, which is a build
		// configuration bug rather than a runtime one.
		CHECK(res != 0 || x.d == 0, "scalar_inverse: non-invertible scalar; is the order prime?")
		r.d = res
		scalar_verify(r)
	}

	scalar_inverse_var :: proc "contextless" (r: ^Scalar, x: ^Scalar) {
		scalar_inverse(r, x)
	}

	scalar_split_128 :: proc "contextless" (r1: ^Scalar, r2: ^Scalar, a: ^Scalar) {
		scalar_verify(a)
		r1^ = a^
		r2.d = 0
		scalar_verify(r1)
		scalar_verify(r2)
	}

	/*
	The endomorphism split, as plain modular arithmetic.

	On the real curve this is a lattice reduction producing two ~128-bit halves. Here it is
	upstream's exhaustive-mode definition: pick r2, then solve for r1. The `+ 5` is
	arbitrary — its only job is to make r2 vary with k so that the split is not trivially
	the identity and the callers' handling of both halves is genuinely exercised.
	*/
	scalar_split_lambda :: proc "contextless" (r1: ^Scalar, r2: ^Scalar, k: ^Scalar) {
		scalar_verify(k)
		CHECK(r1 != r2, "scalar_split_lambda: outputs must not alias")

		r2.d = (k.d + 5) % ORDER
		r1.d = u32(
			(u64(k.d) + u64(ORDER - r2.d) * u64(LAMBDA.d)) % u64(ORDER),
		)
		scalar_verify(r1)
		scalar_verify(r2)
	}

	/*
	Shifts the product a*b right by `shift` bits, rounding to nearest.

	Only `ecmult`'s wNAF setup calls this, and only on the real curve's split constants.
	Reaching it in exhaustive mode means a caller took a path that does not apply here.
	*/
	scalar_mul_shift_var :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar, shift: uint) {
		CHECK(false, "scalar_mul_shift_var: not meaningful for the exhaustive order")
		scalar_set_int(r, 0)
	}
}
