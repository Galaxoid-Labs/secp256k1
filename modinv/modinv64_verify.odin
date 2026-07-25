/*
Invariant helpers for the safegcd implementation, compiled only under `-debug`.

These do arbitrary-precision comparisons on `Signed62` values so the main algorithm can
assert its loop invariants — that f and g stay bounded by the modulus, that d and e stay in
(-2*modulus, modulus), and that each transition matrix has a power-of-two determinant.
Those invariants are the whole safety argument of safegcd, and they are cheap to state and
expensive to get wrong silently.

Mirrors the `#ifdef VERIFY` block in upstream's `modinv64_impl.h`.
*/
package modinv

when VERIFY {
	/*
	Absolute value, avoiding the C standard library's size-dependent `abs` family.
	*/
	@(private)
	abs_i64 :: proc "contextless" (v: i64) -> i64 {
		CHECK(v > min(i64), "abs_i64: cannot negate the minimum value")
		return -v if v < 0 else v
	}

	/*
	Computes a * factor into r, over the low `alen` limbs of a.

	All but the top limb of r end up in [0, 2^62); the top limb absorbs whatever remains,
	which is why the result can represent values outside the normalized range.
	*/
	@(private)
	mul_62 :: proc "contextless" (r: ^Signed62, a: ^Signed62, alen: int, factor: i64) {
		c := i128(0)
		for i in 0 ..< 4 {
			if i < alen {
				c += i128(a.v[i]) * i128(factor)
			}
			r.v[i] = transmute(i64)(u64(c) & M62)
			c >>= 62
		}
		if 4 < alen {
			c += i128(a.v[4]) * i128(factor)
		}
		// The remaining value must fit in a single limb, or the caller has exceeded the
		// range this helper supports.
		CHECK(c == i128(i64(c)), "mul_62: top limb overflowed")
		r.v[4] = i64(c)
	}

	/*
	Compares a against b * factor, returning -1, 0 or 1.

	`a` has `alen` limbs; `b` always has five.
	*/
	@(private)
	mul_cmp_62 :: proc "contextless" (
		a: ^Signed62,
		alen: int,
		b: ^Signed62,
		factor: i64,
	) -> int {
		am, bm: Signed62
		// Normalize all but the top limb of a.
		mul_62(&am, a, alen, 1)
		mul_62(&bm, b, 5, factor)

		for i in 0 ..< 4 {
			CHECK(am.v[i] >> 62 == 0, "mul_cmp_62: a limb not normalized")
			CHECK(bm.v[i] >> 62 == 0, "mul_cmp_62: b limb not normalized")
		}

		for i := 4; i >= 0; i -= 1 {
			if am.v[i] < bm.v[i] {
				return -1
			}
			if am.v[i] > bm.v[i] {
				return 1
			}
		}
		return 0
	}

	/*
	Reports whether the determinant of t equals 2^n, or +/-2^n when `signed_abs` is set.

	A power-of-two determinant is what guarantees that applying the transition matrix
	preserves gcd(f, g) up to a factor of two, which the algorithm divides back out.
	*/
	@(private)
	det_check_pow2 :: proc "contextless" (t: ^Trans2x2, n: uint, signed_abs: bool) -> bool {
		det := i128(t.u) * i128(t.r) - i128(t.v) * i128(t.q)
		if det == i128(1) << n {
			return true
		}
		if signed_abs && det == -(i128(1) << n) {
			return true
		}
		return false
	}
}
