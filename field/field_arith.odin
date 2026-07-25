/*
Field addition, negation, small-integer scaling, halving, conditional move, and the
packed-storage conversions.

None of these reduce; they let magnitudes grow and leave it to the caller to normalize
before the bound is exceeded. Each procedure documents the magnitude it produces, and the
`fe_verify_magnitude` calls are where a caller who let one grow too far gets caught.

Mirrors upstream's `field_5x52_impl.h`.
*/
package field

/*
Adds a into r.

The sum of the two magnitudes must not exceed 32. On output r has magnitude equal to that
sum and is not normalized.
*/
fe_add :: #force_inline proc "contextless" (r: ^Field_Elem, a: ^Field_Elem) {
	fe_verify(r)
	fe_verify(a)
	when VERIFY {
		CHECK(r.magnitude + a.magnitude <= 32, "fe_add: combined magnitude exceeds 32")
	}

	r.n[0] += a.n[0]
	r.n[1] += a.n[1]
	r.n[2] += a.n[2]
	r.n[3] += a.n[3]
	r.n[4] += a.n[4]

	when VERIFY {
		r.magnitude += a.magnitude
		r.normalized = false
	}
	fe_verify(r)
}

/*
Adds a small non-negative integer to r.

`a` must be in [0, 0x7fff]. On output r's magnitude has grown by 1 and it is not
normalized.
*/
fe_add_int :: #force_inline proc "contextless" (r: ^Field_Elem, a: u32) {
	fe_verify(r)
	CHECK(a <= 0x7fff, "fe_add_int: value out of range")
	when VERIFY {
		CHECK(r.magnitude + 1 <= 32, "fe_add_int: magnitude would exceed 32")
	}

	r.n[0] += u64(a)

	when VERIFY {
		r.magnitude += 1
		r.normalized = false
	}
	fe_verify(r)
}

/*
Sets r to -a, where m is an upper bound on a's magnitude.

Rather than subtract from p, this subtracts each limb from a multiple of p large enough
that no limb underflows — which is why the caller must supply the magnitude bound. On
output r has magnitude m+1 and is not normalized.

Passing an m smaller than a's actual magnitude produces a wrong result rather than a
detected error in release builds, so the bound is asserted under `-debug`.
*/
fe_negate :: #force_inline proc "contextless" (r: ^Field_Elem, a: ^Field_Elem, m: int) {
	fe_verify(a)
	CHECK(m >= 0 && m <= 31, "fe_negate: magnitude bound out of range")
	fe_verify_magnitude(a, m)

	// For every legal m these hold, so no limb of the subtraction can underflow.
	CHECK(u64(P0) * 2 * u64(m + 1) >= u64(M52) * 2 * u64(m), "fe_negate: limb 0 bound")
	CHECK(u64(M52) * 2 * u64(m + 1) >= u64(M52) * 2 * u64(m), "fe_negate: limb 1-3 bound")
	CHECK(u64(M48) * 2 * u64(m + 1) >= u64(M48) * 2 * u64(m), "fe_negate: limb 4 bound")

	k := 2 * u64(m + 1)
	r.n[0] = u64(P0) * k - a.n[0]
	r.n[1] = u64(M52) * k - a.n[1]
	r.n[2] = u64(M52) * k - a.n[2]
	r.n[3] = u64(M52) * k - a.n[3]
	r.n[4] = u64(M48) * k - a.n[4]

	when VERIFY {
		r.magnitude = m + 1
		r.normalized = false
	}
	fe_verify(r)
}

/*
Multiplies r by a small non-negative integer.

`a` must be in [0, 32], and r's magnitude times a must not exceed 32. On output r's
magnitude is multiplied by a and it is not normalized.
*/
fe_mul_int :: #force_inline proc "contextless" (r: ^Field_Elem, a: u32) {
	fe_verify(r)
	CHECK(a <= 32, "fe_mul_int: multiplier out of range")
	when VERIFY {
		CHECK(r.magnitude * int(a) <= 32, "fe_mul_int: resulting magnitude exceeds 32")
	}

	r.n[0] *= u64(a)
	r.n[1] *= u64(a)
	r.n[2] *= u64(a)
	r.n[3] *= u64(a)
	r.n[4] *= u64(a)

	when VERIFY {
		r.magnitude *= int(a)
		r.normalized = false
	}
	fe_verify(r)
}

/*
Halves r modulo p, in constant time.

If r is odd, p is added first so the halving is exact; p is odd, so this always produces an
even value. On output r has magnitude floor(m/2) + 1 where m was the input magnitude.

The mask is derived from the low bit arithmetically rather than by branching, so this is
safe on secret data.
*/
fe_half :: #force_inline proc "contextless" (r: ^Field_Elem) {
	fe_verify(r)

	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]
	one := u64(1)
	// All ones when r is odd, all zeros when even. The >> 12 trims it to limb width.
	mask := (-(t0 & one)) >> 12

	// Bounds, over the rationals, with m the input magnitude, C = 2*(2^52-1) and
	// D = 2*(2^48-1). On entry t0..t3 <= C*m and t4 <= D*m.
	t0 += u64(P0) & mask
	t1 += mask
	t2 += mask
	t3 += mask
	t4 += mask >> 4

	CHECK(t0 & one == 0, "fe_half: value is still odd after conditional add")

	// Added at most C/2 to t0..t3 and D/2 to t4, so now t0..t3 <= C*(m + 1/2) and
	// t4 <= D*(m + 1/2).

	r.n[0] = (t0 >> 1) + ((t1 & one) << 51)
	r.n[1] = (t1 >> 1) + ((t2 & one) << 51)
	r.n[2] = (t2 >> 1) + ((t3 & one) << 51)
	r.n[3] = (t3 >> 1) + ((t4 & one) << 51)
	r.n[4] = t4 >> 1

	// After the shift t0..t3 <= C*(m/2 + 1/2) and t4 <= D*(m/2 + 1/4), so the smallest
	// integer magnitude that bounds every limb is floor(m/2) + 1.
	when VERIFY {
		r.magnitude = (r.magnitude >> 1) + 1
		r.normalized = false
	}
	fe_verify(r)
}

/*
Sets r to a if flag is true, and leaves r unchanged otherwise, in constant time.

On output r's magnitude is the larger of the two inputs', and it is normalized only if
both inputs were.
*/
fe_cmov :: #force_inline proc "contextless" (r: ^Field_Elem, a: ^Field_Elem, flag: bool) {
	when VERIFY {
		fe_verify(a)
	}

	// Derived arithmetically so no branch depends on flag.
	mask0 := u64(flag) + ~u64(0)
	mask1 := ~mask0

	r.n[0] = (r.n[0] & mask0) | (a.n[0] & mask1)
	r.n[1] = (r.n[1] & mask0) | (a.n[1] & mask1)
	r.n[2] = (r.n[2] & mask0) | (a.n[2] & mask1)
	r.n[3] = (r.n[3] & mask0) | (a.n[3] & mask1)
	r.n[4] = (r.n[4] & mask0) | (a.n[4] & mask1)

	when VERIFY {
		if flag {
			r.magnitude = a.magnitude
			r.normalized = a.normalized
		}
	}
}

/*
Compares two normalized field elements as integers in [0, p).

Returns 1 if a > b, -1 if a < b, and 0 if they are equal. Variable-time in the values;
never call this on secret data.
*/
fe_cmp_var :: proc "contextless" (a: ^Field_Elem, b: ^Field_Elem) -> int {
	fe_verify(a)
	fe_verify(b)
	when VERIFY {
		CHECK(a.normalized, "fe_cmp_var: a must be normalized")
		CHECK(b.normalized, "fe_cmp_var: b must be normalized")
	}

	for i := LIMBS - 1; i >= 0; i -= 1 {
		if a.n[i] > b.n[i] {
			return 1
		}
		if a.n[i] < b.n[i] {
			return -1
		}
	}
	return 0
}

/*
Reports whether a and b represent the same field element.

a's magnitude must not exceed 1 and b's must not exceed 31. Works on unnormalized input by
comparing through a subtraction rather than requiring both sides be reduced first.
*/
fe_equal :: proc "contextless" (a: ^Field_Elem, b: ^Field_Elem) -> bool {
	fe_verify(a)
	fe_verify(b)
	fe_verify_magnitude(a, 1)
	fe_verify_magnitude(b, 31)

	na: Field_Elem
	fe_negate(&na, a, 1)
	fe_add(&na, b)
	return fe_normalizes_to_zero(&na)
}

/*
Packs a normalized field element into its 4x64 storage form.
*/
fe_to_storage :: proc "contextless" (r: ^Field_Storage, a: ^Field_Elem) {
	fe_verify(a)
	when VERIFY {
		CHECK(a.normalized, "fe_to_storage: input must be normalized")
	}

	r.n[0] = a.n[0] | a.n[1] << 52
	r.n[1] = a.n[1] >> 12 | a.n[2] << 40
	r.n[2] = a.n[2] >> 24 | a.n[3] << 28
	r.n[3] = a.n[3] >> 36 | a.n[4] << 16
}

/*
Unpacks a field element from its 4x64 storage form.

On output r is normalized with magnitude 1.
*/
fe_from_storage :: proc "contextless" (r: ^Field_Elem, a: ^Field_Storage) {
	r.n[0] = a.n[0] & M52
	r.n[1] = a.n[0] >> 52 | (a.n[1] << 12) & M52
	r.n[2] = a.n[1] >> 40 | (a.n[2] << 24) & M52
	r.n[3] = a.n[2] >> 28 | (a.n[3] << 36) & M52
	r.n[4] = a.n[3] >> 16

	when VERIFY {
		r.magnitude = 1
		r.normalized = true
	}
	fe_verify(r)
}

/*
Sets r to a if flag is true, and leaves r unchanged otherwise, in constant time.
*/
fe_storage_cmov :: proc "contextless" (r: ^Field_Storage, a: ^Field_Storage, flag: bool) {
	mask0 := u64(flag) + ~u64(0)
	mask1 := ~mask0

	r.n[0] = (r.n[0] & mask0) | (a.n[0] & mask1)
	r.n[1] = (r.n[1] & mask0) | (a.n[1] & mask1)
	r.n[2] = (r.n[2] & mask0) | (a.n[2] & mask1)
	r.n[3] = (r.n[3] & mask0) | (a.n[3] & mask1)
}
