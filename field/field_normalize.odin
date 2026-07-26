/*
Normalization: reducing a field element's limbs back into range, and its value below p.

Four related routines, differing in how far they reduce and whether they are constant-time:

  - `fe_normalize`       full reduction, constant-time
  - `fe_normalize_weak`  limbs back to magnitude 1, value may still be >= p
  - `fe_normalize_var`   full reduction, variable-time in the value
  - `fe_normalizes_to_zero{,_var}`  test for zero without materialising the reduction

Every one of them first folds the carry out of bit 256 back into limb 0 by multiplying it
by `R` = 2^256 mod p, which is what makes the base-2^52 representation cheap to reduce.

Mirrors upstream's `field_5x52_impl.h`.
*/
package field

/*
Fully reduces r, in constant time.

On output r is normalized with magnitude 1: every limb is in range and the represented
integer is strictly below p.

The final conditional subtraction is performed unconditionally, with the condition folded
into the value added, so the running time does not depend on whether it was needed.
*/
fe_normalize :: proc "contextless" (r: ^Field_Elem) {
	fe_verify(r)

	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	// Reduce the top limb first, so the pass below produces at most a single carry.
	x := t4 >> 48
	t4 &= M48

	// First pass: brings the magnitude to 1, leaving a possible carry at bit 48 of t4.
	t0 += x * R
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52; m := t1
	t3 += t2 >> 52; t2 &= M52; m &= t2
	t4 += t3 >> 52; t3 &= M52; m &= t3

	CHECK(t4 >> 49 == 0, "fe_normalize: carry escaped the top limb")

	// At most one further reduction is needed. It is needed when the carry reached bit
	// 256, or when the value is in [p, 2^256), which requires every limb above limb 0 to
	// be saturated and limb 0 to have reached p's limb 0.
	x = (t4 >> 48) | u64(
		b64(t4 == M48) & b64(m == M52) & b64(t0 >= P0),
	)

	// Applied unconditionally for constant-time behaviour; x is 0 when it is not needed.
	t0 += x * R
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52
	t3 += t2 >> 52; t2 &= M52
	t4 += t3 >> 52; t3 &= M52

	CHECK(t4 >> 48 == x, "fe_normalize: final reduction did not carry as expected")

	// Drop the multiple of 2^256 the final reduction may have produced.
	t4 &= M48

	r.n = {t0, t1, t2, t3, t4}
	when VERIFY {
		r.magnitude = 1
		r.normalized = true
	}
	fe_verify(r)
}

/*
Brings r's limbs back into magnitude 1 without fully reducing its value.

On output r has magnitude 1 but may still represent an integer at or above p, so its
normalized flag is left unchanged. This is the cheap normalization used between
arithmetic steps where only the limb bounds matter.
*/
fe_normalize_weak :: proc "contextless" (r: ^Field_Elem) {
	fe_verify(r)

	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	x := t4 >> 48
	t4 &= M48

	t0 += x * R
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52
	t3 += t2 >> 52; t2 &= M52
	t4 += t3 >> 52; t3 &= M52

	CHECK(t4 >> 49 == 0, "fe_normalize_weak: carry escaped the top limb")

	r.n = {t0, t1, t2, t3, t4}
	when VERIFY {
		r.magnitude = 1
	}
	fe_verify(r)
}

/*
Fully reduces r. Identical in behaviour to `fe_normalize`, but branches on the value and
so is not constant-time.

Never call this on secret data.
*/
fe_normalize_var :: proc "contextless" (r: ^Field_Elem) {
	fe_verify(r)

	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	x := t4 >> 48
	t4 &= M48

	t0 += x * R
	t1 += t0 >> 52; t0 &= M52
	t2 += t1 >> 52; t1 &= M52; m := t1
	t3 += t2 >> 52; t2 &= M52; m &= t2
	t4 += t3 >> 52; t3 &= M52; m &= t3

	CHECK(t4 >> 49 == 0, "fe_normalize_var: carry escaped the top limb")

	x = (t4 >> 48) | u64(
		b64(t4 == M48) & b64(m == M52) & b64(t0 >= P0),
	)

	if x != 0 {
		t0 += R
		t1 += t0 >> 52; t0 &= M52
		t2 += t1 >> 52; t1 &= M52
		t3 += t2 >> 52; t2 &= M52
		t4 += t3 >> 52; t3 &= M52

		CHECK(t4 >> 48 == x, "fe_normalize_var: final reduction did not carry as expected")

		t4 &= M48
	}

	r.n = {t0, t1, t2, t3, t4}
	when VERIFY {
		r.magnitude = 1
		r.normalized = true
	}
	fe_verify(r)
}

/*
Reports whether r represents zero modulo p, in constant time, without requiring r to be
normalized.

Reduction can leave the value as either a raw 0 or a raw p, so both are tested: `z0`
accumulates evidence against 0 and `z1` against p.
*/
fe_normalizes_to_zero :: proc "contextless" (r: ^Field_Elem) -> bool {
	fe_verify(r)

	t0, t1, t2, t3, t4 := r.n[0], r.n[1], r.n[2], r.n[3], r.n[4]

	x := t4 >> 48
	t4 &= M48

	t0 += x * R
	t1 += t0 >> 52; t0 &= M52; z0 := t0;      z1 := t0 ~ 0x1000003d0
	t2 += t1 >> 52; t1 &= M52; z0 |= t1;      z1 &= t1
	t3 += t2 >> 52; t2 &= M52; z0 |= t2;      z1 &= t2
	t4 += t3 >> 52; t3 &= M52; z0 |= t3;      z1 &= t3
	                           z0 |= t4;      z1 &= t4 ~ 0xf000000000000

	CHECK(t4 >> 49 == 0, "fe_normalizes_to_zero: carry escaped the top limb")

	// Bitwise `|`, never `||`. This is the constant-time variant; short-circuiting would
	// make the second comparison conditional on the first, which is a branch on the value.
	// Upstream writes `(z0 == 0) | (z1 == M52)` for the same reason.
	return (z0 == 0) | (z1 == M52)
}

/*
Reports whether r represents zero modulo p. Identical in behaviour to
`fe_normalizes_to_zero`, but returns early on the common non-zero case and so is not
constant-time.

Never call this on secret data.
*/
fe_normalizes_to_zero_var :: proc "contextless" (r: ^Field_Elem) -> bool {
	fe_verify(r)

	t0 := r.n[0]
	t4 := r.n[4]

	x := t4 >> 48
	t0 += x * R

	z0 := t0 & M52
	z1 := z0 ~ 0x1000003d0

	// Catches the large majority of inputs without touching the remaining limbs.
	if z0 != 0 && z1 != M52 {
		return false
	}

	t1 := r.n[1]
	t2 := r.n[2]
	t3 := r.n[3]

	t4 &= M48

	t1 += t0 >> 52
	t2 += t1 >> 52; t1 &= M52; z0 |= t1; z1 &= t1
	t3 += t2 >> 52; t2 &= M52; z0 |= t2; z1 &= t2
	t4 += t3 >> 52; t3 &= M52; z0 |= t3; z1 &= t3
	                           z0 |= t4; z1 &= t4 ~ 0xf000000000000

	CHECK(t4 >> 49 == 0, "fe_normalizes_to_zero_var: carry escaped the top limb")

	return z0 == 0 || z1 == M52
}

/*
Converts a boolean to a 0 or 1 mask word, without branching.

The comparisons feeding it are on limb values whose secrecy is the caller's concern; the
conversion itself is branch-free so a constant-time caller stays constant-time.
*/
@(private)
b64 :: #force_inline proc "contextless" (b: bool) -> u64 {
	return u64(b)
}
