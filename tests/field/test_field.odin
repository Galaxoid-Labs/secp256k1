/*
Field tests, mirroring upstream's `tests.c` function by function.

Each test is named for the upstream `run_*` it mirrors, so a failure here points directly
at the upstream test that covers the same ground. These are tier 2 in `TESTING.md`: they
complement, and do not replace, linking the real `tests.c` in Phase 9.

Run with `-debug` to activate the magnitude and normalization invariant layer; several of
these tests assert on magnitudes directly and only do so when `VERIFY` is set.
*/
package test_field

import "core:testing"
import "../../field"
import "../../params"
import "../../testutil"






@(test)
test_run_field_convert :: proc(t: ^testing.T) {
	b32 := [32]u8 {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40,
	}
	fes := field.Field_Storage {
		n = {
			0x3334353637383940,
			0x2223242526272829,
			0x1112131415161718,
			0x0001020304050607,
		},
	}
	fe := field.fe_const(
		0x00010203, 0x04050607, 0x11121314, 0x15161718,
		0x22232425, 0x26272829, 0x33343536, 0x37383940,
	)

	// Conversions to a field element.
	fe2: field.Field_Elem
	testing.expect(t, field.fe_set_b32_limit(&fe2, &b32), "set_b32_limit rejected an in-range value")
	testing.expect(t, field.fe_equal(&fe, &fe2), "set_b32_limit produced the wrong value")

	field.fe_from_storage(&fe2, &fes)
	testing.expect(t, field.fe_equal(&fe, &fe2), "from_storage produced the wrong value")

	// Conversions from a field element.
	b322: [32]u8
	field.fe_get_b32(&b322, &fe)
	testing.expect_value(t, b322, b32)

	fes2: field.Field_Storage
	field.fe_to_storage(&fes2, &fe)
	testing.expect_value(t, fes2, fes)
}

@(test)
test_run_field_be32_overflow :: proc(t: ^testing.T) {
	{
		// p itself must be rejected by set_b32_limit and reduce to zero under set_b32_mod.
		zero_overflow := [32]u8 {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
		}
		zero: [32]u8

		fe: field.Field_Elem
		testing.expect(t, !field.fe_set_b32_limit(&fe, &zero_overflow), "p was accepted by set_b32_limit")

		field.fe_set_b32_mod(&fe, &zero_overflow)
		testing.expect(t, field.fe_normalizes_to_zero(&fe), "p did not reduce to zero")

		field.fe_normalize(&fe)
		testing.expect(t, field.fe_is_zero(&fe), "normalized p is not zero")

		out: [32]u8
		field.fe_get_b32(&out, &fe)
		testing.expect_value(t, out, zero)
	}
	{
		// p+1 must reduce to 1.
		one_overflow := [32]u8 {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
		}
		one := [32]u8 {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		}

		fe: field.Field_Elem
		testing.expect(t, !field.fe_set_b32_limit(&fe, &one_overflow), "p+1 was accepted by set_b32_limit")

		field.fe_set_b32_mod(&fe, &one_overflow)
		field.fe_normalize(&fe)
		testing.expect_value(t, field.fe_cmp_var(&fe, &field.ONE), 0)

		out: [32]u8
		field.fe_get_b32(&out, &fe)
		testing.expect_value(t, out, one)
	}
	{
		// 2^256-1 must reduce to 2^32+976 = 0x1000003d0.
		ff_overflow := [32]u8 {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		}
		ff := [32]u8 {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0xd0,
		}

		fe: field.Field_Elem
		ff_expected := field.fe_const(0, 0, 0, 0, 0, 0, 0x01, 0x000003d0)

		testing.expect(t, !field.fe_set_b32_limit(&fe, &ff_overflow), "2^256-1 was accepted by set_b32_limit")

		field.fe_set_b32_mod(&fe, &ff_overflow)
		field.fe_normalize(&fe)
		testing.expect_value(t, field.fe_cmp_var(&fe, &ff_expected), 0)

		out: [32]u8
		field.fe_get_b32(&out, &fe)
		testing.expect_value(t, out, ff)
	}
}

@(test)
test_run_field_half :: proc(t: ^testing.T) {
	// Magnitude 0 input.
	tv: field.Field_Elem
	field.fe_get_bounds(&tv, 0)
	field.fe_half(&tv)
	when field.VERIFY {
		testing.expect_value(t, tv.magnitude, 1)
		testing.expect(t, !tv.normalized, "half of zero should not be marked normalized")
	}
	testing.expect(t, field.fe_normalizes_to_zero(&tv), "half of zero is not zero")

	for m in 1 ..< 32 {
		// Maximum-value input for this magnitude.
		field.fe_get_bounds(&tv, m)

		u := tv
		field.fe_half(&u)
		when field.VERIFY {
			testing.expect_value(t, u.magnitude, (m >> 1) + 1)
			testing.expect(t, !u.normalized, "half should clear the normalized flag")
		}
		field.fe_normalize_weak(&u)
		field.fe_add(&u, &u)
		testing.expectf(t, equal_normalized(&tv, &u), "half then double changed the value at magnitude %d", m)

		// Worst case: force the low bit to 1 so that p is added, which makes every carry
		// 1 as well, since the limbs that can carry are all even here and every limb of p
		// is odd.
		field.fe_get_bounds(&tv, m)
		testing.expect(t, tv.n[0] > 0, "bounds limb 0 should be positive")
		testing.expect(t, tv.n[0] & 1 == 0, "bounds limb 0 should be even")
		tv.n[0] -= 1

		u = tv
		field.fe_half(&u)
		when field.VERIFY {
			testing.expect_value(t, u.magnitude, (m >> 1) + 1)
			testing.expect(t, !u.normalized, "half should clear the normalized flag")
		}
		field.fe_normalize_weak(&u)
		field.fe_add(&u, &u)
		testing.expectf(
			t,
			equal_normalized(&tv, &u),
			"half then double changed the odd worst-case value at magnitude %d",
			m,
		)
	}
}

@(test)
test_run_field_misc :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	fe5 := field.fe_const(0, 0, 0, 0, 0, 0, 0, 5)

	for i in 0 ..< params.COUNT * 4 {
		x := random_fe(&rng)
		y := random_fe_non_zero(&rng)

		z := x
		field.fe_add(&z, &y)
		field.fe_normalize(&z)

		q := x
		// x + y - y == x
		neg_y: field.Field_Elem
		field.fe_negate(&neg_y, &y, 1)
		field.fe_add(&q, &y)
		field.fe_add(&q, &neg_y)
		testing.expectf(t, equal_normalized(&q, &x), "add then subtract changed the value (iteration %d)", i)

		// Conditional move leaves the target alone when the flag is false, and replaces
		// it when true.
		a := x
		field.fe_cmov(&a, &y, false)
		testing.expect(t, identical(&a, &x), "cmov(false) modified the target")
		field.fe_cmov(&a, &y, true)
		testing.expect(t, identical(&a, &y), "cmov(true) did not replace the target")

		// Storage round-trip preserves the value.
		xn := x
		field.fe_normalize(&xn)
		s: field.Field_Storage
		field.fe_to_storage(&s, &xn)
		back: field.Field_Elem
		field.fe_from_storage(&back, &s)
		testing.expectf(t, identical(&back, &xn), "storage round-trip changed the value (iteration %d)", i)

		// Storage conditional move behaves like the field-element one.
		yn := y
		field.fe_normalize(&yn)
		sy: field.Field_Storage
		field.fe_to_storage(&sy, &yn)
		sa := s
		field.fe_storage_cmov(&sa, &sy, false)
		testing.expect_value(t, sa, s)
		field.fe_storage_cmov(&sa, &sy, true)
		testing.expect_value(t, sa, sy)

		// Multiplying by the small integer 5 agrees with multiplying by the field
		// element 5.
		m := x
		field.fe_mul_int(&m, 5)
		byfe: field.Field_Elem
		xc := x
		field.fe_mul(&byfe, &xc, &fe5)
		testing.expectf(t, equal_normalized(&m, &byfe), "mul_int(5) disagrees with mul by 5 (iteration %d)", i)

		// Adding a small integer agrees with adding the corresponding field element.
		ai := x
		field.fe_add_int(&ai, 5)
		af := x
		field.fe_add(&af, &fe5)
		testing.expectf(t, equal_normalized(&ai, &af), "add_int(5) disagrees with add of 5 (iteration %d)", i)

		// Negation is an involution.
		n1: field.Field_Elem
		n2: field.Field_Elem
		field.fe_negate(&n1, &x, 1)
		field.fe_negate(&n2, &n1, 2)
		testing.expectf(t, equal_normalized(&n2, &x), "double negation changed the value (iteration %d)", i)
	}
}

@(test)
test_run_fe_mul :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	// Multiplication is commutative, associative, and distributes over addition. These
	// hold for any correct implementation, which is what makes them useful against a
	// hand-derived reduction.
	for i in 0 ..< params.COUNT * 4 {
		a := random_fe(&rng)
		b := random_fe(&rng)
		c := random_fe(&rng)

		ab: field.Field_Elem
		ba: field.Field_Elem
		a1, b1 := a, b
		field.fe_mul(&ab, &a1, &b)
		field.fe_mul(&ba, &b1, &a)
		testing.expectf(t, equal_normalized(&ab, &ba), "multiplication is not commutative (iteration %d)", i)

		// (a*b)*c == a*(b*c)
		lhs := ab
		field.fe_normalize_weak(&lhs)
		l: field.Field_Elem
		field.fe_mul(&l, &lhs, &c)

		bc: field.Field_Elem
		b2 := b
		field.fe_mul(&bc, &b2, &c)
		field.fe_normalize_weak(&bc)
		r: field.Field_Elem
		a2 := a
		field.fe_mul(&r, &a2, &bc)
		testing.expectf(t, equal_normalized(&l, &r), "multiplication is not associative (iteration %d)", i)

		// a*(b+c) == a*b + a*c
		bpc := b
		field.fe_add(&bpc, &c)
		field.fe_normalize_weak(&bpc)
		dl: field.Field_Elem
		a3 := a
		field.fe_mul(&dl, &a3, &bpc)

		ac: field.Field_Elem
		a4 := a
		field.fe_mul(&ac, &a4, &c)
		dr := ab
		field.fe_add(&dr, &ac)
		testing.expectf(t, equal_normalized(&dl, &dr), "multiplication does not distribute (iteration %d)", i)
	}

	// Multiplying by one is the identity; multiplying by zero annihilates.
	zero: field.Field_Elem
	field.fe_set_int(&zero, 0)
	for i in 0 ..< params.COUNT {
		a := random_fe(&rng)

		byone: field.Field_Elem
		a1 := a
		field.fe_mul(&byone, &a1, &field.ONE)
		testing.expectf(t, equal_normalized(&byone, &a), "multiplication by one changed the value (iteration %d)", i)

		byzero: field.Field_Elem
		a2 := a
		field.fe_mul(&byzero, &a2, &zero)
		testing.expectf(t, field.fe_normalizes_to_zero(&byzero), "multiplication by zero is non-zero (iteration %d)", i)
	}
}

@(test)
test_run_sqr :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	// Squaring must agree with multiplying a value by itself. The two kernels share a
	// structure but differ in how the symmetric cross terms are doubled, so this
	// catches a mistake in that doubling.
	for i in 0 ..< params.COUNT * 4 {
		a := random_fe(&rng)

		s: field.Field_Elem
		a1 := a
		field.fe_sqr(&s, &a1)

		m: field.Field_Elem
		a2, a3 := a, a
		field.fe_mul(&m, &a2, &a3)

		testing.expectf(t, equal_normalized(&s, &m), "sqr disagrees with mul by self (iteration %d)", i)
	}

	// (-a)^2 == a^2
	for i in 0 ..< params.COUNT {
		a := random_fe(&rng)

		sa: field.Field_Elem
		a1 := a
		field.fe_sqr(&sa, &a1)

		na: field.Field_Elem
		field.fe_negate(&na, &a, 1)
		field.fe_normalize_weak(&na)
		sna: field.Field_Elem
		field.fe_sqr(&sna, &na)

		testing.expectf(t, equal_normalized(&sa, &sna), "squaring is not sign-invariant (iteration %d)", i)
	}
}

/*
Exercises normalization against representations chosen to sit exactly on the reduction
boundary, where an off-by-one in the final conditional subtraction shows up.

This has no single upstream counterpart; it covers the boundary conditions that
`run_field_misc` reaches only by chance.
*/
@(test)
test_field_normalize_boundaries :: proc(t: ^testing.T) {
	// p, p+1, and 2^256-1 in limb form, built through set_b32_mod so the test does not
	// depend on the constructor under test.
	cases := [][32]u8 {
		// p
		{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
		},
		// p - 1
		{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
		},
		// zero
		{},
		// one
		{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		},
	}

	for c, i in cases {
		b := c

		// The constant-time and variable-time normalizations must agree exactly, limb
		// for limb, not merely in value.
		ct: field.Field_Elem
		field.fe_set_b32_mod(&ct, &b)
		field.fe_normalize(&ct)

		vt: field.Field_Elem
		field.fe_set_b32_mod(&vt, &b)
		field.fe_normalize_var(&vt)

		testing.expectf(
			t,
			identical(&ct, &vt),
			"normalize and normalize_var disagree on case %d",
			i,
		)

		// The zero tests must agree with each other and with the normalized result.
		z: field.Field_Elem
		field.fe_set_b32_mod(&z, &b)
		zct := field.fe_normalizes_to_zero(&z)
		zvt := field.fe_normalizes_to_zero_var(&z)
		testing.expectf(t, zct == zvt, "normalizes_to_zero and _var disagree on case %d", i)
		testing.expectf(t, zct == field.fe_is_zero(&ct), "normalizes_to_zero disagrees with is_zero on case %d", i)

		// Normalizing an already-normalized value is idempotent.
		again := ct
		field.fe_normalize(&again)
		testing.expectf(t, identical(&again, &ct), "normalize is not idempotent on case %d", i)
	}
}

/*
Checks normalization against randomly generated values at every supported magnitude,
including the maximum-magnitude representations that `field.fe_get_bounds` produces.
*/
@(test)
test_field_normalize_magnitudes :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	for m in 0 ..= 31 {
		// The extreme representation for this magnitude.
		bounds: field.Field_Elem
		field.fe_get_bounds(&bounds, m)

		ct := bounds
		field.fe_normalize(&ct)
		vt := bounds
		field.fe_normalize_var(&vt)
		testing.expectf(t, identical(&ct, &vt), "normalize disagreement at bounds magnitude %d", m)

		// Weak normalization must preserve the value while capping the magnitude.
		wk := bounds
		field.fe_normalize_weak(&wk)
		when field.VERIFY {
			testing.expect_value(t, wk.magnitude, 1)
		}
		full := wk
		field.fe_normalize(&full)
		testing.expectf(t, identical(&full, &ct), "normalize_weak lost value at magnitude %d", m)

		if m == 0 {
			continue
		}

		// Random values scaled up to this magnitude.
		for _ in 0 ..< params.COUNT {
			x := random_fe(&rng)
			if m > 1 {
				field.fe_mul_int(&x, u32(m))
			}

			a := x
			field.fe_normalize(&a)
			b := x
			field.fe_normalize_var(&b)
			testing.expectf(t, identical(&a, &b), "normalize disagreement at magnitude %d", m)

			// A normalized value round-trips through bytes unchanged.
			buf: [32]u8
			field.fe_get_b32(&buf, &a)
			c: field.Field_Elem
			testing.expect(t, field.fe_set_b32_limit(&c, &buf), "normalized value failed set_b32_limit")
			testing.expectf(t, identical(&c, &a), "byte round-trip changed the value at magnitude %d", m)
		}
	}
}
