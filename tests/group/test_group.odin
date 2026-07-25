/*
Group tests, mirroring upstream's `run_ge`, `run_gej`, `run_group_decompress` and
`run_ec_combine`.

The most valuable tests here are the ones that pit the constant-time addition against the
variable-time one on the same inputs, especially in the degenerate cases the unified
formula exists to handle: adding a point to itself, to its negation, and to infinity.
Those paths are unreachable by random sampling and are exactly where a unified formula goes
wrong.
*/
package test_group

import "core:testing"
import "../../field"
import "../../group"
import "../../params"
import "../../testutil"

/*
Confirms the configured generator actually lies on the configured curve.

This is the check that catches a mistyped or fabricated curve constant. It applies to
whichever curve `EXHAUSTIVE_ORDER` selects, so running the suite at each supported order
validates all four generators.
*/
@(test)
test_generator_is_on_curve :: proc(t: ^testing.T) {
	g := group.GENERATOR
	testing.expect(t, !group.ge_is_infinity(&g), "the generator is infinity")
	testing.expect(t, group.ge_is_valid_var(&g), "the generator is not on the curve")

	// Its x coordinate must also pass the standalone x-only curve test.
	testing.expect(t, group.ge_x_on_curve_var(&g.x), "the generator's x is not on the curve")

	// And the Jacobian copy must agree.
	gj := group.GENERATOR_J
	testing.expect(t, group.gej_eq_ge_var(&gj, &g), "GENERATOR_J disagrees with GENERATOR")
}

/*
Confirms the generator has the configured order: order*G must be infinity, and no smaller
multiple may be.

On the real curve the order is n and only the first half is checked (multiplying out to n
would need `ecmult`), so this runs the full check only for the exhaustive curves, where the
order is small enough to walk.
*/
@(test)
test_generator_has_expected_order :: proc(t: ^testing.T) {
	when params.EXHAUSTIVE_ORDER > 0 {
		acc: group.Gej
		group.gej_set_infinity(&acc)

		for i in 1 ..= params.EXHAUSTIVE_ORDER {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
			is_inf := group.gej_is_infinity(&acc)
			if i < params.EXHAUSTIVE_ORDER {
				testing.expectf(t, !is_inf, "%d*G is infinity before reaching the order", i)
			} else {
				testing.expectf(t, is_inf, "order*G is not infinity (order = %d)", i)
			}
		}
	} else {
		// On the real curve, just confirm small multiples stay finite and distinct.
		acc: group.Gej
		group.gej_set_infinity(&acc)
		seen: [16]group.Gej
		for i in 0 ..< 16 {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
			testing.expectf(t, !group.gej_is_infinity(&acc), "%d*G is unexpectedly infinity", i + 1)
			seen[i] = acc
			for j in 0 ..< i {
				testing.expectf(t, !group.gej_eq_var(&seen[j], &acc), "%d*G equals %d*G", i + 1, j + 1)
			}
		}
	}
}

@(test)
test_run_ge :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for i in 0 ..< params.COUNT * 2 {
		a := random_ge(&rng)

		// Random points must be on the curve.
		testing.expectf(t, group.ge_is_valid_var(&a), "random point is not on the curve (%d)", i)

		// Negation is an involution and produces a valid point.
		neg, negneg: group.Ge
		group.ge_neg(&neg, &a)
		testing.expectf(t, group.ge_is_valid_var(&neg), "-P is not on the curve (%d)", i)
		group.ge_neg(&negneg, &neg)
		testing.expectf(t, group.ge_eq_var(&negneg, &a), "-(-P) != P (%d)", i)

		// P + (-P) == infinity.
		aj: group.Gej
		group.gej_set_ge(&aj, &a)
		sum: group.Gej
		group.gej_add_ge_var(&sum, &aj, &neg, nil)
		testing.expectf(t, group.gej_is_infinity(&sum), "P + (-P) != infinity (%d)", i)

		// Storage round-trip.
		s: group.Ge_Storage
		group.ge_to_storage(&s, &a)
		back: group.Ge
		group.ge_from_storage(&back, &s)
		testing.expectf(t, group.ge_eq_var(&back, &a), "storage round-trip changed the point (%d)", i)

		// Storage conditional move.
		b := random_ge(&rng)
		sb: group.Ge_Storage
		group.ge_to_storage(&sb, &b)
		sm := s
		group.ge_storage_cmov(&sm, &sb, false)
		testing.expect_value(t, sm, s)
		group.ge_storage_cmov(&sm, &sb, true)
		testing.expect_value(t, sm, sb)

		// The endomorphism maps curve points to curve points, and lambda^3 = 1 means
		// applying it three times is the identity.
		l1, l2, l3: group.Ge
		group.ge_mul_lambda(&l1, &a)
		testing.expectf(t, group.ge_is_valid_var(&l1), "lambda*P is not on the curve (%d)", i)
		group.ge_mul_lambda(&l2, &l1)
		group.ge_mul_lambda(&l3, &l2)
		testing.expectf(t, group.ge_eq_var(&l3, &a), "lambda^3*P != P (%d)", i)
	}

	// Infinity behaves as the identity.
	inf: group.Ge
	group.ge_set_infinity(&inf)
	testing.expect(t, group.ge_is_infinity(&inf), "set_infinity did not set the flag")
	testing.expect(t, !group.ge_is_valid_var(&inf), "infinity was reported as a valid curve point")
}

@(test)
test_run_gej :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	for i in 0 ..< params.COUNT * 2 {
		aj := random_gej(&rng)
		bj := random_gej(&rng)

		a, b: group.Ge
		acopy, bcopy := aj, bj
		group.ge_set_gej_var(&a, &acopy)
		group.ge_set_gej_var(&b, &bcopy)

		// Addition is commutative.
		ab, ba: group.Gej
		group.gej_add_var(&ab, &aj, &bj, nil)
		group.gej_add_var(&ba, &bj, &aj, nil)
		testing.expectf(t, group.gej_eq_var(&ab, &ba), "addition is not commutative (%d)", i)

		// Adding an affine point agrees with adding its Jacobian form.
		abge: group.Gej
		group.gej_add_ge_var(&abge, &aj, &b, nil)
		testing.expectf(t, group.gej_eq_var(&abge, &ab), "add_ge_var disagrees with add_var (%d)", i)

		// The constant-time addition agrees with the variable-time one.
		abct: group.Gej
		group.gej_add_ge(&abct, &aj, &b)
		testing.expectf(t, group.gej_eq_var(&abct, &ab), "gej_add_ge disagrees with add_var (%d)", i)

		// Doubling agrees with adding a point to itself.
		dbl, selfsum: group.Gej
		group.gej_double_var(&dbl, &aj, nil)
		group.gej_add_var(&selfsum, &aj, &aj, nil)
		testing.expectf(t, group.gej_eq_var(&dbl, &selfsum), "double disagrees with self-addition (%d)", i)

		// And the constant-time addition handles the doubling case too.
		ctdbl: group.Gej
		group.gej_add_ge(&ctdbl, &aj, &a)
		testing.expectf(t, group.gej_eq_var(&ctdbl, &dbl), "gej_add_ge doubling disagrees (%d)", i)

		// Adding the negation gives infinity, in both formulas.
		nega: group.Ge
		group.ge_neg(&nega, &a)
		vinf, ctinf: group.Gej
		group.gej_add_ge_var(&vinf, &aj, &nega, nil)
		testing.expectf(t, group.gej_is_infinity(&vinf), "P + (-P) != infinity, var (%d)", i)
		group.gej_add_ge(&ctinf, &aj, &nega)
		testing.expectf(t, group.gej_is_infinity(&ctinf), "P + (-P) != infinity, constant-time (%d)", i)

		// Infinity is the additive identity, for both formulas.
		infj: group.Gej
		group.gej_set_infinity(&infj)
		r1: group.Gej
		group.gej_add_var(&r1, &infj, &aj, nil)
		testing.expectf(t, group.gej_eq_var(&r1, &aj), "infinity + P != P (%d)", i)

		r2: group.Gej
		group.gej_add_ge(&r2, &infj, &a)
		testing.expectf(t, group.gej_eq_var(&r2, &aj), "infinity + P != P, constant-time (%d)", i)

		r3: group.Gej
		inf_ge: group.Ge
		group.ge_set_infinity(&inf_ge)
		group.gej_add_ge_var(&r3, &aj, &inf_ge, nil)
		testing.expectf(t, group.gej_eq_var(&r3, &aj), "P + infinity != P (%d)", i)

		// Rescaling the projective representation does not change the point.
		z := random_fe_non_zero(&rng)
		scaled := aj
		group.gej_rescale(&scaled, &z)
		testing.expectf(t, group.gej_eq_var(&scaled, &aj), "rescale changed the point (%d)", i)
		testing.expectf(t, group.gej_eq_ge_var(&scaled, &a), "rescaled point != affine form (%d)", i)

		// The x-only comparison agrees with the full one.
		testing.expectf(t, group.gej_eq_x_var(&a.x, &aj), "gej_eq_x_var rejected the true x (%d)", i)

		// Negation in Jacobian coordinates matches negation in affine.
		njj: group.Gej
		group.gej_neg(&njj, &aj)
		testing.expectf(t, group.gej_eq_ge_var(&njj, &nega), "gej_neg disagrees with ge_neg (%d)", i)

		// Conditional move.
		m := aj
		group.gej_cmov(&m, &bj, false)
		testing.expectf(t, group.gej_eq_var(&m, &aj), "gej_cmov(false) modified the target (%d)", i)
		group.gej_cmov(&m, &bj, true)
		testing.expectf(t, group.gej_eq_var(&m, &bj), "gej_cmov(true) did not replace the target (%d)", i)
	}
}

/*
Returns the affine point at infinity.
*/
@(private = "file")
group_infinity_ge :: proc() -> group.Ge {
	r: group.Ge
	group.ge_set_infinity(&r)
	return r
}

@(test)
test_run_group_decompress :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	on_curve := 0
	off_curve := 0

	for i in 0 ..< params.COUNT * 4 {
		x := random_fe(&rng)

		even, odd: group.Ge
		ok_even := group.ge_set_xo_var(&even, &x, false)
		ok_odd := group.ge_set_xo_var(&odd, &x, true)

		// Both parities must agree on whether the x coordinate is usable, and that must
		// match the standalone predicate.
		testing.expectf(t, ok_even == ok_odd, "parity changed decompressibility (%d)", i)
		testing.expectf(
			t,
			ok_even == group.ge_x_on_curve_var(&x),
			"set_xo_var disagrees with x_on_curve_var (%d)",
			i,
		)

		if !ok_even {
			off_curve += 1
			continue
		}
		on_curve += 1

		// Both results must be on the curve, have the requested parity, and be negations
		// of each other.
		testing.expectf(t, group.ge_is_valid_var(&even), "even decompression is off-curve (%d)", i)
		testing.expectf(t, group.ge_is_valid_var(&odd), "odd decompression is off-curve (%d)", i)

		ey := even.y
		oy := odd.y
		field.fe_normalize_var(&ey)
		field.fe_normalize_var(&oy)
		testing.expectf(t, !field.fe_is_odd(&ey), "even decompression has odd y (%d)", i)
		testing.expectf(t, field.fe_is_odd(&oy), "odd decompression has even y (%d)", i)

		negodd: group.Ge
		group.ge_neg(&negodd, &odd)
		testing.expectf(t, group.ge_eq_var(&negodd, &even), "the two parities are not negations (%d)", i)
	}

	// Roughly half of all x values lie on the curve. Seeing none of either kind would
	// mean the test is not exercising both branches.
	testing.expect(t, on_curve > 0, "no x coordinate decompressed successfully")
	testing.expect(t, off_curve > 0, "every x coordinate decompressed; the failure path is untested")
}

@(test)
test_run_ec_combine :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	// Summing points one at a time must match summing them in any other grouping.
	for round in 0 ..< params.COUNT {
		points: [6]group.Ge
		for i in 0 ..< len(points) {
			points[i] = random_ge(&rng)
		}

		// Left-to-right.
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for i in 0 ..< len(points) {
			group.gej_add_ge_var(&acc, &acc, &points[i], nil)
		}

		// Right-to-left.
		acc2: group.Gej
		group.gej_set_infinity(&acc2)
		for i := len(points) - 1; i >= 0; i -= 1 {
			group.gej_add_ge_var(&acc2, &acc2, &points[i], nil)
		}
		testing.expectf(t, group.gej_eq_var(&acc, &acc2), "summation order changed the result (%d)", round)

		// Two halves combined.
		h1, h2: group.Gej
		group.gej_set_infinity(&h1)
		group.gej_set_infinity(&h2)
		for i in 0 ..< 3 {
			group.gej_add_ge_var(&h1, &h1, &points[i], nil)
		}
		for i in 3 ..< 6 {
			group.gej_add_ge_var(&h2, &h2, &points[i], nil)
		}
		combined: group.Gej
		group.gej_add_var(&combined, &h1, &h2, nil)
		testing.expectf(t, group.gej_eq_var(&combined, &acc), "split summation disagrees (%d)", round)
	}
}

@(test)
test_ge_set_all_gej :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	N :: 8
	points: [N]group.Gej
	for i in 0 ..< N {
		points[i] = random_gej(&rng)
	}

	// The batched conversion must agree with converting each point individually.
	batched: [N]group.Ge
	group.ge_set_all_gej(batched[:], points[:])

	for i in 0 ..< N {
		one: group.Ge
		copy := points[i]
		group.ge_set_gej_var(&one, &copy)
		testing.expectf(t, group.ge_eq_var(&batched[i], &one), "batched conversion differs at %d", i)
	}

	// The variable-time version must handle infinities mixed in.
	with_inf: [N]group.Gej
	for i in 0 ..< N {
		with_inf[i] = points[i]
	}
	group.gej_set_infinity(&with_inf[2])
	group.gej_set_infinity(&with_inf[5])

	batched_var: [N]group.Ge
	group.ge_set_all_gej_var(batched_var[:], with_inf[:])

	for i in 0 ..< N {
		if i == 2 || i == 5 {
			testing.expectf(t, group.ge_is_infinity(&batched_var[i]), "infinity was not preserved at %d", i)
			continue
		}
		one: group.Ge
		copy := points[i]
		group.ge_set_gej_var(&one, &copy)
		testing.expectf(t, group.ge_eq_var(&batched_var[i], &one), "batched var conversion differs at %d", i)
	}
}

@(test)
test_ge_x_frac_on_curve :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 5)

	// xn/xd on the curve must agree with evaluating the quotient directly.
	for i in 0 ..< params.COUNT {
		xd := random_fe_non_zero(&rng)
		xn := random_fe(&rng)

		inv, quotient: field.Field_Elem
		field.fe_inv_var(&inv, &xd)
		field.fe_mul(&quotient, &xn, &inv)

		testing.expectf(
			t,
			group.ge_x_frac_on_curve_var(&xn, &xd) == group.ge_x_on_curve_var(&quotient),
			"fraction and direct curve tests disagree (%d)",
			i,
		)
	}
}
