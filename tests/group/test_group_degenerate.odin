/*
Tests for the degenerate branch of the constant-time addition formula.

`gej_add_ge` uses a unified add/double formula whose lambda = (y1+y2) denominator vanishes
when y1 = -y2. Usually that means the points are negations of each other and the answer is
infinity — but on this curve it can also happen with x1 != x2, because 1 has nontrivial
cube roots in the field and the curve equation has no x term. In that case the answer is a
perfectly ordinary point, and the formula must switch to lambda = (y1-y2)/(x1-x2), which it
does by conditional move.

That branch is unreachable by random sampling and does not arise in the exhaustive
subgroup walk either, so it went untested until a mutation — replacing the branch's
conditional move with a constant `false` — passed the entire suite unnoticed. These tests
construct the case directly.

# Constructing it

Given P = (x, y) on y^2 = x^3 + b, let Q = (beta*x, -y) where beta is the field's cube root
of unity. Then

	(beta*x)^3 + b = beta^3 * x^3 + b = x^3 + b = y^2 = (-y)^2

so Q is on the curve, has y_Q = -y_P, and x_Q = beta*x_P which differs from x_P whenever
x_P != 0. That is exactly the degenerate case.
*/
package test_group

import "core:testing"
import "../../field"
import "../../group"
import "../../params"
import "../../testutil"

/*
Returns the degenerate partner of a: the point (beta*x, -y).

It has the same y-negation relationship as -a but a different x coordinate.
*/
@(private = "file")
degenerate_partner :: proc(a: ^group.Ge) -> group.Ge {
	q: group.Ge
	q.infinity = false
	field.fe_mul(&q.x, &a.x, &field.BETA)
	q.y = a.y
	field.fe_normalize_weak(&q.y)
	field.fe_negate(&q.y, &q.y, 1)
	return q
}

@(test)
test_add_ge_degenerate_case :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 100)

	exercised := 0

	for i in 0 ..< params.COUNT {
		p := random_ge(&rng)

		px := p.x
		field.fe_normalize_var(&px)
		if field.fe_is_zero(&px) {
			continue
		}

		q := degenerate_partner(&p)

		// Confirm the construction really is degenerate: q is on the curve, its y is the
		// negation of p's, and its x differs.
		testing.expectf(t, group.ge_is_valid_var(&q), "the constructed partner is off-curve (%d)", i)

		py := p.y
		qy := q.y
		field.fe_normalize_var(&py)
		field.fe_normalize_var(&qy)
		negpy: field.Field_Elem
		field.fe_negate(&negpy, &py, 1)
		field.fe_normalize_var(&negpy)
		testing.expectf(t, qy.n == negpy.n, "partner's y is not -y (%d)", i)

		qx := q.x
		field.fe_normalize_var(&qx)
		if qx.n == px.n {
			// beta*x == x only if x == 0, already excluded; skip defensively.
			continue
		}
		exercised += 1

		// The two formulas must agree. This is the assertion the surviving mutation
		// violated.
		pj: group.Gej
		group.gej_set_ge(&pj, &p)

		want: group.Gej
		group.gej_add_ge_var(&want, &pj, &q, nil)

		got: group.Gej
		group.gej_add_ge(&got, &pj, &q)

		testing.expectf(
			t,
			group.gej_eq_var(&got, &want),
			"constant-time addition disagrees in the degenerate case (%d)",
			i,
		)

		// The result must be a real point, not infinity: that is what distinguishes this
		// from the p + (-p) case.
		testing.expectf(
			t,
			!group.gej_is_infinity(&got),
			"the degenerate case wrongly produced infinity (%d)",
			i,
		)

		// And it must be on the curve.
		affine: group.Ge
		copy := got
		group.ge_set_gej_var(&affine, &copy)
		testing.expectf(t, group.ge_is_valid_var(&affine), "degenerate sum is off-curve (%d)", i)

		// Cross-check against the third formula as well.
		qj: group.Gej
		group.gej_set_ge(&qj, &q)
		via_jj: group.Gej
		group.gej_add_var(&via_jj, &pj, &qj, nil)
		testing.expectf(t, group.gej_eq_var(&via_jj, &want), "add_var disagrees in the degenerate case (%d)", i)
	}

	testing.expect(t, exercised > 0, "the degenerate case was never constructed; this test is inert")
}

/*
Checks the other branch of the same conditional move: the genuinely-opposite case, where
the answer *is* infinity.

Both branches share the conditional move, so testing only one leaves the selector itself
unverified.
*/
@(test)
test_add_ge_opposite_points :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 101)

	for i in 0 ..< params.COUNT {
		p := random_ge(&rng)
		neg: group.Ge
		group.ge_neg(&neg, &p)

		pj: group.Gej
		group.gej_set_ge(&pj, &p)

		got: group.Gej
		group.gej_add_ge(&got, &pj, &neg)
		testing.expectf(t, group.gej_is_infinity(&got), "P + (-P) is not infinity (%d)", i)

		// With a rescaled projective representation the same must hold, since the
		// infinity test is on Z3 and Z is scaled.
		z := random_fe_non_zero(&rng)
		scaled := pj
		group.gej_rescale(&scaled, &z)
		got2: group.Gej
		group.gej_add_ge(&got2, &scaled, &neg)
		testing.expectf(t, group.gej_is_infinity(&got2), "rescaled P + (-P) is not infinity (%d)", i)
	}
}
