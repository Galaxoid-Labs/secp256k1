/*
Exhaustive group tests over a reduced-order curve, mirroring upstream's
`tests_exhaustive.c`.

Under `-define:EXHAUSTIVE_ORDER=7|13|199` the curve is replaced by a small subgroup over
the same field, small enough that *every* group element can be enumerated and *every* pair
checked. That is a categorically stronger statement than random sampling: it reaches the
degenerate cases of the addition formula — P + P, P + (-P), P + infinity, and the
y1 = -y2 with x1 != x2 case the unified formula exists to handle — by construction rather
than by luck.

With the default configuration (the real curve) these tests are inert, because 2^256
elements cannot be enumerated. Run them explicitly:

	odin test tests/group/ -debug -define:EXHAUSTIVE_ORDER=13

This file is the Phase 3 gate from DEVELOPMENT.md.
*/
package test_group

import "core:testing"
import "../../group"
import "../../params"

when params.EXHAUSTIVE_ORDER > 0 {
	/*
	Builds the full group as an array indexed by discrete logarithm: `group_elements[i]`
	is i*G, with index 0 the point at infinity.
	*/
	@(private = "file")
	build_group :: proc() -> [params.EXHAUSTIVE_ORDER]group.Ge {
		elements: [params.EXHAUSTIVE_ORDER]group.Ge

		acc: group.Gej
		group.gej_set_infinity(&acc)
		group.ge_set_infinity(&elements[0])

		for i in 1 ..< params.EXHAUSTIVE_ORDER {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
			copy := acc
			group.ge_set_gej_var(&elements[i], &copy)
		}
		return elements
	}

	@(test)
	test_exhaustive_group_is_closed_and_distinct :: proc(t: ^testing.T) {
		elements := build_group()

		// Every non-identity element must be a distinct, valid curve point in the
		// subgroup.
		for i in 1 ..< params.EXHAUSTIVE_ORDER {
			testing.expectf(t, group.ge_is_valid_var(&elements[i]), "%d*G is not on the curve", i)
			testing.expectf(
				t,
				group.ge_is_in_correct_subgroup(&elements[i]),
				"%d*G is not in the correct subgroup",
				i,
			)
			for j in 1 ..< i {
				testing.expectf(t, !group.ge_eq_var(&elements[i], &elements[j]), "%d*G == %d*G", i, j)
			}
		}

		// Wrapping around must return to infinity.
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for _ in 0 ..< params.EXHAUSTIVE_ORDER {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
		}
		testing.expect(t, group.gej_is_infinity(&acc), "order*G is not infinity")
	}

	/*
	Checks the group law for every ordered pair: i*G + j*G must equal ((i+j) mod order)*G.

	This covers all three addition routines on identical inputs, so any disagreement
	between the constant-time and variable-time formulas surfaces here.
	*/
	@(test)
	test_exhaustive_addition_law :: proc(t: ^testing.T) {
		elements := build_group()
		order :: params.EXHAUSTIVE_ORDER

		for i in 0 ..< order {
			ij: group.Gej
			group.gej_set_ge(&ij, &elements[i])

			for j in 0 ..< order {
				want := elements[(i + j) % order]

				// Variable-time Jacobian + affine.
				r1: group.Gej
				group.gej_add_ge_var(&r1, &ij, &elements[j], nil)
				testing.expectf(
					t,
					group.gej_eq_ge_var(&r1, &want),
					"add_ge_var: %d*G + %d*G != %d*G",
					i,
					j,
					(i + j) % order,
				)

				// Variable-time Jacobian + Jacobian.
				jj: group.Gej
				group.gej_set_ge(&jj, &elements[j])
				r2: group.Gej
				group.gej_add_var(&r2, &ij, &jj, nil)
				testing.expectf(
					t,
					group.gej_eq_ge_var(&r2, &want),
					"add_var: %d*G + %d*G != %d*G",
					i,
					j,
					(i + j) % order,
				)

				// Constant-time addition. It requires a non-infinite affine operand, so
				// the j = 0 case is excluded — that is the documented contract, not a
				// gap in coverage, since infinity never appears in a table.
				if j != 0 {
					r3: group.Gej
					group.gej_add_ge(&r3, &ij, &elements[j])
					testing.expectf(
						t,
						group.gej_eq_ge_var(&r3, &want),
						"add_ge (constant-time): %d*G + %d*G != %d*G",
						i,
						j,
						(i + j) % order,
					)
				}
			}
		}
	}

	/*
	Checks doubling for every element: 2*(i*G) must equal ((2i) mod order)*G.
	*/
	@(test)
	test_exhaustive_doubling :: proc(t: ^testing.T) {
		elements := build_group()
		order :: params.EXHAUSTIVE_ORDER

		for i in 0 ..< order {
			ij: group.Gej
			group.gej_set_ge(&ij, &elements[i])

			dbl: group.Gej
			group.gej_double_var(&dbl, &ij, nil)
			want := elements[(2 * i) % order]
			testing.expectf(
				t,
				group.gej_eq_ge_var(&dbl, &want),
				"double: 2*(%d*G) != %d*G",
				i,
				(2 * i) % order,
			)

			// The unified constant-time formula must reach the same answer, which is the
			// doubling branch of its degenerate-case handling.
			if i != 0 {
				ct: group.Gej
				group.gej_add_ge(&ct, &ij, &elements[i])
				testing.expectf(
					t,
					group.gej_eq_ge_var(&ct, &want),
					"add_ge doubling: 2*(%d*G) != %d*G",
					i,
					(2 * i) % order,
				)
			}
		}
	}

	/*
	Checks negation for every element: -(i*G) must equal ((order-i) mod order)*G, and the
	two must sum to infinity.
	*/
	@(test)
	test_exhaustive_negation :: proc(t: ^testing.T) {
		elements := build_group()
		order :: params.EXHAUSTIVE_ORDER

		for i in 0 ..< order {
			neg: group.Ge
			group.ge_neg(&neg, &elements[i])

			want := elements[(order - i) % order]
			testing.expectf(t, group.ge_eq_var(&neg, &want), "-(%d*G) != %d*G", i, (order - i) % order)

			// The sum must be infinity, through both formulas.
			ij: group.Gej
			group.gej_set_ge(&ij, &elements[i])
			sum: group.Gej
			group.gej_add_ge_var(&sum, &ij, &neg, nil)
			testing.expectf(t, group.gej_is_infinity(&sum), "%d*G + -(%d*G) != infinity", i, i)

			if i != 0 {
				ctsum: group.Gej
				group.gej_add_ge(&ctsum, &ij, &neg)
				testing.expectf(
					t,
					group.gej_is_infinity(&ctsum),
					"constant-time %d*G + -(%d*G) != infinity",
					i,
					i,
				)
			}
		}
	}

	/*
	Checks that the endomorphism acts on the whole group as multiplication by lambda.

	The exhaustive curves are chosen to admit the endomorphism, so lambda*(x,y) must be
	(beta*x, y) for every element, and must land back inside the subgroup.
	*/
	@(test)
	test_exhaustive_endomorphism :: proc(t: ^testing.T) {
		elements := build_group()
		order :: params.EXHAUSTIVE_ORDER

		// Find the discrete log of lambda by locating where the endomorphism sends G.
		lam_g: group.Ge
		group.ge_mul_lambda(&lam_g, &elements[1])

		lambda_index := -1
		for i in 1 ..< order {
			if group.ge_eq_var(&lam_g, &elements[i]) {
				lambda_index = i
				break
			}
		}
		testing.expect(t, lambda_index > 0, "the endomorphism did not map G into the subgroup")
		if lambda_index <= 0 {
			return
		}

		// Applying it to i*G must give (i*lambda mod order)*G, for every i.
		for i in 1 ..< order {
			img: group.Ge
			group.ge_mul_lambda(&img, &elements[i])
			want := elements[(i * lambda_index) % order]
			testing.expectf(
				t,
				group.ge_eq_var(&img, &want),
				"lambda*(%d*G) != %d*G",
				i,
				(i * lambda_index) % order,
			)
		}

		// lambda^3 = 1, so applying it three times is the identity.
		testing.expectf(
			t,
			(lambda_index * lambda_index * lambda_index) % order == 1,
			"lambda^3 != 1 in the subgroup (lambda index %d)",
			lambda_index,
		)
	}
}
