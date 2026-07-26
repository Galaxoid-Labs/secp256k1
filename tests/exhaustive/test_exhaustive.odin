/*
Exhaustive tests over a small-order curve, mirroring upstream's `tests_exhaustive.c`.

	odin test tests/exhaustive/ -define:EXHAUSTIVE_ORDER=13

# Why this is worth having

Every other test here samples. This one does not: it enumerates *every* scalar in the group
and checks the answer against a definition, so for these curves the multiplication engines
are not "tested" but proved. A wNAF that mishandles one particular digit pattern, a
constant-time ladder that is wrong only when the top bit is set, an endomorphism split that
is off by one at a boundary — none of those need to be guessed at, because every case runs.

The curve is chosen by `-define:EXHAUSTIVE_ORDER`, which swaps the group order for a small
prime (7, 13 or 199) and, through `scalar_low.odin`, the entire scalar representation with
it. That swap is what upstream does and is what makes this possible; with the real order
there is nothing to enumerate.

Nothing here compiles on the real curve — the whole file is gated — so it costs an ordinary
build nothing.
*/
package test_exhaustive

import "core:testing"
import "../../ecmult"
import "../../field"
import "../../group"
import "../../params"
import "../../scalar"

when params.EXHAUSTIVE_ORDER > 0 {

	ORDER :: params.EXHAUSTIVE_ORDER

	/*
	Builds every group element as an affine point, indexed by scalar: `out[i] = i*G`.

	By repeated addition, which is the definition — deliberately not by any of the engines
	under test, or the comparison would be circular.
	*/
	@(private = "file")
	build_group :: proc(out: []group.Ge) {
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for i in 0 ..< ORDER {
			group.ge_set_gej(&out[i], &acc)
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
		}
	}

	@(private = "file")
	ge_eq :: proc(a: ^group.Ge, b: ^group.Ge) -> bool {
		if bool(a.infinity) || bool(b.infinity) {
			return a.infinity == b.infinity
		}
		ax, ay, bx, by := a.x, a.y, b.x, b.y
		field.fe_normalize_var(&ax); field.fe_normalize_var(&ay)
		field.fe_normalize_var(&bx); field.fe_normalize_var(&by)
		return field.fe_equal(&ax, &bx) && field.fe_equal(&ay, &by)
	}

	/*
	The group really is a group: closed, with the right order, and no element repeats.

	Everything below trusts `build_group`, so its output is checked first. A duplicate point
	would mean the configured order is not the true order of the generator, and every later
	comparison would be against a wrong table.
	*/
	@(test)
	test_exhaustive_group_structure :: proc(t: ^testing.T) {
		pts: [ORDER]group.Ge
		build_group(pts[:])

		testing.expect(t, bool(pts[0].infinity), "0*G must be the point at infinity")

		for i in 1 ..< ORDER {
			testing.expectf(t, !bool(pts[i].infinity), "%d*G is infinity before the order", i)
			for j in 1 ..< i {
				testing.expectf(t, !ge_eq(&pts[i], &pts[j]), "%d*G == %d*G: order is wrong", i, j)
			}
		}

		// ORDER*G must close the loop back to infinity.
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for _ in 0 ..< ORDER {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
		}
		testing.expect(t, group.gej_is_infinity(&acc), "ORDER*G is not infinity")
	}

	/*
	`ecmult_gen` is correct for every scalar in the group.

	This is the constant-time generator multiply used by every signing path, checked against
	the additive definition for all ORDER inputs.
	*/
	@(test)
	test_exhaustive_ecmult_gen :: proc(t: ^testing.T) {
		pts: [ORDER]group.Ge
		build_group(pts[:])

		gen: ecmult.Ecmult_Gen_Context
		ecmult.ecmult_gen_context_build(&gen)

		for i in 0 ..< ORDER {
			k: scalar.Scalar
			scalar.scalar_set_int(&k, u32(i))

			rj: group.Gej
			ecmult.ecmult_gen(&gen, &rj, &k)
			r: group.Ge
			group.ge_set_gej(&r, &rj)

			testing.expectf(t, ge_eq(&r, &pts[i]), "ecmult_gen wrong for k=%d", i)
		}
	}

	/*
	`ecmult_const` is correct for every scalar against every base point.

	ORDER^2 multiplications. This is the constant-time ladder ECDH relies on, and the pair
	loop means every combination of scalar digits and input point is covered rather than
	sampled.
	*/
	@(test)
	test_exhaustive_ecmult_const :: proc(t: ^testing.T) {
		pts: [ORDER]group.Ge
		build_group(pts[:])

		for base in 1 ..< ORDER {
			for i in 0 ..< ORDER {
				k: scalar.Scalar
				scalar.scalar_set_int(&k, u32(i))

				rj: group.Gej
				ecmult.ecmult_const(&rj, &pts[base], &k)
				r: group.Ge
				group.ge_set_gej(&r, &rj)

				// (i * base) mod ORDER, by the table.
				want := pts[(i * base) % ORDER]
				testing.expectf(t, ge_eq(&r, &want), "ecmult_const wrong for %d * (%d*G)", i, base)
			}
		}
	}

	/*
	The variable-time `ecmult` computes a*P + b*G correctly for every (a, b, P).

	ORDER^3 combinations, which is the whole point: the wNAF path has many more internal
	branches than the constant-time one, and this reaches all of them.
	*/
	@(test)
	test_exhaustive_ecmult_var :: proc(t: ^testing.T) {
		pts: [ORDER]group.Ge
		build_group(pts[:])

		for base in 1 ..< ORDER {
			pj: group.Gej
			group.gej_set_ge(&pj, &pts[base])

			for a in 0 ..< ORDER {
				for b in 0 ..< ORDER {
					na, ng: scalar.Scalar
					scalar.scalar_set_int(&na, u32(a))
					scalar.scalar_set_int(&ng, u32(b))

					rj: group.Gej
					ecmult.ecmult(&rj, &pj, &na, &ng)
					r: group.Ge
					group.ge_set_gej(&r, &rj)

					want := pts[(a * base + b) % ORDER]
					testing.expectf(
						t,
						ge_eq(&r, &want),
						"ecmult wrong for %d*(%d*G) + %d*G",
						a,
						base,
						b,
					)
				}
			}
		}
	}

	/*
	The scalar field itself behaves, over every pair.

	Addition, multiplication, negation and inversion are checked against integer arithmetic
	modulo the order. Cheap, and it means a failure in the tests above can be attributed to
	the group code rather than to the scalar layer underneath it.
	*/
	@(test)
	test_exhaustive_scalar :: proc(t: ^testing.T) {
		for a in 0 ..< ORDER {
			sa: scalar.Scalar
			scalar.scalar_set_int(&sa, u32(a))

			// Negation.
			neg: scalar.Scalar
			scalar.scalar_negate(&neg, &sa)
			sum: scalar.Scalar
			scalar.scalar_add(&sum, &sa, &neg)
			testing.expectf(t, scalar.scalar_is_zero(&sum), "a + (-a) != 0 for a=%d", a)

			// Inversion, defined for every non-zero element of a prime-order field.
			if a != 0 {
				inv: scalar.Scalar
				scalar.scalar_inverse(&inv, &sa)
				prod: scalar.Scalar
				scalar.scalar_mul(&prod, &sa, &inv)
				testing.expectf(t, scalar.scalar_is_one(&prod), "a * a^-1 != 1 for a=%d", a)
			}

			for b in 0 ..< ORDER {
				sb: scalar.Scalar
				scalar.scalar_set_int(&sb, u32(b))

				add, mul: scalar.Scalar
				scalar.scalar_add(&add, &sa, &sb)
				scalar.scalar_mul(&mul, &sa, &sb)

				want_add, want_mul: scalar.Scalar
				scalar.scalar_set_int(&want_add, u32((a + b) % ORDER))
				scalar.scalar_set_int(&want_mul, u32((a * b) % ORDER))

				testing.expectf(t, scalar.scalar_eq(&add, &want_add), "%d + %d wrong", a, b)
				testing.expectf(t, scalar.scalar_eq(&mul, &want_mul), "%d * %d wrong", a, b)
			}
		}
	}
}
