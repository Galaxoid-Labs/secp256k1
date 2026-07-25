/*
Shared helpers for the group test package.

See `tests/field/common.odin` for why tests live outside the packages they exercise.
*/
package test_group

import "../../field"
import "../../group"
import "../../params"
import "../../testutil"

/*
Seed for the randomized tests. Override with `-define:TEST_SEED=n` to replay a failure.
*/
TEST_SEED :: #config(TEST_SEED, 0x9e3779b9_7f4a7c15)

/*
Draws a random field element.
*/
random_fe :: proc(rng: ^testutil.Rand) -> (r: field.Field_Elem) {
	b32: [32]u8
	for {
		testutil.rand_bytes_test(rng, b32[:])
		if field.fe_set_b32_limit(&r, &b32) {
			return
		}
	}
}

/*
Draws a random non-zero field element.
*/
random_fe_non_zero :: proc(rng: ^testutil.Rand) -> (r: field.Field_Elem) {
	for {
		r = random_fe(rng)
		if !field.fe_normalizes_to_zero(&r) {
			return
		}
	}
}

/*
Draws a random point on the curve.

Two strategies, because rejection sampling only works on the real curve:

  - **Real curve (cofactor 1).** Pick random x values until one has a square y. About half
    do, so this terminates immediately.

  - **Exhaustive curves.** The subgroup has 7, 13 or 199 elements out of a field of about
    2^256, so a random x essentially never lands in it and rejection sampling would spin
    forever. Instead pick a random multiple of the generator, which is by construction in
    the subgroup.
*/
random_ge :: proc(rng: ^testutil.Rand) -> (r: group.Ge) {
	when params.EXHAUSTIVE_ORDER > 0 {
		// A random non-zero multiple of G, so the result is never infinity.
		k := int(testutil.rand_int(rng, u32(params.EXHAUSTIVE_ORDER - 1))) + 1
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for _ in 0 ..< k {
			group.gej_add_ge_var(&acc, &acc, &group.GENERATOR, nil)
		}
		group.ge_set_gej_var(&r, &acc)
		return
	} else {
		for {
			x := random_fe(rng)
			odd := testutil.rand_bool(rng)
			if group.ge_set_xo_var(&r, &x, odd) {
				return
			}
		}
	}
}

/*
Draws a random point in Jacobian coordinates with a random non-trivial Z.

Using Z = 1 everywhere would leave the projective arithmetic barely exercised, so this
rescales by a random factor.
*/
random_gej :: proc(rng: ^testutil.Rand) -> (r: group.Gej) {
	ge := random_ge(rng)
	group.gej_set_ge(&r, &ge)

	z := random_fe_non_zero(rng)
	group.gej_rescale(&r, &z)
	return
}
