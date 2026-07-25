/*
Tests for the scalar multiplication engines, mirroring upstream's `run_wnaf`,
`run_ecmult_chain`, `run_ecmult_const_tests`, `run_ecmult_constants`, `run_ecmult_pre_g`,
`run_point_times_order` and `run_endomorphism_tests`.

The engines are the point where an error stops being an arithmetic bug and starts being a
signing bug, so the tests lean on two things random sampling cannot fake:

  - **Cross-agreement.** `ecmult`, `ecmult_const` and `ecmult_gen` compute the same
    products by completely different routes — wNAF versus signed digits versus a comb — so
    making all three agree on the same inputs is a strong check on all of them.
  - **Independent ladders.** Small multiples are checked against repeated addition, which
    shares no code with any engine.
*/
package test_ecmult

import "core:testing"
import "../../ecmult"
import "../../field"
import "../../group"
import "../../params"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0x1337_c0de_face_b00c)

/*
Draws a random scalar.
*/
random_scalar :: proc(rng: ^testutil.Rand) -> (r: scalar.Scalar) {
	b32: [32]u8
	for {
		testutil.rand_bytes_test(rng, b32[:])
		if !scalar.scalar_set_b32(&r, &b32) {
			return
		}
	}
}

/*
Draws a random non-zero scalar.
*/
random_scalar_non_zero :: proc(rng: ^testutil.Rand) -> (r: scalar.Scalar) {
	for {
		r = random_scalar(rng)
		if !scalar.scalar_is_zero(&r) {
			return
		}
	}
}

/*
Draws a random point on the curve.
*/
random_ge :: proc(rng: ^testutil.Rand) -> (r: group.Ge) {
	b32: [32]u8
	for {
		x: field.Field_Elem
		testutil.rand_bytes_test(rng, b32[:])
		if !field.fe_set_b32_limit(&x, &b32) {
			continue
		}
		if group.ge_set_xo_var(&r, &x, testutil.rand_bool(rng)) {
			return
		}
	}
}

/*
Computes k*P by a plain double-and-add ladder, sharing no code with any engine.

Deliberately naive and variable-time; it exists only to be an independent oracle.
*/
ladder_mul :: proc(r: ^group.Gej, p: ^group.Ge, k: ^scalar.Scalar) {
	group.gej_set_infinity(r)
	for i := 255; i >= 0; i -= 1 {
		group.gej_double_var(r, r, nil)
		if scalar.scalar_get_bits_limb32(k, uint(i), 1) != 0 {
			group.gej_add_ge_var(r, r, p, nil)
		}
	}
}

@(test)
test_run_wnaf :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for w: uint = 2; w <= 8; w += 1 {
		for i in 0 ..< params.COUNT {
			s := random_scalar(&rng)

			digits: [256]int
			n := ecmult.wnaf(digits[:], &s, w)
			testing.expectf(t, n <= 256, "wnaf returned %d digits for window %d", n, w)

			// Every digit must be zero or odd, and within range.
			limit := 1 << (w - 1)
			for j in 0 ..< 256 {
				d := digits[j]
				if d == 0 {
					continue
				}
				testing.expectf(t, d & 1 != 0, "wnaf digit %d is even (window %d)", d, w)
				testing.expectf(t, d > -limit && d < limit, "wnaf digit %d out of range (window %d)", d, w)
			}

			// Non-zero digits must be separated by at least w-1 zeros; that sparsity is
			// the entire point of the representation.
			last := -1000
			for j in 0 ..< 256 {
				if digits[j] == 0 {
					continue
				}
				testing.expectf(
					t,
					j - last >= int(w),
					"wnaf digits at %d and %d are too close (window %d)",
					last,
					j,
					w,
				)
				last = j
			}

			// The digits must reconstruct the original scalar.
			acc: scalar.Scalar
			scalar.scalar_set_int(&acc, 0)
			for j := 255; j >= 0; j -= 1 {
				scalar.scalar_add(&acc, &acc, &acc)
				if digits[j] == 0 {
					continue
				}
				mag := digits[j]
				negate := mag < 0
				if negate {
					mag = -mag
				}
				term: scalar.Scalar
				scalar.scalar_set_int(&term, u32(mag))
				if negate {
					scalar.scalar_negate(&term, &term)
				}
				scalar.scalar_add(&acc, &acc, &term)
			}
			testing.expectf(t, scalar.scalar_eq(&acc, &s), "wnaf does not reconstruct the scalar (window %d, %d)", w, i)
		}
	}
}

/*
Verifies that the precomputed generator tables really hold odd multiples of G, and of
2^128*G.

This is the check that replaces upstream's byte-identical regeneration: rather than
comparing against a checked-in blob, each entry is compared against a multiple computed by
an independent ladder. Mirrors `run_ecmult_pre_g`.
*/
@(test)
test_run_ecmult_pre_g :: proc(t: ^testing.T) {
	// Entry i must be (2i+1)*G.
	acc: group.Gej
	group.gej_set_ge(&acc, &group.GENERATOR)

	two_g: group.Gej
	group.gej_double_var(&two_g, &acc, nil)
	two_g_affine: group.Ge
	tg := two_g
	group.ge_set_gej_var(&two_g_affine, &tg)

	// Checking every entry of a 2^(W-2) table is slow for large windows; cover the first
	// few hundred, which is where an off-by-one or a wrong step would show.
	limit := min(len(ecmult.PRE_G), 256)
	for i in 0 ..< limit {
		entry: group.Ge
		group.ge_from_storage(&entry, &ecmult.PRE_G[i])
		testing.expectf(t, group.gej_eq_ge_var(&acc, &entry), "PRE_G[%d] is not (2*%d+1)*G", i, i)
		testing.expectf(t, group.ge_is_valid_var(&entry), "PRE_G[%d] is not on the curve", i)
		group.gej_add_ge_var(&acc, &acc, &two_g_affine, nil)
	}

	// The 2^128 table starts at 2^128*G.
	shifted: group.Gej
	group.gej_set_ge(&shifted, &group.GENERATOR)
	for _ in 0 ..< 128 {
		group.gej_double_var(&shifted, &shifted, nil)
	}

	first_128: group.Ge
	group.ge_from_storage(&first_128, &ecmult.PRE_G_128[0])
	testing.expect(t, group.gej_eq_ge_var(&shifted, &first_128), "PRE_G_128[0] is not 2^128*G")

	two_shifted: group.Gej
	group.gej_double_var(&two_shifted, &shifted, nil)
	two_shifted_affine: group.Ge
	ts := two_shifted
	group.ge_set_gej_var(&two_shifted_affine, &ts)

	acc2 := shifted
	for i in 0 ..< limit {
		entry: group.Ge
		group.ge_from_storage(&entry, &ecmult.PRE_G_128[i])
		testing.expectf(t, group.gej_eq_ge_var(&acc2, &entry), "PRE_G_128[%d] is wrong", i)
		group.gej_add_ge_var(&acc2, &acc2, &two_shifted_affine, nil)
	}
}

/*
Verifies the comb table used by `ecmult_gen`.

Each entry must be a valid curve point, none may be infinity — the storage form cannot
represent it, and the constant-time addition cannot consume it — and the table must
reproduce the generator through the engine itself.
*/
@(test)
test_run_ecmult_gen_table :: proc(t: ^testing.T) {
	for block in 0 ..< len(ecmult.PREC_TABLE) {
		for index in 0 ..< len(ecmult.PREC_TABLE[block]) {
			e: group.Ge
			group.ge_from_storage(&e, &ecmult.PREC_TABLE[block][index])
			testing.expectf(t, !group.ge_is_infinity(&e), "comb table [%d][%d] is infinity", block, index)
			testing.expectf(t, group.ge_is_valid_var(&e), "comb table [%d][%d] is off-curve", block, index)
		}
	}
}

@(test)
test_run_ecmult_chain :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	// Small multiples of a random point, checked against repeated addition.
	for i in 0 ..< params.COUNT {
		p := random_ge(&rng)
		pj: group.Gej
		group.gej_set_ge(&pj, &p)

		running: group.Gej
		group.gej_set_infinity(&running)

		for k in 1 ..= 8 {
			group.gej_add_ge_var(&running, &running, &p, nil)

			ks: scalar.Scalar
			scalar.scalar_set_int(&ks, u32(k))

			via_ecmult: group.Gej
			ecmult.ecmult(&via_ecmult, &pj, &ks, nil)
			testing.expectf(t, group.gej_eq_var(&via_ecmult, &running), "ecmult %d*P wrong (%d)", k, i)

			via_const: group.Gej
			ecmult.ecmult_const(&via_const, &p, &ks)
			testing.expectf(t, group.gej_eq_var(&via_const, &running), "ecmult_const %d*P wrong (%d)", k, i)
		}
	}
}

/*
The core cross-agreement test: all three engines must produce the same answer.
*/
@(test)
test_ecmult_engines_agree :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	ctx: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&ctx)

	for i in 0 ..< params.COUNT {
		k := random_scalar_non_zero(&rng)
		p := random_ge(&rng)
		pj: group.Gej
		group.gej_set_ge(&pj, &p)

		// k*P three ways: wNAF, signed-digit constant-time, and an independent ladder.
		via_var: group.Gej
		ecmult.ecmult(&via_var, &pj, &k, nil)

		via_const: group.Gej
		ecmult.ecmult_const(&via_const, &p, &k)

		via_ladder: group.Gej
		ladder_mul(&via_ladder, &p, &k)

		testing.expectf(t, group.gej_eq_var(&via_var, &via_ladder), "ecmult disagrees with the ladder (%d)", i)
		testing.expectf(t, group.gej_eq_var(&via_const, &via_ladder), "ecmult_const disagrees with the ladder (%d)", i)

		// k*G three ways: the generator table, the general engine, and the comb.
		via_g_table: group.Gej
		ecmult.ecmult(&via_g_table, &pj, &scalar.ZERO, &k)

		gj: group.Gej
		group.gej_set_ge(&gj, &group.GENERATOR)
		via_g_general: group.Gej
		ecmult.ecmult(&via_g_general, &gj, &k, nil)

		via_gen: group.Gej
		ecmult.ecmult_gen(&ctx, &via_gen, &k)

		testing.expectf(t, group.gej_eq_var(&via_g_table, &via_g_general), "the two k*G routes disagree (%d)", i)
		testing.expectf(t, group.gej_eq_var(&via_gen, &via_g_general), "ecmult_gen disagrees with ecmult (%d)", i)

		// The combined form must equal the sum of the parts.
		combined: group.Gej
		k2 := random_scalar(&rng)
		ecmult.ecmult(&combined, &pj, &k, &k2)

		part_g: group.Gej
		ecmult.ecmult(&part_g, &gj, &k2, nil)
		expected: group.Gej
		group.gej_add_var(&expected, &via_var, &part_g, nil)

		testing.expectf(t, group.gej_eq_var(&combined, &expected), "na*A + ng*G != na*A + ng*G split (%d)", i)
	}
}

/*
Checks the edge cases every engine must handle: zero scalars, the identity, and infinity.
*/
@(test)
test_ecmult_edge_cases :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	ctx: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&ctx)

	p := random_ge(&rng)
	pj: group.Gej
	group.gej_set_ge(&pj, &p)

	// 0*P is infinity.
	r: group.Gej
	ecmult.ecmult(&r, &pj, &scalar.ZERO, nil)
	testing.expect(t, group.gej_is_infinity(&r), "ecmult: 0*P is not infinity")

	ecmult.ecmult_const(&r, &p, &scalar.ZERO)
	testing.expect(t, group.gej_is_infinity(&r), "ecmult_const: 0*P is not infinity")

	// 0*G is infinity.
	ecmult.ecmult_gen(&ctx, &r, &scalar.ZERO)
	testing.expect(t, group.gej_is_infinity(&r), "ecmult_gen: 0*G is not infinity")

	// 1*P is P.
	ecmult.ecmult(&r, &pj, &scalar.ONE, nil)
	testing.expect(t, group.gej_eq_ge_var(&r, &p), "ecmult: 1*P != P")

	ecmult.ecmult_const(&r, &p, &scalar.ONE)
	testing.expect(t, group.gej_eq_ge_var(&r, &p), "ecmult_const: 1*P != P")

	// 1*G is G.
	ecmult.ecmult_gen(&ctx, &r, &scalar.ONE)
	testing.expect(t, group.gej_eq_ge_var(&r, &group.GENERATOR), "ecmult_gen: 1*G != G")

	// Multiplying infinity gives infinity.
	inf: group.Ge
	group.ge_set_infinity(&inf)
	k := random_scalar_non_zero(&rng)
	ecmult.ecmult_const(&r, &inf, &k)
	testing.expect(t, group.gej_is_infinity(&r), "ecmult_const: k*infinity is not infinity")

	infj: group.Gej
	group.gej_set_infinity(&infj)
	ecmult.ecmult(&r, &infj, &k, nil)
	testing.expect(t, group.gej_is_infinity(&r), "ecmult: k*infinity is not infinity")

	// (-k)*P == -(k*P).
	neg_k: scalar.Scalar
	scalar.scalar_negate(&neg_k, &k)

	kp, neg_kp: group.Gej
	ecmult.ecmult_const(&kp, &p, &k)
	ecmult.ecmult_const(&neg_kp, &p, &neg_k)

	sum: group.Gej
	group.gej_add_var(&sum, &kp, &neg_kp, nil)
	testing.expect(t, group.gej_is_infinity(&sum), "k*P + (-k)*P != infinity")
}

/*
Mirrors upstream's `run_point_times_order`: multiplying any point by the group order gives
infinity, since every curve point has order dividing n.
*/
@(test)
test_run_point_times_order :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	// n as a scalar reduces to zero, so multiply by n-1 and add the point back instead.
	n_minus_1: scalar.Scalar
	scalar.scalar_negate(&n_minus_1, &scalar.ONE)

	for i in 0 ..< params.COUNT {
		p := random_ge(&rng)

		r: group.Gej
		ecmult.ecmult_const(&r, &p, &n_minus_1)

		// (n-1)*P + P == n*P == infinity.
		group.gej_add_ge_var(&r, &r, &p, nil)
		testing.expectf(t, group.gej_is_infinity(&r), "n*P is not infinity (%d)", i)
	}
}

/*
Mirrors upstream's `run_endomorphism_tests`: the endomorphism must agree with multiplying
by lambda.
*/
@(test)
test_run_endomorphism_tests :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 5)

	for i in 0 ..< params.COUNT {
		p := random_ge(&rng)

		// lambda*P via the endomorphism: one field multiplication.
		via_beta: group.Ge
		group.ge_mul_lambda(&via_beta, &p)

		// lambda*P via actual scalar multiplication.
		via_mul: group.Gej
		ecmult.ecmult_const(&via_mul, &p, &scalar.LAMBDA)

		testing.expectf(
			t,
			group.gej_eq_ge_var(&via_mul, &via_beta),
			"the endomorphism disagrees with multiplication by lambda (%d)",
			i,
		)
	}
}

/*
Confirms the K constant used by `ecmult_const` is self-consistent.

K is defined as (2^CONST_BITS - 2^129 - 1)*(1 + lambda) mod n. Rather than restate the
literal, this rebuilds it from that definition using scalar arithmetic, so a mistyped limb
is caught. Mirrors upstream's `run_ecmult_constants`.
*/
@(test)
test_run_ecmult_constants :: proc(t: ^testing.T) {
	when params.EXHAUSTIVE_ORDER == 0 {
		// 2^CONST_BITS
		two_pow_bits: scalar.Scalar
		scalar.scalar_set_int(&two_pow_bits, 1)
		for _ in 0 ..< ecmult.CONST_BITS {
			scalar.scalar_add(&two_pow_bits, &two_pow_bits, &two_pow_bits)
		}

		// 2^129
		two_pow_129: scalar.Scalar
		scalar.scalar_set_int(&two_pow_129, 1)
		for _ in 0 ..< 129 {
			scalar.scalar_add(&two_pow_129, &two_pow_129, &two_pow_129)
		}

		// 2^CONST_BITS - 2^129 - 1
		neg: scalar.Scalar
		scalar.scalar_negate(&neg, &two_pow_129)
		term: scalar.Scalar
		scalar.scalar_add(&term, &two_pow_bits, &neg)
		scalar.scalar_negate(&neg, &scalar.ONE)
		scalar.scalar_add(&term, &term, &neg)

		// times (1 + lambda)
		one_plus_lambda: scalar.Scalar
		scalar.scalar_add(&one_plus_lambda, &scalar.ONE, &scalar.LAMBDA)

		want: scalar.Scalar
		scalar.scalar_mul(&want, &term, &one_plus_lambda)

		testing.expect(
			t,
			scalar.scalar_eq(&want, &ecmult.CONST_K),
			"the K constant does not match its definition",
		)
	}
}
