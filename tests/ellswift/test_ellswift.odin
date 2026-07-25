/*
ElligatorSwift tests, mirroring upstream's `modules/ellswift/tests_impl.h`.

The properties that define the map:

  - **Totality.** Every 64-byte string decodes to a curve point. There is no invalid input,
    which is what makes the encoding indistinguishable from random — an observer has
    nothing to probe.
  - **Round-trip.** Encoding a point and decoding the result returns the same point.
  - **Unlinkability.** The same point under different randomness produces different
    encodings, all of which decode back to it.
*/
package test_ellswift

import "core:testing"
import "../../ecmult"
import "../../eckey"
import "../../ellswift"
import "../../field"
import "../../group"
import "../../params"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0xe115_5717_7000)

/*
Every 64-byte string must decode to a valid curve point.

This is the strongest single statement about the map, and the one a censorship-resistant
transport depends on: a decoder that could fail would leak information through the failure.
*/
@(test)
test_ellswift_decode_is_total :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for i in 0 ..< params.COUNT * 4 {
		ell: [64]u8
		testutil.rand_bytes_test(&rng, ell[:])

		pk: group.Ge
		testing.expectf(t, ellswift.decode(&pk, &ell), "decode failed (%d)", i)
		testing.expectf(t, !group.ge_is_infinity(&pk), "decoded to infinity (%d)", i)
		testing.expectf(t, group.ge_is_valid_var(&pk), "decoded to an off-curve point (%d)", i)
	}

	// Structured inputs too: all-zero, all-ones, and the field modulus, which exercise the
	// u = 0, t = 0 and g + s = 0 special cases the formula patches.
	edge := [][64]u8{{}, {}, {}}
	for i in 0 ..< 64 {
		edge[1][i] = 0xff
	}
	// u = p, t = p (both reduce to zero).
	p_bytes := [32]u8 {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
	}
	for i in 0 ..< 32 {
		edge[2][i] = p_bytes[i]
		edge[2][32 + i] = p_bytes[i]
	}

	for e, i in edge {
		ell := e
		pk: group.Ge
		testing.expectf(t, ellswift.decode(&pk, &ell), "edge decode failed (%d)", i)
		testing.expectf(t, group.ge_is_valid_var(&pk), "edge input decoded off-curve (%d)", i)
	}
}

@(test)
test_ellswift_round_trip :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		seckey: [32]u8
		testutil.rand_bytes(&rng, seckey[:])
		sec: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&sec, &seckey) {
			continue
		}

		pk: group.Ge
		eckey.pubkey_create(&gen, &pk, &sec)

		rnd: [32]u8
		testutil.rand_bytes(&rng, rnd[:])

		ell: [64]u8
		ellswift.encode(&ell, &pk, &rnd)

		decoded: group.Ge
		testing.expectf(t, ellswift.decode(&decoded, &ell), "decode failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&decoded, &pk), "round-trip changed the point (%d)", i)

		// Different randomness must give a different encoding of the same point. That
		// unlinkability is the whole purpose of the construction.
		rnd2: [32]u8
		testutil.rand_bytes(&rng, rnd2[:])
		ell2: [64]u8
		ellswift.encode(&ell2, &pk, &rnd2)
		testing.expectf(t, ell != ell2, "different randomness produced the same encoding (%d)", i)

		decoded2: group.Ge
		ellswift.decode(&decoded2, &ell2)
		testing.expectf(t, group.ge_eq_var(&decoded2, &pk), "the second encoding decoded wrongly (%d)", i)

		// Encoding is deterministic in its randomness.
		ell3: [64]u8
		ellswift.encode(&ell3, &pk, &rnd)
		testing.expectf(t, ell == ell3, "encoding is not deterministic (%d)", i)
	}
}

/*
Checks the inverse map directly: for a random point and random u, whichever branch succeeds
must produce a t that decodes back to the same x.
*/
@(test)
test_ellswift_inverse_map :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	solved := 0

	for i in 0 ..< params.COUNT * 2 {
		// A random curve point.
		pk: group.Ge
		{
			b32: [32]u8
			found := false
			for _ in 0 ..< 64 {
				x: field.Field_Elem
				testutil.rand_bytes_test(&rng, b32[:])
				if !field.fe_set_b32_limit(&x, &b32) {
					continue
				}
				if group.ge_set_xo_var(&pk, &x, false) {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		ub: [32]u8
		testutil.rand_bytes_test(&rng, ub[:])
		u: field.Field_Elem
		field.fe_set_b32_mod(&u, &ub)

		for branch in 0 ..< 8 {
			tv: field.Field_Elem
			if !ellswift.xswiftec_inv_var(&tv, &pk.x, &u, branch) {
				continue
			}
			solved += 1

			// Decoding (u, t) must reproduce the x we started from.
			x_back: field.Field_Elem
			ellswift.xswiftec_var(&x_back, &u, &tv)

			field.fe_normalize_var(&x_back)
			expect := pk.x
			field.fe_normalize_var(&expect)
			testing.expectf(
				t,
				x_back.n == expect.n,
				"branch %d produced a t that does not decode back (%d)",
				branch,
				i,
			)
		}
	}

	testing.expect(t, solved > 0, "no branch ever solved; the inverse map is untested")
}

/*
Checks the fraction form against the direct form.
*/
@(test)
test_ellswift_fraction_matches_direct :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	for i in 0 ..< params.COUNT {
		ub, tb: [32]u8
		testutil.rand_bytes_test(&rng, ub[:])
		testutil.rand_bytes_test(&rng, tb[:])

		u, tv: field.Field_Elem
		field.fe_set_b32_mod(&u, &ub)
		field.fe_set_b32_mod(&tv, &tb)

		xn, xd: field.Field_Elem
		ellswift.xswiftec_frac_var(&xn, &xd, &u, &tv)

		// The fraction must be on the curve.
		testing.expectf(t, group.ge_x_frac_on_curve_var(&xn, &xd), "the fraction is not on the curve (%d)", i)

		// And must equal the directly computed x.
		inv, quotient: field.Field_Elem
		field.fe_inv_var(&inv, &xd)
		field.fe_mul(&quotient, &xn, &inv)

		direct: field.Field_Elem
		ellswift.xswiftec_var(&direct, &u, &tv)

		field.fe_normalize_var(&quotient)
		field.fe_normalize_var(&direct)
		testing.expectf(t, quotient.n == direct.n, "the fraction and direct forms disagree (%d)", i)
	}
}

/*
BIP324 x-only ECDH over encoded keys.

The property is the same as ordinary ECDH — both parties derive the same secret — but with
the transcript binding that makes replay across sessions produce a different secret.
*/
@(test)
test_ellswift_xdh_is_symmetric :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		a32, b32: [32]u8
		testutil.rand_bytes(&rng, a32[:])
		testutil.rand_bytes(&rng, b32[:])

		ell_a, ell_b: [64]u8
		if !ellswift.create(&gen, &ell_a, &a32) || !ellswift.create(&gen, &ell_b, &b32) {
			continue
		}

		// Alice is party true (her encoding is ell_a), Bob is party false.
		sa, sb: [32]u8
		testing.expectf(t, ellswift.xdh(sa[:], &ell_a, &ell_b, &a32, true), "xdh failed for a (%d)", i)
		testing.expectf(t, ellswift.xdh(sb[:], &ell_a, &ell_b, &b32, false), "xdh failed for b (%d)", i)
		testing.expectf(t, sa == sb, "ellswift XDH is not symmetric (%d)", i)

		// Swapping the transcript order must change the secret: the encodings are hashed
		// in the given order, so the binding is order-sensitive by design.
		sc: [32]u8
		ellswift.xdh(sc[:], &ell_b, &ell_a, &a32, false)
		testing.expectf(t, sc != sa, "transcript order did not affect the secret (%d)", i)

		// A third party gets a different secret.
		c32: [32]u8
		testutil.rand_bytes(&rng, c32[:])
		ell_c: [64]u8
		if ellswift.create(&gen, &ell_c, &c32) {
			sd: [32]u8
			ellswift.xdh(sd[:], &ell_a, &ell_c, &a32, true)
			testing.expectf(t, sd != sa, "a different peer produced the same secret (%d)", i)
		}

		// The encoded key must decode to the key the secret actually derives.
		decoded: group.Ge
		ellswift.decode(&decoded, &ell_a)
		sec: scalar.Scalar
		scalar.scalar_set_b32_seckey(&sec, &a32)
		expected: group.Ge
		eckey.pubkey_create(&gen, &expected, &sec)
		testing.expectf(t, group.ge_eq_var(&decoded, &expected), "create produced the wrong key (%d)", i)
	}

	// An invalid secret key must be rejected.
	ell_a, ell_b: [64]u8
	seed: [32]u8
	seed[31] = 1
	ellswift.create(&gen, &ell_a, &seed)
	ellswift.create(&gen, &ell_b, &seed)
	zero: [32]u8
	out: [32]u8
	testing.expect(t, !ellswift.xdh(out[:], &ell_a, &ell_b, &zero, true), "a zero secret key was accepted")
	testing.expect(t, !ellswift.create(&gen, &ell_a, &zero), "create accepted a zero secret key")
}
