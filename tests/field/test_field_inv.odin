/*
Tests for inversion, square roots, and quadratic-residue testing.

Mirrors upstream's `run_inverse_tests`, `run_sqrt`, and the field half of
`run_modinv_tests`. The safegcd machinery underneath is hard to test by inspection — its
loop invariants only hold in aggregate — so these lean on the defining property (a * a^-1
== 1) across structured and random inputs, plus known answers that pin the modulus.
*/
package test_field

import "core:testing"
import "../../field"
import "../../params"
import "../../testutil"

/*
Inputs that have historically broken safegcd implementations: zero, one, the modulus
boundary, and small values whose inverses are large.

Mirrors the spirit of upstream's fixed `secp256k1_fe_inv` test cases.
*/

INV_EDGE_CASES :: []string {
	"0000000000000000000000000000000000000000000000000000000000000000", // 0
	"0000000000000000000000000000000000000000000000000000000000000001", // 1
	"0000000000000000000000000000000000000000000000000000000000000002",
	"0000000000000000000000000000000000000000000000000000000000000003",
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e", // p-1
	"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d", // p-2
	"7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17", // (p-1)/2
	"00000000000000000000000000000000000000000000000000000001000003d1", // the reduction constant
	"0000000000000000000000000000000000000000000000000000000100000000", // 2^32
	"8000000000000000000000000000000000000000000000000000000000000000", // 2^255
}

/*
Checks that inv agrees with its definition on one value, in both constant-time and
variable-time forms.
*/

check_inverse :: proc(t: ^testing.T, x: ^field.Field_Elem, label: string, index: int) {
	xn := x^
	field.fe_normalize(&xn)
	is_zero := field.fe_is_zero(&xn)

	ct: field.Field_Elem
	field.fe_inv(&ct, x)

	vt: field.Field_Elem
	field.fe_inv_var(&vt, x)

	// The two paths must agree exactly, not merely in value.
	testing.expectf(
		t,
		ct.n == vt.n,
		"%s[%d]: field.fe_inv and field.fe_inv_var disagree",
		label,
		index,
	)

	when field.VERIFY {
		testing.expectf(t, ct.normalized, "%s[%d]: field.fe_inv result is not normalized", label, index)
	}

	if is_zero {
		// Zero is defined to invert to zero.
		testing.expectf(t, field.fe_is_zero(&ct), "%s[%d]: inverse of zero is not zero", label, index)
		return
	}

	// x * x^-1 == 1
	prod: field.Field_Elem
	xc := xn
	field.fe_mul(&prod, &xc, &ct)
	field.fe_normalize(&prod)
	testing.expectf(t, prod.n == field.ONE.n, "%s[%d]: x * inv(x) != 1", label, index)

	// Inversion is an involution.
	back: field.Field_Elem
	field.fe_inv(&back, &ct)
	field.fe_normalize(&back)
	testing.expectf(t, back.n == xn.n, "%s[%d]: inv(inv(x)) != x", label, index)
}

@(test)
test_run_inverse_tests :: proc(t: ^testing.T) {
	// Structured edge cases first: these are where carry and boundary handling breaks.
	for hex, i in INV_EDGE_CASES {
		x := parse_hex(t, hex)
		check_inverse(t, &x, "edge", i)
	}

	// Then random values.
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 10)
	for i in 0 ..< params.COUNT * 4 {
		x := random_fe(&rng)
		check_inverse(t, &x, "random", i)
	}

	// And unnormalized inputs at a range of magnitudes, since inv must normalize
	// internally rather than assume its input is reduced.
	for m in 1 ..= 8 {
		for i in 0 ..< params.COUNT {
			x := random_fe(&rng)
			field.fe_mul_int(&x, u32(m))
			check_inverse(t, &x, "unnormalized", i)
		}
	}
}

@(test)
test_run_sqrt :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 11)

	// The square of any value is a residue, and sqrt must recover a root of it.
	for i in 0 ..< params.COUNT * 4 {
		x := random_fe(&rng)
		field.fe_normalize(&x)

		square: field.Field_Elem
		xc := x
		field.fe_sqr(&square, &xc)
		field.fe_normalize(&square)

		root: field.Field_Elem
		ok := field.fe_sqrt(&root, &square)
		testing.expectf(t, ok, "sqrt of a square reported non-residue (iteration %d)", i)

		// The root must be x or -x.
		field.fe_normalize(&root)
		neg_x: field.Field_Elem
		field.fe_negate(&neg_x, &x, 1)
		field.fe_normalize(&neg_x)
		testing.expectf(
			t,
			root.n == x.n || root.n == neg_x.n,
			"sqrt returned a value that is neither x nor -x (iteration %d)",
			i,
		)

		// Squaring the root reproduces the input.
		check: field.Field_Elem
		rc := root
		field.fe_sqr(&check, &rc)
		field.fe_normalize(&check)
		testing.expectf(t, check.n == square.n, "root does not square back (iteration %d)", i)
	}

	// For a non-residue, sqrt must report failure and return a root of -a instead.
	non_residues := 0
	for i in 0 ..< params.COUNT * 4 {
		a := random_fe(&rng)
		field.fe_normalize(&a)
		if field.fe_is_zero(&a) {
			continue
		}

		root: field.Field_Elem
		ok := field.fe_sqrt(&root, &a)

		// sqrt's return value must agree with the independent residue test.
		testing.expectf(
			t,
			ok == field.fe_is_square_var(&a),
			"sqrt and is_square_var disagree (iteration %d)",
			i,
		)

		if !ok {
			non_residues += 1
			// The result is a root of -a.
			sq: field.Field_Elem
			rc := root
			field.fe_sqr(&sq, &rc)
			neg_a: field.Field_Elem
			field.fe_negate(&neg_a, &a, 1)
			testing.expectf(t, field.fe_equal(&sq, &neg_a), "failed sqrt is not a root of -a (iteration %d)", i)
		}
	}

	// Roughly half of all field elements are non-residues; if we saw none, the test is
	// not exercising the failure path at all.
	testing.expect(t, non_residues > 0, "no non-residues encountered; sqrt failure path untested")
}

@(test)
test_run_modinv_tests :: proc(t: ^testing.T) {
	// Known inverses, computed independently.
	cases := []struct {
		x, want: string,
	} {
		{
			"0000000000000000000000000000000000000000000000000000000000000001",
			"0000000000000000000000000000000000000000000000000000000000000001",
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000002",
			"7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe18",
		},
		{
			"0000000000000000000000000000000000000000000000000000000000000003",
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa9fffffd75",
		},
		{
			// p-1 is its own inverse, since (p-1)^2 = 1 mod p.
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
			"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
		},
		{
			"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
			"237afdf1d2938d86870aaeb8ad77626a67b8e794abfb076be61d003687ca9ef6",
		},
		{
			// The reduction constant itself, where a mistake in the low limb shows up.
			"00000000000000000000000000000000000000000000000000000001000003d1",
			"c9bd1905155383999c46c2c295f2b761bcb223fedc24a059d838091d0868192a",
		},
	}

	for c, i in cases {
		x := parse_hex(t, c.x)
		want := parse_hex(t, c.want)

		got: field.Field_Elem
		field.fe_inv(&got, &x)
		field.fe_normalize(&got)
		testing.expectf(t, got.n == want.n, "modinv vector %d: got %v want %v", i, got.n, want.n)

		got_var: field.Field_Elem
		field.fe_inv_var(&got_var, &x)
		field.fe_normalize(&got_var)
		testing.expectf(t, got_var.n == want.n, "modinv_var vector %d disagrees", i)
	}
}

@(test)
test_is_square_var :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 12)

	// Zero is a square.
	zero: field.Field_Elem
	field.fe_set_int(&zero, 0)
	testing.expect(t, field.fe_is_square_var(&zero), "zero should be reported as a square")

	// One is a square.
	one := field.ONE
	testing.expect(t, field.fe_is_square_var(&one), "one should be reported as a square")

	// Every square is a square.
	for i in 0 ..< params.COUNT * 2 {
		x := random_fe_non_zero(&rng)
		sq: field.Field_Elem
		field.fe_sqr(&sq, &x)
		field.fe_normalize(&sq)
		testing.expectf(t, field.fe_is_square_var(&sq), "a square was not reported as one (iteration %d)", i)
	}
}
