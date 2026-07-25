/*
Known-answer tests for the field kernels.

The property tests in `field_test.odin` — commutativity, associativity, distributivity —
hold in *any* commutative ring, so they would pass unchanged if the reduction used the
wrong modulus. These vectors pin the arithmetic to p = 2^256 - 2^32 - 977 specifically.

Expected values were computed independently with exact big-integer arithmetic, not by this
implementation and not by libsecp256k1.
*/
package test_field

import "core:testing"
import "../../field"


Mul_Vector :: struct {
	a, b, want: string,
}


Sqr_Vector :: struct {
	a, want: string,
}


/*
Products modulo p, computed independently.

Covers the identity, p-1 squared (which must be 1), the secp256k1 generator's coordinates
multiplied together, and values built from the reduction constant 2^32+977 itself, where a
mistake in the reduction step is most visible.
*/

MUL_VECTORS :: []Mul_Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001",
	},
	{
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
		"0000000000000000000000000000000000000000000000000000000000000001",
	},
	{
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
	},
	{
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
		"fd3dc529c6eb60fb9d166034cf3c1a5a72324aa9dfd3428a56d7e1ce0179fd9b",
	},
	{
		"00000000000000000000000000000000000000000000000000000001000003d0",
		"000000000000000000000000000000000000000000000000deadbeefcafebabe",
		"0000000000000000000000000000000000000000deadc240c166acf3eb27f460",
	},
	{
		"00000000000000000000000000000000000000000000000000000001000003d1",
		"00000000000000000000000000000000000000000000000000000001000003d1",
		"000000000000000000000000000000000000000000000001000007a2000e90a1",
	},
	{
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
		"0000000000000000000000000000000000000000000000000000000000000003",
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe16",
	},
}

/*
Squares modulo p, computed independently.
*/

SQR_VECTORS :: []Sqr_Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001",
	},
	{
		"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
		"0000000000000000000000000000000000000000000000000000000000000001",
	},
	{
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"8550e7d238fcf3086ba9adcf0fb52a9de3652194d06cb5bb38d50229b854fc49",
	},
	{
		"00000000000000000000000000000000000000000000000000000001000003d0",
		"000000000000000000000000000000000000000000000001000007a0000e8900",
	},
	{
		"00000000000000000000000000000000000000000000000000000001000003d1",
		"000000000000000000000000000000000000000000000001000007a2000e90a1",
	},
	{
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffe17",
		"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c",
	},
}

@(test)
test_fe_mul_known_answers :: proc(t: ^testing.T) {
	for v, i in MUL_VECTORS {
		a := parse_hex(t, v.a)
		b := parse_hex(t, v.b)
		want := parse_hex(t, v.want)

		got: field.Field_Elem
		field.fe_mul(&got, &a, &b)
		field.fe_normalize(&got)

		testing.expectf(t, got.n == want.n, "mul vector %d: got %v, want %v", i, got.n, want.n)

		// The product must be the same with the operands swapped.
		b2 := parse_hex(t, v.b)
		a2 := parse_hex(t, v.a)
		swapped: field.Field_Elem
		field.fe_mul(&swapped, &b2, &a2)
		field.fe_normalize(&swapped)
		testing.expectf(t, swapped.n == want.n, "mul vector %d is not commutative", i)
	}
}

@(test)
test_fe_sqr_known_answers :: proc(t: ^testing.T) {
	for v, i in SQR_VECTORS {
		a := parse_hex(t, v.a)
		want := parse_hex(t, v.want)

		got: field.Field_Elem
		field.fe_sqr(&got, &a)
		field.fe_normalize(&got)

		testing.expectf(t, got.n == want.n, "sqr vector %d: got %v, want %v", i, got.n, want.n)
	}
}

/*
Pins the modulus itself: p must reduce to zero, and p-1 must be the largest representable
value, whose successor wraps to zero.

If the reduction used any modulus other than 2^256 - 2^32 - 977, this fails even though
every ring property still holds.
*/
@(test)
test_fe_modulus_is_p :: proc(t: ^testing.T) {
	p_bytes := [32]u8 {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
	}

	p: field.Field_Elem
	field.fe_set_b32_mod(&p, &p_bytes)
	testing.expect(t, field.fe_normalizes_to_zero(&p), "p does not reduce to zero")

	// (p-1) + 1 == 0
	pm1 := parse_hex(t, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")
	sum := pm1
	field.fe_add_int(&sum, 1)
	testing.expect(t, field.fe_normalizes_to_zero(&sum), "(p-1) + 1 is not zero")

	// (p-1) is its own additive inverse's neighbour: -(p-1) == 1
	neg: field.Field_Elem
	field.fe_negate(&neg, &pm1, 1)
	field.fe_normalize(&neg)
	testing.expect_value(t, neg.n, field.ONE.n)

	// The reduction constant is exactly 2^256 mod p, so 2^256 - p == R.
	// Reducing 2^256-1 must give R - 1 = 0x1000003d0.
	ff := [32]u8 {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	top: field.Field_Elem
	field.fe_set_b32_mod(&top, &ff)
	field.fe_normalize(&top)

	want := field.fe_const(0, 0, 0, 0, 0, 0, 0x01, 0x000003d0)
	testing.expect_value(t, top.n, want.n)
	testing.expect_value(t, u64(field.R) - 1, u64(0x1000003d0))
}

/*
Checks that `BETA` really is a primitive cube root of unity modulo p, which is what makes
the endomorphism valid. A wrong constant here would not surface until `ecmult` produced
subtly wrong points.
*/
@(test)
test_beta_is_cube_root_of_unity :: proc(t: ^testing.T) {
	b := field.BETA
	testing.expect(t, !field.fe_normalizes_to_zero(&b), "beta is zero")

	// beta != 1
	one_cmp := field.BETA
	field.fe_normalize(&one_cmp)
	testing.expect(t, field.fe_cmp_var(&one_cmp, &field.ONE) != 0, "beta is 1, so it is not primitive")

	// beta^3 == 1
	sq: field.Field_Elem
	b1 := field.BETA
	field.fe_sqr(&sq, &b1)
	field.fe_normalize_weak(&sq)

	cube: field.Field_Elem
	b2 := field.BETA
	field.fe_mul(&cube, &sq, &b2)
	field.fe_normalize(&cube)

	testing.expect_value(t, cube.n, field.ONE.n)
}
