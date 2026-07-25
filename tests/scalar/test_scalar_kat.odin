/*
Known-answer tests for scalar arithmetic.

As in the field, the algebraic property tests hold in any commutative ring and would pass
against the wrong modulus. These vectors pin the arithmetic to n, the secp256k1 group
order, specifically. Expected values were computed independently with exact big-integer
arithmetic — not by this implementation and not by libsecp256k1.
*/
package test_scalar

import "core:testing"
import "../../scalar"

@(private = "file")
Mul_Vector :: struct {
	a, b, want: string,
}

@(private = "file")
Inv_Vector :: struct {
	a, want: string,
}

@(private = "file")
MUL_VECTORS :: []Mul_Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000002",
		"0000000000000000000000000000000000000000000000000000000000000003",
		"0000000000000000000000000000000000000000000000000000000000000006",
	},
	{
		// (n-1)^2 == 1 mod n
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"0000000000000000000000000000000000000000000000000000000000000001",
	},
	{
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"0000000000000000000000000000000000000000000000000000000000000002",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
	},
	{
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
		"75cb09a97349237fab20d64525970f01aa842fa7ec7d27fa7617822b64fc0a06",
	},
	{
		// (n-1)/2 * 3
		"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
		"0000000000000000000000000000000000000000000000000000000000000003",
		"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b209f",
	},
}

@(private = "file")
INV_VECTORS :: []Inv_Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000002",
		"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
	},
	{
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
	},
	{
		"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"1dd887b3eaf153260a95e8b9fd31f60ac115d26ccbe1f572c0b8d7a6dec520fe",
	},
	{
		"7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036413f",
	},
}

@(test)
test_scalar_mul_known_answers :: proc(t: ^testing.T) {
	for v, i in MUL_VECTORS {
		a := parse_hex(t, v.a)
		b := parse_hex(t, v.b)
		want := parse_hex(t, v.want)

		got: scalar.Scalar
		scalar.scalar_mul(&got, &a, &b)
		testing.expectf(t, scalar.scalar_eq(&got, &want), "mul vector %d: got %v want %v", i, got.d, want.d)

		swapped: scalar.Scalar
		scalar.scalar_mul(&swapped, &b, &a)
		testing.expectf(t, scalar.scalar_eq(&swapped, &want), "mul vector %d is not commutative", i)
	}
}

@(test)
test_scalar_inverse_known_answers :: proc(t: ^testing.T) {
	for v, i in INV_VECTORS {
		a := parse_hex(t, v.a)
		want := parse_hex(t, v.want)

		got: scalar.Scalar
		scalar.scalar_inverse(&got, &a)
		testing.expectf(t, scalar.scalar_eq(&got, &want), "inv vector %d: got %v want %v", i, got.d, want.d)

		got_var: scalar.Scalar
		scalar.scalar_inverse_var(&got_var, &a)
		testing.expectf(t, scalar.scalar_eq(&got_var, &want), "inv_var vector %d disagrees", i)
	}
}

/*
Pins the modulus to n.

n itself must reduce to zero, n-1 must be the largest representable value, and n+1 must
reduce to 1. If the reduction used any modulus other than the secp256k1 group order, this
fails even though every ring property still holds.
*/
@(test)
test_scalar_modulus_is_n :: proc(t: ^testing.T) {
	n := N_BYTES
	s: scalar.Scalar
	testing.expect(t, scalar.scalar_set_b32(&s, &n), "n did not report overflow")
	testing.expect(t, scalar.scalar_is_zero(&s), "n did not reduce to zero")

	// (n-1) + 1 == 0
	n_minus_1 := parse_hex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	sum: scalar.Scalar
	scalar.scalar_add(&sum, &n_minus_1, &scalar.ONE)
	testing.expect(t, scalar.scalar_is_zero(&sum), "(n-1) + 1 != 0")

	// -(n-1) == 1
	neg: scalar.Scalar
	scalar.scalar_negate(&neg, &n_minus_1)
	testing.expect(t, scalar.scalar_is_one(&neg), "-(n-1) != 1")

	// half(1) == (n+1)/2, the inverse of 2.
	h: scalar.Scalar
	scalar.scalar_half(&h, &scalar.ONE)
	want_half := parse_hex(t, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1")
	testing.expect(t, scalar.scalar_eq(&h, &want_half), "half(1) is not the inverse of 2")

	// Confirm it by multiplying back.
	two := parse_hex(t, "0000000000000000000000000000000000000000000000000000000000000002")
	prod: scalar.Scalar
	scalar.scalar_mul(&prod, &h, &two)
	testing.expect(t, scalar.scalar_is_one(&prod), "half(1) * 2 != 1")
}
