/*
Scalar tests, mirroring upstream's `run_scalar_tests` and
`run_scalar_set_b32_seckey_tests`.

The algebraic property tests here would pass against any commutative ring, exactly as in
the field, so they are backed by known-answer vectors computed independently and by tests
that pin the modulus to n specifically.
*/
package test_scalar

import "core:testing"
import "../../params"
import "../../scalar"
import "../../testutil"

@(test)
test_run_scalar_set_b32_seckey_tests :: proc(t: ^testing.T) {
	// Zero is not a valid secret key.
	zero: [32]u8
	s: scalar.Scalar
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &zero), "zero was accepted as a secret key")

	// n is not a valid secret key, and reduces to zero.
	n := N_BYTES
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &n), "n was accepted as a secret key")
	testing.expect(t, scalar.scalar_set_b32(&s, &n), "n did not report overflow")
	testing.expect(t, scalar.scalar_is_zero(&s), "n did not reduce to zero")

	// n-1 is the largest valid secret key.
	n_minus_1 := N_BYTES
	n_minus_1[31] = 0x40
	testing.expect(t, scalar.scalar_set_b32_seckey(&s, &n_minus_1), "n-1 was rejected")
	testing.expect(t, !scalar.scalar_set_b32(&s, &n_minus_1), "n-1 reported overflow")

	// n+1 is out of range and reduces to 1.
	n_plus_1 := N_BYTES
	n_plus_1[31] = 0x42
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &n_plus_1), "n+1 was accepted")
	testing.expect(t, scalar.scalar_set_b32(&s, &n_plus_1), "n+1 did not report overflow")
	testing.expect(t, scalar.scalar_is_one(&s), "n+1 did not reduce to 1")

	// 2^256-1 is out of range.
	all_ff := [32]u8{}
	for i in 0 ..< 32 {
		all_ff[i] = 0xff
	}
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &all_ff), "2^256-1 was accepted")

	// One is valid.
	one: [32]u8
	one[31] = 1
	testing.expect(t, scalar.scalar_set_b32_seckey(&s, &one), "1 was rejected")
	testing.expect(t, scalar.scalar_is_one(&s), "1 did not parse as one")
}

@(test)
test_run_scalar_tests :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for i in 0 ..< params.COUNT * 4 {
		a := random_scalar(&rng)
		b := random_scalar(&rng)
		c := random_scalar(&rng)

		// Addition is commutative.
		ab, ba: scalar.Scalar
		scalar.scalar_add(&ab, &a, &b)
		scalar.scalar_add(&ba, &b, &a)
		testing.expectf(t, scalar.scalar_eq(&ab, &ba), "addition is not commutative (%d)", i)

		// Multiplication is commutative.
		mab, mba: scalar.Scalar
		scalar.scalar_mul(&mab, &a, &b)
		scalar.scalar_mul(&mba, &b, &a)
		testing.expectf(t, scalar.scalar_eq(&mab, &mba), "multiplication is not commutative (%d)", i)

		// Multiplication is associative.
		l, r, bc: scalar.Scalar
		scalar.scalar_mul(&l, &mab, &c)
		scalar.scalar_mul(&bc, &b, &c)
		scalar.scalar_mul(&r, &a, &bc)
		testing.expectf(t, scalar.scalar_eq(&l, &r), "multiplication is not associative (%d)", i)

		// Multiplication distributes over addition.
		bpc, dl, ac, dr: scalar.Scalar
		scalar.scalar_add(&bpc, &b, &c)
		scalar.scalar_mul(&dl, &a, &bpc)
		scalar.scalar_mul(&ac, &a, &c)
		scalar.scalar_add(&dr, &mab, &ac)
		testing.expectf(t, scalar.scalar_eq(&dl, &dr), "multiplication does not distribute (%d)", i)

		// a + (-a) == 0
		neg, sum: scalar.Scalar
		scalar.scalar_negate(&neg, &a)
		scalar.scalar_add(&sum, &a, &neg)
		testing.expectf(t, scalar.scalar_is_zero(&sum), "a + (-a) != 0 (%d)", i)

		// Negation is an involution.
		negneg: scalar.Scalar
		scalar.scalar_negate(&negneg, &neg)
		testing.expectf(t, scalar.scalar_eq(&negneg, &a), "double negation changed the value (%d)", i)

		// a * 1 == a and a * 0 == 0.
		byone, byzero: scalar.Scalar
		scalar.scalar_mul(&byone, &a, &scalar.ONE)
		testing.expectf(t, scalar.scalar_eq(&byone, &a), "a * 1 != a (%d)", i)
		scalar.scalar_mul(&byzero, &a, &scalar.ZERO)
		testing.expectf(t, scalar.scalar_is_zero(&byzero), "a * 0 != 0 (%d)", i)

		// half then double is the identity.
		h, dbl: scalar.Scalar
		scalar.scalar_half(&h, &a)
		scalar.scalar_add(&dbl, &h, &h)
		testing.expectf(t, scalar.scalar_eq(&dbl, &a), "half then double changed the value (%d)", i)

		// cond_negate agrees with negate, and reports the sign it applied.
		cn := a
		sign := scalar.scalar_cond_negate(&cn, true)
		testing.expectf(t, sign == -1, "cond_negate(true) returned %d, want -1 (%d)", sign, i)
		testing.expectf(t, scalar.scalar_eq(&cn, &neg), "cond_negate(true) != negate (%d)", i)

		cn2 := a
		sign2 := scalar.scalar_cond_negate(&cn2, false)
		testing.expectf(t, sign2 == 1, "cond_negate(false) returned %d, want 1 (%d)", sign2, i)
		testing.expectf(t, scalar.scalar_eq(&cn2, &a), "cond_negate(false) changed the value (%d)", i)

		// cmov behaves like a select.
		m := a
		scalar.scalar_cmov(&m, &b, false)
		testing.expectf(t, scalar.scalar_eq(&m, &a), "cmov(false) modified the target (%d)", i)
		scalar.scalar_cmov(&m, &b, true)
		testing.expectf(t, scalar.scalar_eq(&m, &b), "cmov(true) did not replace the target (%d)", i)

		// Byte round-trip.
		buf: [32]u8
		scalar.scalar_get_b32(&buf, &a)
		back: scalar.Scalar
		testing.expectf(t, !scalar.scalar_set_b32(&back, &buf), "round-trip reported overflow (%d)", i)
		testing.expectf(t, scalar.scalar_eq(&back, &a), "byte round-trip changed the value (%d)", i)

		// is_even agrees with the low bit of the serialization.
		testing.expectf(
			t,
			scalar.scalar_is_even(&a) == (buf[31] & 1 == 0),
			"is_even disagrees with the serialized low bit (%d)",
			i,
		)
	}
}

@(test)
test_run_inverse_tests :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	// Zero inverts to zero.
	zi: scalar.Scalar
	scalar.scalar_inverse(&zi, &scalar.ZERO)
	testing.expect(t, scalar.scalar_is_zero(&zi), "inverse of zero is not zero")
	scalar.scalar_inverse_var(&zi, &scalar.ZERO)
	testing.expect(t, scalar.scalar_is_zero(&zi), "inverse_var of zero is not zero")

	// One inverts to one.
	oi: scalar.Scalar
	scalar.scalar_inverse(&oi, &scalar.ONE)
	testing.expect(t, scalar.scalar_is_one(&oi), "inverse of one is not one")

	for i in 0 ..< params.COUNT * 4 {
		x := random_scalar_non_zero(&rng)

		ct, vt: scalar.Scalar
		scalar.scalar_inverse(&ct, &x)
		scalar.scalar_inverse_var(&vt, &x)
		testing.expectf(t, scalar.scalar_eq(&ct, &vt), "inverse and inverse_var disagree (%d)", i)

		// x * x^-1 == 1
		prod: scalar.Scalar
		scalar.scalar_mul(&prod, &x, &ct)
		testing.expectf(t, scalar.scalar_is_one(&prod), "x * inv(x) != 1 (%d)", i)

		// Inversion is an involution.
		back: scalar.Scalar
		scalar.scalar_inverse(&back, &ct)
		testing.expectf(t, scalar.scalar_eq(&back, &x), "inv(inv(x)) != x (%d)", i)
	}
}

@(test)
test_scalar_is_high_and_low_s :: proc(t: ^testing.T) {
	// n/2 itself is not high; n/2 + 1 is. This boundary is the low-S rule, and an
	// off-by-one here would make signatures inconsistently normalized.
	half_n := parse_hex(t, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
	testing.expect(t, !scalar.scalar_is_high(&half_n), "n/2 was reported high")

	half_n_plus_1 := parse_hex(t, "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1")
	testing.expect(t, scalar.scalar_is_high(&half_n_plus_1), "n/2 + 1 was not reported high")

	testing.expect(t, !scalar.scalar_is_high(&scalar.ZERO), "zero was reported high")
	testing.expect(t, !scalar.scalar_is_high(&scalar.ONE), "one was reported high")

	n_minus_1 := parse_hex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	testing.expect(t, scalar.scalar_is_high(&n_minus_1), "n-1 was not reported high")

	// Negating a high scalar yields a low one, which is what low-S normalization relies
	// on. Zero is the only self-negating value.
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)
	for i in 0 ..< params.COUNT * 2 {
		s := random_scalar_non_zero(&rng)
		neg: scalar.Scalar
		scalar.scalar_negate(&neg, &s)
		testing.expectf(
			t,
			scalar.scalar_is_high(&s) != scalar.scalar_is_high(&neg),
			"s and -s are both %v (%d)",
			scalar.scalar_is_high(&s),
			i,
		)
	}
}

@(test)
test_scalar_get_bits :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	for i in 0 ..< params.COUNT {
		s := random_scalar(&rng)
		buf: [32]u8
		scalar.scalar_get_b32(&buf, &s)

		// Extracted bits must match the serialized big-endian form, bit for bit.
		for offset: uint = 0; offset < 256; offset += 1 {
			got := scalar.scalar_get_bits_var(&s, offset, 1)
			byte_index := 31 - int(offset / 8)
			want := u32((buf[byte_index] >> (offset % 8)) & 1)
			testing.expectf(t, got == want, "bit %d mismatch (iteration %d)", offset, i)
		}

		// Multi-bit reads within a limb agree with single-bit reads.
		for offset: uint = 0; offset + 32 <= 256; offset += 8 {
			wide := scalar.scalar_get_bits_var(&s, offset, 32)
			rebuilt: u32
			for k: uint = 0; k < 32; k += 1 {
				rebuilt |= scalar.scalar_get_bits_var(&s, offset + k, 1) << k
			}
			testing.expectf(t, wide == rebuilt, "32-bit read at %d mismatch (iteration %d)", offset, i)
		}
	}
}

@(test)
test_scalar_split_lambda :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	// lambda is a primitive cube root of unity modulo n.
	l2, l3: scalar.Scalar
	scalar.scalar_mul(&l2, &scalar.LAMBDA, &scalar.LAMBDA)
	scalar.scalar_mul(&l3, &l2, &scalar.LAMBDA)
	testing.expect(t, scalar.scalar_is_one(&l3), "lambda^3 != 1")
	testing.expect(t, !scalar.scalar_is_one(&scalar.LAMBDA), "lambda == 1, so it is not primitive")

	// lambda^2 + lambda + 1 == 0, since lambda is a root of X^2 + X + 1.
	sum: scalar.Scalar
	scalar.scalar_add(&sum, &l2, &scalar.LAMBDA)
	scalar.scalar_add(&sum, &sum, &scalar.ONE)
	testing.expect(t, scalar.scalar_is_zero(&sum), "lambda^2 + lambda + 1 != 0")

	for i in 0 ..< params.COUNT * 2 {
		k := random_scalar(&rng)

		r1, r2: scalar.Scalar
		scalar.scalar_split_lambda(&r1, &r2, &k)

		// r1 + lambda*r2 == k
		check: scalar.Scalar
		scalar.scalar_mul(&check, &scalar.LAMBDA, &r2)
		scalar.scalar_add(&check, &check, &r1)
		testing.expectf(t, scalar.scalar_eq(&check, &k), "r1 + lambda*r2 != k (%d)", i)

		// Both halves must be small in absolute value: either the value or its negation
		// fits in 128 bits. That is the whole point of the decomposition.
		testing.expectf(t, small_in_abs(&r1), "r1 is not small (%d)", i)
		testing.expectf(t, small_in_abs(&r2), "r2 is not small (%d)", i)
	}
}

/*
Reports whether a scalar or its negation fits in 128 bits.
*/
@(private = "file")
small_in_abs :: proc(s: ^scalar.Scalar) -> bool {
	fits :: proc(x: ^scalar.Scalar) -> bool {
		buf: [32]u8
		scalar.scalar_get_b32(&buf, x)
		for i in 0 ..< 16 {
			if buf[i] != 0 {
				return false
			}
		}
		return true
	}

	if fits(s) {
		return true
	}
	neg: scalar.Scalar
	scalar.scalar_negate(&neg, s)
	return fits(&neg)
}
