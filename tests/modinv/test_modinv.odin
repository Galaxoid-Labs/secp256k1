/*
Tests for the safegcd modular inversion, mirroring upstream's `run_modinv_tests`.

These exercise `modinv` directly against a modulus rather than through the field, which is
what catches bugs in the signed62 bookkeeping that a field-level test would mask. The field
and scalar moduli behave differently — p has a large run of set bits, n does not — so both
shapes are covered.
*/
package test_modinv

import "core:testing"
import "../../modinv"
import "../../params"
import "../../testutil"

/*
The field modulus p = 2^256 - 2^32 - 977 in signed62 form, with its inverse mod 2^62.
*/
MODINFO_P := modinv.Modinfo {
	modulus = {v = {-0x1000003d1, 0, 0, 0, 256}},
	modulus_inv62 = 0x27c7f6e22ddacacf,
}

/*
Converts a 256-bit value, given as four 64-bit little-endian words, into signed62 limbs.
*/
to_signed62 :: proc "contextless" (w: [4]u64) -> (r: modinv.Signed62) {
	m62 := modinv.M62
	r.v[0] = transmute(i64)(w[0] & m62)
	r.v[1] = transmute(i64)(((w[0] >> 62) | (w[1] << 2)) & m62)
	r.v[2] = transmute(i64)(((w[1] >> 60) | (w[2] << 4)) & m62)
	r.v[3] = transmute(i64)(((w[2] >> 58) | (w[3] << 6)) & m62)
	r.v[4] = transmute(i64)(w[3] >> 56)
	return
}

/*
Converts signed62 limbs back into four 64-bit little-endian words.
*/
from_signed62 :: proc "contextless" (s: modinv.Signed62) -> (w: [4]u64) {
	v0 := transmute(u64)s.v[0]
	v1 := transmute(u64)s.v[1]
	v2 := transmute(u64)s.v[2]
	v3 := transmute(u64)s.v[3]
	v4 := transmute(u64)s.v[4]

	w[0] = v0 | (v1 << 62)
	w[1] = (v1 >> 2) | (v2 << 60)
	w[2] = (v2 >> 4) | (v3 << 58)
	w[3] = (v3 >> 6) | (v4 << 56)
	return
}

/*
Multiplies two 256-bit values modulo p, using schoolbook arithmetic over `u128`.

Deliberately naive and independent of the `field` package, so that a shared bug in the
5x52 reduction cannot make a wrong inverse look right.
*/
mulmod_p :: proc(a, b: [4]u64) -> [4]u64 {
	// Full 512-bit product.
	prod: [8]u64
	for i in 0 ..< 4 {
		carry := u64(0)
		for j in 0 ..< 4 {
			t := u128(a[i]) * u128(b[j]) + u128(prod[i + j]) + u128(carry)
			prod[i + j] = u64(t)
			carry = u64(t >> 64)
		}
		prod[i + 4] += carry
	}

	// Fold the high half down using 2^256 = 2^32 + 977 (mod p), twice, then a final
	// conditional subtraction.
	R :: u128(0x1000003d1)
	acc: [5]u64
	carry := u128(0)
	for i in 0 ..< 4 {
		carry += u128(prod[i])
		acc[i] = u64(carry)
		carry >>= 64
	}
	acc[4] = u64(carry)

	for round in 0 ..< 2 {
		high := [4]u64{prod[4], prod[5], prod[6], prod[7]} if round == 0 else [4]u64{acc[4], 0, 0, 0}
		if round == 1 {
			acc[4] = 0
		}
		c := u128(0)
		for i in 0 ..< 4 {
			c += u128(acc[i]) + R * u128(high[i])
			acc[i] = u64(c)
			c >>= 64
		}
		acc[4] += u64(c)
	}

	res := [4]u64{acc[0], acc[1], acc[2], acc[3]}
	// Final conditional subtractions of p.
	P := [4]u64{0xffff_fffe_ffff_fc2f, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff}
	for _ in 0 ..< 2 {
		borrow := u128(0)
		tmp: [4]u64
		for i in 0 ..< 4 {
			d := u128(res[i]) - u128(P[i]) - borrow
			tmp[i] = u64(d)
			borrow = (d >> 127) & 1
		}
		if borrow == 0 {
			res = tmp
		}
	}
	return res
}

/*
Checks that inv(x) really is the inverse of x modulo p, using arithmetic that does not go
through the `field` package.
*/
check_inverse_mod_p :: proc(t: ^testing.T, x: [4]u64, label: string, index: int) {
	is_zero := x[0] | x[1] | x[2] | x[3] == 0

	s := to_signed62(x)
	modinv.modinv64(&s, &MODINFO_P)
	ct := from_signed62(s)

	sv := to_signed62(x)
	modinv.modinv64_var(&sv, &MODINFO_P)
	vt := from_signed62(sv)

	testing.expectf(t, ct == vt, "%s[%d]: modinv64 and modinv64_var disagree", label, index)

	if is_zero {
		testing.expectf(t, ct == [4]u64{}, "%s[%d]: inverse of zero is not zero", label, index)
		return
	}

	prod := mulmod_p(x, ct)
	testing.expectf(
		t,
		prod == [4]u64{1, 0, 0, 0},
		"%s[%d]: x * inv(x) = %v, want 1",
		label,
		index,
		prod,
	)
}

@(test)
test_run_modinv_tests :: proc(t: ^testing.T) {
	// Structured inputs: zero, small values, and values adjacent to the modulus, where
	// the normalization steps are most likely to be off by one.
	edge := [][4]u64 {
		{0, 0, 0, 0},
		{1, 0, 0, 0},
		{2, 0, 0, 0},
		{3, 0, 0, 0},
		{0x1000003d1, 0, 0, 0},
		{0xffff_fffe_ffff_fc2e, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff}, // p-1
		{0xffff_fffe_ffff_fc2d, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff}, // p-2
		{0, 0, 0, 0x8000_0000_0000_0000},
		{0xffff_ffff_ffff_ffff, 0, 0, 0},
		{0, 1, 0, 0},
	}
	for x, i in edge {
		check_inverse_mod_p(t, x, "edge", i)
	}

	// Random inputs.
	rng: testutil.Rand
	testutil.rand_seed(&rng, 0x5eed_1234)
	for i in 0 ..< params.COUNT * 2 {
		x: [4]u64
		for j in 0 ..< 4 {
			x[j] = testutil.rand_u64(&rng)
		}
		// Keep it below p by clearing the top bit occasionally; values >= p are also
		// legal inputs to the field path but modinv requires [0, modulus).
		x[3] &= 0x7fff_ffff_ffff_ffff
		check_inverse_mod_p(t, x, "random", i)
	}
}

@(test)
test_jacobi_agrees_with_euler :: proc(t: ^testing.T) {
	// For prime p, the Jacobi symbol equals the Legendre symbol, which is 1 exactly when
	// the value is a non-zero quadratic residue. Squares must therefore always report 1.
	rng: testutil.Rand
	testutil.rand_seed(&rng, 0x5eed_5678)

	residues := 0
	non_residues := 0
	unknown := 0

	for _ in 0 ..< params.COUNT {
		x: [4]u64
		for j in 0 ..< 4 {
			x[j] = testutil.rand_u64(&rng)
		}
		x[3] &= 0x7fff_ffff_ffff_ffff
		if x[0] | x[1] | x[2] | x[3] == 0 {
			continue
		}

		// The square of any value is a residue.
		sq := mulmod_p(x, x)
		if sq[0] | sq[1] | sq[2] | sq[3] == 0 {
			continue
		}

		s := to_signed62(sq)
		jac := modinv.jacobi64_maybe_var(&s, &MODINFO_P)

		switch jac {
		case 1:
			residues += 1
		case -1:
			non_residues += 1
		case 0:
			unknown += 1
		}

		testing.expectf(t, jac != -1, "a square was reported as a non-residue: %v", sq)
	}

	// Under -debug the iteration bound is deliberately low so the give-up path is
	// exercised; a 0 result there is expected and must not be read as "non-residue".
	testing.expect(t, residues > 0, "no squares were identified as residues")
	when !modinv.VERIFY {
		testing.expectf(t, unknown == 0, "jacobi failed to converge %d times in a release build", unknown)
	}
	_ = non_residues
}
