/*
ElligatorSwift: encoding curve points as uniformly random 64-byte strings.

Mirrors upstream's `modules/ellswift/main_impl.h`. Specified for BIP324 v2 transport.

# The problem it solves

A compressed public key is 33 bytes with a fixed prefix and an x coordinate that is
recognisably a curve point — trivially distinguishable from random. For a censorship-
resistant transport that is fatal: a network observer can fingerprint the handshake.

ElligatorSwift maps a curve point to a pair (u, t) of field elements, 64 bytes total, such
that the encoding is computationally indistinguishable from uniform random bytes. Decoding
is a direct formula; encoding searches for a preimage by trying random u values until one
admits a solution, which takes about four iterations on average.

# Decoding

Given (u, t), with c0 = sqrt(-3):

	if u = 0, set u = 1
	if t = 0, set s = 1, else s = t^2
	g = u^3 + 7
	if g + s = 0, set s = 4*s
	if x3 = (3*s*u^3 - (g+s)^2) / (3*s*u^2) is on the curve, return it
	if x2 = u*(c1*s + c2*g) / (g+s)      is on the curve, return it
	return x1 = -(x2 + u)

At least one of the three is always a valid x coordinate, which is what makes the map
total. The parity of y is taken from the parity of t.
*/
package ellswift

import "../field"
import "../group"
import "../hash"

/*
Constants derived from c0 = sqrt(-3):

	c1 = (sqrt(-3) - 1)/2
	c2 = (-sqrt(-3) - 1)/2 = -(c1 + 1)
	c3 = (-sqrt(-3) + 1)/2 = -c1 = c2 + 1
	c4 = (sqrt(-3) + 1)/2  = -c2 = c1 + 1

Note that c2 has the same value as the field's `BETA`, since both are built from the same
cube root of unity.
*/
C1, C2, C3, C4: field.Field_Elem

@(init, private)
init_constants :: proc "contextless" () {
	C1 = field.fe_const(
		0x851695d4, 0x9a83f8ef, 0x919bb861, 0x53cbcb16,
		0x630fb68a, 0xed0a766a, 0x3ec693d6, 0x8e6afa40,
	)
	C2 = field.fe_const(
		0x7ae96a2b, 0x657c0710, 0x6e64479e, 0xac3434e9,
		0x9cf04975, 0x12f58995, 0xc1396c28, 0x719501ee,
	)
	C3 = field.fe_const(
		0x7ae96a2b, 0x657c0710, 0x6e64479e, 0xac3434e9,
		0x9cf04975, 0x12f58995, 0xc1396c28, 0x719501ef,
	)
	C4 = field.fe_const(
		0x851695d4, 0x9a83f8ef, 0x919bb861, 0x53cbcb16,
		0x630fb68a, 0xed0a766a, 0x3ec693d6, 0x8e6afa41,
	)
}

/*
Decodes (u, t) to a curve x coordinate expressed as the fraction xn/xd.

Returning a fraction rather than a value lets the caller skip a field inversion when the
result feeds straight into an x-only ladder.
*/
xswiftec_frac_var :: proc "contextless" (
	xn: ^field.Field_Elem,
	xd: ^field.Field_Elem,
	u: ^field.Field_Elem,
	t: ^field.Field_Elem,
) {
	u1, s, g, p, d, n, l: field.Field_Elem

	u1 = u^
	if field.fe_normalizes_to_zero_var(&u1) {
		u1 = field.ONE
	}

	field.fe_sqr(&s, t)
	if field.fe_normalizes_to_zero_var(t) {
		s = field.ONE
	}

	field.fe_sqr(&l, &u1) // l = u^2
	field.fe_mul(&g, &l, &u1) // g = u^3
	field.fe_add_int(&g, group.CURVE_B) // g = u^3 + 7

	p = g
	field.fe_add(&p, &s) // p = g + s
	if field.fe_normalizes_to_zero_var(&p) {
		// g + s = 0 would make the second candidate's denominator vanish.
		field.fe_mul_int(&s, 4)
		p = g
		field.fe_add(&p, &s)
	}

	field.fe_mul(&d, &s, &l) // d = s*u^2
	field.fe_mul_int(&d, 3) // d = 3*s*u^2
	field.fe_sqr(&l, &p) // l = (g+s)^2
	field.fe_negate(&l, &l, 1) // l = -(g+s)^2
	field.fe_mul(&n, &d, &u1) // n = 3*s*u^3
	field.fe_add(&n, &l) // n = 3*s*u^3 - (g+s)^2

	if group.ge_x_frac_on_curve_var(&n, &d) {
		xn^ = n
		xd^ = d
		return
	}

	xd^ = p
	field.fe_mul(&l, &C1, &s) // l = c1*s
	field.fe_mul(&n, &C2, &g) // n = c2*g
	field.fe_add(&n, &l) // n = c1*s + c2*g
	field.fe_mul(&n, &n, &u1) // n = u*(c1*s + c2*g)

	if group.ge_x_frac_on_curve_var(&n, &p) {
		xn^ = n
		return
	}

	// The third candidate is guaranteed valid, so no test is needed.
	field.fe_mul(&l, &p, &u1) // l = u*(g+s)
	field.fe_add(&n, &l)
	field.fe_negate(xn, &n, 2)
}

/*
Decodes (u, t) to a curve x coordinate.
*/
xswiftec_var :: proc "contextless" (
	x: ^field.Field_Elem,
	u: ^field.Field_Elem,
	t: ^field.Field_Elem,
) {
	xn, xd: field.Field_Elem
	xswiftec_frac_var(&xn, &xd, u, t)
	field.fe_inv_var(&xd, &xd)
	field.fe_mul(x, &xn, &xd)
}

/*
Decodes (u, t) to a curve point.

The parity of y is taken from the parity of t, which is what makes the encoding cover both
halves of the curve.
*/
swiftec_var :: proc "contextless" (p: ^group.Ge, u: ^field.Field_Elem, t: ^field.Field_Elem) {
	x: field.Field_Elem
	xswiftec_var(&x, u, t)

	tn := t^
	field.fe_normalize_var(&tn)
	group.ge_set_xo_var(p, &x, field.fe_is_odd(&tn))
}

/*
Finds a t such that (u, t) decodes to x, for one of eight branches.

Returns false when this branch admits no solution, which is the normal case — the caller
tries successive (u, branch) pairs until one succeeds. The branch index selects which of
the decode formula's cases to invert and which square root to take.

`x` must be a valid curve x coordinate and `c` must be in [0, 8).
*/
xswiftec_inv_var :: proc "contextless" (
	t: ^field.Field_Elem,
	x_in: ^field.Field_Elem,
	u_in: ^field.Field_Elem,
	c: int,
) -> bool {
	x := x_in^
	u := u_in^
	g, v, s, m, r, q: field.Field_Elem

	field.fe_normalize_weak(&x)
	field.fe_normalize_weak(&u)

	if c & 2 == 0 {
		// Invert the x1/x2 cases.
		m = x
		field.fe_add(&m, &u) // m = u + x
		field.fe_negate(&m, &m, 2) // m = -u - x
		if group.ge_x_on_curve_var(&m) {
			// This x would have been produced by a different branch.
			return false
		}

		field.fe_sqr(&s, &m) // s = (u+x)^2
		field.fe_negate(&s, &s, 1) // s = -(u+x)^2
		field.fe_mul(&m, &u, &x) // m = u*x
		field.fe_add(&s, &m) // s = -(u^2 + u*x + x^2)

		field.fe_sqr(&g, &u)
		field.fe_mul(&g, &g, &u)
		field.fe_add_int(&g, group.CURVE_B) // g = u^3 + 7

		field.fe_mul(&m, &s, &g)
		if !field.fe_is_square_var(&m) {
			return false
		}

		field.fe_inv_var(&s, &s)
		field.fe_mul(&s, &s, &g) // s = -(u^3+7)/(u^2 + u*x + x^2)

		v = x
	} else {
		// Invert the x3 case.
		field.fe_negate(&m, &u, 1) // m = -u
		s = m
		field.fe_add(&s, &x) // s = x - u

		if !field.fe_is_square_var(&s) {
			return false
		}

		field.fe_sqr(&g, &u) // g = u^2
		field.fe_mul(&q, &s, &g)
		field.fe_mul_int(&q, 3) // q = 3*s*u^2
		field.fe_mul(&g, &g, &u) // g = u^3
		field.fe_mul_int(&g, 4)
		field.fe_add_int(&g, 4 * group.CURVE_B) // g = 4*(u^3+7)
		field.fe_add(&q, &g)
		field.fe_mul(&q, &q, &s)
		field.fe_negate(&q, &q, 1) // q = -s*(4*(u^3+7) + 3*u^2*s)

		if !field.fe_is_square_var(&q) {
			return false
		}
		field.fe_sqrt(&r, &q)

		if c & 1 != 0 && field.fe_normalizes_to_zero_var(&r) {
			// The two odd branches would coincide here.
			return false
		}
		if field.fe_normalizes_to_zero_var(&s) {
			return false
		}

		field.fe_inv_var(&v, &s)
		field.fe_mul(&v, &v, &r)
		field.fe_add(&v, &m)
		field.fe_half(&v) // v = (r/s - u)/2
	}

	field.fe_sqrt(&m, &s) // m = sqrt(s) = w

	// Branch bits 0 and 2 together select the sign of w.
	if (c & 5) == 0 || (c & 5) == 5 {
		field.fe_negate(&m, &m, 1)
	}

	if c & 1 != 0 {
		field.fe_mul(&u, &u, &C4)
	} else {
		field.fe_mul(&u, &u, &C3)
	}
	field.fe_add(&u, &v)
	field.fe_mul(t, &m, &u)
	return true
}

/*
Derives 32 pseudorandom bytes from a hasher state and a counter.

The hasher carries the caller's entropy; the counter walks the candidate space. Writing the
counter and finalizing triggers exactly one compression, so each candidate costs one block.
*/
@(private)
prng :: proc "contextless" (out32: ^[32]u8, hasher: ^hash.Sha256, cnt: u32) {
	h := hasher^
	buf4 := [4]u8{u8(cnt), u8(cnt >> 8), u8(cnt >> 16), u8(cnt >> 24)}
	hash.sha256_write(&h, buf4[:])
	hash.sha256_finalize(&h, out32)
}

/*
Finds an ElligatorSwift encoding (u, t) for a given curve x coordinate.

Candidate u values and branch selectors are drawn from the hasher. Each (u, branch) pair
succeeds with probability roughly 1/4, so this terminates in about four iterations; the
loop is unbounded because there is no useful bound to impose, and failure is not possible
in aggregate.
*/
xelligatorswift_var :: proc "contextless" (
	u32_out: ^[32]u8,
	t: ^field.Field_Elem,
	x: ^field.Field_Elem,
	hasher: ^hash.Sha256,
) {
	branch_hash: [32]u8
	branches_left := 0
	cnt := u32(0)

	for {
		// Refill the pool of branch selectors when it runs out.
		if branches_left == 0 {
			prng(&branch_hash, hasher, cnt)
			cnt += 1
			branches_left = 64
		}

		branches_left -= 1
		branch := int((branch_hash[branches_left >> 1] >> uint((branches_left & 1) << 2)) & 7)

		prng(u32_out, hasher, cnt)
		cnt += 1

		u: field.Field_Elem
		// Reduction rather than rejection: a uniform 32-byte string matters more than a
		// uniform field element, since the bytes are what goes on the wire.
		field.fe_set_b32_mod(&u, u32_out)

		if xswiftec_inv_var(t, x, &u, branch) {
			return
		}
	}
}

/*
Finds an ElligatorSwift encoding for a full curve point.

The sign of t is adjusted so that its parity matches y's, which is how the decoder recovers
the correct half of the curve.
*/
elligatorswift_var :: proc "contextless" (
	u32_out: ^[32]u8,
	t: ^field.Field_Elem,
	p: ^group.Ge,
	hasher: ^hash.Sha256,
) {
	pt := p^
	field.fe_normalize_var(&pt.x)
	field.fe_normalize_var(&pt.y)

	xelligatorswift_var(u32_out, t, &pt.x, hasher)

	field.fe_normalize_var(t)
	if field.fe_is_odd(t) != field.fe_is_odd(&pt.y) {
		field.fe_negate(t, t, 1)
		field.fe_normalize_var(t)
	}
}

/*
Decodes a 64-byte ElligatorSwift encoding to a public key.

Every 64-byte string decodes to some point, which is exactly what makes the encoding
indistinguishable from random: there is no invalid input to reject and therefore nothing
for an observer to probe.
*/
decode :: proc "contextless" (pubkey: ^group.Ge, ell64: ^[64]u8) -> bool {
	u, t: field.Field_Elem
	u_bytes := (^[32]u8)(&ell64[0])
	t_bytes := (^[32]u8)(&ell64[32])

	field.fe_set_b32_mod(&u, u_bytes)
	field.fe_set_b32_mod(&t, t_bytes)
	swiftec_var(pubkey, &u, &t)
	return true
}

/*
Encodes a public key as a 64-byte ElligatorSwift string.

`rnd32` supplies the entropy that selects among the many valid encodings of the same point.
Two encodings of the same key under different randomness are unlinkable, which is the
property BIP324 relies on.
*/
encode :: proc "contextless" (ell64: ^[64]u8, pubkey: ^group.Ge, rnd32: ^[32]u8) {
	hasher: hash.Sha256
	tag := "secp256k1_ellswift_encode"
	hash.sha256_initialize_tagged(&hasher, transmute([]u8)tag)

	// Bind the encoding to the key being encoded as well as to the randomness, so the
	// candidate stream cannot be reused across keys.
	p := pubkey^
	field.fe_normalize_var(&p.x)
	field.fe_normalize_var(&p.y)

	pk33: [33]u8
	pk33[0] = 0x03 if field.fe_is_odd(&p.y) else 0x02
	xb := (^[32]u8)(&pk33[1])
	field.fe_get_b32(xb, &p.x)

	hash.sha256_write(&hasher, pk33[:])
	hash.sha256_write(&hasher, rnd32[:])

	u_out := (^[32]u8)(&ell64[0])
	t: field.Field_Elem
	elligatorswift_var(u_out, &t, &p, &hasher)

	t_out := (^[32]u8)(&ell64[32])
	field.fe_normalize_var(&t)
	field.fe_get_b32(t_out, &t)

	hash.sha256_clear(&hasher)
}
