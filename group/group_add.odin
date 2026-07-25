/*
Point addition and doubling.

Two families, and the difference matters for security rather than just speed:

  - `gej_add_ge` is the **constant-time** unified add/double. It computes the same sequence
    of field operations regardless of whether the inputs are equal, opposite, or infinite,
    and patches up the degenerate cases with conditional moves. Secret-dependent point
    arithmetic must use this.

  - `gej_add_*_var` and `gej_double_var` branch on the inputs and are faster. They are for
    public data only — verification, table construction, tests.

Mirrors upstream's `group_impl.h`. The magnitude produced by each step is noted in the
right-hand comments, because the formulas are written to stay inside the `GEJ_*_MAGNITUDE`
limits and there is no other way to see that by inspection.
*/
package group

import "../field"

/*
Sets r to 2*a.

For secp256k1 proper, 2Q is infinity only when Q is, since y = 0 would require x^3 = -b and
-7 has no cube root modulo p. That is why no special case is needed here. A point on a
sextic twist — reachable only by fault injection — can violate this, in which case the
result is gibberish with z = 0 but the infinity flag clear.

Formula:

	L  = (3/2) * X1^2
	S  = Y1^2
	T  = -X1*S
	X3 = L^2 + 2*T
	Y3 = -(L*(X3 + T) + S^2)
	Z3 = Y1*Z1
*/
gej_double :: proc "contextless" (r: ^Gej, a: ^Gej) {
	gej_verify(a)

	r.infinity = a.infinity

	l, s, t: field.Field_Elem

	field.fe_mul(&r.z, &a.z, &a.y) // Z3 = Y1*Z1        (1)
	field.fe_sqr(&s, &a.y) // S = Y1^2                  (1)
	field.fe_sqr(&l, &a.x) // L = X1^2                  (1)
	field.fe_mul_int(&l, 3) // L = 3*X1^2               (3)
	field.fe_half(&l) // L = 3/2*X1^2                   (2)
	field.fe_negate(&t, &s, 1) // T = -S                (2)
	field.fe_mul(&t, &t, &a.x) // T = -X1*S             (1)
	field.fe_sqr(&r.x, &l) // X3 = L^2                  (1)
	field.fe_add(&r.x, &t) // X3 = L^2 + T              (2)
	field.fe_add(&r.x, &t) // X3 = L^2 + 2*T            (3)
	field.fe_sqr(&s, &s) // S' = S^2                    (1)
	field.fe_add(&t, &r.x) // T' = X3 + T               (4)
	field.fe_mul(&r.y, &t, &l) // Y3 = L*(X3 + T)       (1)
	field.fe_add(&r.y, &s) // Y3 = L*(X3 + T) + S^2     (2)
	field.fe_negate(&r.y, &r.y, 2) // Y3 = -(...)       (3)

	gej_verify(r)
}

/*
Sets r to 2*a, handling infinity explicitly and optionally reporting the Z ratio.

When `rzr` is non-nil it receives the factor by which Z was multiplied, which the table
builders use to keep a chain of points on a shared Z.

Variable-time in whether a is infinity. Never call this on secret data.
*/
gej_double_var :: proc "contextless" (r: ^Gej, a: ^Gej, rzr: ^field.Field_Elem) {
	gej_verify(a)

	if a.infinity {
		gej_set_infinity(r)
		if rzr != nil {
			field.fe_set_int(rzr, 1)
		}
		return
	}

	if rzr != nil {
		rzr^ = a.y
		field.fe_normalize_weak(rzr)
	}

	gej_double(r, a)
	gej_verify(r)
}

/*
Sets r to a + b, both in Jacobian coordinates.

Variable-time: branches on whether either input is infinity and on whether the points are
equal or opposite. Never call this on secret data.
*/
gej_add_var :: proc "contextless" (r: ^Gej, a: ^Gej, b: ^Gej, rzr: ^field.Field_Elem) {
	gej_verify(a)
	gej_verify(b)

	if a.infinity {
		CHECK(rzr == nil, "gej_add_var: rzr is meaningless when a is infinity")
		r^ = b^
		return
	}
	if b.infinity {
		if rzr != nil {
			field.fe_set_int(rzr, 1)
		}
		r^ = a^
		return
	}

	z22, z12, u1, u2, s1, s2, h, i, h2, h3, t: field.Field_Elem

	field.fe_sqr(&z22, &b.z)
	field.fe_sqr(&z12, &a.z)
	field.fe_mul(&u1, &a.x, &z22)
	field.fe_mul(&u2, &b.x, &z12)
	field.fe_mul(&s1, &a.y, &z22)
	field.fe_mul(&s1, &s1, &b.z)
	field.fe_mul(&s2, &b.y, &z12)
	field.fe_mul(&s2, &s2, &a.z)
	field.fe_negate(&h, &u1, 1)
	field.fe_add(&h, &u2) // h = U2 - U1
	field.fe_negate(&i, &s2, 1)
	field.fe_add(&i, &s1) // i = S1 - S2

	if field.fe_normalizes_to_zero_var(&h) {
		// x coordinates agree: the points are equal or opposite.
		if field.fe_normalizes_to_zero_var(&i) {
			gej_double_var(r, a, rzr)
		} else {
			if rzr != nil {
				field.fe_set_int(rzr, 0)
			}
			gej_set_infinity(r)
		}
		return
	}

	r.infinity = false
	field.fe_mul(&t, &h, &b.z)
	if rzr != nil {
		rzr^ = t
	}
	field.fe_mul(&r.z, &a.z, &t)

	field.fe_sqr(&h2, &h)
	field.fe_negate(&h2, &h2, 1)
	field.fe_mul(&h3, &h2, &h)
	field.fe_mul(&t, &u1, &h2)

	field.fe_sqr(&r.x, &i)
	field.fe_add(&r.x, &h3)
	field.fe_add(&r.x, &t)
	field.fe_add(&r.x, &t)

	field.fe_add(&t, &r.x)
	field.fe_mul(&r.y, &t, &i)
	field.fe_mul(&h3, &h3, &s1)
	field.fe_add(&r.y, &h3)

	gej_verify(r)
}

/*
Sets r to a + b, where b is affine.

Cheaper than `gej_add_var` because b's Z is known to be 1. Variable-time; never call this
on secret data.
*/
gej_add_ge_var :: proc "contextless" (r: ^Gej, a: ^Gej, b: ^Ge, rzr: ^field.Field_Elem) {
	gej_verify(a)
	ge_verify(b)

	if a.infinity {
		CHECK(rzr == nil, "gej_add_ge_var: rzr is meaningless when a is infinity")
		gej_set_ge(r, b)
		return
	}
	if b.infinity {
		if rzr != nil {
			field.fe_set_int(rzr, 1)
		}
		r^ = a^
		return
	}

	z12, u1, u2, s1, s2, h, i, h2, h3, t: field.Field_Elem

	field.fe_sqr(&z12, &a.z)
	u1 = a.x
	field.fe_mul(&u2, &b.x, &z12)
	s1 = a.y
	field.fe_mul(&s2, &b.y, &z12)
	field.fe_mul(&s2, &s2, &a.z)
	field.fe_negate(&h, &u1, GEJ_X_MAGNITUDE_MAX)
	field.fe_add(&h, &u2)
	field.fe_negate(&i, &s2, 1)
	field.fe_add(&i, &s1)

	if field.fe_normalizes_to_zero_var(&h) {
		if field.fe_normalizes_to_zero_var(&i) {
			gej_double_var(r, a, rzr)
		} else {
			if rzr != nil {
				field.fe_set_int(rzr, 0)
			}
			gej_set_infinity(r)
		}
		return
	}

	r.infinity = false
	if rzr != nil {
		rzr^ = h
	}
	field.fe_mul(&r.z, &a.z, &h)

	field.fe_sqr(&h2, &h)
	field.fe_negate(&h2, &h2, 1)
	field.fe_mul(&h3, &h2, &h)
	field.fe_mul(&t, &u1, &h2)

	field.fe_sqr(&r.x, &i)
	field.fe_add(&r.x, &h3)
	field.fe_add(&r.x, &t)
	field.fe_add(&r.x, &t)

	field.fe_add(&t, &r.x)
	field.fe_mul(&r.y, &t, &i)
	field.fe_mul(&h3, &h3, &s1)
	field.fe_add(&r.y, &h3)

	gej_verify(r)
	when VERIFY {
		if rzr != nil {
			field.fe_verify(rzr)
		}
	}
}

/*
Sets r to a + b, where b is affine and given with the inverse of its Z coordinate.

Uses the isomorphism that lets both sides be scaled by bzinv, so b behaves as though its Z
were 1 without an inversion. Variable-time; never call this on secret data.
*/
gej_add_zinv_var :: proc "contextless" (r: ^Gej, a: ^Gej, b: ^Ge, bzinv: ^field.Field_Elem) {
	gej_verify(a)
	ge_verify(b)
	when VERIFY {
		field.fe_verify(bzinv)
	}

	if a.infinity {
		bzinv2, bzinv3: field.Field_Elem
		r.infinity = b.infinity
		field.fe_sqr(&bzinv2, bzinv)
		field.fe_mul(&bzinv3, &bzinv2, bzinv)
		field.fe_mul(&r.x, &b.x, &bzinv2)
		field.fe_mul(&r.y, &b.y, &bzinv3)
		field.fe_set_int(&r.z, 1)
		gej_verify(r)
		return
	}
	if b.infinity {
		r^ = a^
		return
	}

	// (rx,ry,rz) = (ax,ay,az) + (bx,by,1/bzinv). Multiplying the Z coordinates on both
	// sides by bzinv gives (rx,ry,rz*bzinv) = (ax,ay,az*bzinv) + (bx,by,1), so using
	// az*bzinv for x and y — but not for rz — produces the right answer.
	az: field.Field_Elem
	field.fe_mul(&az, &a.z, bzinv)

	z12, u1, u2, s1, s2, h, i, h2, h3, t: field.Field_Elem

	field.fe_sqr(&z12, &az)
	u1 = a.x
	field.fe_mul(&u2, &b.x, &z12)
	s1 = a.y
	field.fe_mul(&s2, &b.y, &z12)
	field.fe_mul(&s2, &s2, &az)
	field.fe_negate(&h, &u1, GEJ_X_MAGNITUDE_MAX)
	field.fe_add(&h, &u2)
	field.fe_negate(&i, &s2, 1)
	field.fe_add(&i, &s1)

	if field.fe_normalizes_to_zero_var(&h) {
		if field.fe_normalizes_to_zero_var(&i) {
			gej_double_var(r, a, nil)
		} else {
			gej_set_infinity(r)
		}
		return
	}

	r.infinity = false
	field.fe_mul(&r.z, &a.z, &h)

	field.fe_sqr(&h2, &h)
	field.fe_negate(&h2, &h2, 1)
	field.fe_mul(&h3, &h2, &h)
	field.fe_mul(&t, &u1, &h2)

	field.fe_sqr(&r.x, &i)
	field.fe_add(&r.x, &h3)
	field.fe_add(&r.x, &t)
	field.fe_add(&r.x, &t)

	field.fe_add(&t, &r.x)
	field.fe_mul(&r.y, &t, &i)
	field.fe_mul(&h3, &h3, &s1)
	field.fe_add(&r.y, &h3)

	gej_verify(r)
}

/*
Sets r to a + b, where b is affine, in **constant time**.

This is the addition used on secret data. `b` must not be infinity.

The unified formula comes from Brier and Joye, "Weierstrass Elliptic Curves and
Side-Channel Attacks":

	lambda = ((x1 + x2)^2 - x1*x2 + a) / (y1 + y2)    with a = 0 for this curve
	x3     = lambda^2 - (x1 + x2)
	2*y3   = lambda * (x1 + x2 - 2*x3) - (y1 + y2)

In Jacobian coordinates:

	U1 = X1*Z2^2, U2 = X2*Z1^2, S1 = Y1*Z2^3, S2 = Y2*Z1^3
	Z = Z1*Z2, T = U1+U2, M = S1+S2
	Q = -T*M^2, R = T^2-U1*U2
	X3 = R^2+Q, Y3 = -(R*(2*X3+Q)+M^4)/2, Z3 = M*Z

The same expression covers both addition and doubling, which is what makes it
constant-time. It breaks down in three ways, each handled without branching:

  - **a is infinity.** The computation runs anyway and produces garbage, then the result is
    replaced with b by conditional move.
  - **a = -b.** The answer is infinity, and setting the infinity flag overrides the computed
    coordinates without needing a move.
  - **y1 = -y2 with x1 != x2.** Possible here because 1 has nontrivial cube roots in this
    field and the curve has no x term. M = 0 makes lambda indeterminate, so an alternative
    expression (y1 - y2)/(x1 - x2) is conditionally moved into place. Wherever both forms
    are defined they agree, and for any pair of non-zero points at least one is defined.
*/
gej_add_ge :: proc "contextless" (r: ^Gej, a: ^Gej, b: ^Ge) {
	gej_verify(a)
	ge_verify(b)
	CHECK(!b.infinity, "gej_add_ge: b must not be infinity")

	zz, u1, u2, s1, s2, t, tt, m, n, q, rr: field.Field_Elem
	m_alt, rr_alt: field.Field_Elem

	field.fe_sqr(&zz, &a.z) // zz = Z1^2
	u1 = a.x // u1 = U1 = X1*Z2^2       (GEJ_X_M)
	field.fe_mul(&u2, &b.x, &zz) // u2 = U2 = X2*Z1^2  (1)
	s1 = a.y // s1 = S1 = Y1*Z2^3       (GEJ_Y_M)
	field.fe_mul(&s2, &b.y, &zz) // s2 = Y2*Z1^2       (1)
	field.fe_mul(&s2, &s2, &a.z) // s2 = S2 = Y2*Z1^3  (1)
	t = u1
	field.fe_add(&t, &u2) // t = T = U1+U2             (GEJ_X_M+1)
	m = s1
	field.fe_add(&m, &s2) // m = M = S1+S2             (GEJ_Y_M+1)
	field.fe_sqr(&rr, &t) // rr = T^2                  (1)
	field.fe_negate(&m_alt, &u2, 1) // Malt = -X2*Z1^2 (2)
	field.fe_mul(&tt, &u1, &m_alt) // tt = -U1*U2      (1)
	field.fe_add(&rr, &tt) // rr = R = T^2-U1*U2       (2)

	// lambda = R/M is indeterminate when M = 0, except in the trivial Z = 0 case which is
	// special-cased at the end.
	degenerate := field.fe_normalizes_to_zero(&m)

	// The degenerate case occurs when y1 == -y2 and x1^3 == x2^3 but x1 != x2, meaning
	// x1 == beta*x2 or beta*x1 == x2. There lambda = (y1 - y2)/(x1 - x2) instead.
	rr_alt = s1
	field.fe_mul_int(&rr_alt, 2) // rr_alt = Y1*Z2^3 - Y2*Z1^3  (GEJ_Y_M*2)
	field.fe_add(&m_alt, &u1) // Malt = X1*Z2^2 - X2*Z1^2       (GEJ_X_M+2)

	field.fe_cmov(&rr_alt, &rr, !degenerate)
	field.fe_cmov(&m_alt, &m, !degenerate)

	// From here rr_alt/m_alt is lambda, guaranteed to have a non-zero denominator.
	field.fe_sqr(&n, &m_alt) // n = Malt^2                       (1)
	field.fe_negate(&q, &t, GEJ_X_MAGNITUDE_MAX + 1) // q = -T   (GEJ_X_M+2)
	field.fe_mul(&q, &q, &n) // q = Q = -T*Malt^2                (1)

	// Either M == Malt or M == 0, so M^3 * Malt is either Malt^4 — one squaring — or zero,
	// which a conditional move supplies. That saves a multiplication over computing it
	// directly.
	field.fe_sqr(&n, &n) // n = Malt^4                           (1)
	field.fe_cmov(&n, &m, degenerate) // n = M^3 * Malt          (GEJ_Y_M+1)
	field.fe_sqr(&t, &rr_alt) // t = Ralt^2                      (1)
	field.fe_mul(&r.z, &a.z, &m_alt) // Z3 = Malt*Z              (1)
	field.fe_add(&t, &q) // t = Ralt^2 + Q                       (2)
	r.x = t // X3 = Ralt^2 + Q                                   (2)
	field.fe_mul_int(&t, 2) // t = 2*X3                          (4)
	field.fe_add(&t, &q) // t = 2*X3 + Q                         (5)
	field.fe_mul(&t, &t, &rr_alt) // t = Ralt*(2*X3 + Q)         (1)
	field.fe_add(&t, &n) // t = Ralt*(2*X3 + Q) + M^3*Malt       (GEJ_Y_M+2)
	field.fe_negate(&r.y, &t, GEJ_Y_MAGNITUDE_MAX + 2) //        (GEJ_Y_M+3)
	field.fe_half(&r.y) // Y3 = -(...)/2                         ((GEJ_Y_M+3)/2 + 1)

	// If a was infinity, replace the garbage with (b.x, b.y, 1).
	field.fe_cmov(&r.x, &b.x, a.infinity)
	field.fe_cmov(&r.y, &b.y, a.infinity)
	field.fe_cmov(&r.z, &field.ONE, a.infinity)

	// r is infinity exactly when Z3 is zero.
	//
	// If a was infinity then r.z is 1, so this is false — correct, since b is not
	// infinity by contract.
	//
	// Otherwise Z = Z1 != 0. When y1 = -y2 we may have a = -b, namely if x1 = x2; there
	// degenerate holds and r.z = (x1 - x2)*Z, so r is infinity exactly when x1 = x2, that
	// is when a = -b. When y1 != -y2 we cannot have a = -b, and r.z = (y1 + y2)*Z is
	// non-zero.
	r.infinity = field.fe_normalizes_to_zero(&r.z)

	gej_verify(r)
}
