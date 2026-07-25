/*
Group operations on the secp256k1 curve, y^2 = x^3 + b.

Two representations:

  - `Ge`  — affine (x, y), used for stored points and table entries.
  - `Gej` — Jacobian (X, Y, Z) where x = X/Z^2 and y = Y/Z^3, used for accumulation, since
            addition in Jacobian coordinates needs no field inversion.

Both carry an explicit `infinity` flag rather than encoding the point at infinity as Z=0,
because the constant-time addition formula needs to compute *something* for infinity inputs
and patch the result afterwards.

Mirrors upstream's `group_impl.h`. For the exhaustive test configuration the curve is
replaced by a small-order curve over the same field, which is why `b` comes from `params`
rather than being written as a literal here.

# Magnitude limits

Group coordinates are field elements with bounded magnitude, and the bounds differ between
the two representations. They are stated once, as constants, and enforced by `ge_verify`
and `gej_verify`; every formula below is annotated with the magnitude it produces so the
bounds can be checked by reading.
*/
package group

import "core:mem"
import "base:runtime"
import "../field"
import "../params"

/*
Whether internal invariant checks are compiled in. Follows `-debug`.
*/
VERIFY :: ODIN_DEBUG

/*
Maximum magnitudes for affine and Jacobian coordinates.

These are not arbitrary: they are the tightest bounds every routine below is proven to
respect, and the addition formulas are written to stay inside them. Raising one to silence
an assertion would hide a real overflow.
*/
GE_X_MAGNITUDE_MAX :: 4
GE_Y_MAGNITUDE_MAX :: 3
GEJ_X_MAGNITUDE_MAX :: 4
GEJ_Y_MAGNITUDE_MAX :: 4
GEJ_Z_MAGNITUDE_MAX :: 1

/*
The curve's b coefficient, from the active configuration. 7 for the real curve.
*/
CURVE_B :: params.CURVE_B

/*
A point in affine coordinates, or the point at infinity.

Also used for points on the isomorphic curve y^2 = x^3 + b*t^6 that arise inside the
multiplication engines.
*/
Ge :: struct {
	x, y:     field.Field_Elem,
	infinity: bool,
}

/*
A point in Jacobian coordinates: x = X/Z^2, y = Y/Z^3.
*/
Gej :: struct {
	x, y, z:  field.Field_Elem,
	infinity: bool,
}

/*
An affine point in packed storage form, for precomputed tables.

Carries no infinity flag: tables never contain it.
*/
Ge_Storage :: struct {
	x, y: field.Field_Storage,
}

@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "group invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(condition, message, loc)
	}
}

/*
Asserts that an affine point's coordinates are within their magnitude limits.
*/
ge_verify :: #force_inline proc "contextless" (a: ^Ge, loc := #caller_location) {
	when VERIFY {
		field.fe_verify(&a.x, loc)
		field.fe_verify(&a.y, loc)
		field.fe_verify_magnitude(&a.x, GE_X_MAGNITUDE_MAX, loc)
		field.fe_verify_magnitude(&a.y, GE_Y_MAGNITUDE_MAX, loc)
	}
}

/*
Asserts that a Jacobian point's coordinates are within their magnitude limits.
*/
gej_verify :: #force_inline proc "contextless" (a: ^Gej, loc := #caller_location) {
	when VERIFY {
		field.fe_verify(&a.x, loc)
		field.fe_verify(&a.y, loc)
		field.fe_verify(&a.z, loc)
		field.fe_verify_magnitude(&a.x, GEJ_X_MAGNITUDE_MAX, loc)
		field.fe_verify_magnitude(&a.y, GEJ_Y_MAGNITUDE_MAX, loc)
		field.fe_verify_magnitude(&a.z, GEJ_Z_MAGNITUDE_MAX, loc)
	}
}

/*
Sets r to the point with the given coordinates. No curve check is performed.
*/
ge_set_xy :: #force_inline proc "contextless" (r: ^Ge, x: ^field.Field_Elem, y: ^field.Field_Elem) {
	when VERIFY {
		field.fe_verify(x)
		field.fe_verify(y)
	}
	r.infinity = false
	r.x = x^
	r.y = y^
	ge_verify(r)
}

/*
Sets r to the point at infinity.
*/
ge_set_infinity :: proc "contextless" (r: ^Ge) {
	r.infinity = true
	field.fe_set_int(&r.x, 0)
	field.fe_set_int(&r.y, 0)
	ge_verify(r)
}

/*
Sets r to the point at infinity.
*/
gej_set_infinity :: proc "contextless" (r: ^Gej) {
	r.infinity = true
	field.fe_set_int(&r.x, 0)
	field.fe_set_int(&r.y, 0)
	field.fe_set_int(&r.z, 0)
	gej_verify(r)
}

/*
Reports whether a is the point at infinity.
*/
ge_is_infinity :: #force_inline proc "contextless" (a: ^Ge) -> bool {
	ge_verify(a)
	return a.infinity
}

/*
Reports whether a is the point at infinity.
*/
gej_is_infinity :: #force_inline proc "contextless" (a: ^Gej) -> bool {
	gej_verify(a)
	return a.infinity
}

/*
Zeroes a point so that secret material does not outlive its use.
*/
ge_clear :: proc "contextless" (r: ^Ge) {
	mem.zero_explicit(r, size_of(Ge))
}

/*
Zeroes a point so that secret material does not outlive its use.
*/
gej_clear :: proc "contextless" (r: ^Gej) {
	mem.zero_explicit(r, size_of(Gej))
}

/*
Sets r to -a, the point mirrored across the x axis.
*/
ge_neg :: #force_inline proc "contextless" (r: ^Ge, a: ^Ge) {
	ge_verify(a)
	r^ = a^
	field.fe_normalize_weak(&r.y)
	field.fe_negate(&r.y, &r.y, 1)
	ge_verify(r)
}

/*
Sets r to -a.
*/
gej_neg :: #force_inline proc "contextless" (r: ^Gej, a: ^Gej) {
	gej_verify(a)
	r.infinity = a.infinity
	r.x = a.x
	r.y = a.y
	r.z = a.z
	field.fe_normalize_weak(&r.y)
	field.fe_negate(&r.y, &r.y, 1)
	gej_verify(r)
}

/*
Lifts an affine point into Jacobian coordinates with Z = 1.
*/
gej_set_ge :: #force_inline proc "contextless" (r: ^Gej, a: ^Ge) {
	ge_verify(a)
	r.infinity = a.infinity
	r.x = a.x
	r.y = a.y
	field.fe_set_int(&r.z, 1)
	gej_verify(r)
}

/*
Sets r to the affine form of the Jacobian point (a.x, a.y, 1/zi).

`a` must not be infinity, and zi must be the inverse of a's Z coordinate.
*/
ge_set_gej_zinv :: #force_inline proc "contextless" (r: ^Ge, a: ^Gej, zi: ^field.Field_Elem) {
	gej_verify(a)
	when VERIFY {
		field.fe_verify(zi)
	}
	CHECK(!a.infinity, "ge_set_gej_zinv: input is infinity")

	zi2, zi3: field.Field_Elem
	field.fe_sqr(&zi2, zi)
	field.fe_mul(&zi3, &zi2, zi)
	field.fe_mul(&r.x, &a.x, &zi2)
	field.fe_mul(&r.y, &a.y, &zi3)
	r.infinity = a.infinity

	ge_verify(r)
}

/*
Rescales an affine point by a Z inverse, as `ge_set_gej_zinv` but from affine input.
*/
ge_set_ge_zinv :: #force_inline proc "contextless" (r: ^Ge, a: ^Ge, zi: ^field.Field_Elem) {
	ge_verify(a)
	when VERIFY {
		field.fe_verify(zi)
	}
	CHECK(!a.infinity, "ge_set_ge_zinv: input is infinity")

	zi2, zi3: field.Field_Elem
	field.fe_sqr(&zi2, zi)
	field.fe_mul(&zi3, &zi2, zi)
	field.fe_mul(&r.x, &a.x, &zi2)
	field.fe_mul(&r.y, &a.y, &zi3)
	r.infinity = a.infinity

	ge_verify(r)
}

/*
Converts a Jacobian point to affine, in constant time.

`a` is modified in place — its Z is inverted and its coordinates normalized — which is how
upstream avoids a second temporary. Infinity is propagated but its coordinates are
meaningless.
*/
ge_set_gej :: proc "contextless" (r: ^Ge, a: ^Gej) {
	gej_verify(a)

	r.infinity = a.infinity
	field.fe_inv(&a.z, &a.z)

	z2, z3: field.Field_Elem
	field.fe_sqr(&z2, &a.z)
	field.fe_mul(&z3, &a.z, &z2)
	field.fe_mul(&a.x, &a.x, &z2)
	field.fe_mul(&a.y, &a.y, &z3)
	field.fe_set_int(&a.z, 1)
	r.x = a.x
	r.y = a.y

	gej_verify(a)
	ge_verify(r)
}

/*
Converts a Jacobian point to affine, in variable time.

Never call this on secret data.
*/
ge_set_gej_var :: proc "contextless" (r: ^Ge, a: ^Gej) {
	gej_verify(a)

	if gej_is_infinity(a) {
		ge_set_infinity(r)
		return
	}

	r.infinity = false
	field.fe_inv_var(&a.z, &a.z)

	z2, z3: field.Field_Elem
	field.fe_sqr(&z2, &a.z)
	field.fe_mul(&z3, &a.z, &z2)
	field.fe_mul(&a.x, &a.x, &z2)
	field.fe_mul(&a.y, &a.y, &z3)
	field.fe_set_int(&a.z, 1)
	ge_set_xy(r, &a.x, &a.y)

	gej_verify(a)
	ge_verify(r)
}

/*
Converts many Jacobian points to affine using a single field inversion.

Montgomery's trick: accumulate the running product of Z values, invert once, then walk
backwards recovering each individual inverse. Inversion dominates the cost of the naive
approach, so this turns len inversions into one plus 3*len multiplications.

None of the inputs may be infinity; use `ge_set_all_gej_var` when they might be.
*/
ge_set_all_gej :: proc "contextless" (r: []Ge, a: []Gej) {
	CHECK(len(r) >= len(a), "ge_set_all_gej: destination too small")
	when VERIFY {
		for i in 0 ..< len(a) {
			gej_verify(&a[i])
			CHECK(!a[i].infinity, "ge_set_all_gej: input is infinity")
		}
	}

	length := len(a)
	if length == 0 {
		return
	}

	// Use the destination's x coordinates as scratch for the running products.
	r[0].x = a[0].z
	for i in 1 ..< length {
		field.fe_mul(&r[i].x, &r[i - 1].x, &a[i].z)
	}

	u: field.Field_Elem
	field.fe_inv(&u, &r[length - 1].x)

	for i := length - 1; i > 0; i -= 1 {
		field.fe_mul(&r[i].x, &r[i - 1].x, &u)
		field.fe_mul(&u, &u, &a[i].z)
	}
	r[0].x = u

	for i in 0 ..< length {
		ge_set_gej_zinv(&r[i], &a[i], &r[i].x)
	}

	when VERIFY {
		for i in 0 ..< length {
			ge_verify(&r[i])
		}
	}
}

/*
Converts many Jacobian points to affine using a single inversion, skipping infinities.

Variable-time in which inputs are infinity. Never call this on secret data.
*/
ge_set_all_gej_var :: proc "contextless" (r: []Ge, a: []Gej) {
	CHECK(len(r) >= len(a), "ge_set_all_gej_var: destination too small")
	when VERIFY {
		for i in 0 ..< len(a) {
			gej_verify(&a[i])
		}
	}

	length := len(a)
	last := -1

	for i in 0 ..< length {
		if a[i].infinity {
			ge_set_infinity(&r[i])
		} else {
			if last == -1 {
				r[i].x = a[i].z
			} else {
				field.fe_mul(&r[i].x, &r[last].x, &a[i].z)
			}
			last = i
		}
	}
	if last == -1 {
		return
	}

	u: field.Field_Elem
	field.fe_inv_var(&u, &r[last].x)

	i := last
	for i > 0 {
		i -= 1
		if !a[i].infinity {
			field.fe_mul(&r[last].x, &r[i].x, &u)
			field.fe_mul(&u, &u, &a[last].z)
			last = i
		}
	}
	CHECK(!a[last].infinity, "ge_set_all_gej_var: bookkeeping error")
	r[last].x = u

	for j in 0 ..< length {
		if !a[j].infinity {
			ge_set_gej_zinv(&r[j], &a[j], &r[j].x)
		}
	}

	when VERIFY {
		for j in 0 ..< length {
			ge_verify(&r[j])
		}
	}
}

/*
Brings a table of affine points onto a common Z, given the ratios between successive Z
values.

Used by the multiplication engines, which produce points sharing a Z chain rather than
independent ones.
*/
ge_table_set_globalz :: proc "contextless" (a: []Ge, zr: []field.Field_Elem) {
	length := len(a)
	CHECK(len(zr) >= length, "ge_table_set_globalz: ratio slice too small")
	when VERIFY {
		for i in 0 ..< length {
			ge_verify(&a[i])
			field.fe_verify(&zr[i])
		}
	}

	if length == 0 {
		return
	}

	i := length - 1
	// Leave y in weak normal form so points can be negated cheaply later.
	field.fe_normalize_weak(&a[i].y)
	zs := zr[i]

	// Walk backwards, scaling by the accumulated ratios.
	for i > 0 {
		if i != length - 1 {
			field.fe_mul(&zs, &zs, &zr[i])
		}
		i -= 1
		ge_set_ge_zinv(&a[i], &a[i], &zs)
	}

	when VERIFY {
		for j in 0 ..< length {
			ge_verify(&a[j])
		}
	}
}

/*
Sets r to the point with the given x coordinate and the requested parity of y.

Returns whether such a point exists — that is, whether x^3 + b is a quadratic residue. This
is `lift_x` in BIP340 terms. Variable-time; the x coordinate is public in every caller.
*/
ge_set_xo_var :: proc "contextless" (r: ^Ge, x: ^field.Field_Elem, odd: bool) -> bool {
	when VERIFY {
		field.fe_verify(x)
	}

	r.x = x^
	x2, x3: field.Field_Elem
	field.fe_sqr(&x2, x)
	field.fe_mul(&x3, x, &x2)
	r.infinity = false
	field.fe_add_int(&x3, CURVE_B)

	ret := field.fe_sqrt(&r.y, &x3)
	field.fe_normalize_var(&r.y)
	if field.fe_is_odd(&r.y) != odd {
		field.fe_negate(&r.y, &r.y, 1)
	}

	ge_verify(r)
	return ret
}

/*
Reports whether a lies on the curve. Infinity is not considered valid.
*/
ge_is_valid_var :: proc "contextless" (a: ^Ge) -> bool {
	ge_verify(a)

	if a.infinity {
		return false
	}

	// y^2 == x^3 + b
	y2, x3: field.Field_Elem
	field.fe_sqr(&y2, &a.y)
	field.fe_sqr(&x3, &a.x)
	field.fe_mul(&x3, &x3, &a.x)
	field.fe_add_int(&x3, CURVE_B)
	return field.fe_equal(&y2, &x3)
}

/*
Reports whether x is the x coordinate of some point on the curve.
*/
ge_x_on_curve_var :: proc "contextless" (x: ^field.Field_Elem) -> bool {
	c: field.Field_Elem
	field.fe_sqr(&c, x)
	field.fe_mul(&c, &c, x)
	field.fe_add_int(&c, CURVE_B)
	return field.fe_is_square_var(&c)
}

/*
Reports whether the fraction xn/xd is the x coordinate of some point on the curve.

`xd` must be non-zero. Multiplying through by xd^4, which is a square and therefore does not
change residuosity, turns the test into "is xd*xn^3 + b*xd^4 a square" and avoids an
inversion.
*/
ge_x_frac_on_curve_var :: proc "contextless" (xn: ^field.Field_Elem, xd: ^field.Field_Elem) -> bool {
	CHECK(!field.fe_normalizes_to_zero_var(xd), "ge_x_frac_on_curve_var: denominator is zero")
	#assert(CURVE_B <= 31)

	r, t: field.Field_Elem
	field.fe_mul(&r, xd, xn) // r = xd*xn
	field.fe_sqr(&t, xn) // t = xn^2
	field.fe_mul(&r, &r, &t) // r = xd*xn^3
	field.fe_sqr(&t, xd) // t = xd^2
	field.fe_sqr(&t, &t) // t = xd^4
	field.fe_mul_int(&t, CURVE_B) // t = b*xd^4
	field.fe_add(&r, &t) // r = xd*xn^3 + b*xd^4
	return field.fe_is_square_var(&r)
}

/*
Reports whether two affine points are equal.
*/
ge_eq_var :: proc "contextless" (a: ^Ge, b: ^Ge) -> bool {
	ge_verify(a)
	ge_verify(b)

	if a.infinity != b.infinity {
		return false
	}
	if a.infinity {
		return true
	}

	tmp := a.x
	field.fe_normalize_weak(&tmp)
	if !field.fe_equal(&tmp, &b.x) {
		return false
	}

	tmp = a.y
	field.fe_normalize_weak(&tmp)
	return field.fe_equal(&tmp, &b.y)
}

/*
Reports whether two Jacobian points represent the same curve point.

Compares by subtracting rather than by normalizing both, since normalization needs an
inversion and subtraction does not.
*/
gej_eq_var :: proc "contextless" (a: ^Gej, b: ^Gej) -> bool {
	gej_verify(a)
	gej_verify(b)

	tmp: Gej
	gej_neg(&tmp, a)
	gej_add_var(&tmp, &tmp, b, nil)
	return gej_is_infinity(&tmp)
}

/*
Reports whether a Jacobian point equals an affine one.
*/
gej_eq_ge_var :: proc "contextless" (a: ^Gej, b: ^Ge) -> bool {
	gej_verify(a)
	ge_verify(b)

	tmp: Gej
	gej_neg(&tmp, a)
	gej_add_ge_var(&tmp, &tmp, b, nil)
	return gej_is_infinity(&tmp)
}

/*
Reports whether a Jacobian point has the given affine x coordinate.

`a` must not be infinity. Used by ECDSA verification, which needs only the x coordinate and
so can skip the inversion a full conversion would cost.
*/
gej_eq_x_var :: proc "contextless" (x: ^field.Field_Elem, a: ^Gej) -> bool {
	when VERIFY {
		field.fe_verify(x)
	}
	gej_verify(a)
	CHECK(!a.infinity, "gej_eq_x_var: point is infinity")

	r: field.Field_Elem
	field.fe_sqr(&r, &a.z)
	field.fe_mul(&r, &r, x)
	return field.fe_equal(&r, &a.x)
}

/*
Rescales a Jacobian point by s, giving an equivalent point with Z multiplied by s.

`s` must be non-zero. Used to randomize the projective representation, which blinds the
Z coordinate against side channels.
*/
gej_rescale :: proc "contextless" (r: ^Gej, s: ^field.Field_Elem) {
	gej_verify(r)
	when VERIFY {
		field.fe_verify(s)
	}
	CHECK(!field.fe_normalizes_to_zero_var(s), "gej_rescale: scale factor is zero")

	zz: field.Field_Elem
	field.fe_sqr(&zz, s)
	field.fe_mul(&r.x, &r.x, &zz) // x *= s^2
	field.fe_mul(&r.y, &r.y, &zz)
	field.fe_mul(&r.y, &r.y, s) // y *= s^3
	field.fe_mul(&r.z, &r.z, s) // z *= s

	gej_verify(r)
}

/*
Sets r to a if flag is true, in constant time.
*/
gej_cmov :: proc "contextless" (r: ^Gej, a: ^Gej, flag: bool) {
	gej_verify(r)
	gej_verify(a)

	field.fe_cmov(&r.x, &a.x, flag)
	field.fe_cmov(&r.y, &a.y, flag)
	field.fe_cmov(&r.z, &a.z, flag)
	r.infinity = bool(u8(r.infinity) ~ ((u8(r.infinity) ~ u8(a.infinity)) & u8(flag)))

	gej_verify(r)
}

/*
Packs an affine point into storage form. The point must not be infinity.
*/
ge_to_storage :: proc "contextless" (r: ^Ge_Storage, a: ^Ge) {
	ge_verify(a)
	CHECK(!a.infinity, "ge_to_storage: cannot store infinity")

	x := a.x
	field.fe_normalize(&x)
	y := a.y
	field.fe_normalize(&y)
	field.fe_to_storage(&r.x, &x)
	field.fe_to_storage(&r.y, &y)
}

/*
Unpacks an affine point from storage form.
*/
ge_from_storage :: proc "contextless" (r: ^Ge, a: ^Ge_Storage) {
	field.fe_from_storage(&r.x, &a.x)
	field.fe_from_storage(&r.y, &a.y)
	r.infinity = false
	ge_verify(r)
}

/*
Sets r to a if flag is true, in constant time.
*/
ge_storage_cmov :: proc "contextless" (r: ^Ge_Storage, a: ^Ge_Storage, flag: bool) {
	field.fe_storage_cmov(&r.x, &a.x, flag)
	field.fe_storage_cmov(&r.y, &a.y, flag)
}

/*
Applies the endomorphism: sets r to lambda*a, which is (beta*x, y).

This is the whole reason the endomorphism is cheap — a scalar multiplication by lambda
costs one field multiplication.
*/
ge_mul_lambda :: proc "contextless" (r: ^Ge, a: ^Ge) {
	ge_verify(a)
	r^ = a^
	field.fe_mul(&r.x, &r.x, &field.BETA)
	ge_verify(r)
}

/*
Reports whether a point lies in the correct subgroup.

The real secp256k1 group has cofactor 1, so every curve point qualifies and this is
trivially true. Under the exhaustive test configuration the curve has a small subgroup and
the check is real, performed by a simple ladder that avoids depending on `ecmult`.
*/
ge_is_in_correct_subgroup :: proc "contextless" (ge: ^Ge) -> bool {
	ge_verify(ge)

	when params.EXHAUSTIVE_ORDER > 0 {
		out: Gej
		gej_set_infinity(&out)
		for i in 0 ..< 32 {
			gej_double_var(&out, &out, nil)
			if (u32(params.EXHAUSTIVE_ORDER) >> uint(31 - i)) & 1 == 1 {
				gej_add_ge_var(&out, &out, ge, nil)
			}
		}
		return gej_is_infinity(&out)
	} else {
		return true
	}
}
