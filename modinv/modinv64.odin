/*
Modular inversion and Jacobi symbols by the safegcd algorithm.

Implements "Fast constant-time gcd computation and modular inversion" by Daniel J.
Bernstein and Bo-Yin Yang, for N=62 using signed 62-bit limbs. Mirrors upstream's
`modinv64_impl.h`; upstream's `doc/safegcd_implementation.md` is the long-form explanation
of why the algorithm works.

Both the field (mod p) and the scalar (mod n) need this, so it lives in its own package
parameterized by a `Modinfo` rather than being duplicated in each.

# Why not just exponentiate

Inversion by a^(p-2) is simpler and constant-time by construction, but roughly an order of
magnitude slower, and it does not generalise to the scalar modulus n, which has no
exploitable structure. safegcd is what upstream uses and what a differential test against
it requires.

# Constant-time status

`modinv64` is constant-time in x but not in the modulus, which is public. `modinv64_var`
and `jacobi64_maybe_var` branch on values and must never see secret data.

The masking below relies on the compiler not rewriting mask arithmetic into branches.
Upstream marks the relevant locals `volatile` to prevent that; Odin has no direct
equivalent, so this is asserted by the Phase 8 valgrind harness rather than by the source.
Until that harness runs, `modinv64` is `unverified` in TRUST.md.
*/
package modinv

import "base:intrinsics"

/*
Mask selecting one 62-bit limb.
*/
M62 :: u64(0xffff_ffff_ffff_ffff) >> 2

/*
An integer as five signed 62-bit limbs, with value sum(v[i] * 2^(62*i), i=0..4).

Limbs may be negative during the algorithm; only the final normalized output is guaranteed
to have every limb in [0, 2^62).
*/
Signed62 :: struct {
	v: [5]i64,
}

/*
The constant 1.
*/
SIGNED62_ONE :: Signed62{v = {1, 0, 0, 0, 0}}

/*
A modulus and the precomputed inverse the algorithm needs.
*/
Modinfo :: struct {
	/*
	The modulus in signed62 form. Must be odd and in [3, 2^256].
	*/
	modulus:       Signed62,
	/*
	modulus^-1 mod 2^62.
	*/
	modulus_inv62: u64,
}

/*
A 2x2 transition matrix

	t = [ u  v ]
	    [ q  r ]

accumulated over a batch of divsteps, scaled by 2^62.
*/
Trans2x2 :: struct {
	u, v, q, r: i64,
}

/*
Whether internal invariant checks are compiled in. Follows `-debug`, matching the `field`
package.
*/
VERIFY :: ODIN_DEBUG

@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "modinv invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		assert_contextless(condition, message, loc)
	}
}

/*
Brings r from range (-2*modulus, modulus) into [0, modulus), negating it first if sign is
negative.

Input limbs must be in (-2^62, 2^62); output limbs are in [0, 2^62). The two conditional
additions are performed with masks rather than branches, so this is constant-time in r.
*/
normalize_62 :: proc "contextless" (r: ^Signed62, sign: i64, modinfo: ^Modinfo) {
	m62 := i64(M62)
	r0, r1, r2, r3, r4 := r.v[0], r.v[1], r.v[2], r.v[3], r.v[4]

	when VERIFY {
		for i in 0 ..< 5 {
			CHECK(r.v[i] >= -m62, "normalize_62: limb below range")
			CHECK(r.v[i] <= m62, "normalize_62: limb above range")
		}
		CHECK(mul_cmp_62(r, 5, &modinfo.modulus, -2) > 0, "normalize_62: r <= -2*modulus")
		CHECK(mul_cmp_62(r, 5, &modinfo.modulus, 1) < 0, "normalize_62: r >= modulus")
	}

	// Add the modulus if negative, then negate if asked. This moves r from
	// (-2*modulus, modulus) to (-modulus, modulus); since every limb is in (-2^62, 2^62),
	// no i64 overflows. The shifts are arithmetic, so they broadcast the sign bit.
	cond_add := r4 >> 63
	r0 += modinfo.modulus.v[0] & cond_add
	r1 += modinfo.modulus.v[1] & cond_add
	r2 += modinfo.modulus.v[2] & cond_add
	r3 += modinfo.modulus.v[3] & cond_add
	r4 += modinfo.modulus.v[4] & cond_add

	cond_negate := sign >> 63
	r0 = (r0 ~ cond_negate) - cond_negate
	r1 = (r1 ~ cond_negate) - cond_negate
	r2 = (r2 ~ cond_negate) - cond_negate
	r3 = (r3 ~ cond_negate) - cond_negate
	r4 = (r4 ~ cond_negate) - cond_negate

	// Propagate the top bits back into range.
	r1 += r0 >> 62; r0 &= m62
	r2 += r1 >> 62; r1 &= m62
	r3 += r2 >> 62; r2 &= m62
	r4 += r3 >> 62; r3 &= m62

	// Add the modulus again if still negative, bringing r to [0, modulus).
	cond_add = r4 >> 63
	r0 += modinfo.modulus.v[0] & cond_add
	r1 += modinfo.modulus.v[1] & cond_add
	r2 += modinfo.modulus.v[2] & cond_add
	r3 += modinfo.modulus.v[3] & cond_add
	r4 += modinfo.modulus.v[4] & cond_add

	r1 += r0 >> 62; r0 &= m62
	r2 += r1 >> 62; r1 &= m62
	r3 += r2 >> 62; r2 &= m62
	r4 += r3 >> 62; r3 &= m62

	r.v = {r0, r1, r2, r3, r4}

	CHECK(r0 >> 62 == 0, "normalize_62: limb 0 not normalized")
	CHECK(r1 >> 62 == 0, "normalize_62: limb 1 not normalized")
	CHECK(r2 >> 62 == 0, "normalize_62: limb 2 not normalized")
	CHECK(r3 >> 62 == 0, "normalize_62: limb 3 not normalized")
	CHECK(r4 >> 62 == 0, "normalize_62: limb 4 not normalized")
	when VERIFY {
		CHECK(mul_cmp_62(r, 5, &modinfo.modulus, 0) >= 0, "normalize_62: result negative")
		CHECK(mul_cmp_62(r, 5, &modinfo.modulus, 1) < 0, "normalize_62: result >= modulus")
	}
}

/*
Computes the transition matrix and new zeta for 59 divsteps, in constant time.

zeta is -(delta + 1/2). The matrix is scaled by 2^62 rather than 2^59, which is why u and r
start at 8 rather than 1.

Implements `divsteps_n_matrix` from upstream's explanation.
*/
divsteps_59 :: proc "contextless" (zeta_in: i64, f0, g0: u64, t: ^Trans2x2) -> i64 {
	// Held as unsigned so that left shifts of conceptually-negative values are defined;
	// the range stays inside [-2^62, 2^62], so reinterpreting as signed at the end is
	// exact.
	u, v, q, r := u64(8), u64(0), u64(0), u64(8)
	f, g := f0, g0
	zeta := zeta_in

	for i in 3 ..< 62 {
		CHECK(f & 1 == 1, "divsteps_59: f must stay odd")
		CHECK(u * f0 + v * g0 == f << uint(i), "divsteps_59: u,v invariant broken")
		CHECK(q * f0 + r * g0 == g << uint(i), "divsteps_59: q,r invariant broken")

		// Masks for (zeta < 0) and for (g odd).
		c1 := zeta >> 63
		mask1 := transmute(u64)c1
		c2 := g & 1
		mask2 := -c2

		// Conditionally negated f, u, v.
		x := (f ~ mask1) - mask1
		y := (u ~ mask1) - mask1
		z := (v ~ mask1) - mask1

		// Conditionally add those to g, q, r.
		g += x & mask2
		q += y & mask2
		r += z & mask2

		// From here mask1 means (zeta < 0) and (g odd).
		mask1 &= mask2

		// Conditionally turn zeta into -zeta-2, else zeta-1.
		zeta = (zeta ~ transmute(i64)mask1) - 1

		// Conditionally add g, q, r to f, u, v.
		f += g & mask1
		u += q & mask1
		v += r & mask1

		g >>= 1
		u <<= 1
		v <<= 1

		// Follows from the bound of 10*59 divsteps overall.
		CHECK(zeta >= -591 && zeta <= 591, "divsteps_59: zeta out of range")
	}

	t.u = transmute(i64)u
	t.v = transmute(i64)v
	t.q = transmute(i64)q
	t.r = transmute(i64)r

	// Each divstep's matrix has determinant 2, so 59 of them give 2^59; the initial
	// 8*identity contributes 2^6, for 2^65 overall. A power-of-two determinant is what
	// guarantees the transformation preserves gcd up to a factor of 2.
	when VERIFY {
		CHECK(det_check_pow2(t, 65, false), "divsteps_59: determinant is not 2^65")
	}

	return zeta
}

/*
Computes the transition matrix and new eta for 62 divsteps, in variable time.

eta is -delta. Faster than `divsteps_59` because it can skip runs of zero bits and cancel
several bits of g at once, but it branches on values.

Implements `divsteps_n_matrix_var` from upstream's explanation.
*/
divsteps_62_var :: proc "contextless" (eta_in: i64, f0, g0: u64, t: ^Trans2x2) -> i64 {
	u, v, q, r := u64(1), u64(0), u64(0), u64(1)
	f, g := f0, g0
	eta := eta_in
	i := 62

	for {
		// A sentinel bit bounds the zero count by the steps remaining.
		zeros := int(intrinsics.count_trailing_zeros(g | (max(u64) << uint(i))))
		// Those divsteps all just halve g, so apply them in one go.
		g >>= uint(zeros)
		u <<= uint(zeros)
		v <<= uint(zeros)
		eta -= i64(zeros)
		i -= zeros

		if i == 0 {
			break
		}

		CHECK(f & 1 == 1, "divsteps_62_var: f must be odd")
		CHECK(g & 1 == 1, "divsteps_62_var: g must be odd here")
		CHECK(u * f0 + v * g0 == f << uint(62 - i), "divsteps_62_var: u,v invariant broken")
		CHECK(q * f0 + r * g0 == g << uint(62 - i), "divsteps_62_var: q,r invariant broken")
		// Follows from the bound of 12*62 divsteps overall.
		CHECK(eta >= -745 && eta <= 745, "divsteps_62_var: eta out of range")

		m: u64
		w: u64

		if eta < 0 {
			// Negate eta and swap f, g with g, -f.
			eta = -eta
			tmp := f; f = g; g = -tmp
			tmp = u; u = q; q = -tmp
			tmp = v; v = r; r = -tmp

			// Cancel up to 6 bits of g at once, bounded by the steps left and by how
			// long eta's sign will hold.
			limit := i if i64(i) < eta + 1 else int(eta + 1)
			CHECK(limit > 0 && limit <= 62, "divsteps_62_var: limit out of range")
			m = (max(u64) >> uint(64 - limit)) & 63
			w = (f * g * (f * f - 2)) & m
		} else {
			// eta tends to be small here, so a cheaper formula cancelling 4 bits suffices.
			limit := i if i64(i) < eta + 1 else int(eta + 1)
			CHECK(limit > 0 && limit <= 62, "divsteps_62_var: limit out of range")
			m = (max(u64) >> uint(64 - limit)) & 15
			w = f + (((f + 1) & 4) << 1)
			w = (-w * g) & m
		}

		g += f * w
		q += u * w
		r += v * w

		CHECK(g & m == 0, "divsteps_62_var: bits were not cancelled")
	}

	t.u = transmute(i64)u
	t.v = transmute(i64)v
	t.q = transmute(i64)q
	t.r = transmute(i64)r

	when VERIFY {
		CHECK(det_check_pow2(t, 62, false), "divsteps_62_var: determinant is not 2^62")
	}

	return eta
}

/*
Computes the transition matrix and new eta for 62 posdivsteps in variable time, tracking
the Jacobi symbol along the way.

f0 and g0 must be f and g modulo 2^64 rather than 2^62, because the Jacobi tracking needs
(f mod 8), not just (f mod 2). The low bit of jacp is flipped whenever the symbol changes
sign; its other bits are meaningless.
*/
posdivsteps_62_var :: proc "contextless" (
	eta_in: i64,
	f0, g0: u64,
	t: ^Trans2x2,
	jacp: ^int,
) -> i64 {
	u, v, q, r := u64(1), u64(0), u64(0), u64(1)
	f, g := f0, g0
	eta := eta_in
	i := 62
	jac := jacp^

	for {
		zeros := int(intrinsics.count_trailing_zeros(g | (max(u64) << uint(i))))
		g >>= uint(zeros)
		u <<= uint(zeros)
		v <<= uint(zeros)
		eta -= i64(zeros)
		i -= zeros

		// Dividing g by an odd power of 2 flips the symbol when (f mod 8) is 3 or 5.
		jac ~= int(u64(zeros) & ((f >> 1) ~ (f >> 2)))

		if i == 0 {
			break
		}

		CHECK(f & 1 == 1, "posdivsteps_62_var: f must be odd")
		CHECK(g & 1 == 1, "posdivsteps_62_var: g must be odd here")

		m: u64
		w: u64

		if eta < 0 {
			eta = -eta
			tmp := f; f = g; g = tmp
			tmp = u; u = q; q = tmp
			tmp = v; v = r; r = tmp

			// Swapping f and g flips the symbol when both are 3 mod 4.
			jac ~= int((f & g) >> 1)

			limit := i if i64(i) < eta + 1 else int(eta + 1)
			CHECK(limit > 0 && limit <= 62, "posdivsteps_62_var: limit out of range")
			m = (max(u64) >> uint(64 - limit)) & 63
			w = (f * g * (f * f - 2)) & m
		} else {
			limit := i if i64(i) < eta + 1 else int(eta + 1)
			CHECK(limit > 0 && limit <= 62, "posdivsteps_62_var: limit out of range")
			m = (max(u64) >> uint(64 - limit)) & 15
			w = f + (((f + 1) & 4) << 1)
			w = (-w * g) & m
		}

		g += f * w
		q += u * w
		r += v * w

		CHECK(g & m == 0, "posdivsteps_62_var: bits were not cancelled")
	}

	t.u = transmute(i64)u
	t.v = transmute(i64)v
	t.q = transmute(i64)q
	t.r = transmute(i64)r

	// Each posdivstep matrix has determinant 2 or -2, so the aggregate is +/-2^62.
	when VERIFY {
		CHECK(det_check_pow2(t, 62, true), "posdivsteps_62_var: determinant is not +/-2^62")
	}

	jacp^ = jac
	return eta
}

/*
Computes (t / 2^62) * [d, e] modulo the modulus.

d and e are in (-2*modulus, modulus) on input and output; output limbs are in
(-2^62, 2^62). Multiples of the modulus are added so the low 62 bits cancel exactly, which
is what makes the division by 2^62 exact.

Implements `update_de` from upstream's explanation.
*/
update_de_62 :: proc "contextless" (d, e: ^Signed62, t: ^Trans2x2, modinfo: ^Modinfo) {
	d0, d1, d2, d3, d4 := d.v[0], d.v[1], d.v[2], d.v[3], d.v[4]
	e0, e1, e2, e3, e4 := e.v[0], e.v[1], e.v[2], e.v[3], e.v[4]
	u, v, q, r := t.u, t.v, t.q, t.r

	when VERIFY {
		CHECK(mul_cmp_62(d, 5, &modinfo.modulus, -2) > 0, "update_de_62: d <= -2*modulus")
		CHECK(mul_cmp_62(d, 5, &modinfo.modulus, 1) < 0, "update_de_62: d >= modulus")
		CHECK(mul_cmp_62(e, 5, &modinfo.modulus, -2) > 0, "update_de_62: e <= -2*modulus")
		CHECK(mul_cmp_62(e, 5, &modinfo.modulus, 1) < 0, "update_de_62: e >= modulus")
		CHECK(abs_i64(u) <= (i64(1) << 62) - abs_i64(v), "update_de_62: |u|+|v| > 2^62")
		CHECK(abs_i64(q) <= (i64(1) << 62) - abs_i64(r), "update_de_62: |q|+|r| > 2^62")
	}

	// md, me start at zero, plus [u,q] if d is negative and [v,r] if e is negative.
	sd := d4 >> 63
	se := e4 >> 63
	md := (u & sd) + (v & se)
	me := (q & sd) + (r & se)

	cd := i128(u) * i128(d0)
	cd += i128(v) * i128(e0)
	ce := i128(q) * i128(d0)
	ce += i128(r) * i128(e0)

	// Correct md, me so the bottom 62 bits of the result vanish.
	md -= transmute(i64)((modinfo.modulus_inv62 * u64(cd) + transmute(u64)md) & M62)
	me -= transmute(i64)((modinfo.modulus_inv62 * u64(ce) + transmute(u64)me) & M62)

	cd += i128(modinfo.modulus.v[0]) * i128(md)
	ce += i128(modinfo.modulus.v[0]) * i128(me)

	CHECK(u64(cd) & M62 == 0, "update_de_62: low bits of d did not cancel")
	cd >>= 62
	CHECK(u64(ce) & M62 == 0, "update_de_62: low bits of e did not cancel")
	ce >>= 62

	cd += i128(u) * i128(d1)
	cd += i128(v) * i128(e1)
	ce += i128(q) * i128(d1)
	ce += i128(r) * i128(e1)
	if modinfo.modulus.v[1] != 0 {
		cd += i128(modinfo.modulus.v[1]) * i128(md)
		ce += i128(modinfo.modulus.v[1]) * i128(me)
	}
	d.v[0] = transmute(i64)(u64(cd) & M62); cd >>= 62
	e.v[0] = transmute(i64)(u64(ce) & M62); ce >>= 62

	cd += i128(u) * i128(d2)
	cd += i128(v) * i128(e2)
	ce += i128(q) * i128(d2)
	ce += i128(r) * i128(e2)
	if modinfo.modulus.v[2] != 0 {
		cd += i128(modinfo.modulus.v[2]) * i128(md)
		ce += i128(modinfo.modulus.v[2]) * i128(me)
	}
	d.v[1] = transmute(i64)(u64(cd) & M62); cd >>= 62
	e.v[1] = transmute(i64)(u64(ce) & M62); ce >>= 62

	cd += i128(u) * i128(d3)
	cd += i128(v) * i128(e3)
	ce += i128(q) * i128(d3)
	ce += i128(r) * i128(e3)
	if modinfo.modulus.v[3] != 0 {
		cd += i128(modinfo.modulus.v[3]) * i128(md)
		ce += i128(modinfo.modulus.v[3]) * i128(me)
	}
	d.v[2] = transmute(i64)(u64(cd) & M62); cd >>= 62
	e.v[2] = transmute(i64)(u64(ce) & M62); ce >>= 62

	cd += i128(u) * i128(d4)
	cd += i128(v) * i128(e4)
	ce += i128(q) * i128(d4)
	ce += i128(r) * i128(e4)
	cd += i128(modinfo.modulus.v[4]) * i128(md)
	ce += i128(modinfo.modulus.v[4]) * i128(me)
	d.v[3] = transmute(i64)(u64(cd) & M62); cd >>= 62
	e.v[3] = transmute(i64)(u64(ce) & M62); ce >>= 62

	d.v[4] = i64(cd)
	e.v[4] = i64(ce)

	when VERIFY {
		CHECK(mul_cmp_62(d, 5, &modinfo.modulus, -2) > 0, "update_de_62: d <= -2*modulus")
		CHECK(mul_cmp_62(d, 5, &modinfo.modulus, 1) < 0, "update_de_62: d >= modulus")
		CHECK(mul_cmp_62(e, 5, &modinfo.modulus, -2) > 0, "update_de_62: e <= -2*modulus")
		CHECK(mul_cmp_62(e, 5, &modinfo.modulus, 1) < 0, "update_de_62: e >= modulus")
	}
}

/*
Computes (t / 2^62) * [f, g], on all five limbs.

Implements `update_fg` from upstream's explanation.
*/
update_fg_62 :: proc "contextless" (f, g: ^Signed62, t: ^Trans2x2) {
	f0, f1, f2, f3, f4 := f.v[0], f.v[1], f.v[2], f.v[3], f.v[4]
	g0, g1, g2, g3, g4 := g.v[0], g.v[1], g.v[2], g.v[3], g.v[4]
	u, v, q, r := t.u, t.v, t.q, t.r

	cf := i128(u) * i128(f0)
	cf += i128(v) * i128(g0)
	cg := i128(q) * i128(f0)
	cg += i128(r) * i128(g0)

	CHECK(u64(cf) & M62 == 0, "update_fg_62: low bits of f did not cancel")
	cf >>= 62
	CHECK(u64(cg) & M62 == 0, "update_fg_62: low bits of g did not cancel")
	cg >>= 62

	cf += i128(u) * i128(f1)
	cf += i128(v) * i128(g1)
	cg += i128(q) * i128(f1)
	cg += i128(r) * i128(g1)
	f.v[0] = transmute(i64)(u64(cf) & M62); cf >>= 62
	g.v[0] = transmute(i64)(u64(cg) & M62); cg >>= 62

	cf += i128(u) * i128(f2)
	cf += i128(v) * i128(g2)
	cg += i128(q) * i128(f2)
	cg += i128(r) * i128(g2)
	f.v[1] = transmute(i64)(u64(cf) & M62); cf >>= 62
	g.v[1] = transmute(i64)(u64(cg) & M62); cg >>= 62

	cf += i128(u) * i128(f3)
	cf += i128(v) * i128(g3)
	cg += i128(q) * i128(f3)
	cg += i128(r) * i128(g3)
	f.v[2] = transmute(i64)(u64(cf) & M62); cf >>= 62
	g.v[2] = transmute(i64)(u64(cg) & M62); cg >>= 62

	cf += i128(u) * i128(f4)
	cf += i128(v) * i128(g4)
	cg += i128(q) * i128(f4)
	cg += i128(r) * i128(g4)
	f.v[3] = transmute(i64)(u64(cf) & M62); cf >>= 62
	g.v[3] = transmute(i64)(u64(cg) & M62); cg >>= 62

	f.v[4] = i64(cf)
	g.v[4] = i64(cg)
}

/*
Computes (t / 2^62) * [f, g] over the low `length` limbs only.

The variable-time inversion shrinks its working length as the top limbs go to zero, which
is where most of its speed advantage comes from.
*/
update_fg_62_var :: proc "contextless" (length: int, f, g: ^Signed62, t: ^Trans2x2) {
	u, v, q, r := t.u, t.v, t.q, t.r
	CHECK(length > 0, "update_fg_62_var: length must be positive")

	fi := f.v[0]
	gi := g.v[0]
	cf := i128(u) * i128(fi)
	cf += i128(v) * i128(gi)
	cg := i128(q) * i128(fi)
	cg += i128(r) * i128(gi)

	CHECK(u64(cf) & M62 == 0, "update_fg_62_var: low bits of f did not cancel")
	cf >>= 62
	CHECK(u64(cg) & M62 == 0, "update_fg_62_var: low bits of g did not cancel")
	cg >>= 62

	for i in 1 ..< length {
		fi = f.v[i]
		gi = g.v[i]
		cf += i128(u) * i128(fi)
		cf += i128(v) * i128(gi)
		cg += i128(q) * i128(fi)
		cg += i128(r) * i128(gi)
		f.v[i - 1] = transmute(i64)(u64(cf) & M62); cf >>= 62
		g.v[i - 1] = transmute(i64)(u64(cg) & M62); cg >>= 62
	}

	f.v[length - 1] = i64(cf)
	g.v[length - 1] = i64(cg)
}

/*
Replaces x with its inverse modulo the modulus, in constant time with respect to x.

x must be in [0, modulus). Zero maps to zero; any other x must be coprime with the modulus,
which is automatic when the modulus is prime. Output limbs are in [0, 2^62).

Runs a fixed 10 iterations of 59 divsteps — 590 total, which suffices for any 256-bit
input — so the running time does not depend on x.
*/
modinv64 :: proc "contextless" (x: ^Signed62, modinfo: ^Modinfo) {
	// d=0, e=1, f=modulus, g=x, zeta=-1.
	d := Signed62{}
	e := Signed62{v = {1, 0, 0, 0, 0}}
	f := modinfo.modulus
	g := x^
	zeta := i64(-1) // zeta = -(delta + 1/2); delta starts at 1/2.

	for _ in 0 ..< 10 {
		t: Trans2x2
		zeta = divsteps_59(zeta, transmute(u64)f.v[0], transmute(u64)g.v[0], &t)
		update_de_62(&d, &e, &t, modinfo)

		when VERIFY {
			CHECK(mul_cmp_62(&f, 5, &modinfo.modulus, -1) > 0, "modinv64: f <= -modulus")
			CHECK(mul_cmp_62(&f, 5, &modinfo.modulus, 1) <= 0, "modinv64: f > modulus")
			CHECK(mul_cmp_62(&g, 5, &modinfo.modulus, -1) > 0, "modinv64: g <= -modulus")
			CHECK(mul_cmp_62(&g, 5, &modinfo.modulus, 1) < 0, "modinv64: g >= modulus")
		}

		update_fg_62(&f, &g, &t)

		when VERIFY {
			CHECK(mul_cmp_62(&f, 5, &modinfo.modulus, -1) > 0, "modinv64: f <= -modulus")
			CHECK(mul_cmp_62(&f, 5, &modinfo.modulus, 1) <= 0, "modinv64: f > modulus")
			CHECK(mul_cmp_62(&g, 5, &modinfo.modulus, -1) > 0, "modinv64: g <= -modulus")
			CHECK(mul_cmp_62(&g, 5, &modinfo.modulus, 1) < 0, "modinv64: g >= modulus")
		}
	}

	// g must now be 0, and unless x was 0, f is +/-gcd = +/-1 with d holding +/- the
	// inverse.
	when VERIFY {
		one := SIGNED62_ONE
		CHECK(mul_cmp_62(&g, 5, &one, 0) == 0, "modinv64: g did not reach zero")
		CHECK(
			mul_cmp_62(&f, 5, &one, -1) == 0 ||
			mul_cmp_62(&f, 5, &one, 1) == 0 ||
			(mul_cmp_62(x, 5, &one, 0) == 0 &&
					mul_cmp_62(&d, 5, &one, 0) == 0 &&
					mul_cmp_62(&f, 5, &modinfo.modulus, 1) == 0),
			"modinv64: |f| is not 1 and the input was not zero",
		)
	}

	normalize_62(&d, f.v[4], modinfo)
	x^ = d
}

/*
Replaces x with its inverse modulo the modulus, in variable time.

Behaves identically to `modinv64` but branches on values, iterating only until g reaches
zero and shrinking the working limb count as the top limbs vanish. Never call this on
secret data.
*/
modinv64_var :: proc "contextless" (x: ^Signed62, modinfo: ^Modinfo) {
	d := Signed62{}
	e := Signed62{v = {1, 0, 0, 0, 0}}
	f := modinfo.modulus
	g := x^
	length := 5
	eta := i64(-1) // eta = -delta; delta starts at 1.
	when VERIFY {
		iterations := 0
	}

	for {
		t: Trans2x2
		eta = divsteps_62_var(eta, transmute(u64)f.v[0], transmute(u64)g.v[0], &t)
		update_de_62(&d, &e, &t, modinfo)

		when VERIFY {
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, -1) > 0, "modinv64_var: f <= -modulus")
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 1) <= 0, "modinv64_var: f > modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, -1) > 0, "modinv64_var: g <= -modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 1) < 0, "modinv64_var: g >= modulus")
		}

		update_fg_62_var(length, &f, &g, &t)

		// A zero bottom limb means g might be zero overall.
		if g.v[0] == 0 {
			cond := i64(0)
			for j in 1 ..< length {
				cond |= g.v[j]
			}
			if cond == 0 {
				break
			}
		}

		// Shrink the working length when the top limb of both f and g is 0 or -1,
		// propagating the sign into the limb below.
		fn := f.v[length - 1]
		gn := g.v[length - 1]
		cond := i64(length - 2) >> 63
		cond |= fn ~ (fn >> 63)
		cond |= gn ~ (gn >> 63)
		if cond == 0 {
			f.v[length - 2] |= transmute(i64)(transmute(u64)fn << 62)
			g.v[length - 2] |= transmute(i64)(transmute(u64)gn << 62)
			length -= 1
		}

		when VERIFY {
			iterations += 1
			CHECK(iterations < 12, "modinv64_var: exceeded 12*62 divsteps")
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, -1) > 0, "modinv64_var: f <= -modulus")
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 1) <= 0, "modinv64_var: f > modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, -1) > 0, "modinv64_var: g <= -modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 1) < 0, "modinv64_var: g >= modulus")
		}
	}

	when VERIFY {
		one := SIGNED62_ONE
		CHECK(mul_cmp_62(&g, length, &one, 0) == 0, "modinv64_var: g did not reach zero")
		CHECK(
			mul_cmp_62(&f, length, &one, -1) == 0 ||
			mul_cmp_62(&f, length, &one, 1) == 0 ||
			(mul_cmp_62(x, 5, &one, 0) == 0 &&
					mul_cmp_62(&d, 5, &one, 0) == 0 &&
					mul_cmp_62(&f, length, &modinfo.modulus, 1) == 0),
			"modinv64_var: |f| is not 1 and the input was not zero",
		)
	}

	normalize_62(&d, f.v[length - 1], modinfo)
	x^ = d
}

/*
Number of posdivstep iterations before giving up.

Under VERIFY a deliberately low bound is used so the give-up path is actually exercised;
the median requirement is around 756 steps. In release builds the bound is high enough that
failure is vanishingly rare.
*/
JACOBI64_ITERATIONS :: 12 when VERIFY else 25

/*
Computes the Jacobi symbol of x modulo the modulus, in variable time.

x must be coprime with the modulus, so it cannot be zero. All limbs of x must be
non-negative. Returns 1 or -1, or **0 when the result could not be computed** within the
iteration bound — callers must handle that third case rather than treating 0 as a
non-residue.
*/
jacobi64_maybe_var :: proc "contextless" (x: ^Signed62, modinfo: ^Modinfo) -> int {
	f := modinfo.modulus
	g := x^
	length := 5
	eta := i64(-1)
	jac := 0

	CHECK(
		g.v[0] >= 0 && g.v[1] >= 0 && g.v[2] >= 0 && g.v[3] >= 0 && g.v[4] >= 0,
		"jacobi64_maybe_var: input limbs must be non-negative",
	)
	// If the loop converges it converges to gcd(x, modulus) = 1, so x cannot be zero.
	CHECK(
		(g.v[0] | g.v[1] | g.v[2] | g.v[3] | g.v[4]) != 0,
		"jacobi64_maybe_var: input must be non-zero",
	)

	for _ in 0 ..< JACOBI64_ITERATIONS {
		t: Trans2x2
		eta = posdivsteps_62_var(
			eta,
			transmute(u64)f.v[0] | (transmute(u64)f.v[1] << 62),
			transmute(u64)g.v[0] | (transmute(u64)g.v[1] << 62),
			&t,
			&jac,
		)

		when VERIFY {
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 0) > 0, "jacobi: f <= 0")
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 1) <= 0, "jacobi: f > modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 0) > 0, "jacobi: g <= 0")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 1) < 0, "jacobi: g >= modulus")
		}

		update_fg_62_var(length, &f, &g, &t)

		// f == 1 means we are done, and the symbol (g | f) is 1.
		if f.v[0] == 1 {
			cond := i64(0)
			for j in 1 ..< length {
				cond |= f.v[j]
			}
			if cond == 0 {
				return 1 - 2 * (jac & 1)
			}
		}

		// Shrink the working length when the top limb of both f and g is zero.
		fn := f.v[length - 1]
		gn := g.v[length - 1]
		cond := i64(length - 2) >> 63
		cond |= fn
		cond |= gn
		if cond == 0 {
			length -= 1
		}

		when VERIFY {
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 0) > 0, "jacobi: f <= 0")
			CHECK(mul_cmp_62(&f, length, &modinfo.modulus, 1) <= 0, "jacobi: f > modulus")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 0) > 0, "jacobi: g <= 0")
			CHECK(mul_cmp_62(&g, length, &modinfo.modulus, 1) < 0, "jacobi: g >= modulus")
		}
	}

	// Did not converge within the bound; the caller must fall back.
	return 0
}
