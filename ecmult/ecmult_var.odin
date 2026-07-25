/*
Variable-time double multiplication: R = na*A + ng*G.

This is the verification path. Both scalars are public — a signature's r and s, or a
public key — so branching on them is safe and the wNAF sparsity is worth taking.

The algorithm is Straus's, with two accelerations:

  - **GLV endomorphism.** na is split into na_1 + na_lam*lambda where both halves are about
    128 bits. Multiplying by lambda costs one field multiplication, so two 128-bit
    multiplications replace one 256-bit one.
  - **Effective affine coordinates.** All the odd multiples of A share a single Z
    denominator, so the cheap `gej_add_ge_var` can be used throughout and the Z coordinate
    corrected once at the end.

Never call this on secret data; use `ecmult_const` instead.

Mirrors upstream's `ecmult_strauss_wnaf`.
*/
package ecmult

import "../field"
import "../group"
import "../scalar"

/*
Per-point wNAF state for the Straus loop.
*/
@(private)
Strauss_Point_State :: struct {
	wnaf_na_1:   [129]i8,
	wnaf_na_lam: [129]i8,
	bits_na_1:   int,
	bits_na_lam: int,
}

/*
Computes r = na*a + ng*G in variable time.

Either scalar may be zero, and `a` may be infinity. Passing a nil `ng` skips the generator
term entirely.
*/
ecmult :: proc "contextless" (
	r: ^group.Gej,
	a: ^group.Gej,
	na: ^scalar.Scalar,
	ng: ^scalar.Scalar,
) {
	// Odd multiples of a, and their beta-scaled x coordinates for the endomorphism.
	pre_a: [TABLE_SIZE_A]group.Ge
	aux: [TABLE_SIZE_A]field.Field_Elem
	ps: Strauss_Point_State

	z: field.Field_Elem
	field.fe_set_int(&z, 1)

	// Whether the point term contributes at all.
	have_point := !scalar.scalar_is_zero(na) && !group.gej_is_infinity(a)
	bits := 0

	if have_point {
		// na = na_1 + na_lam*lambda, with both halves around 128 bits.
		na_1, na_lam: scalar.Scalar
		scalar.scalar_split_lambda(&na_1, &na_lam, na)

		ps.bits_na_1 = wnaf_small(ps.wnaf_na_1[:129], &na_1, WINDOW_A)
		ps.bits_na_lam = wnaf_small(ps.wnaf_na_lam[:129], &na_lam, WINDOW_A)
		CHECK(ps.bits_na_1 <= 129, "ecmult: na_1 wnaf too long")
		CHECK(ps.bits_na_lam <= 129, "ecmult: na_lam wnaf too long")

		if ps.bits_na_1 > bits {
			bits = ps.bits_na_1
		}
		if ps.bits_na_lam > bits {
			bits = ps.bits_na_lam
		}

		tmp := a^
		odd_multiples_table(pre_a[:], aux[:], &z, &tmp)
		group.ge_table_set_globalz(pre_a[:], aux[:])

		// Precompute beta*x for each entry, so endomorphism lookups are free.
		for i in 0 ..< TABLE_SIZE_A {
			field.fe_mul(&aux[i], &pre_a[i].x, &field.BETA)
		}
	}

	// Split ng into its low and high 128-bit halves, matching the two generator tables.
	wnaf_ng_1: [129]int
	wnaf_ng_128: [129]int
	bits_ng_1 := 0
	bits_ng_128 := 0

	if ng != nil {
		ng_1, ng_128: scalar.Scalar
		scalar.scalar_split_128(&ng_1, &ng_128, ng)

		bits_ng_1 = wnaf(wnaf_ng_1[:129], &ng_1, WINDOW_G)
		bits_ng_128 = wnaf(wnaf_ng_128[:129], &ng_128, WINDOW_G)

		if bits_ng_1 > bits {
			bits = bits_ng_1
		}
		if bits_ng_128 > bits {
			bits = bits_ng_128
		}
	}

	group.gej_set_infinity(r)

	tmpa: group.Ge
	for i := bits - 1; i >= 0; i -= 1 {
		group.gej_double_var(r, r, nil)

		if have_point {
			if i < ps.bits_na_1 && ps.wnaf_na_1[i] != 0 {
				table_get_ge(&tmpa, pre_a[:], int(ps.wnaf_na_1[i]), WINDOW_A)
				group.gej_add_ge_var(r, r, &tmpa, nil)
			}
			if i < ps.bits_na_lam && ps.wnaf_na_lam[i] != 0 {
				table_get_ge_lambda(&tmpa, pre_a[:], aux[:], int(ps.wnaf_na_lam[i]), WINDOW_A)
				group.gej_add_ge_var(r, r, &tmpa, nil)
			}
		}

		// The generator table entries are genuinely affine, so relative to the shared Z
		// used above they have a Z ratio of 1/Z. `gej_add_zinv_var` exploits that.
		if i < bits_ng_1 && wnaf_ng_1[i] != 0 {
			table_get_ge_storage(&tmpa, PRE_G[:], wnaf_ng_1[i], WINDOW_G)
			group.gej_add_zinv_var(r, r, &tmpa, &z)
		}
		if i < bits_ng_128 && wnaf_ng_128[i] != 0 {
			table_get_ge_storage(&tmpa, PRE_G_128[:], wnaf_ng_128[i], WINDOW_G)
			group.gej_add_zinv_var(r, r, &tmpa, &z)
		}
	}

	// Undo the shared-Z isomorphism.
	if !group.gej_is_infinity(r) {
		field.fe_mul(&r.z, &r.z, &z)
	}
}

/*
Computes r = sum(scalars[i] * points[i]) + ng*G in variable time.

The simple algorithm: multiply each point separately and add. Upstream additionally offers
Strauss and Pippenger variants over a scratch space, which this implementation omits
because `CLAUDE.md` requires the hot paths to be allocation-free and there is no scratch
allocator here.

Pass a nil `ng` to omit the generator term.
*/
ecmult_multi_var :: proc "contextless" (
	r: ^group.Gej,
	ng: ^scalar.Scalar,
	scalars: []scalar.Scalar,
	points: []group.Gej,
) {
	CHECK(len(scalars) == len(points), "ecmult_multi_var: mismatched input lengths")

	group.gej_set_infinity(r)

	if ng != nil {
		ecmult(r, r, &scalar.ZERO, ng)
	}

	for i in 0 ..< len(points) {
		term: group.Gej
		pt := points[i]
		ecmult(&term, &pt, &scalars[i], nil)
		group.gej_add_var(r, r, &term, nil)
	}
}
