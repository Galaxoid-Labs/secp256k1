/*
Constant-time multiplication of the generator: R = gn*G.

This is the path used for public-key derivation and for signing nonces, so it handles the
most sensitive scalars in the library. Two protections beyond constant-time execution:

  - **Scalar blinding.** The computation is rewritten as (gn - b)*G + b*G for a
    context-supplied blinding value b, so the scalar actually fed to the comb is not the
    secret one.
  - **Projective blinding.** The accumulator is given a random Z coordinate at the start,
    which randomizes every intermediate value without changing the result.

Both come from the context and are refreshed by `context_randomize`. With a zero-initialized
context the blinding is the identity, which is correct but unblinded — Phase 5 wires up
real randomization.

# The comb

The signed-digit multi-comb from Hamburg's "Fast and compact elliptic-curve cryptography"
section 3.3. Define comb(s, P) = sum((2*s[i] - 1) * 2^i * P), reading the bits of s as
signs. Then comb(s, P) = (2*s - (2^COMB_BITS - 1)) * P, so computing (gn-b)*G as
comb(d, G/2) requires

	d = gn - b + (2^COMB_BITS - 1)/2   (mod n)

Using G/2 rather than G is what avoids a modular division by two per call. Folding the
constants into the context gives

	scalar_offset = (2^COMB_BITS - 1)/2 - b   (mod n)
	ge_offset     = b*G
	d             = gn + scalar_offset
	R             = comb(d, G/2) + ge_offset

Mirrors upstream's `ecmult_gen_impl.h`.
*/
package ecmult

import "../field"
import "../group"
import "../params"
import "../scalar"

/*
Comb parameters. The table holds COMB_BLOCKS * 2^(COMB_TEETH-1) points; the computation
costs COMB_BLOCKS * COMB_SPACING point additions and COMB_SPACING - 1 doublings.

Upstream's (11, 6) default gives a 22 kB table, which is the size/speed sweet spot.
*/
when params.EXHAUSTIVE_ORDER == 0 {
	COMB_RANGE :: 256
	COMB_BLOCKS :: 11
	COMB_TEETH :: 6
} else when params.EXHAUSTIVE_ORDER == 7 {
	COMB_RANGE :: 3
	COMB_BLOCKS :: 1
	COMB_TEETH :: 2
} else when params.EXHAUSTIVE_ORDER == 13 {
	COMB_RANGE :: 4
	COMB_BLOCKS :: 1
	COMB_TEETH :: 2
} else {
	COMB_RANGE :: 8
	COMB_BLOCKS :: 2
	COMB_TEETH :: 3
}

/*
Distance between the teeth of the comb: ceil(COMB_RANGE / (COMB_BLOCKS * COMB_TEETH)).
*/
COMB_SPACING :: (COMB_RANGE + COMB_BLOCKS * COMB_TEETH - 1) / (COMB_BLOCKS * COMB_TEETH)

/*
Total bits covered by all blocks; at least COMB_RANGE.
*/
COMB_BITS :: COMB_BLOCKS * COMB_TEETH * COMB_SPACING

/*
Entries per block. Only half the values need storing, because flipping the relevant bits
of an index negates the table value.
*/
COMB_POINTS :: 1 << (COMB_TEETH - 1)

#assert(COMB_BITS >= COMB_RANGE, "comb does not cover the scalar range")

/*
The precomputed comb table: `PREC_TABLE[block][index]`.
*/
PREC_TABLE: [COMB_BLOCKS][COMB_POINTS]group.Ge_Storage

/*
Per-context blinding state.

A zero value is usable and correct, but performs no blinding. `context_randomize` in Phase
5 replaces it with real values.
*/
Ecmult_Gen_Context :: struct {
	/*
	(2^COMB_BITS - 1)/2 - b (mod n), where b is the blinding scalar.
	*/
	scalar_offset: scalar.Scalar,
	/*
	b*G, added back at the end.
	*/
	ge_offset:     group.Ge,
	/*
	Random Z coordinate applied to the accumulator to blind intermediate values.
	*/
	proj_blind:    field.Field_Elem,
	/*
	Whether the context has been initialized.
	*/
	built:         bool,
}

/*
Computes (2^COMB_BITS - 1)/2, the difference between the caller's scalar and the one whose
bits the comb reads.
*/
@(private)
gen_scalar_diff :: proc "contextless" (diff: ^scalar.Scalar) {
	// -1/2
	neghalf: scalar.Scalar
	scalar.scalar_half(&neghalf, &scalar.ONE)
	scalar.scalar_negate(&neghalf, &neghalf)

	// 2^(COMB_BITS - 1)
	diff^ = scalar.ONE
	for _ in 0 ..< COMB_BITS - 1 {
		scalar.scalar_add(diff, diff, diff)
	}

	// 2^(COMB_BITS - 1) + (-1/2)
	scalar.scalar_add(diff, diff, &neghalf)
}

/*
Initializes a context with no blinding.

Correct but unblinded: every call uses the same intermediate values, which is exactly what
`context_randomize` exists to prevent. Suitable for public-data use and for tests.

The blinding value is set to -1 rather than 0. Zero would make ge_offset = 0*G = infinity,
and `gej_add_ge` — the constant-time addition used at the end of every call — cannot accept
an infinite affine operand. With b = -1 the offsets are ge_offset = -G and
scalar_offset = diff + 1, which is equally unblinded and always well defined.
*/
ecmult_gen_context_build :: proc "contextless" (ctx: ^Ecmult_Gen_Context) {
	// Only the signing comb table is needed here. `ecmult_gen` never reads `PRE_G` — those
	// serve the variable-time engine — so building them from a signing setup path would be
	// ~12 ms of work for a megabyte this context never touches.
	ensure_gen_table()

	diff: scalar.Scalar
	gen_scalar_diff(&diff)

	g := group.GENERATOR
	group.ge_neg(&ctx.ge_offset, &g)
	scalar.scalar_add(&ctx.scalar_offset, &scalar.ONE, &diff)
	field.fe_set_int(&ctx.proj_blind, 1)
	ctx.built = true
}

/*
Re-randomizes a context's blinding from a 32-byte seed, chaining the previous value
forward.

Passing a nil seed resets to the unblinded state of `ecmult_gen_context_build`.

Implemented in `ecmult_blind.odin`, which is where the `hash` dependency lives.
*/
ecmult_gen_blind :: ecmult_gen_blind_seeded

/*
Zeroes a context's blinding state.
*/
ecmult_gen_context_clear :: proc "contextless" (ctx: ^Ecmult_Gen_Context) {
	scalar.scalar_clear(&ctx.scalar_offset)
	group.ge_clear(&ctx.ge_offset)
	field.fe_clear(&ctx.proj_blind)
	ctx.built = false
}

/*
Builds the comb table of multiples of G/2.

Entry `table[block][index]` holds table(block, m) = (m - mask(block)/2) * G, where the bits
of the index select which powers of two in that block are added versus subtracted.
*/
gen_compute_table :: proc "contextless" (
	table: ^[COMB_BLOCKS][COMB_POINTS]group.Ge_Storage,
	gen: ^group.Ge,
) {
	vs: [COMB_BLOCKS * COMB_POINTS]group.Gej
	ds: [COMB_TEETH]group.Gej
	prec: [COMB_BLOCKS * COMB_POINTS]group.Ge
	vs_pos := 0

	// u is the running power of two times gen, starting at gen/2. A plain ladder is used
	// so that table construction does not depend on the very engine it feeds.
	half := scalar_half_one()
	u: group.Gej
	group.gej_set_infinity(&u)
	for i := 255; i >= 0; i -= 1 {
		group.gej_double_var(&u, &u, nil)
		if scalar.scalar_get_bits_limb32(&half, uint(i), 1) != 0 {
			group.gej_add_ge_var(&u, &u, gen, nil)
		}
	}

	when VERIFY {
		double_u: group.Gej
		group.gej_double_var(&double_u, &u, nil)
		CHECK(group.gej_eq_ge_var(&double_u, gen), "gen_compute_table: u*2 != gen")
	}

	for block in 0 ..< COMB_BLOCKS {
		// Here u = 2^(block*teeth*spacing) * gen/2.
		sum: group.Gej
		group.gej_set_infinity(&sum)

		for tooth in 0 ..< COMB_TEETH {
			group.gej_add_var(&sum, &sum, &u, nil)
			group.gej_double_var(&u, &u, nil)
			ds[tooth] = u

			if block + tooth != COMB_BLOCKS + COMB_TEETH - 2 {
				for _ in 1 ..< COMB_SPACING {
					group.gej_double_var(&u, &u, nil)
				}
			}
		}

		// The first entry corresponds to every power of two being subtracted.
		group.gej_neg(&vs[vs_pos], &sum)
		vs_pos += 1

		// Then double the covered index range teeth-1 times, each step adding ds[tooth]
		// to an existing entry.
		for tooth in 0 ..< COMB_TEETH - 1 {
			stride := 1 << uint(tooth)
			for index in 0 ..< stride {
				group.gej_add_var(&vs[vs_pos], &vs[vs_pos - stride], &ds[tooth], nil)
				vs_pos += 1
			}
		}
	}
	CHECK(vs_pos == COMB_BLOCKS * COMB_POINTS, "gen_compute_table: wrong entry count")

	// One batched inversion for the whole table.
	group.ge_set_all_gej_var(prec[:], vs[:])

	for block in 0 ..< COMB_BLOCKS {
		for index in 0 ..< COMB_POINTS {
			e := &prec[block * COMB_POINTS + index]
			CHECK(!group.ge_is_infinity(e), "gen_compute_table: entry is infinity")
			group.ge_to_storage(&table[block][index], e)
		}
	}
}

/*
Rotates a 32-bit value right.

Used instead of a plain shift when extracting comb bits, so that the value keeps its full
entropy: a shift discards the bits that fall off the bottom, which can leave a variable
with very few possible values and make it a side-channel target. See
https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-alam.pdf
*/
@(private)
rotr32 :: #force_inline proc "contextless" (x: u32, n: u32) -> u32 {
	return (x >> n) | (x << ((32 - n) & 31))
}

/*
Computes r = gn*G in constant time.
*/
ecmult_gen :: proc "contextless" (ctx: ^Ecmult_Gen_Context, r: ^group.Gej, gn: ^scalar.Scalar) {
	CHECK(ctx.built, "ecmult_gen: context has not been built")

	// d = gn + scalar_offset, the scalar whose bits the comb reads.
	d: scalar.Scalar
	scalar.scalar_add(&d, &ctx.scalar_offset, gn)

	// Only the bottom eight words are ever non-zero; the padding avoids out-of-range
	// reads when COMB_BITS exceeds 256.
	recoded: [(COMB_BITS + 31) >> 5]u32
	for i in 0 ..< min(8, (COMB_BITS + 31) >> 5) {
		recoded[i] = scalar.scalar_get_bits_limb32(&d, uint(32 * i), 32)
	}
	scalar.scalar_clear(&d)

	adds: group.Ge_Storage
	add: group.Ge
	neg: field.Field_Elem
	first := true

	comb_off := COMB_SPACING - 1
	for {
		bit_pos := comb_off

		for block in 0 ..< COMB_BLOCKS {
			// Gather this block's bits, packed:
			//   bits[tooth] = d[(block*TEETH + tooth)*SPACING + comb_off]
			//
			// Built by xoring rotated reads rather than reading bits individually, so
			// intermediate values never collapse to a small set of possibilities.
			bits := u32(0)
			for tooth in 0 ..< COMB_TEETH {
				bitdata := rotr32(recoded[bit_pos >> 5], u32(bit_pos) & 0x1f)

				// Clear the target bit, then write the real one in. The junk in higher
				// bits is masked off below.
				bits &= ~(u32(1) << uint(tooth))
				bits ~= bitdata << uint(tooth)
				bit_pos += COMB_SPACING
			}

			// A set top bit means the negated entry is wanted.
			sign := (bits >> (COMB_TEETH - 1)) & 1
			abs := (bits ~ (0 - sign)) & (COMB_POINTS - 1)
			CHECK(abs < COMB_POINTS, "ecmult_gen: index out of range")

			// Scan the whole block with conditional moves. Indexing by `abs` would be
			// faster and would leak the scalar through the cache; see
			// https://cryptojedi.org/peter/data/chesrump-20130822.pdf and
			// https://eprint.iacr.org/2005/271.pdf
			for index in 0 ..< u32(COMB_POINTS) {
				group.ge_storage_cmov(&adds, &PREC_TABLE[block][index], index == abs)
			}

			group.ge_from_storage(&add, &adds)
			field.fe_negate(&neg, &add.y, 1)
			field.fe_cmov(&add.y, &neg, sign == 1)

			if first {
				group.gej_set_ge(r, &add)
				// Blind the intermediate values with a random Z.
				group.gej_rescale(r, &ctx.proj_blind)
				first = false
			} else {
				group.gej_add_ge(r, r, &add)
			}
		}

		if comb_off == 0 {
			break
		}
		comb_off -= 1
		group.gej_double(r, r)
	}

	// Undo the blinding: ge_offset is b*G, and b was folded out of the input scalar.
	group.gej_add_ge(r, r, &ctx.ge_offset)
}
