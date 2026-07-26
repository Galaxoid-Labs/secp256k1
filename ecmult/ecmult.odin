/*
Scalar multiplication engines.

Three of them, with different security and performance characteristics:

  - `ecmult`       — computes na*A + ng*G in **variable time**, using wNAF and the GLV
                     endomorphism. This is the verification path; both scalars are public.
  - `ecmult_const` — computes q*A in **constant time**, for secret scalars. Used by ECDH and
                     anything else multiplying by a secret.
  - `ecmult_gen`   — computes gn*G in **constant time** with a precomputed, blinded table.
                     Used for public-key derivation and signing nonces.

Choosing the wrong one is a security bug, not a performance one: running `ecmult` on a
secret scalar leaks it through timing. The naming follows upstream so the distinction is
visible at every call site.

Mirrors upstream's `ecmult_impl.h`, `ecmult_const_impl.h` and `ecmult_gen_impl.h`.

# Tables

Upstream generates its generator tables into a checked-in C source file of several
megabytes. This implementation computes them at package initialization instead, using
batched inversion so the cost is a few milliseconds rather than one field inversion per
entry. That keeps the repository small — which matters when it is consumed as a git
submodule — and means there is no vendored table to drift out of sync with the code.

`tests/ecmult` verifies every table entry against an independently computed multiple of the
generator, which is a stronger check than reproducing a checked-in blob byte for byte.
*/
package ecmult

import "base:runtime"
import "../field"
import "../group"
import "../params"
import "../scalar"

/*
Whether internal invariant checks are compiled in. Follows `-debug`, overridable with
`-define:SECP256K1_VERIFY=false`; see the `field` package for why that override exists.
*/
VERIFY :: #config(SECP256K1_VERIFY, ODIN_DEBUG)

@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "ecmult invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(condition, message, loc)
	}
}

/*
Window size for the variable-time multiplication of an arbitrary point.

The table for a point is built on the fly, so a larger window costs both time and stack.
Five is optimal for 128-bit and 256-bit exponents on the real curve. The exhaustive curves
need smaller values, because a table entry must never be the point at infinity — that would
break the shared-Z tracking the effective-affine technique relies on.
*/
when params.EXHAUSTIVE_ORDER == 0 {
	WINDOW_A :: 5
} else when params.EXHAUSTIVE_ORDER > 128 {
	WINDOW_A :: 5
} else when params.EXHAUSTIVE_ORDER > 8 {
	WINDOW_A :: 4
} else {
	WINDOW_A :: 2
}

/*
Window size for the precomputed generator tables used by variable-time multiplication.

Larger values trade memory for speed: the table holds `1 << (WINDOW_G - 2)` entries, and two
such tables exist because of the endomorphism split. 15 matches upstream and costs about a
megabyte, built at startup here rather than vendored as generated source.

Measured on ARM64, dropping to 12 costs roughly 20% on the verify paths and saves 0.9 MB,
so the default follows upstream. Lower it with `-define:ECMULT_WINDOW_SIZE=n` where the
memory matters more than verification throughput; the range is [2, 24].
*/
ECMULT_WINDOW_SIZE :: #config(ECMULT_WINDOW_SIZE, 15)

#assert(
	ECMULT_WINDOW_SIZE >= 2 && ECMULT_WINDOW_SIZE <= 24,
	"ECMULT_WINDOW_SIZE must be in the range [2, 24]",
)

WINDOW_G :: ECMULT_WINDOW_SIZE

/*
Number of entries in a table of odd multiples for the given window size.
*/
table_size :: #force_inline proc "contextless" (w: uint) -> int {
	return 1 << (w - 2)
}

TABLE_SIZE_A :: 1 << (WINDOW_A - 2)
TABLE_SIZE_G :: 1 << (WINDOW_G - 2)

/*
Number of bits the wNAF representation covers after the endomorphism split.
*/
WNAF_BITS :: 128

/*
Fills `pre` with the odd multiples [1*a, 3*a, ..., (2n-1)*a] of a, and `zr` with the
Z ratios needed to recover their omitted Z coordinates.

`pre` holds affine-looking points that are really Jacobian points with their Z coordinates
omitted. Writing z(b) for the omitted coordinate of entry b:

	z(pre[n-1]) = z
	z(pre[i-1]) = z(pre[i]) / zr[i]   for n > i > 0
	a.z         = z(pre[0]) / zr[0]

The additions are performed on the isomorphic curve Y^2 = X^3 + b*C^6 where C = d.z, under
the map (x, y, z) -> (x*C^2, y*C^3, z). That makes the doubled point representable in
affine coordinates, which lets the cheaper `gej_add_ge_var` be used throughout instead of a
full Jacobian addition.
*/
odd_multiples_table :: proc "contextless" (
	pre: []group.Ge,
	zr: []field.Field_Elem,
	z: ^field.Field_Elem,
	a: ^group.Gej,
) {
	n := len(pre)
	CHECK(n > 0, "odd_multiples_table: empty table")
	CHECK(len(zr) >= n, "odd_multiples_table: ratio slice too small")
	when VERIFY {
		CHECK(!group.gej_is_infinity(a), "odd_multiples_table: input is infinity")
	}

	d, ai: group.Gej
	d_ge: group.Ge

	group.gej_double_var(&d, a, nil)

	group.ge_set_xy(&d_ge, &d.x, &d.y)
	group.ge_set_gej_zinv(&pre[0], a, &d.z)
	group.gej_set_ge(&ai, &pre[0])
	ai.z = a.z

	// pre[0] is (a.x*C^2, a.y*C^3, a.z*C), equivalent to a. zr[0] is C, the ratio between
	// the omitted z(pre[0]) and a.z.
	zr[0] = d.z

	for i in 1 ..< n {
		group.gej_add_ge_var(&ai, &ai, &d_ge, &zr[i])
		group.ge_set_xy(&pre[i], &ai.x, &ai.y)
	}

	// Undo the isomorphism on the final Z. Because the other entries' Z coordinates are
	// implied by the ratios, this corrects all of them at once.
	field.fe_mul(z, &ai.z, &d.z)
}

/*
Asserts that a wNAF digit is valid for window w: odd, and within +/-(2^(w-1) - 1).
*/
@(private)
table_verify :: #force_inline proc "contextless" (n: int, w: uint) {
	when VERIFY {
		CHECK(n & 1 == 1, "ecmult table: digit is not odd")
		CHECK(n >= -((1 << (w - 1)) - 1), "ecmult table: digit below range")
		CHECK(n <= ((1 << (w - 1)) - 1), "ecmult table: digit above range")
	}
}

/*
Looks up the table entry for wNAF digit n, negating it when the digit is negative.

Variable-time in n, which is derived from a public scalar in every caller.
*/
table_get_ge :: proc "contextless" (r: ^group.Ge, pre: []group.Ge, n: int, w: uint) {
	table_verify(n, w)
	if n > 0 {
		r^ = pre[(n - 1) / 2]
	} else {
		r^ = pre[(-n - 1) / 2]
		field.fe_negate(&r.y, &r.y, 1)
	}
}

/*
Looks up the endomorphism image of a table entry, taking the x coordinate from a
precomputed beta-scaled array.

Avoids recomputing beta*x for every lookup.
*/
table_get_ge_lambda :: proc "contextless" (
	r: ^group.Ge,
	pre: []group.Ge,
	x: []field.Field_Elem,
	n: int,
	w: uint,
) {
	table_verify(n, w)
	if n > 0 {
		group.ge_set_xy(r, &x[(n - 1) / 2], &pre[(n - 1) / 2].y)
	} else {
		group.ge_set_xy(r, &x[(-n - 1) / 2], &pre[(-n - 1) / 2].y)
		field.fe_negate(&r.y, &r.y, 1)
	}
}

/*
Looks up a table entry held in packed storage form.
*/
table_get_ge_storage :: proc "contextless" (
	r: ^group.Ge,
	pre: []group.Ge_Storage,
	n: int,
	w: uint,
) {
	table_verify(n, w)
	if n > 0 {
		group.ge_from_storage(r, &pre[(n - 1) / 2])
	} else {
		group.ge_from_storage(r, &pre[(-n - 1) / 2])
		field.fe_negate(&r.y, &r.y, 1)
	}
}

/*
Converts a scalar to windowed non-adjacent form, returning the number of digits written.

The result satisfies a = sum(2^i * wnaf[i]) with:

  - each wnaf[i] either zero or an odd integer in +/-(2^(w-1) - 1)
  - at least w-1 zeros between any two non-zero entries

The sparsity is the point: it reduces the number of point additions in the multiplication
loop to roughly bits/(w+1).

Variable-time in a. Never call this on a secret scalar.
*/
wnaf :: proc "contextless" (out: []int, a: ^scalar.Scalar, w: uint) -> int {
	length := len(out)
	CHECK((length >= 0) & (length <= 256), "wnaf: length out of range")
	CHECK((w >= 2) & (w <= 31), "wnaf: window out of range")

	for i in 0 ..< length {
		out[i] = 0
	}

	s := a^
	sign := 1
	last_set_bit := -1
	carry := u32(0)
	bit := uint(0)

	// Negate if the top bit is set, so the digits stay small; the sign is applied to each
	// digit as it is emitted.
	if scalar.scalar_get_bits_limb32(&s, 255, 1) != 0 {
		scalar.scalar_negate(&s, &s)
		sign = -1
	}

	for bit < uint(length) {
		if scalar.scalar_get_bits_limb32(&s, bit, 1) == carry {
			bit += 1
			continue
		}

		now := w
		if now > uint(length) - bit {
			now = uint(length) - bit
		}

		word := int(scalar.scalar_get_bits_var(&s, bit, now)) + int(carry)

		carry = u32((word >> (w - 1)) & 1)
		word -= int(carry) << w

		out[bit] = sign * word
		last_set_bit = int(bit)

		bit += now
	}

	when VERIFY {
		CHECK(carry == 0, "wnaf: carry escaped the representation")
		for vb := bit; vb < 256; vb += 1 {
			CHECK(scalar.scalar_get_bits_limb32(&s, vb, 1) == 0, "wnaf: bits remain above the range")
		}
	}

	return last_set_bit + 1
}

/*
As `wnaf`, but writes into an i8 array. Requires w <= 8.
*/
wnaf_small :: proc "contextless" (out: []i8, a: ^scalar.Scalar, w: uint) -> int {
	CHECK((w >= 2) & (w <= 8), "wnaf_small: window out of range")

	// Uninitialized on purpose: `wnaf` zeroes the prefix it is given before writing, and
	// only that prefix is read below. Odin would otherwise zero all 256 entries — 2 KB per
	// call, twice per `ecmult`, immediately overwritten.
	tmp: [256]int = ---
	ret := wnaf(tmp[:len(out)], a, w)

	for i in 0 ..< len(out) {
		out[i] = i8(tmp[i])
	}
	return ret
}
