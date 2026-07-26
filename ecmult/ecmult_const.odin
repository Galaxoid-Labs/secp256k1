/*
Constant-time scalar multiplication: R = q*A for a secret q.

This is the path for ECDH and for anything else multiplying by a secret scalar. It has no
data-dependent branches and no secret-indexed memory access: table lookups scan the whole
table with conditional moves rather than indexing it, because indexing by a secret leaks
through the cache even when the access pattern looks uniform.

The approach combines the signed-digit method from Mike Hamburg's "Fast and compact
elliptic-curve cryptography" (https://eprint.iacr.org/2012/309) section 3.3 with the GLV
endomorphism.

# The signed-digit idea

Interpret the bits of a scalar as signs rather than magnitudes. For an n-bit non-negative v,

	C_l(v, A) = sum((2*v[i] - 1) * 2^i*A, i=0..l-1)
	          = (2*v + 1 - 2^l) * A

so q*A = C_256((q + 2^256 - 1)/2, A).

# Combining with the endomorphism

Naively splitting q into s1 + lambda*s2 and applying C_256 to each half does not help:
although s1 and s2 are small, (s1 + 2^256 - 1)/2 mod n is not, so nothing is saved.

The fix is to transform the scalar *before* splitting, so that the halves need only a
2^128 offset to become non-negative and stay within 129 bits. Solving

	q*A = C_l(s1 + 2^128, A) + C_l(s2 + 2^128, lambda*A)

gives s = (q + K)/2 (mod n) with K = (2^l - 2^129 - 1)*(1 + lambda) (mod n), where l is
rounded up to a multiple of the group size. Then both halves fit in [0, 2^129] and each is
processed in groups of `GROUP_SIZE` bits.

Mirrors upstream's `ecmult_const_impl.h`.
*/
package ecmult

import "../field"
import "../group"
import "../params"
import "../scalar"

/*
Number of scalar bits consumed per table lookup.

Four or five is optimal on the real curve. The exhaustive curves need smaller values,
because 2^GROUP_SIZE - 1 must stay below the group order — a table entry that came out as
the point at infinity would break the shared-Z tracking.
*/
when params.EXHAUSTIVE_ORDER == 0 {
	GROUP_SIZE :: 5
} else when params.EXHAUSTIVE_ORDER == 199 {
	GROUP_SIZE :: 4
} else when params.EXHAUSTIVE_ORDER == 13 {
	GROUP_SIZE :: 3
} else {
	GROUP_SIZE :: 2
}

CONST_TABLE_SIZE :: 1 << (GROUP_SIZE - 1)
CONST_GROUPS :: (129 + GROUP_SIZE - 1) / GROUP_SIZE
CONST_BITS :: CONST_GROUPS * GROUP_SIZE

/*
K = (2^CONST_BITS - 2^129 - 1) * (1 + lambda) mod n.

The value depends only on CONST_BITS, so one constant per supported group size. These were
derived independently from the formula above and agree with upstream's.
*/
when params.EXHAUSTIVE_ORDER != 0 {
	/*
	K for the exhaustive curves, as an exact compile-time expression.

	Upstream writes the same thing:

		((2^(CONST_BITS-128) - 2) * 2^128 + ORDER - 1) * (1 + lambda)  mod  ORDER

	Odin's constant arithmetic is arbitrary precision, so this is evaluated by the compiler
	and there is no 256-bit runtime computation to get wrong. Deriving it rather than
	tabulating it also means it stays correct if `GROUP_SIZE` changes for a new order.
	*/
	@(private)
	K_EXHAUSTIVE ::
		((((1 << (CONST_BITS - 128)) - 2) * (1 << 128) + params.EXHAUSTIVE_ORDER - 1) *
			(1 + params.EXHAUSTIVE_LAMBDA)) %
		params.EXHAUSTIVE_ORDER

	@(rodata)
	CONST_K := scalar.Scalar{d = u32(K_EXHAUSTIVE)}
} else when CONST_BITS == 129 {
	@(rodata)
	CONST_K := scalar.Scalar {
		d = {0xe0cfc810b51283ce, 0xa880b9fc8ec739c2, 0x5ad9e3fd77ed9ba4, 0xac9c52b33fa3cf1f},
	}
} else when CONST_BITS == 130 {
	@(rodata)
	CONST_K := scalar.Scalar {
		d = {0xb5c2c1dcde9798d9, 0x589ae84826ba29e4, 0xc2bdd6bf7c118d6b, 0xa4e88a7dcb13034e},
	}
} else when CONST_BITS == 132 {
	@(rodata)
	CONST_K := scalar.Scalar {
		d = {0xb3749ca5d7b6171b, 0x7937fe0db66bcaaf, 0x3215874b94e93813, 0x76b1d93d0fae3c6b},
	}
} else {
	#panic("no K constant for this CONST_BITS; see ecmult_const.odin")
}

/*
The offset added to each split half to make it non-negative: 2^128.

Written per representation rather than shared, because the two hold it differently: the 4x64
scalar has an exact limb for it, while under an exhaustive order it is 2^128 reduced. Odin's
constant arithmetic is arbitrary precision, so that reduction happens at compile time and
there is no runtime initialization to sequence.
*/
when params.EXHAUSTIVE_ORDER == 0 {
	@(rodata)
	S_OFFSET := scalar.Scalar{d = {0, 0, 1, 0}}
} else {
	@(private)
	TWO_POW_128_MOD_ORDER :: (1 << 128) % params.EXHAUSTIVE_ORDER

	@(rodata)
	S_OFFSET := scalar.Scalar{d = u32(TWO_POW_128_MOD_ORDER)}
}

/*
Builds a table of odd multiples of a, all sharing one Z denominator.

`pre` must have room for CONST_TABLE_SIZE entries.
*/
@(private)
const_odd_multiples_table_globalz :: proc "contextless" (
	pre: []group.Ge,
	globalz: ^field.Field_Elem,
	a: ^group.Gej,
) {
	zr: [CONST_TABLE_SIZE]field.Field_Elem
	odd_multiples_table(pre[:CONST_TABLE_SIZE], zr[:], globalz, a)
	group.ge_table_set_globalz(pre[:CONST_TABLE_SIZE], zr[:])
}

/*
Looks up the signed-digit table entry for the GROUP_SIZE-bit value n, in constant time.

The bits of n are signs of successive powers of two, so every n maps to an odd multiple in
+/-(2^GROUP_SIZE - 1). For example with GROUP_SIZE 4, n = 4 is binary 0100, read as
[- + - -], giving -(2^3) + 2^2 - 2^1 - 2^0 = -7, so entry 3 negated.

The whole table is scanned with conditional moves. Indexing it directly by n would be
faster and would leak the scalar.
*/
@(private)
const_table_get_ge :: proc "contextless" (r: ^group.Ge, pre: []group.Ge, n: u32) {
	CHECK(n < (1 << GROUP_SIZE), "const_table_get_ge: digit out of range")

	// If the top bit of n is clear, the negated entry is wanted.
	negative := ((n >> (GROUP_SIZE - 1)) ~ 1) & 1

	// The index is sum(cnot(n[i]) * 2^i) where cnot flips when the top bit is clear.
	index := ((0 - negative) ~ n) & ((1 << (GROUP_SIZE - 1)) - 1)
	CHECK(index < (1 << (GROUP_SIZE - 1)), "const_table_get_ge: index out of range")

	// Start from entry 0 so r is always initialized, then scan the rest.
	group.ge_set_xy(r, &pre[0].x, &pre[0].y)
	for m in 1 ..< u32(CONST_TABLE_SIZE) {
		field.fe_cmov(&r.x, &pre[m].x, m == index)
		field.fe_cmov(&r.y, &pre[m].y, m == index)
	}

	neg_y: field.Field_Elem
	field.fe_negate(&neg_y, &r.y, 1)
	field.fe_cmov(&r.y, &neg_y, negative == 1)
}

/*
Computes r = q*a in constant time with respect to q.

`a` may be infinity, and that check is variable-time — the point is not secret in any
caller, and the shared-Z table construction cannot represent infinity anyway.
*/
ecmult_const :: proc "contextless" (r: ^group.Gej, a: ^group.Ge, q: ^scalar.Scalar) {
	if group.ge_is_infinity(a) {
		group.gej_set_infinity(r)
		return
	}

	// s = (q + K)/2, then split into two ~128-bit halves and offset them to be
	// non-negative.
	s, v1, v2: scalar.Scalar
	scalar.scalar_add(&s, q, &CONST_K)
	scalar.scalar_half(&s, &s)
	scalar.scalar_split_lambda(&v1, &v2, &s)
	scalar.scalar_add(&v1, &v1, &S_OFFSET)
	scalar.scalar_add(&v2, &v2, &S_OFFSET)

	when VERIFY {
		// Both halves must now fit in 129 bits, or the group loop below would drop bits.
		for i in 129 ..< 256 {
			CHECK(scalar.scalar_get_bits_limb32(&v1, uint(i), 1) == 0, "ecmult_const: v1 exceeds 129 bits")
			when VERIFY {
				CHECK(scalar.scalar_get_bits_limb32(&v2, uint(i), 1) == 0, "ecmult_const: v2 exceeds 129 bits")
			}
		}
	}

	// Odd multiples of A and of lambda*A, sharing one Z denominator.
	pre_a: [CONST_TABLE_SIZE]group.Ge
	pre_a_lam: [CONST_TABLE_SIZE]group.Ge
	global_z: field.Field_Elem

	group.gej_set_ge(r, a)
	const_odd_multiples_table_globalz(pre_a[:], &global_z, r)
	for i in 0 ..< CONST_TABLE_SIZE {
		group.ge_mul_lambda(&pre_a_lam[i], &pre_a[i])
	}

	// Walk the groups from high to low, doubling GROUP_SIZE times between them.
	t: group.Ge
	for grp := CONST_GROUPS - 1; grp >= 0; grp -= 1 {
		// Variable in offset and count only, not in the scalar, so this is safe.
		bits1 := scalar.scalar_get_bits_var(&v1, uint(grp) * GROUP_SIZE, GROUP_SIZE)
		bits2 := scalar.scalar_get_bits_var(&v2, uint(grp) * GROUP_SIZE, GROUP_SIZE)

		const_table_get_ge(&t, pre_a[:], bits1)
		if grp == CONST_GROUPS - 1 {
			// First iteration: nothing to add to yet.
			group.gej_set_ge(r, &t)
		} else {
			for _ in 0 ..< GROUP_SIZE {
				group.gej_double(r, r)
			}
			group.gej_add_ge(r, r, &t)
		}

		const_table_get_ge(&t, pre_a_lam[:], bits2)
		group.gej_add_ge(r, r, &t)
	}

	// Map back from the isomorphic curve.
	field.fe_mul(&r.z, &r.z, &global_z)
}
