/*
Scalar arithmetic modulo n, the order of the secp256k1 group.

A scalar is four 64-bit limbs, little-endian, always held fully reduced into [0, n). Unlike
the field, there is no magnitude bookkeeping: n has no exploitable structure — it is not
close to a power of two — so every operation reduces immediately rather than deferring.
That makes reduction more expensive than the field's and is why the multiplication below
folds a 512-bit product down in three stages.

Mirrors upstream's `scalar_4x64_impl.h`.

# Constant-time status

Everything here is constant-time in its scalar operands except the procedures suffixed
`_var`, which branch on values and must never see secret data. Scalars *are* secret data in
signing — a private key and a nonce are both scalars — so this distinction is load-bearing
rather than advisory.
*/
package scalar

import "base:runtime"
import "core:mem"
import "../params"

/*
Number of limbs.
*/
LIMBS :: 4

/*
Limbs of the group order n, little-endian.
*/
N_0 :: 0xbfd25e8cd0364141
N_1 :: 0xbaaedce6af48a03b
N_2 :: 0xffff_ffff_ffff_fffe
N_3 :: 0xffff_ffff_ffff_ffff

/*
Limbs of 2^256 - n, the complement used to fold a carry out of bit 256 back down. Only
three limbs are non-zero, which is what keeps the reduction cheap.
*/
N_C_0 :: ~u64(N_0) + 1
N_C_1 :: ~u64(N_1)
N_C_2 :: 1

/*
Limbs of n/2, rounded down. Used by `is_high` for low-S normalization and by `half`.
*/
N_H_0 :: 0xdfe92f46681b20a0
N_H_1 :: 0x5d576e7357a4501d
N_H_2 :: 0xffff_ffff_ffff_ffff
N_H_3 :: 0x7fff_ffff_ffff_ffff

/*
Whether internal invariant checks are compiled in. Follows `-debug`, matching `field`.
*/
VERIFY :: ODIN_DEBUG

/*
A scalar modulo n: four 64-bit limbs, little-endian, always reduced into [0, n).
*/
Scalar :: struct {
	d: [LIMBS]u64,
}

@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "scalar invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(condition, message, loc)
	}
}

/*
Asserts that a is fully reduced.

Unlike the field's `fe_verify`, there is only one thing to check: scalars carry no
magnitude, so being below n is the entire invariant.
*/
scalar_verify :: #force_inline proc "contextless" (a: ^Scalar, loc := #caller_location) {
	when VERIFY {
		runtime.assert_contextless(
			!scalar_check_overflow(a),
			"scalar_verify: value is not reduced below n",
			loc,
		)
	}
}

/*
The scalar 0.
*/
@(rodata)
ZERO := Scalar{d = {0, 0, 0, 0}}

/*
The scalar 1.
*/
@(rodata)
ONE := Scalar{d = {1, 0, 0, 0}}

/*
lambda: the cube root of 1 modulo n realising the secp256k1 endomorphism. Paired with the
field's `BETA`, it satisfies lambda*(x,y) == (beta*x, y).
*/
@(rodata)
LAMBDA := Scalar {
	d = {0xdf02967c1b23bd72, 0x122e22ea20816678, 0xa5261c028812645a, 0x5363ad4cc05c30e0},
}

/*
Constructs a scalar from eight big-endian 32-bit words, d7 most significant.

The value must already be below n; this does not reduce. Intended for compile-time
constants, with `scalar_set_b32` as the runtime path.
*/
scalar_const :: proc "contextless" (d7, d6, d5, d4, d3, d2, d1, d0: u32) -> (r: Scalar) {
	r.d[0] = u64(d1) << 32 | u64(d0)
	r.d[1] = u64(d3) << 32 | u64(d2)
	r.d[2] = u64(d5) << 32 | u64(d4)
	r.d[3] = u64(d7) << 32 | u64(d6)
	scalar_verify(&r)
	return
}

/*
Zeroes a scalar so that secret material does not outlive its use.
*/
scalar_clear :: proc "contextless" (a: ^Scalar) {
	mem.zero_explicit(a, size_of(Scalar))
}

/*
Sets r to a small non-negative integer.
*/
scalar_set_int :: proc "contextless" (r: ^Scalar, v: u32) {
	r.d = {u64(v), 0, 0, 0}
	scalar_verify(r)
}

/*
Returns `count` bits of a starting at `offset`, where the range lies within a single limb.

`count` must be in [1, 32] and the range must not straddle a limb boundary; use
`scalar_get_bits_var` when it might.
*/
scalar_get_bits_limb32 :: proc "contextless" (a: ^Scalar, offset, count: uint) -> u32 {
	scalar_verify(a)
	CHECK(count > 0 && count <= 32, "scalar_get_bits_limb32: count out of range")
	CHECK(
		(offset + count - 1) >> 6 == offset >> 6,
		"scalar_get_bits_limb32: range straddles a limb boundary",
	)

	return u32((a.d[offset >> 6] >> (offset & 0x3f)) & u64(0xffff_ffff >> (32 - count)))
}

/*
Returns `count` bits of a starting at `offset`, spanning limbs if needed.

Variable-time only in the sense that it branches on `offset`, which is a loop index in the
callers rather than secret data.
*/
scalar_get_bits_var :: proc "contextless" (a: ^Scalar, offset, count: uint) -> u32 {
	scalar_verify(a)
	CHECK(count > 0 && count <= 32, "scalar_get_bits_var: count out of range")
	CHECK(offset + count <= 256, "scalar_get_bits_var: range past the end")

	if (offset + count - 1) >> 6 == offset >> 6 {
		return scalar_get_bits_limb32(a, offset, count)
	}

	CHECK((offset >> 6) + 1 < 4, "scalar_get_bits_var: spans past the top limb")
	lo := a.d[offset >> 6] >> (offset & 0x3f)
	hi := a.d[(offset >> 6) + 1] << (64 - (offset & 0x3f))
	return u32((lo | hi) & u64(0xffff_ffff >> (32 - count)))
}

/*
Reports whether a is at or above n.

Branch-free: the `yes`/`no` accumulators encode a lexicographic comparison without any
data-dependent control flow.
*/
scalar_check_overflow :: proc "contextless" (a: ^Scalar) -> bool {
	yes := u64(0)
	no := u64(0)

	no |= u64(a.d[3] < N_3) // No need for a matching > check: N_3 is all ones.
	no |= u64(a.d[2] < N_2)
	yes |= u64(a.d[2] > N_2) & ~no
	no |= u64(a.d[1] < N_1)
	yes |= u64(a.d[1] > N_1) & ~no
	yes |= u64(a.d[0] >= N_0) & ~no

	return yes != 0
}

/*
Conditionally subtracts n from r, and returns whether it did.

`overflow` must be 0 or 1. The subtraction is performed as an addition of 2^256 - n so that
it runs unconditionally, making this constant-time.
*/
scalar_reduce :: proc "contextless" (r: ^Scalar, overflow: u64) -> u64 {
	CHECK(overflow <= 1, "scalar_reduce: overflow flag must be 0 or 1")

	t := u128(r.d[0])
	t += u128(overflow * N_C_0)
	r.d[0] = u64(t); t >>= 64
	t += u128(r.d[1])
	t += u128(overflow * N_C_1)
	r.d[1] = u64(t); t >>= 64
	t += u128(r.d[2])
	t += u128(overflow * N_C_2)
	r.d[2] = u64(t); t >>= 64
	t += u128(r.d[3])
	r.d[3] = u64(t)

	scalar_verify(r)
	return overflow
}

/*
Sets r to a + b modulo n, returning whether the addition overflowed before reduction.
*/
scalar_add :: proc "contextless" (r: ^Scalar, a: ^Scalar, b: ^Scalar) -> u64 {
	scalar_verify(a)
	scalar_verify(b)

	t := u128(a.d[0]) + u128(b.d[0])
	r.d[0] = u64(t); t >>= 64
	t += u128(a.d[1]) + u128(b.d[1])
	r.d[1] = u64(t); t >>= 64
	t += u128(a.d[2]) + u128(b.d[2])
	r.d[2] = u64(t); t >>= 64
	t += u128(a.d[3]) + u128(b.d[3])
	r.d[3] = u64(t); t >>= 64

	overflow := u64(t) + u64(scalar_check_overflow(r))
	CHECK(overflow == 0 || overflow == 1, "scalar_add: unexpected overflow value")
	scalar_reduce(r, overflow)

	scalar_verify(r)
	return overflow
}

/*
Conditionally adds 2^bit to r, in constant time.

`bit` must be below 256 and `flag` selects whether the addition happens. When flag is
false the bit index is forced past the top limb, which turns every conditional add into a
no-op without branching. The result must not overflow, which the caller guarantees.
*/
scalar_cadd_bit :: proc "contextless" (r: ^Scalar, bit_in: uint, flag: bool) {
	scalar_verify(r)
	CHECK(bit_in < 256, "scalar_cadd_bit: bit index out of range")

	// Forcing (bit >> 6) > 3 makes every limb's contribution zero.
	bit := bit_in + uint((u32(flag) - 1) & 0x100)

	t := u128(r.d[0])
	t += u128(u64(bit >> 6 == 0) << (bit & 0x3f))
	r.d[0] = u64(t); t >>= 64
	t += u128(r.d[1])
	t += u128(u64(bit >> 6 == 1) << (bit & 0x3f))
	r.d[1] = u64(t); t >>= 64
	t += u128(r.d[2])
	t += u128(u64(bit >> 6 == 2) << (bit & 0x3f))
	r.d[2] = u64(t); t >>= 64
	t += u128(r.d[3])
	t += u128(u64(bit >> 6 == 3) << (bit & 0x3f))
	r.d[3] = u64(t)

	scalar_verify(r)
	CHECK(u64(t >> 64) == 0, "scalar_cadd_bit: addition overflowed")
}

/*
Sets r to the 32-byte big-endian value b32, reduced modulo n.

Returns whether the input was at or above n and therefore had to be reduced. Callers
validating a secret key treat a true return as rejection rather than accepting the reduced
value.
*/
scalar_set_b32 :: proc "contextless" (r: ^Scalar, b32: ^[32]u8) -> (overflowed: bool) {
	r.d[0] = read_be64(b32[24:32])
	r.d[1] = read_be64(b32[16:24])
	r.d[2] = read_be64(b32[8:16])
	r.d[3] = read_be64(b32[0:8])

	over := scalar_reduce(r, u64(scalar_check_overflow(r)))
	scalar_verify(r)
	return over != 0
}

/*
Sets r from a 32-byte big-endian value, rejecting zero and out-of-range values.

This is the secret-key validity rule: a key must be in [1, n).
*/
scalar_set_b32_seckey :: proc "contextless" (r: ^Scalar, b32: ^[32]u8) -> bool {
	overflowed := scalar_set_b32(r, b32)
	return !overflowed && !scalar_is_zero(r)
}

/*
Writes a as a 32-byte big-endian value.
*/
scalar_get_b32 :: proc "contextless" (bin: ^[32]u8, a: ^Scalar) {
	scalar_verify(a)
	write_be64(bin[0:8], a.d[3])
	write_be64(bin[8:16], a.d[2])
	write_be64(bin[16:24], a.d[1])
	write_be64(bin[24:32], a.d[0])
}

/*
Reports whether a is zero.
*/
scalar_is_zero :: proc "contextless" (a: ^Scalar) -> bool {
	scalar_verify(a)
	return (a.d[0] | a.d[1] | a.d[2] | a.d[3]) == 0
}

/*
Reports whether a is one.
*/
scalar_is_one :: proc "contextless" (a: ^Scalar) -> bool {
	scalar_verify(a)
	return ((a.d[0] ~ 1) | a.d[1] | a.d[2] | a.d[3]) == 0
}

/*
Reports whether a is even.
*/
scalar_is_even :: proc "contextless" (a: ^Scalar) -> bool {
	scalar_verify(a)
	return a.d[0] & 1 == 0
}

/*
Reports whether a exceeds n/2.

This is the low-S test: an ECDSA signature with a high S is malleable, since (r, n-s) is
equally valid, so signers normalize to the low form and verifiers may reject the high one.
*/
scalar_is_high :: proc "contextless" (a: ^Scalar) -> bool {
	scalar_verify(a)

	yes := u64(0)
	no := u64(0)

	no |= u64(a.d[3] < N_H_3)
	yes |= u64(a.d[3] > N_H_3) & ~no
	no |= u64(a.d[2] < N_H_2) & ~yes // No need for a matching > check.
	no |= u64(a.d[1] < N_H_1) & ~yes
	yes |= u64(a.d[1] > N_H_1) & ~no
	yes |= u64(a.d[0] > N_H_0) & ~no

	return yes != 0
}

/*
Sets r to -a modulo n. Zero negates to zero.
*/
scalar_negate :: proc "contextless" (r: ^Scalar, a: ^Scalar) {
	scalar_verify(a)

	// All-ones when a is non-zero, so that zero stays zero without branching.
	nonzero := u64(0xffff_ffff_ffff_ffff) * u64(!scalar_is_zero(a))

	t := u128(~a.d[0]) + u128(u64(N_0) + 1)
	r.d[0] = u64(t) & nonzero; t >>= 64
	t += u128(~a.d[1]) + u128(u64(N_1))
	r.d[1] = u64(t) & nonzero; t >>= 64
	t += u128(~a.d[2]) + u128(u64(N_2))
	r.d[2] = u64(t) & nonzero; t >>= 64
	t += u128(~a.d[3]) + u128(u64(N_3))
	r.d[3] = u64(t) & nonzero

	scalar_verify(r)
}

/*
Conditionally negates r, returning 1 when it negated and -1 when it did not.

Constant-time in both r and flag. The odd return convention matches upstream, where callers
multiply a tracked sign by it.
*/
scalar_cond_negate :: proc "contextless" (r: ^Scalar, flag: bool) -> int {
	scalar_verify(r)

	mask := u64(0) - u64(flag)
	nonzero := u64(scalar_is_zero(r)) - 1

	t := u128(r.d[0] ~ mask) + u128(u64(N_0 + 1) & mask)
	r.d[0] = u64(t) & nonzero; t >>= 64
	t += u128(r.d[1] ~ mask) + u128(u64(N_1) & mask)
	r.d[1] = u64(t) & nonzero; t >>= 64
	t += u128(r.d[2] ~ mask) + u128(u64(N_2) & mask)
	r.d[2] = u64(t) & nonzero; t >>= 64
	t += u128(r.d[3] ~ mask) + u128(u64(N_3) & mask)
	r.d[3] = u64(t) & nonzero

	scalar_verify(r)
	return 2 * int(mask == 0) - 1
}

/*
Sets r to a/2 modulo n, in constant time.

Uses a/2 = (a >> 1) + (a odd ? n//2 + 1 : 0), since 1/2 == n//2 + 1 (mod n). The sum cannot
overflow: the worst case is a = n-2, the largest odd scalar, where the two terms are
(n-3)//2 and (n+1)//2, summing to n-1.
*/
scalar_half :: proc "contextless" (r: ^Scalar, a: ^Scalar) {
	scalar_verify(a)

	mask := u64(0) - (a.d[0] & 1)

	t := u128((a.d[0] >> 1) | (a.d[1] << 63))
	t += u128(u64(N_H_0 + 1) & mask)
	r.d[0] = u64(t); t >>= 64
	t += u128((a.d[1] >> 1) | (a.d[2] << 63))
	t += u128(u64(N_H_1) & mask)
	r.d[1] = u64(t); t >>= 64
	t += u128((a.d[2] >> 1) | (a.d[3] << 63))
	t += u128(u64(N_H_2) & mask)
	r.d[2] = u64(t); t >>= 64
	r.d[3] = u64(t) + (a.d[3] >> 1) + (u64(N_H_3) & mask)

	when VERIFY {
		// The line above computed only the low 64 bits of the top limb; redo it in full
		// width to confirm nothing was lost.
		t += u128(a.d[3] >> 1)
		t += u128(u64(N_H_3) & mask)
		t >>= 64
		CHECK(u64(t) == 0, "scalar_half: top limb overflowed")
		scalar_verify(r)
	}
}

/*
Reports whether two scalars are equal.
*/
scalar_eq :: proc "contextless" (a: ^Scalar, b: ^Scalar) -> bool {
	scalar_verify(a)
	scalar_verify(b)
	return ((a.d[0] ~ b.d[0]) | (a.d[1] ~ b.d[1]) | (a.d[2] ~ b.d[2]) | (a.d[3] ~ b.d[3])) == 0
}

/*
Sets r to a if flag is true, leaving it unchanged otherwise, in constant time.
*/
scalar_cmov :: proc "contextless" (r: ^Scalar, a: ^Scalar, flag: bool) {
	scalar_verify(a)

	mask0 := u64(flag) + ~u64(0)
	mask1 := ~mask0

	r.d[0] = (r.d[0] & mask0) | (a.d[0] & mask1)
	r.d[1] = (r.d[1] & mask0) | (a.d[1] & mask1)
	r.d[2] = (r.d[2] & mask0) | (a.d[2] & mask1)
	r.d[3] = (r.d[3] & mask0) | (a.d[3] & mask1)

	scalar_verify(r)
}

/*
Splits k into its low and high 128-bit halves.
*/
scalar_split_128 :: proc "contextless" (r1: ^Scalar, r2: ^Scalar, k: ^Scalar) {
	scalar_verify(k)

	r1.d = {k.d[0], k.d[1], 0, 0}
	r2.d = {k.d[2], k.d[3], 0, 0}

	scalar_verify(r1)
	scalar_verify(r2)
}

/*
Reads eight bytes as a big-endian u64.
*/
@(private)
read_be64 :: #force_inline proc "contextless" (b: []u8) -> u64 {
	return(
		u64(b[0]) << 56 |
		u64(b[1]) << 48 |
		u64(b[2]) << 40 |
		u64(b[3]) << 32 |
		u64(b[4]) << 24 |
		u64(b[5]) << 16 |
		u64(b[6]) << 8 |
		u64(b[7]) \
	)
}

/*
Writes a u64 as eight big-endian bytes.
*/
@(private)
write_be64 :: #force_inline proc "contextless" (b: []u8, v: u64) {
	b[0] = u8(v >> 56)
	b[1] = u8(v >> 48)
	b[2] = u8(v >> 40)
	b[3] = u8(v >> 32)
	b[4] = u8(v >> 24)
	b[5] = u8(v >> 16)
	b[6] = u8(v >> 8)
	b[7] = u8(v)
}

// The exhaustive-test curves use a tiny prime order, so the four-limb machinery above is
// overkill but still correct: every value fits in limb 0. `params.EXHAUSTIVE_ORDER` is
// consulted by the group and ecmult layers rather than here.
#assert(params.EXHAUSTIVE_ORDER >= 0)
