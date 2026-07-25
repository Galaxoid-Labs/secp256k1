/*
Conversion between field elements and 32-byte big-endian representations.

The limb boundaries fall at multiples of 52 bits while byte boundaries fall at multiples
of 8, so limbs 1 and 3 straddle a byte: bytes 25 and 12 each carry the low nibble of one
limb and the high nibble of the next. That is the only subtlety here.

Mirrors upstream's `field_5x52_impl.h`.
*/
package field

/*
Sets r to the 32-byte big-endian value a, reduced modulo p.

Any 32-byte input is accepted. On output r has magnitude 1 and is not normalized, since
the value may still be at or above p. Use `fe_set_b32_limit` when an out-of-range input
should be rejected instead of reduced.
*/
fe_set_b32_mod :: proc "contextless" (r: ^Field_Elem, a: ^[32]u8) {
	r.n[0] =
		u64(a[31]) |
		u64(a[30]) << 8 |
		u64(a[29]) << 16 |
		u64(a[28]) << 24 |
		u64(a[27]) << 32 |
		u64(a[26]) << 40 |
		u64(a[25] & 0xf) << 48
	r.n[1] =
		u64((a[25] >> 4) & 0xf) |
		u64(a[24]) << 4 |
		u64(a[23]) << 12 |
		u64(a[22]) << 20 |
		u64(a[21]) << 28 |
		u64(a[20]) << 36 |
		u64(a[19]) << 44
	r.n[2] =
		u64(a[18]) |
		u64(a[17]) << 8 |
		u64(a[16]) << 16 |
		u64(a[15]) << 24 |
		u64(a[14]) << 32 |
		u64(a[13]) << 40 |
		u64(a[12] & 0xf) << 48
	r.n[3] =
		u64((a[12] >> 4) & 0xf) |
		u64(a[11]) << 4 |
		u64(a[10]) << 12 |
		u64(a[9]) << 20 |
		u64(a[8]) << 28 |
		u64(a[7]) << 36 |
		u64(a[6]) << 44
	r.n[4] =
		u64(a[5]) |
		u64(a[4]) << 8 |
		u64(a[3]) << 16 |
		u64(a[2]) << 24 |
		u64(a[1]) << 32 |
		u64(a[0]) << 40

	when VERIFY {
		r.magnitude = 1
		r.normalized = false
	}
	fe_verify(r)
}

/*
Sets r to the 32-byte big-endian value a, rejecting values at or above p.

Returns true and leaves r normalized with magnitude 1 when a < p. Returns false when
a >= p, in which case r is left in an invalid state and must be overwritten before use.
*/
fe_set_b32_limit :: proc "contextless" (r: ^Field_Elem, a: ^[32]u8) -> bool {
	fe_set_b32_mod(r, a)

	overflow :=
		r.n[4] == M48 &&
		(r.n[3] & r.n[2] & r.n[1]) == M52 &&
		r.n[0] >= P0
	if overflow {
		return false
	}

	when VERIFY {
		r.normalized = true
	}
	fe_verify(r)
	return true
}

/*
Writes a as a 32-byte big-endian value.

`a` must be normalized.
*/
fe_get_b32 :: proc "contextless" (r: ^[32]u8, a: ^Field_Elem) {
	fe_verify(a)
	when VERIFY {
		CHECK(a.normalized, "fe_get_b32: input must be normalized")
	}

	r[0] = u8((a.n[4] >> 40) & 0xff)
	r[1] = u8((a.n[4] >> 32) & 0xff)
	r[2] = u8((a.n[4] >> 24) & 0xff)
	r[3] = u8((a.n[4] >> 16) & 0xff)
	r[4] = u8((a.n[4] >> 8) & 0xff)
	r[5] = u8(a.n[4] & 0xff)
	r[6] = u8((a.n[3] >> 44) & 0xff)
	r[7] = u8((a.n[3] >> 36) & 0xff)
	r[8] = u8((a.n[3] >> 28) & 0xff)
	r[9] = u8((a.n[3] >> 20) & 0xff)
	r[10] = u8((a.n[3] >> 12) & 0xff)
	r[11] = u8((a.n[3] >> 4) & 0xff)
	r[12] = u8(((a.n[2] >> 48) & 0xf) | ((a.n[3] & 0xf) << 4))
	r[13] = u8((a.n[2] >> 40) & 0xff)
	r[14] = u8((a.n[2] >> 32) & 0xff)
	r[15] = u8((a.n[2] >> 24) & 0xff)
	r[16] = u8((a.n[2] >> 16) & 0xff)
	r[17] = u8((a.n[2] >> 8) & 0xff)
	r[18] = u8(a.n[2] & 0xff)
	r[19] = u8((a.n[1] >> 44) & 0xff)
	r[20] = u8((a.n[1] >> 36) & 0xff)
	r[21] = u8((a.n[1] >> 28) & 0xff)
	r[22] = u8((a.n[1] >> 20) & 0xff)
	r[23] = u8((a.n[1] >> 12) & 0xff)
	r[24] = u8((a.n[1] >> 4) & 0xff)
	r[25] = u8(((a.n[0] >> 48) & 0xf) | ((a.n[1] & 0xf) << 4))
	r[26] = u8((a.n[0] >> 40) & 0xff)
	r[27] = u8((a.n[0] >> 32) & 0xff)
	r[28] = u8((a.n[0] >> 24) & 0xff)
	r[29] = u8((a.n[0] >> 16) & 0xff)
	r[30] = u8((a.n[0] >> 8) & 0xff)
	r[31] = u8(a.n[0] & 0xff)
}
