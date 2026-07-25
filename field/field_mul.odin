/*
The 5x52 multiplication and squaring kernels, using `u128` for the 64x64->128 products.

This is the reference implementation, mirroring upstream's `field_5x52_int128_impl.h`.
Odin's `u128` is native on every target, so unlike C there is no `__int128`-absent variant
to maintain.

# Reading the kernel

Both routines interleave schoolbook multiplication with reduction, so that the 512-bit
product never exists in full. The commentary uses upstream's notation:

	[... a b c]  means  ... + a<<104 + b<<52 + c<<0   (mod p)
	px           means  sum(a[i]*b[x-i]) over the valid range of i
	[x 0 0 0 0 0] = [x*R], since 2^260 = R<<4 (mod p)

Each `CHECK_BITS` records the bound the following step depends on. They are the reason the
accumulators provably never overflow 128 bits, and they are compiled away outside
`-debug`. Inputs must have magnitude at most 8, which is what keeps limbs within 56 bits.
*/
package field

/*
Sets r to a * b.

Both inputs must have magnitude at most 8. On output r has magnitude 1 but is not
normalized. `r` may alias `a`, but neither may alias `b`.
*/
@(private)
fe_mul_inner :: proc "contextless" (r: ^[LIMBS]u64, a: ^[LIMBS]u64, b: ^[LIMBS]u64) {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]

	CHECK_BITS(a[0], 56)
	CHECK_BITS(a[1], 56)
	CHECK_BITS(a[2], 56)
	CHECK_BITS(a[3], 56)
	CHECK_BITS(a[4], 52)
	CHECK_BITS(b[0], 56)
	CHECK_BITS(b[1], 56)
	CHECK_BITS(b[2], 56)
	CHECK_BITS(b[3], 56)
	CHECK_BITS(b[4], 52)
	CHECK(r != b, "fe_mul_inner: r must not alias b")
	CHECK(a != b, "fe_mul_inner: a must not alias b")

	d := u128(a0) * u128(b[3])
	d += u128(a1) * u128(b[2])
	d += u128(a2) * u128(b[1])
	d += u128(a3) * u128(b[0])
	CHECK_BITS_128(d, 114)
	/* [d 0 0 0] = [p3 0 0 0] */
	c := u128(a4) * u128(b[4])
	CHECK_BITS_128(c, 112)
	/* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	d += u128(R_SHIFTED) * u128(u64(c)); c >>= 64
	CHECK_BITS_128(d, 115)
	CHECK_BITS_128(c, 48)
	/* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	t3 := u64(d) & M52; d >>= 52
	CHECK_BITS(t3, 52)
	CHECK_BITS_128(d, 63)
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

	d += u128(a0) * u128(b[4])
	d += u128(a1) * u128(b[3])
	d += u128(a2) * u128(b[2])
	d += u128(a3) * u128(b[1])
	d += u128(a4) * u128(b[0])
	CHECK_BITS_128(d, 115)
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	d += u128(R_SHIFTED << 12) * u128(u64(c))
	CHECK_BITS_128(d, 116)
	/* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	t4 := u64(d) & M52; d >>= 52
	CHECK_BITS(t4, 52)
	CHECK_BITS_128(d, 64)
	/* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	tx := t4 >> 48; t4 &= M52 >> 4
	CHECK_BITS(tx, 4)
	CHECK_BITS(t4, 48)
	/* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

	c = u128(a0) * u128(b[0])
	CHECK_BITS_128(c, 112)
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
	d += u128(a1) * u128(b[4])
	d += u128(a2) * u128(b[3])
	d += u128(a3) * u128(b[2])
	d += u128(a4) * u128(b[1])
	CHECK_BITS_128(d, 114)
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 := u64(d) & M52; d >>= 52
	CHECK_BITS(u0, 52)
	CHECK_BITS_128(d, 62)
	/* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	/* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 = (u0 << 4) | tx
	CHECK_BITS(u0, 56)
	/* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	c += u128(u0) * u128(R_SHIFTED >> 4)
	CHECK_BITS_128(c, 113)
	/* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	r[0] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[0], 52)
	CHECK_BITS_128(c, 61)
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

	c += u128(a0) * u128(b[1])
	c += u128(a1) * u128(b[0])
	CHECK_BITS_128(c, 114)
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
	d += u128(a2) * u128(b[4])
	d += u128(a3) * u128(b[3])
	d += u128(a4) * u128(b[2])
	CHECK_BITS_128(d, 114)
	/* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	c += u128(u64(d) & M52) * u128(R_SHIFTED); d >>= 52
	CHECK_BITS_128(c, 115)
	CHECK_BITS_128(d, 62)
	/* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	r[1] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[1], 52)
	CHECK_BITS_128(c, 63)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

	c += u128(a0) * u128(b[2])
	c += u128(a1) * u128(b[1])
	c += u128(a2) * u128(b[0])
	CHECK_BITS_128(c, 114)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
	d += u128(a3) * u128(b[4])
	d += u128(a4) * u128(b[3])
	CHECK_BITS_128(d, 114)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	c += u128(R_SHIFTED) * u128(u64(d)); d >>= 64
	CHECK_BITS_128(c, 115)
	CHECK_BITS_128(d, 50)
	/* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

	r[2] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[2], 52)
	CHECK_BITS_128(c, 63)
	/* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	c += u128(R_SHIFTED << 12) * u128(u64(d))
	c += u128(t3)
	CHECK_BITS_128(c, 100)
	/* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[3] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[3], 52)
	CHECK_BITS_128(c, 48)
	/* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[4] = u64(c) + t4
	CHECK_BITS(r[4], 49)
	/* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

/*
Sets r to a * a.

Identical in structure to `fe_mul_inner`, with the symmetric cross terms doubled once
instead of accumulated twice. The input must have magnitude at most 8.
*/
@(private)
fe_sqr_inner :: proc "contextless" (r: ^[LIMBS]u64, a: ^[LIMBS]u64) {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]

	CHECK_BITS(a[0], 56)
	CHECK_BITS(a[1], 56)
	CHECK_BITS(a[2], 56)
	CHECK_BITS(a[3], 56)
	CHECK_BITS(a[4], 52)

	d := u128(a0 * 2) * u128(a3)
	d += u128(a1 * 2) * u128(a2)
	CHECK_BITS_128(d, 114)
	/* [d 0 0 0] = [p3 0 0 0] */
	c := u128(a4) * u128(a4)
	CHECK_BITS_128(c, 112)
	/* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	d += u128(R_SHIFTED) * u128(u64(c)); c >>= 64
	CHECK_BITS_128(d, 115)
	CHECK_BITS_128(c, 48)
	/* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
	t3 := u64(d) & M52; d >>= 52
	CHECK_BITS(t3, 52)
	CHECK_BITS_128(d, 63)
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

	a4 *= 2
	d += u128(a0) * u128(a4)
	d += u128(a1 * 2) * u128(a3)
	d += u128(a2) * u128(a2)
	CHECK_BITS_128(d, 115)
	/* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	d += u128(R_SHIFTED << 12) * u128(u64(c))
	CHECK_BITS_128(d, 116)
	/* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	t4 := u64(d) & M52; d >>= 52
	CHECK_BITS(t4, 52)
	CHECK_BITS_128(d, 64)
	/* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
	tx := t4 >> 48; t4 &= M52 >> 4
	CHECK_BITS(tx, 4)
	CHECK_BITS(t4, 48)
	/* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

	c = u128(a0) * u128(a0)
	CHECK_BITS_128(c, 112)
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
	d += u128(a1) * u128(a4)
	d += u128(a2 * 2) * u128(a3)
	CHECK_BITS_128(d, 114)
	/* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 := u64(d) & M52; d >>= 52
	CHECK_BITS(u0, 52)
	CHECK_BITS_128(d, 62)
	/* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	/* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	u0 = (u0 << 4) | tx
	CHECK_BITS(u0, 56)
	/* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	c += u128(u0) * u128(R_SHIFTED >> 4)
	CHECK_BITS_128(c, 113)
	/* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
	r[0] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[0], 52)
	CHECK_BITS_128(c, 61)
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

	a0 *= 2
	c += u128(a0) * u128(a1)
	CHECK_BITS_128(c, 114)
	/* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
	d += u128(a2) * u128(a4)
	d += u128(a3) * u128(a3)
	CHECK_BITS_128(d, 114)
	/* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	c += u128(u64(d) & M52) * u128(R_SHIFTED); d >>= 52
	CHECK_BITS_128(c, 115)
	CHECK_BITS_128(d, 62)
	/* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
	r[1] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[1], 52)
	CHECK_BITS_128(c, 63)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

	c += u128(a0) * u128(a2)
	c += u128(a1) * u128(a1)
	CHECK_BITS_128(c, 114)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
	d += u128(a3) * u128(a4)
	CHECK_BITS_128(d, 114)
	/* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	c += u128(R_SHIFTED) * u128(u64(d)); d >>= 64
	CHECK_BITS_128(c, 115)
	CHECK_BITS_128(d, 50)
	/* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[2] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[2], 52)
	CHECK_BITS_128(c, 63)
	/* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

	c += u128(R_SHIFTED << 12) * u128(u64(d))
	c += u128(t3)
	CHECK_BITS_128(c, 100)
	/* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[3] = u64(c) & M52; c >>= 52
	CHECK_BITS(r[3], 52)
	CHECK_BITS_128(c, 48)
	/* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
	r[4] = u64(c) + t4
	CHECK_BITS(r[4], 49)
	/* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

/*
Sets r to a * b.

Both inputs must have magnitude at most 8. On output r has magnitude 1 and is not
normalized. `r` may alias `a`, but neither may alias `b`.
*/
fe_mul :: proc "contextless" (r: ^Field_Elem, a: ^Field_Elem, b: ^Field_Elem) {
	fe_verify(a)
	fe_verify(b)
	fe_verify_magnitude(a, 8)
	fe_verify_magnitude(b, 8)
	CHECK(r != b, "fe_mul: r must not alias b")
	CHECK(a != b, "fe_mul: a must not alias b")

	fe_mul_inner(&r.n, &a.n, &b.n)

	when VERIFY {
		r.magnitude = 1
		r.normalized = false
	}
	fe_verify(r)
}

/*
Sets r to a * a.

The input must have magnitude at most 8. On output r has magnitude 1 and is not
normalized.
*/
fe_sqr :: proc "contextless" (r: ^Field_Elem, a: ^Field_Elem) {
	fe_verify(a)
	fe_verify_magnitude(a, 8)

	fe_sqr_inner(&r.n, &a.n)

	when VERIFY {
		r.magnitude = 1
		r.normalized = false
	}
	fe_verify(r)
}
