/*
SHA-256, HMAC-SHA256, the RFC6979 deterministic nonce generator, and BIP340 tagged hashes.

Implemented here rather than taken from `core:crypto` for the reason stated in `CLAUDE.md`:
this is a from-scratch build, and the hash is as much a part of the construction as the
field arithmetic. It also keeps the library dependency-free, which matters for a submodule.

Mirrors upstream's `hash_impl.h`.

# Why the nonce generator matters

RFC6979 makes ECDSA nonces a deterministic function of the key and message rather than
drawing them from an RNG. That removes an entire class of catastrophic failure: a repeated
or predictable nonce reveals the private key outright. The generator is therefore held to
the same standard as the signing code, not treated as a utility.
*/
package hash

import "core:mem"

/*
SHA-256 state: eight working words, a 64-byte block buffer, and a length counter.
*/
Sha256 :: struct {
	s:     [8]u32,
	buf:   [64]u8,
	bytes: u64,
}

/*
The SHA-256 round constants: the first 32 bits of the fractional parts of the cube roots of
the first 64 primes.
*/
@(private)
K := [64]u32 {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

@(private)
rotr :: #force_inline proc "contextless" (x: u32, n: u32) -> u32 {
	return (x >> n) | (x << (32 - n))
}

@(private)
ch :: #force_inline proc "contextless" (x, y, z: u32) -> u32 {
	return z ~ (x & (y ~ z))
}

@(private)
maj :: #force_inline proc "contextless" (x, y, z: u32) -> u32 {
	return (x & y) | (z & (x | y))
}

@(private)
sigma0_big :: #force_inline proc "contextless" (x: u32) -> u32 {
	return rotr(x, 2) ~ rotr(x, 13) ~ rotr(x, 22)
}

@(private)
sigma1_big :: #force_inline proc "contextless" (x: u32) -> u32 {
	return rotr(x, 6) ~ rotr(x, 11) ~ rotr(x, 25)
}

@(private)
sigma0 :: #force_inline proc "contextless" (x: u32) -> u32 {
	return rotr(x, 7) ~ rotr(x, 18) ~ (x >> 3)
}

@(private)
sigma1 :: #force_inline proc "contextless" (x: u32) -> u32 {
	return rotr(x, 17) ~ rotr(x, 19) ~ (x >> 10)
}

@(private)
read_be32 :: #force_inline proc "contextless" (b: []u8) -> u32 {
	return u32(b[0]) << 24 | u32(b[1]) << 16 | u32(b[2]) << 8 | u32(b[3])
}

@(private)
write_be32 :: #force_inline proc "contextless" (b: []u8, v: u32) {
	b[0] = u8(v >> 24)
	b[1] = u8(v >> 16)
	b[2] = u8(v >> 8)
	b[3] = u8(v)
}

/*
Sets the state to the SHA-256 initial values: the first 32 bits of the fractional parts of
the square roots of the first eight primes.
*/
sha256_initialize :: proc "contextless" (h: ^Sha256) {
	h.s = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}
	h.bytes = 0
}

/*
Compresses one or more 64-byte blocks into the state.

The message schedule is kept as sixteen rotating words rather than a materialised array of
sixty-four. Each word is overwritten in place once its last consumer has read it, which is
what the recurrence permits, and the loop is unrolled in groups of sixteen so the rotation
becomes register renaming rather than indexing. That is the shape upstream's macro-based
implementation compiles to, and it is worth roughly 20% here.
*/
@(private)
sha256_transform :: proc "contextless" (s: ^[8]u32, chunk: []u8, blocks: int) {
	a, b, c, d, e, f, g, h: u32
	w0, w1, w2, w3, w4, w5, w6, w7: u32
	w8, w9, w10, w11, w12, w13, w14, w15: u32

	// One round, reading a schedule word and a round constant.
	round :: #force_inline proc "contextless" (
		a: u32,
		b: u32,
		c: u32,
		d: ^u32,
		e: u32,
		f: u32,
		g: u32,
		h: ^u32,
		k: u32,
		w: u32,
	) {
		t1 := h^ + sigma1_big(e) + ch(e, f, g) + k + w
		t2 := sigma0_big(a) + maj(a, b, c)
		d^ += t1
		h^ = t1 + t2
	}

	// Extends the schedule in place: w[i] = sigma1(w[i-2]) + w[i-7] + sigma0(w[i-15]) + w[i-16],
	// where the operands are the rotating registers.
	extend :: #force_inline proc "contextless" (w16, w15, w7, w2: u32) -> u32 {
		return w16 + sigma0(w15) + w7 + sigma1(w2)
	}

	for blk in 0 ..< blocks {
		base := blk * 64

		a, b, c, d = s[0], s[1], s[2], s[3]
		e, f, g, h = s[4], s[5], s[6], s[7]

		w0 = read_be32(chunk[base + 0:]);   round(a, b, c, &d, e, f, g, &h, K[0], w0)
		w1 = read_be32(chunk[base + 4:]);   round(h, a, b, &c, d, e, f, &g, K[1], w1)
		w2 = read_be32(chunk[base + 8:]);   round(g, h, a, &b, c, d, e, &f, K[2], w2)
		w3 = read_be32(chunk[base + 12:]);  round(f, g, h, &a, b, c, d, &e, K[3], w3)
		w4 = read_be32(chunk[base + 16:]);  round(e, f, g, &h, a, b, c, &d, K[4], w4)
		w5 = read_be32(chunk[base + 20:]);  round(d, e, f, &g, h, a, b, &c, K[5], w5)
		w6 = read_be32(chunk[base + 24:]);  round(c, d, e, &f, g, h, a, &b, K[6], w6)
		w7 = read_be32(chunk[base + 28:]);  round(b, c, d, &e, f, g, h, &a, K[7], w7)
		w8 = read_be32(chunk[base + 32:]);  round(a, b, c, &d, e, f, g, &h, K[8], w8)
		w9 = read_be32(chunk[base + 36:]);  round(h, a, b, &c, d, e, f, &g, K[9], w9)
		w10 = read_be32(chunk[base + 40:]); round(g, h, a, &b, c, d, e, &f, K[10], w10)
		w11 = read_be32(chunk[base + 44:]); round(f, g, h, &a, b, c, d, &e, K[11], w11)
		w12 = read_be32(chunk[base + 48:]); round(e, f, g, &h, a, b, c, &d, K[12], w12)
		w13 = read_be32(chunk[base + 52:]); round(d, e, f, &g, h, a, b, &c, K[13], w13)
		w14 = read_be32(chunk[base + 56:]); round(c, d, e, &f, g, h, a, &b, K[14], w14)
		w15 = read_be32(chunk[base + 60:]); round(b, c, d, &e, f, g, h, &a, K[15], w15)

		// Three further groups of sixteen, extending the schedule as it is consumed.
		for j := 16; j < 64; j += 16 {
			w0 = extend(w0, w1, w9, w14);    round(a, b, c, &d, e, f, g, &h, K[j + 0], w0)
			w1 = extend(w1, w2, w10, w15);   round(h, a, b, &c, d, e, f, &g, K[j + 1], w1)
			w2 = extend(w2, w3, w11, w0);    round(g, h, a, &b, c, d, e, &f, K[j + 2], w2)
			w3 = extend(w3, w4, w12, w1);    round(f, g, h, &a, b, c, d, &e, K[j + 3], w3)
			w4 = extend(w4, w5, w13, w2);    round(e, f, g, &h, a, b, c, &d, K[j + 4], w4)
			w5 = extend(w5, w6, w14, w3);    round(d, e, f, &g, h, a, b, &c, K[j + 5], w5)
			w6 = extend(w6, w7, w15, w4);    round(c, d, e, &f, g, h, a, &b, K[j + 6], w6)
			w7 = extend(w7, w8, w0, w5);     round(b, c, d, &e, f, g, h, &a, K[j + 7], w7)
			w8 = extend(w8, w9, w1, w6);     round(a, b, c, &d, e, f, g, &h, K[j + 8], w8)
			w9 = extend(w9, w10, w2, w7);    round(h, a, b, &c, d, e, f, &g, K[j + 9], w9)
			w10 = extend(w10, w11, w3, w8);  round(g, h, a, &b, c, d, e, &f, K[j + 10], w10)
			w11 = extend(w11, w12, w4, w9);  round(f, g, h, &a, b, c, d, &e, K[j + 11], w11)
			w12 = extend(w12, w13, w5, w10); round(e, f, g, &h, a, b, c, &d, K[j + 12], w12)
			w13 = extend(w13, w14, w6, w11); round(d, e, f, &g, h, a, b, &c, K[j + 13], w13)
			w14 = extend(w14, w15, w7, w12); round(c, d, e, &f, g, h, a, &b, K[j + 14], w14)
			w15 = extend(w15, w0, w8, w13);  round(b, c, d, &e, f, g, h, &a, K[j + 15], w15)
		}

		s[0] += a
		s[1] += b
		s[2] += c
		s[3] += d
		s[4] += e
		s[5] += f
		s[6] += g
		s[7] += h
	}
}

/*
Absorbs data into the hash state.

Buffers a partial block internally, so callers may write in arbitrary chunk sizes.
*/
sha256_write :: proc "contextless" (h: ^Sha256, data: []u8) {
	bufsize := int(h.bytes & 0x3f)
	pos := 0
	remaining := len(data)

	h.bytes += u64(len(data))

	// Complete a partially filled buffer first.
	if bufsize > 0 && bufsize + remaining >= 64 {
		fill := 64 - bufsize
		copy(h.buf[bufsize:], data[:fill])
		pos += fill
		remaining -= fill
		sha256_transform(&h.s, h.buf[:], 1)
		bufsize = 0
	}

	// Then whole blocks straight from the input.
	if remaining >= 64 {
		blocks := remaining / 64
		sha256_transform(&h.s, data[pos:], blocks)
		pos += blocks * 64
		remaining -= blocks * 64
	}

	// Keep the remainder for next time.
	if remaining > 0 {
		copy(h.buf[bufsize:], data[pos:pos + remaining])
	}
}

/*
Finishes the hash and writes the 32-byte digest.

The state is left unusable; re-initialize before hashing again.
*/
sha256_finalize :: proc "contextless" (h: ^Sha256, out32: ^[32]u8) {
	pad := [64]u8{0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// The length is appended as a big-endian bit count.
	sizedesc: [8]u8
	bits := h.bytes << 3
	write_be32(sizedesc[0:], u32(bits >> 32))
	write_be32(sizedesc[4:], u32(bits))

	// Pad to 56 mod 64, then append the length.
	bufsize := int(h.bytes & 0x3f)
	padlen := 1 + ((119 - bufsize) & 63)
	sha256_write(h, pad[:padlen])
	sha256_write(h, sizedesc[:])

	for i in 0 ..< 8 {
		write_be32(out32[i * 4:], h.s[i])
	}
}

/*
Zeroes the hash state so that hashed secret material does not outlive its use.
*/
sha256_clear :: proc "contextless" (h: ^Sha256) {
	mem.zero_explicit(h, size_of(Sha256))
}

/*
Initializes a hash for BIP340-style tagged hashing:

	tagged_hash(tag, m) = SHA256(SHA256(tag) || SHA256(tag) || m)

Prefixing with the doubled tag hash domain-separates each use, so a signature over one tag
can never be reinterpreted under another. Writing the tag digest twice fills exactly one
64-byte block, which is what allows the midstate to be precomputed.
*/
sha256_initialize_tagged :: proc "contextless" (h: ^Sha256, tag: []u8) {
	buf: [32]u8
	sha256_initialize(h)
	sha256_write(h, tag)
	sha256_finalize(h, &buf)

	sha256_initialize(h)
	sha256_write(h, buf[:])
	sha256_write(h, buf[:])
}

/*
Computes a tagged hash in one call.
*/
tagged_sha256 :: proc "contextless" (out32: ^[32]u8, tag: []u8, msg: []u8) {
	sha: Sha256
	sha256_initialize_tagged(&sha, tag)
	sha256_write(&sha, msg)
	sha256_finalize(&sha, out32)
	sha256_clear(&sha)
}

/*
HMAC-SHA256 state: the inner and outer hash contexts.
*/
Hmac_Sha256 :: struct {
	inner, outer: Sha256,
}

/*
Initializes an HMAC with the given key.

Keys longer than the 64-byte block size are hashed down first, as HMAC requires; shorter
keys are zero-padded.
*/
hmac_sha256_initialize :: proc "contextless" (h: ^Hmac_Sha256, key: []u8) {
	rkey: [64]u8

	if len(key) <= 64 {
		copy(rkey[:], key)
		// The remainder is already zero.
	} else {
		sha: Sha256
		sha256_initialize(&sha)
		sha256_write(&sha, key)
		digest: [32]u8
		sha256_finalize(&sha, &digest)
		copy(rkey[:], digest[:])
		sha256_clear(&sha)
	}

	sha256_initialize(&h.outer)
	for n in 0 ..< 64 {
		rkey[n] ~= 0x5c
	}
	sha256_write(&h.outer, rkey[:])

	sha256_initialize(&h.inner)
	for n in 0 ..< 64 {
		rkey[n] ~= 0x5c ~ 0x36
	}
	sha256_write(&h.inner, rkey[:])

	mem.zero_explicit(&rkey, size_of(rkey))
}

/*
Absorbs data into the HMAC.
*/
hmac_sha256_write :: proc "contextless" (h: ^Hmac_Sha256, data: []u8) {
	sha256_write(&h.inner, data)
}

/*
Finishes the HMAC and writes the 32-byte tag.
*/
hmac_sha256_finalize :: proc "contextless" (h: ^Hmac_Sha256, out32: ^[32]u8) {
	temp: [32]u8
	sha256_finalize(&h.inner, &temp)
	sha256_write(&h.outer, temp[:])
	mem.zero_explicit(&temp, size_of(temp))
	sha256_finalize(&h.outer, out32)
}

/*
Zeroes the HMAC state.
*/
hmac_sha256_clear :: proc "contextless" (h: ^Hmac_Sha256) {
	mem.zero_explicit(h, size_of(Hmac_Sha256))
}

/*
The RFC6979 deterministic random bit generator, keyed by HMAC-SHA256.

State is the (K, V) pair from the specification plus a retry flag, which distinguishes the
first `generate` call from subsequent ones.
*/
Rfc6979_Hmac_Sha256 :: struct {
	v:     [32]u8,
	k:     [32]u8,
	retry: bool,
}

/*
Seeds the generator, following RFC6979 section 3.2 steps b through f.

The key material is normally the private key concatenated with the message hash, plus any
extra entropy.
*/
rfc6979_hmac_sha256_initialize :: proc "contextless" (rng: ^Rfc6979_Hmac_Sha256, key: []u8) {
	zero := [1]u8{0x00}
	one := [1]u8{0x01}

	// 3.2.b and 3.2.c
	for i in 0 ..< 32 {
		rng.v[i] = 0x01
		rng.k[i] = 0x00
	}

	hmac: Hmac_Sha256

	// 3.2.d
	hmac_sha256_initialize(&hmac, rng.k[:])
	hmac_sha256_write(&hmac, rng.v[:])
	hmac_sha256_write(&hmac, zero[:])
	hmac_sha256_write(&hmac, key)
	hmac_sha256_finalize(&hmac, &rng.k)
	hmac_sha256_initialize(&hmac, rng.k[:])
	hmac_sha256_write(&hmac, rng.v[:])
	hmac_sha256_finalize(&hmac, &rng.v)

	// 3.2.f
	hmac_sha256_initialize(&hmac, rng.k[:])
	hmac_sha256_write(&hmac, rng.v[:])
	hmac_sha256_write(&hmac, one[:])
	hmac_sha256_write(&hmac, key)
	hmac_sha256_finalize(&hmac, &rng.k)
	hmac_sha256_initialize(&hmac, rng.k[:])
	hmac_sha256_write(&hmac, rng.v[:])
	hmac_sha256_finalize(&hmac, &rng.v)

	hmac_sha256_clear(&hmac)
	rng.retry = false
}

/*
Produces the next `len(out)` pseudorandom bytes, per RFC6979 section 3.2.h.

Calls after the first re-key first, which is what makes the retry path of nonce generation
produce a fresh candidate rather than repeating the rejected one.
*/
rfc6979_hmac_sha256_generate :: proc "contextless" (rng: ^Rfc6979_Hmac_Sha256, out: []u8) {
	zero := [1]u8{0x00}
	hmac: Hmac_Sha256

	if rng.retry {
		hmac_sha256_initialize(&hmac, rng.k[:])
		hmac_sha256_write(&hmac, rng.v[:])
		hmac_sha256_write(&hmac, zero[:])
		hmac_sha256_finalize(&hmac, &rng.k)
		hmac_sha256_initialize(&hmac, rng.k[:])
		hmac_sha256_write(&hmac, rng.v[:])
		hmac_sha256_finalize(&hmac, &rng.v)
	}

	pos := 0
	remaining := len(out)
	for remaining > 0 {
		hmac_sha256_initialize(&hmac, rng.k[:])
		hmac_sha256_write(&hmac, rng.v[:])
		hmac_sha256_finalize(&hmac, &rng.v)

		now := min(remaining, 32)
		copy(out[pos:pos + now], rng.v[:now])
		pos += now
		remaining -= now
	}

	hmac_sha256_clear(&hmac)
	rng.retry = true
}

/*
Zeroes the generator state.
*/
rfc6979_hmac_sha256_clear :: proc "contextless" (rng: ^Rfc6979_Hmac_Sha256) {
	mem.zero_explicit(rng, size_of(Rfc6979_Hmac_Sha256))
}
