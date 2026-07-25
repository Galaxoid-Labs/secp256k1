/*
Deterministic randomness for the test suite.

Randomized tests must reproduce: a failure that cannot be replayed is close to useless
when the bug is a carry that only propagates for one input in a million. Every generator
here is seeded explicitly and is a pure function of that seed, so a failing run is
re-runnable from the seed printed alongside it.

The generator is xoshiro256++, matching upstream's `testrand_impl.h`, so a given seed
walks the same sequence in both implementations.

This package is test-only. It links no C and holds no cryptographic guarantees — never use
it to generate keys or nonces.
*/
package testutil

/*
xoshiro256++ state: 256 bits, never all-zero.
*/
Rand :: struct {
	s: [4]u64,
}

/*
Seeds a generator from a 64-bit value.

The seed is expanded through SplitMix64 so that even a low-entropy seed such as 1 produces
a well-distributed initial state, which is the standard companion to xoshiro.
*/
rand_seed :: proc "contextless" (r: ^Rand, seed: u64) {
	z := seed
	for i in 0 ..< 4 {
		z += 0x9e3779b97f4a7c15
		x := z
		x = (x ~ (x >> 30)) * 0xbf58476d1ce4e5b9
		x = (x ~ (x >> 27)) * 0x94d049bb133111eb
		r.s[i] = x ~ (x >> 31)
	}
	// xoshiro requires a non-zero state; SplitMix64 makes this essentially unreachable,
	// but the guarantee is cheap.
	if r.s[0] | r.s[1] | r.s[2] | r.s[3] == 0 {
		r.s[0] = 1
	}
}

/*
Returns the next 64 bits.
*/
rand_u64 :: proc "contextless" (r: ^Rand) -> u64 {
	rotl :: #force_inline proc "contextless" (x: u64, k: uint) -> u64 {
		return (x << k) | (x >> (64 - k))
	}

	result := rotl(r.s[0] + r.s[3], 23) + r.s[0]
	t := r.s[1] << 17

	r.s[2] ~= r.s[0]
	r.s[3] ~= r.s[1]
	r.s[1] ~= r.s[2]
	r.s[0] ~= r.s[3]
	r.s[2] ~= t
	r.s[3] = rotl(r.s[3], 45)

	return result
}

/*
Returns the next 32 bits.
*/
rand_u32 :: proc "contextless" (r: ^Rand) -> u32 {
	return u32(rand_u64(r) >> 32)
}

/*
Returns a value uniformly distributed in [0, n).

Uses rejection sampling on a power-of-two mask, so the result is unbiased. `n` must be
positive.
*/
rand_int :: proc "contextless" (r: ^Rand, n: u32) -> u32 {
	if n <= 1 {
		return 0
	}

	// Smallest mask covering n-1.
	mask: u32 = 0xffff_ffff
	for mask >> 1 >= n - 1 {
		mask >>= 1
	}

	for {
		v := rand_u32(r) & mask
		if v < n {
			return v
		}
	}
}

/*
Returns a single bit as a boolean.
*/
rand_bool :: proc "contextless" (r: ^Rand) -> bool {
	return rand_u64(r) & 1 == 1
}

/*
Fills buf with random bytes.
*/
rand_bytes :: proc "contextless" (r: ^Rand, buf: []u8) {
	i := 0
	for i + 8 <= len(buf) {
		v := rand_u64(r)
		for j in 0 ..< 8 {
			buf[i + j] = u8(v >> (uint(j) * 8))
		}
		i += 8
	}
	if i < len(buf) {
		v := rand_u64(r)
		for ; i < len(buf); i += 1 {
			buf[i] = u8(v)
			v >>= 8
		}
	}
}

/*
Fills buf with random bytes, biased towards patterns that stress carry propagation.

A uniformly random 256-bit value almost never has a run of set or clear bits, so uniform
input alone rarely reaches the edges of a limbed representation. This picks a random run
length and fills with alternating runs of 0x00 and 0xff, then perturbs a few bytes.

Mirrors the intent of upstream's `secp256k1_testrand_bytes_test`.
*/
rand_bytes_test :: proc "contextless" (r: ^Rand, buf: []u8) {
	if len(buf) == 0 {
		return
	}

	// Start from all-zero or all-ones, then flip runs.
	fill: u8 = 0xff if rand_bool(r) else 0x00
	for i in 0 ..< len(buf) {
		buf[i] = fill
	}

	i := 0
	for i < len(buf) {
		// Run lengths are geometric-ish, favouring short runs but reaching long ones.
		run := int(rand_int(r, 16)) + 1
		fill = ~fill
		for j in 0 ..< run {
			if i + j >= len(buf) {
				break
			}
			buf[i + j] = fill
		}
		i += run
	}

	// Perturb a few individual bytes so the value is not purely run-structured.
	perturbs := int(rand_int(r, 4))
	for _ in 0 ..< perturbs {
		buf[rand_int(r, u32(len(buf)))] = u8(rand_u32(r))
	}
}
