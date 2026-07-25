/*
Shared helpers for the scalar test package.

See `tests/field/common.odin` for why tests live outside the packages they exercise.
*/
package test_scalar

import "core:testing"
import "../../scalar"
import "../../testutil"

/*
Seed for the randomized tests. Override with `-define:TEST_SEED=n` to replay a failure.
*/
TEST_SEED :: #config(TEST_SEED, 0xc0ffee_1234_5678)

/*
The group order n as bytes, for range checks.
*/
N_BYTES :: [32]u8 {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

/*
Draws a random scalar, biased towards representations that stress carry propagation.
*/
random_scalar :: proc(rng: ^testutil.Rand) -> (r: scalar.Scalar) {
	b32: [32]u8
	for {
		testutil.rand_bytes_test(rng, b32[:])
		if !scalar.scalar_set_b32(&r, &b32) {
			return
		}
	}
}

/*
Draws a random non-zero scalar.
*/
random_scalar_non_zero :: proc(rng: ^testutil.Rand) -> (r: scalar.Scalar) {
	for {
		r = random_scalar(rng)
		if !scalar.scalar_is_zero(&r) {
			return
		}
	}
}

/*
Parses a 64-character hex string into a scalar, requiring it to be in range.
*/
parse_hex :: proc(t: ^testing.T, s: string) -> scalar.Scalar {
	testing.expect_value(t, len(s), 64)

	b: [32]u8
	for i in 0 ..< 32 {
		b[i] = hex_nibble(s[i * 2]) << 4 | hex_nibble(s[i * 2 + 1])
	}

	r: scalar.Scalar
	overflowed := scalar.scalar_set_b32(&r, &b)
	testing.expectf(t, !overflowed, "test vector %s is not below n", s)
	return r
}

@(private)
hex_nibble :: proc(c: u8) -> u8 {
	switch c {
	case '0' ..= '9':
		return c - '0'
	case 'a' ..= 'f':
		return c - 'a' + 10
	case 'A' ..= 'F':
		return c - 'A' + 10
	}
	panic("scalar test vector contains a non-hex character")
}
