/*
Shared helpers for the field test package.

Tests live outside the packages they exercise, matching the convention in Odin's own
`tests/` tree: a `_test.odin` file inside a package is compiled into ordinary builds too,
which would drag `core:testing` into every consumer of this library. Keeping tests in a
parallel tree avoids that, and it is what a `core:crypto` submission would need anyway.

The consequence is that tests may only use a package's exported surface. That is not a
real constraint here, because `field` and its siblings are internal to the library — the
public API is the root `secp256k1` package — so their exports are already the
"internal" surface upstream's `tests.c` reaches for.
*/
package test_field

import "core:testing"
import "../../field"
import "../../testutil"

/*
Seed for the randomized tests. Override with `-define:TEST_SEED=n` to replay a failure.
*/
TEST_SEED :: #config(TEST_SEED, 0xa5a5_5a5a_1234_5678)

/*
Normalizes a and compares it to b, allowing either side to be unnormalized.

Mirrors the `fe_equal` helper in upstream's `tests.c`, which is distinct from the library's
own `fe_equal` in that it weak-normalizes its first argument first.
*/
equal_normalized :: proc(a: ^field.Field_Elem, b: ^field.Field_Elem) -> bool {
	an := a^
	bn := b^
	field.fe_normalize_weak(&an)
	return field.fe_equal(&an, &bn)
}

/*
Reports whether two field elements have identical limb representations, not merely equal
values. Mirrors upstream's `fe_identical`.
*/
identical :: proc(a: ^field.Field_Elem, b: ^field.Field_Elem) -> bool {
	return a.n == b.n
}

/*
Draws a random field element, biased towards representations that stress carry
propagation.
*/
random_fe :: proc(rng: ^testutil.Rand) -> (r: field.Field_Elem) {
	b32: [32]u8
	for {
		testutil.rand_bytes_test(rng, b32[:])
		if field.fe_set_b32_limit(&r, &b32) {
			return
		}
	}
}

/*
Draws a random non-zero field element.
*/
random_fe_non_zero :: proc(rng: ^testutil.Rand) -> (r: field.Field_Elem) {
	for {
		r = random_fe(rng)
		if !field.fe_normalizes_to_zero(&r) {
			return
		}
	}
}

/*
Parses a 64-character hex string into a normalized field element.

Panics on malformed input: these are compiled-in test vectors, so a bad one is a bug in the
test rather than a runtime condition.
*/
parse_hex :: proc(t: ^testing.T, s: string) -> field.Field_Elem {
	testing.expect_value(t, len(s), 64)

	b: [32]u8
	for i in 0 ..< 32 {
		b[i] = hex_nibble(s[i * 2]) << 4 | hex_nibble(s[i * 2 + 1])
	}

	r: field.Field_Elem
	field.fe_set_b32_mod(&r, &b)
	field.fe_normalize(&r)
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
	panic("field test vector contains a non-hex character")
}
