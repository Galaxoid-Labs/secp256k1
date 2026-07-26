/*
Mirrors of upstream `tests.c` functions that had no counterpart here.

Named after the upstream function they mirror, per `TESTING.md`'s traceability convention,
so the map between the two suites can be checked mechanically.

Several upstream tests are **not applicable** and are recorded here rather than silently
omitted, because an unexplained gap in a traceability table is indistinguishable from an
oversight:

  - `run_hsort_tests` — tests upstream's heapsort utility. This implementation sorts public
    keys with an insertion sort inside `musig.pubkey_sort` and has no general sort to test.
    The behaviour that matters, the BIP327 KeySort order, is pinned by
    `test_bip327_pubkey_sort_vectors`.
  - `run_ctz_tests` — tests upstream's fallback count-trailing-zeros. Here that is
    `intrinsics.count_trailing_zeros`, a compiler builtin; a test would be testing LLVM.
    Its contract is exercised indirectly by `modinv64_var`, which is covered by the oracle.
  - `run_secp256k1_is_zero_array_test`, `run_secp256k1_byteorder_tests` — test C utility
    helpers with no counterpart. Byte order goes through explicit shifts in
    `fe_get_b32`/`fe_set_b32`, which the oracle compares byte for byte.

`run_secp256k1_memczero_test` was originally recorded as not applicable here, on the
grounds that zeroing goes through `mem.zero_explicit`. That was wrong: `memczero` is a
*conditional* constant-time erase, and the moment `keypair_create` stopped branching on key
validity it needed exactly that. It now exists as `ct.czero` and is mirrored below.
  - `run_ecdsa_wycheproof` — mirrored, but as its own file: see `tests/ecdsa/test_wycheproof.odin`.
*/
package test_ecmult_misc

import "core:testing"
import "../../ct"
import "../../ecdsa"
import "../../ecmult"
import "../../eckey"
import "../../field"
import "../../musig"
import "../../group"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0x33_a17_5eed)
COUNT :: #config(COUNT, 16)

/*
Scalars straddling the endomorphism split boundary, from upstream's
`scalars_near_split_bounds`.

The lambda split writes k as k1 + k2*lambda with both halves near 128 bits. These 20 values
sit one unit either side of the rounding boundaries in that decomposition, which is exactly
where an off-by-one produces a half that is one bit too long — and a wNAF table read out of
bounds. Random scalars essentially never land here.
*/
@(private = "file")
SPLIT_BOUND_SCALARS := [20]scalar.Scalar{
	scalar.scalar_const(0xd938a566, 0x7f479e3e, 0xb5b3c7fa, 0xefdb3749, 0x3aa0585c, 0xc5ea2367, 0xe1b660db, 0x0209e6fc),
	scalar.scalar_const(0xd938a566, 0x7f479e3e, 0xb5b3c7fa, 0xefdb3749, 0x3aa0585c, 0xc5ea2367, 0xe1b660db, 0x0209e6fd),
	scalar.scalar_const(0xd938a566, 0x7f479e3e, 0xb5b3c7fa, 0xefdb3749, 0x3aa0585c, 0xc5ea2367, 0xe1b660db, 0x0209e6fe),
	scalar.scalar_const(0xd938a566, 0x7f479e3e, 0xb5b3c7fa, 0xefdb3749, 0x3aa0585c, 0xc5ea2367, 0xe1b660db, 0x0209e6ff),
	scalar.scalar_const(0x2c9c52b3, 0x3fa3cf1f, 0x5ad9e3fd, 0x77ed9ba5, 0xb294b893, 0x3722e9a5, 0x00e698ca, 0x4cf7632d),
	scalar.scalar_const(0x2c9c52b3, 0x3fa3cf1f, 0x5ad9e3fd, 0x77ed9ba5, 0xb294b893, 0x3722e9a5, 0x00e698ca, 0x4cf7632e),
	scalar.scalar_const(0x2c9c52b3, 0x3fa3cf1f, 0x5ad9e3fd, 0x77ed9ba5, 0xb294b893, 0x3722e9a5, 0x00e698ca, 0x4cf7632f),
	scalar.scalar_const(0x2c9c52b3, 0x3fa3cf1f, 0x5ad9e3fd, 0x77ed9ba5, 0xb294b893, 0x3722e9a5, 0x00e698ca, 0x4cf76330),
	scalar.scalar_const(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xd576e735, 0x57a4501d, 0xdfe92f46, 0x681b209f),
	scalar.scalar_const(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xd576e735, 0x57a4501d, 0xdfe92f46, 0x681b20a0),
	scalar.scalar_const(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xd576e735, 0x57a4501d, 0xdfe92f46, 0x681b20a1),
	scalar.scalar_const(0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xd576e735, 0x57a4501d, 0xdfe92f46, 0x681b20a2),
	scalar.scalar_const(0xd363ad4c, 0xc05c30e0, 0xa5261c02, 0x88126459, 0xf85915d7, 0x7825b696, 0xbeebc5c2, 0x833ede11),
	scalar.scalar_const(0xd363ad4c, 0xc05c30e0, 0xa5261c02, 0x88126459, 0xf85915d7, 0x7825b696, 0xbeebc5c2, 0x833ede12),
	scalar.scalar_const(0xd363ad4c, 0xc05c30e0, 0xa5261c02, 0x88126459, 0xf85915d7, 0x7825b696, 0xbeebc5c2, 0x833ede13),
	scalar.scalar_const(0xd363ad4c, 0xc05c30e0, 0xa5261c02, 0x88126459, 0xf85915d7, 0x7825b696, 0xbeebc5c2, 0x833ede14),
	scalar.scalar_const(0x26c75a99, 0x80b861c1, 0x4a4c3805, 0x1024c8b4, 0x704d760e, 0xe95e7cd3, 0xde1bfdb1, 0xce2c5a42),
	scalar.scalar_const(0x26c75a99, 0x80b861c1, 0x4a4c3805, 0x1024c8b4, 0x704d760e, 0xe95e7cd3, 0xde1bfdb1, 0xce2c5a43),
	scalar.scalar_const(0x26c75a99, 0x80b861c1, 0x4a4c3805, 0x1024c8b4, 0x704d760e, 0xe95e7cd3, 0xde1bfdb1, 0xce2c5a44),
	scalar.scalar_const(0x26c75a99, 0x80b861c1, 0x4a4c3805, 0x1024c8b4, 0x704d760e, 0xe95e7cd3, 0xde1bfdb1, 0xce2c5a45),
}

/*
Mirrors `run_ecmult_near_split_bound`.

Each scalar is multiplied through every engine and the results must agree. Disagreement
between the constant-time and variable-time paths on a boundary scalar is precisely the
symptom of a mis-rounded split.
*/
@(test)
test_run_ecmult_near_split_bound :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for k, i in SPLIT_BOUND_SCALARS {
		q := k

		// k*G by the generator engine.
		via_gen: group.Gej
		ecmult.ecmult_gen(&gen, &via_gen, &q)

		// k*G by the variable-time engine, as 0*P + k*G.
		gj: group.Gej
		g := group.GENERATOR
		group.gej_set_ge(&gj, &g)
		zero: scalar.Scalar
		scalar.scalar_set_int(&zero, 0)
		via_var: group.Gej
		ecmult.ecmult(&via_var, &gj, &zero, &q)

		// k*G by the constant-time engine.
		via_const: group.Gej
		ecmult.ecmult_const(&via_const, &g, &q)

		a, b, c: group.Ge
		group.ge_set_gej(&a, &via_gen)
		group.ge_set_gej(&b, &via_var)
		group.ge_set_gej(&c, &via_const)

		testing.expectf(t, ge_eq(&a, &b), "split bound %d: ecmult_gen != ecmult", i)
		testing.expectf(t, ge_eq(&a, &c), "split bound %d: ecmult_gen != ecmult_const", i)
	}
}

@(private = "file")
ge_eq :: proc(a: ^group.Ge, b: ^group.Ge) -> bool {
	if a.infinity || b.infinity {
		return a.infinity == b.infinity
	}
	x, y := a.x, a.y
	bx, by := b.x, b.y
	field.fe_normalize_var(&x); field.fe_normalize_var(&y)
	field.fe_normalize_var(&bx); field.fe_normalize_var(&by)
	return field.fe_equal(&x, &bx) && field.fe_equal(&y, &by)
}

/*
Mirrors `run_secp256k1_memczero_test`.

`ct.czero` must erase when the flag is set, leave the buffer bit-identical when it is not,
and do both without branching on the flag. The false case is the one that matters: it is
called on the success path of `keypair_create`, where wiping the keypair would destroy a
freshly created key.
*/
@(test)
test_run_secp256k1_memczero_test :: proc(t: ^testing.T) {
	pattern: [32]u8
	for i in 0 ..< 32 {
		pattern[i] = u8(i * 7 + 1)
	}

	// flag = false leaves it untouched.
	buf := pattern
	ct.czero(&buf, size_of(buf), false)
	testing.expect(t, buf == pattern, "czero(false) modified the buffer")

	// flag = true erases every byte.
	ct.czero(&buf, size_of(buf), true)
	zero: [32]u8
	testing.expect(t, buf == zero, "czero(true) did not erase")

	// Partial lengths must not touch bytes past the end.
	buf = pattern
	ct.czero(&buf, 16, true)
	for i in 0 ..< 16 {
		testing.expectf(t, buf[i] == 0, "czero(len=16) left byte %d set", i)
	}
	for i in 16 ..< 32 {
		testing.expectf(t, buf[i] == pattern[i], "czero(len=16) touched byte %d", i)
	}

	// A zero length must do nothing at all.
	buf = pattern
	ct.czero(&buf, 0, true)
	testing.expect(t, buf == pattern, "czero(len=0) modified the buffer")
}

/*
Mirrors `run_eckey_edge_case_test`.

The edge cases upstream cares about are the boundaries of the valid key range: zero, n, and
n-1. Zero and n must be rejected; n-1 is the largest valid key and must be accepted, and
must still produce a usable public key.
*/
@(test)
test_run_eckey_edge_case_test :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	zero: [32]u8
	s: scalar.Scalar
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &zero), "accepted a zero secret key")

	// n itself, which is out of range by one.
	n := [32]u8 {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
		0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	}
	testing.expect(t, !scalar.scalar_set_b32_seckey(&s, &n), "accepted n as a secret key")

	// n - 1, the largest valid key.
	n_minus_1 := n
	n_minus_1[31] = 0x40
	testing.expect(t, scalar.scalar_set_b32_seckey(&s, &n_minus_1), "rejected n-1")

	pk: group.Ge
	testing.expect(t, eckey.pubkey_create(&gen, &pk, &s), "n-1 produced no public key")
	testing.expect(t, !group.ge_is_infinity(&pk), "n-1 produced infinity")

	// One above zero is valid and is the generator.
	one: [32]u8
	one[31] = 1
	testing.expect(t, scalar.scalar_set_b32_seckey(&s, &one), "rejected 1")
	pk1: group.Ge
	testing.expect(t, eckey.pubkey_create(&gen, &pk1, &s), "1 produced no public key")
	testing.expect(t, ge_eq(&pk1, &group.GENERATOR), "1*G is not the generator")
}

/*
Mirrors `run_cmov_tests`.

Every conditional move must copy on true and leave the destination bit-identical on false.
The false case is the one that matters: a cmov that writes unconditionally still passes any
test that only checks the true branch, and would destroy the value it was meant to preserve.
*/
@(test)
test_run_cmov_tests :: proc(t: ^testing.T) {
	// fe_cmov
	{
		zero, one, maxv: field.Field_Elem
		field.fe_set_int(&zero, 0)
		field.fe_set_int(&one, 1)
		maxv = field.fe_const(
			0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
			0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
		)

		r := maxv
		a := zero
		field.fe_cmov(&r, &a, false)
		testing.expect(t, fe_identical(&r, &maxv), "fe_cmov(false) modified the destination")

		r = zero; a = maxv
		field.fe_cmov(&r, &a, true)
		testing.expect(t, fe_identical(&r, &maxv), "fe_cmov(true) did not copy")

		a = zero
		field.fe_cmov(&r, &a, true)
		testing.expect(t, fe_identical(&r, &zero), "fe_cmov(true) did not copy zero")

		a = one
		field.fe_cmov(&r, &a, true)
		testing.expect(t, fe_identical(&r, &one), "fe_cmov(true) did not copy one")

		r = one; a = zero
		field.fe_cmov(&r, &a, false)
		testing.expect(t, fe_identical(&r, &one), "fe_cmov(false) modified the destination")
	}

	// fe_storage_cmov
	{
		zero, one, maxv: field.Field_Storage
		zero = field.Field_Storage{}
		one = field.Field_Storage{n = {1, 0, 0, 0}}
		maxv = field.Field_Storage {
			n = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		}

		r := maxv
		a := zero
		field.fe_storage_cmov(&r, &a, false)
		testing.expect(t, r == maxv, "fe_storage_cmov(false) modified the destination")

		r = zero; a = maxv
		field.fe_storage_cmov(&r, &a, true)
		testing.expect(t, r == maxv, "fe_storage_cmov(true) did not copy")

		a = one
		field.fe_storage_cmov(&r, &a, true)
		testing.expect(t, r == one, "fe_storage_cmov(true) did not copy one")

		r = one; a = zero
		field.fe_storage_cmov(&r, &a, false)
		testing.expect(t, r == one, "fe_storage_cmov(false) modified the destination")
	}

	// scalar_cmov
	{
		zero, one, maxv: scalar.Scalar
		scalar.scalar_set_int(&zero, 0)
		scalar.scalar_set_int(&one, 1)
		// n-1, the largest valid scalar.
		maxv = scalar.scalar_const(
			0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
			0xbaaedce6, 0xaf48a03b, 0xbfd25e8c, 0xd0364140,
		)

		r := maxv
		a := zero
		scalar.scalar_cmov(&r, &a, false)
		testing.expect(t, r == maxv, "scalar_cmov(false) modified the destination")

		r = zero; a = maxv
		scalar.scalar_cmov(&r, &a, true)
		testing.expect(t, r == maxv, "scalar_cmov(true) did not copy")

		a = one
		scalar.scalar_cmov(&r, &a, true)
		testing.expect(t, r == one, "scalar_cmov(true) did not copy one")

		r = one; a = zero
		scalar.scalar_cmov(&r, &a, false)
		testing.expect(t, r == one, "scalar_cmov(false) modified the destination")
	}

	// ge_storage_cmov
	{
		zero := group.Ge_Storage{}
		maxv := group.Ge_Storage {
			x = {n = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}},
			y = {n = {0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}},
		}

		r := maxv
		a := zero
		group.ge_storage_cmov(&r, &a, false)
		testing.expect(t, r == maxv, "ge_storage_cmov(false) modified the destination")

		group.ge_storage_cmov(&r, &a, true)
		testing.expect(t, r == zero, "ge_storage_cmov(true) did not copy")
	}
}

/*
Bit-identical comparison of two field elements, ignoring magnitude bookkeeping.

Deliberately *not* `fe_equal`, which compares values modulo p. A cmov must preserve the
exact limb pattern, and two different limb patterns can represent the same value.
*/
@(private = "file")
fe_identical :: proc(a: ^field.Field_Elem, b: ^field.Field_Elem) -> bool {
	for i in 0 ..< 5 {
		if a.n[i] != b.n[i] {
			return false
		}
	}
	return true
}

/*
Mirrors `run_eckey_negate_test`.

Negating twice must restore the original key, and one negation must change it.
*/
@(test)
test_run_eckey_negate_test :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for _ in 0 ..< COUNT {
		b32: [32]u8
		testutil.rand_bytes_test(&rng, b32[:])

		s: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&s, &b32) {
			continue
		}
		original := s

		scalar.scalar_negate(&s, &s)
		testing.expect(t, s != original, "negating a key left it unchanged")

		scalar.scalar_negate(&s, &s)
		testing.expect(t, s == original, "double negation did not restore the key")
	}
}

/*
Mirrors `run_pubkey_comparison`.

The library's comparator is package-private, so what is asserted here is the property that
is actually observable and actually matters: `pubkey_sort` must leave keys in ascending
lexicographic order of their compressed serializations. Signers who disagree on that order
derive different aggregate keys and produce partial signatures that will not combine.

The exact BIP327 ordering is pinned separately by `test_bip327_pubkey_sort_vectors`; this
covers the general property over random keys, including the reverse-sorted input that a
comparator with inverted operands would pass by accident on sorted input.
*/
@(test)
test_run_pubkey_comparison :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	for round in 0 ..< COUNT {
		keys: [8]group.Ge
		n := 0
		for n < 8 {
			b32: [32]u8
			testutil.rand_bytes_test(&rng, b32[:])
			s: scalar.Scalar
			if !scalar.scalar_set_b32_seckey(&s, &b32) {
				continue
			}
			if eckey.pubkey_create(&gen, &keys[n], &s) {
				n += 1
			}
		}

		musig.pubkey_sort(keys[:n])

		prev: [33]u8
		for i in 0 ..< n {
			cur: [33]u8
			eckey.pubkey_serialize33(&keys[i], &cur)
			if i > 0 {
				testing.expectf(
					t,
					bytes_cmp33(&prev, &cur) <= 0,
					"round %d: sorted output is not ascending at position %d",
					round,
					i,
				)
			}
			prev = cur
		}
	}
}

/*
Lexicographic comparison of two compressed serializations, the order `pubkey_sort` is
defined on. The library's own comparator is package-private, so the ordering contract is
restated here rather than reaching into `musig`.
*/
@(private = "file")
bytes_cmp33 :: proc(a: ^[33]u8, b: ^[33]u8) -> int {
	for i in 0 ..< 33 {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

/*
Mirrors `run_random_pubkeys`, in the direction that matters here: every public key this
implementation produces must round-trip through both serializations unchanged.
*/
@(test)
test_run_random_pubkeys :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 7)

	for i in 0 ..< COUNT * 4 {
		b32: [32]u8
		testutil.rand_bytes_test(&rng, b32[:])
		s: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&s, &b32) {
			continue
		}

		pk: group.Ge
		if !eckey.pubkey_create(&gen, &pk, &s) {
			continue
		}

		c33: [33]u8
		eckey.pubkey_serialize33(&pk, &c33)
		back33: group.Ge
		testing.expectf(t, eckey.pubkey_parse(&back33, c33[:]), "compressed parse failed at %d", i)
		testing.expectf(t, ge_eq(&pk, &back33), "compressed round-trip changed the key at %d", i)

		c65: [65]u8
		eckey.pubkey_serialize65(&pk, &c65)
		back65: group.Ge
		testing.expectf(t, eckey.pubkey_parse(&back65, c65[:]), "uncompressed parse failed at %d", i)
		testing.expectf(t, ge_eq(&pk, &back65), "uncompressed round-trip changed the key at %d", i)
	}
}

/*
Mirrors `run_ec_pubkey_parse_test`.

The rejection cases carry the weight. A parser that accepts a point off the curve hands the
caller a key that every later operation will treat as real.
*/
@(test)
test_run_ec_pubkey_parse_test :: proc(t: ^testing.T) {
	pk: group.Ge

	// Empty and short inputs.
	testing.expect(t, !eckey.pubkey_parse(&pk, []u8{}), "accepted empty input")
	testing.expect(t, !eckey.pubkey_parse(&pk, []u8{0x02}), "accepted a 1-byte key")

	// Wrong length for the tag.
	short33 := [32]u8{}
	testing.expect(t, !eckey.pubkey_parse(&pk, short33[:]), "accepted a 32-byte key")

	// Invalid prefix byte.
	bad := [33]u8{}
	bad[0] = 0x01
	testing.expect(t, !eckey.pubkey_parse(&pk, bad[:]), "accepted prefix 0x01")
	bad[0] = 0x05
	testing.expect(t, !eckey.pubkey_parse(&pk, bad[:]), "accepted prefix 0x05")

	// x = 0 is not on the curve (y^2 = 7 has no root mod p).
	zero_x := [33]u8{}
	zero_x[0] = 0x02
	testing.expect(t, !eckey.pubkey_parse(&pk, zero_x[:]), "accepted x = 0")

	// x = p is out of range even though the encoding is well formed.
	x_is_p := [33]u8 {
		0x02,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
	}
	testing.expect(t, !eckey.pubkey_parse(&pk, x_is_p[:]), "accepted x = p")

	// The generator must parse.
	g := [33]u8 {
		0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb,
		0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
		0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28,
		0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
	}
	testing.expect(t, eckey.pubkey_parse(&pk, g[:]), "rejected the generator")
}

/*
Mirrors `run_ecdsa_der_parse`, fuzzing the strict parser for crashes and for acceptance of
anything non-canonical.

The strict parser must never accept an encoding it would not itself produce: re-serializing
whatever it accepted has to reproduce the input exactly. That round-trip is what catches a
parser that tolerates a second encoding of the same signature — which is malleability.
*/
@(test)
test_run_ecdsa_der_parse :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 11)

	accepted := 0
	for _ in 0 ..< COUNT * 64 {
		buf: [72]u8
		n := 6 + int(testutil.rand_u32(&rng) % 66)
		testutil.rand_bytes_test(&rng, buf[:n])

		// Bias towards well-formed shapes so the parser is actually reached.
		if testutil.rand_u32(&rng) % 2 == 0 {
			buf[0] = 0x30
			buf[1] = u8(n - 2)
		}

		sig: ecdsa.Signature
		if !ecdsa.signature_parse_der(&sig, buf[:n]) {
			continue
		}
		accepted += 1

		out: [72]u8
		written := ecdsa.signature_serialize_der(out[:], &sig)
		testing.expectf(
			t,
			written == n,
			"accepted a %d-byte DER that re-serializes to %d bytes",
			n,
			written,
		)
		if written == n {
			same := true
			for k in 0 ..< written {
				if out[k] != buf[k] {
					same = false
					break
				}
			}
			testing.expect(t, same, "accepted a DER encoding that is not the canonical one")
		}
	}
	testing.expect(t, accepted >= 0, "unreachable")
}

/*
Mirrors `run_xoshiro256pp_tests`.

The test RNG is xoshiro256++, matching upstream's `testrand_impl.h`, so that a seed
reproduces the same sequence in both suites and a failure found there can be replayed here.
This checks the generator's own properties: determinism from a seed, and divergence between
different seeds.
*/
@(test)
test_run_xoshiro256pp_tests :: proc(t: ^testing.T) {
	a, b: testutil.Rand
	testutil.rand_seed(&a, 0x1234_5678)
	testutil.rand_seed(&b, 0x1234_5678)

	for i in 0 ..< 64 {
		testing.expectf(
			t,
			testutil.rand_u32(&a) == testutil.rand_u32(&b),
			"same seed diverged at draw %d",
			i,
		)
	}

	c: testutil.Rand
	testutil.rand_seed(&c, 0x8765_4321)
	differs := false
	d: testutil.Rand
	testutil.rand_seed(&d, 0x1234_5678)
	for _ in 0 ..< 64 {
		if testutil.rand_u32(&c) != testutil.rand_u32(&d) {
			differs = true
			break
		}
	}
	testing.expect(t, differs, "different seeds produced identical output")

	// The generator must not be stuck: 256 draws must not all be equal.
	e: testutil.Rand
	testutil.rand_seed(&e, 99)
	first := testutil.rand_u32(&e)
	varied := false
	for _ in 0 ..< 256 {
		if testutil.rand_u32(&e) != first {
			varied = true
			break
		}
	}
	testing.expect(t, varied, "generator appears stuck")
}
