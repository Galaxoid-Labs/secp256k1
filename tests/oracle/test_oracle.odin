/*
Differential tests against upstream libsecp256k1.

This is the strongest correctness signal available: identical inputs into both
implementations, byte-identical outputs demanded. It reaches paths no hand-written vector
covers, because the inputs are fuzzed rather than chosen.

Per `CLAUDE.md`, a divergence here is a bug to diagnose — an unnormalized magnitude, a
skipped low-S, an endomorphism sign, a wrong parity — never something to accommodate.

These tests link C and therefore live outside the library's import graph entirely. A
submodule consumer never builds them.

	odin test tests/oracle/ -debug
*/
package test_oracle

import "core:c"
import "core:testing"
import "../../ecdsa"
import "../../ecdh"
import "../../ecmult"
import "../../eckey"
import "../../ellswift"
import "../../extrakeys"
import "../../field"
import "../../group"
import h "../../hash"
import "../../oracle"
import "../../params"
import "../../recovery"
import "../../scalar"
import "../../schnorr"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0x0dd_c0de_0417)

/*
Iterations per differential test. Raise substantially in CI.
*/
FUZZ_COUNT :: #config(FUZZ_COUNT, 256)

/*
Per-test state.

The Odin test runner executes tests concurrently, so shared mutable globals would race —
and a partially initialized `Ecmult_Gen_Context` read by another thread produces field
elements with impossible magnitudes, which the invariant layer then traps on. Each test
therefore builds its own contexts.
*/
@(private = "file")
Fixture :: struct {
	c_ctx: oracle.Context,
	gen:   ecmult.Ecmult_Gen_Context,
}

@(private = "file")
setup :: proc(f: ^Fixture) {
	f.c_ctx = oracle.context_create(oracle.CONTEXT_SIGN | oracle.CONTEXT_VERIFY)
	ecmult.ecmult_gen_context_build(&f.gen)
}

@(private = "file")
teardown :: proc(f: ^Fixture) {
	oracle.context_destroy(f.c_ctx)
}

/*
Draws a valid secret key, agreed valid by both implementations.

Agreement on *validity* is itself part of what is being tested: if the two disagreed about
which 32-byte strings are keys, every downstream comparison would be meaningless.
*/
@(private = "file")
random_seckey :: proc(t: ^testing.T, f: ^Fixture, rng: ^testutil.Rand) -> [32]u8 {
	for {
		sk: [32]u8
		testutil.rand_bytes_test(rng, sk[:])

		s: scalar.Scalar
		ours := scalar.scalar_set_b32_seckey(&s, &sk)
		theirs := oracle.ec_seckey_verify(f.c_ctx, &sk[0]) == 1

		testing.expectf(t, ours == theirs, "seckey validity disagrees for %x", sk)
		if ours {
			return sk
		}
	}
}

@(test)
test_oracle_pubkey_create :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)

		// Ours.
		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		ours: group.Ge
		testing.expectf(t, eckey.pubkey_create(&f.gen, &ours, &s), "our pubkey_create failed (%d)", i)
		ours33: [33]u8
		eckey.pubkey_serialize33(&ours, &ours33)

		// Theirs.
		cpk: oracle.Pubkey
		testing.expectf(t, oracle.ec_pubkey_create(f.c_ctx, &cpk, &sk[0]) == 1, "C pubkey_create failed (%d)", i)
		theirs33: [33]u8
		outlen := uint(33)
		oracle.ec_pubkey_serialize(f.c_ctx, &theirs33[0], &outlen, &cpk, oracle.EC_COMPRESSED)

		testing.expectf(t, ours33 == theirs33, "pubkey mismatch at %d: ours %x theirs %x", i, ours33, theirs33)

		// Uncompressed too.
		ours65: [65]u8
		eckey.pubkey_serialize65(&ours, &ours65)
		theirs65: [65]u8
		outlen65 := uint(65)
		oracle.ec_pubkey_serialize(f.c_ctx, &theirs65[0], &outlen65, &cpk, oracle.EC_UNCOMPRESSED)
		testing.expectf(t, ours65 == theirs65, "uncompressed pubkey mismatch at %d", i)
	}
}

@(test)
test_oracle_ecdsa_sign_verify :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		msg: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])

		// Both must produce the identical signature: RFC6979 makes signing deterministic,
		// so any difference in nonce derivation or algebra shows up immediately.
		ours: ecdsa.Signature
		testing.expectf(t, ecdsa.sign(&f.gen, &ours, &msg, &sk), "our sign failed (%d)", i)
		ours64: [64]u8
		ecdsa.signature_serialize_compact(&ours64, &ours)

		csig: oracle.Ecdsa_Signature
		testing.expectf(t, oracle.ecdsa_sign(f.c_ctx, &csig, &msg[0], &sk[0], nil, nil) == 1, "C sign failed (%d)", i)
		theirs64: [64]u8
		oracle.ecdsa_signature_serialize_compact(f.c_ctx, &theirs64[0], &csig)

		testing.expectf(t, ours64 == theirs64, "ECDSA signature mismatch at %d", i)

		// Cross-verify: each implementation must accept the other's signature.
		cpk: oracle.Pubkey
		oracle.ec_pubkey_create(f.c_ctx, &cpk, &sk[0])
		testing.expectf(t, oracle.ecdsa_verify(f.c_ctx, &csig, &msg[0], &cpk) == 1, "C rejected its own signature (%d)", i)

		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		ourpk: group.Ge
		eckey.pubkey_create(&f.gen, &ourpk, &s)

		from_c: ecdsa.Signature
		testing.expectf(t, ecdsa.signature_parse_compact(&from_c, &theirs64), "parsing the C signature failed (%d)", i)
		testing.expectf(t, ecdsa.verify(&from_c, &msg, &ourpk), "we rejected the C signature (%d)", i)

		our_sig_for_c: oracle.Ecdsa_Signature
		oracle.ecdsa_signature_parse_compact(f.c_ctx, &our_sig_for_c, &ours64[0])
		testing.expectf(
			t,
			oracle.ecdsa_verify(f.c_ctx, &our_sig_for_c, &msg[0], &cpk) == 1,
			"C rejected our signature (%d)",
			i,
		)

		// DER must agree byte for byte.
		our_der: [80]u8
		our_der_len := ecdsa.signature_serialize_der(our_der[:], &ours)
		their_der: [80]u8
		their_der_len := uint(80)
		oracle.ecdsa_signature_serialize_der(f.c_ctx, &their_der[0], &their_der_len, &csig)

		testing.expectf(t, our_der_len == int(their_der_len), "DER length mismatch at %d", i)
		if our_der_len == int(their_der_len) {
			for j in 0 ..< our_der_len {
				testing.expectf(t, our_der[j] == their_der[j], "DER byte %d mismatch at %d", j, i)
			}
		}
	}
}

@(test)
test_oracle_ecdsa_verify_agrees_on_bad_signatures :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	// Random 64-byte blobs treated as signatures. Both must agree on parseability and, when
	// parseable, on the verdict. This is where a lenient verifier would show up.
	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		msg: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])

		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		ourpk: group.Ge
		eckey.pubkey_create(&f.gen, &ourpk, &s)
		cpk: oracle.Pubkey
		oracle.ec_pubkey_create(f.c_ctx, &cpk, &sk[0])

		blob: [64]u8
		testutil.rand_bytes_test(&rng, blob[:])

		our_sig: ecdsa.Signature
		our_ok := ecdsa.signature_parse_compact(&our_sig, &blob)
		c_sig: oracle.Ecdsa_Signature
		c_ok := oracle.ecdsa_signature_parse_compact(f.c_ctx, &c_sig, &blob[0]) == 1

		testing.expectf(t, our_ok == c_ok, "compact parse disagrees at %d", i)

		if our_ok && c_ok {
			our_v := ecdsa.verify(&our_sig, &msg, &ourpk)
			c_v := oracle.ecdsa_verify(f.c_ctx, &c_sig, &msg[0], &cpk) == 1
			testing.expectf(t, our_v == c_v, "verification verdict disagrees at %d", i)
		}
	}
}

@(test)
test_oracle_schnorr :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		msg: [32]u8
		aux: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])
		testutil.rand_bytes_test(&rng, aux[:])

		// Ours.
		kp: extrakeys.Keypair
		testing.expectf(t, extrakeys.keypair_create(&f.gen, &kp, &sk), "our keypair_create failed (%d)", i)
		xonly: extrakeys.Xonly_Pubkey
		parity: bool
		extrakeys.keypair_xonly_pub(&xonly, &parity, &kp)
		our_pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&our_pk32, &xonly)

		our_sig: [64]u8
		testing.expectf(t, schnorr.sign(&f.gen, &our_sig, msg[:], &kp, &aux), "our schnorr sign failed (%d)", i)

		// Theirs.
		ckp: oracle.Keypair
		testing.expectf(t, oracle.keypair_create(f.c_ctx, &ckp, &sk[0]) == 1, "C keypair_create failed (%d)", i)
		cxonly: oracle.Xonly_Pubkey
		cparity: i32
		oracle.keypair_xonly_pub(f.c_ctx, &cxonly, &cparity, &ckp)
		their_pk32: [32]u8
		oracle.xonly_pubkey_serialize(f.c_ctx, &their_pk32[0], &cxonly)

		testing.expectf(t, our_pk32 == their_pk32, "x-only pubkey mismatch at %d", i)
		testing.expectf(t, parity == (cparity == 1), "x-only parity mismatch at %d", i)

		their_sig: [64]u8
		testing.expectf(
			t,
			oracle.schnorrsig_sign32(f.c_ctx, &their_sig[0], &msg[0], &ckp, &aux[0]) == 1,
			"C schnorr sign failed (%d)",
			i,
		)

		testing.expectf(t, our_sig == their_sig, "Schnorr signature mismatch at %d", i)

		// Cross-verify.
		testing.expectf(
			t,
			oracle.schnorrsig_verify(f.c_ctx, &our_sig[0], &msg[0], 32, &cxonly) == 1,
			"C rejected our Schnorr signature (%d)",
			i,
		)
		testing.expectf(t, schnorr.verify(&their_sig, msg[:], &xonly), "we rejected the C Schnorr signature (%d)", i)
	}
}

@(test)
test_oracle_ecdh :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	for i in 0 ..< FUZZ_COUNT {
		a := random_seckey(t, &f, &rng)
		b := random_seckey(t, &f, &rng)

		// Ours: b's public key, a's secret.
		sb: scalar.Scalar
		scalar.scalar_set_b32_seckey(&sb, &b)
		pb: group.Ge
		eckey.pubkey_create(&f.gen, &pb, &sb)

		ours: [32]u8
		testing.expectf(t, ecdh.ecdh(ours[:], &pb, &a), "our ecdh failed (%d)", i)

		// Theirs.
		cpb: oracle.Pubkey
		oracle.ec_pubkey_create(f.c_ctx, &cpb, &b[0])
		theirs: [32]u8
		testing.expectf(t, oracle.ecdh(f.c_ctx, &theirs[0], &cpb, &a[0], nil, nil) == 1, "C ecdh failed (%d)", i)

		testing.expectf(t, ours == theirs, "ECDH shared secret mismatch at %d", i)
	}
}

@(test)
test_oracle_recovery :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 5)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		msg: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])

		ours: recovery.Recoverable_Signature
		testing.expectf(t, recovery.sign_recoverable(&f.gen, &ours, &msg, &sk), "our recoverable sign failed (%d)", i)
		our64: [64]u8
		our_recid: int
		recovery.signature_serialize_compact(&our64, &our_recid, &ours)

		csig: oracle.Ecdsa_Recoverable_Signature
		testing.expectf(
			t,
			oracle.ecdsa_sign_recoverable(f.c_ctx, &csig, &msg[0], &sk[0], nil, nil) == 1,
			"C recoverable sign failed (%d)",
			i,
		)
		their64: [64]u8
		their_recid: i32
		oracle.ecdsa_recoverable_signature_serialize_compact(f.c_ctx, &their64[0], &their_recid, &csig)

		testing.expectf(t, our64 == their64, "recoverable signature mismatch at %d", i)
		testing.expectf(t, our_recid == int(their_recid), "recovery id mismatch at %d: %d vs %d", i, our_recid, their_recid)

		// The recovered keys must agree.
		our_rec: group.Ge
		testing.expectf(t, recovery.recover(&our_rec, &ours, &msg), "our recovery failed (%d)", i)
		our_rec33: [33]u8
		eckey.pubkey_serialize33(&our_rec, &our_rec33)

		their_rec: oracle.Pubkey
		testing.expectf(t, oracle.ecdsa_recover(f.c_ctx, &their_rec, &csig, &msg[0]) == 1, "C recovery failed (%d)", i)
		their_rec33: [33]u8
		outlen := uint(33)
		oracle.ec_pubkey_serialize(f.c_ctx, &their_rec33[0], &outlen, &their_rec, oracle.EC_COMPRESSED)

		testing.expectf(t, our_rec33 == their_rec33, "recovered key mismatch at %d", i)
	}
}

@(test)
test_oracle_pubkey_parse_and_tweak :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 6)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		tweak: [32]u8
		testutil.rand_bytes_test(&rng, tweak[:])

		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		ourpk: group.Ge
		eckey.pubkey_create(&f.gen, &ourpk, &s)
		cpk: oracle.Pubkey
		oracle.ec_pubkey_create(f.c_ctx, &cpk, &sk[0])

		// Tweak add must agree, including on failure.
		ts: scalar.Scalar
		tweak_overflow := scalar.scalar_set_b32(&ts, &tweak)

		our_tweaked := ourpk
		our_ok := !tweak_overflow && eckey.pubkey_tweak_add(&our_tweaked, &ts)

		their_tweaked := cpk
		their_ok := oracle.ec_pubkey_tweak_add(f.c_ctx, &their_tweaked, &tweak[0]) == 1

		testing.expectf(t, our_ok == their_ok, "pubkey_tweak_add success disagrees at %d", i)

		if our_ok && their_ok {
			ours33: [33]u8
			eckey.pubkey_serialize33(&our_tweaked, &ours33)
			theirs33: [33]u8
			outlen := uint(33)
			oracle.ec_pubkey_serialize(f.c_ctx, &theirs33[0], &outlen, &their_tweaked, oracle.EC_COMPRESSED)
			testing.expectf(t, ours33 == theirs33, "tweaked pubkey mismatch at %d", i)
		}

		// Parsing arbitrary 33-byte blobs must agree on acceptance.
		blob: [33]u8
		testutil.rand_bytes_test(&rng, blob[:])
		blob[0] = 0x02 | (blob[0] & 1)

		our_parsed: group.Ge
		our_p := eckey.pubkey_parse(&our_parsed, blob[:])
		their_parsed: oracle.Pubkey
		their_p := oracle.ec_pubkey_parse(f.c_ctx, &their_parsed, &blob[0], 33) == 1

		testing.expectf(t, our_p == their_p, "pubkey_parse disagrees at %d for %x", i, blob)
	}
}

@(test)
test_oracle_ellswift :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 7)

	for i in 0 ..< FUZZ_COUNT {
		// Decoding is a pure function of the 64 bytes, so it must agree exactly on
		// arbitrary input — including the degenerate cases the formula patches.
		ell: [64]u8
		testutil.rand_bytes_test(&rng, ell[:])

		ours: group.Ge
		testing.expectf(t, ellswift.decode(&ours, &ell), "our ellswift decode failed (%d)", i)
		ours33: [33]u8
		eckey.pubkey_serialize33(&ours, &ours33)

		theirs: oracle.Pubkey
		testing.expectf(t, oracle.ellswift_decode(f.c_ctx, &theirs, &ell[0]) == 1, "C ellswift decode failed (%d)", i)
		theirs33: [33]u8
		outlen := uint(33)
		oracle.ec_pubkey_serialize(f.c_ctx, &theirs33[0], &outlen, &theirs, oracle.EC_COMPRESSED)

		testing.expectf(t, ours33 == theirs33, "ellswift decode mismatch at %d", i)
	}
}

/*
ellswift encoding of an existing public key, against C.

The third member of the family that had no comparison, and it had drifted the same way
`create` had: the candidate stream is `H(pubkey || "\x00"*31 || rnd32 || cnt)`, and this
implementation was hashing the bare 33-byte serialization with no padding. The encoding it
produced was valid — `decode` returns the original key, so the round-trip test this file
already had passed — but no other implementation derives it from the same randomness, which
is the whole property `rnd32` exists to provide.

Found by the drop-in swap test in `dropin/`, which links a C consumer against each library
in turn; nothing that only exercised our own code could see it.

Encoding is deterministic in (pubkey, rnd32), so the comparison is exact.
*/
@(test)
test_oracle_ellswift_encode :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x5151)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		rnd: [32]u8
		testutil.rand_bytes_test(&rng, rnd[:])

		our_pk: group.Ge
		s: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&s, &sk) {
			continue
		}
		if !eckey.pubkey_create(&f.gen, &our_pk, &s) {
			continue
		}
		ours: [64]u8
		ellswift.encode(&ours, &our_pk, &rnd)

		their_pk: oracle.Pubkey
		testing.expectf(
			t,
			oracle.ec_pubkey_create(f.c_ctx, &their_pk, &sk[0]) == 1,
			"C pubkey_create failed at %d",
			i,
		)
		theirs: [64]u8
		testing.expectf(
			t,
			oracle.ellswift_encode(f.c_ctx, &theirs[0], &their_pk, &rnd[0]) == 1,
			"C ellswift_encode failed at %d",
			i,
		)

		testing.expectf(
			t,
			ours == theirs,
			"ellswift_encode mismatch at %d\n  ours   %x\n  theirs %x",
			i,
			ours,
			theirs,
		)
	}
}

@(test)
test_oracle_tagged_hash :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 8)

	for i in 0 ..< FUZZ_COUNT {
		tag: [16]u8
		msg: [64]u8
		testutil.rand_bytes_test(&rng, tag[:])
		testutil.rand_bytes_test(&rng, msg[:])

		ours: [32]u8
		h.tagged_sha256(&ours, tag[:], msg[:])

		theirs: [32]u8
		oracle.tagged_sha256(f.c_ctx, &theirs[0], &tag[0], 16, &msg[0], 64)

		testing.expectf(t, ours == theirs, "tagged hash mismatch at %d", i)
	}
}

/*
ellswift key creation and BIP324 x-only ECDH, against C.

These two were the gap in ellswift coverage: only `decode` was compared, so `create` and
`xdh` were unchecked against any external implementation. That mattered — `create`'s RNG
framing had drifted from the specification (`seckey || zero32 [|| aux]`, where this
implementation was substituting aux *for* the zeros rather than appending after them). The
result was a perfectly valid encoding that no other implementation would reproduce, and
nothing could see it, because an encoding verifies against itself either way.

`create` is deterministic in (seckey, aux), so the comparison is exact.
*/
@(test)
test_oracle_ellswift_create_xdh :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x5150)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		aux: [32]u8
		testutil.rand_bytes_test(&rng, aux[:])

		// With auxiliary randomness.
		ours: [64]u8
		testing.expectf(t, ellswift.create(&f.gen, &ours, &sk, &aux), "our create failed at %d", i)

		theirs: [64]u8
		testing.expectf(
			t,
			oracle.ellswift_create(f.c_ctx, &theirs[0], &sk[0], &aux[0]) == 1,
			"C create failed at %d",
			i,
		)
		testing.expectf(
			t,
			ours == theirs,
			"ellswift_create mismatch at %d (with aux)\n  ours   %x\n  theirs %x",
			i,
			ours,
			theirs,
		)

		// And without, which takes the other branch of the framing.
		ours_na: [64]u8
		theirs_na: [64]u8
		testing.expectf(t, ellswift.create(&f.gen, &ours_na, &sk, nil), "our create(nil) failed at %d", i)
		testing.expectf(
			t,
			oracle.ellswift_create(f.c_ctx, &theirs_na[0], &sk[0], nil) == 1,
			"C create(nil) failed at %d",
			i,
		)
		testing.expectf(
			t,
			ours_na == theirs_na,
			"ellswift_create mismatch at %d (no aux)\n  ours   %x\n  theirs %x",
			i,
			ours_na,
			theirs_na,
		)

		// xdh in both party roles, against the same pair of encodings.
		sk2 := random_seckey(t, &f, &rng)
		shared_by_party: [2][32]u8
		other: [64]u8
		if !ellswift.create(&f.gen, &other, &sk2, nil) {
			continue
		}

		// A real handshake: party A holds `sk` and encoding `ours`, party B holds `sk2` and
		// encoding `other`. Each side supplies its own key with its own party flag.
		for party in 0 ..< 2 {
			p := party == 1
			my_sk := p ? sk2 : sk

			our_shared: [32]u8
			ok := ellswift.xdh(our_shared[:], &ours, &other, &my_sk, p)

			their_shared: [32]u8
			cok := oracle.ellswift_xdh(
				f.c_ctx,
				&their_shared[0],
				&ours[0],
				&other[0],
				&my_sk[0],
				c.int(party),
				oracle.ellswift_xdh_hash_function_bip324,
				nil,
			) == 1

			testing.expectf(t, ok == cok, "xdh success disagrees at %d party %d", i, party)
			if !ok {
				continue
			}
			shared_by_party[party] = our_shared
			testing.expectf(
				t,
				our_shared == their_shared,
				"xdh shared secret mismatch at %d party %d\n  ours   %x\n  theirs %x",
				i,
				party,
				our_shared,
				their_shared,
			)
		}

		// The point of the exchange: both parties must arrive at the same secret. This is
		// what an inverted `party` breaks in the field while leaving a symmetric
		// self-test perfectly happy.
		testing.expectf(
			t,
			shared_by_party[0] == shared_by_party[1],
			"the two parties derived different secrets at %d\n  A %x\n  B %x",
			i,
			shared_by_party[0],
			shared_by_party[1],
		)
	}
}
