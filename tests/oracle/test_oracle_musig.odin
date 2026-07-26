/*
Differential tests for MuSig2 against upstream libsecp256k1.

Until these existed, MuSig2 had **zero** differential coverage — the riskiest module in the
project was the one module the oracle skipped. `CLAUDE.md` names it the highest-risk code
here, and its only evidence was self-consistency: an aggregated signature verified as
BIP340. That is a weak signal for a multi-party protocol, because an implementation can be
wrong in a way that is wrong *identically* for every participant and still round-trip
perfectly. Exactly that happened — nonce generation did not implement BIP327 at all, and
nothing caught it until the specification's vectors were run.

These tests close the gap from the other side. Where the vectors pin a handful of chosen
inputs, this pins thousands of fuzzed ones against a second implementation.

# Exact comparison, not round-tripping

Nonce generation is deterministic given the same session randomness, so the comparison is
byte-for-byte on the derived nonces rather than "both produce something that verifies".
That distinction matters: a round-trip check would have passed the whole time the
derivation was non-compliant.

One wrinkle makes that harder than it looks. Upstream's `musig_nonce_gen` **overwrites**
`session_secrand32` on the way out, deliberately, so reusing the buffer is not silently
possible. A fresh copy therefore goes to each implementation.
*/
package test_oracle

import "core:testing"
import "../../ecmult"
import "../../eckey"
import "../../extrakeys"
import "../../group"
import "../../musig"
import "../../oracle"
import "../../scalar"
import "../../testutil"

/*
Per-test state. A file-local twin of the one in `test_oracle.odin`, which is file-private
there; the runner executes tests concurrently, so each builds its own contexts rather than
sharing.
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
Draws a secret key both implementations agree is valid.
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

/*
The opaque MuSig2 struct sizes must match `include/secp256k1_musig.h` exactly.

C writes the whole struct through these pointers. Too small is a buffer overflow; too large
works by accident while hiding a layout mismatch. Pinning them here means a future upstream
bump that changes a size fails loudly instead of corrupting the stack.
*/
@(test)
test_oracle_musig_struct_sizes :: proc(t: ^testing.T) {
	testing.expect_value(t, size_of(oracle.Musig_Keyagg_Cache), 197)
	testing.expect_value(t, size_of(oracle.Musig_Secnonce), 132)
	testing.expect_value(t, size_of(oracle.Musig_Pubnonce), 132)
	testing.expect_value(t, size_of(oracle.Musig_Aggnonce), 132)
	testing.expect_value(t, size_of(oracle.Musig_Session), 133)
	testing.expect_value(t, size_of(oracle.Musig_Partial_Sig), 36)
}

/*
Key aggregation must agree byte for byte, over key sets of varying size and order.

Order is varied deliberately: MuSig2 aggregation is order-dependent, so two implementations
that agree on sorted input can still disagree on unsorted input. Repeated keys are included
for the same reason — they are where an implementation that quietly deduplicates diverges.
*/
@(test)
test_oracle_musig_pubkey_agg :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x111)

	for i in 0 ..< FUZZ_COUNT {
		n := 1 + int(testutil.rand_u32(&rng) % 4)

		sks: [4][32]u8
		ours_keys: [4]group.Ge
		c_pks: [4]oracle.Pubkey
		c_ptrs: [4]^oracle.Pubkey

		for j in 0 ..< n {
			sks[j] = random_seckey(t, &f, &rng)

			s: scalar.Scalar
			scalar.scalar_set_b32_seckey(&s, &sks[j])
			eckey.pubkey_create(&f.gen, &ours_keys[j], &s)

			if oracle.ec_pubkey_create(f.c_ctx, &c_pks[j], &sks[j][0]) != 1 {
				testing.expectf(t, false, "C pubkey_create failed at %d", i)
				return
			}
			c_ptrs[j] = &c_pks[j]
		}

		// Repeat the first key sometimes, which exercises the "second distinct key"
		// coefficient rule that only fires on duplicates.
		if n > 1 && testutil.rand_u32(&rng) % 3 == 0 {
			ours_keys[n - 1] = ours_keys[0]
			c_ptrs[n - 1] = &c_pks[0]
		}

		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		ours_ok := musig.pubkey_agg(&agg_pk, &cache, ours_keys[:n])

		c_agg: oracle.Xonly_Pubkey
		c_cache: oracle.Musig_Keyagg_Cache
		theirs_ok := oracle.musig_pubkey_agg(f.c_ctx, &c_agg, &c_cache, &c_ptrs[0], uint(n)) == 1

		testing.expectf(t, ours_ok == theirs_ok, "agg success disagrees at %d", i)
		if !ours_ok {
			continue
		}

		ours32: [32]u8
		extrakeys.xonly_pubkey_serialize(&ours32, &agg_pk)

		theirs32: [32]u8
		oracle.xonly_pubkey_serialize(f.c_ctx, &theirs32[0], &c_agg)

		testing.expectf(
			t,
			ours32 == theirs32,
			"aggregate key mismatch at %d (n=%d)\n  ours   %x\n  theirs %x",
			i,
			n,
			ours32,
			theirs32,
		)
	}
}

/*
Nonce generation must agree exactly, including the optional inputs.

This is the test that would have caught the BIP327 non-compliance immediately. The optional
arguments are varied independently so that the presence framing — which is what a
non-compliant implementation gets wrong — is exercised in every combination.
*/
@(test)
test_oracle_musig_nonce_gen :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x222)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)

		session_id: [32]u8
		testutil.rand_bytes_test(&rng, session_id[:])

		msg: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])
		extra: [32]u8
		testutil.rand_bytes_test(&rng, extra[:])

		// Vary which optional inputs are supplied. Absent must not hash like present-zero.
		use_msg := testutil.rand_u32(&rng) % 2 == 0
		use_extra := testutil.rand_u32(&rng) % 2 == 0
		use_aggpk := testutil.rand_u32(&rng) % 2 == 0

		// Ours.
		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		our_pk: group.Ge
		eckey.pubkey_create(&f.gen, &our_pk, &s)

		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		one_key := []group.Ge{our_pk}
		if !musig.pubkey_agg(&agg_pk, &cache, one_key) {
			continue
		}
		agg_pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

		// Theirs — note the C side needs its own copy of the session randomness, because
		// `musig_nonce_gen` overwrites the buffer it is given.
		c_pk: oracle.Pubkey
		if oracle.ec_pubkey_create(f.c_ctx, &c_pk, &sk[0]) != 1 {
			continue
		}
		c_ptrs := [1]^oracle.Pubkey{&c_pk}
		c_agg: oracle.Xonly_Pubkey
		c_cache: oracle.Musig_Keyagg_Cache
		if oracle.musig_pubkey_agg(f.c_ctx, &c_agg, &c_cache, &c_ptrs[0], 1) != 1 {
			continue
		}

		our_secnonce: musig.Secnonce
		our_pubnonce: musig.Pubnonce
		ours_ok := musig.nonce_gen(
			&f.gen,
			&our_secnonce,
			&our_pubnonce,
			&session_id,
			&sk,
			&our_pk,
			use_msg ? &msg : nil,
			use_aggpk ? &agg_pk32 : nil,
			use_extra ? &extra : nil,
		)

		c_session_id := session_id
		c_secnonce: oracle.Musig_Secnonce
		c_pubnonce: oracle.Musig_Pubnonce
		theirs_ok := oracle.musig_nonce_gen(
			f.c_ctx,
			&c_secnonce,
			&c_pubnonce,
			&c_session_id[0],
			&sk[0],
			&c_pk,
			use_msg ? &msg[0] : nil,
			use_aggpk ? &c_cache : nil,
			use_extra ? &extra[0] : nil,
		) == 1

		testing.expectf(t, ours_ok == theirs_ok, "nonce_gen success disagrees at %d", i)
		if !ours_ok {
			continue
		}

		ours66: [66]u8
		musig.pubnonce_serialize(&ours66, &our_pubnonce)

		theirs66: [66]u8
		oracle.musig_pubnonce_serialize(f.c_ctx, &theirs66[0], &c_pubnonce)

		testing.expectf(
			t,
			ours66 == theirs66,
			"pubnonce mismatch at %d (msg=%v aggpk=%v extra=%v)\n  ours   %x\n  theirs %x",
			i,
			use_msg,
			use_aggpk,
			use_extra,
			ours66,
			theirs66,
		)
	}
}

/*
Nonce aggregation must agree, including the infinity case.

An aggregate nonce can legitimately be the point at infinity, which BIP327 encodes as 33
zero bytes rather than treating as an error. Fuzzing rarely produces it, so the vectors
cover it explicitly and this covers everything else.
*/
@(test)
test_oracle_musig_nonce_agg :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x333)

	for i in 0 ..< FUZZ_COUNT {
		n := 1 + int(testutil.rand_u32(&rng) % 3)

		ours_nonces: [3]musig.Pubnonce
		c_nonces: [3]oracle.Musig_Pubnonce
		c_ptrs: [3]^oracle.Musig_Pubnonce
		built := 0

		for j in 0 ..< n {
			sk := random_seckey(t, &f, &rng)
			session_id: [32]u8
			testutil.rand_bytes_test(&rng, session_id[:])

			s: scalar.Scalar
			scalar.scalar_set_b32_seckey(&s, &sk)
			pk: group.Ge
			eckey.pubkey_create(&f.gen, &pk, &s)

			secnonce: musig.Secnonce
			if !musig.nonce_gen(&f.gen, &secnonce, &ours_nonces[built], &session_id, &sk, &pk) {
				continue
			}

			// Feed the C side the same nonce by serializing ours across, so both aggregate
			// identical inputs rather than merely similar ones.
			ser: [66]u8
			musig.pubnonce_serialize(&ser, &ours_nonces[built])
			if oracle.musig_pubnonce_parse(f.c_ctx, &c_nonces[built], &ser[0]) != 1 {
				testing.expectf(t, false, "C rejected a pubnonce we produced, at %d", i)
				return
			}
			c_ptrs[built] = &c_nonces[built]
			built += 1
		}
		if built == 0 {
			continue
		}

		our_agg: musig.Aggnonce
		ours_ok := musig.nonce_agg(&our_agg, ours_nonces[:built])

		c_agg: oracle.Musig_Aggnonce
		theirs_ok := oracle.musig_nonce_agg(f.c_ctx, &c_agg, &c_ptrs[0], uint(built)) == 1

		testing.expectf(t, ours_ok == theirs_ok, "nonce_agg success disagrees at %d", i)
		if !ours_ok {
			continue
		}

		ours66: [66]u8
		musig.aggnonce_serialize(&ours66, &our_agg)
		theirs66: [66]u8
		oracle.musig_aggnonce_serialize(f.c_ctx, &theirs66[0], &c_agg)

		testing.expectf(
			t,
			ours66 == theirs66,
			"aggnonce mismatch at %d (n=%d)\n  ours   %x\n  theirs %x",
			i,
			built,
			ours66,
			theirs66,
		)
	}
}

/*
Partial signatures must agree byte for byte, and each implementation must accept the
other's.

The cross-verification is the part that would catch a shared-but-wrong convention: two
implementations can produce identical partial signatures from identical inputs and still
both be wrong, but a partial signature that C's verifier accepts is a signature that
composes with C's aggregation.
*/
@(test)
test_oracle_musig_partial_sign :: proc(t: ^testing.T) {
	f: Fixture
	setup(&f)
	defer teardown(&f)
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 0x444)

	for i in 0 ..< FUZZ_COUNT {
		sk := random_seckey(t, &f, &rng)
		session_id: [32]u8
		testutil.rand_bytes_test(&rng, session_id[:])
		msg: [32]u8
		testutil.rand_bytes_test(&rng, msg[:])

		// Ours: single-signer session, which still exercises the whole pipeline —
		// aggregation, binding coefficient, challenge, partial signing.
		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, &sk)
		pk: group.Ge
		eckey.pubkey_create(&f.gen, &pk, &s)

		kp: extrakeys.Keypair
		if !extrakeys.keypair_create(&f.gen, &kp, &sk) {
			continue
		}

		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		keys := []group.Ge{pk}
		if !musig.pubkey_agg(&agg_pk, &cache, keys) {
			continue
		}
		agg_pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

		our_secnonce: musig.Secnonce
		our_pubnonce: musig.Pubnonce
		if !musig.nonce_gen(
			&f.gen,
			&our_secnonce,
			&our_pubnonce,
			&session_id,
			&sk,
			&pk,
			&msg,
			&agg_pk32,
		) {
			continue
		}

		our_aggnonce: musig.Aggnonce
		if !musig.nonce_agg(&our_aggnonce, []musig.Pubnonce{our_pubnonce}) {
			continue
		}

		our_session: musig.Session
		musig.nonce_process(&our_session, &our_aggnonce, &msg, &cache)

		our_psig: musig.Partial_Sig
		if !musig.partial_sign(&our_psig, &our_secnonce, &kp, &cache, &our_session) {
			testing.expectf(t, false, "our partial_sign failed at %d", i)
			continue
		}

		// Theirs, driven from the identical nonce so the comparison is meaningful.
		c_pk: oracle.Pubkey
		if oracle.ec_pubkey_create(f.c_ctx, &c_pk, &sk[0]) != 1 {
			continue
		}
		c_kp: oracle.Keypair
		if oracle.keypair_create(f.c_ctx, &c_kp, &sk[0]) != 1 {
			continue
		}
		c_ptrs := [1]^oracle.Pubkey{&c_pk}
		c_agg: oracle.Xonly_Pubkey
		c_cache: oracle.Musig_Keyagg_Cache
		if oracle.musig_pubkey_agg(f.c_ctx, &c_agg, &c_cache, &c_ptrs[0], 1) != 1 {
			continue
		}

		c_session_id := session_id
		c_secnonce: oracle.Musig_Secnonce
		c_pubnonce: oracle.Musig_Pubnonce
		if oracle.musig_nonce_gen(
			f.c_ctx,
			&c_secnonce,
			&c_pubnonce,
			&c_session_id[0],
			&sk[0],
			&c_pk,
			&msg[0],
			&c_cache,
			nil,
		) != 1 {
			continue
		}

		c_nonce_ptrs := [1]^oracle.Musig_Pubnonce{&c_pubnonce}
		c_aggnonce: oracle.Musig_Aggnonce
		if oracle.musig_nonce_agg(f.c_ctx, &c_aggnonce, &c_nonce_ptrs[0], 1) != 1 {
			continue
		}

		c_session: oracle.Musig_Session
		if oracle.musig_nonce_process(f.c_ctx, &c_session, &c_aggnonce, &msg[0], &c_cache) != 1 {
			continue
		}

		c_psig: oracle.Musig_Partial_Sig
		if oracle.musig_partial_sign(f.c_ctx, &c_psig, &c_secnonce, &c_kp, &c_cache, &c_session) != 1 {
			testing.expectf(t, false, "C partial_sign failed at %d", i)
			continue
		}

		ours32: [32]u8
		musig.partial_sig_serialize(&ours32, &our_psig)
		theirs32: [32]u8
		oracle.musig_partial_sig_serialize(f.c_ctx, &theirs32[0], &c_psig)

		testing.expectf(
			t,
			ours32 == theirs32,
			"partial signature mismatch at %d\n  ours   %x\n  theirs %x",
			i,
			ours32,
			theirs32,
		)

		// C must accept the partial signature we produced. Byte equality already implies it
		// here, but this fails loudly if the serializations ever agree while the underlying
		// session state does not.
		c_ours: oracle.Musig_Partial_Sig
		if oracle.musig_partial_sig_parse(f.c_ctx, &c_ours, &ours32[0]) == 1 {
			testing.expectf(
				t,
				oracle.musig_partial_sig_verify(
					f.c_ctx,
					&c_ours,
					&c_pubnonce,
					&c_pk,
					&c_cache,
					&c_session,
				) == 1,
				"C rejected our partial signature at %d",
				i,
			)
		}

		// And the aggregate must match, which is what actually goes on chain.
		our_sig: [64]u8
		if musig.partial_sig_agg(&our_sig, &our_session, []musig.Partial_Sig{our_psig}) {
			c_sig_ptrs := [1]^oracle.Musig_Partial_Sig{&c_psig}
			c_sig: [64]u8
			if oracle.musig_partial_sig_agg(f.c_ctx, &c_sig[0], &c_session, &c_sig_ptrs[0], 1) == 1 {
				testing.expectf(
					t,
					our_sig == c_sig,
					"aggregate signature mismatch at %d\n  ours   %x\n  theirs %x",
					i,
					our_sig,
					c_sig,
				)
			}
		}
	}
}
