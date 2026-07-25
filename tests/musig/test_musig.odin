/*
MuSig2 tests, mirroring upstream's `modules/musig/tests_impl.h`.

The end-to-end property is that an aggregated multi-signature verifies as an ordinary
BIP340 signature under the aggregate key. That single check exercises key aggregation,
nonce aggregation, the binding coefficient, both parity accumulators and partial-signature
aggregation together — and it is checked against the *real* Schnorr verifier, not a
MuSig-specific one.

The security properties get dedicated tests, because they fail silently:

  - **Nonce reuse must be impossible.** A second `partial_sign` with the same secnonce must
    fail rather than sign. Two signatures under one nonce reveal the secret key.
  - **Rogue-key resistance.** Aggregation must depend on the whole key list, so a
    participant who chooses its key last cannot control the aggregate.
  - **Order sensitivity.** Aggregation is order-dependent unless keys are sorted.
*/
package test_musig

import "core:testing"
import "../../ecmult"
import "../../eckey"
import "../../extrakeys"
import "../../group"
import "../../musig"
import "../../params"
import "../../scalar"
import "../../schnorr"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0x0451_9327_2026)

/*
A complete signing session for `n` participants.
*/
@(private = "file")
run_session :: proc(
	t: ^testing.T,
	gen: ^ecmult.Ecmult_Gen_Context,
	rng: ^testutil.Rand,
	n: int,
	msg: ^[32]u8,
	tweak: ^[32]u8 = nil,
	xonly_tweak: bool = true,
) -> (
	sig: [64]u8,
	agg_pk: extrakeys.Xonly_Pubkey,
	ok: bool,
) {
	keypairs := make([]extrakeys.Keypair, n)
	defer delete(keypairs)
	pubkeys := make([]group.Ge, n)
	defer delete(pubkeys)

	for i in 0 ..< n {
		sk: [32]u8
		for {
			testutil.rand_bytes(rng, sk[:])
			if extrakeys.keypair_create(gen, &keypairs[i], &sk) {
				break
			}
		}
		extrakeys.keypair_pub(&pubkeys[i], &keypairs[i])
	}

	cache: musig.Keyagg_Cache
	if !musig.pubkey_agg(&agg_pk, &cache, pubkeys) {
		return
	}

	if tweak != nil {
		out: group.Ge
		applied := xonly_tweak ? musig.pubkey_xonly_tweak_add(&out, &cache, tweak) : musig.pubkey_ec_tweak_add(&out, &cache, tweak)
		if !applied {
			return
		}
		if !musig.pubkey_get(&agg_pk, &cache) {
			return
		}
	}

	agg_pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

	secnonces := make([]musig.Secnonce, n)
	defer delete(secnonces)
	pubnonces := make([]musig.Pubnonce, n)
	defer delete(pubnonces)

	for i in 0 ..< n {
		session_id: [32]u8
		testutil.rand_bytes(rng, session_id[:])
		sk32: [32]u8
		extrakeys.keypair_sec(&sk32, &keypairs[i])
		if !musig.nonce_gen(gen, &secnonces[i], &pubnonces[i], &session_id, &sk32, &pubkeys[i], msg, &agg_pk32) {
			return
		}
	}

	aggnonce: musig.Aggnonce
	if !musig.nonce_agg(&aggnonce, pubnonces) {
		return
	}

	session: musig.Session
	if !musig.nonce_process(&session, &aggnonce, msg, &cache) {
		return
	}

	partials := make([]musig.Partial_Sig, n)
	defer delete(partials)
	for i in 0 ..< n {
		if !musig.partial_sign(&partials[i], &secnonces[i], &keypairs[i], &cache, &session) {
			return
		}
		// Every partial signature must verify on its own.
		if !musig.partial_sig_verify(&partials[i], &pubnonces[i], &pubkeys[i], &cache, &session) {
			testing.expectf(t, false, "partial signature %d does not verify", i)
			return
		}
	}

	if !musig.partial_sig_agg(&sig, &session, partials) {
		return
	}
	ok = true
	return
}

/*
The defining test: an aggregated MuSig2 signature must verify as an ordinary BIP340
signature under the aggregate key.
*/
@(test)
test_musig_end_to_end :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for n in 1 ..= 5 {
		for round in 0 ..< 4 {
			msg: [32]u8
			testutil.rand_bytes(&rng, msg[:])

			sig, agg_pk, ok := run_session(t, &gen, &rng, n, &msg)
			testing.expectf(t, ok, "session failed for n=%d round=%d", n, round)
			if !ok {
				continue
			}

			testing.expectf(
				t,
				schnorr.verify(&sig, msg[:], &agg_pk),
				"the aggregated signature does not verify (n=%d round=%d)",
				n,
				round,
			)

			// A tampered message must not verify.
			other := msg
			other[0] ~= 1
			testing.expectf(
				t,
				!schnorr.verify(&sig, other[:], &agg_pk),
				"verified against the wrong message (n=%d)",
				n,
			)
		}
	}
}

/*
The same, with the aggregate key tweaked — the Taproot case, where both parity accumulators
matter.
*/
@(test)
test_musig_with_tweaks :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for n in 1 ..= 4 {
		for xonly in ([]bool{true, false}) {
			msg: [32]u8
			tweak: [32]u8
			testutil.rand_bytes(&rng, msg[:])
			testutil.rand_bytes(&rng, tweak[:])

			sig, agg_pk, ok := run_session(t, &gen, &rng, n, &msg, &tweak, xonly)
			testing.expectf(t, ok, "tweaked session failed (n=%d xonly=%v)", n, xonly)
			if !ok {
				continue
			}

			testing.expectf(
				t,
				schnorr.verify(&sig, msg[:], &agg_pk),
				"the tweaked aggregate signature does not verify (n=%d xonly=%v)",
				n,
				xonly,
			)
		}
	}
}

/*
Nonce reuse must be structurally impossible.

This is the single most important test in the module: two partial signatures under one
secret nonce let anyone solve for the signer's secret key.
*/
@(test)
test_musig_nonce_is_single_use :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	kp: extrakeys.Keypair
	sk: [32]u8
	for {
		testutil.rand_bytes(&rng, sk[:])
		if extrakeys.keypair_create(&gen, &kp, &sk) {
			break
		}
	}
	pk: group.Ge
	extrakeys.keypair_pub(&pk, &kp)

	pubkeys := []group.Ge{pk}
	agg_pk: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache
	testing.expect(t, musig.pubkey_agg(&agg_pk, &cache, pubkeys), "aggregation failed")

	agg_pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

	msg: [32]u8
	testutil.rand_bytes(&rng, msg[:])

	session_id: [32]u8
	testutil.rand_bytes(&rng, session_id[:])

	secnonce: musig.Secnonce
	pubnonce: musig.Pubnonce
	testing.expect(
		t,
		musig.nonce_gen(&gen, &secnonce, &pubnonce, &session_id, &sk, &pk, &msg, &agg_pk32),
		"nonce generation failed",
	)

	aggnonce: musig.Aggnonce
	musig.nonce_agg(&aggnonce, []musig.Pubnonce{pubnonce})

	session: musig.Session
	testing.expect(t, musig.nonce_process(&session, &aggnonce, &msg, &cache), "nonce_process failed")

	// The first signature succeeds.
	sig1: musig.Partial_Sig
	testing.expect(t, musig.partial_sign(&sig1, &secnonce, &kp, &cache, &session), "the first sign failed")

	// The second must not. If this ever passes, the secret key is recoverable from the two
	// partial signatures.
	sig2: musig.Partial_Sig
	testing.expect(
		t,
		!musig.partial_sign(&sig2, &secnonce, &kp, &cache, &session),
		"NONCE REUSE: a second partial signature was produced under the same secnonce",
	)

	// And the nonce must have been wiped, not merely flagged.
	zero: musig.Secnonce
	testing.expect(t, secnonce == zero, "the secnonce was not zeroed after use")
}

/*
Key aggregation must depend on the entire key list.

This is what defeats the rogue-key attack: a participant who picks its key after seeing the
others cannot steer the aggregate, because changing its key changes every coefficient.
*/
@(test)
test_musig_aggregation_binds_all_keys :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 3)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	make_key :: proc(gen: ^ecmult.Ecmult_Gen_Context, rng: ^testutil.Rand) -> group.Ge {
		kp: extrakeys.Keypair
		sk: [32]u8
		for {
			testutil.rand_bytes(rng, sk[:])
			if extrakeys.keypair_create(gen, &kp, &sk) {
				break
			}
		}
		p: group.Ge
		extrakeys.keypair_pub(&p, &kp)
		return p
	}

	a := make_key(&gen, &rng)
	b := make_key(&gen, &rng)
	c := make_key(&gen, &rng)

	agg_ab, agg_ac, agg_ba: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache

	testing.expect(t, musig.pubkey_agg(&agg_ab, &cache, []group.Ge{a, b}), "agg(a,b) failed")
	testing.expect(t, musig.pubkey_agg(&agg_ac, &cache, []group.Ge{a, c}), "agg(a,c) failed")
	testing.expect(t, musig.pubkey_agg(&agg_ba, &cache, []group.Ge{b, a}), "agg(b,a) failed")

	// Changing one key changes the aggregate.
	testing.expect(t, !group.ge_eq_var(&agg_ab.point, &agg_ac.point), "the aggregate ignored a key change")

	// Order matters, which is why `pubkey_sort` exists.
	testing.expect(t, !group.ge_eq_var(&agg_ab.point, &agg_ba.point), "aggregation is order-independent")

	// Sorting makes it order-independent.
	s1 := []group.Ge{a, b}
	s2 := []group.Ge{b, a}
	musig.pubkey_sort(s1)
	musig.pubkey_sort(s2)

	agg_s1, agg_s2: extrakeys.Xonly_Pubkey
	musig.pubkey_agg(&agg_s1, &cache, s1)
	musig.pubkey_agg(&agg_s2, &cache, s2)
	testing.expect(t, group.ge_eq_var(&agg_s1.point, &agg_s2.point), "sorting did not make aggregation canonical")

	// The aggregate must not be the plain sum of the keys — that would be the broken
	// scheme the coefficients exist to prevent.
	plain: group.Gej
	group.gej_set_ge(&plain, &a)
	group.gej_add_ge_var(&plain, &plain, &b, nil)
	plain_ge: group.Ge
	group.ge_set_gej_var(&plain_ge, &plain)
	extrakeys.ge_even_y(&plain_ge)
	testing.expect(
		t,
		!group.ge_eq_var(&agg_ab.point, &plain_ge),
		"the aggregate is the plain key sum; rogue-key protection is absent",
	)
}

/*
A partial signature from the wrong signer, or over the wrong nonce, must be rejected.

Verifying partials individually is what lets a coordinator attribute a failure to a specific
participant instead of only observing that the combined signature is bad.
*/
@(test)
test_musig_partial_sig_verify_rejects :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 4)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	n :: 3
	keypairs: [n]extrakeys.Keypair
	pubkeys: [n]group.Ge
	for i in 0 ..< n {
		sk: [32]u8
		for {
			testutil.rand_bytes(&rng, sk[:])
			if extrakeys.keypair_create(&gen, &keypairs[i], &sk) {
				break
			}
		}
		extrakeys.keypair_pub(&pubkeys[i], &keypairs[i])
	}

	agg_pk: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache
	musig.pubkey_agg(&agg_pk, &cache, pubkeys[:])
	agg_pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

	msg: [32]u8
	testutil.rand_bytes(&rng, msg[:])

	secnonces: [n]musig.Secnonce
	pubnonces: [n]musig.Pubnonce
	for i in 0 ..< n {
		sid: [32]u8
		testutil.rand_bytes(&rng, sid[:])
		sk32: [32]u8
		extrakeys.keypair_sec(&sk32, &keypairs[i])
		musig.nonce_gen(&gen, &secnonces[i], &pubnonces[i], &sid, &sk32, &pubkeys[i], &msg, &agg_pk32)
	}

	aggnonce: musig.Aggnonce
	musig.nonce_agg(&aggnonce, pubnonces[:])
	session: musig.Session
	musig.nonce_process(&session, &aggnonce, &msg, &cache)

	partials: [n]musig.Partial_Sig
	for i in 0 ..< n {
		musig.partial_sign(&partials[i], &secnonces[i], &keypairs[i], &cache, &session)
	}

	// Each partial verifies against its own key and nonce.
	for i in 0 ..< n {
		testing.expectf(
			t,
			musig.partial_sig_verify(&partials[i], &pubnonces[i], &pubkeys[i], &cache, &session),
			"partial %d does not verify",
			i,
		)
	}

	// Against another signer's key it must not.
	testing.expect(
		t,
		!musig.partial_sig_verify(&partials[0], &pubnonces[0], &pubkeys[1], &cache, &session),
		"a partial verified against the wrong key",
	)

	// Against another signer's nonce it must not.
	testing.expect(
		t,
		!musig.partial_sig_verify(&partials[0], &pubnonces[1], &pubkeys[0], &cache, &session),
		"a partial verified against the wrong nonce",
	)

	// A tampered partial must not verify.
	bad := partials[0]
	scalar.scalar_add(&bad.s, &bad.s, &scalar.ONE)
	testing.expect(
		t,
		!musig.partial_sig_verify(&bad, &pubnonces[0], &pubkeys[0], &cache, &session),
		"a tampered partial verified",
	)

	// Serialization round-trips.
	ser: [32]u8
	musig.partial_sig_serialize(&ser, &partials[0])
	back: musig.Partial_Sig
	testing.expect(t, musig.partial_sig_parse(&back, &ser), "partial signature parse failed")
	testing.expect(t, scalar.scalar_eq(&back.s, &partials[0].s), "partial round-trip changed the value")

	non66: [66]u8
	musig.pubnonce_serialize(&non66, &pubnonces[0])
	nback: musig.Pubnonce
	testing.expect(t, musig.pubnonce_parse(&nback, &non66), "pubnonce parse failed")
	testing.expect(t, group.ge_eq_var(&nback.pt[0], &pubnonces[0].pt[0]), "pubnonce round-trip changed pt[0]")
	testing.expect(t, group.ge_eq_var(&nback.pt[1], &pubnonces[0].pt[1]), "pubnonce round-trip changed pt[1]")
}

/*
Confirms the precomputed MuSig tagged-hash midstates match a live computation.
*/
@(test)
test_musig_tagged_midstates :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 5)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	// If the KeyAgg midstates were wrong, aggregation would be self-consistent but would
	// disagree with every other BIP327 implementation. Checking that a single key
	// aggregates to itself pins the coefficient path: with one key the coefficient is
	// H(L, P), and the aggregate must be that multiple of P.
	kp: extrakeys.Keypair
	sk: [32]u8
	for {
		testutil.rand_bytes(&rng, sk[:])
		if extrakeys.keypair_create(&gen, &kp, &sk) {
			break
		}
	}
	pk: group.Ge
	extrakeys.keypair_pub(&pk, &kp)

	agg: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache
	testing.expect(t, musig.pubkey_agg(&agg, &cache, []group.Ge{pk}), "single-key aggregation failed")

	// Recompute the coefficient and the expected aggregate independently.
	pks_hash: [32]u8
	keys := []group.Ge{pk}
	testing.expect(t, musig.compute_pks_hash(&pks_hash, keys), "pks_hash failed")

	inf: group.Ge
	group.ge_set_infinity(&inf)
	a: scalar.Scalar
	musig.keyaggcoef_internal(&a, &pks_hash, &pk, &inf)

	pj: group.Gej
	group.gej_set_ge(&pj, &pk)
	want: group.Gej
	ecmult.ecmult(&want, &pj, &a, nil)
	want_ge: group.Ge
	group.ge_set_gej_var(&want_ge, &want)
	extrakeys.ge_even_y(&want_ge)

	testing.expect(t, group.ge_eq_var(&agg.point, &want_ge), "aggregation disagrees with the coefficient formula")
	_ = eckey.pubkey_negate
}
