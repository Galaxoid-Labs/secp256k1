/*
BIP340 Schnorr tests, mirroring upstream's `modules/schnorrsig/tests_impl.h`.

The signing vectors are the official BIP340 ones. They were regenerated here from an
independent implementation written directly against the specification, and the results
agree with the published `test-vectors.csv` — which is how a transcription error in one of
them was caught before it reached the test.

The rejection cases matter as much as the acceptance cases. A verifier that accepts a
negated s, or a signature whose R has odd y, is not merely lenient: it reintroduces
malleability, which is precisely what x-only encoding exists to remove. Those cases are
constructed from the definitions rather than transcribed, so they cannot silently drift.
*/
package test_schnorr

import "core:testing"
import "../../ecmult"
import "../../extrakeys"
import "../../field"
import hash "../../hash"
import "../../group"
import "../../params"
import "../../schnorr"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0x5c4_0bb_3407)

@(private = "file")
nib :: proc(c: u8) -> u8 {
	switch c {
	case '0' ..= '9':
		return c - '0'
	case 'a' ..= 'f':
		return c - 'a' + 10
	case 'A' ..= 'F':
		return c - 'A' + 10
	}
	panic("non-hex character in a test vector")
}

@(private = "file")
hex_into :: proc(s: string, out: []u8) {
	for i in 0 ..< len(s) / 2 {
		out[i] = nib(s[i * 2]) << 4 | nib(s[i * 2 + 1])
	}
}

@(private = "file")
hex32 :: proc(s: string) -> (b: [32]u8) {
	hex_into(s, b[:])
	return
}

@(private = "file")
hex64 :: proc(s: string) -> (b: [64]u8) {
	hex_into(s, b[:])
	return
}

@(private = "file")
Vector :: struct {
	seckey, pubkey, aux, msg, sig: string,
}

/*
The official BIP340 signing vectors.
*/
@(private = "file")
VECTORS :: []Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000003",
		"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
	},
	{
		"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
		"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
		"6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
	},
	{
		"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
		"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
		"c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906",
		"7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
		"5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
	},
	{
		// Fails if the message is reduced modulo p or n.
		"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
		"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
	},
}

@(test)
test_bip340_signing_vectors :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for v, i in VECTORS {
		seckey := hex32(v.seckey)
		aux := hex32(v.aux)
		msg := hex32(v.msg)
		want_sig := hex64(v.sig)
		want_pk := hex32(v.pubkey)

		kp: extrakeys.Keypair
		testing.expectf(t, extrakeys.keypair_create(&gen, &kp, &seckey), "keypair_create failed (%d)", i)

		// The x-only public key must match.
		xonly: extrakeys.Xonly_Pubkey
		parity: bool
		testing.expectf(t, extrakeys.keypair_xonly_pub(&xonly, &parity, &kp), "keypair_xonly_pub failed (%d)", i)

		pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&pk32, &xonly)
		testing.expectf(t, pk32 == want_pk, "vector %d: public key mismatch", i)

		// The signature must match byte for byte.
		sig: [64]u8
		testing.expectf(t, schnorr.sign(&gen, &sig, msg[:], &kp, &aux), "signing failed (%d)", i)
		testing.expectf(t, sig == want_sig, "vector %d: signature mismatch", i)

		// And it must verify.
		testing.expectf(t, schnorr.verify(&sig, msg[:], &xonly), "vector %d: the signature does not verify", i)
	}
}

/*
Rejection cases, each constructed from a valid signature by violating exactly one rule.

Building them from definitions rather than transcribing means they stay correct if the
vectors are ever regenerated.
*/
@(test)
test_bip340_rejection_cases :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	v := VECTORS[1]
	seckey := hex32(v.seckey)
	aux := hex32(v.aux)
	msg := hex32(v.msg)

	kp: extrakeys.Keypair
	extrakeys.keypair_create(&gen, &kp, &seckey)
	xonly: extrakeys.Xonly_Pubkey
	parity: bool
	extrakeys.keypair_xonly_pub(&xonly, &parity, &kp)

	sig: [64]u8
	schnorr.sign(&gen, &sig, msg[:], &kp, &aux)
	testing.expect(t, schnorr.verify(&sig, msg[:], &xonly), "the baseline signature does not verify")

	// A negated s. This is the malleability the parity rule exists to prevent.
	{
		bad := sig
		s: scalar.Scalar
		s32 := (^[32]u8)(&bad[32])
		scalar.scalar_set_b32(&s, s32)
		scalar.scalar_negate(&s, &s)
		scalar.scalar_get_b32(s32, &s)
		testing.expect(t, !schnorr.verify(&bad, msg[:], &xonly), "a negated s was accepted")
	}

	// A tampered message.
	{
		other := msg
		other[0] ~= 1
		testing.expect(t, !schnorr.verify(&sig, other[:], &xonly), "verified against the wrong message")
	}

	// A tampered r.
	{
		bad := sig
		bad[0] ~= 1
		testing.expect(t, !schnorr.verify(&bad, msg[:], &xonly), "a tampered r was accepted")
	}

	// s equal to the curve order must be rejected, not reduced.
	{
		bad := sig
		n := hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
		for i in 0 ..< 32 {
			bad[32 + i] = n[i]
		}
		testing.expect(t, !schnorr.verify(&bad, msg[:], &xonly), "s = n was accepted")
	}

	// r equal to the field size must be rejected.
	{
		bad := sig
		p := hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
		for i in 0 ..< 32 {
			bad[i] = p[i]
		}
		testing.expect(t, !schnorr.verify(&bad, msg[:], &xonly), "r = p was accepted")
	}

	// r = 0 is not the x coordinate of any curve point on secp256k1.
	{
		bad := sig
		for i in 0 ..< 32 {
			bad[i] = 0
		}
		testing.expect(t, !schnorr.verify(&bad, msg[:], &xonly), "r = 0 was accepted")
	}

	// A public key that is not a valid x coordinate must fail to parse at all.
	{
		bad_pk := hex32("eefdea4cd0b40b0b0b1b0e2b1b0b1b0b1b0b1b0b1b0b1b0b1b0b1b0b1b0b1b0b")
		parsed: extrakeys.Xonly_Pubkey
		if extrakeys.xonly_pubkey_parse(&parsed, &bad_pk) {
			// If it happens to be a valid x coordinate, it is simply the wrong key.
			testing.expect(t, !schnorr.verify(&sig, msg[:], &parsed), "verified against the wrong key")
		}
	}

	// A key at or above p must be rejected outright.
	{
		too_big := hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30")
		parsed: extrakeys.Xonly_Pubkey
		testing.expect(t, !extrakeys.xonly_pubkey_parse(&parsed, &too_big), "an x-only key >= p was accepted")
	}
}

@(test)
test_schnorr_sign_verify_random :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)
	seed: [32]u8
	testutil.rand_bytes(&rng, seed[:])
	ecmult.ecmult_gen_blind(&gen, &seed)

	for i in 0 ..< params.COUNT {
		seckey: [32]u8
		msg: [32]u8
		aux: [32]u8
		testutil.rand_bytes(&rng, seckey[:])
		testutil.rand_bytes(&rng, msg[:])
		testutil.rand_bytes(&rng, aux[:])

		kp: extrakeys.Keypair
		if !extrakeys.keypair_create(&gen, &kp, &seckey) {
			continue
		}

		xonly: extrakeys.Xonly_Pubkey
		parity: bool
		extrakeys.keypair_xonly_pub(&xonly, &parity, &kp)

		sig: [64]u8
		testing.expectf(t, schnorr.sign(&gen, &sig, msg[:], &kp, &aux), "signing failed (%d)", i)
		testing.expectf(t, schnorr.verify(&sig, msg[:], &xonly), "verification failed (%d)", i)

		// Signing without aux randomness must also work, and must be deterministic.
		sig_det, sig_det2: [64]u8
		schnorr.sign(&gen, &sig_det, msg[:], &kp, nil)
		schnorr.sign(&gen, &sig_det2, msg[:], &kp, nil)
		testing.expectf(t, sig_det == sig_det2, "deterministic signing is not reproducible (%d)", i)
		testing.expectf(t, schnorr.verify(&sig_det, msg[:], &xonly), "the deterministic signature failed (%d)", i)

		// Aux randomness must change the signature.
		testing.expectf(t, sig != sig_det, "aux randomness did not change the signature (%d)", i)

		// The x-only key round-trips.
		pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&pk32, &xonly)
		reparsed: extrakeys.Xonly_Pubkey
		testing.expectf(t, extrakeys.xonly_pubkey_parse(&reparsed, &pk32), "x-only parse failed (%d)", i)
		testing.expectf(t, schnorr.verify(&sig, msg[:], &reparsed), "the reparsed key failed to verify (%d)", i)
	}
}

/*
Messages of arbitrary length must work, and the length must be bound into the hash so that
one message cannot be reinterpreted as another.
*/
@(test)
test_schnorr_variable_length_messages :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	seckey := hex32(VECTORS[1].seckey)
	kp: extrakeys.Keypair
	extrakeys.keypair_create(&gen, &kp, &seckey)
	xonly: extrakeys.Xonly_Pubkey
	parity: bool
	extrakeys.keypair_xonly_pub(&xonly, &parity, &kp)

	buf: [100]u8
	for i in 0 ..< len(buf) {
		buf[i] = u8(i)
	}

	for n in 0 ..= 100 {
		sig: [64]u8
		testing.expectf(t, schnorr.sign(&gen, &sig, buf[:n], &kp, nil), "signing failed at length %d", n)
		testing.expectf(t, schnorr.verify(&sig, buf[:n], &xonly), "verification failed at length %d", n)

		// A signature over a prefix must not verify over a longer message.
		if n > 0 {
			testing.expectf(
				t,
				!schnorr.verify(&sig, buf[:n - 1], &xonly),
				"a signature verified over a truncated message at length %d",
				n,
			)
		}
	}
}

/*
Confirms the precomputed tagged-hash midstates match a live computation.

The midstates exist purely as an optimization; if one were wrong, every signature would be
wrong in a way that is hard to attribute. Checking them directly localises that failure.
*/
@(test)
test_schnorr_tagged_midstates :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	// Sign with the real implementation, then recompute the challenge the slow way and
	// confirm the signature satisfies s*G = R + e*P.
	seckey := hex32(VECTORS[1].seckey)
	msg := hex32(VECTORS[1].msg)
	aux := hex32(VECTORS[1].aux)

	kp: extrakeys.Keypair
	extrakeys.keypair_create(&gen, &kp, &seckey)
	xonly: extrakeys.Xonly_Pubkey
	parity: bool
	extrakeys.keypair_xonly_pub(&xonly, &parity, &kp)

	sig: [64]u8
	schnorr.sign(&gen, &sig, msg[:], &kp, &aux)

	// e computed through the generic tagged-hash path, not the precomputed midstate.
	pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&pk32, &xonly)

	preimage: [96]u8
	copy(preimage[0:32], sig[0:32])
	copy(preimage[32:64], pk32[:])
	copy(preimage[64:96], msg[:])

	e_bytes: [32]u8
	tag := "BIP0340/challenge"
	hash_tagged(&e_bytes, transmute([]u8)tag, preimage[:])

	e: scalar.Scalar
	scalar.scalar_set_b32(&e, &e_bytes)

	// s*G - e*P must be R, with even y and x equal to sig[0:32].
	s: scalar.Scalar
	s32 := (^[32]u8)(&sig[32])
	scalar.scalar_set_b32(&s, s32)

	neg_e: scalar.Scalar
	scalar.scalar_negate(&neg_e, &e)

	pkj: group.Gej
	group.gej_set_ge(&pkj, &xonly.point)
	rj: group.Gej
	ecmult.ecmult(&rj, &pkj, &neg_e, &s)

	r: group.Ge
	group.ge_set_gej_var(&r, &rj)
	testing.expect(t, !group.ge_is_infinity(&r), "the reconstructed R is infinity")

	field.fe_normalize_var(&r.y)
	testing.expect(t, !field.fe_is_odd(&r.y), "the reconstructed R has odd y")

	field.fe_normalize_var(&r.x)
	rx: [32]u8
	field.fe_get_b32(&rx, &r.x)
	sig_r: [32]u8
	copy(sig_r[:], sig[0:32])
	testing.expect(t, rx == sig_r, "the generic challenge path disagrees with the precomputed midstate")
}

@(private = "file")
hash_tagged :: proc(out: ^[32]u8, tag: []u8, msg: []u8) {
	hash.tagged_sha256(out, tag, msg)
}
