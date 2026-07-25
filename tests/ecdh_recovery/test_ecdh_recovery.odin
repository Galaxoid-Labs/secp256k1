/*
ECDH and recovery tests, mirroring upstream's `modules/ecdh/tests_impl.h` and
`modules/recovery/tests_impl.h`, plus the extrakeys tests.

The defining property of ECDH is symmetry: both parties must derive the same secret from
opposite halves of the exchange. The defining property of recovery is that the recovered
key is the signing key — checked against a key derived independently, not merely against
one that happens to verify.
*/
package test_ecdh_recovery

import "core:testing"
import "../../ecdh"
import "../../ecdsa"
import "../../ecmult"
import "../../eckey"
import "../../extrakeys"
import "../../field"
import "../../group"
import "../../params"
import "../../recovery"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0xecd4_5ec0_7e11)

@(test)
test_ecdh_is_symmetric :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		a32, b32: [32]u8
		testutil.rand_bytes(&rng, a32[:])
		testutil.rand_bytes(&rng, b32[:])

		a, b: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&a, &a32) || !scalar.scalar_set_b32_seckey(&b, &b32) {
			continue
		}

		pa, pb: group.Ge
		eckey.pubkey_create(&gen, &pa, &a)
		eckey.pubkey_create(&gen, &pb, &b)

		// Alice with Bob's key, and Bob with Alice's, must agree.
		s1, s2: [32]u8
		testing.expectf(t, ecdh.ecdh(s1[:], &pb, &a32), "ecdh failed for a (%d)", i)
		testing.expectf(t, ecdh.ecdh(s2[:], &pa, &b32), "ecdh failed for b (%d)", i)
		testing.expectf(t, s1 == s2, "ECDH is not symmetric (%d)", i)

		// A third party's key must give a different secret.
		c32: [32]u8
		testutil.rand_bytes(&rng, c32[:])
		c: scalar.Scalar
		if scalar.scalar_set_b32_seckey(&c, &c32) {
			pc: group.Ge
			eckey.pubkey_create(&gen, &pc, &c)
			s3: [32]u8
			ecdh.ecdh(s3[:], &pc, &a32)
			testing.expectf(t, s3 != s1, "a different key produced the same secret (%d)", i)
		}
	}
}

@(test)
test_ecdh_rejects_invalid_scalars :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	one: [32]u8
	one[31] = 1
	s: scalar.Scalar
	scalar.scalar_set_b32_seckey(&s, &one)
	p: group.Ge
	eckey.pubkey_create(&gen, &p, &s)

	out: [32]u8

	// Zero is not a valid scalar.
	zero: [32]u8
	testing.expect(t, !ecdh.ecdh(out[:], &p, &zero), "a zero scalar was accepted")

	// n and above are not valid.
	n := [32]u8 {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
		0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
		0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
	}
	testing.expect(t, !ecdh.ecdh(out[:], &p, &n), "n was accepted as a scalar")

	// A custom hash function must be used when supplied.
	custom :: proc "contextless" (output: []u8, x32: ^[32]u8, y32: ^[32]u8, data: rawptr) -> bool {
		for i in 0 ..< len(output) {
			output[i] = 0xab
		}
		return true
	}
	custom_out: [32]u8
	testing.expect(t, ecdh.ecdh(custom_out[:], &p, &one, custom), "the custom hash function failed")
	for i in 0 ..< 32 {
		testing.expect(t, custom_out[i] == 0xab, "the custom hash function was not used")
	}

	// A hash function that fails must fail the exchange.
	failing :: proc "contextless" (output: []u8, x32: ^[32]u8, y32: ^[32]u8, data: rawptr) -> bool {
		return false
	}
	testing.expect(t, !ecdh.ecdh(out[:], &p, &one, failing), "a failing hash function was ignored")
}

@(test)
test_recovery_round_trip :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		seckey, msg: [32]u8
		testutil.rand_bytes(&rng, seckey[:])
		testutil.rand_bytes(&rng, msg[:])

		sec: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&sec, &seckey) {
			continue
		}

		// The key the signature should recover to, derived independently.
		expected: group.Ge
		eckey.pubkey_create(&gen, &expected, &sec)

		rsig: recovery.Recoverable_Signature
		testing.expectf(t, recovery.sign_recoverable(&gen, &rsig, &msg, &seckey), "recoverable signing failed (%d)", i)

		recovered: group.Ge
		testing.expectf(t, recovery.recover(&recovered, &rsig, &msg), "recovery failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&recovered, &expected), "recovered the wrong key (%d)", i)

		// The signature must also verify as an ordinary one.
		plain: ecdsa.Signature
		recovery.signature_convert(&plain, &rsig)
		testing.expectf(t, ecdsa.verify(&plain, &msg, &expected), "the converted signature failed to verify (%d)", i)

		// Compact round-trip.
		compact: [64]u8
		recid: int
		recovery.signature_serialize_compact(&compact, &recid, &rsig)
		testing.expectf(t, recid >= 0 && recid <= 3, "recovery id %d out of range (%d)", recid, i)

		parsed: recovery.Recoverable_Signature
		testing.expectf(t, recovery.signature_parse_compact(&parsed, &compact, recid), "compact parse failed (%d)", i)

		reparsed: group.Ge
		testing.expectf(t, recovery.recover(&reparsed, &parsed, &msg), "recovery after round-trip failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&reparsed, &expected), "round-trip changed the recovered key (%d)", i)

		// A wrong recovery id must recover a different key, or fail outright.
		wrong := rsig
		wrong.recid = (rsig.recid + 1) & 1
		other: group.Ge
		if recovery.recover(&other, &wrong, &msg) {
			testing.expectf(t, !group.ge_eq_var(&other, &expected), "a wrong recid recovered the right key (%d)", i)
		}

		// A tampered message must not recover the signing key.
		bad_msg := msg
		bad_msg[0] ~= 1
		other2: group.Ge
		if recovery.recover(&other2, &rsig, &bad_msg) {
			testing.expectf(t, !group.ge_eq_var(&other2, &expected), "a tampered message recovered the right key (%d)", i)
		}
	}
}

@(test)
test_recovery_rejects_bad_input :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	seckey: [32]u8
	seckey[31] = 7
	msg: [32]u8
	msg[31] = 3

	rsig: recovery.Recoverable_Signature
	testing.expect(t, recovery.sign_recoverable(&gen, &rsig, &msg, &seckey), "signing failed")

	// Out-of-range recovery ids.
	pub: group.Ge
	for bad in ([]int{-1, 4, 100}) {
		r := rsig
		r.recid = bad
		testing.expectf(t, !recovery.recover(&pub, &r, &msg), "recovery id %d was accepted", bad)
	}

	// Zero r or s must fail.
	zr := rsig
	scalar.scalar_set_int(&zr.sig.r, 0)
	testing.expect(t, !recovery.recover(&pub, &zr, &msg), "a zero r was accepted")

	zs := rsig
	scalar.scalar_set_int(&zs.sig.s, 0)
	testing.expect(t, !recovery.recover(&pub, &zs, &msg), "a zero s was accepted")

	// Parsing must reject out-of-range ids.
	compact: [64]u8
	recid: int
	recovery.signature_serialize_compact(&compact, &recid, &rsig)
	parsed: recovery.Recoverable_Signature
	testing.expect(t, !recovery.signature_parse_compact(&parsed, &compact, 4), "parse accepted recid 4")
	testing.expect(t, !recovery.signature_parse_compact(&parsed, &compact, -1), "parse accepted recid -1")
}

@(test)
test_extrakeys_xonly_and_tweaks :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 2)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		seckey: [32]u8
		testutil.rand_bytes(&rng, seckey[:])

		kp: extrakeys.Keypair
		if !extrakeys.keypair_create(&gen, &kp, &seckey) {
			continue
		}

		// The x-only key must have even y by construction.
		xonly: extrakeys.Xonly_Pubkey
		parity: bool
		testing.expectf(t, extrakeys.keypair_xonly_pub(&xonly, &parity, &kp), "keypair_xonly_pub failed (%d)", i)

		y := xonly.point.y
		field.fe_normalize_var(&y)
		testing.expectf(t, !field.fe_is_odd(&y), "the x-only key has odd y (%d)", i)

		// The reported parity must match the full key's actual parity.
		full: group.Ge
		extrakeys.keypair_pub(&full, &kp)
		fy := full.y
		field.fe_normalize_var(&fy)
		testing.expectf(t, parity == field.fe_is_odd(&fy), "the reported parity is wrong (%d)", i)

		// Serialization round-trip.
		pk32: [32]u8
		extrakeys.xonly_pubkey_serialize(&pk32, &xonly)
		reparsed: extrakeys.Xonly_Pubkey
		testing.expectf(t, extrakeys.xonly_pubkey_parse(&reparsed, &pk32), "x-only parse failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&reparsed.point, &xonly.point), "x-only round-trip changed the key (%d)", i)

		// A tweak must be consistent between the keypair and the public-only path.
		tweak: [32]u8
		testutil.rand_bytes(&rng, tweak[:])

		tweaked_pub: group.Ge
		if !extrakeys.xonly_pubkey_tweak_add(&tweaked_pub, &xonly, &tweak) {
			continue
		}

		tweaked_kp := kp
		if !extrakeys.keypair_xonly_tweak_add(&tweaked_kp, &tweak) {
			continue
		}

		// The tweaked keypair's public half must equal the independently tweaked key.
		// This is the Taproot consistency property: get it wrong and the output is
		// unspendable.
		kp_pub: group.Ge
		extrakeys.keypair_pub(&kp_pub, &tweaked_kp)
		testing.expectf(t, group.ge_eq_var(&kp_pub, &tweaked_pub), "keypair and pubkey tweaks disagree (%d)", i)

		// And the tweaked secret must still derive the tweaked public key.
		derived: group.Ge
		testing.expectf(
			t,
			eckey.pubkey_create(&gen, &derived, &tweaked_kp.seckey),
			"deriving from the tweaked secret failed (%d)",
			i,
		)
		testing.expectf(t, group.ge_eq_var(&derived, &kp_pub), "the tweaked secret does not match its public key (%d)", i)

		// The tweak check must accept the true output and reject a wrong parity.
		tw_x: [32]u8
		field.fe_normalize_var(&tweaked_pub.x)
		field.fe_normalize_var(&tweaked_pub.y)
		field.fe_get_b32(&tw_x, &tweaked_pub.x)
		tw_parity := field.fe_is_odd(&tweaked_pub.y)

		testing.expectf(
			t,
			extrakeys.xonly_pubkey_tweak_add_check(&tw_x, tw_parity, &xonly, &tweak),
			"tweak_add_check rejected the true output (%d)",
			i,
		)
		testing.expectf(
			t,
			!extrakeys.xonly_pubkey_tweak_add_check(&tw_x, !tw_parity, &xonly, &tweak),
			"tweak_add_check accepted the wrong parity (%d)",
			i,
		)
	}
}
