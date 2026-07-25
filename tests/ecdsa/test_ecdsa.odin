/*
ECDSA tests, mirroring upstream's `run_ecdsa_sign_verify`, `run_ecdsa_end_to_end`,
`run_ecdsa_der_parse` and `run_ecdsa_edge_cases`, plus `run_ec_pubkey_parse_test` and the
eckey tests.

The signing vectors were produced by an independent reference implementation of RFC6979 and
ECDSA written against the raw curve equations — not by this code and not by libsecp256k1 —
so they pin the deterministic nonce derivation, the signature values themselves, and the
low-S normalization all at once.
*/
package test_ecdsa

import "core:testing"
import "../../ecdsa"
import "../../ecmult"
import "../../eckey"
import "../../group"
import "../../params"
import "../../scalar"
import "../../testutil"

TEST_SEED :: #config(TEST_SEED, 0xecd5a_5eed_1234)

@(private = "file")
hexbytes :: proc(t: ^testing.T, s: string, out: []u8) -> []u8 {
	testing.expect_value(t, len(s) % 2, 0)
	n := len(s) / 2
	for i in 0 ..< n {
		out[i] = nib(s[i * 2]) << 4 | nib(s[i * 2 + 1])
	}
	return out[:n]
}

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
hex32 :: proc(t: ^testing.T, s: string) -> [32]u8 {
	b: [32]u8
	hexbytes(t, s, b[:])
	return b
}

/*
Signing vectors computed by an independent reference: (seckey, msg) -> (r, s, compressed
pubkey), with the RFC6979 nonce and low-S normalization applied.
*/
@(private = "file")
Sign_Vector :: struct {
	seckey, msg, r, s, pubkey: string,
}

@(private = "file")
SIGN_VECTORS :: []Sign_Vector {
	{
		"0000000000000000000000000000000000000000000000000000000000000001",
		"0000000000000000000000000000000000000000000000000000000000000001",
		"6673ffad2147741f04772b6f921f0ba6af0c1e77fc439e65c36dedf4092e8898",
		"4c1a971652e0ada880120ef8025e709fff2080c4a39aae068d12eed009b68c89",
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	},
	{
		"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		"deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe",
		"88c23441c631232815845188a5e82438aa108ae00c652f6e13def96266b8b3d8",
		"3ba6c317d5fc27d0967972b9c8aa1c0f279c4dd2aeb3d2686d891539d43e66ab",
		"02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d",
	},
	{
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
		"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"8dfc4d53a6beebeb7f0fb42c0acdf28256ffbe81328514d17d39f29a0f08ce4e",
		"6da415376ac7fe6e39f36bb5f1105d5aa07ee6c998da7f3f0e4598df53d37e31",
		"0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
	},
}

/*
Pins the deterministic signing path against independently computed values.

Because RFC6979 makes signing a pure function, these are exact-match vectors rather than
verify-only checks: any change to the nonce derivation, the signing algebra, or the low-S
rule breaks them.
*/
@(test)
test_ecdsa_known_answer_vectors :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for v, i in SIGN_VECTORS {
		seckey := hex32(t, v.seckey)
		msg := hex32(t, v.msg)

		sig: ecdsa.Signature
		testing.expectf(t, ecdsa.sign(&gen, &sig, &msg, &seckey), "signing failed on vector %d", i)

		got: [64]u8
		ecdsa.signature_serialize_compact(&got, &sig)

		want_r := hex32(t, v.r)
		want_s := hex32(t, v.s)
		gr := ([^]u8)(&got[0])[:32]
		gs := ([^]u8)(&got[32])[:32]

		testing.expectf(t, slice_eq(gr, want_r[:]), "vector %d: r mismatch", i)
		testing.expectf(t, slice_eq(gs, want_s[:]), "vector %d: s mismatch", i)

		// Signing must be reproducible; that is the whole point of RFC6979.
		sig2: ecdsa.Signature
		ecdsa.sign(&gen, &sig2, &msg, &seckey)
		testing.expectf(t, scalar.scalar_eq(&sig.r, &sig2.r), "vector %d: signing is not deterministic", i)
		testing.expectf(t, scalar.scalar_eq(&sig.s, &sig2.s), "vector %d: signing is not deterministic", i)

		// The derived public key must match, and the signature must verify against it.
		sec: scalar.Scalar
		testing.expect(t, scalar.scalar_set_b32_seckey(&sec, &seckey), "the vector's seckey was rejected")

		pub: group.Ge
		testing.expect(t, eckey.pubkey_create(&gen, &pub, &sec), "public key derivation failed")

		pub33: [33]u8
		eckey.pubkey_serialize33(&pub, &pub33)
		wantpub: [33]u8
		hexbytes(t, v.pubkey, wantpub[:])
		testing.expectf(t, pub33 == wantpub, "vector %d: public key mismatch", i)

		testing.expectf(t, ecdsa.verify(&sig, &msg, &pub), "vector %d: the signature does not verify", i)

		// s must be in the low half.
		testing.expectf(t, !scalar.scalar_is_high(&sig.s), "vector %d: s is not low", i)
	}
}

@(private = "file")
slice_eq :: proc(a, b: []u8) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

@(test)
test_run_ecdsa_sign_verify :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for i in 0 ..< params.COUNT {
		seckey: [32]u8
		msg: [32]u8
		testutil.rand_bytes(&rng, seckey[:])
		testutil.rand_bytes(&rng, msg[:])

		sec: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&sec, &seckey) {
			continue
		}

		pub: group.Ge
		testing.expect(t, eckey.pubkey_create(&gen, &pub, &sec), "pubkey_create failed")

		sig: ecdsa.Signature
		testing.expectf(t, ecdsa.sign(&gen, &sig, &msg, &seckey), "signing failed (%d)", i)
		testing.expectf(t, ecdsa.verify(&sig, &msg, &pub), "the signature does not verify (%d)", i)

		// A different message must not verify.
		other := msg
		other[0] ~= 1
		testing.expectf(t, !ecdsa.verify(&sig, &other, &pub), "verified against the wrong message (%d)", i)

		// A different key must not verify.
		negpub := pub
		eckey.pubkey_negate(&negpub)
		testing.expectf(t, !ecdsa.verify(&sig, &msg, &negpub), "verified against the wrong key (%d)", i)

		// A tampered signature must not verify.
		bad := sig
		scalar.scalar_add(&bad.r, &bad.r, &scalar.ONE)
		testing.expectf(t, !ecdsa.verify(&bad, &msg, &pub), "verified a tampered r (%d)", i)

		bad2 := sig
		scalar.scalar_add(&bad2.s, &bad2.s, &scalar.ONE)
		testing.expectf(t, !ecdsa.verify(&bad2, &msg, &pub), "verified a tampered s (%d)", i)

		// The high-S form must be rejected, and normalizing it must restore acceptance.
		// This is the malleability rule.
		high: ecdsa.Signature
		high.r = sig.r
		scalar.scalar_negate(&high.s, &sig.s)
		testing.expectf(t, !ecdsa.verify(&high, &msg, &pub), "a high-S signature was accepted (%d)", i)

		normalized: ecdsa.Signature
		changed := ecdsa.signature_normalize(&normalized, &high)
		testing.expectf(t, changed, "normalize did not report a change (%d)", i)
		testing.expectf(t, ecdsa.verify(&normalized, &msg, &pub), "normalized signature failed (%d)", i)
		testing.expectf(t, scalar.scalar_eq(&normalized.s, &sig.s), "normalize did not restore s (%d)", i)

		// Normalizing an already-low signature must be a no-op.
		again: ecdsa.Signature
		testing.expectf(t, !ecdsa.signature_normalize(&again, &sig), "normalize changed a low-S signature (%d)", i)
	}
}

@(test)
test_run_ecdsa_end_to_end :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 1)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)
	seed: [32]u8
	testutil.rand_bytes(&rng, seed[:])
	ecmult.ecmult_gen_blind(&gen, &seed)

	for i in 0 ..< params.COUNT {
		seckey: [32]u8
		msg: [32]u8
		testutil.rand_bytes(&rng, seckey[:])
		testutil.rand_bytes(&rng, msg[:])

		sec: scalar.Scalar
		if !scalar.scalar_set_b32_seckey(&sec, &seckey) {
			continue
		}

		pub: group.Ge
		eckey.pubkey_create(&gen, &pub, &sec)

		sig: ecdsa.Signature
		testing.expect(t, ecdsa.sign(&gen, &sig, &msg, &seckey), "signing failed")

		// Round-trip through both serializations.
		compact: [64]u8
		ecdsa.signature_serialize_compact(&compact, &sig)
		from_compact: ecdsa.Signature
		testing.expectf(t, ecdsa.signature_parse_compact(&from_compact, &compact), "compact parse failed (%d)", i)
		testing.expectf(
			t,
			scalar.scalar_eq(&from_compact.r, &sig.r) && scalar.scalar_eq(&from_compact.s, &sig.s),
			"compact round-trip changed the signature (%d)",
			i,
		)

		der: [80]u8
		dlen := ecdsa.signature_serialize_der(der[:], &sig)
		testing.expectf(t, dlen > 0 && dlen <= 72, "DER serialization produced %d bytes (%d)", dlen, i)

		from_der: ecdsa.Signature
		testing.expectf(t, ecdsa.signature_parse_der(&from_der, der[:dlen]), "DER parse failed (%d)", i)
		testing.expectf(
			t,
			scalar.scalar_eq(&from_der.r, &sig.r) && scalar.scalar_eq(&from_der.s, &sig.s),
			"DER round-trip changed the signature (%d)",
			i,
		)
		testing.expectf(t, ecdsa.verify(&from_der, &msg, &pub), "the DER-parsed signature failed to verify (%d)", i)

		// Public key round-trip, both encodings.
		p33: [33]u8
		eckey.pubkey_serialize33(&pub, &p33)
		parsed: group.Ge
		testing.expectf(t, eckey.pubkey_parse(&parsed, p33[:]), "compressed pubkey parse failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&parsed, &pub), "compressed round-trip changed the key (%d)", i)

		p65: [65]u8
		eckey.pubkey_serialize65(&pub, &p65)
		parsed65: group.Ge
		testing.expectf(t, eckey.pubkey_parse(&parsed65, p65[:]), "uncompressed pubkey parse failed (%d)", i)
		testing.expectf(t, group.ge_eq_var(&parsed65, &pub), "uncompressed round-trip changed the key (%d)", i)
	}
}

@(test)
test_run_ecdsa_edge_cases :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	msg := hex32(t, "0000000000000000000000000000000000000000000000000000000000000001")

	// A zero secret key must be rejected.
	zero: [32]u8
	sig: ecdsa.Signature
	testing.expect(t, !ecdsa.sign(&gen, &sig, &msg, &zero), "a zero secret key was accepted")

	// n and above must be rejected.
	n_bytes := hex32(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	testing.expect(t, !ecdsa.sign(&gen, &sig, &msg, &n_bytes), "n was accepted as a secret key")

	all_ff: [32]u8
	for i in 0 ..< 32 {
		all_ff[i] = 0xff
	}
	testing.expect(t, !ecdsa.sign(&gen, &sig, &msg, &all_ff), "2^256-1 was accepted as a secret key")

	// n-1 is the largest valid key.
	max_key := hex32(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")
	testing.expect(t, ecdsa.sign(&gen, &sig, &msg, &max_key), "n-1 was rejected as a secret key")

	// A signature with zero r or s must never verify.
	sec: scalar.Scalar
	scalar.scalar_set_b32_seckey(&sec, &max_key)
	pub: group.Ge
	eckey.pubkey_create(&gen, &pub, &sec)

	zero_r := sig
	scalar.scalar_set_int(&zero_r.r, 0)
	testing.expect(t, !ecdsa.verify(&zero_r, &msg, &pub), "a zero r verified")

	zero_s := sig
	scalar.scalar_set_int(&zero_s.s, 0)
	testing.expect(t, !ecdsa.verify(&zero_s, &msg, &pub), "a zero s verified")

	// Compact parsing must reject out-of-range halves.
	bad: [64]u8
	for i in 0 ..< 32 {
		bad[i] = n_bytes[i]
	}
	bad[32 + 31] = 1
	parsed: ecdsa.Signature
	testing.expect(t, !ecdsa.signature_parse_compact(&parsed, &bad), "compact parse accepted r = n")

	// Extra entropy must change the signature while keeping it valid.
	extra: [32]u8
	extra[0] = 1
	sig_extra: ecdsa.Signature
	testing.expect(t, ecdsa.sign(&gen, &sig_extra, &msg, &max_key, &extra), "signing with extra entropy failed")
	testing.expect(
		t,
		!scalar.scalar_eq(&sig_extra.r, &sig.r) || !scalar.scalar_eq(&sig_extra.s, &sig.s),
		"extra entropy did not change the signature",
	)
	testing.expect(t, ecdsa.verify(&sig_extra, &msg, &pub), "the extra-entropy signature does not verify")
}
