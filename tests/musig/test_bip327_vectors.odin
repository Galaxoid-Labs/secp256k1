/*
BIP327 MuSig2 vectors — the Phase 7 hard gate, mirroring upstream's
`modules/musig/tests_impl.h`.

`CLAUDE.md` names MuSig2 the highest-risk module here, and until these ran it had the least
external validation of anything in the project: its only evidence was self-consistency (an
aggregated signature verifies as BIP340) plus a differential oracle that did not cover musig
at all. Self-consistency is a weak signal for a multi-party protocol — an implementation can
be wrong in a way that is wrong identically for every participant, and still round-trip
perfectly.

These vectors are external ground truth. The error cases are the important half: they pin
what must be *rejected*, and rejection is exactly what self-consistency testing cannot
check.
*/
package test_musig

import "core:testing"
import "../../extrakeys"
import "../../eckey"
import "../../group"
import "../../ecmult"
import "../../musig"
import "../../scalar"

@(private = "file")
v_nib :: proc(c: u8) -> u8 {
	switch c {
	case '0' ..= '9':
		return c - '0'
	case 'a' ..= 'f':
		return c - 'a' + 10
	case 'A' ..= 'F':
		return c - 'A' + 10
	}
	panic("non-hex character in a BIP327 vector")
}

@(private = "file")
v_hex :: proc(s: string, buf: []u8) -> []u8 {
	n := len(s) / 2
	for i in 0 ..< n {
		buf[i] = v_nib(s[i * 2]) << 4 | v_nib(s[i * 2 + 1])
	}
	return buf[:n]
}

/*
Aggregates the keys named by `indices`, returning false if any fails to parse.

Parsing is part of the operation under test: three of the five error cases are invalid
*encodings* — a point not on the curve, an x coordinate at or above p, an invalid prefix
byte — and rejecting them at parse time is the correct behaviour, not a way of dodging the
test.
*/
@(private = "file")
agg_keys :: proc(
	indices: []int,
	agg_pk: ^extrakeys.Xonly_Pubkey,
	cache: ^musig.Keyagg_Cache,
) -> bool {
	keys: [8]group.Ge
	n := 0
	for idx in indices {
		buf: [33]u8
		raw := v_hex(KEY_AGG_PUBKEYS[idx], buf[:])
		if !eckey.pubkey_parse(&keys[n], raw) {
			return false
		}
		n += 1
	}
	return musig.pubkey_agg(agg_pk, cache, keys[:n])
}

/*
Key aggregation, valid cases.

Includes the two orderings of the same key set, which must give *different* aggregates —
MuSig2 key aggregation is order-dependent by design — and the repeated-key cases, which are
where a naive implementation that deduplicates silently gets a different answer.
*/
@(test)
test_bip327_key_agg_valid :: proc(t: ^testing.T) {
	for c, i in KEY_AGG_VALID {
		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		ok := agg_keys(c.key_indices, &agg_pk, &cache)
		if !testing.expectf(t, ok, "valid case %d: aggregation failed", i) {
			continue
		}

		got: [32]u8
		extrakeys.xonly_pubkey_serialize(&got, &agg_pk)

		exp_buf: [32]u8
		v_hex(c.expected, exp_buf[:])
		testing.expectf(
			t,
			got == exp_buf,
			"valid case %d: aggregate key mismatch\n  got      %x\n  expected %x",
			i,
			got,
			exp_buf,
		)
	}
	testing.expect_value(t, len(KEY_AGG_VALID), 4)
}

/*
Key aggregation, error cases — each must be rejected.

Two shapes. `MUSIG_PUBKEY` cases carry a malformed public key and must fail at parse or
aggregation. `MUSIG_TWEAK` cases aggregate successfully and must then fail when the tweak is
applied, because the tweak is out of range or drives the result to infinity. Conflating the
two would let a bug in one hide behind the other, so each is asserted at the step where it
is supposed to fail.
*/
@(test)
test_bip327_key_agg_error :: proc(t: ^testing.T) {
	n_pubkey_cases, n_tweak_cases := 0, 0

	for c, i in KEY_AGG_ERROR {
		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		agg_ok := agg_keys(c.key_indices, &agg_pk, &cache)

		switch c.error {
		case "MUSIG_PUBKEY":
			n_pubkey_cases += 1
			testing.expectf(
				t,
				!agg_ok,
				"error case %d: aggregated a key set that must be rejected",
				i,
			)

		case "MUSIG_TWEAK":
			n_tweak_cases += 1
			if !testing.expectf(
				t,
				agg_ok,
				"error case %d: keys should aggregate; the tweak is what must fail",
				i,
			) {
				continue
			}

			// Apply the tweaks in order; the case passes when one of them is rejected.
			rejected := false
			for ti, k in c.tweak_indices {
				buf: [32]u8
				tweak := v_hex(KEY_AGG_TWEAKS[ti], buf[:])
				tweak32 := (^[32]u8)(&tweak[0])

				out: group.Ge
				ok := c.is_xonly[k] \
					? musig.pubkey_xonly_tweak_add(&out, &cache, tweak32) \
					: musig.pubkey_ec_tweak_add(&out, &cache, tweak32)
				if !ok {
					rejected = true
					break
				}
			}
			testing.expectf(t, rejected, "error case %d: accepted an invalid tweak", i)

		case:
			testing.expectf(t, false, "error case %d: unknown discriminant %q", i, c.error)
		}
	}

	// Both shapes must actually be exercised; a transcription slip that turned every case
	// into one kind would otherwise still pass.
	testing.expect_value(t, len(KEY_AGG_ERROR), 5)
	testing.expect_value(t, n_pubkey_cases, 3)
	testing.expect_value(t, n_tweak_cases, 2)
}

/*
Nonce aggregation, valid cases.

The second case is the one worth reading: its expected aggregate ends in 33 zero bytes,
which is BIP327's encoding of the point at infinity. An implementation that treats infinity
as an error, or that serializes it as anything else, fails here and nowhere else.
*/
@(test)
test_bip327_nonce_agg_valid :: proc(t: ^testing.T) {
	for c, i in NONCE_AGG_VALID {
		nonces: [4]musig.Pubnonce
		n := 0
		parsed := true
		for idx in c.pnonce_indices {
			buf: [66]u8
			v_hex(NONCE_AGG_PNONCES[idx], buf[:])
			if !musig.pubnonce_parse(&nonces[n], &buf) {
				parsed = false
				break
			}
			n += 1
		}
		if !testing.expectf(t, parsed, "valid nonce case %d: a public nonce failed to parse", i) {
			continue
		}

		agg: musig.Aggnonce
		if !testing.expectf(
			t,
			musig.nonce_agg(&agg, nonces[:n]),
			"valid nonce case %d: aggregation failed",
			i,
		) {
			continue
		}

		got: [66]u8
		musig.aggnonce_serialize(&got, &agg)

		exp_buf: [66]u8
		v_hex(c.expected, exp_buf[:])
		testing.expectf(
			t,
			got == exp_buf,
			"valid nonce case %d: aggregate nonce mismatch\n  got      %x\n  expected %x",
			i,
			got,
			exp_buf,
		)
	}
	testing.expect_value(t, len(NONCE_AGG_VALID), 2)
}

/*
Nonce aggregation, error cases — each carries one malformed public nonce that must be
rejected, and the vector names which one.
*/
@(test)
test_bip327_nonce_agg_error :: proc(t: ^testing.T) {
	for c, i in NONCE_AGG_ERROR {
		nonces: [4]musig.Pubnonce
		n := 0
		failed_at := -1

		for idx, k in c.pnonce_indices {
			buf: [66]u8
			v_hex(NONCE_AGG_PNONCES[idx], buf[:])
			if !musig.pubnonce_parse(&nonces[n], &buf) {
				failed_at = k
				break
			}
			n += 1
		}

		rejected := failed_at >= 0
		if !rejected {
			agg: musig.Aggnonce
			rejected = !musig.nonce_agg(&agg, nonces[:n])
		}

		testing.expectf(
			t,
			rejected,
			"error nonce case %d: accepted a set containing an invalid nonce (index %d)",
			i,
			c.invalid_nonce_idx,
		)

		// When the rejection happens at parse time, it must be the nonce the vector blames.
		// Rejecting the right set for the wrong reason would otherwise pass.
		if failed_at >= 0 {
			testing.expectf(
				t,
				failed_at == c.invalid_nonce_idx,
				"error nonce case %d: rejected nonce %d but the vector blames %d",
				i,
				failed_at,
				c.invalid_nonce_idx,
			)
		}
	}
	testing.expect_value(t, len(NONCE_AGG_ERROR), 3)
}

/*
The BIP327 KeySort vectors, from upstream's `test_sort_vectors` in `tests.c`.

Sorting is consensus-critical for MuSig2 even though it looks like housekeeping: signers who
sort differently derive different aggregate keys and produce signatures that do not combine.
The order is lexicographic over the 33-byte compressed serialization.

The set contains a duplicate — keys 0 and 5 are byte-identical — which is why the expected
order names index 0 twice. That is the case a sort with an unstable or strict comparator
gets wrong.
*/
@(test)
test_bip327_pubkey_sort_vectors :: proc(t: ^testing.T) {
	SORT_KEYS := [6]string{
		"02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
		"02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
		"03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
		"023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66",
		"02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eff",
		"02dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
	}
	// Upstream's `sorted[]`, as indices into SORT_KEYS.
	EXPECTED_ORDER := [6]int{3, 0, 0, 4, 1, 2}

	keys: [6]group.Ge
	for s, i in SORT_KEYS {
		buf: [33]u8
		raw := v_hex(s, buf[:])
		if !testing.expectf(t, eckey.pubkey_parse(&keys[i], raw), "sort key %d failed to parse", i) {
			return
		}
	}

	musig.pubkey_sort(keys[:])

	// Compare serializations rather than points: that is the order the sort is defined on,
	// and it is what two signers would actually exchange.
	for want_idx, i in EXPECTED_ORDER {
		got: [33]u8
		eckey.pubkey_serialize33(&keys[i], &got)

		exp_buf: [33]u8
		v_hex(SORT_KEYS[want_idx], exp_buf[:])

		testing.expectf(
			t,
			got == exp_buf,
			"sorted position %d: got %x, expected key %d (%x)",
			i,
			got,
			want_idx,
			exp_buf,
		)
	}
}

/*
Nonce generation — the highest-risk code in the project, pinned against BIP327.

`CLAUDE.md` singles this out: "MuSig2 signing is the last to graduate and its nonce handling
is the highest-risk code here." Nonce derivation is where MuSig2 fails catastrophically
rather than gracefully — two signers deriving the same nonce, or a nonce that is a
predictable function of the message, leaks the secret key outright.

These two vectors fix the derivation exactly, including how *absent* optional inputs are
encoded. That last part matters more than it looks: if an omitted message and a
32-byte-zero message hashed to the same thing, an attacker who could choose between them
would get two signatures under one nonce. The presence-byte framing is what prevents it, and
case 2 — which omits the secret key, aggregate key, message and extra input all at once — is
what tests it.

The secnonce is compared in its 97-byte BIP327 form, k1 || k2 || pk, assembled here because
this implementation has no secnonce serializer: a secret nonce has no business being
serialized outside a test.
*/
@(test)
test_bip327_nonce_gen :: proc(t: ^testing.T) {
	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	for c, i in NONCE_GEN {
		rand_buf: [32]u8
		v_hex(c.rand, rand_buf[:])

		pk_buf: [33]u8
		v_hex(c.pk, pk_buf[:])
		pubkey: group.Ge
		if !testing.expectf(t, eckey.pubkey_parse(&pubkey, pk_buf[:]), "case %d: pk parse", i) {
			continue
		}

		// Optional inputs: an empty string in the vector means the field is absent, which is
		// a different derivation from supplying zeros.
		sk_buf, aggpk_buf, msg_buf, extra_buf: [32]u8
		sk_ptr, aggpk_ptr, msg_ptr, extra_ptr: ^[32]u8

		if len(c.sk) > 0 {
			v_hex(c.sk, sk_buf[:]);       sk_ptr = &sk_buf
		}
		if len(c.aggpk) > 0 {
			v_hex(c.aggpk, aggpk_buf[:]); aggpk_ptr = &aggpk_buf
		}
		if len(c.msg) > 0 {
			v_hex(c.msg, msg_buf[:]);     msg_ptr = &msg_buf
		}
		if len(c.extra_in) > 0 {
			v_hex(c.extra_in, extra_buf[:]); extra_ptr = &extra_buf
		}

		secnonce: musig.Secnonce
		pubnonce: musig.Pubnonce
		ok := musig.nonce_gen(
			&gen,
			&secnonce,
			&pubnonce,
			&rand_buf,
			sk_ptr,
			&pubkey,
			msg_ptr,
			aggpk_ptr,
			extra_ptr,
		)
		if !testing.expectf(t, ok, "case %d: nonce_gen failed", i) {
			continue
		}

		// Assemble the 97-byte secnonce: k1 || k2 || compressed pk.
		got_sec: [97]u8
		k0 := (^[32]u8)(&got_sec[0])
		k1 := (^[32]u8)(&got_sec[32])
		scalar.scalar_get_b32(k0, &secnonce.k[0])
		scalar.scalar_get_b32(k1, &secnonce.k[1])
		sec_pk := (^[33]u8)(&got_sec[64])
		eckey.pubkey_serialize33(&secnonce.pk, sec_pk)

		exp_sec: [97]u8
		v_hex(c.expected_secnonce, exp_sec[:])
		testing.expectf(
			t,
			got_sec == exp_sec,
			"case %d: secnonce mismatch\n  got      %x\n  expected %x",
			i,
			got_sec,
			exp_sec,
		)

		got_pub: [66]u8
		musig.pubnonce_serialize(&got_pub, &pubnonce)

		exp_pub: [66]u8
		v_hex(c.expected_pubnonce, exp_pub[:])
		testing.expectf(
			t,
			got_pub == exp_pub,
			"case %d: pubnonce mismatch\n  got      %x\n  expected %x",
			i,
			got_pub,
			exp_pub,
		)
	}
	testing.expect_value(t, len(NONCE_GEN), 2)
}

/*
Signature aggregation, from BIP327's `sig_agg` vectors.

This is the last MuSig2 surface without external validation, and the one that produces the
bytes that actually go on chain. It also exercises the tweak machinery in anger: three of
the four valid cases apply chains of x-only and plain EC tweaks, in mixed order, and the
tweak accumulator (`tacc`) has to track them all to reach the right aggregate signature.

The error case supplies a partial signature that is not a valid scalar, which must be
rejected at parse time rather than folded into a sum.

Each case is driven from the vector's own aggregate nonce, so this tests aggregation
independently of nonce generation — a bug in one cannot mask a bug in the other.
*/
@(test)
test_bip327_sig_agg :: proc(t: ^testing.T) {
	for c, ci in SIG_AGG_VALID {
		keys: [4]group.Ge
		n := 0
		ok := true
		for idx in c.key_indices {
			buf: [33]u8
			raw := v_hex(SIG_AGG_PUBKEYS[idx], buf[:])
			if !eckey.pubkey_parse(&keys[n], raw) {
				ok = false
				break
			}
			n += 1
		}
		if !testing.expectf(t, ok, "sig_agg valid %d: a public key failed to parse", ci) {
			continue
		}

		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		if !testing.expectf(
			t,
			musig.pubkey_agg(&agg_pk, &cache, keys[:n]),
			"sig_agg valid %d: aggregation failed",
			ci,
		) {
			continue
		}

		// Apply the tweak chain in order; each updates the cache in place.
		tweaked := true
		for ti, k in c.tweak_indices {
			tbuf: [32]u8
			v_hex(SIG_AGG_TWEAKS[ti], tbuf[:])
			out: group.Ge
			applied := c.is_xonly[k] \
				? musig.pubkey_xonly_tweak_add(&out, &cache, &tbuf) \
				: musig.pubkey_ec_tweak_add(&out, &cache, &tbuf)
			if !applied {
				tweaked = false
				break
			}
		}
		if !testing.expectf(t, tweaked, "sig_agg valid %d: a tweak was rejected", ci) {
			continue
		}

		abuf: [66]u8
		v_hex(c.aggnonce, abuf[:])
		aggnonce: musig.Aggnonce
		if !testing.expectf(
			t,
			musig.aggnonce_parse(&aggnonce, &abuf),
			"sig_agg valid %d: aggnonce failed to parse",
			ci,
		) {
			continue
		}

		msg: [32]u8
		v_hex(SIG_AGG_MSG, msg[:])

		session: musig.Session
		if !testing.expectf(
			t,
			musig.nonce_process(&session, &aggnonce, &msg, &cache),
			"sig_agg valid %d: nonce_process failed",
			ci,
		) {
			continue
		}

		psigs: [4]musig.Partial_Sig
		pn := 0
		parsed := true
		for pi in c.psig_indices {
			pbuf: [32]u8
			v_hex(SIG_AGG_PSIGS[pi], pbuf[:])
			if !musig.partial_sig_parse(&psigs[pn], &pbuf) {
				parsed = false
				break
			}
			pn += 1
		}
		if !testing.expectf(t, parsed, "sig_agg valid %d: a partial signature failed to parse", ci) {
			continue
		}

		got: [64]u8
		if !testing.expectf(
			t,
			musig.partial_sig_agg(&got, &session, psigs[:pn]),
			"sig_agg valid %d: aggregation failed",
			ci,
		) {
			continue
		}

		exp: [64]u8
		v_hex(c.expected, exp[:])
		testing.expectf(
			t,
			got == exp,
			"sig_agg valid %d: signature mismatch\n  got      %x\n  expected %x",
			ci,
			got,
			exp,
		)
	}

	testing.expect_value(t, len(SIG_AGG_VALID), 4)
}

/*
Signature aggregation, error case: one partial signature is not a valid scalar and must be
rejected rather than reduced or summed in.
*/
@(test)
test_bip327_sig_agg_error :: proc(t: ^testing.T) {
	for c, ci in SIG_AGG_ERROR {
		rejected := false
		for pi, k in c.psig_indices {
			pbuf: [32]u8
			v_hex(SIG_AGG_PSIGS[pi], pbuf[:])
			sig: musig.Partial_Sig
			if !musig.partial_sig_parse(&sig, &pbuf) {
				rejected = true
				testing.expectf(
					t,
					k == c.invalid_sig_idx,
					"sig_agg error %d: rejected partial signature %d but the vector blames %d",
					ci,
					k,
					c.invalid_sig_idx,
				)
				break
			}
		}
		testing.expectf(t, rejected, "sig_agg error %d: accepted an invalid partial signature", ci)
	}
	testing.expect_value(t, len(SIG_AGG_ERROR), 1)
}

/*
Builds a `Secnonce` from BIP327's 97-byte serialization, k1 || k2 || pk.

There is no public parser for this and there should not be — a secret nonce has no business
crossing a serialization boundary outside a test. The vectors supply them in that form, so
the struct is assembled directly here.
*/
@(private = "file")
secnonce_from_bytes :: proc(out: ^musig.Secnonce, raw: []u8) -> bool {
	if len(raw) != 97 {
		return false
	}
	k0 := (^[32]u8)(&raw[0])
	k1 := (^[32]u8)(&raw[32])
	scalar.scalar_set_b32(&out.k[0], k0)
	scalar.scalar_set_b32(&out.k[1], k1)
	if !eckey.pubkey_parse(&out.pk, raw[64:97]) {
		return false
	}
	out.valid = true
	return true
}

/*
Aggregates the named keys from a table of hex serializations.
*/
@(private = "file")
agg_from :: proc(
	table: []string,
	indices: []int,
	agg_pk: ^extrakeys.Xonly_Pubkey,
	cache: ^musig.Keyagg_Cache,
) -> bool {
	keys: [8]group.Ge
	n := 0
	for idx in indices {
		buf: [33]u8
		raw := v_hex(table[idx], buf[:])
		if !eckey.pubkey_parse(&keys[n], raw) {
			return false
		}
		n += 1
	}
	return musig.pubkey_agg(agg_pk, cache, keys[:n])
}

/*
BIP327 sign/verify vectors: one signer's partial signature inside a full session.

This is the group that pins `partial_sign` itself against external ground truth. Everything
feeding it — key aggregation, nonce aggregation, the binding coefficient, the challenge — is
fixed by the vector, so a mismatch localises to the signing step rather than to the setup.
*/
@(test)
test_bip327_sign_verify :: proc(t: ^testing.T) {
	sk_buf: [32]u8
	v_hex(SV_SK, sk_buf[:])

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	kp: extrakeys.Keypair
	if !testing.expect(t, extrakeys.keypair_create(&gen, &kp, &sk_buf), "sign_verify: keypair") {
		return
	}

	for c, ci in SV_VALID {
		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		if !testing.expectf(
			t,
			agg_from(SV_PUBKEYS[:], c.key_indices, &agg_pk, &cache),
			"sv valid %d: aggregation failed",
			ci,
		) {
			continue
		}

		abuf: [66]u8
		v_hex(SV_AGGNONCES[c.aggnonce_index], abuf[:])
		aggnonce: musig.Aggnonce
		if !testing.expectf(t, musig.aggnonce_parse(&aggnonce, &abuf), "sv valid %d: aggnonce", ci) {
			continue
		}

		msg: [32]u8
		v_hex(SV_MSGS[c.msg_index], msg[:])

		session: musig.Session
		if !testing.expectf(
			t,
			musig.nonce_process(&session, &aggnonce, &msg, &cache),
			"sv valid %d: nonce_process",
			ci,
		) {
			continue
		}

		// The signer's secnonce is the first of the vector's, matching upstream's use.
		sn_buf: [97]u8
		v_hex(SV_SECNONCES[0], sn_buf[:])
		secnonce: musig.Secnonce
		if !testing.expectf(
			t,
			secnonce_from_bytes(&secnonce, sn_buf[:]),
			"sv valid %d: secnonce parse",
			ci,
		) {
			continue
		}

		psig: musig.Partial_Sig
		if !testing.expectf(
			t,
			musig.partial_sign(&psig, &secnonce, &kp, &cache, &session),
			"sv valid %d: partial_sign failed",
			ci,
		) {
			continue
		}

		got: [32]u8
		musig.partial_sig_serialize(&got, &psig)

		exp: [32]u8
		v_hex(c.expected, exp[:])
		testing.expectf(
			t,
			got == exp,
			"sv valid %d: partial signature mismatch\n  got      %x\n  expected %x",
			ci,
			got,
			exp,
		)
	}

	testing.expect_value(t, len(SV_VALID), 4)
}

/*
BIP327 sign error cases — each must be rejected somewhere on the path.

The vector names *which* component is bad (a public key, the aggregate nonce, the secret
nonce), and rejection is accepted at whichever step owns that component: a malformed public
key should fail aggregation, a malformed aggnonce should fail parsing, an invalidated
secnonce should fail signing. What is asserted is that the case does not produce a
signature.
*/
@(test)
test_bip327_sign_error :: proc(t: ^testing.T) {
	sk_buf: [32]u8
	v_hex(SV_SK, sk_buf[:])

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	kp: extrakeys.Keypair
	if !testing.expect(t, extrakeys.keypair_create(&gen, &kp, &sk_buf), "sign_error: keypair") {
		return
	}

	for c, ci in SV_SIGN_ERROR {
		// Case 0 aggregates a key set that does not contain the signer's own key. Upstream
		// skips it verbatim — "the implementation does not error out when the signing key
		// does not belong to any pubkey" — so demanding a rejection here would be inventing
		// a requirement the reference does not meet. Skipped for the same reason, not
		// because it fails.
		if ci == 0 {
			continue
		}

		produced := false

		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		if agg_from(SV_PUBKEYS[:], c.key_indices, &agg_pk, &cache) {
			abuf: [66]u8
			v_hex(SV_AGGNONCES[c.aggnonce_index], abuf[:])
			aggnonce: musig.Aggnonce
			if musig.aggnonce_parse(&aggnonce, &abuf) {
				msg: [32]u8
				v_hex(SV_MSGS[c.msg_index], msg[:])

				session: musig.Session
				if musig.nonce_process(&session, &aggnonce, &msg, &cache) {
					sn_buf: [97]u8
					v_hex(SV_SECNONCES[c.secnonce_index], sn_buf[:])
					secnonce: musig.Secnonce
					if secnonce_from_bytes(&secnonce, sn_buf[:]) {
						psig: musig.Partial_Sig
						produced = musig.partial_sign(&psig, &secnonce, &kp, &cache, &session)
					}
				}
			}
		}

		testing.expectf(
			t,
			!produced,
			"sign error %d (%s): produced a signature that must be rejected",
			ci,
			c.error,
		)
	}

	testing.expect_value(t, len(SV_SIGN_ERROR), 6)
}

/*
BIP327 tweak vectors: signing under a tweaked aggregate key.

Five valid cases apply chains of x-only and plain EC tweaks in mixed order before signing,
which exercises the tweak accumulator *and* the parity flag together — a signer that tracks
one but not the other produces a partial signature that will not aggregate. The error case
uses an out-of-range tweak, which must be rejected.
*/
@(test)
test_bip327_tweak :: proc(t: ^testing.T) {
	sk_buf: [32]u8
	v_hex(TW_SK, sk_buf[:])

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	kp: extrakeys.Keypair
	if !testing.expect(t, extrakeys.keypair_create(&gen, &kp, &sk_buf), "tweak: keypair") {
		return
	}

	msg: [32]u8
	v_hex(TW_MSG, msg[:])

	sn_buf: [97]u8
	v_hex(TW_SECNONCE, sn_buf[:])

	abuf: [66]u8
	v_hex(TW_AGGNONCE, abuf[:])

	run :: proc(
		t: ^testing.T,
		c: Tweak_Case,
		kp: ^extrakeys.Keypair,
		msg: ^[32]u8,
		sn_buf: ^[97]u8,
		abuf: ^[66]u8,
		label: string,
		ci: int,
	) -> (
		got: [32]u8,
		ok: bool,
	) {
		agg_pk: extrakeys.Xonly_Pubkey
		cache: musig.Keyagg_Cache
		if !agg_from(TW_PUBKEYS[:], c.key_indices, &agg_pk, &cache) {
			return got, false
		}

		for ti, k in c.tweak_indices {
			tbuf: [32]u8
			v_hex(TW_TWEAKS[ti], tbuf[:])
			out: group.Ge
			applied := c.is_xonly[k] \
				? musig.pubkey_xonly_tweak_add(&out, &cache, &tbuf) \
				: musig.pubkey_ec_tweak_add(&out, &cache, &tbuf)
			if !applied {
				return got, false
			}
		}

		aggnonce: musig.Aggnonce
		if !musig.aggnonce_parse(&aggnonce, abuf) {
			return got, false
		}

		session: musig.Session
		if !musig.nonce_process(&session, &aggnonce, msg, &cache) {
			return got, false
		}

		secnonce: musig.Secnonce
		if !secnonce_from_bytes(&secnonce, sn_buf[:]) {
			return got, false
		}

		psig: musig.Partial_Sig
		if !musig.partial_sign(&psig, &secnonce, kp, &cache, &session) {
			return got, false
		}

		musig.partial_sig_serialize(&got, &psig)
		return got, true
	}

	for c, ci in TW_VALID {
		got, ok := run(t, c, &kp, &msg, &sn_buf, &abuf, "valid", ci)
		if !testing.expectf(t, ok, "tweak valid %d: signing failed", ci) {
			continue
		}
		exp: [32]u8
		v_hex(c.expected, exp[:])
		testing.expectf(
			t,
			got == exp,
			"tweak valid %d: partial signature mismatch\n  got      %x\n  expected %x",
			ci,
			got,
			exp,
		)
	}

	for c, ci in TW_ERROR {
		_, ok := run(t, c, &kp, &msg, &sn_buf, &abuf, "error", ci)
		testing.expectf(t, !ok, "tweak error %d: accepted an invalid tweak", ci)
	}

	testing.expect_value(t, len(TW_VALID), 5)
	testing.expect_value(t, len(TW_ERROR), 1)
}
