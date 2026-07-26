/*
Wycheproof ECDH — the Phase 6 companion gate to the ECDSA corpus.

752 cases. Unlike the ECDSA corpus these are mostly *valid*, and what they pin is the
arithmetic: the shared x coordinate for a given (private, public) pair, over a wide spread
of edge-case points including small-order-looking values, points near the field boundary,
and keys with unusual encodings.

Two things about this corpus need stating plainly, because both limit what a pass means.

**The public keys are X.509 SubjectPublicKeyInfo, not bare points.** This library does not
parse X.509 and should not — that is a certificate concern, not a curve concern. So the
wrapper is matched against the one header that means "uncompressed secp256k1 named-curve
point" and the point is taken from behind it; see `SPKI_HEADER` for why matching it exactly
is what makes the invalid cases meaningful.

That costs nothing in coverage: **all 473 valid cases carry that exact header**, so every
one of them is executed and its shared secret compared. Of the 49 invalid cases, 18 also
carry it — those are the ones testing the point and the private key themselves — and the
other 31 are rejected on the header. The counts are asserted below so a regression cannot
quietly shrink the corpus.

**"acceptable" is a third verdict.** Upstream marks inputs a conforming implementation may
either accept or reject — non-canonical encodings, mostly. Those are executed for crash
resistance but their verdict is not asserted, because asserting either way would be
inventing a requirement the corpus explicitly declines to make.

The default ECDH hash is SHA256 over the compressed point, but Wycheproof records the raw x
coordinate, so a passthrough hash is supplied to compare the actual curve output rather than
a digest of it.
*/
package test_ecdh_recovery

import "core:testing"
import "../../ecdh"
import "../../eckey"
import "../../group"

@(private = "file")
wp_nib :: proc(c: u8) -> u8 {
	switch c {
	case '0' ..= '9':
		return c - '0'
	case 'a' ..= 'f':
		return c - 'a' + 10
	case 'A' ..= 'F':
		return c - 'A' + 10
	}
	panic("non-hex character in a Wycheproof vector")
}

@(private = "file")
wp_hex :: proc(s: string, buf: []u8) -> []u8 {
	if len(s) % 2 != 0 {
		panic("odd-length hex in a Wycheproof vector")
	}
	n := len(s) / 2
	if n > len(buf) {
		panic("Wycheproof vector longer than its buffer")
	}
	for i in 0 ..< n {
		buf[i] = wp_nib(s[i * 2]) << 4 | wp_nib(s[i * 2 + 1])
	}
	return buf[:n]
}

/*
Hands back the shared point's x coordinate unhashed, which is what the corpus records.
*/
@(private = "file")
raw_x_hash :: proc "contextless" (output: []u8, x32: ^[32]u8, y32: ^[32]u8, data: rawptr) -> bool {
	if len(output) < 32 {
		return false
	}
	for i in 0 ..< 32 {
		output[i] = x32[i]
	}
	return true
}

/*
Right-aligns a big-endian scalar into 32 bytes.

Wycheproof writes private keys with a leading zero byte, and occasionally shorter than 32
bytes. Anything with a significant byte above the 32-byte window is out of range for the
curve and cannot be represented, which is reported rather than truncated — truncating would
turn an invalid key into a valid one and hide a rejection the corpus expects.
*/
@(private = "file")
normalize_seckey :: proc(raw: []u8) -> (out: [32]u8, ok: bool) {
	start := 0
	for start < len(raw) && raw[start] == 0 {
		start += 1
	}
	sig := raw[start:]
	if len(sig) > 32 {
		return out, false
	}
	copy(out[32 - len(sig):], sig)
	return out, true
}

/*
The one SubjectPublicKeyInfo header this test accepts: an uncompressed secp256k1 point
identified by the *named curve* OID.

	30 56          SEQUENCE, 86 bytes
	   30 10       SEQUENCE (AlgorithmIdentifier), 16 bytes
	      06 07 2A8648CE3D0201     OID id-ecPublicKey
	      06 05 2B8104000A         OID secp256k1
	   03 42 00    BIT STRING, 66 bytes, 0 unused bits
	      04       uncompressed point tag, then x || y

Matching the header exactly rather than seeking the point at the tail is what makes the
`invalid` half of this corpus meaningful. A large group of those cases are valid secp256k1
*points* wrapped in a header that names a different curve, or that spells the curve out with
explicit parameters carrying a modified order, cofactor or prime — tcId 492 says so in as
many words: "The point of the public key is a valid on secp256k1." Seeking the tail would
compute a shared secret for every one of them and call the corpus wrong. Rejecting anything
that is not this exact header rejects them for the right reason: the key is not a secp256k1
key, whatever its coordinates happen to satisfy.
*/
@(private = "file")
SPKI_HEADER :: [23]u8 {
	0x30, 0x56, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
	0x01, 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A, 0x03, 0x42, 0x00,
}

/*
Extracts the uncompressed point from an X.509 SubjectPublicKeyInfo.

Returns false unless the input is exactly the secp256k1 named-curve header followed by a
65-byte uncompressed point.
*/
@(private = "file")
point_from_spki :: proc(der: []u8) -> (out: [65]u8, ok: bool) {
	header := SPKI_HEADER
	if len(der) != len(header) + 65 {
		return out, false
	}
	for b, i in header {
		if der[i] != b {
			return out, false
		}
	}
	if der[len(header)] != 0x04 {
		return out, false
	}
	copy(out[:], der[len(header):])
	return out, true
}

/*
Runs the whole Wycheproof ECDH corpus.
*/
@(test)
test_run_ecdh_wycheproof :: proc(t: ^testing.T) {
	n_valid, n_invalid, n_acceptable, n_not_applicable := 0, 0, 0, 0

	for c in WYCHEPROOF_ECDH {
		der_buf: [8192]u8
		der := wp_hex(c.public, der_buf[:])

		priv_buf: [128]u8
		priv_raw := wp_hex(c.private, priv_buf[:])

		point_bytes, have_point := point_from_spki(der)
		seckey, key_in_range := normalize_seckey(priv_raw)

		// Compute the verdict this library would give a caller.
		got_ok := false
		shared: [32]u8
		if have_point && key_in_range {
			pubkey: group.Ge
			if eckey.pubkey_parse(&pubkey, point_bytes[:]) {
				got_ok = ecdh.ecdh(shared[:], &pubkey, &seckey, raw_x_hash)
			}
		}

		switch c.result {
		case "valid":
			if !have_point {
				// A case the corpus calls valid but whose point this API cannot reach is a
				// gap in the harness, not a pass. Count it and say so.
				n_not_applicable += 1
				continue
			}
			n_valid += 1
			if !got_ok {
				testing.expectf(t, false, "tc%d: rejected a valid case — %s", c.tc_id, c.comment)
				continue
			}
			// Right-align: the corpus strips leading zeros from some shared coordinates, and
			// a left-aligned compare would fail those for the wrong reason.
			raw_buf: [64]u8
			raw := wp_hex(c.shared, raw_buf[:])
			expected: [32]u8
			match := len(raw) <= 32
			if match {
				copy(expected[32 - len(raw):], raw)
				match = shared == expected
			}
			testing.expectf(t, match, "tc%d: shared secret mismatch — %s", c.tc_id, c.comment)

		case "invalid":
			n_invalid += 1
			testing.expectf(
				t,
				!got_ok,
				"tc%d: accepted an invalid case — %s",
				c.tc_id,
				c.comment,
			)

		case "acceptable":
			// Executed for crash resistance; the verdict is deliberately not asserted.
			n_acceptable += 1

		case:
			testing.expectf(t, false, "tc%d: unknown result %q", c.tc_id, c.result)
		}
	}

	// Pin the shape of the corpus so a generator or header regression cannot shrink it
	// silently. These are derived from the JSON, not read off a passing run: if one moves,
	// re-derive it from the corpus rather than editing it to match.
	//
	// `n_not_applicable` is zero and must stay zero — every valid case is reachable through
	// this API, so any skip is a harness gap and not an excuse.
	testing.expect_value(t, len(WYCHEPROOF_ECDH), 752)
	testing.expect_value(t, n_valid, 473)
	testing.expect_value(t, n_invalid, 49)
	testing.expect_value(t, n_acceptable, 230)
	testing.expect_value(t, n_not_applicable, 0)
}
