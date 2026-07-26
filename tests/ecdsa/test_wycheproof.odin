/*
Wycheproof ECDSA — the Phase 6 hard gate, mirroring upstream's `run_ecdsa_wycheproof`.

These are chosen adversarial inputs, not random ones, and that is the point: 301 of the 463
cases are expected to be *rejected*. A verifier is easy to get right on valid signatures and
hard to get right on malformed ones, so the invalid cases carry most of the information
here. Fuzzing against the C oracle cannot substitute for them — both implementations would
have to be wrong in the same way for a divergence to show up, whereas these cases encode
what the answer actually is.

The corpus is the "bitcoin" variant, which requires strict DER *and* low-S. A signature with
high s is arithmetically valid and still expected to be rejected, because accepting it
reintroduces malleability.

Every case is run through the full public path — parse the public key, hash the message,
parse the DER, verify — because that is the path a caller uses, and a rejection is only
meaningful if it happens somewhere on it.
*/
package test_ecdsa

import "core:testing"
import "../../ecdsa"
import "../../eckey"
import "../../group"
import "../../hash"

/*
Decodes a hex string of arbitrary length into a caller-supplied buffer.

Returns the filled prefix. Odd-length input is a corpus transcription error, not a test
failure, so it panics rather than reporting.
*/
@(private = "file")
hex_nib :: proc(c: u8) -> u8 {
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
hex_bytes :: proc(s: string, buf: []u8) -> []u8 {
	if len(s) % 2 != 0 {
		panic("odd-length hex in a Wycheproof vector")
	}
	n := len(s) / 2
	if n > len(buf) {
		panic("Wycheproof vector longer than its buffer")
	}
	for i in 0 ..< n {
		buf[i] = hex_nib(s[i * 2]) << 4 | hex_nib(s[i * 2 + 1])
	}
	return buf[:n]
}

/*
Runs the whole Wycheproof ECDSA corpus.

A case passes when the verdict matches, whether that verdict is accept or reject. Where the
two disagree the failure names the tcId and upstream's own comment, so a finding can be
looked up in the JSON directly.
*/
@(test)
test_run_ecdsa_wycheproof :: proc(t: ^testing.T) {
	valid_seen, invalid_seen := 0, 0

	for c in WYCHEPROOF_ECDSA {
		// The public key is fixed per group and always a well-formed uncompressed point;
		// a parse failure here would be a corpus problem, so it is asserted separately
		// rather than folded into the verdict.
		pk_buf: [65]u8
		pk_bytes := hex_bytes(c.pubkey, pk_buf[:])
		pubkey: group.Ge
		if !eckey.pubkey_parse(&pubkey, pk_bytes) {
			testing.expectf(t, false, "tc%d: public key failed to parse (%s)", c.tc_id, c.comment)
			continue
		}

		// Messages are short in this corpus, but size the buffer generously rather than
		// assuming: a truncated message would silently verify against the wrong digest.
		msg_buf: [64]u8
		msg := hex_bytes(c.msg, msg_buf[:])

		digest: [32]u8
		h: hash.Sha256
		hash.sha256_initialize(&h)
		hash.sha256_write(&h, msg)
		hash.sha256_finalize(&h, &digest)

		sig_buf: [8192]u8
		sig_bytes := hex_bytes(c.sig, sig_buf[:])

		// Strict DER, then verify. Either step rejecting is a rejection of the case: a
		// caller cannot tell the difference and should not have to.
		sig: ecdsa.Signature
		got := eckey_parse_and_verify(&sig, sig_bytes, &digest, &pubkey)

		if c.valid {
			valid_seen += 1
		} else {
			invalid_seen += 1
		}

		if got != c.valid {
			verdict := "accepted" if got else "rejected"
			expected := "valid" if c.valid else "invalid"
			testing.expectf(
				t,
				false,
				"tc%d: %s but the corpus says %s — %s",
				c.tc_id,
				verdict,
				expected,
				c.comment,
			)
		}
	}

	// Pin the corpus size. A generator regression that silently dropped cases would
	// otherwise leave this test green while testing less.
	testing.expect_value(t, len(WYCHEPROOF_ECDSA), 463)
	testing.expect_value(t, valid_seen, 162)
	testing.expect_value(t, invalid_seen, 301)
}

/*
Parses a DER signature strictly and verifies it, returning the single accept/reject verdict
a caller would see.
*/
@(private = "file")
eckey_parse_and_verify :: proc(
	sig: ^ecdsa.Signature,
	der: []u8,
	digest: ^[32]u8,
	pubkey: ^group.Ge,
) -> bool {
	if !ecdsa.signature_parse_der(sig, der) {
		return false
	}
	return ecdsa.verify(sig, digest, pubkey)
}
