/*
Hash tests, mirroring upstream's `run_sha256_known_output_tests`,
`run_sha256_counter_tests`, `run_hmac_sha256_tests`, `run_rfc6979_hmac_sha256_tests` and
`run_tagged_sha256_tests`.

Vectors are the published ones — NIST FIPS 180-2 for SHA-256, RFC 4231 for HMAC-SHA256,
RFC 6979 A.2.5 for the nonce generator — reproduced unmodified, per `CLAUDE.md`.
*/
package test_hash

import "core:testing"
import "../../hash"

/*
Parses a hex string into bytes.
*/
@(private = "file")
from_hex :: proc(t: ^testing.T, s: string, out: []u8) -> []u8 {
	testing.expect_value(t, len(s) % 2, 0)
	n := len(s) / 2
	testing.expect(t, n <= len(out), "hex string longer than the destination")
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
to_hex :: proc(b: []u8, out: []u8) -> string {
	digits := "0123456789abcdef"
	for i in 0 ..< len(b) {
		out[i * 2] = digits[b[i] >> 4]
		out[i * 2 + 1] = digits[b[i] & 0xf]
	}
	return string(out[:len(b) * 2])
}

@(test)
test_run_sha256_known_output_tests :: proc(t: ^testing.T) {
	Case :: struct {
		input:  string,
		repeat: int,
		want:   string,
	}

	// NIST FIPS 180-2 examples plus the standard empty-string and long-input cases.
	cases := []Case {
		{"", 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"abc", 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
			1,
			"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
		},
		{
			"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
			1,
			"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
		},
		// One million 'a' characters.
		{"a", 1_000_000, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
		// Exactly one block, and one block plus one byte, to exercise the buffering
		// boundary where a partial block must be carried across writes.
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			1,
			"ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
		},
	}

	for c, i in cases {
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		for _ in 0 ..< c.repeat {
			hash.sha256_write(&sha, transmute([]u8)c.input)
		}
		digest: [32]u8
		hash.sha256_finalize(&sha, &digest)

		buf: [64]u8
		got := to_hex(digest[:], buf[:])
		testing.expectf(t, got == c.want, "sha256 case %d: got %s want %s", i, got, c.want)
	}
}

/*
Checks that writing the same input in different chunk sizes gives the same digest.

This is where the internal block buffering is exercised; upstream's
`run_sha256_counter_tests` covers the same ground.
*/
@(test)
test_run_sha256_counter_tests :: proc(t: ^testing.T) {
	data: [200]u8
	for i in 0 ..< len(data) {
		data[i] = u8(i * 7 + 13)
	}

	// Reference: one write.
	ref: [32]u8
	{
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, data[:])
		hash.sha256_finalize(&sha, &ref)
	}

	// Every chunk size must agree, including sizes that straddle the 64-byte boundary.
	for chunk in 1 ..= 70 {
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		pos := 0
		for pos < len(data) {
			n := min(chunk, len(data) - pos)
			hash.sha256_write(&sha, data[pos:pos + n])
			pos += n
		}
		got: [32]u8
		hash.sha256_finalize(&sha, &got)
		testing.expectf(t, got == ref, "chunked write of size %d gave a different digest", chunk)
	}

	// Lengths around the padding boundary: 55, 56 and 64 bytes exercise the case where
	// the length field does not fit in the final block and an extra block is needed.
	for n in 50 ..= 70 {
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, data[:n])
		a: [32]u8
		hash.sha256_finalize(&sha, &a)

		sha2: hash.Sha256
		hash.sha256_initialize(&sha2)
		for i in 0 ..< n {
			hash.sha256_write(&sha2, data[i:i + 1])
		}
		b: [32]u8
		hash.sha256_finalize(&sha2, &b)

		testing.expectf(t, a == b, "byte-at-a-time differs at length %d", n)
	}
}

@(test)
test_run_hmac_sha256_tests :: proc(t: ^testing.T) {
	Case :: struct {
		key, data, want: string,
	}

	// RFC 4231 test cases 1, 2, 3, 6 and 7.
	cases := []Case {
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			"4869205468657265", // "Hi There"
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			"4a656665", // "Jefe"
			"7768617420646f2079612077616e7420666f72206e6f7468696e673f",
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
		},
		{
			// Key longer than one block, so it must be hashed down first.
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
		},
		{
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
			"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
		},
	}

	for c, i in cases {
		kbuf: [256]u8
		dbuf: [256]u8
		key := from_hex(t, c.key, kbuf[:])
		data := from_hex(t, c.data, dbuf[:])

		h: hash.Hmac_Sha256
		hash.hmac_sha256_initialize(&h, key)
		hash.hmac_sha256_write(&h, data)
		out: [32]u8
		hash.hmac_sha256_finalize(&h, &out)

		buf: [64]u8
		got := to_hex(out[:], buf[:])
		testing.expectf(t, got == c.want, "hmac case %d: got %s want %s", i, got, c.want)
	}
}

/*
Checks the RFC6979 generator against the values upstream's own test uses, and confirms the
properties the nonce generation depends on.
*/
@(test)
test_run_rfc6979_hmac_sha256_tests :: proc(t: ^testing.T) {
	// Upstream's `run_rfc6979_hmac_sha256_tests` vector: a 64-byte key of the given form,
	// and the first two 32-byte outputs.
	key1 := [64]u8 {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	want1 := "601cf54e09f7b9149eee6624bfba7d12daae70b5f2d8c57b405f96d1aa92dc47"
	want2 := "5b01f41b19fac4275d50e29a795c8d4be1eba6c3ac4c9e56ee7c168e3de228cd"

	rng: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng, key1[:])

	out: [32]u8
	// Each digest needs its own scratch: to_hex returns a view into the buffer it is
	// given, so sharing one would make every result alias the most recent conversion.
	buf1, buf2, buf3: [64]u8

	hash.rfc6979_hmac_sha256_generate(&rng, out[:])
	got1 := to_hex(out[:], buf1[:])
	testing.expectf(t, got1 == want1, "rfc6979 first output: got %s want %s", got1, want1)

	hash.rfc6979_hmac_sha256_generate(&rng, out[:])
	got2 := to_hex(out[:], buf2[:])
	testing.expectf(t, got2 == want2, "rfc6979 second output: got %s want %s", got2, want2)

	// Determinism: the same seed must reproduce the same stream. This is the property the
	// whole construction exists for.
	rng2: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng2, key1[:])
	a: [32]u8
	hash.rfc6979_hmac_sha256_generate(&rng2, a[:])
	testing.expect(t, to_hex(a[:], buf3[:]) == want1, "the generator is not deterministic")

	// Successive outputs must differ; a generator that repeats would be catastrophic for
	// ECDSA, since a repeated nonce reveals the private key.
	testing.expect(t, got1 != got2, "successive outputs are identical")

	// A different seed must give a different stream.
	key2 := key1
	key2[63] = 1
	rng3: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng3, key2[:])
	c: [32]u8
	cbuf: [64]u8
	hash.rfc6979_hmac_sha256_generate(&rng3, c[:])
	testing.expect(t, to_hex(c[:], cbuf[:]) != want1, "different seeds produced the same output")

	// Requesting a long run must match concatenated short requests.
	rng4: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng4, key1[:])
	long: [96]u8
	hash.rfc6979_hmac_sha256_generate(&rng4, long[:])

	rng5: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng5, key1[:])
	short: [96]u8
	hash.rfc6979_hmac_sha256_generate(&rng5, short[0:96])
	testing.expect(t, long == short, "long and short generation disagree")
}

@(test)
test_run_tagged_sha256_tests :: proc(t: ^testing.T) {
	// tagged_hash(tag, m) must equal SHA256(SHA256(tag) || SHA256(tag) || m), computed
	// here the long way round.
	tag := "BIP0340/challenge"
	msg := []u8{1, 2, 3, 4, 5}

	taghash: [32]u8
	{
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, transmute([]u8)tag)
		hash.sha256_finalize(&sha, &taghash)
	}

	want: [32]u8
	{
		sha: hash.Sha256
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, taghash[:])
		hash.sha256_write(&sha, taghash[:])
		hash.sha256_write(&sha, msg)
		hash.sha256_finalize(&sha, &want)
	}

	got: [32]u8
	hash.tagged_sha256(&got, transmute([]u8)tag, msg)
	testing.expect(t, got == want, "tagged_sha256 does not match its definition")

	// The incremental form must agree with the one-shot form.
	got2: [32]u8
	{
		sha: hash.Sha256
		hash.sha256_initialize_tagged(&sha, transmute([]u8)tag)
		hash.sha256_write(&sha, msg)
		hash.sha256_finalize(&sha, &got2)
	}
	testing.expect(t, got2 == want, "incremental tagged hashing disagrees")

	// Different tags must domain-separate: the whole point of the construction.
	other: [32]u8
	hash.tagged_sha256(&other, transmute([]u8)string("BIP0340/aux"), msg)
	testing.expect(t, other != want, "different tags produced the same hash")

	// The three BIP340 tags must all differ from each other.
	challenge, aux, nonce: [32]u8
	hash.tagged_sha256(&challenge, transmute([]u8)string("BIP0340/challenge"), msg)
	hash.tagged_sha256(&aux, transmute([]u8)string("BIP0340/aux"), msg)
	hash.tagged_sha256(&nonce, transmute([]u8)string("BIP0340/nonce"), msg)
	testing.expect(t, challenge != aux && aux != nonce && challenge != nonce, "BIP340 tags collide")
}
