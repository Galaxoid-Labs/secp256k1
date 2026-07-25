/*
Signature serialization: the 64-byte compact form and DER.

Mirrors upstream's `ecdsa_impl.h`.

# Why DER parsing is strict

DER is a canonical encoding: for any given signature there is exactly one valid byte
sequence. Accepting non-canonical variants — extra leading zeros, wrong length octets,
negative-looking integers — makes a signature malleable at the encoding layer, which for
Bitcoin means a third party can change a transaction's txid without invalidating it. So
`signature_parse_der` rejects anything non-canonical.

`signature_parse_der_lax` accepts the historical variants that existed before that rule was
enforced. It is for reading old data only. Never use it to validate new signatures.
*/
package ecdsa

import "../scalar"

/*
Writes a signature in the 64-byte compact form: r and s as big-endian 32-byte values.
*/
signature_serialize_compact :: proc "contextless" (out64: ^[64]u8, sig: ^Signature) {
	r := (^[32]u8)(&out64[0])
	s := (^[32]u8)(&out64[32])
	scalar.scalar_get_b32(r, &sig.r)
	scalar.scalar_get_b32(s, &sig.s)
}

/*
Parses a signature from the 64-byte compact form.

Returns false if either half is at or above n. Out-of-range values are rejected rather than
reduced, since reduction would silently accept a different signature than the one supplied.
*/
signature_parse_compact :: proc "contextless" (sig: ^Signature, in64: ^[64]u8) -> bool {
	r := (^[32]u8)(&in64[0])
	s := (^[32]u8)(&in64[32])

	over_r := scalar.scalar_set_b32(&sig.r, r)
	over_s := scalar.scalar_set_b32(&sig.s, s)

	if over_r || over_s {
		scalar.scalar_set_int(&sig.r, 0)
		scalar.scalar_set_int(&sig.s, 0)
		return false
	}
	return true
}

/*
Writes a signature in DER:

	0x30 <total-len> 0x02 <r-len> <r> 0x02 <s-len> <s>

Each integer is minimally encoded and gets a leading zero byte when its top bit is set, so
that it is not read as negative.

Returns the number of bytes written, or 0 if the buffer is too small. The maximum is 72
bytes.
*/
signature_serialize_der :: proc "contextless" (out: []u8, sig: ^Signature) -> int {
	r, s: [32]u8
	scalar.scalar_get_b32(&r, &sig.r)
	scalar.scalar_get_b32(&s, &sig.s)

	// Strip leading zeros, then re-add one if the top bit is set.
	rp := 0
	for rp < 32 && r[rp] == 0 {
		rp += 1
	}
	sp := 0
	for sp < 32 && s[sp] == 0 {
		sp += 1
	}

	rlen := 32 - rp
	slen := 32 - sp
	r_needs_pad := rlen > 0 && r[rp] >= 0x80
	s_needs_pad := slen > 0 && s[sp] >= 0x80

	// A zero integer still needs one content byte.
	if rlen == 0 {
		rlen = 1
		rp = 31
	}
	if slen == 0 {
		slen = 1
		sp = 31
	}

	r_total := rlen + (1 if r_needs_pad else 0)
	s_total := slen + (1 if s_needs_pad else 0)
	total := 4 + r_total + s_total

	if len(out) < total + 2 {
		return 0
	}

	pos := 0
	out[pos] = 0x30; pos += 1
	out[pos] = u8(total - 2 + 2); pos += 1 // content length after the two header bytes

	out[pos] = 0x02; pos += 1
	out[pos] = u8(r_total); pos += 1
	if r_needs_pad {
		out[pos] = 0; pos += 1
	}
	copy(out[pos:], r[rp:32]); pos += rlen

	out[pos] = 0x02; pos += 1
	out[pos] = u8(s_total); pos += 1
	if s_needs_pad {
		out[pos] = 0; pos += 1
	}
	copy(out[pos:], s[sp:32]); pos += slen

	// Fix the sequence length now that the exact size is known.
	out[1] = u8(pos - 2)
	return pos
}

/*
Reads a DER length octet.

Only the short form and minimally encoded long forms are accepted; everything else is
non-canonical.
*/
@(private)
der_read_len :: proc "contextless" (
	length: ^int,
	sig: []u8,
	pos: ^int,
) -> bool {
	length^ = 0
	if pos^ >= len(sig) {
		return false
	}

	b1 := sig[pos^]
	pos^ += 1

	if b1 == 0xff {
		// Indefinite length is not allowed in DER.
		return false
	}
	if b1 & 0x80 == 0 {
		// Short form.
		length^ = int(b1)
		return true
	}
	if b1 == 0x80 {
		// Indefinite length is not allowed in DER.
		return false
	}

	lenleft := int(b1 & 0x7f)
	if lenleft > len(sig) - pos^ {
		return false
	}
	if sig[pos^] == 0 {
		// Not minimally encoded.
		return false
	}

	if lenleft > 4 {
		// Longer than any signature could be.
		return false
	}

	l := 0
	for lenleft > 0 {
		l = (l << 8) | int(sig[pos^])
		pos^ += 1
		lenleft -= 1
	}
	if l > len(sig) - pos^ {
		return false
	}

	length^ = l
	return true
}

/*
Reads a DER-encoded integer into a scalar.

Returns false on any non-canonical encoding: a missing tag, a negative value, a
non-minimal leading zero, or an over-long value. A value at or above n is reported through
`overflow` rather than as a parse failure, because the encoding is well formed even though
the value is unusable.
*/
@(private)
der_parse_integer :: proc "contextless" (
	r: ^scalar.Scalar,
	sig: []u8,
	pos: ^int,
) -> (
	ok: bool,
	overflow: bool,
) {
	if pos^ >= len(sig) || sig[pos^] != 0x02 {
		return false, false
	}
	pos^ += 1

	rlen: int
	if !der_read_len(&rlen, sig, pos) {
		return false, false
	}
	if rlen == 0 || pos^ + rlen > len(sig) {
		return false, false
	}

	// A leading 0x00 is only allowed when the next byte would otherwise look negative.
	if sig[pos^] == 0x00 && rlen > 1 && (sig[pos^ + 1] & 0x80) == 0 {
		return false, false
	}
	// A negative integer is invalid: signature components are non-negative.
	if sig[pos^] & 0x80 != 0 {
		return false, false
	}

	// Skip the single permitted padding byte.
	p := pos^
	l := rlen
	if sig[p] == 0x00 && l > 1 {
		p += 1
		l -= 1
	}

	if l > 32 {
		pos^ += rlen
		return true, true
	}

	b32: [32]u8
	copy(b32[32 - l:], sig[p:p + l])
	over := scalar.scalar_set_b32(r, &b32)

	pos^ += rlen
	return true, over
}

/*
Parses a strictly DER-encoded signature.

Rejects any non-canonical encoding, and rejects r or s at or above n. This is what should
be used to validate signatures received from the network.
*/
signature_parse_der :: proc "contextless" (sig: ^Signature, input: []u8) -> bool {
	pos := 0

	if pos >= len(input) || input[pos] != 0x30 {
		return false
	}
	pos += 1

	seqlen: int
	if !der_read_len(&seqlen, input, &pos) {
		return false
	}
	// The sequence must consume exactly the rest of the input; trailing bytes are not
	// canonical.
	if seqlen != len(input) - pos {
		return false
	}

	ok, over_r := der_parse_integer(&sig.r, input, &pos)
	if !ok || over_r {
		return false
	}

	ok2, over_s := der_parse_integer(&sig.s, input, &pos)
	if !ok2 || over_s {
		return false
	}

	if pos != len(input) {
		return false
	}
	return true
}

/*
Parses a DER-encoded signature, tolerating the historical non-canonical variants.

**For reading legacy data only.** Accepting these encodings reintroduces the malleability
that strict parsing exists to prevent, so never use this to validate a signature that will
be treated as authoritative.

Out-of-range r or s values are clamped to zero rather than rejected, matching upstream's
lax parser, so a caller must still check that the resulting signature verifies.
*/
signature_parse_der_lax :: proc "contextless" (sig: ^Signature, input: []u8) -> bool {
	scalar.scalar_set_int(&sig.r, 0)
	scalar.scalar_set_int(&sig.s, 0)

	pos := 0
	if pos == len(input) || input[pos] != 0x30 {
		return false
	}
	pos += 1

	// Sequence length: accept short and long forms without minimality checks.
	if pos == len(input) {
		return false
	}
	if input[pos] & 0x80 != 0 {
		n := int(input[pos] & 0x7f)
		pos += 1
		if n > len(input) - pos {
			return false
		}
		pos += n
	} else {
		pos += 1
	}

	// r
	if pos == len(input) || input[pos] != 0x02 {
		return false
	}
	pos += 1
	rlen: int
	if pos == len(input) {
		return false
	}
	if input[pos] & 0x80 != 0 {
		n := int(input[pos] & 0x7f)
		pos += 1
		if n > len(input) - pos {
			return false
		}
		for input[pos] == 0 && n > 0 {
			pos += 1
			n -= 1
		}
		if n > 4 {
			return false
		}
		rlen = 0
		for i in 0 ..< n {
			rlen = (rlen << 8) | int(input[pos + i])
		}
		pos += n
	} else {
		rlen = int(input[pos])
		pos += 1
	}
	if rlen > len(input) - pos {
		return false
	}
	rpos := pos
	pos += rlen

	// s
	if pos == len(input) || input[pos] != 0x02 {
		return false
	}
	pos += 1
	slen: int
	if pos == len(input) {
		return false
	}
	if input[pos] & 0x80 != 0 {
		n := int(input[pos] & 0x7f)
		pos += 1
		if n > len(input) - pos {
			return false
		}
		for input[pos] == 0 && n > 0 {
			pos += 1
			n -= 1
		}
		if n > 4 {
			return false
		}
		slen = 0
		for i in 0 ..< n {
			slen = (slen << 8) | int(input[pos + i])
		}
		pos += n
	} else {
		slen = int(input[pos])
		pos += 1
	}
	if slen > len(input) - pos {
		return false
	}
	spos := pos

	// Strip leading zeros and load, clamping over-long or out-of-range values to zero.
	load :: proc "contextless" (dst: ^scalar.Scalar, src: []u8) -> bool {
		p := 0
		l := len(src)
		for l > 0 && src[p] == 0 {
			p += 1
			l -= 1
		}
		if l > 32 {
			return false
		}
		b32: [32]u8
		copy(b32[32 - l:], src[p:p + l])
		if scalar.scalar_set_b32(dst, &b32) {
			scalar.scalar_set_int(dst, 0)
			return false
		}
		return true
	}

	if !load(&sig.r, input[rpos:rpos + rlen]) {
		scalar.scalar_set_int(&sig.r, 0)
	}
	if !load(&sig.s, input[spos:spos + slen]) {
		scalar.scalar_set_int(&sig.s, 0)
	}
	return true
}
