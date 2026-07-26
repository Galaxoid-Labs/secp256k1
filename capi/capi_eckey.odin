/*
Public and secret key operations: parsing, serialization, comparison, ordering, and the
additive and multiplicative tweaks that Taproot and BIP32 are built on.

Mirrors the key-handling half of upstream's `secp256k1.h`.
*/
package capi

import "core:c"
import "core:mem"
import "../eckey"
import "../group"
import "../scalar"

/*
Parses a public key from a compressed, uncompressed or hybrid encoding.
*/
@(export, link_name = "secp256k1_ec_pubkey_parse")
ec_pubkey_parse :: proc "c" (
	ctx: ^Context,
	pubkey: ^Pubkey,
	input: [^]u8,
	inputlen: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_parse: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Pubkey))
	if !arg_check(ctx, input != nil, "ec_pubkey_parse: input is null") {
		return 0
	}
	ge: group.Ge
	if !eckey.pubkey_parse(&ge, input[:int(inputlen)]) {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Serializes a public key. `outputlen` carries the buffer size in and the length written out.
*/
@(export, link_name = "secp256k1_ec_pubkey_serialize")
ec_pubkey_serialize :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	outputlen: ^c.size_t,
	pubkey: ^Pubkey,
	flags: c.uint,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, outputlen != nil, "ec_pubkey_serialize: outputlen is null") {
		return 0
	}

	compressed := (flags & FLAGS_BIT_COMPRESSION) != 0
	want := c.size_t(33) if compressed else c.size_t(65)

	if !arg_check(ctx, outputlen^ >= want, "ec_pubkey_serialize: output buffer too small") {
		return 0
	}
	if !arg_check(ctx, output != nil, "ec_pubkey_serialize: output is null") {
		return 0
	}
	mem.zero(output, int(want))
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_serialize: pubkey is null") {
		return 0
	}
	if !arg_check(
		ctx,
		(flags & FLAGS_TYPE_MASK) == FLAGS_TYPE_COMPRESSION,
		"ec_pubkey_serialize: invalid flags",
	) {
		return 0
	}

	ge: group.Ge
	if !pubkey_load(&ge, pubkey) {
		// Upstream returns 0 with the buffer zeroed and does not call the illegal callback
		// here: an unparseable blob is a failed load, not a bad argument.
		outputlen^ = 0
		return 0
	}

	if compressed {
		buf: [33]u8
		eckey.pubkey_serialize33(&ge, &buf)
		mem.copy(output, &buf[0], 33)
		outputlen^ = 33
	} else {
		buf: [65]u8
		eckey.pubkey_serialize65(&ge, &buf)
		mem.copy(output, &buf[0], 65)
		outputlen^ = 65
	}
	return 1
}

/*
Orders two public keys by their compressed serialization, returning <0, 0 or >0.

The ordering is over the 33-byte compressed form, which is what BIP327's KeySort specifies
and what makes aggregate keys reproducible across implementations.
*/
@(export, link_name = "secp256k1_ec_pubkey_cmp")
ec_pubkey_cmp :: proc "c" (ctx: ^Context, pubkey1: ^Pubkey, pubkey2: ^Pubkey) -> c.int {
	ensure_ready()

	out: [2][33]u8
	ok: [2]bool
	for pk, i in ([2]^Pubkey{pubkey1, pubkey2}) {
		ge: group.Ge
		// A null or unparseable key sorts before every valid one, and two of them compare
		// equal. Upstream reaches the same outcome by leaving the buffer zeroed.
		ok[i] = pk != nil && pubkey_load(&ge, pk)
		if ok[i] {
			eckey.pubkey_serialize33(&ge, &out[i])
		}
	}
	if !arg_check(ctx, ok[0], "ec_pubkey_cmp: pubkey1 is invalid") {
		// Fall through: upstream still returns a total order so a sort cannot loop.
	}
	if !arg_check(ctx, ok[1], "ec_pubkey_cmp: pubkey2 is invalid") {
	}

	return c.int(mem.compare_ptrs(&out[0][0], &out[1][0], 33))
}

/*
Sorts an array of public key pointers into BIP327 KeySort order.

The array of *pointers* is permuted; the keys themselves are untouched, matching upstream's
signature. Insertion sort, for the same reason `musig.pubkey_sort` uses one: signer sets are
small, and it needs no allocation, which keeps the no-heap property this library holds
everywhere else.
*/
@(export, link_name = "secp256k1_ec_pubkey_sort")
ec_pubkey_sort :: proc "c" (ctx: ^Context, pubkeys: [^]^Pubkey, n_pubkeys: c.size_t) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkeys != nil || n_pubkeys == 0, "ec_pubkey_sort: pubkeys is null") {
		return 0
	}
	n := int(n_pubkeys)
	for i in 0 ..< n {
		if !arg_check(ctx, pubkeys[i] != nil, "ec_pubkey_sort: a pubkey is null") {
			return 0
		}
	}

	ser :: proc "contextless" (pk: ^Pubkey) -> (out: [33]u8) {
		ge: group.Ge
		if pubkey_load(&ge, pk) {
			eckey.pubkey_serialize33(&ge, &out)
		}
		return
	}

	for i in 1 ..< n {
		key := pubkeys[i]
		key_ser := ser(key)
		j := i - 1
		for j >= 0 {
			j_ser := ser(pubkeys[j])
			if mem.compare_ptrs(&j_ser[0], &key_ser[0], 33) <= 0 {
				break
			}
			pubkeys[j + 1] = pubkeys[j]
			j -= 1
		}
		pubkeys[j + 1] = key
	}
	return 1
}

/*
Reports whether a 32-byte value is a valid secret key: in [1, n).
*/
@(export, link_name = "secp256k1_ec_seckey_verify")
ec_seckey_verify :: proc "c" (ctx: ^Context, seckey: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, seckey != nil, "ec_seckey_verify: seckey is null") {
		return 0
	}
	s: scalar.Scalar
	ok := scalar.scalar_set_b32_seckey(&s, seckey)
	scalar.scalar_clear(&s)
	return 1 if ok else 0
}

/*
Derives a public key from a secret key.
*/
@(export, link_name = "secp256k1_ec_pubkey_create")
ec_pubkey_create :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, seckey: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_create: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Pubkey))
	if !arg_check(ctx, ctx != nil, "ec_pubkey_create: ctx is null") {
		return 0
	}
	if !arg_check(ctx, seckey != nil, "ec_pubkey_create: seckey is null") {
		return 0
	}

	s: scalar.Scalar
	defer scalar.scalar_clear(&s)
	if !scalar.scalar_set_b32_seckey(&s, seckey) {
		return 0
	}
	ge: group.Ge
	if !eckey.pubkey_create(&ctx.inner.ecmult_gen_ctx, &ge, &s) {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Negates a secret key in place.
*/
@(export, link_name = "secp256k1_ec_seckey_negate")
ec_seckey_negate :: proc "c" (ctx: ^Context, seckey: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, seckey != nil, "ec_seckey_negate: seckey is null") {
		return 0
	}
	s: scalar.Scalar
	defer scalar.scalar_clear(&s)

	ok := scalar.scalar_set_b32_seckey(&s, seckey)
	// Zero the output on failure rather than branching away: the caller's buffer must not
	// keep a value that is neither the input nor a valid key.
	scalar.scalar_cmov(&s, &scalar.ZERO, !ok)
	scalar.scalar_negate(&s, &s)
	scalar.scalar_get_b32(seckey, &s)
	return 1 if ok else 0
}

/*
Negates a public key in place.
*/
@(export, link_name = "secp256k1_ec_pubkey_negate")
ec_pubkey_negate :: proc "c" (ctx: ^Context, pubkey: ^Pubkey) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_negate: pubkey is null") {
		return 0
	}
	ge: group.Ge
	ok := pubkey_load(&ge, pubkey)
	mem.zero(pubkey, size_of(Pubkey))
	if !ok {
		return 0
	}
	eckey.pubkey_negate(&ge)
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Adds a tweak to a secret key in place: `seckey = seckey + tweak (mod n)`.

Fails, leaving the key zeroed, if the tweak is out of range or the result is zero.
*/
@(export, link_name = "secp256k1_ec_seckey_tweak_add")
ec_seckey_tweak_add :: proc "c" (ctx: ^Context, seckey: ^[32]u8, tweak32: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, seckey != nil, "ec_seckey_tweak_add: seckey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "ec_seckey_tweak_add: tweak32 is null") {
		return 0
	}

	term, sec: scalar.Scalar
	defer scalar.scalar_clear(&term)
	defer scalar.scalar_clear(&sec)

	overflow := scalar.scalar_set_b32(&term, tweak32)
	ok := scalar.scalar_set_b32_seckey(&sec, seckey)
	ok &&= !overflow
	ok &&= eckey.privkey_tweak_add(&sec, &term)
	scalar.scalar_cmov(&sec, &scalar.ZERO, !ok)
	scalar.scalar_get_b32(seckey, &sec)
	return 1 if ok else 0
}

/*
Multiplies a secret key by a tweak in place: `seckey = seckey * tweak (mod n)`.
*/
@(export, link_name = "secp256k1_ec_seckey_tweak_mul")
ec_seckey_tweak_mul :: proc "c" (ctx: ^Context, seckey: ^[32]u8, tweak32: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, seckey != nil, "ec_seckey_tweak_mul: seckey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "ec_seckey_tweak_mul: tweak32 is null") {
		return 0
	}

	factor, sec: scalar.Scalar
	defer scalar.scalar_clear(&factor)
	defer scalar.scalar_clear(&sec)

	overflow := scalar.scalar_set_b32(&factor, tweak32)
	ok := scalar.scalar_set_b32_seckey(&sec, seckey)
	ok &&= !overflow
	ok &&= eckey.privkey_tweak_mul(&sec, &factor)
	scalar.scalar_cmov(&sec, &scalar.ZERO, !ok)
	scalar.scalar_get_b32(seckey, &sec)
	return 1 if ok else 0
}

/*
Adds `tweak*G` to a public key in place.
*/
@(export, link_name = "secp256k1_ec_pubkey_tweak_add")
ec_pubkey_tweak_add :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, tweak32: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_tweak_add: pubkey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "ec_pubkey_tweak_add: tweak32 is null") {
		return 0
	}

	ge: group.Ge
	ok := pubkey_load(&ge, pubkey)
	mem.zero(pubkey, size_of(Pubkey))

	term: scalar.Scalar
	overflow := scalar.scalar_set_b32(&term, tweak32)
	ok &&= !overflow
	ok &&= eckey.pubkey_tweak_add(&ge, &term)
	if !ok {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Multiplies a public key by a tweak in place.
*/
@(export, link_name = "secp256k1_ec_pubkey_tweak_mul")
ec_pubkey_tweak_mul :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, tweak32: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ec_pubkey_tweak_mul: pubkey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "ec_pubkey_tweak_mul: tweak32 is null") {
		return 0
	}

	ge: group.Ge
	ok := pubkey_load(&ge, pubkey)
	mem.zero(pubkey, size_of(Pubkey))

	factor: scalar.Scalar
	overflow := scalar.scalar_set_b32(&factor, tweak32)
	ok &&= !overflow
	ok &&= eckey.pubkey_tweak_mul(&ge, &factor)
	if !ok {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Adds public keys together, writing their sum.

Fails if the sum is the point at infinity, which is not a representable public key.
*/
@(export, link_name = "secp256k1_ec_pubkey_combine")
ec_pubkey_combine :: proc "c" (
	ctx: ^Context,
	out: ^Pubkey,
	ins: [^]^Pubkey,
	n: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, out != nil, "ec_pubkey_combine: out is null") {
		return 0
	}
	mem.zero(out, size_of(Pubkey))
	if !arg_check(ctx, n >= 1, "ec_pubkey_combine: n is zero") {
		return 0
	}
	if !arg_check(ctx, ins != nil, "ec_pubkey_combine: ins is null") {
		return 0
	}

	acc: group.Gej
	group.gej_set_infinity(&acc)
	for i in 0 ..< int(n) {
		if !arg_check(ctx, ins[i] != nil, "ec_pubkey_combine: an input is null") {
			return 0
		}
		ge: group.Ge
		if !pubkey_load(&ge, ins[i]) {
			return 0
		}
		term: group.Gej
		group.gej_set_ge(&term, &ge)
		group.gej_add_var(&acc, &acc, &term, nil)
	}
	if group.gej_is_infinity(&acc) {
		return 0
	}

	sum: group.Ge
	group.ge_set_gej(&sum, &acc)
	pubkey_store(out, &sum)
	return 1
}
