/*
X-only public keys, keypairs, and BIP340 Schnorr signatures.

Mirrors upstream's `secp256k1_extrakeys.h` and `secp256k1_schnorrsig.h`.
*/
package capi

import "core:c"
import "core:mem"
import "../extrakeys"
import "../group"
import "../scalar"
import "../schnorr"

// ---------------------------------------------------------------------------------------
// Conversions.
//
// A keypair is 32 bytes of secret scalar followed by the 64-byte packed public point,
// matching upstream's 96-byte layout.
// ---------------------------------------------------------------------------------------

@(private)
xonly_store :: proc "contextless" (dst: ^Xonly_Pubkey, xk: ^extrakeys.Xonly_Pubkey) {
	st: group.Ge_Storage
	group.ge_to_storage(&st, &xk.point)
	mem.copy(&dst.data[0], &st, size_of(group.Ge_Storage))
}

@(private)
xonly_load :: proc "contextless" (xk: ^extrakeys.Xonly_Pubkey, src: ^Xonly_Pubkey) -> bool {
	st: group.Ge_Storage
	mem.copy(&st, &src.data[0], size_of(group.Ge_Storage))
	group.ge_from_storage(&xk.point, &st)
	return group.ge_is_valid_var(&xk.point)
}

@(private)
kp_store :: proc "contextless" (dst: ^Keypair, kp: ^extrakeys.Keypair) {
	sec: [32]u8
	scalar.scalar_get_b32(&sec, &kp.seckey)
	mem.copy(&dst.data[0], &sec[0], 32)
	mem.zero_explicit(&sec, 32)

	st: group.Ge_Storage
	group.ge_to_storage(&st, &kp.pubkey)
	mem.copy(&dst.data[32], &st, size_of(group.Ge_Storage))
}

@(private)
kp_load :: proc "contextless" (kp: ^extrakeys.Keypair, src: ^Keypair) -> bool {
	sec: [32]u8
	mem.copy(&sec[0], &src.data[0], 32)
	ok := scalar.scalar_set_b32_seckey(&kp.seckey, &sec)
	mem.zero_explicit(&sec, 32)

	st: group.Ge_Storage
	mem.copy(&st, &src.data[32], size_of(group.Ge_Storage))
	group.ge_from_storage(&kp.pubkey, &st)
	return ok && group.ge_is_valid_var(&kp.pubkey)
}

// ---------------------------------------------------------------------------------------
// X-only public keys.
// ---------------------------------------------------------------------------------------

/*
Parses a 32-byte x-only public key.

Fails if x is not on the curve or is not a valid field element.
*/
@(export, link_name = "secp256k1_xonly_pubkey_parse")
xonly_pubkey_parse :: proc "c" (
	ctx: ^Context,
	pubkey: ^Xonly_Pubkey,
	input32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "xonly_pubkey_parse: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Xonly_Pubkey))
	if !arg_check(ctx, input32 != nil, "xonly_pubkey_parse: input32 is null") {
		return 0
	}
	xk: extrakeys.Xonly_Pubkey
	if !extrakeys.xonly_pubkey_parse(&xk, input32) {
		return 0
	}
	xonly_store(pubkey, &xk)
	return 1
}

/*
Serializes an x-only public key as its 32-byte x coordinate.
*/
@(export, link_name = "secp256k1_xonly_pubkey_serialize")
xonly_pubkey_serialize :: proc "c" (
	ctx: ^Context,
	output32: ^[32]u8,
	pubkey: ^Xonly_Pubkey,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output32 != nil, "xonly_pubkey_serialize: output32 is null") {
		return 0
	}
	mem.zero(output32, 32)
	if !arg_check(ctx, pubkey != nil, "xonly_pubkey_serialize: pubkey is null") {
		return 0
	}
	xk: extrakeys.Xonly_Pubkey
	if !xonly_load(&xk, pubkey) {
		return 0
	}
	extrakeys.xonly_pubkey_serialize(output32, &xk)
	return 1
}

/*
Orders two x-only public keys by their 32-byte serialization.
*/
@(export, link_name = "secp256k1_xonly_pubkey_cmp")
xonly_pubkey_cmp :: proc "c" (ctx: ^Context, pk1: ^Xonly_Pubkey, pk2: ^Xonly_Pubkey) -> c.int {
	ensure_ready()

	out: [2][32]u8
	for pk, i in ([2]^Xonly_Pubkey{pk1, pk2}) {
		xk: extrakeys.Xonly_Pubkey
		ok := pk != nil && xonly_load(&xk, pk)
		if ok {
			extrakeys.xonly_pubkey_serialize(&out[i], &xk)
		} else {
			// An invalid key sorts before every valid one, and two invalid keys compare
			// equal, so the result is still a total order and a sort cannot loop.
			arg_check(ctx, false, "xonly_pubkey_cmp: a pubkey is invalid")
		}
	}
	return c.int(mem.compare_ptrs(&out[0][0], &out[1][0], 32))
}

/*
Converts a full public key to its x-only form, reporting the discarded y parity.
*/
@(export, link_name = "secp256k1_xonly_pubkey_from_pubkey")
xonly_pubkey_from_pubkey :: proc "c" (
	ctx: ^Context,
	xonly_pubkey: ^Xonly_Pubkey,
	pk_parity: ^c.int,
	pubkey: ^Pubkey,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, xonly_pubkey != nil, "xonly_pubkey_from_pubkey: xonly_pubkey is null") {
		return 0
	}
	mem.zero(xonly_pubkey, size_of(Xonly_Pubkey))
	if !arg_check(ctx, pubkey != nil, "xonly_pubkey_from_pubkey: pubkey is null") {
		return 0
	}

	ge: group.Ge
	if !pubkey_load(&ge, pubkey) {
		return 0
	}
	xk: extrakeys.Xonly_Pubkey
	parity: bool
	if !extrakeys.xonly_pubkey_from_pubkey(&xk, &parity, &ge) {
		return 0
	}
	if pk_parity != nil {
		pk_parity^ = 1 if parity else 0
	}
	xonly_store(xonly_pubkey, &xk)
	return 1
}

/*
Adds `tweak*G` to an x-only public key, producing a full public key.

This is the Taproot output-key computation: the parity of the result matters and is why the
output is a full key rather than another x-only one.
*/
@(export, link_name = "secp256k1_xonly_pubkey_tweak_add")
xonly_pubkey_tweak_add :: proc "c" (
	ctx: ^Context,
	output_pubkey: ^Pubkey,
	internal_pubkey: ^Xonly_Pubkey,
	tweak32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output_pubkey != nil, "xonly_pubkey_tweak_add: output_pubkey is null") {
		return 0
	}
	mem.zero(output_pubkey, size_of(Pubkey))
	if !arg_check(ctx, internal_pubkey != nil, "xonly_pubkey_tweak_add: internal_pubkey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "xonly_pubkey_tweak_add: tweak32 is null") {
		return 0
	}

	xk: extrakeys.Xonly_Pubkey
	if !xonly_load(&xk, internal_pubkey) {
		return 0
	}
	out: group.Ge
	if !extrakeys.xonly_pubkey_tweak_add(&out, &xk, tweak32) {
		return 0
	}
	pubkey_store(output_pubkey, &out)
	return 1
}

/*
Checks that a serialized tweaked key and parity match a tweak applied to an internal key.

Cheaper than recomputing and comparing, and the operation a Taproot verifier actually needs.
*/
@(export, link_name = "secp256k1_xonly_pubkey_tweak_add_check")
xonly_pubkey_tweak_add_check :: proc "c" (
	ctx: ^Context,
	tweaked_pubkey32: ^[32]u8,
	tweaked_pk_parity: c.int,
	internal_pubkey: ^Xonly_Pubkey,
	tweak32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, tweaked_pubkey32 != nil, "xonly_pubkey_tweak_add_check: tweaked_pubkey32 is null") {
		return 0
	}
	if !arg_check(ctx, internal_pubkey != nil, "xonly_pubkey_tweak_add_check: internal_pubkey is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "xonly_pubkey_tweak_add_check: tweak32 is null") {
		return 0
	}

	xk: extrakeys.Xonly_Pubkey
	if !xonly_load(&xk, internal_pubkey) {
		return 0
	}
	ok := extrakeys.xonly_pubkey_tweak_add_check(
		tweaked_pubkey32,
		tweaked_pk_parity != 0,
		&xk,
		tweak32,
	)
	return 1 if ok else 0
}

// ---------------------------------------------------------------------------------------
// Keypairs.
// ---------------------------------------------------------------------------------------

/*
Creates a keypair from a secret key.

Holding both halves lets Schnorr signing skip re-deriving the public key, which is most of
the cost of a signature.
*/
@(export, link_name = "secp256k1_keypair_create")
keypair_create :: proc "c" (ctx: ^Context, keypair: ^Keypair, seckey: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "keypair_create: ctx is null") {
		return 0
	}
	if !arg_check(ctx, keypair != nil, "keypair_create: keypair is null") {
		return 0
	}
	mem.zero(keypair, size_of(Keypair))
	if !arg_check(ctx, seckey != nil, "keypair_create: seckey is null") {
		return 0
	}

	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !extrakeys.keypair_create(&ctx.inner.ecmult_gen_ctx, &kp, seckey) {
		return 0
	}
	kp_store(keypair, &kp)
	return 1
}

/*
Extracts the secret key from a keypair.
*/
@(export, link_name = "secp256k1_keypair_sec")
keypair_sec :: proc "c" (ctx: ^Context, seckey: ^[32]u8, keypair: ^Keypair) -> c.int {
	ensure_ready()
	if !arg_check(ctx, seckey != nil, "keypair_sec: seckey is null") {
		return 0
	}
	mem.zero(seckey, 32)
	if !arg_check(ctx, keypair != nil, "keypair_sec: keypair is null") {
		return 0
	}
	// The secret half is stored raw, so this is a copy rather than a scalar round trip.
	mem.copy(seckey, &keypair.data[0], 32)
	return 1
}

/*
Extracts the full public key from a keypair.
*/
@(export, link_name = "secp256k1_keypair_pub")
keypair_pub :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, keypair: ^Keypair) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "keypair_pub: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Pubkey))
	if !arg_check(ctx, keypair != nil, "keypair_pub: keypair is null") {
		return 0
	}
	// The public half is already in storage form; copy it across rather than round-tripping
	// through a live point.
	mem.copy(&pubkey.data[0], &keypair.data[32], 64)
	return 1
}

/*
Extracts the x-only public key from a keypair, reporting the discarded parity.
*/
@(export, link_name = "secp256k1_keypair_xonly_pub")
keypair_xonly_pub :: proc "c" (
	ctx: ^Context,
	pubkey: ^Xonly_Pubkey,
	pk_parity: ^c.int,
	keypair: ^Keypair,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "keypair_xonly_pub: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Xonly_Pubkey))
	if !arg_check(ctx, keypair != nil, "keypair_xonly_pub: keypair is null") {
		return 0
	}

	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !kp_load(&kp, keypair) {
		return 0
	}
	xk: extrakeys.Xonly_Pubkey
	parity: bool
	if !extrakeys.keypair_xonly_pub(&xk, &parity, &kp) {
		return 0
	}
	if pk_parity != nil {
		pk_parity^ = 1 if parity else 0
	}
	xonly_store(pubkey, &xk)
	return 1
}

/*
Tweaks a keypair as an x-only key, updating both halves.
*/
@(export, link_name = "secp256k1_keypair_xonly_tweak_add")
keypair_xonly_tweak_add :: proc "c" (
	ctx: ^Context,
	keypair: ^Keypair,
	tweak32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, keypair != nil, "keypair_xonly_tweak_add: keypair is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "keypair_xonly_tweak_add: tweak32 is null") {
		return 0
	}

	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !kp_load(&kp, keypair) {
		mem.zero(keypair, size_of(Keypair))
		return 0
	}
	if !extrakeys.keypair_xonly_tweak_add(&kp, tweak32) {
		mem.zero(keypair, size_of(Keypair))
		return 0
	}
	kp_store(keypair, &kp)
	return 1
}

// ---------------------------------------------------------------------------------------
// BIP340 Schnorr signatures.
// ---------------------------------------------------------------------------------------

/*
The C hardened nonce function type, matching upstream's
`secp256k1_nonce_function_hardened`.
*/
Nonce_Function_Hardened :: #type proc "c" (
	nonce32: ^[32]u8,
	msg: [^]u8,
	msglen: c.size_t,
	key32: ^[32]u8,
	xonly_pk32: ^[32]u8,
	algo: [^]u8,
	algolen: c.size_t,
	data: rawptr,
) -> c.int

/*
Extra parameters for `schnorrsig_sign_custom`, matching upstream's layout.

The magic field is how upstream detects a struct that was declared but never initialized
with its initializer macro — a real hazard in C, where an uninitialized `noncefp` is a wild
function pointer.
*/
Schnorrsig_Extraparams :: struct {
	magic:   [4]u8,
	noncefp: Nonce_Function_Hardened,
	ndata:   rawptr,
}

@(private)
EXTRAPARAMS_MAGIC :: [4]u8{0xda, 0x6f, 0xb3, 0x8c}

@(private)
schnorr_nonce_c_fn: Nonce_Function_Hardened
@(private)
schnorr_nonce_c_data: rawptr

/*
Bridges a C hardened nonce function to the Odin one the `schnorr` package calls.

A `proc "contextless"` cannot capture, and the package's callback signature has no user-data
parameter to thread one through, so the C pointer travels in these globals. That makes a
signing call with a *custom* nonce function non-reentrant; the default path, which is the
one every ordinary caller and the whole constant-time story uses, touches neither global.
*/
@(private)
schnorr_nonce_shim :: proc "contextless" (
	nonce32: ^[32]u8,
	msg: []u8,
	key32: ^[32]u8,
	xonly_pk32: ^[32]u8,
	algo: []u8,
	data: rawptr,
) -> bool {
	if schnorr_nonce_c_fn == nil {
		return false
	}
	m := raw_data(msg)
	a := raw_data(algo)
	return schnorr_nonce_c_fn(
		nonce32,
		m,
		c.size_t(len(msg)),
		key32,
		xonly_pk32,
		a,
		c.size_t(len(algo)),
		schnorr_nonce_c_data,
	) != 0
}

/*
`secp256k1_nonce_function_bip340` — the default BIP340 nonce function.

Exposed so a caller can name it explicitly in an extraparams struct.
*/
@(private)
nonce_function_bip340_c :: proc "c" (
	nonce32: ^[32]u8,
	msg: [^]u8,
	msglen: c.size_t,
	key32: ^[32]u8,
	xonly_pk32: ^[32]u8,
	algo: [^]u8,
	algolen: c.size_t,
	data: rawptr,
) -> c.int {
	if nonce32 == nil || key32 == nil || xonly_pk32 == nil {
		return 0
	}
	// Upstream rejects a call that names a different algorithm, so that a nonce function
	// installed for one scheme cannot silently serve another.
	want := transmute([]u8)string(schnorr.ALGO_BIP340)
	if algo == nil || int(algolen) != len(want) {
		return 0
	}
	for i in 0 ..< int(algolen) {
		if algo[i] != want[i] {
			return 0
		}
	}
	m := msg[:int(msglen)] if msglen > 0 else nil
	schnorr.nonce_function_bip340(nonce32, m, key32, xonly_pk32, (^[32]u8)(data))
	return 1
}

@(export, link_name = "secp256k1_nonce_function_bip340")
nonce_function_bip340: Nonce_Function_Hardened = nonce_function_bip340_c

@(private)
schnorrsig_sign_internal :: proc "contextless" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg: []u8,
	keypair: ^Keypair,
	aux_rand32: ^[32]u8,
	noncefp: Nonce_Function_Hardened,
	ndata: rawptr,
) -> c.int {
	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !kp_load(&kp, keypair) {
		mem.zero(sig64, 64)
		return 0
	}

	ok: bool
	if noncefp == nil || noncefp == nonce_function_bip340_c {
		ok = schnorr.sign(&ctx.inner.ecmult_gen_ctx, sig64, msg, &kp, aux_rand32)
	} else {
		schnorr_nonce_c_fn = noncefp
		schnorr_nonce_c_data = ndata
		ok = schnorr.sign(
			&ctx.inner.ecmult_gen_ctx,
			sig64,
			msg,
			&kp,
			aux_rand32,
			schnorr_nonce_shim,
			ndata,
		)
		schnorr_nonce_c_fn = nil
		schnorr_nonce_c_data = nil
	}
	return 1 if ok else 0
}

/*
Signs a 32-byte message with BIP340 Schnorr. `aux_rand32` may be null.
*/
@(export, link_name = "secp256k1_schnorrsig_sign32")
schnorrsig_sign32 :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg32: ^[32]u8,
	keypair: ^Keypair,
	aux_rand32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "schnorrsig_sign32: ctx is null") {
		return 0
	}
	if !arg_check(ctx, sig64 != nil, "schnorrsig_sign32: sig64 is null") {
		return 0
	}
	if !arg_check(ctx, msg32 != nil, "schnorrsig_sign32: msg32 is null") {
		return 0
	}
	if !arg_check(ctx, keypair != nil, "schnorrsig_sign32: keypair is null") {
		return 0
	}
	return schnorrsig_sign_internal(ctx, sig64, msg32[:], keypair, aux_rand32, nil, nil)
}

/*
The deprecated spelling of `schnorrsig_sign32`, kept for older consumers.
*/
@(export, link_name = "secp256k1_schnorrsig_sign")
schnorrsig_sign :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg32: ^[32]u8,
	keypair: ^Keypair,
	aux_rand32: ^[32]u8,
) -> c.int {
	return schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32)
}

/*
Signs a message of any length, with optional custom nonce derivation.
*/
@(export, link_name = "secp256k1_schnorrsig_sign_custom")
schnorrsig_sign_custom :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg: [^]u8,
	msglen: c.size_t,
	keypair: ^Keypair,
	extraparams: ^Schnorrsig_Extraparams,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "schnorrsig_sign_custom: ctx is null") {
		return 0
	}
	if !arg_check(ctx, sig64 != nil, "schnorrsig_sign_custom: sig64 is null") {
		return 0
	}
	if !arg_check(ctx, msg != nil || msglen == 0, "schnorrsig_sign_custom: msg is null") {
		return 0
	}
	if !arg_check(ctx, keypair != nil, "schnorrsig_sign_custom: keypair is null") {
		return 0
	}

	noncefp: Nonce_Function_Hardened
	ndata: rawptr
	if extraparams != nil {
		if !arg_check(
			ctx,
			extraparams.magic == EXTRAPARAMS_MAGIC,
			"schnorrsig_sign_custom: extraparams was not initialized with the magic macro",
		) {
			return 0
		}
		noncefp = extraparams.noncefp
		ndata = extraparams.ndata
	}

	m := msg[:int(msglen)] if msglen > 0 else nil
	// `ndata` doubles as the aux randomness for the default nonce function, which is what
	// upstream does: the extraparams struct is the only way to pass it for this entry point.
	return schnorrsig_sign_internal(ctx, sig64, m, keypair, (^[32]u8)(ndata), noncefp, ndata)
}

/*
Verifies a BIP340 Schnorr signature over a message of any length.
*/
@(export, link_name = "secp256k1_schnorrsig_verify")
schnorrsig_verify :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg: [^]u8,
	msglen: c.size_t,
	pubkey: ^Xonly_Pubkey,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig64 != nil, "schnorrsig_verify: sig64 is null") {
		return 0
	}
	if !arg_check(ctx, msg != nil || msglen == 0, "schnorrsig_verify: msg is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "schnorrsig_verify: pubkey is null") {
		return 0
	}

	xk: extrakeys.Xonly_Pubkey
	if !xonly_load(&xk, pubkey) {
		return 0
	}
	m := msg[:int(msglen)] if msglen > 0 else nil
	return 1 if schnorr.verify(sig64, m, &xk) else 0
}
