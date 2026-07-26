/*
MuSig2 key aggregation and multi-signature signing (BIP327).

Mirrors upstream's `secp256k1_musig.h`.

# The opaque blobs

MuSig2's six opaque types are the ABI's tightest constraint: a C caller declares them on its
own stack from its own header, so each must be exactly upstream's size. The packings below
are derived from the fields each type actually holds, and every one lands on the required
size with the bytes accounted for. The layouts are this implementation's own — the bytes are
not interchangeable with upstream's, which is true of upstream's own blobs across versions
too.

Each blob carries a magic prefix. That is not decoration either: passing a `secp256k1_musig_
secnonce` where a `pubnonce` belongs is a mistake C's type system does catch, but passing an
*uninitialized* one is not, and a signer that proceeds on garbage nonce state is precisely
the failure mode that leaks a key in MuSig2.

# Where the nonce danger is

`nonce_gen` writes a secret nonce that must never be reused across sessions or messages.
Upstream zeroes the caller's `session_secrand32` on success to make accidental reuse harder;
this does the same.
*/
package capi

import "base:runtime"
import "core:c"
import "core:mem"
import "../extrakeys"
import "../group"
import "../musig"
import "../scalar"

// ---------------------------------------------------------------------------------------
// Opaque types. The sizes are upstream's and are the ABI contract.
// ---------------------------------------------------------------------------------------

Musig_Keyagg_Cache :: struct {
	data: [197]u8,
}

Musig_Secnonce :: struct {
	data: [132]u8,
}

Musig_Pubnonce :: struct {
	data: [132]u8,
}

Musig_Aggnonce :: struct {
	data: [132]u8,
}

Musig_Session :: struct {
	data: [133]u8,
}

Musig_Partial_Sig :: struct {
	data: [36]u8,
}

#assert(size_of(Musig_Keyagg_Cache) == 197)
#assert(size_of(Musig_Secnonce) == 132)
#assert(size_of(Musig_Pubnonce) == 132)
#assert(size_of(Musig_Aggnonce) == 132)
#assert(size_of(Musig_Session) == 133)
#assert(size_of(Musig_Partial_Sig) == 36)

// Distinct three-byte tags, so a blob of one type passed where another belongs is rejected
// rather than silently reinterpreted.
@(private)
MAGIC_KEYAGG :: [3]u8{0xf4, 0xad, 0xbb}
@(private)
MAGIC_SECNONCE :: [3]u8{0x22, 0x0e, 0xdc}
@(private)
MAGIC_PUBNONCE :: [3]u8{0xf0, 0x7c, 0xa1}
@(private)
MAGIC_AGGNONCE :: [3]u8{0xa8, 0xb7, 0xe4}
@(private)
MAGIC_SESSION :: [3]u8{0x9e, 0x31, 0x4b}
@(private)
MAGIC_PARTIAL :: [3]u8{0x6b, 0xd2, 0x55}

@(private)
magic_write :: proc "contextless" (data: [^]u8, magic: [3]u8) {
	data[0] = magic[0]
	data[1] = magic[1]
	data[2] = magic[2]
}

@(private)
magic_ok :: proc "contextless" (data: [^]u8, magic: [3]u8) -> bool {
	return data[0] == magic[0] && data[1] == magic[1] && data[2] == magic[2]
}

/*
Writes a point into 64 bytes of storage, reporting whether it was the point at infinity.

`ge_to_storage` has no representation for infinity, and MuSig2 genuinely produces infinite
nonce points — a signer set whose nonces cancel is rare but legal, and BIP327 specifies its
handling rather than treating it as an error. The caller records the flag alongside.
*/
@(private)
point_store :: proc "contextless" (dst: [^]u8, ge: ^group.Ge) -> (infinite: bool) {
	if group.ge_is_infinity(ge) {
		mem.zero(dst, 64)
		return true
	}
	st: group.Ge_Storage
	group.ge_to_storage(&st, ge)
	mem.copy(dst, &st, size_of(group.Ge_Storage))
	return false
}

@(private)
point_load :: proc "contextless" (ge: ^group.Ge, src: [^]u8, infinite: bool) {
	if infinite {
		group.ge_set_infinity(ge)
		return
	}
	st: group.Ge_Storage
	mem.copy(&st, src, size_of(group.Ge_Storage))
	group.ge_from_storage(ge, &st)
}

// ---------------------------------------------------------------------------------------
// Keyagg cache: magic(3) flags(1) pk(64) second_pk(64) pks_hash(32) tweak(32) parity(1).
// ---------------------------------------------------------------------------------------

@(private)
cache_store :: proc "contextless" (dst: ^Musig_Keyagg_Cache, c_in: ^musig.Keyagg_Cache) {
	d := ([^]u8)(&dst.data[0])
	magic_write(d, MAGIC_KEYAGG)
	inf_pk := point_store(d[4:], &c_in.pk)
	inf_second := point_store(d[68:], &c_in.second_pk)
	d[3] = (1 if inf_pk else 0) | (2 if inf_second else 0)
	mem.copy(d[132:], &c_in.pks_hash[0], 32)
	scalar.scalar_get_b32((^[32]u8)(d[164:]), &c_in.tweak)
	d[196] = 1 if c_in.parity_acc else 0
}

@(private)
cache_load :: proc "contextless" (c_out: ^musig.Keyagg_Cache, src: ^Musig_Keyagg_Cache) -> bool {
	d := ([^]u8)(&src.data[0])
	if !magic_ok(d, MAGIC_KEYAGG) {
		return false
	}
	point_load(&c_out.pk, d[4:], d[3] & 1 != 0)
	point_load(&c_out.second_pk, d[68:], d[3] & 2 != 0)
	mem.copy(&c_out.pks_hash[0], d[132:], 32)
	scalar.scalar_set_b32(&c_out.tweak, (^[32]u8)(d[164:]))
	c_out.parity_acc = d[196] != 0
	return true
}

// ---------------------------------------------------------------------------------------
// Secnonce: magic(3) valid(1) k0(32) k1(32) pk(64).
// ---------------------------------------------------------------------------------------

@(private)
secnonce_store :: proc "contextless" (dst: ^Musig_Secnonce, n: ^musig.Secnonce) {
	d := ([^]u8)(&dst.data[0])
	magic_write(d, MAGIC_SECNONCE)
	d[3] = 1 if n.valid else 0
	scalar.scalar_get_b32((^[32]u8)(d[4:]), &n.k[0])
	scalar.scalar_get_b32((^[32]u8)(d[36:]), &n.k[1])
	point_store(d[68:], &n.pk)
}

@(private)
secnonce_load :: proc "contextless" (n: ^musig.Secnonce, src: ^Musig_Secnonce) -> bool {
	d := ([^]u8)(&src.data[0])
	if !magic_ok(d, MAGIC_SECNONCE) {
		return false
	}
	n.valid = d[3] != 0
	scalar.scalar_set_b32(&n.k[0], (^[32]u8)(d[4:]))
	scalar.scalar_set_b32(&n.k[1], (^[32]u8)(d[36:]))
	point_load(&n.pk, d[68:], false)
	return true
}

// ---------------------------------------------------------------------------------------
// Pub/agg nonce: magic(3) flags(1) pt0(64) pt1(64).
// ---------------------------------------------------------------------------------------

@(private)
nonce_pts_store :: proc "contextless" (dst: [^]u8, magic: [3]u8, pts: ^[2]group.Ge) {
	magic_write(dst, magic)
	inf0 := point_store(dst[4:], &pts[0])
	inf1 := point_store(dst[68:], &pts[1])
	dst[3] = (1 if inf0 else 0) | (2 if inf1 else 0)
}

@(private)
nonce_pts_load :: proc "contextless" (pts: ^[2]group.Ge, src: [^]u8, magic: [3]u8) -> bool {
	if !magic_ok(src, magic) {
		return false
	}
	point_load(&pts[0], src[4:], src[3] & 1 != 0)
	point_load(&pts[1], src[68:], src[3] & 2 != 0)
	return true
}

@(private)
pubnonce_store :: proc "contextless" (dst: ^Musig_Pubnonce, n: ^musig.Pubnonce) {
	nonce_pts_store(([^]u8)(&dst.data[0]), MAGIC_PUBNONCE, &n.pt)
}

@(private)
pubnonce_load :: proc "contextless" (n: ^musig.Pubnonce, src: ^Musig_Pubnonce) -> bool {
	return nonce_pts_load(&n.pt, ([^]u8)(&src.data[0]), MAGIC_PUBNONCE)
}

@(private)
aggnonce_store :: proc "contextless" (dst: ^Musig_Aggnonce, n: ^musig.Aggnonce) {
	nonce_pts_store(([^]u8)(&dst.data[0]), MAGIC_AGGNONCE, &n.pt)
}

@(private)
aggnonce_load :: proc "contextless" (n: ^musig.Aggnonce, src: ^Musig_Aggnonce) -> bool {
	return nonce_pts_load(&n.pt, ([^]u8)(&src.data[0]), MAGIC_AGGNONCE)
}

// ---------------------------------------------------------------------------------------
// Session: magic(3) pad(1) fin_nonce(32) noncecoef(32) challenge(32) s_part(32) parity(1).
// ---------------------------------------------------------------------------------------

@(private)
session_store :: proc "contextless" (dst: ^Musig_Session, s: ^musig.Session) {
	d := ([^]u8)(&dst.data[0])
	magic_write(d, MAGIC_SESSION)
	d[3] = 0
	mem.copy(d[4:], &s.fin_nonce[0], 32)
	scalar.scalar_get_b32((^[32]u8)(d[36:]), &s.noncecoef)
	scalar.scalar_get_b32((^[32]u8)(d[68:]), &s.challenge)
	scalar.scalar_get_b32((^[32]u8)(d[100:]), &s.s_part)
	d[132] = 1 if s.fin_nonce_parity else 0
}

@(private)
session_load :: proc "contextless" (s: ^musig.Session, src: ^Musig_Session) -> bool {
	d := ([^]u8)(&src.data[0])
	if !magic_ok(d, MAGIC_SESSION) {
		return false
	}
	mem.copy(&s.fin_nonce[0], d[4:], 32)
	scalar.scalar_set_b32(&s.noncecoef, (^[32]u8)(d[36:]))
	scalar.scalar_set_b32(&s.challenge, (^[32]u8)(d[68:]))
	scalar.scalar_set_b32(&s.s_part, (^[32]u8)(d[100:]))
	s.fin_nonce_parity = d[132] != 0
	return true
}

// ---------------------------------------------------------------------------------------
// Partial signature: magic(3) pad(1) s(32).
// ---------------------------------------------------------------------------------------

@(private)
psig_store :: proc "contextless" (dst: ^Musig_Partial_Sig, p: ^musig.Partial_Sig) {
	d := ([^]u8)(&dst.data[0])
	magic_write(d, MAGIC_PARTIAL)
	d[3] = 0
	scalar.scalar_get_b32((^[32]u8)(d[4:]), &p.s)
}

@(private)
psig_load :: proc "contextless" (p: ^musig.Partial_Sig, src: ^Musig_Partial_Sig) -> bool {
	d := ([^]u8)(&src.data[0])
	if !magic_ok(d, MAGIC_PARTIAL) {
		return false
	}
	scalar.scalar_set_b32(&p.s, (^[32]u8)(d[4:]))
	return true
}

// ---------------------------------------------------------------------------------------
// Serialization.
// ---------------------------------------------------------------------------------------

/*
Parses a public nonce from its 66-byte wire form.
*/
@(export, link_name = "secp256k1_musig_pubnonce_parse")
musig_pubnonce_parse :: proc "c" (
	ctx: ^Context,
	nonce: ^Musig_Pubnonce,
	in66: ^[66]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, nonce != nil, "musig_pubnonce_parse: nonce is null") {
		return 0
	}
	if !arg_check(ctx, in66 != nil, "musig_pubnonce_parse: in66 is null") {
		return 0
	}
	n: musig.Pubnonce
	if !musig.pubnonce_parse(&n, in66) {
		return 0
	}
	pubnonce_store(nonce, &n)
	return 1
}

/*
Serializes a public nonce as 66 bytes: two compressed points.
*/
@(export, link_name = "secp256k1_musig_pubnonce_serialize")
musig_pubnonce_serialize :: proc "c" (
	ctx: ^Context,
	out66: ^[66]u8,
	nonce: ^Musig_Pubnonce,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, out66 != nil, "musig_pubnonce_serialize: out66 is null") {
		return 0
	}
	if !arg_check(ctx, nonce != nil, "musig_pubnonce_serialize: nonce is null") {
		return 0
	}
	n: musig.Pubnonce
	if !arg_check(ctx, pubnonce_load(&n, nonce), "musig_pubnonce_serialize: nonce is invalid") {
		return 0
	}
	musig.pubnonce_serialize(out66, &n)
	return 1
}

/*
Parses an aggregate nonce from its 66-byte wire form.
*/
@(export, link_name = "secp256k1_musig_aggnonce_parse")
musig_aggnonce_parse :: proc "c" (
	ctx: ^Context,
	nonce: ^Musig_Aggnonce,
	in66: ^[66]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, nonce != nil, "musig_aggnonce_parse: nonce is null") {
		return 0
	}
	if !arg_check(ctx, in66 != nil, "musig_aggnonce_parse: in66 is null") {
		return 0
	}
	n: musig.Aggnonce
	if !musig.aggnonce_parse(&n, in66) {
		return 0
	}
	aggnonce_store(nonce, &n)
	return 1
}

/*
Serializes an aggregate nonce as 66 bytes.

An infinite component serializes as 33 zero bytes, which BIP327 specifies rather than
treating as an error.
*/
@(export, link_name = "secp256k1_musig_aggnonce_serialize")
musig_aggnonce_serialize :: proc "c" (
	ctx: ^Context,
	out66: ^[66]u8,
	nonce: ^Musig_Aggnonce,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, out66 != nil, "musig_aggnonce_serialize: out66 is null") {
		return 0
	}
	if !arg_check(ctx, nonce != nil, "musig_aggnonce_serialize: nonce is null") {
		return 0
	}
	n: musig.Aggnonce
	if !arg_check(ctx, aggnonce_load(&n, nonce), "musig_aggnonce_serialize: nonce is invalid") {
		return 0
	}
	musig.aggnonce_serialize(out66, &n)
	return 1
}

/*
Parses a partial signature from 32 bytes.
*/
@(export, link_name = "secp256k1_musig_partial_sig_parse")
musig_partial_sig_parse :: proc "c" (
	ctx: ^Context,
	sig: ^Musig_Partial_Sig,
	in32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "musig_partial_sig_parse: sig is null") {
		return 0
	}
	if !arg_check(ctx, in32 != nil, "musig_partial_sig_parse: in32 is null") {
		return 0
	}
	p: musig.Partial_Sig
	if !musig.partial_sig_parse(&p, in32) {
		return 0
	}
	psig_store(sig, &p)
	return 1
}

/*
Serializes a partial signature as 32 bytes.
*/
@(export, link_name = "secp256k1_musig_partial_sig_serialize")
musig_partial_sig_serialize :: proc "c" (
	ctx: ^Context,
	out32: ^[32]u8,
	sig: ^Musig_Partial_Sig,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, out32 != nil, "musig_partial_sig_serialize: out32 is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "musig_partial_sig_serialize: sig is null") {
		return 0
	}
	p: musig.Partial_Sig
	if !arg_check(ctx, psig_load(&p, sig), "musig_partial_sig_serialize: sig is invalid") {
		return 0
	}
	musig.partial_sig_serialize(out32, &p)
	return 1
}

// ---------------------------------------------------------------------------------------
// Key aggregation.
// ---------------------------------------------------------------------------------------

/*
Aggregates public keys into a single x-only key, and fills a cache for later steps.

The keys are used in the order given; `ec_pubkey_sort` produces the canonical order if the
protocol calls for one.

Unlike the rest of this library, this allocates: the internal routine takes a slice of
points and a C caller supplies an array of pointers, so the keys have to be gathered. That
is a property of the boundary, not of the arithmetic, and it fails cleanly if the allocation
does.
*/
@(export, link_name = "secp256k1_musig_pubkey_agg")
musig_pubkey_agg :: proc "c" (
	ctx: ^Context,
	agg_pk: ^Xonly_Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
	pubkeys: [^]^Pubkey,
	n_pubkeys: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkeys != nil, "musig_pubkey_agg: pubkeys is null") {
		return 0
	}
	if !arg_check(ctx, n_pubkeys > 0, "musig_pubkey_agg: n_pubkeys is zero") {
		return 0
	}
	if agg_pk != nil {
		mem.zero(agg_pk, size_of(Xonly_Pubkey))
	}
	context = runtime.default_context()

	n := int(n_pubkeys)
	keys := make([]group.Ge, n)
	if keys == nil {
		call_error(ctx, "musig_pubkey_agg: out of memory")
		return 0
	}
	defer delete(keys)

	for i in 0 ..< n {
		if !arg_check(ctx, pubkeys[i] != nil, "musig_pubkey_agg: a pubkey is null") {
			return 0
		}
		if !pubkey_load(&keys[i], pubkeys[i]) {
			return 0
		}
	}

	cache: musig.Keyagg_Cache
	xk: extrakeys.Xonly_Pubkey
	if !musig.pubkey_agg(&xk, &cache, keys) {
		return 0
	}
	if agg_pk != nil {
		xonly_store(agg_pk, &xk)
	}
	if keyagg_cache != nil {
		cache_store(keyagg_cache, &cache)
	}
	return 1
}

/*
Recovers the aggregate public key, including applied tweaks, from a cache.

The result is a full public key rather than an x-only one, because a tweaked aggregate key
has a parity that later steps need.
*/
@(export, link_name = "secp256k1_musig_pubkey_get")
musig_pubkey_get :: proc "c" (
	ctx: ^Context,
	agg_pk: ^Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, agg_pk != nil, "musig_pubkey_get: agg_pk is null") {
		return 0
	}
	mem.zero(agg_pk, size_of(Pubkey))
	if !arg_check(ctx, keyagg_cache != nil, "musig_pubkey_get: keyagg_cache is null") {
		return 0
	}
	cache: musig.Keyagg_Cache
	if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig_pubkey_get: cache is invalid") {
		return 0
	}
	pubkey_store(agg_pk, &cache.pk)
	return 1
}

@(private)
musig_tweak_add :: proc "contextless" (
	ctx: ^Context,
	output_pubkey: ^Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
	tweak32: ^[32]u8,
	xonly: bool,
	what: string,
) -> c.int {
	if output_pubkey != nil {
		mem.zero(output_pubkey, size_of(Pubkey))
	}
	if !arg_check(ctx, keyagg_cache != nil, "musig tweak: keyagg_cache is null") {
		return 0
	}
	if !arg_check(ctx, tweak32 != nil, "musig tweak: tweak32 is null") {
		return 0
	}
	cache: musig.Keyagg_Cache
	if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig tweak: cache is invalid") {
		return 0
	}

	out: group.Ge
	ok := musig.pubkey_xonly_tweak_add(&out, &cache, tweak32) if xonly else musig.pubkey_ec_tweak_add(&out, &cache, tweak32)
	if !ok {
		return 0
	}
	// The cache accumulates the tweak, so it must be written back even when the caller does
	// not want the resulting point.
	cache_store(keyagg_cache, &cache)
	if output_pubkey != nil {
		pubkey_store(output_pubkey, &out)
	}
	return 1
}

/*
Applies an x-only (Taproot-style) tweak to an aggregate key, updating the cache.
*/
@(export, link_name = "secp256k1_musig_pubkey_xonly_tweak_add")
musig_pubkey_xonly_tweak_add :: proc "c" (
	ctx: ^Context,
	output_pubkey: ^Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
	tweak32: ^[32]u8,
) -> c.int {
	ensure_ready()
	return musig_tweak_add(ctx, output_pubkey, keyagg_cache, tweak32, true, "xonly")
}

/*
Applies a plain EC (BIP32-style) tweak to an aggregate key, updating the cache.
*/
@(export, link_name = "secp256k1_musig_pubkey_ec_tweak_add")
musig_pubkey_ec_tweak_add :: proc "c" (
	ctx: ^Context,
	output_pubkey: ^Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
	tweak32: ^[32]u8,
) -> c.int {
	ensure_ready()
	return musig_tweak_add(ctx, output_pubkey, keyagg_cache, tweak32, false, "ec")
}

// ---------------------------------------------------------------------------------------
// Nonces.
// ---------------------------------------------------------------------------------------

/*
Extracts the aggregate key's x coordinate from a cache, for nonce binding.
*/
@(private)
cache_agg_pk32 :: proc "contextless" (out32: ^[32]u8, cache: ^musig.Keyagg_Cache) -> bool {
	xk: extrakeys.Xonly_Pubkey
	c_local := cache^
	if !musig.pubkey_get(&xk, &c_local) {
		return false
	}
	extrakeys.xonly_pubkey_serialize(out32, &xk)
	return true
}

@(private)
musig_nonce_gen_internal :: proc "contextless" (
	ctx: ^Context,
	secnonce: ^Musig_Secnonce,
	pubnonce: ^Musig_Pubnonce,
	session_secrand32: ^[32]u8,
	seckey: ^[32]u8,
	pk: ^group.Ge,
	msg32: ^[32]u8,
	keyagg_cache: ^Musig_Keyagg_Cache,
	extra_input32: ^[32]u8,
) -> c.int {
	agg_pk32: [32]u8
	agg_pk_ptr: ^[32]u8
	if keyagg_cache != nil {
		cache: musig.Keyagg_Cache
		if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig_nonce_gen: cache is invalid") {
			return 0
		}
		if !cache_agg_pk32(&agg_pk32, &cache) {
			return 0
		}
		agg_pk_ptr = &agg_pk32
	}

	sn: musig.Secnonce
	pn: musig.Pubnonce
	ok := musig.nonce_gen(
		&ctx.inner.ecmult_gen_ctx,
		&sn,
		&pn,
		session_secrand32,
		seckey,
		pk,
		msg32,
		agg_pk_ptr,
		extra_input32,
	)
	if !ok {
		musig.secnonce_clear(&sn)
		return 0
	}

	secnonce_store(secnonce, &sn)
	musig.secnonce_clear(&sn)
	if pubnonce != nil {
		pubnonce_store(pubnonce, &pn)
	}
	return 1
}

/*
Generates a secret nonce and its public counterpart.

`session_secrand32` must be uniformly random and is **zeroed on success**, because reusing a
nonce across sessions reveals the secret key — the single sharpest edge in MuSig2. Zeroing
it makes the mistake visible rather than silent.
*/
@(export, link_name = "secp256k1_musig_nonce_gen")
musig_nonce_gen :: proc "c" (
	ctx: ^Context,
	secnonce: ^Musig_Secnonce,
	pubnonce: ^Musig_Pubnonce,
	session_secrand32: ^[32]u8,
	seckey: ^[32]u8,
	pubkey: ^Pubkey,
	msg32: ^[32]u8,
	keyagg_cache: ^Musig_Keyagg_Cache,
	extra_input32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "musig_nonce_gen: ctx is null") {
		return 0
	}
	if !arg_check(ctx, secnonce != nil, "musig_nonce_gen: secnonce is null") {
		return 0
	}
	mem.zero(secnonce, size_of(Musig_Secnonce))
	if !arg_check(ctx, session_secrand32 != nil, "musig_nonce_gen: session_secrand32 is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "musig_nonce_gen: pubkey is null") {
		return 0
	}

	pk: group.Ge
	if !pubkey_load(&pk, pubkey) {
		return 0
	}

	ret := musig_nonce_gen_internal(
		ctx,
		secnonce,
		pubnonce,
		session_secrand32,
		seckey,
		&pk,
		msg32,
		keyagg_cache,
		extra_input32,
	)
	if ret == 1 {
		mem.zero_explicit(session_secrand32, 32)
	}
	return ret
}

/*
Generates a nonce from a counter rather than fresh randomness.

Safe only if the counter genuinely never repeats for this key — which is a stronger promise
than it sounds, since it has to survive process restarts, restores from backup, and running
two copies of the signer.
*/
@(export, link_name = "secp256k1_musig_nonce_gen_counter")
musig_nonce_gen_counter :: proc "c" (
	ctx: ^Context,
	secnonce: ^Musig_Secnonce,
	pubnonce: ^Musig_Pubnonce,
	nonrepeating_cnt: u64,
	keypair: ^Keypair,
	msg32: ^[32]u8,
	keyagg_cache: ^Musig_Keyagg_Cache,
	extra_input32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "musig_nonce_gen_counter: ctx is null") {
		return 0
	}
	if !arg_check(ctx, secnonce != nil, "musig_nonce_gen_counter: secnonce is null") {
		return 0
	}
	mem.zero(secnonce, size_of(Musig_Secnonce))
	if !arg_check(ctx, keypair != nil, "musig_nonce_gen_counter: keypair is null") {
		return 0
	}

	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !kp_load(&kp, keypair) {
		return 0
	}

	// The counter takes the place of the random session value, big-endian in the first eight
	// bytes and zero elsewhere, matching upstream so the two derive identical nonces.
	buf: [32]u8
	defer mem.zero_explicit(&buf, 32)
	for i in 0 ..< 8 {
		buf[i] = u8(nonrepeating_cnt >> uint(56 - 8 * i))
	}

	seckey: [32]u8
	defer mem.zero_explicit(&seckey, 32)
	scalar.scalar_get_b32(&seckey, &kp.seckey)

	return musig_nonce_gen_internal(
		ctx,
		secnonce,
		pubnonce,
		&buf,
		&seckey,
		&kp.pubkey,
		msg32,
		keyagg_cache,
		extra_input32,
	)
}

/*
Sums the participants' public nonces.
*/
@(export, link_name = "secp256k1_musig_nonce_agg")
musig_nonce_agg :: proc "c" (
	ctx: ^Context,
	aggnonce: ^Musig_Aggnonce,
	pubnonces: [^]^Musig_Pubnonce,
	n_pubnonces: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, aggnonce != nil, "musig_nonce_agg: aggnonce is null") {
		return 0
	}
	mem.zero(aggnonce, size_of(Musig_Aggnonce))
	if !arg_check(ctx, pubnonces != nil, "musig_nonce_agg: pubnonces is null") {
		return 0
	}
	if !arg_check(ctx, n_pubnonces > 0, "musig_nonce_agg: n_pubnonces is zero") {
		return 0
	}
	context = runtime.default_context()

	n := int(n_pubnonces)
	nonces := make([]musig.Pubnonce, n)
	if nonces == nil {
		call_error(ctx, "musig_nonce_agg: out of memory")
		return 0
	}
	defer delete(nonces)

	for i in 0 ..< n {
		if !arg_check(ctx, pubnonces[i] != nil, "musig_nonce_agg: a pubnonce is null") {
			return 0
		}
		if !arg_check(
			ctx,
			pubnonce_load(&nonces[i], pubnonces[i]),
			"musig_nonce_agg: a pubnonce is invalid",
		) {
			return 0
		}
	}

	agg: musig.Aggnonce
	if !musig.nonce_agg(&agg, nonces) {
		return 0
	}
	aggnonce_store(aggnonce, &agg)
	return 1
}

/*
Builds the signing session from the aggregate nonce, message and key cache.
*/
@(export, link_name = "secp256k1_musig_nonce_process")
musig_nonce_process :: proc "c" (
	ctx: ^Context,
	session: ^Musig_Session,
	aggnonce: ^Musig_Aggnonce,
	msg32: ^[32]u8,
	keyagg_cache: ^Musig_Keyagg_Cache,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, session != nil, "musig_nonce_process: session is null") {
		return 0
	}
	if !arg_check(ctx, aggnonce != nil, "musig_nonce_process: aggnonce is null") {
		return 0
	}
	if !arg_check(ctx, msg32 != nil, "musig_nonce_process: msg32 is null") {
		return 0
	}
	if !arg_check(ctx, keyagg_cache != nil, "musig_nonce_process: keyagg_cache is null") {
		return 0
	}

	agg: musig.Aggnonce
	if !arg_check(ctx, aggnonce_load(&agg, aggnonce), "musig_nonce_process: aggnonce is invalid") {
		return 0
	}
	cache: musig.Keyagg_Cache
	if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig_nonce_process: cache is invalid") {
		return 0
	}

	s: musig.Session
	if !musig.nonce_process(&s, &agg, msg32, &cache) {
		return 0
	}
	session_store(session, &s)
	return 1
}

// ---------------------------------------------------------------------------------------
// Signing.
// ---------------------------------------------------------------------------------------

/*
Produces this signer's partial signature.

The secret nonce is consumed: it is zeroed whether or not signing succeeds, so the same
nonce cannot be used twice even by a caller that ignores the return value.
*/
@(export, link_name = "secp256k1_musig_partial_sign")
musig_partial_sign :: proc "c" (
	ctx: ^Context,
	partial_sig: ^Musig_Partial_Sig,
	secnonce: ^Musig_Secnonce,
	keypair: ^Keypair,
	keyagg_cache: ^Musig_Keyagg_Cache,
	session: ^Musig_Session,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, partial_sig != nil, "musig_partial_sign: partial_sig is null") {
		return 0
	}
	mem.zero(partial_sig, size_of(Musig_Partial_Sig))
	if !arg_check(ctx, secnonce != nil, "musig_partial_sign: secnonce is null") {
		return 0
	}

	sn: musig.Secnonce
	loaded := secnonce_load(&sn, secnonce)
	// Consume the caller's copy first, so that every path out of here — including the
	// failures below — leaves it unusable.
	mem.zero_explicit(secnonce, size_of(Musig_Secnonce))
	defer musig.secnonce_clear(&sn)

	if !arg_check(ctx, loaded, "musig_partial_sign: secnonce is invalid") {
		return 0
	}
	if !arg_check(ctx, keypair != nil, "musig_partial_sign: keypair is null") {
		return 0
	}
	if !arg_check(ctx, keyagg_cache != nil, "musig_partial_sign: keyagg_cache is null") {
		return 0
	}
	if !arg_check(ctx, session != nil, "musig_partial_sign: session is null") {
		return 0
	}

	kp: extrakeys.Keypair
	defer extrakeys.keypair_clear(&kp)
	if !kp_load(&kp, keypair) {
		return 0
	}
	cache: musig.Keyagg_Cache
	if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig_partial_sign: cache is invalid") {
		return 0
	}
	s: musig.Session
	if !arg_check(ctx, session_load(&s, session), "musig_partial_sign: session is invalid") {
		return 0
	}

	p: musig.Partial_Sig
	if !musig.partial_sign(&p, &sn, &kp, &cache, &s) {
		return 0
	}
	psig_store(partial_sig, &p)
	return 1
}

/*
Verifies one signer's partial signature against their public nonce and key.

Worth doing before aggregation: an invalid aggregate signature says only that *someone*
cheated, while this says who.
*/
@(export, link_name = "secp256k1_musig_partial_sig_verify")
musig_partial_sig_verify :: proc "c" (
	ctx: ^Context,
	partial_sig: ^Musig_Partial_Sig,
	pubnonce: ^Musig_Pubnonce,
	pubkey: ^Pubkey,
	keyagg_cache: ^Musig_Keyagg_Cache,
	session: ^Musig_Session,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, partial_sig != nil, "musig_partial_sig_verify: partial_sig is null") {
		return 0
	}
	if !arg_check(ctx, pubnonce != nil, "musig_partial_sig_verify: pubnonce is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "musig_partial_sig_verify: pubkey is null") {
		return 0
	}
	if !arg_check(ctx, keyagg_cache != nil, "musig_partial_sig_verify: keyagg_cache is null") {
		return 0
	}
	if !arg_check(ctx, session != nil, "musig_partial_sig_verify: session is null") {
		return 0
	}

	p: musig.Partial_Sig
	if !arg_check(ctx, psig_load(&p, partial_sig), "musig_partial_sig_verify: sig is invalid") {
		return 0
	}
	pn: musig.Pubnonce
	if !arg_check(ctx, pubnonce_load(&pn, pubnonce), "musig_partial_sig_verify: pubnonce is invalid") {
		return 0
	}
	pk: group.Ge
	if !pubkey_load(&pk, pubkey) {
		return 0
	}
	cache: musig.Keyagg_Cache
	if !arg_check(ctx, cache_load(&cache, keyagg_cache), "musig_partial_sig_verify: cache is invalid") {
		return 0
	}
	s: musig.Session
	if !arg_check(ctx, session_load(&s, session), "musig_partial_sig_verify: session is invalid") {
		return 0
	}

	return 1 if musig.partial_sig_verify(&p, &pn, &pk, &cache, &s) else 0
}

/*
Aggregates partial signatures into a single BIP340 Schnorr signature.

The result verifies under the aggregate key with an ordinary `schnorrsig_verify` — that
indistinguishability is the point of MuSig2.
*/
@(export, link_name = "secp256k1_musig_partial_sig_agg")
musig_partial_sig_agg :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	session: ^Musig_Session,
	partial_sigs: [^]^Musig_Partial_Sig,
	n_sigs: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig64 != nil, "musig_partial_sig_agg: sig64 is null") {
		return 0
	}
	if !arg_check(ctx, session != nil, "musig_partial_sig_agg: session is null") {
		return 0
	}
	if !arg_check(ctx, partial_sigs != nil, "musig_partial_sig_agg: partial_sigs is null") {
		return 0
	}
	if !arg_check(ctx, n_sigs > 0, "musig_partial_sig_agg: n_sigs is zero") {
		return 0
	}
	context = runtime.default_context()

	s: musig.Session
	if !arg_check(ctx, session_load(&s, session), "musig_partial_sig_agg: session is invalid") {
		return 0
	}

	n := int(n_sigs)
	sigs := make([]musig.Partial_Sig, n)
	if sigs == nil {
		call_error(ctx, "musig_partial_sig_agg: out of memory")
		return 0
	}
	defer delete(sigs)

	for i in 0 ..< n {
		if !arg_check(ctx, partial_sigs[i] != nil, "musig_partial_sig_agg: a sig is null") {
			return 0
		}
		if !arg_check(
			ctx,
			psig_load(&sigs[i], partial_sigs[i]),
			"musig_partial_sig_agg: a sig is invalid",
		) {
			return 0
		}
	}

	if !musig.partial_sig_agg(sig64, &s, sigs) {
		return 0
	}
	return 1
}
