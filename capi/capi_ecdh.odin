/*
ECDH shared secrets and the ElligatorSwift encoding used by BIP324.

Mirrors upstream's `secp256k1_ecdh.h` and `secp256k1_ellswift.h`.

# How the caller's hash function reaches the library

Both modules let a caller replace the hash applied to the shared point. The internal
callback types take an Odin slice and a `data` pointer; the C types take raw pointers. The
bridge packs the C function pointer and the caller's data into a struct, passes a pointer to
*that* as the internal `data`, and unpacks it in a shim. This keeps the trampoline
reentrant, unlike a global — which matters here because ECDH is exactly the sort of call a
server makes from several threads at once.
*/
package capi

import "core:c"
import "core:mem"
import "../ecdh"
import "../ellswift"
import "../group"

// ---------------------------------------------------------------------------------------
// ECDH.
// ---------------------------------------------------------------------------------------

/*
The C ECDH hash function type, matching upstream's `secp256k1_ecdh_hash_function`.
*/
Ecdh_Hash_Function :: #type proc "c" (
	output: [^]u8,
	x32: ^[32]u8,
	y32: ^[32]u8,
	data: rawptr,
) -> c.int

@(private)
Ecdh_Trampoline :: struct {
	fn:   Ecdh_Hash_Function,
	data: rawptr,
}

@(private)
ecdh_shim :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	y32: ^[32]u8,
	data: rawptr,
) -> bool {
	t := (^Ecdh_Trampoline)(data)
	if t == nil || t.fn == nil {
		return false
	}
	return t.fn(raw_data(output), x32, y32, t.data) != 0
}

@(private)
ecdh_hash_function_sha256_c :: proc "c" (
	output: [^]u8,
	x32: ^[32]u8,
	y32: ^[32]u8,
	data: rawptr,
) -> c.int {
	if output == nil || x32 == nil || y32 == nil {
		return 0
	}
	return 1 if ecdh.hash_function_sha256(output[:32], x32, y32, data) else 0
}

/*
`secp256k1_ecdh_hash_function_sha256` — SHA256 of the compressed shared point.
*/
@(export, link_name = "secp256k1_ecdh_hash_function_sha256")
ecdh_hash_function_sha256: Ecdh_Hash_Function = ecdh_hash_function_sha256_c

/*
`secp256k1_ecdh_hash_function_default` — an alias for the SHA256 function above.
*/
@(export, link_name = "secp256k1_ecdh_hash_function_default")
ecdh_hash_function_default: Ecdh_Hash_Function = ecdh_hash_function_sha256_c

/*
Computes an ECDH shared secret.

With a null `hashfp` the result is SHA256 of the compressed shared point, which is what
almost every consumer wants and the only form with a test vector corpus behind it.
*/
@(export, link_name = "secp256k1_ecdh")
ecdh_c :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	pubkey: ^Pubkey,
	seckey: ^[32]u8,
	hashfp: Ecdh_Hash_Function,
	data: rawptr,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output != nil, "ecdh: output is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "ecdh: pubkey is null") {
		return 0
	}
	if !arg_check(ctx, seckey != nil, "ecdh: seckey is null") {
		return 0
	}

	ge: group.Ge
	if !pubkey_load(&ge, pubkey) {
		return 0
	}

	if hashfp == nil || hashfp == ecdh_hash_function_sha256_c {
		// The default path writes exactly 32 bytes and is the one the vectors cover.
		return 1 if ecdh.ecdh(output[:32], &ge, seckey) else 0
	}

	// A custom function decides its own output length, so the slice handed to it carries the
	// pointer and nothing more; the C signature has no length either.
	t := Ecdh_Trampoline {
		fn   = hashfp,
		data = data,
	}
	return 1 if ecdh.ecdh(output[:0], &ge, seckey, ecdh_shim, &t) else 0
}

// ---------------------------------------------------------------------------------------
// ElligatorSwift.
// ---------------------------------------------------------------------------------------

/*
The C ellswift x-only DH hash function type.
*/
Ellswift_Xdh_Hash_Function :: #type proc "c" (
	output: [^]u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> c.int

@(private)
Xdh_Trampoline :: struct {
	fn:   Ellswift_Xdh_Hash_Function,
	data: rawptr,
}

@(private)
xdh_shim :: proc "contextless" (
	output: []u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> bool {
	t := (^Xdh_Trampoline)(data)
	if t == nil || t.fn == nil {
		return false
	}
	return t.fn(raw_data(output), x32, ell_a64, ell_b64, t.data) != 0
}

@(private)
xdh_hash_function_prefix_c :: proc "c" (
	output: [^]u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> c.int {
	if output == nil || x32 == nil || ell_a64 == nil || ell_b64 == nil {
		return 0
	}
	return 1 if ellswift.xdh_hash_function_prefix(output[:32], x32, ell_a64, ell_b64, data) else 0
}

@(private)
xdh_hash_function_bip324_c :: proc "c" (
	output: [^]u8,
	x32: ^[32]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	data: rawptr,
) -> c.int {
	if output == nil || x32 == nil || ell_a64 == nil || ell_b64 == nil {
		return 0
	}
	return 1 if ellswift.xdh_hash_function_bip324(output[:32], x32, ell_a64, ell_b64, data) else 0
}

/*
`secp256k1_ellswift_xdh_hash_function_prefix` — SHA256 of a caller-supplied prefix followed
by the two encodings and the shared x coordinate.
*/
@(export, link_name = "secp256k1_ellswift_xdh_hash_function_prefix")
ellswift_xdh_hash_function_prefix: Ellswift_Xdh_Hash_Function = xdh_hash_function_prefix_c

/*
`secp256k1_ellswift_xdh_hash_function_bip324` — the BIP324 v2 transport key derivation.
*/
@(export, link_name = "secp256k1_ellswift_xdh_hash_function_bip324")
ellswift_xdh_hash_function_bip324: Ellswift_Xdh_Hash_Function = xdh_hash_function_bip324_c

/*
Encodes a public key as 64 bytes indistinguishable from uniform randomness.

`rnd32` must be uniformly random and must not be reused across keys: it is what makes the
encoding hiding rather than merely reversible.
*/
@(export, link_name = "secp256k1_ellswift_encode")
ellswift_encode :: proc "c" (
	ctx: ^Context,
	ell64: ^[64]u8,
	pubkey: ^Pubkey,
	rnd32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ell64 != nil, "ellswift_encode: ell64 is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "ellswift_encode: pubkey is null") {
		return 0
	}
	if !arg_check(ctx, rnd32 != nil, "ellswift_encode: rnd32 is null") {
		return 0
	}

	ge: group.Ge
	if !pubkey_load(&ge, pubkey) {
		return 0
	}
	ellswift.encode(ell64, &ge, rnd32)
	return 1
}

/*
Decodes a 64-byte ElligatorSwift encoding back to a public key.

Every 64-byte string decodes to some point, which is the whole purpose: an observer cannot
tell an encoding from random bytes because there is nothing to fail on.
*/
@(export, link_name = "secp256k1_ellswift_decode")
ellswift_decode :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, ell64: ^[64]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ellswift_decode: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Pubkey))
	if !arg_check(ctx, ell64 != nil, "ellswift_decode: ell64 is null") {
		return 0
	}

	ge: group.Ge
	if !ellswift.decode(&ge, ell64) {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}

/*
Derives a secret key's public key directly in ElligatorSwift form.
*/
@(export, link_name = "secp256k1_ellswift_create")
ellswift_create :: proc "c" (
	ctx: ^Context,
	ell64: ^[64]u8,
	seckey32: ^[32]u8,
	auxrnd32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "ellswift_create: ctx is null") {
		return 0
	}
	if !arg_check(ctx, ell64 != nil, "ellswift_create: ell64 is null") {
		return 0
	}
	if !arg_check(ctx, seckey32 != nil, "ellswift_create: seckey32 is null") {
		return 0
	}
	ok := ellswift.create(&ctx.inner.ecmult_gen_ctx, ell64, seckey32, auxrnd32)
	return 1 if ok else 0
}

/*
Computes an x-only Diffie-Hellman secret from two ElligatorSwift encodings.

`party` says which side this caller is, which is what makes the two ends derive the same
secret from inputs they hold in opposite orders.
*/
@(export, link_name = "secp256k1_ellswift_xdh")
ellswift_xdh :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	ell_a64: ^[64]u8,
	ell_b64: ^[64]u8,
	seckey32: ^[32]u8,
	party: c.int,
	hashfp: Ellswift_Xdh_Hash_Function,
	data: rawptr,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output != nil, "ellswift_xdh: output is null") {
		return 0
	}
	if !arg_check(ctx, ell_a64 != nil, "ellswift_xdh: ell_a64 is null") {
		return 0
	}
	if !arg_check(ctx, ell_b64 != nil, "ellswift_xdh: ell_b64 is null") {
		return 0
	}
	if !arg_check(ctx, seckey32 != nil, "ellswift_xdh: seckey32 is null") {
		return 0
	}
	if !arg_check(ctx, hashfp != nil, "ellswift_xdh: hashfp is null") {
		return 0
	}

	if hashfp == xdh_hash_function_bip324_c {
		ok := ellswift.xdh(
			output[:32],
			ell_a64,
			ell_b64,
			seckey32,
			party != 0,
			ellswift.xdh_hash_function_bip324,
			data,
		)
		return 1 if ok else 0
	}
	if hashfp == xdh_hash_function_prefix_c {
		ok := ellswift.xdh(
			output[:32],
			ell_a64,
			ell_b64,
			seckey32,
			party != 0,
			ellswift.xdh_hash_function_prefix,
			data,
		)
		return 1 if ok else 0
	}

	t := Xdh_Trampoline {
		fn   = hashfp,
		data = data,
	}
	ok := ellswift.xdh(output[:0], ell_a64, ell_b64, seckey32, party != 0, xdh_shim, &t)
	return 1 if ok else 0
}
