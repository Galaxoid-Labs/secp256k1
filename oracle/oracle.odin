/*
FFI bindings to upstream libsecp256k1, used **only** as a differential-testing oracle.

Per `CLAUDE.md`: the C library exists here for exactly one reason — feed identical inputs to
both implementations and assert byte-identical output. It is never a runtime fallback, it
never signs or derives anything this library ships, and when the two disagree, that
divergence is the bug to chase, not to paper over.

# Quarantine

This is the only package that links C, and it must never appear in the import graph of the
library packages. A consumer who git-submodules this repository will not have
`libsecp256k1.a` and must never need it. Only the test tree imports this.

# Providing the library

Odin resolves `foreign import` paths relative to the package directory, so the static
library is expected at `oracle/libsecp256k1.a`. It is deliberately **not** committed —
`.gitignore` excludes it, and a submodule consumer neither has it nor needs it.

Link it from an upstream build:

	./oracle/link-lib.sh /path/to/secp256k1/build/lib/libsecp256k1.a

The library must be built with the ecdh, extrakeys, schnorrsig, recovery, ellswift and
musig modules enabled, which is upstream's default for a full build. If it is absent, the
oracle tests fail to link; the rest of the suite is unaffected.
*/
package oracle

import "core:c"

foreign import libsecp "libsecp256k1.a"

/*
Opaque context handle.
*/
Context :: distinct rawptr

/*
Upstream's 64-byte opaque public key. The layout is internal to the C library, so it is
treated as an opaque blob and only ever passed back through C entry points.
*/
Pubkey :: struct {
	data: [64]u8,
}

/*
Upstream's 64-byte opaque signature.
*/
Ecdsa_Signature :: struct {
	data: [64]u8,
}

/*
Upstream's 65-byte opaque recoverable signature.
*/
Ecdsa_Recoverable_Signature :: struct {
	data: [65]u8,
}

/*
Upstream's 64-byte opaque x-only public key.
*/
Xonly_Pubkey :: struct {
	data: [64]u8,
}

/*
Upstream's 96-byte opaque keypair.
*/
Keypair :: struct {
	data: [96]u8,
}

/*
Context creation flags.
*/
FLAGS_TYPE_CONTEXT :: 1 << 0
FLAGS_BIT_CONTEXT_SIGN :: 1 << 9
FLAGS_BIT_CONTEXT_VERIFY :: 1 << 8

CONTEXT_SIGN :: FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN
CONTEXT_VERIFY :: FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY
CONTEXT_NONE :: FLAGS_TYPE_CONTEXT

/*
Serialization flags.
*/
FLAGS_TYPE_COMPRESSION :: 1 << 1
FLAGS_BIT_COMPRESSION :: 1 << 8

EC_COMPRESSED :: FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION
EC_UNCOMPRESSED :: FLAGS_TYPE_COMPRESSION

@(default_calling_convention = "c", link_prefix = "secp256k1_")
foreign libsecp {
	context_create :: proc(flags: c.uint) -> Context ---
	context_destroy :: proc(ctx: Context) ---
	context_randomize :: proc(ctx: Context, seed32: ^u8) -> c.int ---

	ec_seckey_verify :: proc(ctx: Context, seckey: ^u8) -> c.int ---
	ec_pubkey_create :: proc(ctx: Context, pubkey: ^Pubkey, seckey: ^u8) -> c.int ---
	ec_pubkey_parse :: proc(ctx: Context, pubkey: ^Pubkey, input: ^u8, inputlen: c.size_t) -> c.int ---
	ec_pubkey_serialize :: proc(ctx: Context, output: ^u8, outputlen: ^c.size_t, pubkey: ^Pubkey, flags: c.uint) -> c.int ---
	ec_pubkey_negate :: proc(ctx: Context, pubkey: ^Pubkey) -> c.int ---
	ec_pubkey_tweak_add :: proc(ctx: Context, pubkey: ^Pubkey, tweak32: ^u8) -> c.int ---
	ec_pubkey_tweak_mul :: proc(ctx: Context, pubkey: ^Pubkey, tweak32: ^u8) -> c.int ---
	ec_seckey_tweak_add :: proc(ctx: Context, seckey: ^u8, tweak32: ^u8) -> c.int ---
	ec_seckey_tweak_mul :: proc(ctx: Context, seckey: ^u8, tweak32: ^u8) -> c.int ---
	ec_seckey_negate :: proc(ctx: Context, seckey: ^u8) -> c.int ---

	ecdsa_sign :: proc(ctx: Context, sig: ^Ecdsa_Signature, msghash32: ^u8, seckey: ^u8, noncefp: rawptr, ndata: rawptr) -> c.int ---
	ecdsa_verify :: proc(ctx: Context, sig: ^Ecdsa_Signature, msghash32: ^u8, pubkey: ^Pubkey) -> c.int ---
	ecdsa_signature_serialize_compact :: proc(ctx: Context, output64: ^u8, sig: ^Ecdsa_Signature) -> c.int ---
	ecdsa_signature_parse_compact :: proc(ctx: Context, sig: ^Ecdsa_Signature, input64: ^u8) -> c.int ---
	ecdsa_signature_serialize_der :: proc(ctx: Context, output: ^u8, outputlen: ^c.size_t, sig: ^Ecdsa_Signature) -> c.int ---
	ecdsa_signature_parse_der :: proc(ctx: Context, sig: ^Ecdsa_Signature, input: ^u8, inputlen: c.size_t) -> c.int ---
	ecdsa_signature_normalize :: proc(ctx: Context, sigout: ^Ecdsa_Signature, sigin: ^Ecdsa_Signature) -> c.int ---

	ecdsa_sign_recoverable :: proc(ctx: Context, sig: ^Ecdsa_Recoverable_Signature, msghash32: ^u8, seckey: ^u8, noncefp: rawptr, ndata: rawptr) -> c.int ---
	ecdsa_recoverable_signature_serialize_compact :: proc(ctx: Context, output64: ^u8, recid: ^c.int, sig: ^Ecdsa_Recoverable_Signature) -> c.int ---
	ecdsa_recover :: proc(ctx: Context, pubkey: ^Pubkey, sig: ^Ecdsa_Recoverable_Signature, msghash32: ^u8) -> c.int ---

	ecdh :: proc(ctx: Context, output: ^u8, pubkey: ^Pubkey, seckey: ^u8, hashfp: rawptr, data: rawptr) -> c.int ---

	keypair_create :: proc(ctx: Context, keypair: ^Keypair, seckey: ^u8) -> c.int ---
	keypair_xonly_pub :: proc(ctx: Context, pubkey: ^Xonly_Pubkey, pk_parity: ^c.int, keypair: ^Keypair) -> c.int ---
	xonly_pubkey_parse :: proc(ctx: Context, pubkey: ^Xonly_Pubkey, input32: ^u8) -> c.int ---
	xonly_pubkey_serialize :: proc(ctx: Context, output32: ^u8, pubkey: ^Xonly_Pubkey) -> c.int ---
	xonly_pubkey_from_pubkey :: proc(ctx: Context, xonly: ^Xonly_Pubkey, pk_parity: ^c.int, pubkey: ^Pubkey) -> c.int ---
	xonly_pubkey_tweak_add :: proc(ctx: Context, output: ^Pubkey, internal: ^Xonly_Pubkey, tweak32: ^u8) -> c.int ---
	keypair_xonly_tweak_add :: proc(ctx: Context, keypair: ^Keypair, tweak32: ^u8) -> c.int ---

	schnorrsig_sign32 :: proc(ctx: Context, sig64: ^u8, msg32: ^u8, keypair: ^Keypair, aux_rand32: ^u8) -> c.int ---
	schnorrsig_verify :: proc(ctx: Context, sig64: ^u8, msg: ^u8, msglen: c.size_t, pubkey: ^Xonly_Pubkey) -> c.int ---

	ellswift_encode :: proc(ctx: Context, ell64: ^u8, pubkey: ^Pubkey, rnd32: ^u8) -> c.int ---
	ellswift_decode :: proc(ctx: Context, pubkey: ^Pubkey, ell64: ^u8) -> c.int ---
	ellswift_create :: proc(ctx: Context, ell64: ^u8, seckey32: ^u8, auxrnd32: ^u8) -> c.int ---

	tagged_sha256 :: proc(ctx: Context, hash32: ^u8, tag: ^u8, taglen: c.size_t, msg: ^u8, msglen: c.size_t) -> c.int ---
}
