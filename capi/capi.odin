/*
C ABI for the secp256k1 library.

Exports a C-callable surface so Rust, Python, Go, Zig, Swift and anything else with an FFI
can link against this implementation. Signatures and struct sizes match libsecp256k1's
public headers, so it is a drop-in for existing C consumers.

	odin build capi/ -build-mode:shared -o:speed    # .dylib / .so / .dll
	odin build capi/ -build-mode:static -o:speed    # .a

Headers are in `capi/include/`, hand-written to match the documented ABI rather than copied
from upstream — see DEVELOPMENT.md §0.5.

# Contract

Every entry point validates its arguments, because a C caller can pass anything. A null
pointer or an out-of-range value returns 0 rather than trapping. Return values follow
upstream's convention: 1 for success, 0 for failure.

Opaque types are fixed-size byte blobs whose layout matches upstream's, so a consumer's
existing struct definitions keep working.
*/
package capi

import "base:runtime"
import "core:c"
import "core:mem"
import ".."
import "../ecdsa"
import "../ellswift"
import "../ecmult"
import "../extrakeys"
import "../group"
import "../recovery"
import "../scalar"

/*
Opaque context, matching upstream's `secp256k1_context`.
*/
Context :: struct {
	inner: secp256k1.Context,
}

/*
Opaque 64-byte public key, matching upstream's `secp256k1_pubkey`.
*/
Pubkey :: struct {
	data: [64]u8,
}

/*
Opaque 64-byte signature.
*/
Signature :: struct {
	data: [64]u8,
}

/*
Opaque 64-byte x-only public key.
*/
Xonly_Pubkey :: struct {
	data: [64]u8,
}

/*
Opaque 96-byte keypair.
*/
Keypair :: struct {
	data: [96]u8,
}

// Points cross the ABI in their packed 4x64 storage form, exactly as upstream does. That
// is what makes the opaque blobs 64 bytes: a live `Ge` is larger, and larger still under
// `-debug` where it carries magnitude bookkeeping, so copying the in-memory representation
// would neither fit nor be ABI-stable.

@(private)
pubkey_store :: proc "contextless" (dst: ^Pubkey, pk: secp256k1.Pubkey) {
	ge := group.Ge(pk)
	st: group.Ge_Storage
	group.ge_to_storage(&st, &ge)
	mem.copy(&dst.data[0], &st, size_of(group.Ge_Storage))
}

@(private)
pubkey_load :: proc "contextless" (src: ^Pubkey) -> secp256k1.Pubkey {
	st: group.Ge_Storage
	mem.copy(&st, &src.data[0], size_of(group.Ge_Storage))
	ge: group.Ge
	group.ge_from_storage(&ge, &st)
	return secp256k1.Pubkey(ge)
}

@(private)
sig_store :: proc "contextless" (dst: ^Signature, s: secp256k1.Ecdsa_Signature) {
	src := s
	mem.copy(&dst.data[0], &src, size_of(secp256k1.Ecdsa_Signature))
}

@(private)
sig_load :: proc "contextless" (src: ^Signature) -> (s: secp256k1.Ecdsa_Signature) {
	mem.copy(&s, &src.data[0], size_of(secp256k1.Ecdsa_Signature))
	return
}

// A keypair is 32 bytes of secret scalar followed by the 64-byte packed public point,
// matching upstream's 96-byte layout.

@(private)
kp_store :: proc "contextless" (dst: ^Keypair, k: secp256k1.Keypair) {
	kp := extrakeys.Keypair(k)
	sec: [32]u8
	scalar.scalar_get_b32(&sec, &kp.seckey)
	mem.copy(&dst.data[0], &sec[0], 32)

	st: group.Ge_Storage
	group.ge_to_storage(&st, &kp.pubkey)
	mem.copy(&dst.data[32], &st, size_of(group.Ge_Storage))
	mem.zero_explicit(&sec, 32)
}

@(private)
kp_load :: proc "contextless" (src: ^Keypair) -> secp256k1.Keypair {
	kp: extrakeys.Keypair
	sec: [32]u8
	mem.copy(&sec[0], &src.data[0], 32)
	scalar.scalar_set_b32(&kp.seckey, &sec)

	st: group.Ge_Storage
	mem.copy(&st, &src.data[32], size_of(group.Ge_Storage))
	group.ge_from_storage(&kp.pubkey, &st)
	mem.zero_explicit(&sec, 32)
	return secp256k1.Keypair(kp)
}

@(private)
xonly_store :: proc "contextless" (dst: ^Xonly_Pubkey, x: secp256k1.Xonly_Pubkey) {
	xk := extrakeys.Xonly_Pubkey(x)
	st: group.Ge_Storage
	group.ge_to_storage(&st, &xk.point)
	mem.copy(&dst.data[0], &st, size_of(group.Ge_Storage))
}

@(private)
xonly_load :: proc "contextless" (src: ^Xonly_Pubkey) -> secp256k1.Xonly_Pubkey {
	st: group.Ge_Storage
	mem.copy(&st, &src.data[0], size_of(group.Ge_Storage))
	xk: extrakeys.Xonly_Pubkey
	group.ge_from_storage(&xk.point, &st)
	return secp256k1.Xonly_Pubkey(xk)
}

// The opaque blobs must match upstream's sizes exactly, or a consumer's existing struct
// definitions break. These assertions are the ABI contract.
#assert(size_of(group.Ge_Storage) == 64)
#assert(size_of(secp256k1.Ecdsa_Signature) <= 64)
#assert(size_of(Pubkey) == 64)
#assert(size_of(Signature) == 64)
#assert(size_of(Xonly_Pubkey) == 64)
#assert(size_of(Keypair) == 96)

/*
Allocates and initializes a context.

The `flags` argument is accepted for source compatibility with upstream and ignored: this
implementation has no separate sign and verify contexts.
*/
@(export, link_name = "secp256k1_odin_context_create")
context_create :: proc "c" (flags: c.uint) -> ^Context {
	// A `proc "c"` has no implicit context; establish the default one so the allocator
	// is available.
	context = runtime.default_context()

	// `@(init)` procedures do not run when this library is linked into a C program, so
	// every precomputed table and constant must be built explicitly here. Each of these
	// is idempotent.
	group.ensure_init()
	ecmult.ensure_init()
	ecdsa.ensure_init()
	ellswift.ensure_init()

	ctx := new(Context)
	if ctx == nil {
		return nil
	}
	secp256k1.init(&ctx.inner)
	return ctx
}

/*
Destroys a context, zeroing its secret state.
*/
@(export, link_name = "secp256k1_odin_context_destroy")
context_destroy :: proc "c" (ctx: ^Context) {
	if ctx == nil {
		return
	}
	context = runtime.default_context()
	secp256k1.destroy(&ctx.inner)
	free(ctx)
}

/*
Re-randomizes a context's blinding. Returns 1 on success.
*/
@(export, link_name = "secp256k1_odin_context_randomize")
context_randomize :: proc "c" (ctx: ^Context, seed32: ^[32]u8) -> c.int {
	if ctx == nil {
		return 0
	}
	secp256k1.randomize(&ctx.inner, seed32)
	return 1
}

/*
Reports whether a 32-byte value is a valid secret key.
*/
@(export, link_name = "secp256k1_odin_ec_seckey_verify")
ec_seckey_verify :: proc "c" (ctx: ^Context, seckey: ^[32]u8) -> c.int {
	if seckey == nil {
		return 0
	}
	return 1 if secp256k1.seckey_verify(seckey) else 0
}

/*
Derives a public key from a secret key.
*/
@(export, link_name = "secp256k1_odin_ec_pubkey_create")
ec_pubkey_create :: proc "c" (ctx: ^Context, pubkey: ^Pubkey, seckey: ^[32]u8) -> c.int {
	if ctx == nil || pubkey == nil || seckey == nil {
		return 0
	}
	pk, err := secp256k1.pubkey_from_seckey(&ctx.inner, seckey)
	if err != .None {
		return 0
	}
	pubkey_store(pubkey, pk)
	return 1
}

/*
Parses a public key from a compressed, uncompressed or hybrid encoding.
*/
@(export, link_name = "secp256k1_odin_ec_pubkey_parse")
ec_pubkey_parse :: proc "c" (
	ctx: ^Context,
	pubkey: ^Pubkey,
	input: [^]u8,
	inputlen: c.size_t,
) -> c.int {
	if pubkey == nil || input == nil {
		return 0
	}
	pk, err := secp256k1.pubkey_parse(input[:int(inputlen)])
	if err != .None {
		return 0
	}
	pubkey_store(pubkey, pk)
	return 1
}

/*
Serializes a public key. `outputlen` is updated with the number of bytes written.

`flags` selects compression, matching upstream's `SECP256K1_EC_COMPRESSED`.
*/
@(export, link_name = "secp256k1_odin_ec_pubkey_serialize")
ec_pubkey_serialize :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	outputlen: ^c.size_t,
	pubkey: ^Pubkey,
	flags: c.uint,
) -> c.int {
	if output == nil || outputlen == nil || pubkey == nil {
		return 0
	}
	pk := pubkey_load(pubkey)

	compressed := (flags & 0x0100) != 0
	if compressed {
		if outputlen^ < 33 {
			return 0
		}
		b := secp256k1.pubkey_serialize(pk)
		mem.copy(output, &b[0], 33)
		outputlen^ = 33
	} else {
		if outputlen^ < 65 {
			return 0
		}
		b := secp256k1.pubkey_serialize_uncompressed(pk)
		mem.copy(output, &b[0], 65)
		outputlen^ = 65
	}
	return 1
}

/*
Signs a 32-byte message hash. The nonce is derived per RFC6979 and s is low.

`noncefp` and `ndata` are accepted for source compatibility and must be null; a custom
nonce function is not supported through this ABI.
*/
@(export, link_name = "secp256k1_odin_ecdsa_sign")
ecdsa_sign :: proc "c" (
	ctx: ^Context,
	sig: ^Signature,
	msghash32: ^[32]u8,
	seckey: ^[32]u8,
	noncefp: rawptr,
	ndata: rawptr,
) -> c.int {
	if ctx == nil || sig == nil || msghash32 == nil || seckey == nil {
		return 0
	}
	if noncefp != nil {
		return 0
	}
	s, err := secp256k1.ecdsa_sign(&ctx.inner, msghash32, seckey)
	if err != .None {
		return 0
	}
	sig_store(sig, s)
	return 1
}

/*
Verifies an ECDSA signature. High-S signatures are rejected.
*/
@(export, link_name = "secp256k1_odin_ecdsa_verify")
ecdsa_verify :: proc "c" (
	ctx: ^Context,
	sig: ^Signature,
	msghash32: ^[32]u8,
	pubkey: ^Pubkey,
) -> c.int {
	if sig == nil || msghash32 == nil || pubkey == nil {
		return 0
	}
	s := sig_load(sig)
	pk := pubkey_load(pubkey)
	return 1 if secp256k1.ecdsa_verify(s, msghash32, pk) else 0
}

/*
Serializes a signature in the 64-byte compact form.
*/
@(export, link_name = "secp256k1_odin_ecdsa_signature_serialize_compact")
ecdsa_signature_serialize_compact :: proc "c" (
	ctx: ^Context,
	output64: ^[64]u8,
	sig: ^Signature,
) -> c.int {
	if output64 == nil || sig == nil {
		return 0
	}
	s := sig_load(sig)
	output64^ = secp256k1.ecdsa_serialize_compact(s)
	return 1
}

/*
Parses a signature from the 64-byte compact form.
*/
@(export, link_name = "secp256k1_odin_ecdsa_signature_parse_compact")
ecdsa_signature_parse_compact :: proc "c" (
	ctx: ^Context,
	sig: ^Signature,
	input64: ^[64]u8,
) -> c.int {
	if sig == nil || input64 == nil {
		return 0
	}
	s, err := secp256k1.ecdsa_parse_compact(input64)
	if err != .None {
		return 0
	}
	sig_store(sig, s)
	return 1
}

/*
Serializes a signature as DER. `outputlen` is updated with the length written.
*/
@(export, link_name = "secp256k1_odin_ecdsa_signature_serialize_der")
ecdsa_signature_serialize_der :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	outputlen: ^c.size_t,
	sig: ^Signature,
) -> c.int {
	if output == nil || outputlen == nil || sig == nil {
		return 0
	}
	s := sig_load(sig)
	written, err := secp256k1.ecdsa_serialize_der(output[:int(outputlen^)], s)
	if err != .None {
		return 0
	}
	outputlen^ = c.size_t(len(written))
	return 1
}

/*
Parses a strictly DER-encoded signature.
*/
@(export, link_name = "secp256k1_odin_ecdsa_signature_parse_der")
ecdsa_signature_parse_der :: proc "c" (
	ctx: ^Context,
	sig: ^Signature,
	input: [^]u8,
	inputlen: c.size_t,
) -> c.int {
	if sig == nil || input == nil {
		return 0
	}
	s, err := secp256k1.ecdsa_parse_der(input[:int(inputlen)])
	if err != .None {
		return 0
	}
	sig_store(sig, s)
	return 1
}

/*
Creates a keypair for Schnorr signing.
*/
@(export, link_name = "secp256k1_odin_keypair_create")
keypair_create :: proc "c" (ctx: ^Context, keypair: ^Keypair, seckey32: ^[32]u8) -> c.int {
	if ctx == nil || keypair == nil || seckey32 == nil {
		return 0
	}
	kp, err := secp256k1.keypair_create(&ctx.inner, seckey32)
	if err != .None {
		return 0
	}
	kp_store(keypair, kp)
	return 1
}

/*
Extracts the x-only public key from a keypair.
*/
@(export, link_name = "secp256k1_odin_keypair_xonly_pub")
keypair_xonly_pub :: proc "c" (
	ctx: ^Context,
	pubkey: ^Xonly_Pubkey,
	pk_parity: ^c.int,
	keypair: ^Keypair,
) -> c.int {
	if pubkey == nil || keypair == nil {
		return 0
	}
	kp := kp_load(keypair)
	x, parity, err := secp256k1.keypair_xonly_pubkey(&kp)
	if err != .None {
		return 0
	}
	if pk_parity != nil {
		pk_parity^ = 1 if parity else 0
	}
	xonly_store(pubkey, x)
	return 1
}

/*
Serializes an x-only public key as 32 bytes.
*/
@(export, link_name = "secp256k1_odin_xonly_pubkey_serialize")
xonly_pubkey_serialize :: proc "c" (
	ctx: ^Context,
	output32: ^[32]u8,
	pubkey: ^Xonly_Pubkey,
) -> c.int {
	if output32 == nil || pubkey == nil {
		return 0
	}
	x := xonly_load(pubkey)
	output32^ = secp256k1.xonly_pubkey_serialize(x)
	return 1
}

/*
Parses a 32-byte x-only public key.
*/
@(export, link_name = "secp256k1_odin_xonly_pubkey_parse")
xonly_pubkey_parse :: proc "c" (
	ctx: ^Context,
	pubkey: ^Xonly_Pubkey,
	input32: ^[32]u8,
) -> c.int {
	if pubkey == nil || input32 == nil {
		return 0
	}
	x, err := secp256k1.xonly_pubkey_parse(input32)
	if err != .None {
		return 0
	}
	xonly_store(pubkey, x)
	return 1
}

/*
Signs a 32-byte message with BIP340 Schnorr. `aux_rand32` may be null.
*/
@(export, link_name = "secp256k1_odin_schnorrsig_sign32")
schnorrsig_sign32 :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg32: ^[32]u8,
	keypair: ^Keypair,
	aux_rand32: ^[32]u8,
) -> c.int {
	if ctx == nil || sig64 == nil || msg32 == nil || keypair == nil {
		return 0
	}
	kp := kp_load(keypair)
	s, err := secp256k1.schnorr_sign(&ctx.inner, msg32[:], &kp, aux_rand32)
	if err != .None {
		return 0
	}
	sig64^ = transmute([64]u8)s
	return 1
}

/*
Verifies a BIP340 Schnorr signature over a message of any length.
*/
@(export, link_name = "secp256k1_odin_schnorrsig_verify")
schnorrsig_verify :: proc "c" (
	ctx: ^Context,
	sig64: ^[64]u8,
	msg: [^]u8,
	msglen: c.size_t,
	pubkey: ^Xonly_Pubkey,
) -> c.int {
	if sig64 == nil || pubkey == nil {
		return 0
	}
	if msg == nil && msglen != 0 {
		return 0
	}
	x := xonly_load(pubkey)
	s := secp256k1.Schnorr_Signature(sig64^)
	m := msg[:int(msglen)] if msglen > 0 else nil
	return 1 if secp256k1.schnorr_verify(s, m, x) else 0
}

/*
Computes an ECDH shared secret: SHA256 of the compressed shared point.

`hashfp` and `data` are accepted for source compatibility and must be null.
*/
@(export, link_name = "secp256k1_odin_ecdh")
ecdh :: proc "c" (
	ctx: ^Context,
	output32: ^[32]u8,
	pubkey: ^Pubkey,
	seckey32: ^[32]u8,
	hashfp: rawptr,
	data: rawptr,
) -> c.int {
	if output32 == nil || pubkey == nil || seckey32 == nil {
		return 0
	}
	if hashfp != nil {
		return 0
	}
	pk := pubkey_load(pubkey)
	secret, err := secp256k1.ecdh_shared_secret(pk, seckey32)
	if err != .None {
		return 0
	}
	output32^ = secret
	return 1
}
