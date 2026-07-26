/*
ECDSA signing, verification, serialization, and public key recovery.

Mirrors the ECDSA half of upstream's `secp256k1.h` plus all of `secp256k1_recovery.h`.
*/
package capi

import "core:c"
import "core:mem"
import "../ecdsa"
import "../group"
import "../recovery"
import "../scalar"

/*
The C nonce function type, matching upstream's `secp256k1_nonce_function`.

Returns 1 if it produced a nonce, 0 to abort signing.
*/
Nonce_Function :: #type proc "c" (
	nonce32: ^[32]u8,
	msg32: ^[32]u8,
	key32: ^[32]u8,
	algo16: ^[16]u8,
	data: rawptr,
	attempt: c.uint,
) -> c.int

@(private)
nonce_function_rfc6979_c :: proc "c" (
	nonce32: ^[32]u8,
	msg32: ^[32]u8,
	key32: ^[32]u8,
	algo16: ^[16]u8,
	data: rawptr,
	attempt: c.uint,
) -> c.int {
	if nonce32 == nil || msg32 == nil || key32 == nil {
		return 0
	}
	ecdsa.nonce_function_rfc6979(
		nonce32,
		msg32,
		key32,
		algo16,
		(^[32]u8)(data),
		uint(attempt),
	)
	return 1
}

/*
`secp256k1_nonce_function_rfc6979` — the RFC6979 deterministic nonce function.

Exported as a variable holding a function pointer, which is how upstream declares it.
*/
@(export, link_name = "secp256k1_nonce_function_rfc6979")
nonce_function_rfc6979: Nonce_Function = nonce_function_rfc6979_c

/*
`secp256k1_nonce_function_default` — an alias for the RFC6979 function above.
*/
@(export, link_name = "secp256k1_nonce_function_default")
nonce_function_default: Nonce_Function = nonce_function_rfc6979_c

/*
Parses a signature from the 64-byte compact form.

Fails if either half is at or above the group order.
*/
@(export, link_name = "secp256k1_ecdsa_signature_parse_compact")
ecdsa_signature_parse_compact :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Signature,
	input64: ^[64]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "ecdsa_signature_parse_compact: sig is null") {
		return 0
	}
	if !arg_check(ctx, input64 != nil, "ecdsa_signature_parse_compact: input64 is null") {
		return 0
	}
	s: ecdsa.Signature
	if !ecdsa.signature_parse_compact(&s, input64) {
		mem.zero(sig, size_of(Ecdsa_Signature))
		return 0
	}
	sig_store(sig, &s)
	return 1
}

/*
Serializes a signature in the 64-byte compact form.
*/
@(export, link_name = "secp256k1_ecdsa_signature_serialize_compact")
ecdsa_signature_serialize_compact :: proc "c" (
	ctx: ^Context,
	output64: ^[64]u8,
	sig: ^Ecdsa_Signature,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output64 != nil, "ecdsa_signature_serialize_compact: output64 is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "ecdsa_signature_serialize_compact: sig is null") {
		return 0
	}
	s: ecdsa.Signature
	sig_load(&s, sig)
	ecdsa.signature_serialize_compact(output64, &s)
	return 1
}

/*
Parses a strictly DER-encoded signature.

Strict means exactly what BIP66 means: minimal lengths, no trailing data, no negative or
padded integers. Laxly encoded signatures from old software are rejected.
*/
@(export, link_name = "secp256k1_ecdsa_signature_parse_der")
ecdsa_signature_parse_der :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Signature,
	input: [^]u8,
	inputlen: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "ecdsa_signature_parse_der: sig is null") {
		return 0
	}
	if !arg_check(ctx, input != nil, "ecdsa_signature_parse_der: input is null") {
		return 0
	}
	s: ecdsa.Signature
	if !ecdsa.signature_parse_der(&s, input[:int(inputlen)]) {
		mem.zero(sig, size_of(Ecdsa_Signature))
		return 0
	}
	sig_store(sig, &s)
	return 1
}

/*
Serializes a signature as DER. `outputlen` carries the buffer size in and the length out.

Returns 0 if the buffer is too small, in which case `outputlen` holds the size required.
*/
@(export, link_name = "secp256k1_ecdsa_signature_serialize_der")
ecdsa_signature_serialize_der :: proc "c" (
	ctx: ^Context,
	output: [^]u8,
	outputlen: ^c.size_t,
	sig: ^Ecdsa_Signature,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, outputlen != nil, "ecdsa_signature_serialize_der: outputlen is null") {
		return 0
	}
	if !arg_check(ctx, output != nil, "ecdsa_signature_serialize_der: output is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "ecdsa_signature_serialize_der: sig is null") {
		return 0
	}
	s: ecdsa.Signature
	sig_load(&s, sig)
	n := ecdsa.signature_serialize_der(output[:int(outputlen^)], &s)
	if n == 0 {
		// The internal routine reports "did not fit" as zero and leaves the caller to ask
		// for the needed size; 72 is the DER maximum for this curve.
		outputlen^ = 72
		return 0
	}
	outputlen^ = c.size_t(n)
	return 1
}

/*
Converts a signature to its lower-S form, the only form this library will verify.

Returns 1 if the input was high-S and was changed. `sigout` may be null, which makes this a
test for whether normalization is needed.
*/
@(export, link_name = "secp256k1_ecdsa_signature_normalize")
ecdsa_signature_normalize :: proc "c" (
	ctx: ^Context,
	sigout: ^Ecdsa_Signature,
	sigin: ^Ecdsa_Signature,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sigin != nil, "ecdsa_signature_normalize: sigin is null") {
		return 0
	}
	s_in, s_out: ecdsa.Signature
	sig_load(&s_in, sigin)
	changed := ecdsa.signature_normalize(&s_out, &s_in)
	if sigout != nil {
		sig_store(sigout, &s_out)
	}
	return 1 if changed else 0
}

/*
Verifies an ECDSA signature.

High-S signatures are rejected, matching upstream: malleability is a consensus concern, and
accepting both forms of the same signature is what BIP146 exists to prevent.
*/
@(export, link_name = "secp256k1_ecdsa_verify")
ecdsa_verify :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Signature,
	msghash32: ^[32]u8,
	pubkey: ^Pubkey,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "ecdsa_verify: sig is null") {
		return 0
	}
	if !arg_check(ctx, msghash32 != nil, "ecdsa_verify: msghash32 is null") {
		return 0
	}
	if !arg_check(ctx, pubkey != nil, "ecdsa_verify: pubkey is null") {
		return 0
	}

	ge: group.Ge
	if !pubkey_load(&ge, pubkey) {
		return 0
	}
	s: ecdsa.Signature
	sig_load(&s, sig)
	return 1 if ecdsa.verify(&s, msghash32, &ge) else 0
}

/*
Runs the retry loop around a caller-supplied nonce function.

Only reached when the caller passes a nonce function that is not the built-in one. It is
kept separate from the default path deliberately: `ecdsa.sign` is the routine the
constant-time harness clears, and routing every signature through a generic loop that calls
out to arbitrary C would put an unanalyzable function inside the secret path. A caller who
supplies their own nonce function owns its side-channel behaviour.
*/
@(private)
sign_with_nonce_function :: proc "contextless" (
	ctx: ^Context,
	sig: ^ecdsa.Signature,
	recid: ^int,
	msghash32: ^[32]u8,
	seckey: ^[32]u8,
	noncefp: Nonce_Function,
	ndata: rawptr,
) -> bool {
	sec, non, msg: scalar.Scalar
	defer scalar.scalar_clear(&sec)
	defer scalar.scalar_clear(&non)

	if !scalar.scalar_set_b32_seckey(&sec, seckey) {
		return false
	}
	scalar.scalar_set_b32(&msg, msghash32)

	nonce32: [32]u8
	defer mem.zero_explicit(&nonce32, size_of(nonce32))

	for attempt: c.uint = 0; ; attempt += 1 {
		if noncefp(&nonce32, msghash32, seckey, nil, ndata, attempt) == 0 {
			return false
		}
		if !scalar.scalar_set_b32_seckey(&non, &nonce32) {
			continue
		}
		if ecdsa.sig_sign(&ctx.inner.ecmult_gen_ctx, sig, &sec, &msg, &non, recid) {
			return true
		}
	}
}

/*
Reports whether a nonce function pointer is this library's built-in one.

A caller that passes `secp256k1_nonce_function_default` explicitly — which plenty do — must
land on the same code path, and the same constant-time guarantees, as one that passes NULL.
*/
@(private)
is_default_nonce_function :: proc "contextless" (noncefp: Nonce_Function) -> bool {
	return noncefp == nil || noncefp == nonce_function_rfc6979_c
}

/*
Signs a 32-byte message hash. The resulting signature always has low S.

`noncefp` selects the nonce function; null means RFC6979. `ndata` is 32 bytes of extra
entropy for the default function, or arbitrary data for a custom one.
*/
@(export, link_name = "secp256k1_ecdsa_sign")
ecdsa_sign :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Signature,
	msghash32: ^[32]u8,
	seckey: ^[32]u8,
	noncefp: Nonce_Function,
	ndata: rawptr,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "ecdsa_sign: ctx is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "ecdsa_sign: sig is null") {
		return 0
	}
	mem.zero(sig, size_of(Ecdsa_Signature))
	if !arg_check(ctx, msghash32 != nil, "ecdsa_sign: msghash32 is null") {
		return 0
	}
	if !arg_check(ctx, seckey != nil, "ecdsa_sign: seckey is null") {
		return 0
	}

	s: ecdsa.Signature
	ok: bool
	if is_default_nonce_function(noncefp) {
		ok = ecdsa.sign(&ctx.inner.ecmult_gen_ctx, &s, msghash32, seckey, (^[32]u8)(ndata))
	} else {
		ok = sign_with_nonce_function(ctx, &s, nil, msghash32, seckey, noncefp, ndata)
	}
	if !ok {
		return 0
	}
	sig_store(sig, &s)
	return 1
}

// ---------------------------------------------------------------------------------------
// Recovery. Mirrors upstream's `secp256k1_recovery.h`.
// ---------------------------------------------------------------------------------------

@(private)
recsig_store :: proc "contextless" (dst: ^Ecdsa_Recoverable_Signature, sig: ^recovery.Recoverable_Signature) {
	scalar.scalar_get_b32((^[32]u8)(&dst.data[0]), &sig.sig.r)
	scalar.scalar_get_b32((^[32]u8)(&dst.data[32]), &sig.sig.s)
	dst.data[64] = u8(sig.recid)
}

@(private)
recsig_load :: proc "contextless" (sig: ^recovery.Recoverable_Signature, src: ^Ecdsa_Recoverable_Signature) {
	scalar.scalar_set_b32(&sig.sig.r, (^[32]u8)(&src.data[0]))
	scalar.scalar_set_b32(&sig.sig.s, (^[32]u8)(&src.data[32]))
	sig.recid = int(src.data[64])
}

/*
Parses a recoverable signature from its compact form and recovery id.
*/
@(export, link_name = "secp256k1_ecdsa_recoverable_signature_parse_compact")
ecdsa_recoverable_signature_parse_compact :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Recoverable_Signature,
	input64: ^[64]u8,
	recid: c.int,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "recoverable_signature_parse_compact: sig is null") {
		return 0
	}
	if !arg_check(ctx, input64 != nil, "recoverable_signature_parse_compact: input64 is null") {
		return 0
	}
	if !arg_check(
		ctx,
		recid >= 0 && recid <= 3,
		"recoverable_signature_parse_compact: recid out of range",
	) {
		return 0
	}

	rs: recovery.Recoverable_Signature
	if !recovery.signature_parse_compact(&rs, input64, int(recid)) {
		mem.zero(sig, size_of(Ecdsa_Recoverable_Signature))
		return 0
	}
	recsig_store(sig, &rs)
	return 1
}

/*
Serializes a recoverable signature as 64 bytes plus a separate recovery id.
*/
@(export, link_name = "secp256k1_ecdsa_recoverable_signature_serialize_compact")
ecdsa_recoverable_signature_serialize_compact :: proc "c" (
	ctx: ^Context,
	output64: ^[64]u8,
	recid: ^c.int,
	sig: ^Ecdsa_Recoverable_Signature,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, output64 != nil, "recoverable_signature_serialize_compact: output64 is null") {
		return 0
	}
	if !arg_check(ctx, recid != nil, "recoverable_signature_serialize_compact: recid is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "recoverable_signature_serialize_compact: sig is null") {
		return 0
	}

	rs: recovery.Recoverable_Signature
	recsig_load(&rs, sig)
	r: int
	recovery.signature_serialize_compact(output64, &r, &rs)
	recid^ = c.int(r)
	return 1
}

/*
Discards the recovery id, yielding an ordinary signature.
*/
@(export, link_name = "secp256k1_ecdsa_recoverable_signature_convert")
ecdsa_recoverable_signature_convert :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Signature,
	sigin: ^Ecdsa_Recoverable_Signature,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, sig != nil, "recoverable_signature_convert: sig is null") {
		return 0
	}
	if !arg_check(ctx, sigin != nil, "recoverable_signature_convert: sigin is null") {
		return 0
	}
	rs: recovery.Recoverable_Signature
	recsig_load(&rs, sigin)
	out: ecdsa.Signature
	recovery.signature_convert(&out, &rs)
	sig_store(sig, &out)
	return 1
}

/*
Signs a message hash, producing a signature that carries a recovery id.
*/
@(export, link_name = "secp256k1_ecdsa_sign_recoverable")
ecdsa_sign_recoverable :: proc "c" (
	ctx: ^Context,
	sig: ^Ecdsa_Recoverable_Signature,
	msghash32: ^[32]u8,
	seckey: ^[32]u8,
	noncefp: Nonce_Function,
	ndata: rawptr,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "ecdsa_sign_recoverable: ctx is null") {
		return 0
	}
	if !arg_check(ctx, sig != nil, "ecdsa_sign_recoverable: sig is null") {
		return 0
	}
	mem.zero(sig, size_of(Ecdsa_Recoverable_Signature))
	if !arg_check(ctx, msghash32 != nil, "ecdsa_sign_recoverable: msghash32 is null") {
		return 0
	}
	if !arg_check(ctx, seckey != nil, "ecdsa_sign_recoverable: seckey is null") {
		return 0
	}

	rs: recovery.Recoverable_Signature
	ok: bool
	if is_default_nonce_function(noncefp) {
		ok = recovery.sign_recoverable(
			&ctx.inner.ecmult_gen_ctx,
			&rs,
			msghash32,
			seckey,
			(^[32]u8)(ndata),
		)
	} else {
		ok = sign_with_nonce_function(
			ctx,
			&rs.sig,
			&rs.recid,
			msghash32,
			seckey,
			noncefp,
			ndata,
		)
	}
	if !ok {
		return 0
	}
	recsig_store(sig, &rs)
	return 1
}

/*
Recovers the public key that produced a recoverable signature.
*/
@(export, link_name = "secp256k1_ecdsa_recover")
ecdsa_recover :: proc "c" (
	ctx: ^Context,
	pubkey: ^Pubkey,
	sig: ^Ecdsa_Recoverable_Signature,
	msghash32: ^[32]u8,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, pubkey != nil, "ecdsa_recover: pubkey is null") {
		return 0
	}
	mem.zero(pubkey, size_of(Pubkey))
	if !arg_check(ctx, sig != nil, "ecdsa_recover: sig is null") {
		return 0
	}
	if !arg_check(ctx, msghash32 != nil, "ecdsa_recover: msghash32 is null") {
		return 0
	}

	rs: recovery.Recoverable_Signature
	recsig_load(&rs, sig)
	ge: group.Ge
	if !recovery.recover(&ge, &rs, msghash32) {
		return 0
	}
	pubkey_store(pubkey, &ge)
	return 1
}
