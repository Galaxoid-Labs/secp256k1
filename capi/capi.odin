/*
A drop-in C ABI for libsecp256k1.

This exports the upstream public API under the *upstream symbol names*, with upstream's
struct sizes, flag values and return conventions. An existing C program compiled against
libsecp256k1's own headers links against this archive unchanged:

	odin build capi/ -build-mode:static -o:speed -out:libsecp256k1.a
	cc consumer.c libsecp256k1.a -o consumer      # upstream's headers, our implementation

	odin build capi/ -build-mode:shared -o:speed  # .dylib / .so / .dll

Headers are in `capi/include/`, hand-written to declare the same API rather than copied from
upstream — see DEVELOPMENT.md §0.5. A consumer that already has upstream's headers should
keep using them; that is the case this target is built for.

> **Not for real value.** Being link-compatible with libsecp256k1 makes it *easy* to
> substitute this for the real library. Don't. Unaudited hand-rolled cryptography must never
> guard real keys or real funds, and a drop-in replacement is exactly the shape of mistake
> that ends with it deployed by accident.

# Deliberate symbol collision

These names collide with the real libsecp256k1 by design — that is what "drop-in" means.
A binary must link one or the other, never both. Inside this repository the C library is
reached only through the `oracle` package, which links upstream's archive and is never
combined with this target.

# Contract

Every entry point validates its arguments, because a C caller can pass anything. Invalid
arguments route through the context's illegal-argument callback and return 0, matching
upstream; they never trap. Return values follow upstream's convention: 1 for success, 0 for
failure.

Opaque types are fixed-size byte blobs whose *sizes* match upstream's exactly, so a
consumer's existing struct definitions and stack frames are correct. The bytes inside are
this implementation's own packing and are not interchangeable with upstream's — the same
caveat upstream states for its own blobs, which carry no cross-version guarantee either.
*/
package capi

import "base:intrinsics"
import "base:runtime"
import "core:c"
import "core:mem"
import ctxp "../ctx"
import "../ecdsa"
import "../ecmult"
import "../ellswift"
import "../group"
import "../hash"
import "../scalar"

// ---------------------------------------------------------------------------------------
// Flags, matching upstream's `secp256k1.h`.
// ---------------------------------------------------------------------------------------

FLAGS_TYPE_MASK :: (1 << 8) - 1
FLAGS_TYPE_CONTEXT :: 1 << 0
FLAGS_TYPE_COMPRESSION :: 1 << 1
FLAGS_BIT_CONTEXT_VERIFY :: 1 << 8
FLAGS_BIT_CONTEXT_SIGN :: 1 << 9
FLAGS_BIT_CONTEXT_DECLASSIFY :: 1 << 10
FLAGS_BIT_COMPRESSION :: 1 << 8

CONTEXT_NONE :: FLAGS_TYPE_CONTEXT
CONTEXT_VERIFY :: FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_VERIFY
CONTEXT_SIGN :: FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_SIGN
CONTEXT_DECLASSIFY :: FLAGS_TYPE_CONTEXT | FLAGS_BIT_CONTEXT_DECLASSIFY

EC_COMPRESSED :: FLAGS_TYPE_COMPRESSION | FLAGS_BIT_COMPRESSION
EC_UNCOMPRESSED :: FLAGS_TYPE_COMPRESSION

// ---------------------------------------------------------------------------------------
// Opaque types. The sizes are the ABI contract: a C caller allocates these on its own stack
// from its own header, so every one of them must match upstream to the byte.
// ---------------------------------------------------------------------------------------

Pubkey :: struct {
	data: [64]u8,
}

Ecdsa_Signature :: struct {
	data: [64]u8,
}

Ecdsa_Recoverable_Signature :: struct {
	data: [65]u8,
}

Xonly_Pubkey :: struct {
	data: [64]u8,
}

Keypair :: struct {
	data: [96]u8,
}

#assert(size_of(Pubkey) == 64)
#assert(size_of(Ecdsa_Signature) == 64)
#assert(size_of(Ecdsa_Recoverable_Signature) == 65)
#assert(size_of(Xonly_Pubkey) == 64)
#assert(size_of(Keypair) == 96)
#assert(size_of(group.Ge_Storage) == 64)

/*
A C callback and its user data.

The C signature takes a `const char *`; the internal callback system passes an Odin `string`,
which is a pointer and a length and carries no terminator. `c_callback_shim` bridges the two.
*/
C_Callback :: struct {
	fn:   proc "c" (message: cstring, data: rawptr),
	data: rawptr,
}

/*
The C-visible context.

Upstream's context is opaque and heap-allocated, so its size is not part of the ABI — only
the fact that callers hold a pointer to it. That leaves this free to carry whatever the
implementation needs, which is the internal context plus the two C callbacks it may have to
call back into.
*/
Context :: struct {
	inner:            ctxp.Context,
	illegal:          C_Callback,
	error_cb:         C_Callback,
	/*
	Whether `context_destroy` should free this. False for a context placed in a caller's
	buffer by the preallocated API, and for the static context.
	*/
	heap_allocated:   bool,
}

// ---------------------------------------------------------------------------------------
// One-time initialization.
//
// `@(init)` procedures do not run when this code is linked into a C program: there is no
// Odin runtime start-up to run them. Every precomputed table would be zero, and signing
// would silently produce garbage — which is exactly what happened before this existed.
//
// The tables cannot simply be built by `context_create` either, because `secp256k1_context_
// static` lets a caller reach the library without ever creating a context. So every entry
// point calls `ensure_ready`, which is one relaxed atomic load in the common case.
// ---------------------------------------------------------------------------------------

@(private)
INIT_UNSTARTED :: 0
@(private)
INIT_RUNNING :: 1
@(private)
INIT_DONE :: 2

@(private)
init_state: u32

/*
Guarantees the library's tables and the static context are built before any use.

The double-checked lock is not decoration. `ecmult`'s tables are built once and then read
without synchronization, which is safe only if no reader can observe a partially built
table; that invariant normally holds because `@(init)` runs before any caller exists, and
under C linkage this is what replaces it.
*/
@(private)
ensure_ready :: #force_inline proc "contextless" () {
	if intrinsics.atomic_load_explicit(&init_state, .Acquire) == INIT_DONE {
		return
	}
	slow_init()
}

@(private)
slow_init :: proc "contextless" () {
	for {
		prev, won := intrinsics.atomic_compare_exchange_strong_explicit(
			&init_state,
			u32(INIT_UNSTARTED),
			u32(INIT_RUNNING),
			.Acquire,
			.Acquire,
		)
		if won {
			group.ensure_init()
			ecmult.ensure_init()
			ecdsa.ensure_init()
			ellswift.ensure_init()

			ctxp.context_create(&STATIC_CONTEXT.inner)
			// The static context is shared and immutable: `context_randomize` on it must
			// fail rather than reblind a context other callers are using.
			STATIC_CONTEXT.inner.declassify = true
			STATIC_CONTEXT.heap_allocated = false

			intrinsics.atomic_store_explicit(&init_state, u32(INIT_DONE), .Release)
			return
		}
		if prev == INIT_DONE {
			return
		}
		// Another thread is building the tables. Spin rather than proceed: the tables it
		// is writing are the ones this thread is about to read.
		intrinsics.cpu_relax()
	}
}

@(init, private)
init_on_load :: proc "contextless" () {
	// Runs only when linked into an Odin program. A C consumer never reaches this, which is
	// why `ensure_ready` exists.
	ensure_ready()
}

// ---------------------------------------------------------------------------------------
// The static context.
// ---------------------------------------------------------------------------------------

@(private)
STATIC_CONTEXT: Context

/*
`secp256k1_context_static` — a shared context usable for every operation that does not need
randomization.

Upstream exports this as `const secp256k1_context * const`, so it is a pointer variable, not
a function. It is exported unconditionally; `ensure_ready` is what makes the object behind
it valid, and every entry point that can receive it calls that first.
*/
@(export, link_name = "secp256k1_context_static")
context_static: ^Context = &STATIC_CONTEXT

/*
The deprecated spelling of the same object, kept because consumers written against older
headers still reference it.
*/
@(export, link_name = "secp256k1_context_no_precomp")
context_no_precomp: ^Context = &STATIC_CONTEXT

// ---------------------------------------------------------------------------------------
// Argument checking.
// ---------------------------------------------------------------------------------------

/*
Reports a violated precondition through the context's illegal-argument callback and returns
false, so callers can write `if !arg_check(...) { return 0 }`.

Matching upstream here matters more than it looks: a consumer's test suite may install a
callback and assert that a specific bad argument triggers it, and silently returning 0
without calling back would pass the functional test while failing that one.
*/
@(private)
arg_check :: proc "contextless" (ctx: ^Context, condition: bool, message: string) -> bool {
	if condition {
		return true
	}
	call_illegal(ctx, message)
	return false
}

@(private)
call_illegal :: proc "contextless" (ctx: ^Context, message: string) {
	if ctx == nil {
		// `call_illegal` routes a null context to the default handler, which aborts.
		ctxp.call_illegal(nil, message)
		return
	}
	ctxp.call_illegal(&ctx.inner, message)
}

@(private)
call_error :: proc "contextless" (ctx: ^Context, message: string) {
	if ctx == nil {
		ctxp.call_error(nil, message)
		return
	}
	ctxp.call_error(&ctx.inner, message)
}

/*
Bridges the internal callback signature to the C one.

`data` points at the `C_Callback` stored in the context, which is how the C function pointer
reaches a `proc "contextless"` that cannot capture it.
*/
@(private)
c_callback_shim :: proc "contextless" (message: string, data: rawptr) {
	cb := (^C_Callback)(data)
	if cb == nil || cb.fn == nil {
		return
	}
	// The C signature promises a NUL-terminated string. Odin string literals happen to be
	// stored with a trailing zero, but that is not a guarantee the language makes about an
	// arbitrary `string`, so copy rather than cast.
	buf: [256]u8
	n := min(len(message), len(buf) - 1)
	if n > 0 {
		mem.copy(&buf[0], raw_data(message), n)
	}
	buf[n] = 0
	cb.fn(cstring(&buf[0]), cb.data)
}

// ---------------------------------------------------------------------------------------
// Conversions between the opaque blobs and the internal representations.
//
// Points cross the ABI in their packed storage form, exactly as upstream does. That is what
// makes the blobs 64 bytes: a live `Ge` is larger, and larger still under `-debug` where it
// carries magnitude bookkeeping, so copying the in-memory representation would neither fit
// nor be ABI-stable.
// ---------------------------------------------------------------------------------------

@(private)
pubkey_store :: proc "contextless" (dst: ^Pubkey, ge: ^group.Ge) {
	st: group.Ge_Storage
	group.ge_to_storage(&st, ge)
	mem.copy(&dst.data[0], &st, size_of(group.Ge_Storage))
}

/*
Loads a public key, reporting whether the blob held a valid point.

A C caller can pass a zeroed or garbage `secp256k1_pubkey`, so this is fallible where the
Odin API's equivalent is not.
*/
@(private)
pubkey_load :: proc "contextless" (ge: ^group.Ge, src: ^Pubkey) -> bool {
	st: group.Ge_Storage
	mem.copy(&st, &src.data[0], size_of(group.Ge_Storage))
	group.ge_from_storage(ge, &st)
	return group.ge_is_valid_var(ge)
}

@(private)
sig_store :: proc "contextless" (dst: ^Ecdsa_Signature, sig: ^ecdsa.Signature) {
	scalar.scalar_get_b32((^[32]u8)(&dst.data[0]), &sig.r)
	scalar.scalar_get_b32((^[32]u8)(&dst.data[32]), &sig.s)
}

@(private)
sig_load :: proc "contextless" (sig: ^ecdsa.Signature, src: ^Ecdsa_Signature) {
	// Overflow is impossible for a blob this library wrote, and a blob it did not write is
	// the caller's problem; reducing is what upstream does too.
	scalar.scalar_set_b32(&sig.r, (^[32]u8)(&src.data[0]))
	scalar.scalar_set_b32(&sig.s, (^[32]u8)(&src.data[32]))
}

// ---------------------------------------------------------------------------------------
// Context lifecycle.
// ---------------------------------------------------------------------------------------

/*
Validates the flags a context-creating call was given.

Upstream accepts NONE, VERIFY, SIGN and DECLASSIFY, and rejects anything else through the
illegal callback.
*/
@(private)
flags_ok :: proc "contextless" (ctx: ^Context, flags: c.uint) -> bool {
	if (flags & FLAGS_TYPE_MASK) != FLAGS_TYPE_CONTEXT {
		call_illegal(ctx, "context_create: invalid flags")
		return false
	}
	return true
}

@(private)
context_init :: proc "contextless" (out: ^Context, declassify: bool) {
	ctxp.context_create(&out.inner)
	out.inner.declassify = declassify
	out.illegal = {}
	out.error_cb = {}
}

/*
Allocates and initializes a context.

The `flags` argument is accepted for source compatibility and, beyond validation, ignored:
this implementation has no separate sign and verify contexts, exactly as upstream has not
since 0.2.
*/
@(export, link_name = "secp256k1_context_create")
context_create :: proc "c" (flags: c.uint) -> ^Context {
	ensure_ready()
	if !flags_ok(nil, flags) {
		return nil
	}
	context = runtime.default_context()

	ctx := new(Context)
	if ctx == nil {
		return nil
	}
	context_init(ctx, false)
	ctx.heap_allocated = true
	return ctx
}

/*
Copies a context, including its callbacks.
*/
@(export, link_name = "secp256k1_context_clone")
context_clone :: proc "c" (ctx: ^Context) -> ^Context {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "context_clone: ctx is null") {
		return nil
	}
	context = runtime.default_context()

	out := new(Context)
	if out == nil {
		return nil
	}
	out^ = ctx^
	out.heap_allocated = true
	// The callbacks point into the *old* context's storage; re-aim them at the copy's.
	rebind_callbacks(out)
	return out
}

/*
Re-points a context's internal callback records at its own `C_Callback` fields.

A context is copied by value in `clone` and in the preallocated API, and the internal
callback carries a `data` pointer into the original's storage. Left alone, freeing the
original would leave the copy calling through a dangling pointer.
*/
@(private)
rebind_callbacks :: proc "contextless" (ctx: ^Context) {
	if ctx.illegal.fn != nil {
		ctxp.context_set_illegal_callback(&ctx.inner, c_callback_shim, &ctx.illegal)
	}
	if ctx.error_cb.fn != nil {
		ctxp.context_set_error_callback(&ctx.inner, c_callback_shim, &ctx.error_cb)
	}
}

/*
Destroys a context, zeroing its secret state.

Destroying the static context, or a context created by the preallocated API, is the caller's
error; upstream treats the former as a no-op-with-callback and the latter as undefined. Both
are handled explicitly here rather than freeing a pointer this library never allocated.
*/
@(export, link_name = "secp256k1_context_destroy")
context_destroy :: proc "c" (ctx: ^Context) {
	if ctx == nil {
		return
	}
	if ctx == &STATIC_CONTEXT {
		call_illegal(ctx, "context_destroy: the static context cannot be destroyed")
		return
	}
	context_destroy_inner(ctx)
	if ctx.heap_allocated {
		context = runtime.default_context()
		free(ctx)
	}
}

/*
Zeroes a context's secret state, without touching how it was allocated.

Shared with the preallocated API, which must scrub exactly the same state but has no buffer
of its own to release.
*/
@(private)
context_destroy_inner :: proc "contextless" (ctx: ^Context) {
	ctxp.context_destroy(&ctx.inner)
	ctx.illegal = {}
	ctx.error_cb = {}
}

/*
Re-randomizes a context's blinding. Returns 1 on success.
*/
@(export, link_name = "secp256k1_context_randomize")
context_randomize :: proc "c" (ctx: ^Context, seed32: ^[32]u8) -> c.int {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "context_randomize: ctx is null") {
		return 0
	}
	return 1 if ctxp.context_randomize(&ctx.inner, seed32) else 0
}

/*
Installs the callback invoked when an argument violates a documented precondition.

Passing a null function restores the default, which aborts.
*/
@(export, link_name = "secp256k1_context_set_illegal_callback")
context_set_illegal_callback :: proc "c" (
	ctx: ^Context,
	fun: proc "c" (message: cstring, data: rawptr),
	data: rawptr,
) {
	ensure_ready()
	if ctx == nil {
		return
	}
	if fun == nil {
		ctx.illegal = {}
		ctxp.context_set_illegal_callback(&ctx.inner, nil, nil)
		return
	}
	ctx.illegal = C_Callback {
		fn   = fun,
		data = data,
	}
	ctxp.context_set_illegal_callback(&ctx.inner, c_callback_shim, &ctx.illegal)
}

/*
Installs the callback invoked on an internal error — a condition that should be unreachable.
*/
@(export, link_name = "secp256k1_context_set_error_callback")
context_set_error_callback :: proc "c" (
	ctx: ^Context,
	fun: proc "c" (message: cstring, data: rawptr),
	data: rawptr,
) {
	ensure_ready()
	if ctx == nil {
		return
	}
	if fun == nil {
		ctx.error_cb = {}
		ctxp.context_set_error_callback(&ctx.inner, nil, nil)
		return
	}
	ctx.error_cb = C_Callback {
		fn   = fun,
		data = data,
	}
	ctxp.context_set_error_callback(&ctx.inner, c_callback_shim, &ctx.error_cb)
}

// ---------------------------------------------------------------------------------------
// Miscellaneous.
// ---------------------------------------------------------------------------------------

/*
Runs a minimal self-test.

Upstream's checks that the precomputed generator table is intact, which is the failure mode
a corrupted or mis-linked build actually produces. This does the same thing end to end: it
derives a known public key and verifies a known signature, so a zeroed table — the exact
symptom of `@(init)` not running under C linkage — cannot pass.
*/
@(export, link_name = "secp256k1_selftest")
selftest :: proc "c" () {
	ensure_ready()

	// seckey = 1, so the public key is G itself and the expected bytes are the curve
	// parameters rather than anything this implementation computed.
	seckey := [32]u8 {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}
	want := [33]u8 {
		0x02,
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}

	pk: Pubkey
	if ec_pubkey_create(&STATIC_CONTEXT, &pk, &seckey) != 1 {
		call_error(nil, "selftest: public key derivation failed")
	}

	out: [65]u8
	outlen := c.size_t(33)
	if ec_pubkey_serialize(&STATIC_CONTEXT, &out[0], &outlen, &pk, EC_COMPRESSED) != 1 {
		call_error(nil, "selftest: public key serialization failed")
	}
	for i in 0 ..< 33 {
		if out[i] != want[i] {
			call_error(nil, "selftest: generator multiple is wrong — the tables are corrupt")
		}
	}
}

/*
Computes the BIP340-style tagged hash `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
*/
@(export, link_name = "secp256k1_tagged_sha256")
tagged_sha256 :: proc "c" (
	ctx: ^Context,
	hash32: ^[32]u8,
	tag: [^]u8,
	taglen: c.size_t,
	msg: [^]u8,
	msglen: c.size_t,
) -> c.int {
	ensure_ready()
	if !arg_check(ctx, hash32 != nil, "tagged_sha256: hash32 is null") {
		return 0
	}
	if !arg_check(ctx, tag != nil || taglen == 0, "tagged_sha256: tag is null") {
		return 0
	}
	if !arg_check(ctx, msg != nil || msglen == 0, "tagged_sha256: msg is null") {
		return 0
	}
	t := tag[:int(taglen)] if taglen > 0 else nil
	m := msg[:int(msglen)] if msglen > 0 else nil
	hash.tagged_sha256(hash32, t, m)
	return 1
}
