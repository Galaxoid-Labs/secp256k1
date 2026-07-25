/*
The library context: blinding state and the callback system.

A context carries the `ecmult_gen` blinding state and two callbacks. It is not a
performance cache — the multiplication tables are package-level and shared — so a context
exists almost entirely to hold randomization and error-handling policy.

# Why callbacks rather than panics

`CLAUDE.md` forbids panics in library paths. Upstream routes invalid arguments through a
settable callback that, by default, aborts; a caller who prefers to recover can install
their own. That behaviour is reproduced here because it is part of the API contract the C
ABI must match, and because a cryptographic library that aborts inside a signing routine is
a denial-of-service vector in a server.

Two distinct callbacks, mirroring upstream:

  - **illegal argument** — the caller violated a documented precondition. The library's
    state is fine; the call is not performed.
  - **error** — an internal invariant failed. This should be unreachable.

Both default to aborting, which is the safe behaviour when nobody has said otherwise: it is
far better to stop than to return a value computed from invalid input.

Mirrors upstream's context handling in `secp256k1.c` and `util.h`.

# Naming

`CLAUDE.md` lists this module as `context`, but `context` is a reserved word in Odin — it
names the implicit context every procedure receives — so the package is `ctx`. This is the
one place the documented layout could not be followed literally; the language forbids it.
*/
package ctx

import "base:intrinsics"
import "base:runtime"
import "core:os"
import "../ecmult"

/*
A callback invoked when a precondition is violated.

`data` is the pointer supplied when the callback was installed.
*/
Callback :: struct {
	fn:   proc "contextless" (message: string, data: rawptr),
	data: rawptr,
}

/*
The library context.
*/
Context :: struct {
	ecmult_gen_ctx:   ecmult.Ecmult_Gen_Context,
	illegal_callback: Callback,
	error_callback:   Callback,
	/*
	Whether this context may be modified. The static context is immutable, so that a
	shared default cannot be randomized or reconfigured out from under other users.
	*/
	declassify:       bool,
}

/*
The default handler: report and abort.

Aborting is the right default because the alternative is continuing with invalid input. A
caller who needs to recover installs their own handler and is responsible for not using the
result.
*/
@(private)
default_illegal_handler :: proc "contextless" (message: string, data: rawptr) {
	print_and_abort("[secp256k1] illegal argument: ", message)
}

@(private)
default_error_handler :: proc "contextless" (message: string, data: rawptr) {
	print_and_abort("[secp256k1] internal consistency check failed: ", message)
}

@(private)
print_and_abort :: proc "contextless" (prefix: string, message: string) -> ! {
	// `core:os` writes need a context, which a `contextless` procedure does not have, so
	// establish the default one. Nothing here allocates; the write goes straight to the
	// stderr file descriptor rather than through `core:fmt`.
	context = runtime.default_context()
	os.write(os.stderr, transmute([]u8)prefix)
	os.write(os.stderr, transmute([]u8)message)
	os.write(os.stderr, []u8{'\n'})

	// Terminate immediately without unwinding, matching upstream's abort(): once an
	// invariant has failed, running any more code on that state is the greater risk.
	intrinsics.trap()
}

/*
The default callback pair, used by every context that has not overridden them.
*/
@(rodata)
DEFAULT_ILLEGAL_CALLBACK := Callback {
	fn   = default_illegal_handler,
	data = nil,
}

@(rodata)
DEFAULT_ERROR_CALLBACK := Callback {
	fn   = default_error_handler,
	data = nil,
}

/*
Creates a context with default callbacks and no blinding.

Call `context_randomize` before using it for any secret-key operation; until then
`ecmult_gen` runs deterministically and unblinded.
*/
context_create :: proc "contextless" (ctx: ^Context) {
	ecmult.ecmult_gen_context_build(&ctx.ecmult_gen_ctx)
	ctx.illegal_callback = DEFAULT_ILLEGAL_CALLBACK
	ctx.error_callback = DEFAULT_ERROR_CALLBACK
	ctx.declassify = false
}

/*
Zeroes a context's secret state.
*/
context_destroy :: proc "contextless" (ctx: ^Context) {
	ecmult.ecmult_gen_context_clear(&ctx.ecmult_gen_ctx)
}

/*
Re-randomizes the context's blinding from a 32-byte seed.

This protects secret-key operations against side channels that depend on the intermediate
values of the computation. It is the caller's job to invoke it with good entropy; passing a
nil seed resets to the deterministic, unblinded state.

Repeated calls accumulate entropy rather than replacing it, so calling it periodically —
for example between signatures — is strictly better than calling it once.
*/
context_randomize :: proc "contextless" (ctx: ^Context, seed32: ^[32]u8) -> bool {
	if ctx.declassify {
		call_illegal(ctx, "context_randomize: the static context cannot be randomized")
		return false
	}
	ecmult.ecmult_gen_blind(&ctx.ecmult_gen_ctx, seed32)
	return true
}

/*
Installs a handler for precondition violations.

Passing a nil function restores the default aborting handler.
*/
context_set_illegal_callback :: proc "contextless" (
	ctx: ^Context,
	fn: proc "contextless" (message: string, data: rawptr),
	data: rawptr,
) {
	if fn == nil {
		ctx.illegal_callback = DEFAULT_ILLEGAL_CALLBACK
		return
	}
	ctx.illegal_callback = Callback {
		fn   = fn,
		data = data,
	}
}

/*
Installs a handler for internal errors.

Passing a nil function restores the default aborting handler.
*/
context_set_error_callback :: proc "contextless" (
	ctx: ^Context,
	fn: proc "contextless" (message: string, data: rawptr),
	data: rawptr,
) {
	if fn == nil {
		ctx.error_callback = DEFAULT_ERROR_CALLBACK
		return
	}
	ctx.error_callback = Callback {
		fn   = fn,
		data = data,
	}
}

/*
Invokes the illegal-argument callback.
*/
call_illegal :: proc "contextless" (ctx: ^Context, message: string) {
	if ctx == nil || ctx.illegal_callback.fn == nil {
		default_illegal_handler(message, nil)
		return
	}
	ctx.illegal_callback.fn(message, ctx.illegal_callback.data)
}

/*
Invokes the internal-error callback.
*/
call_error :: proc "contextless" (ctx: ^Context, message: string) {
	if ctx == nil || ctx.error_callback.fn == nil {
		default_error_handler(message, nil)
		return
	}
	ctx.error_callback.fn(message, ctx.error_callback.data)
}

/*
Checks a precondition, invoking the illegal-argument callback and returning false if it
fails.

This is the shape every public entry point uses:

	if !arg_check(ctx, seckey != nil, "seckey must not be nil") { return false }

so that a bad argument produces a defined failure rather than undefined behaviour.
*/
arg_check :: proc "contextless" (ctx: ^Context, condition: bool, message: string) -> bool {
	if !condition {
		call_illegal(ctx, message)
		return false
	}
	return true
}
