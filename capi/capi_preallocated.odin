/*
Context creation in caller-supplied memory.

Mirrors upstream's `secp256k1_preallocated.h`. It exists for callers that cannot use malloc
at all — embedded targets, allocator-free environments, and anything that must place the
context in a specific arena.

The caller's buffer must be aligned for any type this library uses. Upstream states the same
requirement; the practical reading is that a buffer from `malloc`, or one declared as an
array of `uint64_t` or `max_align_t`, is fine, and a `char` array at an arbitrary offset is
not.
*/
package capi

import "core:c"
import "core:mem"

/*
The number of bytes a context occupies.

The `flags` argument is validated and otherwise unused: this implementation, like upstream
since 0.2, builds one kind of context.
*/
@(export, link_name = "secp256k1_context_preallocated_size")
context_preallocated_size :: proc "c" (flags: c.uint) -> c.size_t {
	ensure_ready()
	if !flags_ok(nil, flags) {
		return 0
	}
	return c.size_t(size_of(Context))
}

/*
Initializes a context inside a caller-supplied buffer.

The buffer must be at least `context_preallocated_size(flags)` bytes and stay alive for as
long as the context is used. It is not freed by `context_destroy`.
*/
@(export, link_name = "secp256k1_context_preallocated_create")
context_preallocated_create :: proc "c" (prealloc: rawptr, flags: c.uint) -> ^Context {
	ensure_ready()
	if prealloc == nil {
		call_illegal(nil, "context_preallocated_create: prealloc is null")
		return nil
	}
	if !flags_ok(nil, flags) {
		return nil
	}
	ctx := (^Context)(prealloc)
	mem.zero(ctx, size_of(Context))
	context_init(ctx, false)
	ctx.heap_allocated = false
	return ctx
}

/*
The number of bytes a clone of this context would occupy.
*/
@(export, link_name = "secp256k1_context_preallocated_clone_size")
context_preallocated_clone_size :: proc "c" (ctx: ^Context) -> c.size_t {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "context_preallocated_clone_size: ctx is null") {
		return 0
	}
	return c.size_t(size_of(Context))
}

/*
Copies a context into a caller-supplied buffer.
*/
@(export, link_name = "secp256k1_context_preallocated_clone")
context_preallocated_clone :: proc "c" (ctx: ^Context, prealloc: rawptr) -> ^Context {
	ensure_ready()
	if !arg_check(ctx, ctx != nil, "context_preallocated_clone: ctx is null") {
		return nil
	}
	if !arg_check(ctx, prealloc != nil, "context_preallocated_clone: prealloc is null") {
		return nil
	}
	out := (^Context)(prealloc)
	out^ = ctx^
	out.heap_allocated = false
	// The copy's callbacks still point into the source context's storage; re-aim them, or
	// destroying the source would leave this one calling through freed memory.
	rebind_callbacks(out)
	return out
}

/*
Zeroes a preallocated context's secret state without freeing the caller's buffer.
*/
@(export, link_name = "secp256k1_context_preallocated_destroy")
context_preallocated_destroy :: proc "c" (ctx: ^Context) {
	if ctx == nil {
		return
	}
	if ctx == &STATIC_CONTEXT {
		call_illegal(ctx, "context_preallocated_destroy: the static context cannot be destroyed")
		return
	}
	if !arg_check(
		ctx,
		!ctx.heap_allocated,
		"context_preallocated_destroy: this context came from context_create; use context_destroy",
	) {
		return
	}
	context_destroy_inner(ctx)
}
