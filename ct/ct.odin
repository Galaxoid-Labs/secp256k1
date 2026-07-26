/*
Constant-time support: the declassification hook, and helpers that must not branch.

# What this is for

The constant-time harness marks secret buffers as undefined and lets a memory checker report
any branch or memory index that depends on them. Some values *stop* being secret partway
through an operation, and the code is then entitled to branch on them: a signature is
published, a validity flag is returned to the caller, a Schnorr `R` becomes half the
signature. Without a way to say so, every one of those is reported as a leak, and real
findings drown in them.

Upstream solves this with `secp256k1_declassify(ctx, p, len)` calls placed inside the
library at each such point. This is the same idea.

# Why a function pointer rather than a direct call

`CLAUDE.md` is explicit that the quarantined `oracle` package is the only one that links C.
The memory-checker primitives are C, so the library cannot call them directly without
breaking that rule. Instead the harness installs a hook and the library calls through it.

# Cost when disabled

None. `DECLASSIFY_ENABLED` is false unless `-define:SECP256K1_DECLASSIFY=true`, so in every
ordinary build — including `-o:speed` releases and the normal test suite — `declassify` has
an empty body, holds no state, and compiles to nothing. The hook variable does not exist.

# What a call here means

Every call site is an assertion that the value has genuinely become public, and each one
carries a comment saying why. A declassification that is not true is worse than no harness
at all: it silences a real leak and leaves a green result behind. Note what upstream does
*not* declassify — the validity of a secret key is deliberately kept secret, because
publishing it narrows the key's range.
*/
package ct

import "base:intrinsics"

/*
Whether the declassification hook is compiled in.

Off by default. The constant-time harness turns it on with
`-define:SECP256K1_DECLASSIFY=true`.
*/
DECLASSIFY_ENABLED :: #config(SECP256K1_DECLASSIFY, false)

Hook :: proc "contextless" (p: rawptr, len: int)

when DECLASSIFY_ENABLED {
	@(private)
	hook: Hook

	/*
	Installs the declassification hook. Called once by the harness at start-up.
	*/
	set_hook :: proc "contextless" (h: Hook) {
		hook = h
	}
}

/*
Marks a value as no longer secret, so the checker stops reporting branches on it.

A no-op unless the hook is compiled in and installed.
*/
declassify :: #force_inline proc "contextless" (p: rawptr, len: int) {
	when DECLASSIFY_ENABLED {
		if hook != nil {
			hook(p, len)
		}
	}
}

/*
Zeroes a buffer if `flag` is set, in constant time.

Mirrors upstream's `secp256k1_memczero`. The obvious `if flag { zero }` is a branch on
`flag`, and `flag` is usually the validity of a secret key — which is exactly the bit that
must not become observable. `keypair_create` is the motivating caller: it writes the keypair
unconditionally and then erases it if the key turned out to be invalid, so the erase itself
cannot be allowed to leak.

The mask goes through a volatile round-trip for the same reason the field and scalar `cmov`
helpers do: written as plain arithmetic, LLVM recognises the idiom and rewrites it back into
a branch. See `field/field_arith.odin` for the full argument and the disassembly that
motivated it.
*/
czero :: proc "contextless" (p: rawptr, len: int, flag: bool) {
	v: u8
	intrinsics.volatile_store(&v, u8(0) - u8(flag))
	mask := ~intrinsics.volatile_load(&v)

	b := ([^]u8)(p)
	for i in 0 ..< len {
		b[i] &= mask
	}
}
