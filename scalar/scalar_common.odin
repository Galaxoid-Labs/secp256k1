/*
Definitions shared by both scalar representations.

The 4x64 implementation (`scalar.odin` and friends) and the single-word exhaustive-test
implementation (`scalar_low.odin`) are mutually exclusive — each is wrapped in a `when` on
`EXHAUSTIVE_ORDER` and exactly one is compiled. Anything both of them need therefore has to
live outside those gates, which is what this file is for.
*/
package scalar

import "base:intrinsics"
import "base:runtime"

/*
Whether internal invariant checks are compiled in. Follows `-debug`, matching `field`, and
overridable the same way with `-define:SECP256K1_VERIFY=false`.
*/
VERIFY :: #config(SECP256K1_VERIFY, ODIN_DEBUG)

@(private)
CHECK :: #force_inline proc "contextless" (
	condition: bool,
	message: string = "scalar invariant violated",
	loc := #caller_location,
) {
	when VERIFY {
		runtime.assert_contextless(condition, message, loc)
	}
}

/*
Turns a selection flag into a full-width mask: 0 when false, all ones when true.

The volatile round-trip stops LLVM from recognizing the mask-select idiom and turning it
back into a branch. See the twin helper in the `field` package for the full argument and
for the `ecmult_gen` table scan that motivated it.
*/
@(private)
ct_mask :: #force_inline proc "contextless" (flag: bool) -> u64 {
	v: u64
	intrinsics.volatile_store(&v, u64(0) - u64(flag))
	return intrinsics.volatile_load(&v)
}
