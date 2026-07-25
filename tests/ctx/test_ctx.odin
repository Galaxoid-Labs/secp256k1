/*
Context and callback tests, mirroring upstream's `run_proper_context_tests`,
`run_ec_illegal_argument_tests` and `run_selftest_tests`.

The callback system exists so that a bad argument produces a defined failure instead of
undefined behaviour, and so that a library embedded in a server does not abort the process.
Testing it requires installing a handler that records rather than aborts — which is exactly
what a real caller who cares about availability would do.
*/
package test_ctx

import "core:testing"
import "../../ctx"
import "../../ecmult"
import "../../group"
import "../../params"
import "../../scalar"
import "../../testutil"

/*
Records callback invocations instead of aborting.
*/
Counter :: struct {
	count:   int,
	last:    string,
}

@(private = "file")
counting_handler :: proc "contextless" (message: string, data: rawptr) {
	c := (^Counter)(data)
	c.count += 1
	c.last = message
}

@(test)
test_run_proper_context_tests :: proc(t: ^testing.T) {
	c: ctx.Context
	ctx.context_create(&c)
	defer ctx.context_destroy(&c)

	testing.expect(t, c.ecmult_gen_ctx.built, "a fresh context is not built")

	// A fresh context must produce correct results even before randomization.
	k: scalar.Scalar
	scalar.scalar_set_int(&k, 12345)

	r: group.Gej
	ecmult.ecmult_gen(&c.ecmult_gen_ctx, &r, &k)

	// Cross-check against the general engine.
	gj: group.Gej
	group.gej_set_ge(&gj, &group.GENERATOR)
	want: group.Gej
	ecmult.ecmult(&want, &gj, &k, nil)
	testing.expect(t, group.gej_eq_var(&r, &want), "a fresh context computes the wrong result")

	// Randomizing must not change results.
	rng: testutil.Rand
	testutil.rand_seed(&rng, 0xfeed_face)
	seed: [32]u8
	testutil.rand_bytes(&rng, seed[:])
	testing.expect(t, ctx.context_randomize(&c, &seed), "context_randomize failed")

	r2: group.Gej
	ecmult.ecmult_gen(&c.ecmult_gen_ctx, &r2, &k)
	testing.expect(t, group.gej_eq_var(&r2, &want), "randomization changed the result")

	// And it must have actually changed the blinding state.
	testing.expect(t, !scalar.scalar_is_zero(&c.ecmult_gen_ctx.scalar_offset), "blinding state is zero")

	// Destroying must clear the built flag, so later use is detectable.
	ctx.context_destroy(&c)
	testing.expect(t, !c.ecmult_gen_ctx.built, "destroy did not clear the built flag")

	// Rebuild so the deferred destroy is harmless.
	ctx.context_create(&c)
}

@(test)
test_run_ec_illegal_argument_tests :: proc(t: ^testing.T) {
	c: ctx.Context
	ctx.context_create(&c)
	defer ctx.context_destroy(&c)

	counter: Counter
	ctx.context_set_illegal_callback(&c, counting_handler, &counter)

	// A satisfied precondition must not fire the callback and must report success.
	testing.expect(t, ctx.arg_check(&c, true, "should not fire"), "arg_check rejected a true condition")
	testing.expect_value(t, counter.count, 0)

	// A violated one must fire it exactly once and report failure.
	testing.expect(t, !ctx.arg_check(&c, false, "bad argument"), "arg_check accepted a false condition")
	testing.expect_value(t, counter.count, 1)
	testing.expect_value(t, counter.last, "bad argument")

    // Repeated violations accumulate rather than latching.
	ctx.arg_check(&c, false, "second failure")
	testing.expect_value(t, counter.count, 2)
	testing.expect_value(t, counter.last, "second failure")

	// The error callback is independent of the illegal-argument one.
	errors: Counter
	ctx.context_set_error_callback(&c, counting_handler, &errors)
	ctx.call_error(&c, "internal")
	testing.expect_value(t, errors.count, 1)
	testing.expect_value(t, counter.count, 2)

	// Installing nil restores the default handler. Not invoked here: the default aborts,
	// which is the documented behaviour and cannot be exercised from inside a test.
	ctx.context_set_illegal_callback(&c, nil, nil)
	testing.expect(t, c.illegal_callback.fn != nil, "the default handler was not restored")
	testing.expect(t, c.illegal_callback.data == nil, "the default handler kept stale user data")
}

/*
Confirms that the immutability flag blocks randomization, mirroring upstream's static
context behaviour.
*/
@(test)
test_run_static_context_tests :: proc(t: ^testing.T) {
	c: ctx.Context
	ctx.context_create(&c)
	defer ctx.context_destroy(&c)

	counter: Counter
	ctx.context_set_illegal_callback(&c, counting_handler, &counter)

	before := c.ecmult_gen_ctx.scalar_offset

	c.declassify = true
	seed: [32]u8
	testing.expect(t, !ctx.context_randomize(&c, &seed), "an immutable context accepted randomization")
	testing.expect_value(t, counter.count, 1)
	testing.expect(
		t,
		scalar.scalar_eq(&c.ecmult_gen_ctx.scalar_offset, &before),
		"a rejected randomization still modified the blinding",
	)
}

/*
Mirrors upstream's `run_selftest_tests`: a cheap end-to-end check that the library's own
arithmetic is self-consistent, of the kind a caller might run at startup.
*/
@(test)
test_run_selftest_tests :: proc(t: ^testing.T) {
	c: ctx.Context
	ctx.context_create(&c)
	defer ctx.context_destroy(&c)

	rng: testutil.Rand
	testutil.rand_seed(&rng, 0x5e1f_7e57)

	gj: group.Gej
	group.gej_set_ge(&gj, &group.GENERATOR)

	for i in 0 ..< params.COUNT {
		b32: [32]u8
		testutil.rand_bytes_test(&rng, b32[:])
		k: scalar.Scalar
		if scalar.scalar_set_b32(&k, &b32) {
			continue
		}

		// k*G computed three ways must agree.
		via_gen: group.Gej
		ecmult.ecmult_gen(&c.ecmult_gen_ctx, &via_gen, &k)

		via_ecmult: group.Gej
		ecmult.ecmult(&via_ecmult, &gj, &k, nil)

		via_table: group.Gej
		ecmult.ecmult(&via_table, &gj, &scalar.ZERO, &k)

		testing.expectf(t, group.gej_eq_var(&via_gen, &via_ecmult), "selftest: gen vs ecmult (%d)", i)
		testing.expectf(t, group.gej_eq_var(&via_table, &via_ecmult), "selftest: table vs ecmult (%d)", i)

		// The result must be on the curve.
		affine: group.Ge
		copy := via_gen
		group.ge_set_gej_var(&affine, &copy)
		if !group.ge_is_infinity(&affine) {
			testing.expectf(t, group.ge_is_valid_var(&affine), "selftest: k*G is off-curve (%d)", i)
		}
	}
}
