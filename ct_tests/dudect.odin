/*
Statistical constant-time testing, in the style of dudect.

Reparaz, Balasch and Verbauwhede, "Dude, is my code constant time?" (DATE 2017).

# Why this exists

The memory-checker harness in `main.odin` is the rigorous route, but both of its backends
require Linux: valgrind has no macOS ARM64 port, and `-sanitize:memory` is rejected by
clang on this target. Verified, not assumed — both were attempted.

This test needs neither. Instead of reasoning about *why* timing might vary, it measures
whether it does:

  - Two input classes. **Class 0** uses a fixed secret; **class 1** uses a fresh random
    secret each time. Everything else is identical.
  - The operation is timed for randomly interleaved samples from both classes, so drift in
    CPU frequency, cache state or scheduling affects both equally.
  - Welch's t-test compares the two timing distributions. Under the null hypothesis — that
    running time is independent of the secret — the two are samples from the same
    distribution and |t| stays small.

A large |t| means the running time carries information about the secret. That is a timing
side channel, measured rather than inferred.

# What it can and cannot say

It **can** catch a variable-time multiply on a secret scalar, an early return on a secret
comparison, or a secret-indexed table lookup large enough to move the cache.

It **cannot** prove absence. A negative result means no leak was detected at this sample
size on this machine — not that none exists. Small leaks need more samples, and a
sufficiently noisy machine can mask a real signal. It also cannot see leaks that do not
manifest as wall-clock time, which is exactly where valgrind's instruction-level view is
stronger.

The two approaches are complementary, and neither replaces the other. `TRUST.md` grants
`ct-verified` only on the valgrind gate; this test is evidence, not the gate.

	./ct_tests/build.sh --dudect && ./ct_tests.bin
*/
package ct_tests

import "core:fmt"
import "core:math"
import "core:time"
import "../ecdh"
import "../ecdsa"
import "../ecmult"
import "../eckey"
import "../extrakeys"
import "../group"
import "../scalar"
import "../schnorr"
import "../testutil"

/*
Whether to run the statistical test instead of the memory-checker harness.
*/
DUDECT :: #config(DUDECT, false)

/*
Measurements per class. More samples resolve smaller leaks.
*/
DUDECT_SAMPLES :: #config(DUDECT_SAMPLES, 20000)

/*
The |t| threshold above which a leak is reported.

dudect uses 10, which is deliberately conservative: |t| > 4.5 would already be significant
at any reasonable confidence, so 10 leaves a wide margin for measurement noise and avoids
crying wolf on a loaded machine.
*/
T_THRESHOLD :: 10.0

/*
Running mean and variance, by Welford's method.

Computed incrementally rather than by storing every sample: the naive two-pass formula
loses precision on the large, tightly clustered values a cycle counter produces.
*/
Stats :: struct {
	n:    f64,
	mean: f64,
	m2:   f64,
}

stats_push :: proc(s: ^Stats, x: f64) {
	s.n += 1
	delta := x - s.mean
	s.mean += delta / s.n
	s.m2 += delta * (x - s.mean)
}

stats_var :: proc(s: ^Stats) -> f64 {
	if s.n < 2 {
		return 0
	}
	return s.m2 / (s.n - 1)
}

/*
Welch's t statistic for two samples with unequal variances.
*/
welch_t :: proc(a: ^Stats, b: ^Stats) -> f64 {
	va := stats_var(a) / a.n
	vb := stats_var(b) / b.n
	denom := math.sqrt(va + vb)
	if denom == 0 {
		return 0
	}
	return (a.mean - b.mean) / denom
}

/*
One timing measurement class.
*/
Class :: enum {
	Fixed,
	Random,
}

/*
Runs a timing test over an operation that consumes a 32-byte secret.

`prepare` fills the secret for a class; `run` performs the operation. The operation must do
the same amount of *logical* work for both classes — only the secret differs — or the test
measures the difference in work rather than a leak.
*/
run_dudect :: proc(
	name: string,
	prepare: proc(rng: ^testutil.Rand, class: Class, secret: ^[32]u8),
	run: proc(secret: ^[32]u8),
) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, 0xd0d0_cafe_1234)

	fixed_stats, random_stats: Stats
	secret: [32]u8

	// Warm up: first calls pay for lazy table construction and cold caches, and would
	// otherwise land entirely in whichever class happens to go first.
	for _ in 0 ..< 100 {
		prepare(&rng, .Random, &secret)
		run(&secret)
	}

	// Collect raw timings, interleaving classes at random so that any drift over the run
	// affects both equally.
	raw_fixed := make([dynamic]f64, 0, DUDECT_SAMPLES)
	raw_random := make([dynamic]f64, 0, DUDECT_SAMPLES)
	defer delete(raw_fixed)
	defer delete(raw_random)

	for i in 0 ..< DUDECT_SAMPLES * 2 {
		class: Class = .Fixed if testutil.rand_bool(&rng) else .Random
		prepare(&rng, class, &secret)

		start := time.tick_now()
		run(&secret)
		elapsed := f64(time.tick_since(start))

		if class == .Fixed {
			if len(raw_fixed) < DUDECT_SAMPLES {
				append(&raw_fixed, elapsed)
			}
		} else {
			if len(raw_random) < DUDECT_SAMPLES {
				append(&raw_random, elapsed)
			}
		}
	}

	// Discard the slowest 10%. Long tails come from preemption and interrupts, not from
	// the code under test, and they inflate the variance enough to hide a real signal.
	// dudect applies the same cropping.
	crop :: proc(xs: []f64) -> f64 {
		hi := f64(0)
		for x in xs {
			if x > hi {
				hi = x
			}
		}
		return hi * 0.9
	}
	limit_f := crop(raw_fixed[:])
	limit_r := crop(raw_random[:])
	limit := min(limit_f, limit_r)

	for x in raw_fixed {
		if x <= limit {
			stats_push(&fixed_stats, x)
		}
	}
	for x in raw_random {
		if x <= limit {
			stats_push(&random_stats, x)
		}
	}

	t := welch_t(&fixed_stats, &random_stats)
	abs_t := t if t >= 0 else -t

	verdict := "ok" if abs_t < T_THRESHOLD else "LEAK"
	fmt.printf(
		"  %-4s %-34s |t| = %7.2f   (n=%.0f/%.0f, %.0f vs %.0f ns)\n",
		verdict,
		name,
		abs_t,
		fixed_stats.n,
		random_stats.n,
		fixed_stats.mean,
		random_stats.mean,
	)

	if abs_t >= T_THRESHOLD {
		failures += 1
	}
}

// Fixtures shared by the measured operations.
@(private = "file")
dctx: ecmult.Ecmult_Gen_Context
@(private = "file")
dmsg: [32]u8
@(private = "file")
dpoint: group.Ge
@(private = "file")
dkp: extrakeys.Keypair

/*
Fills the secret for a class.

The fixed class uses a single constant value throughout; the random class draws fresh bytes
each time. Both are always valid secret keys, so key-validity checks cannot themselves
cause a difference.
*/
@(private = "file")
prep_seckey :: proc(rng: ^testutil.Rand, class: Class, secret: ^[32]u8) {
	if class == .Fixed {
		for i in 0 ..< 32 {
			secret[i] = u8(i + 1)
		}
		return
	}
	for {
		testutil.rand_bytes(rng, secret[:])
		// Keep the top byte clear so the value is always well below n; this removes the
		// rejection loop, which would otherwise run a different number of times per class.
		secret[0] = 0x01
		if secp_seckey_ok(secret) {
			return
		}
	}
}

@(private = "file")
secp_seckey_ok :: proc(secret: ^[32]u8) -> bool {
	s: scalar.Scalar
	ok := scalar.scalar_set_b32_seckey(&s, secret)
	scalar.scalar_clear(&s)
	return ok
}

run_dudect_suite :: proc() {
	ecmult.ecmult_gen_context_build(&dctx)
	seed: [32]u8
	for i in 0 ..< 32 {
		seed[i] = u8(i * 3 + 1)
		dmsg[i] = u8(i * 7 + 5)
	}
	ecmult.ecmult_gen_blind(&dctx, &seed)

	base: [32]u8
	for i in 0 ..< 32 {
		base[i] = u8(i + 2)
	}
	bs: scalar.Scalar
	scalar.scalar_set_b32_seckey(&bs, &base)
	eckey.pubkey_create(&dctx, &dpoint, &bs)
	extrakeys.keypair_create(&dctx, &dkp, &base)

	fmt.printfln("secp256k1 statistical constant-time test (dudect)")
	fmt.printfln("%d samples per class, |t| threshold %.1f, %v/%v", DUDECT_SAMPLES, T_THRESHOLD, ODIN_OS, ODIN_ARCH)
	fmt.println()

	run_dudect("ecmult_gen (pubkey_create)", prep_seckey, proc(secret: ^[32]u8) {
		s: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, secret)
		pk: group.Ge
		eckey.pubkey_create(&dctx, &pk, &s)
	})

	run_dudect("ecdsa_sign", prep_seckey, proc(secret: ^[32]u8) {
		sig: ecdsa.Signature
		ecdsa.sign(&dctx, &sig, &dmsg, secret)
	})

	run_dudect("ecdh (ecmult_const)", prep_seckey, proc(secret: ^[32]u8) {
		out: [32]u8
		ecdh.ecdh(out[:], &dpoint, secret)
	})

	run_dudect("scalar_inverse", prep_seckey, proc(secret: ^[32]u8) {
		s, inv: scalar.Scalar
		scalar.scalar_set_b32_seckey(&s, secret)
		scalar.scalar_inverse(&inv, &s)
	})

	run_dudect("schnorr_sign", prep_seckey, proc(secret: ^[32]u8) {
		kp: extrakeys.Keypair
		if !extrakeys.keypair_create(&dctx, &kp, secret) {
			return
		}
		sig: [64]u8
		schnorr.sign(&dctx, &sig, dmsg[:], &kp, nil)
	})

	fmt.println()
	if failures > 0 {
		fmt.printfln("%d operation(s) show a secret-dependent timing signal", failures)
	} else {
		fmt.println("no timing signal detected at this sample size")
		fmt.println()
		fmt.println("This is evidence, not proof: a negative result bounds the leak by the")
		fmt.println("resolution of the measurement. The valgrind gate in TRUST.md still applies.")
	}
}
