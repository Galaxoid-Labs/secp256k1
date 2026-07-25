/*
Benchmarks, reported side by side with libsecp256k1.

Mirrors the operation names and `us/op` units of upstream's `src/bench.c` so a run of this
and a run of upstream's can be diffed line by line, with an added ratio column.

	./bench/run.sh

Benchmarks are a **reporting tool, not a gate**. No phase is blocked on hitting a
performance target, and a benchmark result never justifies weakening a `*_verify` check or
taking a variable-time path on secret data.

# Reading the ratio

`ratio` is Odin time divided by C time, so below 1.00 is faster than C. Report the target
architecture alongside any number: on x86-64 upstream enables hand-written assembly for the
scalar reduction, so the comparison there is Odin-vs-asm for scalar work and Odin-vs-C
elsewhere. On ARM64 upstream has no assembly and every comparison is Odin-vs-C.
*/
package bench

import "core:c"
import "core:fmt"
import "core:time"
import "../ecdh"
import "../ecdsa"
import "../ecmult"
import "../eckey"
import "../extrakeys"
import "../group"
import "../oracle"
import "../scalar"
import "../schnorr"

ITERS :: #config(ITERS, 2000)

Result :: struct {
	name:    string,
	ours_us: f64,
	c_us:    f64,
}

results: [dynamic]Result

/*
Times a procedure, returning microseconds per operation.
*/
timeit :: proc(iters: int, f: proc(i: int)) -> f64 {
	// One warm-up pass, so first-call costs (table init, page faults) are not counted.
	f(0)
	start := time.now()
	for i in 0 ..< iters {
		f(i)
	}
	elapsed := time.since(start)
	return time.duration_microseconds(elapsed) / f64(iters)
}

report :: proc(name: string, ours, c_time: f64) {
	append(&results, Result{name, ours, c_time})
	ratio := ours / c_time
	// Odin's %10.3f zero-pads rather than space-pads, which reads badly in a table, so
	// the number is formatted first and padded as a string.
	fmt.printf(
		"%-28s %10s %10s %8s\n",
		name,
		fmt.tprintf("%.3f", ours),
		fmt.tprintf("%.3f", c_time),
		fmt.tprintf("%.2fx", ratio),
	)
}

// Shared fixtures.
gen: ecmult.Ecmult_Gen_Context
cctx: oracle.Context
seckey: [32]u8
msg: [32]u8
our_pub: group.Ge
c_pub: oracle.Pubkey
our_sig: ecdsa.Signature
c_sig: oracle.Ecdsa_Signature
our_kp: extrakeys.Keypair
c_kp: oracle.Keypair
our_xonly: extrakeys.Xonly_Pubkey
c_xonly: oracle.Xonly_Pubkey
our_schnorr_sig: [64]u8
aux: [32]u8

main :: proc() {
	ecmult.ecmult_gen_context_build(&gen)
	cctx = oracle.context_create(oracle.CONTEXT_SIGN | oracle.CONTEXT_VERIFY)

	for i in 0 ..< 32 {
		seckey[i] = u8(i + 1)
		msg[i] = u8(i * 7 + 3)
		aux[i] = u8(i * 3 + 5)
	}

	s: scalar.Scalar
	scalar.scalar_set_b32_seckey(&s, &seckey)
	eckey.pubkey_create(&gen, &our_pub, &s)
	oracle.ec_pubkey_create(cctx, &c_pub, &seckey[0])

	ecdsa.sign(&gen, &our_sig, &msg, &seckey)
	oracle.ecdsa_sign(cctx, &c_sig, &msg[0], &seckey[0], nil, nil)

	extrakeys.keypair_create(&gen, &our_kp, &seckey)
	oracle.keypair_create(cctx, &c_kp, &seckey[0])
	parity: bool
	extrakeys.keypair_xonly_pub(&our_xonly, &parity, &our_kp)
	cparity: i32
	oracle.keypair_xonly_pub(cctx, &c_xonly, &cparity, &c_kp)

	schnorr.sign(&gen, &our_schnorr_sig, msg[:], &our_kp, &aux)

	fmt.printfln("secp256k1 benchmarks — %d iterations, %v/%v", ITERS, ODIN_OS, ODIN_ARCH)
	fmt.println()
	fmt.printf("%-28s %10s %10s %9s\n", "operation", "odin us", "c us", "ratio")
	fmt.printf("%-28s %10s %10s %9s\n", "----------------------------", "----------", "----------", "---------")

	report(
		"ecdsa_sign",
		timeit(ITERS, proc(i: int) {
			sig: ecdsa.Signature
			ecdsa.sign(&gen, &sig, &msg, &seckey)
		}),
		timeit(ITERS, proc(i: int) {
			sig: oracle.Ecdsa_Signature
			oracle.ecdsa_sign(cctx, &sig, &msg[0], &seckey[0], nil, nil)
		}),
	)

	report(
		"ecdsa_verify",
		timeit(ITERS, proc(i: int) {
			ecdsa.verify(&our_sig, &msg, &our_pub)
		}),
		timeit(ITERS, proc(i: int) {
			oracle.ecdsa_verify(cctx, &c_sig, &msg[0], &c_pub)
		}),
	)

	report(
		"ec_pubkey_create",
		timeit(ITERS, proc(i: int) {
			s: scalar.Scalar
			scalar.scalar_set_b32_seckey(&s, &seckey)
			pk: group.Ge
			eckey.pubkey_create(&gen, &pk, &s)
		}),
		timeit(ITERS, proc(i: int) {
			pk: oracle.Pubkey
			oracle.ec_pubkey_create(cctx, &pk, &seckey[0])
		}),
	)

	report(
		"schnorrsig_sign",
		timeit(ITERS, proc(i: int) {
			sig: [64]u8
			schnorr.sign(&gen, &sig, msg[:], &our_kp, &aux)
		}),
		timeit(ITERS, proc(i: int) {
			sig: [64]u8
			oracle.schnorrsig_sign32(cctx, &sig[0], &msg[0], &c_kp, &aux[0])
		}),
	)

	report(
		"schnorrsig_verify",
		timeit(ITERS, proc(i: int) {
			schnorr.verify(&our_schnorr_sig, msg[:], &our_xonly)
		}),
		timeit(ITERS, proc(i: int) {
			oracle.schnorrsig_verify(cctx, &our_schnorr_sig[0], &msg[0], 32, &c_xonly)
		}),
	)

	report(
		"ecdh",
		timeit(ITERS, proc(i: int) {
			out: [32]u8
			ecdh.ecdh(out[:], &our_pub, &seckey)
		}),
		timeit(ITERS, proc(i: int) {
			out: [32]u8
			oracle.ecdh(cctx, &out[0], &c_pub, &seckey[0], nil, nil)
		}),
	)

	fmt.println()
	total_ours, total_c := 0.0, 0.0
	for r in results {
		total_ours += r.ours_us
		total_c += r.c_us
	}
	fmt.printfln("aggregate: %.2fx of C", total_ours / total_c)
	fmt.println()
	fmt.println("Ratios below 1.00 are faster than C. On x86-64 upstream uses hand-written")
	fmt.println("assembly for scalar reduction; on ARM64 it does not. Report the architecture.")

	oracle.context_destroy(cctx)
}
