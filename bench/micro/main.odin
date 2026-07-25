/*
Component-level micro-benchmarks, to locate where time actually goes.

The top-level benchmarks say ecdsa_sign is the slowest relative to C; these break the
operations into their parts so the cause is measured rather than guessed.
*/
package micro

import "core:fmt"
import "core:time"
import "../../ecmult"
import "../../field"
import "../../group"
import "../../hash"
import "../../oracle"
import "../../scalar"

N :: 200000

timeit :: proc(name: string, iters: int, f: proc(i: int)) -> f64 {
	f(0)
	start := time.tick_now()
	for i in 0 ..< iters {
		f(i)
	}
	ns := f64(time.tick_since(start)) / f64(iters)
	fmt.printf("  %-30s %10s ns/op\n", name, fmt.tprintf("%.1f", ns))
	return ns
}

a, b, r: field.Field_Elem
s1, s2, sr: scalar.Scalar
buf: [32]u8
big: [1024]u8
gen: ecmult.Ecmult_Gen_Context
pt: group.Ge
ptj: group.Gej

main :: proc() {
	ecmult.ecmult_gen_context_build(&gen)
	for i in 0 ..< 32 {
		buf[i] = u8(i * 7 + 1)
	}
	for i in 0 ..< 1024 {
		big[i] = u8(i)
	}
	field.fe_set_b32_mod(&a, &buf)
	buf[0] ~= 0xff
	field.fe_set_b32_mod(&b, &buf)
	scalar.scalar_set_b32(&s1, &buf)
	buf[1] ~= 0x0f
	scalar.scalar_set_b32(&s2, &buf)
	pt = group.GENERATOR
	group.gej_set_ge(&ptj, &pt)

	fmt.println("field / scalar primitives")
	timeit("fe_mul", N, proc(i: int) { field.fe_mul(&r, &a, &b) })
	timeit("fe_sqr", N, proc(i: int) { field.fe_sqr(&r, &a) })
	timeit("fe_inv", 20000, proc(i: int) { field.fe_inv(&r, &a) })
	timeit("scalar_mul", N, proc(i: int) { scalar.scalar_mul(&sr, &s1, &s2) })
	timeit("scalar_inverse", 20000, proc(i: int) { scalar.scalar_inverse(&sr, &s1) })

	fmt.println()
	fmt.println("hashing (the RFC6979 nonce path)")
	timeit("sha256 32B", N, proc(i: int) {
		sha: hash.Sha256
		out: [32]u8
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, buf[:])
		hash.sha256_finalize(&sha, &out)
	})
	timeit("sha256 1KiB", 50000, proc(i: int) {
		sha: hash.Sha256
		out: [32]u8
		hash.sha256_initialize(&sha)
		hash.sha256_write(&sha, big[:])
		hash.sha256_finalize(&sha, &out)
	})
	timeit("hmac_sha256 32B", 100000, proc(i: int) {
		h: hash.Hmac_Sha256
		out: [32]u8
		hash.hmac_sha256_initialize(&h, buf[:])
		hash.hmac_sha256_write(&h, buf[:])
		hash.hmac_sha256_finalize(&h, &out)
	})
	timeit("rfc6979 init+gen", 50000, proc(i: int) {
		rng: hash.Rfc6979_Hmac_Sha256
		out: [32]u8
		hash.rfc6979_hmac_sha256_initialize(&rng, big[:64])
		hash.rfc6979_hmac_sha256_generate(&rng, out[:])
	})

	fmt.println()
	fmt.println("group / ecmult")
	timeit("gej_double", N, proc(i: int) { group.gej_double(&ptj, &ptj) })
	timeit("gej_add_ge", N, proc(i: int) { group.gej_add_ge(&ptj, &ptj, &pt) })
	timeit("ecmult_gen", 20000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult_gen(&gen, &out, &s1)
	})
	timeit("ecmult_const", 20000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult_const(&out, &pt, &s1)
	})
	timeit("ecmult (a*P + b*G)", 20000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult(&out, &ptj, &s1, &s2)
	})

	fmt.println()
	fmt.println("C reference for the same hashes")
	ctx_global = oracle.context_create(oracle.CONTEXT_NONE)
	tag := [4]u8{'t', 'a', 'g', '!'}
	timeit("C tagged_sha256 32B", N, proc(i: int) {
		out: [32]u8
		t := [4]u8{'t', 'a', 'g', '!'}
		oracle.tagged_sha256(ctx_global, &out[0], &t[0], 4, &buf[0], 32)
	})
	oracle.context_destroy(ctx_global)
	_ = tag
}

ctx_global: oracle.Context
