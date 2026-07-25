/*
Component-level micro-benchmarks for the verify path.

`ecmult` dominates both verify operations, so this breaks it into the parts that can be
timed independently: the wNAF conversion, the odd-multiples table, and the point arithmetic
in the main loop.
*/
package micro

import "core:fmt"
import "core:time"
import "../../ecmult"
import "../../field"
import "../../group"
import "../../scalar"

sink: u64

timeit :: proc(name: string, iters: int, f: proc(i: int)) {
	f(0)
	start := time.tick_now()
	for i in 0 ..< iters {
		f(i)
	}
	ns := f64(time.tick_since(start)) / f64(iters)
	fmt.printf("  %-32s %10s ns/op\n", name, fmt.tprintf("%.1f", ns))
}

a, b, r: field.Field_Elem
s1, s2: scalar.Scalar
pt: group.Ge
ptj, acc: group.Gej

main :: proc() {
	buf: [32]u8
	for i in 0 ..< 32 { buf[i] = u8(i * 7 + 1) }
	field.fe_set_b32_mod(&a, &buf)
	buf[0] ~= 0xff
	field.fe_set_b32_mod(&b, &buf)
	scalar.scalar_set_b32(&s1, &buf)
	buf[1] ~= 0x0f
	scalar.scalar_set_b32(&s2, &buf)
	pt = group.GENERATOR
	group.gej_set_ge(&ptj, &pt)
	acc = ptj

	fmt.println("field primitives")
	timeit("fe_mul", 500000, proc(i: int) { field.fe_mul(&r, &a, &b); sink += r.n[0] })
	timeit("fe_sqr", 500000, proc(i: int) { field.fe_sqr(&r, &a); sink += r.n[0] })
	timeit("fe_negate+add", 500000, proc(i: int) {
		field.fe_negate(&r, &a, 1); field.fe_add(&r, &b); sink += r.n[0]
	})

	fmt.println()
	fmt.println("point arithmetic (the ecmult inner loop)")
	timeit("gej_double_var", 500000, proc(i: int) {
		group.gej_double_var(&acc, &acc, nil); sink += acc.x.n[0]
	})
	timeit("gej_add_ge_var", 500000, proc(i: int) {
		group.gej_add_ge_var(&acc, &acc, &pt, nil); sink += acc.x.n[0]
	})
	timeit("gej_add_zinv_var", 500000, proc(i: int) {
		group.gej_add_zinv_var(&acc, &acc, &pt, &a); sink += acc.x.n[0]
	})

	fmt.println()
	fmt.println("ecmult stages")
	timeit("wnaf(129, w=5)", 200000, proc(i: int) {
		d: [129]int
		n := ecmult.wnaf(d[:], &s1, 5); sink += u64(n)
	})
	timeit("wnaf(129, w=15)", 200000, proc(i: int) {
		d: [129]int
		n := ecmult.wnaf(d[:], &s1, 15); sink += u64(n)
	})
	timeit("split_lambda", 200000, proc(i: int) {
		x, y: scalar.Scalar
		scalar.scalar_split_lambda(&x, &y, &s1); sink += x.d[0]
	})
	timeit("odd_multiples_table(8)", 200000, proc(i: int) {
		pre: [8]group.Ge
		zr: [8]field.Field_Elem
		z: field.Field_Elem
		tmp := ptj
		ecmult.odd_multiples_table(pre[:], zr[:], &z, &tmp); sink += z.n[0]
	})

	fmt.println()
	fmt.println("whole operations")
	timeit("ecmult (na*P + ng*G)", 30000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult(&out, &ptj, &s1, &s2); sink += out.x.n[0]
	})
	timeit("ecmult (na*P only)", 30000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult(&out, &ptj, &s1, nil); sink += out.x.n[0]
	})
	timeit("ecmult (ng*G only)", 30000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult(&out, &ptj, &scalar.ZERO, &s2); sink += out.x.n[0]
	})
	timeit("ecmult_const", 30000, proc(i: int) {
		out: group.Gej
		ecmult.ecmult_const(&out, &pt, &s1); sink += out.x.n[0]
	})
	fmt.printfln("(sink %d)", sink & 1)
}
