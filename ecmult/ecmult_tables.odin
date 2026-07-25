/*
Precomputed tables of generator multiples, and the programs that build them.

Two tables serve the variable-time engine: odd multiples of G, and odd multiples of
2^128*G. The endomorphism-free split of a scalar into two 128-bit halves is what makes the
second one useful.

Upstream generates equivalent tables into a checked-in C source file. Here they are built
at package initialization by the same algorithm, which means:

  - nothing is vendored, so there is no checked-in blob to drift out of sync with the code
    and nothing large for a submodule consumer to clone;
  - the "regenerate and compare" requirement is met continuously rather than by a separate
    step, and `tests/ecmult` additionally verifies each entry against an independently
    computed multiple of G.

The cost is a few milliseconds of startup, kept low by converting all points with a single
batched inversion instead of one inversion per entry.

Mirrors upstream's `ecmult_compute_table_impl.h` and `ecmult_gen_compute_table_impl.h`.
*/
package ecmult

import "../group"
import "../scalar"

/*
Odd multiples of G: [1*G, 3*G, ..., (2*TABLE_SIZE_G - 1)*G].
*/
PRE_G: [TABLE_SIZE_G]group.Ge_Storage

/*
Odd multiples of 2^128*G, for the high half of a 256-bit scalar.
*/
PRE_G_128: [TABLE_SIZE_G]group.Ge_Storage

/*
Fills `table` with odd multiples of `gen`: [1*gen, 3*gen, 5*gen, ...].

Each entry is obtained by adding 2*gen to the previous one. Conversions to affine are
batched, so the whole table costs one field inversion rather than one per entry.
*/
compute_table :: proc "contextless" (table: []group.Ge_Storage, gen: ^group.Gej) {
	n := len(table)
	if n == 0 {
		return
	}

	// Build the multiples in Jacobian coordinates first.
	points := make_gej_buffer(n)
	defer_free_gej_buffer(points)

	gj := gen^
	points[0] = gj

	dgen_j: group.Gej
	group.gej_double_var(&dgen_j, gen, nil)
	dgen: group.Ge
	dcopy := dgen_j
	group.ge_set_gej_var(&dgen, &dcopy)

	for j in 1 ..< n {
		acc := points[j - 1]
		group.gej_add_ge_var(&acc, &acc, &dgen, nil)
		points[j] = acc
	}

	// One batched inversion for the whole table.
	affine := make_ge_buffer(n)
	defer_free_ge_buffer(affine)
	group.ge_set_all_gej_var(affine[:n], points[:n])

	for j in 0 ..< n {
		CHECK(!group.ge_is_infinity(&affine[j]), "compute_table: table entry is infinity")
		group.ge_to_storage(&table[j], &affine[j])
	}
}

/*
Fills both generator tables: odd multiples of gen, and of 2^128*gen.
*/
compute_two_tables :: proc "contextless" (
	table: []group.Ge_Storage,
	table_128: []group.Ge_Storage,
	gen: ^group.Ge,
) {
	gj: group.Gej
	group.gej_set_ge(&gj, gen)
	compute_table(table, &gj)

	for _ in 0 ..< 128 {
		group.gej_double_var(&gj, &gj, nil)
	}
	compute_table(table_128, &gj)
}

/*
Storage for table construction.

The tables are built once at initialization, so fixed global scratch avoids both a heap
allocation and a large stack frame. `CLAUDE.md` requires the hot paths to be
allocation-free; this is initialization, but using static storage keeps the rule uniform.
*/
@(private)
table_scratch_gej: [TABLE_SIZE_G]group.Gej
@(private)
table_scratch_ge: [TABLE_SIZE_G]group.Ge

@(private)
make_gej_buffer :: #force_inline proc "contextless" (n: int) -> []group.Gej {
	CHECK(n <= TABLE_SIZE_G, "table scratch too small")
	return table_scratch_gej[:n]
}

@(private)
make_ge_buffer :: #force_inline proc "contextless" (n: int) -> []group.Ge {
	CHECK(n <= TABLE_SIZE_G, "table scratch too small")
	return table_scratch_ge[:n]
}

@(private)
defer_free_gej_buffer :: #force_inline proc "contextless" (_: []group.Gej) {}

@(private)
defer_free_ge_buffer :: #force_inline proc "contextless" (_: []group.Ge) {}

@(init, private)
init_tables :: proc "contextless" () {
	g := group.GENERATOR
	compute_two_tables(PRE_G[:], PRE_G_128[:], &g)
}

/*
Returns the scalar 1/2 mod n, used when building the comb table for `ecmult_gen`.

The comb operates on G/2 rather than G, which avoids a modular division by two in the
per-call path.
*/
@(private)
scalar_half_one :: proc "contextless" () -> scalar.Scalar {
	h: scalar.Scalar
	scalar.scalar_half(&h, &scalar.ONE)
	return h
}
