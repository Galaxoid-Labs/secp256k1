/*
Generates the precomputed generator tables as a binary blob for compile-time embedding.

Mirrors upstream's `precompute_ecmult`, which emits a C source file compiled into the
library. Odin has no arbitrary compile-time execution — no `#run` — so the table cannot be
*computed* by the compiler. It can be *embedded* by one: this program writes the raw table
bytes, and `ecmult_tables.odin` pulls them in with `#load` when
`-define:SECP256K1_EMBED_TABLES=true` is set.

That turns roughly 12 ms of process start-up into zero, because the tables arrive as rodata
in the binary rather than being built by every process that starts.

# Why a blob rather than generated source

Emitting Odin source with 131,072 `u64` literals would be about 2.6 MB of text for the
compiler to parse on every build. The blob is 1 MB, costs nothing to parse, and is
reinterpreted in place with a pointer cast rather than copied.

The price is that the bytes are host-endian, so the embedded path is little-endian only and
asserts as much. Every target this library cares about is little-endian, and the runtime
build remains available everywhere as the fallback.

# Nothing is trusted

`tests/ecmult` recomputes both tables from scratch and compares them against the embedded
bytes entry by entry. A stale or corrupted blob fails that test rather than silently serving
wrong points — which is what `CLAUDE.md` means by "regeneration from scratch must reproduce
byte-identical tables; that reproduction is a test".

	odin run precompute_ecmult/ -o:speed
*/
package precompute_ecmult

import "core:fmt"
import "core:os"
import "../ecmult"

OUT_PATH :: "ecmult/pre_g.bin"

main :: proc() {
	// Building the context is what populates the tables.
	ecmult.ensure_init()

	n := len(ecmult.PRE_G)
	entry := size_of(ecmult.PRE_G[0])
	total := 2 * n * entry

	buf := make([]u8, total)
	defer delete(buf)

	// Both tables, back to back, in their in-memory representation.
	src_a := ([^]u8)(&ecmult.PRE_G[0])
	src_b := ([^]u8)(&ecmult.PRE_G_128[0])
	copy(buf[:n * entry], src_a[:n * entry])
	copy(buf[n * entry:], src_b[:n * entry])

	// `core:os` returns an `os.Error` union rather than a bool since dev-2026-03.
	if err := os.write_entire_file(OUT_PATH, buf); err != nil {
		fmt.eprintfln("failed to write %s: %v", OUT_PATH, err)
		os.exit(1)
	}

	fmt.printfln(
		"wrote %s: %d entries x %d bytes x 2 tables = %d bytes",
		OUT_PATH,
		n,
		entry,
		total,
	)
	fmt.printfln("enable with: odin build . -define:SECP256K1_EMBED_TABLES=true")
}
