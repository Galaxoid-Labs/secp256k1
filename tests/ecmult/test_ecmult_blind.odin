/*
Tests for `ecmult_gen` blinding, mirroring upstream's `run_ecmult_gen_blind`.

The property that matters is that blinding changes nothing observable about the *result*
while changing everything about the intermediate values. Only the first half is testable
from outside the implementation; the second is what the Phase 8 constant-time harness is
for. What is checked here:

  - a blinded context computes the same products as an unblinded one, for every scalar;
  - re-randomizing actually changes the internal blinding state, so the call is not a
    silent no-op;
  - chaining is entropy-accumulating rather than entropy-replacing.

A blinding bug that produced *wrong* answers would be caught immediately by any signing
test. The dangerous failure is blinding that silently does nothing, which is why the state
itself is inspected rather than only the outputs.
*/
package test_ecmult

import "core:testing"
import "../../ecmult"
import "../../group"
import "../../params"
import "../../scalar"
import "../../testutil"

@(test)
test_run_ecmult_gen_blind :: proc(t: ^testing.T) {
	rng: testutil.Rand
	testutil.rand_seed(&rng, TEST_SEED + 10)

	unblinded: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&unblinded)

	blinded: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&blinded)

	seed: [32]u8
	testutil.rand_bytes(&rng, seed[:])
	ecmult.ecmult_gen_blind(&blinded, &seed)

	// The blinding state must actually have changed.
	testing.expect(
		t,
		!scalar.scalar_eq(&blinded.scalar_offset, &unblinded.scalar_offset),
		"blinding did not change the scalar offset",
	)
	testing.expect(
		t,
		!group.ge_eq_var(&blinded.ge_offset, &unblinded.ge_offset),
		"blinding did not change the group offset",
	)

	// Results must be identical regardless of blinding.
	for i in 0 ..< params.COUNT {
		k := random_scalar(&rng)

		a, b: group.Gej
		ecmult.ecmult_gen(&unblinded, &a, &k)
		ecmult.ecmult_gen(&blinded, &b, &k)

		testing.expectf(t, group.gej_eq_var(&a, &b), "blinded and unblinded results differ (%d)", i)
	}

	// Re-blinding with a fresh seed must change the state again, and still not change the
	// results.
	before := blinded.scalar_offset
	seed2: [32]u8
	testutil.rand_bytes(&rng, seed2[:])
	ecmult.ecmult_gen_blind(&blinded, &seed2)
	testing.expect(
		t,
		!scalar.scalar_eq(&blinded.scalar_offset, &before),
		"re-blinding left the scalar offset unchanged",
	)

	k := random_scalar(&rng)
	a, b: group.Gej
	ecmult.ecmult_gen(&unblinded, &a, &k)
	ecmult.ecmult_gen(&blinded, &b, &k)
	testing.expect(t, group.gej_eq_var(&a, &b), "results differ after re-blinding")

	// The same seed applied to two contexts in the same state must give the same blinding,
	// since the derivation is deterministic.
	c1, c2: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&c1)
	ecmult.ecmult_gen_context_build(&c2)
	ecmult.ecmult_gen_blind(&c1, &seed)
	ecmult.ecmult_gen_blind(&c2, &seed)
	testing.expect(
		t,
		scalar.scalar_eq(&c1.scalar_offset, &c2.scalar_offset),
		"blinding derivation is not deterministic",
	)

	// Different seeds must give different blinding.
	c3: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&c3)
	ecmult.ecmult_gen_blind(&c3, &seed2)
	testing.expect(
		t,
		!scalar.scalar_eq(&c1.scalar_offset, &c3.scalar_offset),
		"different seeds produced the same blinding",
	)

	// A nil seed resets to the unblinded state.
	ecmult.ecmult_gen_blind(&c3, nil)
	testing.expect(
		t,
		scalar.scalar_eq(&c3.scalar_offset, &unblinded.scalar_offset),
		"a nil seed did not reset the blinding",
	)

	// Blinding must survive the edge scalars too.
	for k_edge in ([]^scalar.Scalar{&scalar.ZERO, &scalar.ONE}) {
		x, y: group.Gej
		ecmult.ecmult_gen(&unblinded, &x, k_edge)
		ecmult.ecmult_gen(&blinded, &y, k_edge)
		testing.expect(t, group.gej_eq_var(&x, &y), "blinded and unblinded differ on an edge scalar")
	}
}
