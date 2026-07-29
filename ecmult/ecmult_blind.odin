/*
Blinding for `ecmult_gen`.

Split from `ecmult_gen.odin` because it is the only part of the package that needs the
`hash` package, and keeping the dependency visible makes the layering obvious.

Two independent blinds are applied, and they defend against different things:

  - **Scalar blinding.** R = gn*G is computed as (gn - b)*G + b*G, so the scalar the comb
    actually consumes is not the secret one. An attacker who recovers the comb's input
    learns gn - b, not gn.
  - **Projective blinding.** The accumulator starts with a random Z coordinate. The result
    is unchanged, since Jacobian coordinates are only defined up to that scaling, but every
    intermediate field value differs from run to run.

Both are derived from an RFC6979 CSPRNG rather than taken from the caller, which means the
interface cannot fail and a weak or adversarial seed still yields usable blinds. The
previous blinding value is chained into the hash, so calling `context_randomize` repeatedly
accumulates entropy instead of replacing it.

Mirrors upstream's `secp256k1_ecmult_gen_blind`.
*/
package ecmult

import "core:mem"
import "../field"
import "../group"
import hash "../hash"
import "../scalar"

/*
Re-randomizes a context's blinding from a 32-byte seed.

Passing a nil seed resets to the deterministic, unblinded state — useful for reproducible
tests, and what `ecmult_gen_context_build` installs.
*/
ecmult_gen_blind_seeded :: proc "contextless" (ctx: ^Ecmult_Gen_Context, seed32: ^[32]u8) {
	diff: scalar.Scalar
	gen_scalar_diff(&diff)

	if seed32 == nil {
		ecmult_gen_context_build(ctx)
		return
	}

	// Chain the previous blinding value forward so repeated calls accumulate entropy.
	keydata: [64]u8
	kd0 := (^[32]u8)(&keydata[0])
	scalar.scalar_get_b32(kd0, &ctx.scalar_offset)
	copy(keydata[32:], seed32[:])

	rng: hash.Rfc6979_Hmac_Sha256
	hash.rfc6979_hmac_sha256_initialize(&rng, keydata[:])
	mem.zero_explicit(&keydata, size_of(keydata))

	nonce32: [32]u8

	// The projective blind must be non-zero, or the rescale would send the point to
	// infinity.
	hash.rfc6979_hmac_sha256_generate(&rng, nonce32[:])
	f: field.Field_Elem
	field.fe_set_b32_mod(&f, &nonce32)
	field.fe_cmov(&f, &field.ONE, field.fe_normalizes_to_zero(&f))
	ctx.proj_blind = f

	// For a blinding scalar b: scalar_offset = diff - b, ge_offset = b*G.
	hash.rfc6979_hmac_sha256_generate(&rng, nonce32[:])
	b: scalar.Scalar
	scalar.scalar_set_b32(&b, &nonce32)

	// b must not be zero: ge_offset would then be infinity, which the constant-time
	// addition at the end of `ecmult_gen` cannot accept.
	scalar.scalar_cmov(&b, &scalar.ONE, scalar.scalar_is_zero(&b))

	gb: group.Gej
	ecmult_gen(ctx, &gb, &b)
	scalar.scalar_negate(&b, &b)
	scalar.scalar_add(&ctx.scalar_offset, &b, &diff)
	group.ge_set_gej(&ctx.ge_offset, &gb)

	mem.zero_explicit(&nonce32, size_of(nonce32))
	scalar.scalar_clear(&b)
	group.gej_clear(&gb)
	field.fe_clear(&f)
	hash.rfc6979_hmac_sha256_clear(&rng)
}
