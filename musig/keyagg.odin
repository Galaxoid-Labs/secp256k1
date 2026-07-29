/*
MuSig2 key aggregation, per BIP327.

Mirrors upstream's `modules/musig/keyagg_impl.h`.

# Why aggregation is not just a sum

The naive scheme — aggregate key = sum of participants' keys — is broken by the **rogue-key
attack**. A malicious last signer who sees everyone else's key P_1..P_{n-1} can publish
P_n = Q - sum(P_i) for a key Q it controls, making the aggregate exactly Q and letting it
sign alone.

MuSig2 defeats this by weighting each key with a coefficient derived from the hash of the
full key list:

	Q = sum(a_i * P_i),   a_i = H_agg(L, P_i)

An attacker cannot choose P_n to control Q, because changing P_n changes L and therefore
every coefficient.

The one exception is deliberate: the coefficient of the **second distinct key** in the list
is fixed at 1. This is a known optimisation from the specification that preserves security
while allowing one multiplication to be skipped, and it is why `second_pk` is tracked
separately.

# Tweaking and parity

Aggregate keys are tweaked for Taproot. Two accumulators must be carried alongside the key,
because a tweak applied to an x-only key may negate the underlying point:

  - `tweak` — the running sum of applied tweaks (`tacc` in the spec).
  - `parity_acc` — whether the accumulated point has been negated (`gacc` in the spec, as
    (1 - gacc)/2).

Signers need both to reconstruct their contribution correctly. Losing track of parity
produces partial signatures that fail to aggregate.
*/
package musig

import "../eckey"
import "../extrakeys"
import "../field"
import "../group"
import hash "../hash"
import "../scalar"

/*
State carried between key aggregation and signing.

Not a cache in the performance sense: `tweak` and `parity_acc` are load-bearing, and a
signer that discards them cannot produce a valid partial signature.
*/
Keyagg_Cache :: struct {
	/*
	The aggregate public key, including any applied tweaks.
	*/
	pk:         group.Ge,
	/*
	The second distinct key in the list, or infinity if every key is identical. Its
	aggregation coefficient is 1 by definition.
	*/
	second_pk:  group.Ge,
	/*
	Hash of the ordered list of participant keys.
	*/
	pks_hash:   [32]u8,
	/*
	Running sum of applied tweaks; `tacc` in the specification.
	*/
	tweak:      scalar.Scalar,
	/*
	Whether the accumulated point has been negated; corresponds to (1 - gacc)/2.
	*/
	parity_acc: bool,
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("KeyAgg list", ...).

Verified against a live computation by `tests/musig`.
*/
@(private)
sha256_keyagglist :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0xb399d5e0,
		0xc8fff302,
		0x6badac71,
		0x07c5b7f1,
		0x9701e2ef,
		0x2a72ecf8,
		0x201a4c7b,
		0xab148a38,
	}
	sha.bytes = 64
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("KeyAgg coefficient", ...).
*/
@(private)
sha256_keyaggcoef :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0x6ef02c5a,
		0x06a480de,
		0x1f298665,
		0x1d1134f2,
		0x56a0b063,
		0x52da4147,
		0xf280d9d4,
		0x4484be15,
	}
	sha.bytes = 64
}

/*
Hashes the ordered list of participant public keys.

Order matters: the same set of keys in a different order aggregates to a different key.
Callers who want order-independence must sort first, which is what `pubkey_sort` is for.
*/
compute_pks_hash :: proc "contextless" (pks_hash: ^[32]u8, pks: []group.Ge) -> bool {
	sha: hash.Sha256
	sha256_keyagglist(&sha)

	for i in 0 ..< len(pks) {
		if group.ge_is_infinity(&pks[i]) {
			return false
		}
		ser: [33]u8
		pk := pks[i]
		eckey.pubkey_serialize33(&pk, &ser)
		hash.sha256_write(&sha, ser[:])
	}

	hash.sha256_finalize(&sha, pks_hash)
	hash.sha256_clear(&sha)
	return true
}

/*
Computes the aggregation coefficient for one key.

Returns 1 for the second distinct key, per the specification's optimisation; otherwise
H_agg(pks_hash, pk).
*/
keyaggcoef_internal :: proc "contextless" (
	r: ^scalar.Scalar,
	pks_hash: ^[32]u8,
	pk: ^group.Ge,
	second_pk: ^group.Ge,
) {
	if !group.ge_is_infinity(second_pk) && group.ge_eq_var(pk, second_pk) {
		scalar.scalar_set_int(r, 1)
		return
	}

	sha: hash.Sha256
	sha256_keyaggcoef(&sha)
	hash.sha256_write(&sha, pks_hash[:])

	buf: [33]u8
	p := pk^
	eckey.pubkey_serialize33(&p, &buf)
	hash.sha256_write(&sha, buf[:])

	out: [32]u8
	hash.sha256_finalize(&sha, &out)
	scalar.scalar_set_b32(r, &out)
	hash.sha256_clear(&sha)
}

/*
Computes the aggregation coefficient for a key against a cache.
*/
keyaggcoef :: proc "contextless" (r: ^scalar.Scalar, cache: ^Keyagg_Cache, pk: ^group.Ge) {
	c := cache^
	keyaggcoef_internal(r, &c.pks_hash, pk, &c.second_pk)
}

/*
Aggregates participant public keys into a single x-only key.

`agg_pk` receives the x-only aggregate; `cache` receives the state signing will need. At
least one key is required, and none may be the point at infinity.

Returns false if the aggregate is the point at infinity, which happens only with
negligible probability for honestly generated keys but must still be rejected.
*/
pubkey_agg :: proc "contextless" (
	agg_pk: ^extrakeys.Xonly_Pubkey,
	cache: ^Keyagg_Cache,
	pubkeys: []group.Ge,
) -> bool {
	if len(pubkeys) == 0 {
		return false
	}
	for i in 0 ..< len(pubkeys) {
		if group.ge_is_infinity(&pubkeys[i]) {
			return false
		}
	}

	// Find the second distinct key; its coefficient is fixed at 1.
	second_pk: group.Ge
	group.ge_set_infinity(&second_pk)
	for i in 1 ..< len(pubkeys) {
		if !group.ge_eq_var(&pubkeys[0], &pubkeys[i]) {
			second_pk = pubkeys[i]
			break
		}
	}

	pks_hash: [32]u8
	if !compute_pks_hash(&pks_hash, pubkeys) {
		return false
	}

	// Q = sum(a_i * P_i)
	pkj: group.Gej
	group.gej_set_infinity(&pkj)

	for i in 0 ..< len(pubkeys) {
		pk := pubkeys[i]
		a: scalar.Scalar
		keyaggcoef_internal(&a, &pks_hash, &pk, &second_pk)

		term: group.Gej
		// The keys are public, so the variable-time engine is appropriate here.
		pj: group.Gej
		group.gej_set_ge(&pj, &pk)
		ecmult_point(&term, &pj, &a)
		group.gej_add_var(&pkj, &pkj, &term, nil)
	}

	pkp: group.Ge
	group.ge_set_gej(&pkp, &pkj)
	if group.ge_is_infinity(&pkp) {
		return false
	}
	field.fe_normalize_var(&pkp.y)

	if cache != nil {
		cache.pk = pkp
		cache.second_pk = second_pk
		cache.pks_hash = pks_hash
		scalar.scalar_set_int(&cache.tweak, 0)
		cache.parity_acc = false
	}

	if agg_pk != nil {
		p := pkp
		extrakeys.ge_even_y(&p)
		agg_pk.point = p
	}
	return true
}

/*
Extracts the current aggregate key from a cache as an x-only key.
*/
pubkey_get :: proc "contextless" (agg_pk: ^extrakeys.Xonly_Pubkey, cache: ^Keyagg_Cache) -> bool {
	if group.ge_is_infinity(&cache.pk) {
		return false
	}
	p := cache.pk
	extrakeys.ge_even_y(&p)
	agg_pk.point = p
	return true
}

/*
Applies a tweak to the aggregate key, updating the cache's accumulators.

`xonly` selects the tweaking convention: true for BIP341 Taproot, where the key is first
forced to even y and the parity accumulator flipped; false for a plain additive tweak.

Returns false if the tweak is at or above n, or if the result would be the point at
infinity.
*/
pubkey_tweak_add_internal :: proc "contextless" (
	output: ^group.Ge,
	cache: ^Keyagg_Cache,
	tweak32: ^[32]u8,
	xonly: bool,
) -> bool {
	tweak: scalar.Scalar
	if scalar.scalar_set_b32(&tweak, tweak32) {
		return false
	}

	// For an x-only tweak the point is forced to even y first. That negation has to be
	// recorded in both accumulators, or signers will compute the wrong contribution.
	if xonly && extrakeys.ge_even_y(&cache.pk) {
		cache.parity_acc = !cache.parity_acc
		scalar.scalar_negate(&cache.tweak, &cache.tweak)
	}

	scalar.scalar_add(&cache.tweak, &cache.tweak, &tweak)

	if !eckey.pubkey_tweak_add(&cache.pk, &tweak) {
		return false
	}
	if group.ge_is_infinity(&cache.pk) {
		return false
	}

	if output != nil {
		output^ = cache.pk
	}
	return true
}

/*
Applies a BIP341 x-only tweak to the aggregate key.
*/
pubkey_xonly_tweak_add :: proc "contextless" (
	output: ^group.Ge,
	cache: ^Keyagg_Cache,
	tweak32: ^[32]u8,
) -> bool {
	return pubkey_tweak_add_internal(output, cache, tweak32, true)
}

/*
Applies a plain additive tweak to the aggregate key.
*/
pubkey_ec_tweak_add :: proc "contextless" (
	output: ^group.Ge,
	cache: ^Keyagg_Cache,
	tweak32: ^[32]u8,
) -> bool {
	return pubkey_tweak_add_internal(output, cache, tweak32, false)
}

/*
Sorts public keys into the canonical order defined by their compressed serializations.

Aggregation is order-dependent, so participants who want to agree on a key without agreeing
on an order sort first. Insertion sort: participant counts are small, and a simple
comparison-stable algorithm is easier to audit than a fast one.
*/
pubkey_sort :: proc "contextless" (pubkeys: []group.Ge) {
	for i in 1 ..< len(pubkeys) {
		key := pubkeys[i]
		ki: [33]u8
		kcopy := key
		eckey.pubkey_serialize33(&kcopy, &ki)

		j := i - 1
		for j >= 0 {
			jj: [33]u8
			jcopy := pubkeys[j]
			eckey.pubkey_serialize33(&jcopy, &jj)
			if compare33(&jj, &ki) <= 0 {
				break
			}
			pubkeys[j + 1] = pubkeys[j]
			j -= 1
		}
		pubkeys[j + 1] = key
	}
}

@(private)
compare33 :: proc "contextless" (a: ^[33]u8, b: ^[33]u8) -> int {
	for i in 0 ..< 33 {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
