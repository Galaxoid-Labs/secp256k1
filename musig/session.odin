/*
MuSig2 signing sessions: nonces, partial signatures, and aggregation.

Mirrors upstream's `modules/musig/session_impl.h`.

# Two nonces per signer, and why

A naive multi-signature where each signer publishes one nonce point is broken by Wagner's
generalised birthday attack: an adversary who can open many concurrent sessions and choose
its nonce last can solve for a forgery.

MuSig2 defeats this by giving each signer **two** nonces (R_i1, R_i2) and combining them
with a coefficient b derived from the hash of the aggregate nonces, the aggregate key and
the message:

	R = R_1 + b*R_2

Because b depends on all the nonces, an adversary cannot choose its contribution to control
R, and the attack does not apply.

# Nonce reuse is fatal

Two partial signatures produced under the same secret nonce let anyone solve for that
signer's secret key by elementary algebra. There is no recovery and no detection: the
signatures look valid.

The API therefore enforces single use structurally. `partial_sign` **zeroes the secnonce
before doing anything else**, so a second call with the same nonce fails rather than
signing. That ordering is deliberate — the wipe happens even on the error paths, because a
caller that retries after a failure must not get a second signature under the first nonce.
*/
package musig

import "core:mem"
import "../ct"
import "../ecmult"
import "../eckey"
import "../extrakeys"
import "../field"
import "../group"
import "../hash"
import "../scalar"

/*
A signer's secret nonce pair.

**Single use.** Consumed and zeroed by `partial_sign`. Never persist it, never copy it, and
never sign twice with one.
*/
Secnonce :: struct {
	k:     [2]scalar.Scalar,
	pk:    group.Ge,
	valid: bool,
}

/*
A signer's public nonce pair.
*/
Pubnonce :: struct {
	pt: [2]group.Ge,
}

/*
The aggregate of all signers' public nonces.
*/
Aggnonce :: struct {
	pt: [2]group.Ge,
}

/*
Per-session values shared by all signers, derived once nonces and message are known.
*/
Session :: struct {
	fin_nonce:        [32]u8,
	fin_nonce_parity: bool,
	/*
	The binding coefficient b.
	*/
	noncecoef:        scalar.Scalar,
	/*
	The BIP340 challenge for the final nonce and aggregate key.
	*/
	challenge:        scalar.Scalar,
	/*
	The part of s contributed by tweaks rather than by signers.
	*/
	s_part:           scalar.Scalar,
}

/*
A signer's partial signature.
*/
Partial_Sig :: struct {
	s: scalar.Scalar,
}

/*
Initializes a SHA-256 state to the precomputed midstate for
tagged_hash("MuSig/noncecoef", ...).
*/
@(private)
sha256_noncecoef :: proc "contextless" (sha: ^hash.Sha256) {
	hash.sha256_initialize(sha)
	sha.s = {
		0x2c7d5a45,
		0x06bf7e53,
		0x89be68a6,
		0x971254c0,
		0x60ac12d2,
		0x72846dcd,
		0x6c81212f,
		0xde7a2500,
	}
	sha.bytes = 64
}

/*
Serializes a point in the 33-byte "extended" form used by the nonce hash, where the point
at infinity is encoded as 33 zero bytes.

Infinity has no ordinary compressed encoding, but an aggregate nonce can legitimately be
infinity, so the specification defines this extension rather than failing.
*/
@(private)
ge_serialize_ext :: proc "contextless" (out33: ^[33]u8, p: ^group.Ge) {
	if group.ge_is_infinity(p) {
		for i in 0 ..< 33 {
			out33[i] = 0
		}
		return
	}
	q := p^
	eckey.pubkey_serialize33(&q, out33)
}

/*
Parses the 33-byte extended form, accepting all-zero as the point at infinity.
*/
@(private)
ge_parse_ext :: proc "contextless" (p: ^group.Ge, in33: ^[33]u8) -> bool {
	all_zero := true
	for i in 0 ..< 33 {
		if in33[i] != 0 {
			all_zero = false
			break
		}
	}
	if all_zero {
		group.ge_set_infinity(p)
		return true
	}
	return eckey.pubkey_parse(p, in33[:])
}

/*
Computes the binding coefficient input hash over the aggregate nonces, aggregate key and
message.
*/
@(private)
compute_noncehash :: proc "contextless" (
	noncehash: ^[32]u8,
	aggnonce: ^[2]group.Ge,
	agg_pk32: ^[32]u8,
	msg: []u8,
) {
	sha: hash.Sha256
	sha256_noncecoef(&sha)

	buf: [33]u8
	for i in 0 ..< 2 {
		ge_serialize_ext(&buf, &aggnonce[i])
		hash.sha256_write(&sha, buf[:])
	}
	hash.sha256_write(&sha, agg_pk32[:])
	hash.sha256_write(&sha, msg)
	hash.sha256_finalize(&sha, noncehash)
	hash.sha256_clear(&sha)
}

/*
Generates a signer's nonce pair.

`session_id32` **must not repeat** across signing sessions for the same key. It is the
primary defence against nonce reuse: the derivation mixes it with the secret key, the
message and the aggregate key, but a repeated session id with identical other inputs
reproduces the nonce exactly.

Supplying `seckey32` is strongly recommended — it binds the nonce to the signer's key so
that a session-id collision across different signers is harmless.
*/
nonce_gen :: proc "contextless" (
	ctx: ^ecmult.Ecmult_Gen_Context,
	secnonce: ^Secnonce,
	pubnonce: ^Pubnonce,
	session_id32: ^[32]u8,
	seckey32: ^[32]u8,
	pubkey: ^group.Ge,
	msg32: ^[32]u8 = nil,
	agg_pk32: ^[32]u8 = nil,
	extra_input32: ^[32]u8 = nil,
) -> bool {
	// BIP327 NonceGen, exactly. Every framing detail below is normative, not stylistic:
	// this derivation has to agree byte for byte with any other conforming implementation,
	// and a scheme that is merely self-consistent will interoperate with nobody and fail
	// the specification's vectors.
	//
	//   rand      = seckey XOR tagged_hash("MuSig/aux", session_id), or session_id alone
	//   k_i       = int(tagged_hash("MuSig/nonce",
	//                     rand || len(pk)  || pk
	//                          || len(aggpk) || aggpk
	//                          || msg_prefix
	//                          || len32(extra) || extra
	//                          || i)) mod n
	//
	// The secret key is folded in by XOR against a hash of the session id rather than being
	// hashed alongside it, so that a caller who reuses a session id across signers still
	// gets distinct nonces. The signer's own public key is part of the hash for the same
	// reason — omitting it is how two signers sharing entropy end up sharing a nonce, which
	// leaks both secret keys.
	rand: [32]u8
	if seckey32 != nil {
		aux: hash.Sha256
		hash.sha256_initialize_tagged(&aux, transmute([]u8)string("MuSig/aux"))
		hash.sha256_write(&aux, session_id32[:])
		hash.sha256_finalize(&aux, &rand)
		hash.sha256_clear(&aux)
		for i in 0 ..< 32 {
			rand[i] ~= seckey32[i]
		}
	} else {
		rand = session_id32^
	}

	sha: hash.Sha256
	hash.sha256_initialize_tagged(&sha, transmute([]u8)string("MuSig/nonce"))
	hash.sha256_write(&sha, rand[:])

	// The signer's public key, length-prefixed with its 33-byte compressed form.
	pk_ser: [33]u8
	eckey.pubkey_serialize33(pubkey, &pk_ser)
	pk_len := [1]u8{33}
	hash.sha256_write(&sha, pk_len[:])
	hash.sha256_write(&sha, pk_ser[:])

	// The aggregate key, or a zero length when absent.
	if agg_pk32 != nil {
		l := [1]u8{32}
		hash.sha256_write(&sha, l[:])
		hash.sha256_write(&sha, agg_pk32[:])
	} else {
		l := [1]u8{0}
		hash.sha256_write(&sha, l[:])
	}

	// The message is framed as a presence byte and, when present, an 8-byte big-endian
	// length. An absent message and a 32-byte zero message must not hash alike.
	if msg32 != nil {
		present := [1]u8{1}
		hash.sha256_write(&sha, present[:])
		msg_len := [8]u8{0, 0, 0, 0, 0, 0, 0, 32}
		hash.sha256_write(&sha, msg_len[:])
		hash.sha256_write(&sha, msg32[:])
	} else {
		present := [1]u8{0}
		hash.sha256_write(&sha, present[:])
	}

	// Extra input carries a 4-byte big-endian length, unlike the message's 8.
	if extra_input32 != nil {
		l := [4]u8{0, 0, 0, 32}
		hash.sha256_write(&sha, l[:])
		hash.sha256_write(&sha, extra_input32[:])
	} else {
		l := [4]u8{0, 0, 0, 0}
		hash.sha256_write(&sha, l[:])
	}

	// Both nonces come from the same prefix with the index appended, so the state is cloned
	// rather than recomputed.
	for i in 0 ..< 2 {
		h := sha
		idx := [1]u8{u8(i)}
		hash.sha256_write(&h, idx[:])

		out: [32]u8
		hash.sha256_finalize(&h, &out)
		hash.sha256_clear(&h)

		scalar.scalar_set_b32(&secnonce.k[i], &out)
		mem.zero_explicit(&out, size_of(out))

		// Whether the derived nonce came out zero is declassified so the rejection can
		// branch on it. Only that one bit becomes public, not the nonce, and it is set with
		// probability below 1 in 2^255. Upstream declassifies the same bit in
		// `musig_secnonce_load`.
		is_zero := scalar.scalar_is_zero(&secnonce.k[i])
		ct.declassify(&is_zero, size_of(is_zero))
		if is_zero {
			// Astronomically unlikely; refuse rather than substitute.
			mem.zero_explicit(secnonce, size_of(Secnonce))
			mem.zero_explicit(&rand, size_of(rand))
			hash.sha256_clear(&sha)
			return false
		}

		rj: group.Gej
		ecmult.ecmult_gen(ctx, &rj, &secnonce.k[i])
		group.ge_set_gej(&pubnonce.pt[i], &rj)
		group.gej_clear(&rj)
	}

	secnonce.pk = pubkey^
	secnonce.valid = true
	mem.zero_explicit(&rand, size_of(rand))
	hash.sha256_clear(&sha)
	return true
}

/*
Aggregates signers' public nonces componentwise.

Either component may aggregate to infinity, which is legitimate and handled by the extended
serialization.
*/
nonce_agg :: proc "contextless" (aggnonce: ^Aggnonce, pubnonces: []Pubnonce) -> bool {
	if len(pubnonces) == 0 {
		return false
	}

	for i in 0 ..< 2 {
		acc: group.Gej
		group.gej_set_infinity(&acc)
		for j in 0 ..< len(pubnonces) {
			p := pubnonces[j].pt[i]
			if group.ge_is_infinity(&p) {
				continue
			}
			group.gej_add_ge_var(&acc, &acc, &p, nil)
		}
		group.ge_set_gej_var(&aggnonce.pt[i], &acc)
	}
	return true
}

/*
Derives the session values every signer needs: the binding coefficient, the final nonce and
the challenge.

Must be called with the same aggregate nonce, message and key by all participants, or their
partial signatures will not combine.
*/
nonce_process :: proc "contextless" (
	session: ^Session,
	aggnonce: ^Aggnonce,
	msg32: ^[32]u8,
	cache: ^Keyagg_Cache,
) -> bool {
	agg_pk: extrakeys.Xonly_Pubkey
	if !pubkey_get(&agg_pk, cache) {
		return false
	}
	agg_pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

	// b = H(aggnonce, agg_pk, msg)
	noncehash: [32]u8
	pts := aggnonce.pt
	compute_noncehash(&noncehash, &pts, &agg_pk32, msg32[:])
	scalar.scalar_set_b32(&session.noncecoef, &noncehash)

	// R = R_1 + b*R_2
	fin: group.Gej
	group.gej_set_infinity(&fin)
	if !group.ge_is_infinity(&pts[1]) {
		r2j: group.Gej
		group.gej_set_ge(&r2j, &pts[1])
		ecmult.ecmult(&fin, &r2j, &session.noncecoef, nil)
	}
	if !group.ge_is_infinity(&pts[0]) {
		group.gej_add_ge_var(&fin, &fin, &pts[0], nil)
	}

	fin_pt: group.Ge
	group.ge_set_gej_var(&fin_pt, &fin)
	if group.ge_is_infinity(&fin_pt) {
		// The specification substitutes the generator so the session is still well
		// defined; the resulting signature simply will not verify unless everyone agrees.
		fin_pt = group.GENERATOR
	}

	field.fe_normalize_var(&fin_pt.x)
	field.fe_get_b32(&session.fin_nonce, &fin_pt.x)
	field.fe_normalize_var(&fin_pt.y)
	session.fin_nonce_parity = field.fe_is_odd(&fin_pt.y)

	// e = H_BIP340(R, agg_pk, msg)
	challenge_bip340(&session.challenge, &session.fin_nonce, msg32[:], &agg_pk32)

	// Tweaks contribute e*t to s, independently of any signer.
	scalar.scalar_set_int(&session.s_part, 0)
	if !scalar.scalar_is_zero(&cache.tweak) {
		e_t: scalar.Scalar
		scalar.scalar_mul(&e_t, &session.challenge, &cache.tweak)
		// If the tweaked key has odd y, the tweak contribution is negated.
		pk := cache.pk
		field.fe_normalize_var(&pk.y)
		if field.fe_is_odd(&pk.y) {
			scalar.scalar_negate(&e_t, &e_t)
		}
		session.s_part = e_t
	}
	return true
}

/*
Computes the BIP340 challenge. Duplicated here rather than imported from `schnorr` to keep
`musig` from depending on the signing module for one hash.
*/
@(private)
challenge_bip340 :: proc "contextless" (
	e: ^scalar.Scalar,
	r32: ^[32]u8,
	msg: []u8,
	pubkey32: ^[32]u8,
) {
	sha: hash.Sha256
	hash.sha256_initialize(&sha)
	sha.s = {
		0x9cecba11,
		0x23925381,
		0x11679112,
		0xd1627e0f,
		0x97c87550,
		0x003cc765,
		0x90f61164,
		0x33e9b66a,
	}
	sha.bytes = 64

	hash.sha256_write(&sha, r32[:])
	hash.sha256_write(&sha, pubkey32[:])
	hash.sha256_write(&sha, msg)

	buf: [32]u8
	hash.sha256_finalize(&sha, &buf)
	scalar.scalar_set_b32(e, &buf)
	hash.sha256_clear(&sha)
}

/*
Produces this signer's partial signature, consuming the secret nonce.

**The nonce is zeroed before anything else happens**, including before validity checks, so
that no path through this procedure can leave a usable nonce behind. A second call with the
same `Secnonce` fails.

Returns false if the nonce has already been used, or if the keypair does not match the
public key the nonce was generated for.
*/
partial_sign :: proc "contextless" (
	partial_sig: ^Partial_Sig,
	secnonce: ^Secnonce,
	keypair: ^extrakeys.Keypair,
	cache: ^Keyagg_Cache,
	session: ^Session,
) -> bool {
	// Take a local copy and destroy the caller's immediately. Nonce reuse is
	// unrecoverable, so this happens before any check that could return early.
	local := secnonce^
	mem.zero_explicit(secnonce, size_of(Secnonce))

	if !local.valid {
		mem.zero_explicit(&local, size_of(Secnonce))
		return false
	}

	// Reject a zeroed nonce on its own merits, not only via the `valid` flag.
	//
	// The flag catches the ordinary reuse case, because `partial_sign` clears it above. This
	// catches a secnonce that arrived zeroed by some other route — a caller that
	// deserialized one, memset it, or copied a wiped struct. Signing with k = 0 makes s = e*d
	// and hands the secret key to anyone who sees the partial signature, so it must fail
	// even when the bookkeeping says the nonce is usable. BIP327 requires the rejection and
	// upstream enforces it in `musig_secnonce_load`.
	//
	// The predicate is computed first and then explicitly declassified, rather than branched
	// on directly. Both are needed and for different reasons: `|` instead of `||` so the
	// second limb is always examined — short-circuiting on the first is itself a branch on a
	// secret — and the declassify because the resulting bit *is* legitimately public, since
	// the caller learns it from the `false` returned below. Upstream declassifies the same
	// bit in `musig_secnonce_load` with the same justification. Branching on the limbs
	// without this is a genuine leak: valgrind reported exactly that here.
	nonce_is_zero := scalar.scalar_is_zero(&local.k[0]) | scalar.scalar_is_zero(&local.k[1])
	ct.declassify(&nonce_is_zero, size_of(nonce_is_zero))
	if nonce_is_zero {
		mem.zero_explicit(&local, size_of(Secnonce))
		return false
	}

	sk := keypair.seckey
	keypair_pk := keypair.pubkey

	// The nonce must belong to this signer.
	if !group.ge_eq_var(&local.pk, &keypair_pk) {
		scalar.scalar_clear(&sk)
		mem.zero_explicit(&local, size_of(Secnonce))
		return false
	}

	// d = g * gacc * d'. The two parity bits combine: the aggregate key's own parity and
	// the accumulated parity from tweaking.
	pk := cache.pk
	field.fe_normalize_var(&pk.y)
	if field.fe_is_odd(&pk.y) != cache.parity_acc {
		scalar.scalar_negate(&sk, &sk)
	}

	// Weight by this signer's aggregation coefficient.
	mu: scalar.Scalar
	keyaggcoef(&mu, cache, &local.pk)
	scalar.scalar_mul(&sk, &sk, &mu)

	// If the final nonce had odd y, both secret nonces are negated.
	k0 := local.k[0]
	k1 := local.k[1]
	if session.fin_nonce_parity {
		scalar.scalar_negate(&k0, &k0)
		scalar.scalar_negate(&k1, &k1)
	}

	// s = k_1 + b*k_2 + e*a*d
	s: scalar.Scalar
	scalar.scalar_mul(&s, &session.challenge, &sk)
	scalar.scalar_mul(&k1, &session.noncecoef, &k1)
	scalar.scalar_add(&k0, &k0, &k1)
	scalar.scalar_add(&s, &s, &k0)
	partial_sig.s = s

	scalar.scalar_clear(&sk)
	scalar.scalar_clear(&k0)
	scalar.scalar_clear(&k1)
	mem.zero_explicit(&local, size_of(Secnonce))
	return true
}

/*
Verifies one signer's partial signature.

Checking partial signatures before aggregating is what lets a coordinator identify *which*
participant misbehaved, instead of only learning that the combined signature is invalid.
*/
partial_sig_verify :: proc "contextless" (
	partial_sig: ^Partial_Sig,
	pubnonce: ^Pubnonce,
	pubkey: ^group.Ge,
	cache: ^Keyagg_Cache,
	session: ^Session,
) -> bool {
	// The signer's effective nonce point: R_i1 + b*R_i2, negated if the final nonce had
	// odd y.
	rj: group.Gej
	group.gej_set_infinity(&rj)
	if !group.ge_is_infinity(&pubnonce.pt[1]) {
		r2j: group.Gej
		group.gej_set_ge(&r2j, &pubnonce.pt[1])
		ecmult.ecmult(&rj, &r2j, &session.noncecoef, nil)
	}
	if !group.ge_is_infinity(&pubnonce.pt[0]) {
		group.gej_add_ge_var(&rj, &rj, &pubnonce.pt[0], nil)
	}

	rp: group.Ge
	group.ge_set_gej_var(&rp, &rj)
	if group.ge_is_infinity(&rp) {
		return false
	}
	if session.fin_nonce_parity {
		group.ge_neg(&rp, &rp)
	}

	// The signer's effective public key: a_i * P_i, negated to match the aggregate's
	// parity bookkeeping.
	pk := pubkey^
	mu: scalar.Scalar
	keyaggcoef(&mu, cache, &pk)

	agg := cache.pk
	field.fe_normalize_var(&agg.y)
	if field.fe_is_odd(&agg.y) != cache.parity_acc {
		scalar.scalar_negate(&mu, &mu)
	}

	// e*a
	ea: scalar.Scalar
	scalar.scalar_mul(&ea, &session.challenge, &mu)

	// The identity to check is s_i*G = R_i + e*a_i*P_i, rearranged as
	// s_i*G - e*a_i*P_i = R_i so that a single `ecmult` computes both terms.
	pj: group.Gej
	group.gej_set_ge(&pj, &pk)

	neg_ea: scalar.Scalar
	scalar.scalar_negate(&neg_ea, &ea)

	check: group.Gej
	ecmult.ecmult(&check, &pj, &neg_ea, &partial_sig.s)

	return group.gej_eq_ge_var(&check, &rp)
}

/*
Aggregates partial signatures into a 64-byte BIP340 signature.

The tweak contribution from the session is added in, so a signature over a tweaked
aggregate key verifies against that tweaked key directly.
*/
partial_sig_agg :: proc "contextless" (
	sig64: ^[64]u8,
	session: ^Session,
	partial_sigs: []Partial_Sig,
) -> bool {
	s := session.s_part
	for i in 0 ..< len(partial_sigs) {
		scalar.scalar_add(&s, &s, &partial_sigs[i].s)
	}

	copy(sig64[0:32], session.fin_nonce[:])
	s32 := (^[32]u8)(&sig64[32])
	scalar.scalar_get_b32(s32, &s)
	return true
}

/*
Serializes a public nonce as 66 bytes: two extended-form points.
*/
pubnonce_serialize :: proc "contextless" (out66: ^[66]u8, nonce: ^Pubnonce) {
	buf: [33]u8
	for i in 0 ..< 2 {
		p := nonce.pt[i]
		ge_serialize_ext(&buf, &p)
		copy(out66[i * 33:(i + 1) * 33], buf[:])
	}
}

/*
Parses a public nonce from its 66-byte form.
*/
pubnonce_parse :: proc "contextless" (nonce: ^Pubnonce, in66: ^[66]u8) -> bool {
	for i in 0 ..< 2 {
		buf: [33]u8
		copy(buf[:], in66[i * 33:(i + 1) * 33])
		if !ge_parse_ext(&nonce.pt[i], &buf) {
			return false
		}
	}
	return true
}

/*
Serializes an aggregate nonce as 66 bytes.
*/
aggnonce_serialize :: proc "contextless" (out66: ^[66]u8, nonce: ^Aggnonce) {
	buf: [33]u8
	for i in 0 ..< 2 {
		p := nonce.pt[i]
		ge_serialize_ext(&buf, &p)
		copy(out66[i * 33:(i + 1) * 33], buf[:])
	}
}

/*
Parses an aggregate nonce from its 66-byte form.
*/
aggnonce_parse :: proc "contextless" (nonce: ^Aggnonce, in66: ^[66]u8) -> bool {
	for i in 0 ..< 2 {
		buf: [33]u8
		copy(buf[:], in66[i * 33:(i + 1) * 33])
		if !ge_parse_ext(&nonce.pt[i], &buf) {
			return false
		}
	}
	return true
}

/*
Serializes a partial signature as 32 bytes.
*/
partial_sig_serialize :: proc "contextless" (out32: ^[32]u8, sig: ^Partial_Sig) {
	scalar.scalar_get_b32(out32, &sig.s)
}

/*
Parses a partial signature, rejecting values at or above n.
*/
partial_sig_parse :: proc "contextless" (sig: ^Partial_Sig, in32: ^[32]u8) -> bool {
	return !scalar.scalar_set_b32(&sig.s, in32)
}

/*
Zeroes a secret nonce without signing.

For a signer that abandons a session: the nonce must not survive, since reusing it in a
later session is exactly the fatal case.
*/
secnonce_clear :: proc "contextless" (secnonce: ^Secnonce) {
	mem.zero_explicit(secnonce, size_of(Secnonce))
}
