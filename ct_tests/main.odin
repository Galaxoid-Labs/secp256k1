/*
Constant-time verification harness.

Every other test in this project checks *what* the code computes. This one checks *how
long it takes* — or rather, checks that the answer cannot depend on secret data. That is a
property no functional test can observe, as demonstrated concretely in `TESTING.md`:
swapping ECDH's constant-time multiply for the variable-time one passes the entire suite.

# How it works

Secret buffers are marked "undefined" through a memory checker. The checker then reports
any conditional branch or memory index whose outcome depends on undefined data — which is
precisely a secret-dependent branch or a secret-indexed load. Public outputs are explicitly
re-marked as defined, and each such declassification is a claim that the value is safe to
publish.

	./ct_tests/build.sh --valgrind
	valgrind --error-exitcode=1 ./ct_tests.bin

# Platform status

**This cannot run on macOS ARM64.** valgrind has no working port for that target, and
Odin's LLVM backend does not currently expose MemorySanitizer instrumentation for the
runtime, so neither backend is available on the development machine. The harness therefore
builds everywhere but only *verifies* under Linux or in CI.

That is a real gap, not a formality. It is why every symbol in `TRUST.md` is `unverified`
and none is `ct-verified`. Running this file is the gate that changes that, and the harness
refuses to report success when no checker is compiled in — a green run that verified
nothing would be worse than no run at all.
*/
package ct_tests

import "core:c"
import "core:fmt"
import "core:os"
import "../ct"
import "../ecdh"
import "../ecdsa"
import "../ecmult"
import "../ellswift"
import "../eckey"
import "../extrakeys"
import "../group"
import "../musig"
import "../scalar"
import "../recovery"
import "../schnorr"

foreign import checkmem "checkmem.o"

@(default_calling_convention = "c")
foreign checkmem {
	ct_checkmem_enabled :: proc() -> c.int ---
	ct_checkmem_undefine :: proc(p: rawptr, len: c.size_t) ---
	ct_checkmem_define :: proc(p: rawptr, len: c.size_t) ---
}

/*
Marks a value as secret.
*/
secret :: proc "contextless" (p: rawptr, len: int) {
	ct_checkmem_undefine(p, c.size_t(len))
}

/*
Marks a value as safe to publish.

Each call site must justify why: the harness would otherwise flag the ordinary act of
returning a signature, since a signature is derived from a secret key.
*/
declassify :: proc "contextless" (p: rawptr, len: int) {
	ct_checkmem_define(p, c.size_t(len))
}

failures := 0

check :: proc(name: string, ok: bool) {
	if ok {
		fmt.printfln("  ok   %s", name)
	} else {
		fmt.printfln("  FAIL %s", name)
		failures += 1
	}
}

/*
ECDSA signing: the secret key and the derived nonce must not influence control flow.
*/
test_ecdsa_sign :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	msg: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 1)
		msg[i] = u8(i * 3 + 7)
	}

	secret(&seckey, 32)

	sig: ecdsa.Signature
	ok := ecdsa.sign(gen, &sig, &msg, &seckey)

	// The signature is published, and so is the success flag: a caller must be able to
	// branch on whether signing worked.
	declassify(&sig, size_of(sig))
	declassify(&ok, size_of(ok))

	check("ecdsa.sign", ok)
}

/*
Public-key derivation from a secret key.
*/
test_pubkey_create :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 9)
	}
	secret(&seckey, 32)

	s: scalar.Scalar
	valid := scalar.scalar_set_b32_seckey(&s, &seckey)
	// Key validity is a public fact: the caller is told whether the key was accepted.
	declassify(&valid, size_of(valid))

	pk: group.Ge
	ok := eckey.pubkey_create(gen, &pk, &s)

	// A public key is public by definition.
	declassify(&pk, size_of(pk))
	declassify(&ok, size_of(ok))

	check("eckey.pubkey_create", ok && valid)
}

/*
Schnorr signing: two conditional negations on secret data, both of which must be
branch-free.
*/
test_schnorr_sign :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	msg: [32]u8
	aux: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 3)
		msg[i] = u8(i * 5 + 1)
		aux[i] = u8(i * 7 + 2)
	}

	kp: extrakeys.Keypair
	created := extrakeys.keypair_create(gen, &kp, &seckey)
	declassify(&created, size_of(created))
	// The keypair's public half is published; only its secret half stays secret.
	declassify(&kp.pubkey, size_of(kp.pubkey))

	secret(&kp.seckey, size_of(kp.seckey))
	secret(&aux, 32)

	sig: [64]u8
	ok := schnorr.sign(gen, &sig, msg[:], &kp, &aux)

	declassify(&sig, 64)
	declassify(&ok, size_of(ok))

	check("schnorr.sign", ok && created)
}

/*
ECDH: the whole point is that the scalar is secret.

This is the case where a functional test cannot help — `ecmult_const` and `ecmult` give the
same answer.
*/
test_ecdh :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	a: [32]u8
	b: [32]u8
	for i in 0 ..< 32 {
		a[i] = u8(i + 11)
		b[i] = u8(i + 23)
	}

	sb: scalar.Scalar
	scalar.scalar_set_b32_seckey(&sb, &b)
	pb: group.Ge
	eckey.pubkey_create(gen, &pb, &sb)

	// The peer's public key is public. It has to be declassified explicitly: it came out of
	// a blinded `ecmult_gen`, so it carries the taint of the blinding seed even though the
	// value itself is published. Upstream's ctime_tests declassifies pubkeys for the same
	// reason.
	declassify(&pb, size_of(pb))

	// Our scalar is not public.
	secret(&a, 32)

	out: [32]u8
	ok := ecdh.ecdh(out[:], &pb, &a)

	// The shared secret stays secret; only the success flag is published.
	declassify(&ok, size_of(ok))

	check("ecdh.ecdh", ok)
}

/*
Secret-key tweaking, as used by BIP32 derivation.
*/
test_seckey_tweak :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	tweak: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 5)
		tweak[i] = u8(i + 17)
	}

	secret(&seckey, 32)
	secret(&tweak, 32)

	s, tw: scalar.Scalar
	scalar.scalar_set_b32_seckey(&s, &seckey)
	scalar.scalar_set_b32(&tw, &tweak)

	ok := eckey.privkey_tweak_add(&s, &tw)
	// Whether the tweak produced a valid key is reported to the caller.
	declassify(&ok, size_of(ok))

	check("eckey.privkey_tweak_add", ok)
}

/*
MuSig2 nonce generation and partial signing.

`CLAUDE.md` calls this out explicitly: the secnonce paths are the highest-risk code in the
project, so they get their own case rather than riding along with Schnorr.
*/
test_musig_partial_sign :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	session_id: [32]u8
	msg: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 13)
		session_id[i] = u8(i + 29)
		msg[i] = u8(i + 41)
	}

	kp: extrakeys.Keypair
	created := extrakeys.keypair_create(gen, &kp, &seckey)
	declassify(&created, size_of(created))
	declassify(&kp.pubkey, size_of(kp.pubkey))

	pk: group.Ge
	extrakeys.keypair_pub(&pk, &kp)
	// Every signer's public key is broadcast to the other signers, and key aggregation is
	// deliberately variable-time in it.
	declassify(&pk, size_of(pk))

	agg_pk: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache
	keys := []group.Ge{pk}
	agged := musig.pubkey_agg(&agg_pk, &cache, keys)
	declassify(&agged, size_of(agged))
	// The aggregate key and the cache derived from it are published to all signers.
	declassify(&agg_pk, size_of(agg_pk))
	declassify(&cache, size_of(cache))

	agg_pk32: [32]u8
	extrakeys.xonly_pubkey_serialize(&agg_pk32, &agg_pk)

	// The session id and the secret key are both secret inputs to nonce derivation.
	secret(&session_id, 32)
	secret(&kp.seckey, size_of(kp.seckey))

	secnonce: musig.Secnonce
	pubnonce: musig.Pubnonce
	gen_ok := musig.nonce_gen(gen, &secnonce, &pubnonce, &session_id, &seckey, &pk, &msg, &agg_pk32)

	// The public nonce is published; the secret nonce is not.
	declassify(&pubnonce, size_of(pubnonce))
	declassify(&gen_ok, size_of(gen_ok))

	aggnonce: musig.Aggnonce
	musig.nonce_agg(&aggnonce, []musig.Pubnonce{pubnonce})

	session: musig.Session
	musig.nonce_process(&session, &aggnonce, &msg, &cache)

	partial: musig.Partial_Sig
	sign_ok := musig.partial_sign(&partial, &secnonce, &kp, &cache, &session)

	// A partial signature is published to the coordinator.
	declassify(&partial, size_of(partial))
	declassify(&sign_ok, size_of(sign_ok))

	check("musig.nonce_gen + partial_sign", gen_ok && sign_ok)
}

/*
Keypair creation and the x-only keypair tweak used by BIP341 key-path spending.

The tweak is the interesting one: it negates the secret key when the tweaked point has odd
y, and that negation is on secret data.
*/
test_keypair_tweak :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	tweak: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 19)
		tweak[i] = u8(i * 3 + 5)
	}
	// The key is secret; the tweak is not. Upstream's ctime_tests states this outright —
	// "The tweak is not treated as a secret in keypair_tweak_add" — and it is the right
	// model: a BIP341 tweak is derived from the script tree, which is published when the
	// output is spent. Marking it secret here would demand constant-time behaviour the API
	// never promised and that upstream does not provide either.
	secret(&seckey, 32)

	kp: extrakeys.Keypair
	created := extrakeys.keypair_create(gen, &kp, &seckey)
	declassify(&created, size_of(created))
	declassify(&kp.pubkey, size_of(kp.pubkey))

	ok := extrakeys.keypair_xonly_tweak_add(&kp, &tweak)
	// Whether the tweak produced a usable key is reported to the caller.
	declassify(&ok, size_of(ok))
	declassify(&kp.pubkey, size_of(kp.pubkey))

	check("extrakeys.keypair_xonly_tweak_add", ok && created)
}

/*
MuSig2 aggregate-key tweaking, both flavours.

Separate from the signing case because the tweak accumulator carries a parity flag that is
updated conditionally, and the aggregate key it operates on is public while the tweak may
not be.
*/
test_musig_tweak :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	tweak: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 23)
		tweak[i] = u8(i * 5 + 3)
	}

	kp: extrakeys.Keypair
	created := extrakeys.keypair_create(gen, &kp, &seckey)
	declassify(&created, size_of(created))
	declassify(&kp.pubkey, size_of(kp.pubkey))

	pk: group.Ge
	extrakeys.keypair_pub(&pk, &kp)
	declassify(&pk, size_of(pk))

	agg_pk: extrakeys.Xonly_Pubkey
	cache: musig.Keyagg_Cache
	agged := musig.pubkey_agg(&agg_pk, &cache, []group.Ge{pk})
	declassify(&agged, size_of(agged))
	declassify(&cache, size_of(cache))

	// The tweak is public, for the same reason as in the keypair case above.
	out: group.Ge
	ok1 := musig.pubkey_xonly_tweak_add(&out, &cache, &tweak)
	declassify(&ok1, size_of(ok1))
	declassify(&out, size_of(out))

	ok2 := musig.pubkey_ec_tweak_add(&out, &cache, &tweak)
	declassify(&ok2, size_of(ok2))
	declassify(&out, size_of(out))

	check("musig.pubkey_{xonly,ec}_tweak_add", ok1 && ok2)
}

/*
Recoverable ECDSA signing. Same secret material as ordinary signing, plus the recovery id,
which is derived from the nonce point's parity and is published with the signature.
*/
test_recovery_sign :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	seckey: [32]u8
	msg: [32]u8
	for i in 0 ..< 32 {
		seckey[i] = u8(i + 31)
		msg[i] = u8(i * 7 + 11)
	}
	secret(&seckey, 32)

	sig: recovery.Recoverable_Signature
	ok := recovery.sign_recoverable(gen, &sig, &msg, &seckey)

	// The signature and its recovery id are published together.
	declassify(&sig, size_of(sig))
	declassify(&ok, size_of(ok))

	check("recovery.sign_recoverable", ok)
}

/*
ellswift key encoding and the BIP324 x-only Diffie-Hellman.

`create` derives a public key from a secret and encodes it so the result is
indistinguishable from uniform bytes; `xdh` is the transport handshake's shared-secret step
and is squarely a secret-scalar operation.
*/
test_ellswift :: proc(gen: ^ecmult.Ecmult_Gen_Context) {
	sk_a: [32]u8
	sk_b: [32]u8
	aux: [32]u8
	for i in 0 ..< 32 {
		sk_a[i] = u8(i + 37)
		sk_b[i] = u8(i + 41)
		aux[i] = u8(i * 3 + 13)
	}

	// Build the peer's encoding with a key that is not marked secret, so only our own
	// scalar is under test.
	ell_b: [64]u8
	made_b := ellswift.create(gen, &ell_b, &sk_b, &aux)
	declassify(&made_b, size_of(made_b))
	declassify(&ell_b, 64)

	// The key is secret; the auxiliary randomness is not. Upstream's ctime_tests passes a
	// previous ellswift encoding as aux — public data — and the encoder absorbs aux *after*
	// the point at which the state stops being secret, so treating it as secret would demand
	// constant-time behaviour from the deliberately variable-time encoder.
	secret(&sk_a, 32)

	ell_a: [64]u8
	made_a := ellswift.create(gen, &ell_a, &sk_a, &aux)
	// The encoding is published on the wire; that is its entire purpose.
	declassify(&made_a, size_of(made_a))
	declassify(&ell_a, 64)

	shared: [32]u8
	ok := ellswift.xdh(shared[:], &ell_a, &ell_b, &sk_a, false)
	// The shared secret stays secret; only the success flag is published.
	declassify(&ok, size_of(ok))

	check("ellswift.create + xdh", made_a && made_b && ok)
}

main :: proc() {
	when DUDECT {
		run_dudect_suite()
		if failures > 0 {
			os.exit(1)
		}
		return
	}

	enabled := ct_checkmem_enabled() != 0

	fmt.println("secp256k1 constant-time harness")
	if !enabled {
		fmt.println()
		fmt.println("  NO MEMORY CHECKER COMPILED IN — this run verifies nothing.")
		fmt.println()
		fmt.println("  Build against a checker and run under it:")
		fmt.println("      ./ct_tests/build.sh --valgrind")
		fmt.println("      valgrind --error-exitcode=1 ./ct_tests.bin")
		fmt.println()
		fmt.println("  Needs the valgrind headers (Fedora: valgrind-devel).")
		fmt.println("  valgrind has no macOS ARM64 port; use Linux or CI.")
		fmt.println()
		fmt.println("  A statistical timing test runs anywhere:")
		fmt.println("      odin run ct_tests/ -o:speed -define:DUDECT=true")
		fmt.println()
		// Exit non-zero so this can never be mistaken for a passing gate.
		os.exit(2)
	}

	// Let the library declassify its own legitimate publication points. Without this the
	// checker reports every one of them — the validity of an RFC6979 nonce, Schnorr's R,
	// the success flag — and those reports bury real findings.
	ct.set_hook(declassify)

	gen: ecmult.Ecmult_Gen_Context
	ecmult.ecmult_gen_context_build(&gen)

	// Blind the context, as any real caller would; blinding is itself on the secret path.
	seed: [32]u8
	for i in 0 ..< 32 {
		seed[i] = u8(i * 11 + 3)
	}
	secret(&seed, 32)
	ecmult.ecmult_gen_blind(&gen, &seed)

	fmt.println()
	test_pubkey_create(&gen)
	test_ecdsa_sign(&gen)
	test_schnorr_sign(&gen)
	test_ecdh(&gen)
	test_seckey_tweak(&gen)
	test_musig_partial_sign(&gen)
	test_keypair_tweak(&gen)
	test_musig_tweak(&gen)
	test_recovery_sign(&gen)
	test_ellswift(&gen)
	fmt.println()

	if failures > 0 {
		fmt.printfln("%d operation(s) failed to complete", failures)
		os.exit(1)
	}

	fmt.println("all operations completed; any constant-time findings are reported by the checker itself")
}
