/*
 * The drop-in test.
 *
 * This file is an ordinary libsecp256k1 consumer. It includes upstream's own headers, calls
 * upstream's API, and knows nothing about Odin. `run.sh` compiles it twice — once linked
 * against the real libsecp256k1, once against ours — and diffs the two outputs.
 *
 * That is a stronger claim than the differential oracle makes. The oracle calls both
 * libraries from Odin through hand-written bindings, so it proves the *arithmetic* agrees.
 * This proves the *boundary* agrees: struct sizes, field offsets, flag values, callback
 * signatures, return conventions, and the initialization that has to happen before a C
 * caller's first call. Every one of those has been wrong here at least once.
 *
 * Everything is deterministic. There is no randomness anywhere, because the whole point is
 * that two runs produce identical bytes.
 */

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Any failure is fatal: a drop-in that returns 0 where the real library returns 1 is a
 * divergence, and continuing would just produce a confusing diff further down. */
static int failures = 0;

static void emit(const char *label, const unsigned char *data, size_t len) {
    size_t i;
    printf("%-40s ", label);
    for (i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static void emit_int(const char *label, long value) {
    printf("%-40s %ld\n", label, value);
}

static void check(const char *what, int cond) {
    if (!cond) {
        printf("FAIL %s\n", what);
        failures++;
    }
}

/* Fills a buffer deterministically, so both builds see identical inputs. */
static void fill(unsigned char *buf, size_t len, unsigned char seed) {
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (unsigned char)(seed + 7 * i + (i >> 3));
}

/* ------------------------------------------------------------------------------------- */

static void test_context_and_selftest(void) {
    unsigned char seed[32];
    secp256k1_context *ctx;
    size_t sz;
    void *buf;
    secp256k1_context *pre;

    secp256k1_selftest();
    printf("selftest                                 ok\n");

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    check("context_create", ctx != NULL);

    fill(seed, 32, 0x11);
    check("context_randomize", secp256k1_context_randomize(ctx, seed) == 1);

    /* The static context must be usable without any create call at all — that is the case
     * that catches initialization which only runs inside context_create. */
    check("context_static usable", secp256k1_ec_seckey_verify(secp256k1_context_static, seed) == 1);

    {
        secp256k1_context *clone = secp256k1_context_clone(ctx);
        check("context_clone", clone != NULL);
        secp256k1_context_destroy(clone);
    }

    sz = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE);
    check("preallocated_size nonzero", sz > 0);
    buf = malloc(sz);
    pre = secp256k1_context_preallocated_create(buf, SECP256K1_CONTEXT_NONE);
    check("preallocated_create", pre != NULL);
    check("preallocated context works",
          secp256k1_ec_seckey_verify(pre, seed) == 1);
    secp256k1_context_preallocated_destroy(pre);
    free(buf);

    secp256k1_context_destroy(ctx);
}

static void test_pubkeys(secp256k1_context *ctx) {
    unsigned char sk[32], out[65], tweak[32];
    secp256k1_pubkey pk, pk2, sum;
    const secp256k1_pubkey *ins[2];
    size_t len;

    fill(sk, 32, 0x01);
    check("pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);

    len = 33;
    check("serialize compressed",
          secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, SECP256K1_EC_COMPRESSED) == 1);
    emit("pubkey.compressed", out, len);

    len = 65;
    check("serialize uncompressed",
          secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, SECP256K1_EC_UNCOMPRESSED) == 1);
    emit("pubkey.uncompressed", out, len);

    /* Round-trip through the parser, then through serialization again: a packing bug that
     * is self-consistent survives a round trip but not a byte comparison with upstream. */
    check("pubkey_parse", secp256k1_ec_pubkey_parse(ctx, &pk2, out, len) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk2, SECP256K1_EC_COMPRESSED);
    emit("pubkey.reparsed", out, len);

    emit_int("pubkey_cmp(self)", secp256k1_ec_pubkey_cmp(ctx, &pk, &pk2));

    fill(sk, 32, 0x02);
    check("pubkey_create 2", secp256k1_ec_pubkey_create(ctx, &pk2, sk) == 1);
    emit_int("pubkey_cmp(sign)", secp256k1_ec_pubkey_cmp(ctx, &pk, &pk2) < 0 ? -1 : 1);

    ins[0] = &pk;
    ins[1] = &pk2;
    check("pubkey_combine", secp256k1_ec_pubkey_combine(ctx, &sum, ins, 2) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &sum, SECP256K1_EC_COMPRESSED);
    emit("pubkey.combined", out, len);

    {
        const secp256k1_pubkey *arr[3];
        secp256k1_pubkey p3;
        unsigned char sk3[32];
        int i;
        fill(sk3, 32, 0x03);
        check("pubkey_create 3", secp256k1_ec_pubkey_create(ctx, &p3, sk3) == 1);
        arr[0] = &p3; arr[1] = &pk; arr[2] = &pk2;
        check("pubkey_sort", secp256k1_ec_pubkey_sort(ctx, arr, 3) == 1);
        for (i = 0; i < 3; i++) {
            len = 33;
            secp256k1_ec_pubkey_serialize(ctx, out, &len, arr[i], SECP256K1_EC_COMPRESSED);
            emit("pubkey.sorted", out, len);
        }
    }

    check("pubkey_negate", secp256k1_ec_pubkey_negate(ctx, &pk2) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk2, SECP256K1_EC_COMPRESSED);
    emit("pubkey.negated", out, len);

    fill(tweak, 32, 0x40);
    check("pubkey_tweak_add", secp256k1_ec_pubkey_tweak_add(ctx, &pk, tweak) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, SECP256K1_EC_COMPRESSED);
    emit("pubkey.tweak_add", out, len);

    check("pubkey_tweak_mul", secp256k1_ec_pubkey_tweak_mul(ctx, &pk, tweak) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out, &len, &pk, SECP256K1_EC_COMPRESSED);
    emit("pubkey.tweak_mul", out, len);
}

static void test_seckeys(secp256k1_context *ctx) {
    unsigned char sk[32], tweak[32];

    fill(sk, 32, 0x05);
    check("seckey_verify", secp256k1_ec_seckey_verify(ctx, sk) == 1);

    check("seckey_negate", secp256k1_ec_seckey_negate(ctx, sk) == 1);
    emit("seckey.negated", sk, 32);

    fill(tweak, 32, 0x41);
    check("seckey_tweak_add", secp256k1_ec_seckey_tweak_add(ctx, sk, tweak) == 1);
    emit("seckey.tweak_add", sk, 32);

    check("seckey_tweak_mul", secp256k1_ec_seckey_tweak_mul(ctx, sk, tweak) == 1);
    emit("seckey.tweak_mul", sk, 32);

    /* An out-of-range tweak must fail and zero the key, not silently reduce. */
    memset(tweak, 0xff, 32);
    emit_int("seckey_tweak_add(overflow)", secp256k1_ec_seckey_tweak_add(ctx, sk, tweak));
}

static void test_ecdsa(secp256k1_context *ctx) {
    unsigned char sk[32], msg[32], out[72], extra[32];
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig, sig2, norm;
    size_t len;

    fill(sk, 32, 0x21);
    fill(msg, 32, 0x22);
    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);

    check("ecdsa_sign", secp256k1_ecdsa_sign(ctx, &sig, msg, sk, NULL, NULL) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig);
    emit("ecdsa.sig.compact", out, 64);

    check("ecdsa_verify", secp256k1_ecdsa_verify(ctx, &sig, msg, &pk) == 1);

    len = sizeof(out);
    check("ecdsa der", secp256k1_ecdsa_signature_serialize_der(ctx, out, &len, &sig) == 1);
    emit("ecdsa.sig.der", out, len);

    check("ecdsa der parse", secp256k1_ecdsa_signature_parse_der(ctx, &sig2, out, len) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig2);
    emit("ecdsa.sig.der.roundtrip", out, 64);

    emit_int("ecdsa_normalize(low-s)", secp256k1_ecdsa_signature_normalize(ctx, &norm, &sig));

    /* Explicitly naming the default nonce function must take the same path as NULL. */
    check("ecdsa_sign(explicit default)",
          secp256k1_ecdsa_sign(ctx, &sig2, msg, sk, secp256k1_nonce_function_default, NULL) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig2);
    emit("ecdsa.sig.explicit_default", out, 64);

    /* Extra entropy changes the nonce and therefore the signature, deterministically. */
    fill(extra, 32, 0x77);
    check("ecdsa_sign(extra entropy)",
          secp256k1_ecdsa_sign(ctx, &sig2, msg, sk, NULL, extra) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig2);
    emit("ecdsa.sig.extra_entropy", out, 64);
}

/* A caller-supplied nonce function, to exercise the path that is not the built-in one. */
static int fixed_nonce(unsigned char *nonce32, const unsigned char *msg32,
                       const unsigned char *key32, const unsigned char *algo16,
                       void *data, unsigned int attempt) {
    (void)msg32; (void)key32; (void)algo16; (void)data;
    if (attempt > 4) return 0;
    fill(nonce32, 32, (unsigned char)(0x90 + attempt));
    return 1;
}

static void test_ecdsa_custom_nonce(secp256k1_context *ctx) {
    unsigned char sk[32], msg[32], out[64];
    secp256k1_pubkey pk;
    secp256k1_ecdsa_signature sig;

    fill(sk, 32, 0x23);
    fill(msg, 32, 0x24);
    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);

    check("ecdsa_sign(custom nonce)",
          secp256k1_ecdsa_sign(ctx, &sig, msg, sk, fixed_nonce, NULL) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &sig);
    emit("ecdsa.sig.custom_nonce", out, 64);
    check("ecdsa_verify(custom nonce)", secp256k1_ecdsa_verify(ctx, &sig, msg, &pk) == 1);
}

static void test_recovery(secp256k1_context *ctx) {
    unsigned char sk[32], msg[32], out[64], ser[33];
    secp256k1_pubkey pk, rec;
    secp256k1_ecdsa_recoverable_signature rsig;
    secp256k1_ecdsa_signature plain;
    size_t len;
    int recid;

    fill(sk, 32, 0x31);
    fill(msg, 32, 0x32);
    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);

    check("sign_recoverable",
          secp256k1_ecdsa_sign_recoverable(ctx, &rsig, msg, sk, NULL, NULL) == 1);
    check("recsig serialize",
          secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, out, &recid, &rsig) == 1);
    emit("recovery.sig", out, 64);
    emit_int("recovery.recid", recid);

    check("recover", secp256k1_ecdsa_recover(ctx, &rec, &rsig, msg) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &rec, SECP256K1_EC_COMPRESSED);
    emit("recovery.pubkey", ser, len);
    check("recovered key matches", secp256k1_ec_pubkey_cmp(ctx, &pk, &rec) == 0);

    check("recsig parse",
          secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rsig, out, recid) == 1);
    check("recsig convert",
          secp256k1_ecdsa_recoverable_signature_convert(ctx, &plain, &rsig) == 1);
    secp256k1_ecdsa_signature_serialize_compact(ctx, out, &plain);
    emit("recovery.converted", out, 64);
}

static void test_ecdh(secp256k1_context *ctx) {
    unsigned char sk_a[32], sk_b[32], out_a[32], out_b[32];
    secp256k1_pubkey pk_a, pk_b;

    fill(sk_a, 32, 0x41);
    fill(sk_b, 32, 0x42);
    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk_a, sk_a) == 1);
    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk_b, sk_b) == 1);

    check("ecdh a", secp256k1_ecdh(ctx, out_a, &pk_b, sk_a, NULL, NULL) == 1);
    check("ecdh b", secp256k1_ecdh(ctx, out_b, &pk_a, sk_b, NULL, NULL) == 1);
    emit("ecdh.shared", out_a, 32);
    check("ecdh agrees", memcmp(out_a, out_b, 32) == 0);

    check("ecdh explicit hashfp",
          secp256k1_ecdh(ctx, out_a, &pk_b, sk_a, secp256k1_ecdh_hash_function_sha256, NULL) == 1);
    emit("ecdh.explicit_hashfp", out_a, 32);
}

static void test_extrakeys(secp256k1_context *ctx) {
    unsigned char sk[32], out[32], tweak[32];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk, xpk2;
    secp256k1_pubkey pk, tweaked;
    int parity;

    fill(sk, 32, 0x51);
    check("keypair_create", secp256k1_keypair_create(ctx, &kp, sk) == 1);

    check("keypair_sec", secp256k1_keypair_sec(ctx, out, &kp) == 1);
    emit("keypair.sec", out, 32);
    check("keypair_sec round trip", memcmp(out, sk, 32) == 0);

    check("keypair_pub", secp256k1_keypair_pub(ctx, &pk, &kp) == 1);
    check("keypair_xonly_pub", secp256k1_keypair_xonly_pub(ctx, &xpk, &parity, &kp) == 1);
    emit_int("keypair.xonly.parity", parity);

    check("xonly_serialize", secp256k1_xonly_pubkey_serialize(ctx, out, &xpk) == 1);
    emit("xonly.serialized", out, 32);

    check("xonly_parse", secp256k1_xonly_pubkey_parse(ctx, &xpk2, out) == 1);
    emit_int("xonly_cmp", secp256k1_xonly_pubkey_cmp(ctx, &xpk, &xpk2));

    check("xonly_from_pubkey",
          secp256k1_xonly_pubkey_from_pubkey(ctx, &xpk2, &parity, &pk) == 1);
    emit_int("xonly_from_pubkey.parity", parity);

    fill(tweak, 32, 0x52);
    check("xonly_tweak_add",
          secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked, &xpk, tweak) == 1);
    check("xonly_from_tweaked",
          secp256k1_xonly_pubkey_from_pubkey(ctx, &xpk2, &parity, &tweaked) == 1);
    secp256k1_xonly_pubkey_serialize(ctx, out, &xpk2);
    emit("xonly.tweaked", out, 32);

    check("xonly_tweak_add_check",
          secp256k1_xonly_pubkey_tweak_add_check(ctx, out, parity, &xpk, tweak) == 1);

    check("keypair_xonly_tweak_add",
          secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak) == 1);
    secp256k1_keypair_xonly_pub(ctx, &xpk2, &parity, &kp);
    secp256k1_xonly_pubkey_serialize(ctx, out, &xpk2);
    emit("keypair.tweaked.xonly", out, 32);
}

static void test_schnorr(secp256k1_context *ctx) {
    unsigned char sk[32], msg[32], aux[32], sig[64], long_msg[100];
    secp256k1_keypair kp;
    secp256k1_xonly_pubkey xpk;
    secp256k1_schnorrsig_extraparams extra = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;

    fill(sk, 32, 0x61);
    fill(msg, 32, 0x62);
    fill(aux, 32, 0x63);
    check("secp256k1_keypair_create", secp256k1_keypair_create(ctx, &kp, sk) == 1);
    secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp);

    check("schnorrsig_sign32(no aux)",
          secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, NULL) == 1);
    emit("schnorr.sig.no_aux", sig, 64);
    check("schnorrsig_verify", secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &xpk) == 1);

    check("schnorrsig_sign32(aux)",
          secp256k1_schnorrsig_sign32(ctx, sig, msg, &kp, aux) == 1);
    emit("schnorr.sig.aux", sig, 64);
    check("schnorrsig_verify(aux)", secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &xpk) == 1);

    fill(long_msg, sizeof(long_msg), 0x64);
    check("schnorrsig_sign_custom",
          secp256k1_schnorrsig_sign_custom(ctx, sig, long_msg, sizeof(long_msg), &kp, &extra) == 1);
    emit("schnorr.sig.custom", sig, 64);
    check("schnorrsig_verify(long)",
          secp256k1_schnorrsig_verify(ctx, sig, long_msg, sizeof(long_msg), &xpk) == 1);

    /* An empty message is legal under the generalised BIP340 and is an easy off-by-one. */
    check("schnorrsig_sign_custom(empty)",
          secp256k1_schnorrsig_sign_custom(ctx, sig, NULL, 0, &kp, &extra) == 1);
    emit("schnorr.sig.empty_msg", sig, 64);
    check("schnorrsig_verify(empty)",
          secp256k1_schnorrsig_verify(ctx, sig, NULL, 0, &xpk) == 1);
}

static void test_ellswift(secp256k1_context *ctx) {
    unsigned char sk_a[32], sk_b[32], rnd[32], ell_a[64], ell_b[64];
    unsigned char shared_a[32], shared_b[32];
    secp256k1_pubkey pk, decoded;
    size_t len;
    unsigned char ser[33];

    fill(sk_a, 32, 0x71);
    fill(sk_b, 32, 0x72);
    fill(rnd, 32, 0x73);

    check("secp256k1_ec_pubkey_create", secp256k1_ec_pubkey_create(ctx, &pk, sk_a) == 1);
    check("ellswift_encode", secp256k1_ellswift_encode(ctx, ell_a, &pk, rnd) == 1);
    emit("ellswift.encoded", ell_a, 64);

    check("ellswift_decode", secp256k1_ellswift_decode(ctx, &decoded, ell_a) == 1);
    len = 33;
    secp256k1_ec_pubkey_serialize(ctx, ser, &len, &decoded, SECP256K1_EC_COMPRESSED);
    emit("ellswift.decoded", ser, len);
    check("ellswift round trip", secp256k1_ec_pubkey_cmp(ctx, &pk, &decoded) == 0);

    check("ellswift_create a", secp256k1_ellswift_create(ctx, ell_a, sk_a, rnd) == 1);
    emit("ellswift.created.a", ell_a, 64);
    check("ellswift_create b", secp256k1_ellswift_create(ctx, ell_b, sk_b, rnd) == 1);

    check("ellswift_xdh a",
          secp256k1_ellswift_xdh(ctx, shared_a, ell_a, ell_b, sk_a, 0,
                                 secp256k1_ellswift_xdh_hash_function_bip324, NULL) == 1);
    check("ellswift_xdh b",
          secp256k1_ellswift_xdh(ctx, shared_b, ell_a, ell_b, sk_b, 1,
                                 secp256k1_ellswift_xdh_hash_function_bip324, NULL) == 1);
    emit("ellswift.xdh", shared_a, 32);
    check("ellswift_xdh agrees", memcmp(shared_a, shared_b, 32) == 0);
}

static void test_musig(secp256k1_context *ctx) {
    enum { N = 3 };
    unsigned char sk[N][32], secrand[N][32], msg[32], tweak[32];
    secp256k1_keypair kp[N];
    secp256k1_pubkey pk[N];
    const secp256k1_pubkey *pk_ptr[N];
    secp256k1_musig_secnonce secnonce[N];
    secp256k1_musig_pubnonce pubnonce[N];
    const secp256k1_musig_pubnonce *pubnonce_ptr[N];
    secp256k1_musig_partial_sig psig[N];
    const secp256k1_musig_partial_sig *psig_ptr[N];
    secp256k1_musig_keyagg_cache cache;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_xonly_pubkey agg_xonly;
    secp256k1_pubkey agg_pk, tweaked;
    unsigned char sig[64], buf[66];
    int i;

    fill(msg, 32, 0x81);
    for (i = 0; i < N; i++) {
        fill(sk[i], 32, (unsigned char)(0x82 + i));
        fill(secrand[i], 32, (unsigned char)(0x92 + i));
        check("musig keypair", secp256k1_keypair_create(ctx, &kp[i], sk[i]) == 1);
        check("musig pubkey", secp256k1_keypair_pub(ctx, &pk[i], &kp[i]) == 1);
        pk_ptr[i] = &pk[i];
    }

    check("musig_pubkey_agg",
          secp256k1_musig_pubkey_agg(ctx, &agg_xonly, &cache, pk_ptr, N) == 1);
    secp256k1_xonly_pubkey_serialize(ctx, buf, &agg_xonly);
    emit("musig.agg_pk", buf, 32);

    check("musig_pubkey_get", secp256k1_musig_pubkey_get(ctx, &agg_pk, &cache) == 1);
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &agg_pk, SECP256K1_EC_COMPRESSED);
        emit("musig.agg_pk.full", buf, len);
    }

    fill(tweak, 32, 0x88);
    check("musig_pubkey_xonly_tweak_add",
          secp256k1_musig_pubkey_xonly_tweak_add(ctx, &tweaked, &cache, tweak) == 1);
    {
        size_t len = 33;
        secp256k1_ec_pubkey_serialize(ctx, buf, &len, &tweaked, SECP256K1_EC_COMPRESSED);
        emit("musig.tweaked", buf, len);
    }

    for (i = 0; i < N; i++) {
        check("musig_nonce_gen",
              secp256k1_musig_nonce_gen(ctx, &secnonce[i], &pubnonce[i], secrand[i],
                                        sk[i], &pk[i], msg, &cache, NULL) == 1);
        /* Upstream zeroes the caller's randomness on success, so that reuse is visibly
         * wrong rather than silently catastrophic. */
        {
            int all_zero = 1, j;
            for (j = 0; j < 32; j++) if (secrand[i][j] != 0) all_zero = 0;
            check("session_secrand zeroed", all_zero);
        }
        check("pubnonce_serialize",
              secp256k1_musig_pubnonce_serialize(ctx, buf, &pubnonce[i]) == 1);
        emit("musig.pubnonce", buf, 66);
        pubnonce_ptr[i] = &pubnonce[i];
    }

    check("musig_nonce_agg",
          secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, N) == 1);
    check("aggnonce_serialize",
          secp256k1_musig_aggnonce_serialize(ctx, buf, &aggnonce) == 1);
    emit("musig.aggnonce", buf, 66);

    check("musig_nonce_process",
          secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, &cache) == 1);

    for (i = 0; i < N; i++) {
        check("musig_partial_sign",
              secp256k1_musig_partial_sign(ctx, &psig[i], &secnonce[i], &kp[i],
                                           &cache, &session) == 1);
        check("musig_partial_sig_serialize",
              secp256k1_musig_partial_sig_serialize(ctx, buf, &psig[i]) == 1);
        emit("musig.partial_sig", buf, 32);
        check("musig_partial_sig_verify",
              secp256k1_musig_partial_sig_verify(ctx, &psig[i], &pubnonce[i], &pk[i],
                                                 &cache, &session) == 1);
        psig_ptr[i] = &psig[i];
    }

    check("musig_partial_sig_agg",
          secp256k1_musig_partial_sig_agg(ctx, sig, &session, psig_ptr, N) == 1);
    emit("musig.sig", sig, 64);

    /* The whole point of MuSig2: the result is an ordinary BIP340 signature under the
     * tweaked aggregate key. */
    {
        secp256k1_xonly_pubkey out_xonly;
        int parity;
        check("musig xonly from tweaked",
              secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xonly, &parity, &tweaked) == 1);
        check("musig sig verifies as schnorr",
              secp256k1_schnorrsig_verify(ctx, sig, msg, 32, &out_xonly) == 1);
    }

    /* Counter-based nonces, which derive from a counter rather than randomness. */
    {
        secp256k1_musig_secnonce sn;
        secp256k1_musig_pubnonce pn;
        check("musig_nonce_gen_counter",
              secp256k1_musig_nonce_gen_counter(ctx, &sn, &pn, 42, &kp[0], msg,
                                                &cache, NULL) == 1);
        check("counter pubnonce serialize",
              secp256k1_musig_pubnonce_serialize(ctx, buf, &pn) == 1);
        emit("musig.pubnonce.counter", buf, 66);
    }
}

static void test_tagged_hash(secp256k1_context *ctx) {
    unsigned char out[32];
    const char *tag = "drop-in/test";
    const char *msg = "the quick brown fox";
    check("tagged_sha256",
          secp256k1_tagged_sha256(ctx, out, (const unsigned char *)tag, strlen(tag),
                                  (const unsigned char *)msg, strlen(msg)) == 1);
    emit("tagged_sha256", out, 32);
}

/* The illegal-argument callback must fire, and must receive the data pointer it was given.
 * This is the one place the C function-pointer bridge is observable from outside. */
static int callback_hits = 0;
static void *callback_data_seen = NULL;

static void on_illegal(const char *message, void *data) {
    (void)message;
    callback_hits++;
    callback_data_seen = data;
}

static void test_callbacks(void) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    int marker = 0;

    secp256k1_context_set_illegal_callback(ctx, on_illegal, &marker);
    /* A null pubkey out-pointer is a documented precondition violation. */
    /* Deliberately illegal: a null out-pointer, to make the callback fire.
     *
     * Two compiler defences have to be got past, and neither is optional. The nulls travel
     * through volatile pointers because upstream's headers mark these arguments nonnull, so
     * a literal NULL is diagnosed at the call this test exists to make. And the result is
     * stored rather than cast to void, because the function is warn_unused_result and GCC —
     * unlike clang — does not accept a (void) cast as acknowledgement. The stored value is
     * then checked: an illegal argument must return 0. */
    {
        secp256k1_pubkey *volatile null_pk = NULL;
        const unsigned char *volatile null_sk = NULL;
        int ret = secp256k1_ec_pubkey_create(ctx, null_pk, null_sk);
        check("illegal argument returns 0", ret == 0);
    }
    check("illegal callback fired", callback_hits > 0);
    check("illegal callback data", callback_data_seen == &marker);
    emit_int("callback.hits", callback_hits > 0 ? 1 : 0);

    secp256k1_context_destroy(ctx);
}

int main(void) {
    secp256k1_context *ctx;

    test_context_and_selftest();

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    test_pubkeys(ctx);
    test_seckeys(ctx);
    test_ecdsa(ctx);
    test_ecdsa_custom_nonce(ctx);
    test_recovery(ctx);
    test_ecdh(ctx);
    test_extrakeys(ctx);
    test_schnorr(ctx);
    test_ellswift(ctx);
    test_musig(ctx);
    test_tagged_hash(ctx);

    secp256k1_context_destroy(ctx);

    test_callbacks();

    if (failures != 0) {
        printf("\n%d checks failed\n", failures);
        return 1;
    }
    printf("\nall checks passed\n");
    return 0;
}
