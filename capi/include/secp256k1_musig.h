/*
 * MuSig2 multi-signatures (BIP327). Mirrors upstream's secp256k1_musig.h.
 *
 * The protocol runs in three rounds: aggregate the public keys, exchange nonces, then
 * exchange partial signatures. The result is an ordinary BIP340 signature under the
 * aggregate key, indistinguishable from a single-signer one.
 *
 * !!! The secret nonce is the sharp edge. !!!
 * A secret nonce must be used for exactly one partial signature. Signing twice with the
 * same nonce reveals the secret key outright. secp256k1_musig_nonce_gen zeroes the caller's
 * session_secrand32 on success, and secp256k1_musig_partial_sign consumes the secnonce, to
 * make the mistake visible rather than silent.
 */
#ifndef SECP256K1_MUSIG_H
#define SECP256K1_MUSIG_H

#include <stdint.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque cache of the key aggregation state, including any applied tweaks. */
typedef struct secp256k1_musig_keyagg_cache {
    unsigned char data[197];
} secp256k1_musig_keyagg_cache;

/** Opaque secret nonce. Must never be copied, serialized, or used twice. */
typedef struct secp256k1_musig_secnonce {
    unsigned char data[132];
} secp256k1_musig_secnonce;

/** Opaque public nonce, shared with the other signers. */
typedef struct secp256k1_musig_pubnonce {
    unsigned char data[132];
} secp256k1_musig_pubnonce;

/** Opaque aggregate of every signer's public nonce. */
typedef struct secp256k1_musig_aggnonce {
    unsigned char data[132];
} secp256k1_musig_aggnonce;

/** Opaque signing session state. */
typedef struct secp256k1_musig_session {
    unsigned char data[133];
} secp256k1_musig_session;

/** Opaque partial signature. */
typedef struct secp256k1_musig_partial_sig {
    unsigned char data[36];
} secp256k1_musig_partial_sig;

SECP256K1_API int secp256k1_musig_pubnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_pubnonce *nonce,
    const unsigned char *in66
);

SECP256K1_API int secp256k1_musig_pubnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_musig_pubnonce *nonce
);

SECP256K1_API int secp256k1_musig_aggnonce_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_aggnonce *nonce,
    const unsigned char *in66
);

SECP256K1_API int secp256k1_musig_aggnonce_serialize(
    const secp256k1_context *ctx,
    unsigned char *out66,
    const secp256k1_musig_aggnonce *nonce
);

SECP256K1_API int secp256k1_musig_partial_sig_parse(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *sig,
    const unsigned char *in32
);

SECP256K1_API int secp256k1_musig_partial_sig_serialize(
    const secp256k1_context *ctx,
    unsigned char *out32,
    const secp256k1_musig_partial_sig *sig
);

SECP256K1_API int secp256k1_musig_pubkey_agg(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *agg_pk,
    secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_pubkey *const *pubkeys,
    size_t n_pubkeys
);

SECP256K1_API int secp256k1_musig_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *agg_pk,
    const secp256k1_musig_keyagg_cache *keyagg_cache
);

SECP256K1_API int secp256k1_musig_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *tweak32
);

SECP256K1_API int secp256k1_musig_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *tweak32
);

/** Generates a nonce pair. session_secrand32 must be uniformly random and is zeroed here. */
SECP256K1_API int secp256k1_musig_nonce_gen(
    const secp256k1_context *ctx,
    secp256k1_musig_secnonce *secnonce,
    secp256k1_musig_pubnonce *pubnonce,
    unsigned char *session_secrand32,
    const unsigned char *seckey,
    const secp256k1_pubkey *pubkey,
    const unsigned char *msg32,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *extra_input32
);

/** Generates a nonce pair from a counter. Safe only if the counter truly never repeats. */
SECP256K1_API int secp256k1_musig_nonce_gen_counter(
    const secp256k1_context *ctx,
    secp256k1_musig_secnonce *secnonce,
    secp256k1_musig_pubnonce *pubnonce,
    uint64_t nonrepeating_cnt,
    const secp256k1_keypair *keypair,
    const unsigned char *msg32,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const unsigned char *extra_input32
);

SECP256K1_API int secp256k1_musig_nonce_agg(
    const secp256k1_context *ctx,
    secp256k1_musig_aggnonce *aggnonce,
    const secp256k1_musig_pubnonce *const *pubnonces,
    size_t n_pubnonces
);

SECP256K1_API int secp256k1_musig_nonce_process(
    const secp256k1_context *ctx,
    secp256k1_musig_session *session,
    const secp256k1_musig_aggnonce *aggnonce,
    const unsigned char *msg32,
    const secp256k1_musig_keyagg_cache *keyagg_cache
);

/** Produces a partial signature. The secnonce is consumed and must not be reused. */
SECP256K1_API int secp256k1_musig_partial_sign(
    const secp256k1_context *ctx,
    secp256k1_musig_partial_sig *partial_sig,
    secp256k1_musig_secnonce *secnonce,
    const secp256k1_keypair *keypair,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_session *session
);

SECP256K1_API int secp256k1_musig_partial_sig_verify(
    const secp256k1_context *ctx,
    const secp256k1_musig_partial_sig *partial_sig,
    const secp256k1_musig_pubnonce *pubnonce,
    const secp256k1_pubkey *pubkey,
    const secp256k1_musig_keyagg_cache *keyagg_cache,
    const secp256k1_musig_session *session
);

SECP256K1_API int secp256k1_musig_partial_sig_agg(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const secp256k1_musig_session *session,
    const secp256k1_musig_partial_sig *const *partial_sigs,
    size_t n_sigs
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_MUSIG_H */
