/*
 * secp256k1_odin.h — C interface to the pure-Odin secp256k1 implementation.
 *
 * NOT FOR REAL VALUE. This is an educational implementation held to production standards.
 * Unaudited hand-rolled cryptography must never guard real keys or real funds.
 *
 * Copyright (c) 2026 Galaxoid Labs. MIT licensed; see LICENSE.
 *
 * Hand-written to match the documented ABI of libsecp256k1; no upstream code is
 * incorporated. Opaque struct sizes are identical to upstream's, so existing consumer
 * definitions remain valid.
 *
 * Symbols are prefixed `secp256k1_odin_` so this can be linked alongside the real
 * libsecp256k1 — which is exactly what the differential tests do.
 *
 * Build:
 *     odin build capi/ -build-mode:shared -o:speed
 *     odin build capi/ -build-mode:static -o:speed
 *
 * Convention: every function returns 1 on success and 0 on failure. A null pointer is a
 * failure, never a crash.
 */

#ifndef SECP256K1_ODIN_H
#define SECP256K1_ODIN_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque context. Create with secp256k1_odin_context_create. */
typedef struct secp256k1_odin_context_struct secp256k1_odin_context;

/* Opaque public key. The layout is internal; use the serialize/parse functions. */
typedef struct {
    unsigned char data[64];
} secp256k1_odin_pubkey;

/* Opaque ECDSA signature. */
typedef struct {
    unsigned char data[64];
} secp256k1_odin_ecdsa_signature;

/* Opaque x-only public key (BIP340). */
typedef struct {
    unsigned char data[64];
} secp256k1_odin_xonly_pubkey;

/* Opaque keypair. Contains secret material; zero it when finished. */
typedef struct {
    unsigned char data[96];
} secp256k1_odin_keypair;

/* Flags accepted by context_create, for source compatibility with libsecp256k1. This
 * implementation has no separate sign and verify contexts, so the value is ignored. */
#define SECP256K1_ODIN_CONTEXT_NONE   1
#define SECP256K1_ODIN_CONTEXT_SIGN   (1 | (1 << 9))
#define SECP256K1_ODIN_CONTEXT_VERIFY (1 | (1 << 8))

/* Serialization flags. */
#define SECP256K1_ODIN_EC_COMPRESSED   ((1 << 1) | (1 << 8))
#define SECP256K1_ODIN_EC_UNCOMPRESSED (1 << 1)

/* Creates a context. Returns NULL on allocation failure. */
secp256k1_odin_context *secp256k1_odin_context_create(unsigned int flags);

/* Destroys a context, zeroing its secret state. */
void secp256k1_odin_context_destroy(secp256k1_odin_context *ctx);

/* Re-randomizes the context's blinding.
 *
 * Call this with good entropy before any secret-key operation, and periodically after.
 * A context that has never been randomized computes correct results but performs no
 * blinding. */
int secp256k1_odin_context_randomize(secp256k1_odin_context *ctx,
                                     const unsigned char *seed32);

/* Returns 1 if seckey is a valid secret key: in [1, n). */
int secp256k1_odin_ec_seckey_verify(const secp256k1_odin_context *ctx,
                                    const unsigned char *seckey);

/* Derives the public key for a secret key. */
int secp256k1_odin_ec_pubkey_create(const secp256k1_odin_context *ctx,
                                    secp256k1_odin_pubkey *pubkey,
                                    const unsigned char *seckey);

/* Parses a public key from a 33-byte compressed, 65-byte uncompressed, or hybrid
 * encoding. */
int secp256k1_odin_ec_pubkey_parse(const secp256k1_odin_context *ctx,
                                   secp256k1_odin_pubkey *pubkey,
                                   const unsigned char *input, size_t inputlen);

/* Serializes a public key. On input *outputlen is the buffer size; on output it is the
 * number of bytes written (33 compressed, 65 uncompressed). */
int secp256k1_odin_ec_pubkey_serialize(const secp256k1_odin_context *ctx,
                                       unsigned char *output, size_t *outputlen,
                                       const secp256k1_odin_pubkey *pubkey,
                                       unsigned int flags);

/* Signs a 32-byte message hash.
 *
 * The nonce is derived deterministically per RFC6979 and s is normalized low, so the
 * signature is reproducible and non-malleable. noncefp and ndata must be NULL; custom
 * nonce functions are not exposed through this ABI. */
int secp256k1_odin_ecdsa_sign(const secp256k1_odin_context *ctx,
                              secp256k1_odin_ecdsa_signature *sig,
                              const unsigned char *msghash32,
                              const unsigned char *seckey,
                              const void *noncefp, const void *ndata);

/* Verifies an ECDSA signature. High-S signatures are rejected. */
int secp256k1_odin_ecdsa_verify(const secp256k1_odin_context *ctx,
                                const secp256k1_odin_ecdsa_signature *sig,
                                const unsigned char *msghash32,
                                const secp256k1_odin_pubkey *pubkey);

int secp256k1_odin_ecdsa_signature_serialize_compact(
    const secp256k1_odin_context *ctx, unsigned char *output64,
    const secp256k1_odin_ecdsa_signature *sig);

int secp256k1_odin_ecdsa_signature_parse_compact(
    const secp256k1_odin_context *ctx, secp256k1_odin_ecdsa_signature *sig,
    const unsigned char *input64);

/* Serializes as DER. On input *outputlen is the buffer size (at least 72); on output it
 * is the length written. */
int secp256k1_odin_ecdsa_signature_serialize_der(
    const secp256k1_odin_context *ctx, unsigned char *output, size_t *outputlen,
    const secp256k1_odin_ecdsa_signature *sig);

/* Parses a strictly DER-encoded signature. Non-canonical encodings are rejected. */
int secp256k1_odin_ecdsa_signature_parse_der(
    const secp256k1_odin_context *ctx, secp256k1_odin_ecdsa_signature *sig,
    const unsigned char *input, size_t inputlen);

/* Creates a keypair for Schnorr signing. */
int secp256k1_odin_keypair_create(const secp256k1_odin_context *ctx,
                                  secp256k1_odin_keypair *keypair,
                                  const unsigned char *seckey32);

/* Extracts the x-only public key and the parity that was removed. pk_parity may be
 * NULL. */
int secp256k1_odin_keypair_xonly_pub(const secp256k1_odin_context *ctx,
                                     secp256k1_odin_xonly_pubkey *pubkey,
                                     int *pk_parity,
                                     const secp256k1_odin_keypair *keypair);

int secp256k1_odin_xonly_pubkey_serialize(const secp256k1_odin_context *ctx,
                                          unsigned char *output32,
                                          const secp256k1_odin_xonly_pubkey *pubkey);

int secp256k1_odin_xonly_pubkey_parse(const secp256k1_odin_context *ctx,
                                      secp256k1_odin_xonly_pubkey *pubkey,
                                      const unsigned char *input32);

/* Signs a 32-byte message with BIP340 Schnorr. aux_rand32 may be NULL, which makes
 * signing deterministic. */
int secp256k1_odin_schnorrsig_sign32(const secp256k1_odin_context *ctx,
                                     unsigned char *sig64,
                                     const unsigned char *msg32,
                                     const secp256k1_odin_keypair *keypair,
                                     const unsigned char *aux_rand32);

/* Verifies a BIP340 Schnorr signature over a message of any length. */
int secp256k1_odin_schnorrsig_verify(const secp256k1_odin_context *ctx,
                                     const unsigned char *sig64,
                                     const unsigned char *msg, size_t msglen,
                                     const secp256k1_odin_xonly_pubkey *pubkey);

/* Computes an ECDH shared secret: SHA256 over the compressed shared point.
 *
 * hashfp and data must be NULL; custom hash functions are not exposed through this ABI. */
int secp256k1_odin_ecdh(const secp256k1_odin_context *ctx, unsigned char *output32,
                        const secp256k1_odin_pubkey *pubkey,
                        const unsigned char *seckey32,
                        const void *hashfp, const void *data);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ODIN_H */
