/*
 * Elliptic curve Diffie-Hellman. Mirrors upstream's secp256k1_ecdh.h.
 */
#ifndef SECP256K1_ECDH_H
#define SECP256K1_ECDH_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Hashes the shared point into the output secret. Returns 1 on success. */
typedef int (*secp256k1_ecdh_hash_function)(
    unsigned char *output,
    const unsigned char *x32,
    const unsigned char *y32,
    void *data
);

/** SHA256 of the compressed shared point. */
SECP256K1_API const secp256k1_ecdh_hash_function secp256k1_ecdh_hash_function_sha256;
SECP256K1_API const secp256k1_ecdh_hash_function secp256k1_ecdh_hash_function_default;

/** Computes a shared secret. Pass NULL for hashfp to use the default. */
SECP256K1_API int secp256k1_ecdh(
    const secp256k1_context *ctx,
    unsigned char *output,
    const secp256k1_pubkey *pubkey,
    const unsigned char *seckey,
    secp256k1_ecdh_hash_function hashfp,
    void *data
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDH_H */
