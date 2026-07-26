/*
 * ElligatorSwift encoding, for the BIP324 v2 transport. Mirrors upstream's
 * secp256k1_ellswift.h.
 *
 * An ElligatorSwift encoding is 64 bytes that a passive observer cannot distinguish from
 * uniform randomness, which is what lets a handshake carry a public key with no
 * recognizable structure on the wire.
 */
#ifndef SECP256K1_ELLSWIFT_H
#define SECP256K1_ELLSWIFT_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Hashes an x-only DH result into the output secret. */
typedef int (*secp256k1_ellswift_xdh_hash_function)(
    unsigned char *output,
    const unsigned char *x32,
    const unsigned char *ell_a64,
    const unsigned char *ell_b64,
    void *data
);

/** SHA256 of a caller-supplied prefix, the two encodings and the shared x coordinate. */
SECP256K1_API const secp256k1_ellswift_xdh_hash_function secp256k1_ellswift_xdh_hash_function_prefix;

/** The BIP324 v2 transport key derivation. */
SECP256K1_API const secp256k1_ellswift_xdh_hash_function secp256k1_ellswift_xdh_hash_function_bip324;

/** Encodes a public key. rnd32 must be uniformly random and must not be reused. */
SECP256K1_API int secp256k1_ellswift_encode(
    const secp256k1_context *ctx,
    unsigned char *ell64,
    const secp256k1_pubkey *pubkey,
    const unsigned char *rnd32
);

/** Decodes an encoding to a public key. Every 64-byte string decodes to some point. */
SECP256K1_API int secp256k1_ellswift_decode(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *ell64
);

/** Derives a secret key's public key directly in encoded form. */
SECP256K1_API int secp256k1_ellswift_create(
    const secp256k1_context *ctx,
    unsigned char *ell64,
    const unsigned char *seckey32,
    const unsigned char *auxrnd32
);

/** x-only Diffie-Hellman over two encodings. `party` says which side the caller is. */
SECP256K1_API int secp256k1_ellswift_xdh(
    const secp256k1_context *ctx,
    unsigned char *output,
    const unsigned char *ell_a64,
    const unsigned char *ell_b64,
    const unsigned char *seckey32,
    int party,
    secp256k1_ellswift_xdh_hash_function hashfp,
    void *data
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ELLSWIFT_H */
