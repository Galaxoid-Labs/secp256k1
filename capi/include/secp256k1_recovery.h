/*
 * Public key recovery from ECDSA signatures. Mirrors upstream's secp256k1_recovery.h.
 */
#ifndef SECP256K1_RECOVERY_H
#define SECP256K1_RECOVERY_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** An opaque recoverable signature: 64 bytes of signature plus the recovery id. */
typedef struct secp256k1_ecdsa_recoverable_signature {
    unsigned char data[65];
} secp256k1_ecdsa_recoverable_signature;

SECP256K1_API int secp256k1_ecdsa_recoverable_signature_parse_compact(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *input64,
    int recid
);

SECP256K1_API int secp256k1_ecdsa_recoverable_signature_convert(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const secp256k1_ecdsa_recoverable_signature *sigin
);

SECP256K1_API int secp256k1_ecdsa_recoverable_signature_serialize_compact(
    const secp256k1_context *ctx,
    unsigned char *output64,
    int *recid,
    const secp256k1_ecdsa_recoverable_signature *sig
);

SECP256K1_API int secp256k1_ecdsa_sign_recoverable(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msghash32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

SECP256K1_API int secp256k1_ecdsa_recover(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msghash32
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_RECOVERY_H */
