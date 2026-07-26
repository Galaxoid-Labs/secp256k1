/*
 * A drop-in C API for libsecp256k1, implemented in pure Odin.
 *
 * This declares the same API as upstream's secp256k1.h, with the same symbol names, struct
 * sizes and flag values, so an existing consumer compiles and links unchanged. It is
 * hand-written rather than copied from upstream: the declarations match because they must,
 * not because the text was duplicated.
 *
 * A consumer that already has upstream's headers should keep using them. These exist for
 * consumers that do not.
 *
 * !!! NOT FOR REAL VALUE !!!
 * This is an educational implementation held to production standards, not an audited one.
 * Being a drop-in replacement makes it easy to substitute for the real library; do not.
 * Unaudited hand-rolled cryptography must never guard real keys or real funds.
 *
 * For the full documentation of each function's contract, see upstream's headers at
 * https://github.com/bitcoin-core/secp256k1 — the semantics here are identical, and any
 * divergence is a bug in this implementation.
 */

#ifndef SECP256K1_H
#define SECP256K1_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* The version of this implementation. Note this is the Odin project's version, not the
 * upstream libsecp256k1 version whose API it mirrors. */
#define SECP256K1_VER_MAJOR 0
#define SECP256K1_VER_MINOR 1
#define SECP256K1_VER_PATCH 0
#define SECP256K1_VER_STRING "0.1.0"

/* Identifies this as the Odin implementation, for a consumer that wants to assert which
 * library it linked. Upstream does not define this. */
#define SECP256K1_ODIN 1

/* Upstream decorates its declarations with visibility, nonnull and warn_unused_result
 * attributes. They affect diagnostics, not the ABI, so they are omitted here; a consumer
 * that wants them should compile against upstream's headers, which this library links
 * against equally well. */
#if !defined(SECP256K1_API)
# if defined(_WIN32) && !defined(SECP256K1_STATIC)
#  define SECP256K1_API extern __declspec(dllimport)
# else
#  define SECP256K1_API extern
# endif
#endif

/* Opaque types. The sizes are the ABI contract: callers allocate these themselves. */

/** An opaque public key. 64 bytes; not a serialization — use the serialize functions. */
typedef struct secp256k1_pubkey {
    unsigned char data[64];
} secp256k1_pubkey;

/** An opaque ECDSA signature. 64 bytes; use the serialize functions for the wire form. */
typedef struct secp256k1_ecdsa_signature {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

/** An opaque library context. */
typedef struct secp256k1_context_struct secp256k1_context;

/** A scratch space. Declared for source compatibility; upstream deprecated the API that
 *  used it, and no function here takes one. */
typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

/* Flags. The bit values are upstream's and must not be changed. */
#define SECP256K1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256K1_FLAGS_TYPE_COMPRESSION (1 << 1)
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY (1 << 10)
#define SECP256K1_FLAGS_BIT_COMPRESSION (1 << 8)

#define SECP256K1_CONTEXT_NONE (SECP256K1_FLAGS_TYPE_CONTEXT)
#define SECP256K1_CONTEXT_VERIFY (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)
#define SECP256K1_CONTEXT_SIGN (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
#define SECP256K1_CONTEXT_DECLASSIFY (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY)

#define SECP256K1_EC_COMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION)

#define SECP256K1_TAG_PUBKEY_EVEN 0x02
#define SECP256K1_TAG_PUBKEY_ODD 0x03
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 0x06
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD 0x07

/** A shared context, usable for everything that does not require randomization. */
SECP256K1_API const secp256k1_context *const secp256k1_context_static;

/** The deprecated spelling of secp256k1_context_static. */
SECP256K1_API const secp256k1_context *const secp256k1_context_no_precomp;

/** Verifies that the library's precomputed tables are intact. */
SECP256K1_API void secp256k1_selftest(void);

/* Context lifecycle. */

SECP256K1_API secp256k1_context *secp256k1_context_create(unsigned int flags);
SECP256K1_API secp256k1_context *secp256k1_context_clone(const secp256k1_context *ctx);
SECP256K1_API void secp256k1_context_destroy(secp256k1_context *ctx);

/** Installs the callback for a violated documented precondition. The default aborts. */
SECP256K1_API void secp256k1_context_set_illegal_callback(
    secp256k1_context *ctx,
    void (*fun)(const char *message, void *data),
    const void *data
);

/** Installs the callback for an internal error, which should be unreachable. */
SECP256K1_API void secp256k1_context_set_error_callback(
    secp256k1_context *ctx,
    void (*fun)(const char *message, void *data),
    const void *data
);

/** Re-randomizes the context's blinding. Call before secret-key operations. */
SECP256K1_API int secp256k1_context_randomize(
    secp256k1_context *ctx,
    const unsigned char *seed32
);

/* Public keys. */

SECP256K1_API int secp256k1_ec_pubkey_parse(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *input,
    size_t inputlen
);

SECP256K1_API int secp256k1_ec_pubkey_serialize(
    const secp256k1_context *ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey *pubkey,
    unsigned int flags
);

SECP256K1_API int secp256k1_ec_pubkey_cmp(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *pubkey1,
    const secp256k1_pubkey *pubkey2
);

SECP256K1_API int secp256k1_ec_pubkey_sort(
    const secp256k1_context *ctx,
    const secp256k1_pubkey **pubkeys,
    size_t n_pubkeys
);

SECP256K1_API int secp256k1_ec_pubkey_create(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);

SECP256K1_API int secp256k1_ec_pubkey_negate(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey
);

SECP256K1_API int secp256k1_ec_pubkey_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak32
);

SECP256K1_API int secp256k1_ec_pubkey_tweak_mul(
    const secp256k1_context *ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak32
);

SECP256K1_API int secp256k1_ec_pubkey_combine(
    const secp256k1_context *ctx,
    secp256k1_pubkey *out,
    const secp256k1_pubkey *const *ins,
    size_t n
);

/* Secret keys. */

SECP256K1_API int secp256k1_ec_seckey_verify(
    const secp256k1_context *ctx,
    const unsigned char *seckey
);

SECP256K1_API int secp256k1_ec_seckey_negate(
    const secp256k1_context *ctx,
    unsigned char *seckey
);

SECP256K1_API int secp256k1_ec_seckey_tweak_add(
    const secp256k1_context *ctx,
    unsigned char *seckey,
    const unsigned char *tweak32
);

SECP256K1_API int secp256k1_ec_seckey_tweak_mul(
    const secp256k1_context *ctx,
    unsigned char *seckey,
    const unsigned char *tweak32
);

/* ECDSA signatures. */

SECP256K1_API int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *input64
);

SECP256K1_API int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *input,
    size_t inputlen
);

SECP256K1_API int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context *ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature *sig
);

SECP256K1_API int secp256k1_ecdsa_signature_serialize_compact(
    const secp256k1_context *ctx,
    unsigned char *output64,
    const secp256k1_ecdsa_signature *sig
);

/** Verifies a signature. High-S signatures are rejected; normalize first if needed. */
SECP256K1_API int secp256k1_ecdsa_verify(
    const secp256k1_context *ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msghash32,
    const secp256k1_pubkey *pubkey
);

SECP256K1_API int secp256k1_ecdsa_signature_normalize(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sigout,
    const secp256k1_ecdsa_signature *sigin
);

/** A nonce derivation function. Returns 1 on success, 0 to abort signing. */
typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

SECP256K1_API const secp256k1_nonce_function secp256k1_nonce_function_rfc6979;
SECP256K1_API const secp256k1_nonce_function secp256k1_nonce_function_default;

/** Signs a message hash. Pass NULL for noncefp to use RFC6979. */
SECP256K1_API int secp256k1_ecdsa_sign(
    const secp256k1_context *ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msghash32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

/** Computes SHA256(SHA256(tag) || SHA256(tag) || msg), the BIP340 tagged hash. */
SECP256K1_API int secp256k1_tagged_sha256(
    const secp256k1_context *ctx,
    unsigned char *hash32,
    const unsigned char *tag,
    size_t taglen,
    const unsigned char *msg,
    size_t msglen
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_H */
