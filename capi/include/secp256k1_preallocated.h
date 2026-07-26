/*
 * Context creation in caller-supplied memory. Mirrors upstream's secp256k1_preallocated.h.
 *
 * The buffer must be aligned for any type the library uses; a malloc'd buffer, or an array
 * of uint64_t, satisfies that. It must outlive the context and is not freed for you.
 */
#ifndef SECP256K1_PREALLOCATED_H
#define SECP256K1_PREALLOCATED_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

SECP256K1_API size_t secp256k1_context_preallocated_size(unsigned int flags);

SECP256K1_API secp256k1_context *secp256k1_context_preallocated_create(
    void *prealloc,
    unsigned int flags
);

SECP256K1_API size_t secp256k1_context_preallocated_clone_size(const secp256k1_context *ctx);

SECP256K1_API secp256k1_context *secp256k1_context_preallocated_clone(
    const secp256k1_context *ctx,
    void *prealloc
);

SECP256K1_API void secp256k1_context_preallocated_destroy(secp256k1_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_PREALLOCATED_H */
