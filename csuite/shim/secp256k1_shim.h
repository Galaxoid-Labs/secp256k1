/*
 * Header shim: upstream's internal API, backed by this implementation via `csuite`.
 *
 * # Why this exists
 *
 * Upstream's `tests.c` cannot be linked against a foreign implementation. Its line 20 is
 * `#include "secp256k1.c"` — it compiles the entire C library into its own translation unit
 * rather than linking one, so there is no point at which another implementation's symbols
 * could be substituted. Upstream's definitions would collide with ours, not be replaced.
 *
 * This header is the alternative described as option B in `TODO.md` item 5: keep upstream's
 * test *bodies* byte-for-byte, and replace only what they include. Everything below either
 * declares a `csuite` export or reproduces a macro from upstream's headers, because macros
 * are not symbols and cannot be exported.
 *
 * # What this licenses, precisely
 *
 * "Runs upstream's test bodies against this implementation." **Not** "passes libsecp256k1's
 * tests" — that phrase is reserved for linking the unmodified file, which is not achievable
 * without an upstream change. The assertions are upstream's and unmodified; the include
 * block is not.
 *
 * # Layout
 *
 * The struct definitions here must match both upstream's headers and this implementation's
 * Odin types. `csuite` asserts the Odin side at compile time and `secp256k1_csuite_layout`
 * reports it at runtime so the C side can check rather than assume — see `test_csuite.c`.
 * `secp256k1_fe` is declared *without* upstream's VERIFY fields, which means the shim must
 * be paired with a `csuite` built using `-define:SECP256K1_VERIFY=false`.
 */

#ifndef SECP256K1_SHIM_H
#define SECP256K1_SHIM_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* ---------------------------------------------------------------------------------------
 * Types, matching upstream's 5x52 / 4x64 backends.
 * ------------------------------------------------------------------------------------ */

typedef struct { uint64_t n[5]; } secp256k1_fe;
typedef struct { uint64_t n[4]; } secp256k1_fe_storage;
typedef struct { uint64_t d[4]; } secp256k1_scalar;
typedef struct { secp256k1_fe x; secp256k1_fe y; int infinity; } secp256k1_ge;
typedef struct { secp256k1_fe x; secp256k1_fe y; secp256k1_fe z; int infinity; } secp256k1_gej;
typedef struct { secp256k1_fe_storage x; secp256k1_fe_storage y; } secp256k1_ge_storage;

/* ---------------------------------------------------------------------------------------
 * Macros, reproduced from upstream's headers verbatim. These are not symbols and so cannot
 * come from the library; they are copied rather than reimplemented so that a constant
 * written in a test body expands to exactly the limbs upstream would produce.
 * ------------------------------------------------------------------------------------ */

#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((uint64_t)(d1) & 0xFFFFFUL) << 32), \
    ((uint64_t)(d1) >> 20) | (((uint64_t)(d2)) << 12) | (((uint64_t)(d3) & 0xFFUL) << 44), \
    ((uint64_t)(d3) >> 8) | (((uint64_t)(d4) & 0xFFFFFFFUL) << 24), \
    ((uint64_t)(d4) >> 28) | (((uint64_t)(d5)) << 4) | (((uint64_t)(d6) & 0xFFFFUL) << 36), \
    ((uint64_t)(d6) >> 16) | (((uint64_t)(d7)) << 16) \
}

#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
    {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}

#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{ \
    (d0) | (((uint64_t)(d1)) << 32), \
    (d2) | (((uint64_t)(d3)) << 32), \
    (d4) | (((uint64_t)(d5)) << 32), \
    (d6) | (((uint64_t)(d7)) << 32) \
}}

#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) \
    {{((uint64_t)(d1)) << 32 | (d0), ((uint64_t)(d3)) << 32 | (d2), \
      ((uint64_t)(d5)) << 32 | (d4), ((uint64_t)(d7)) << 32 | (d6)}}

#define SECP256K1_GE_CONST(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) \
    {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), \
     SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}

#define SECP256K1_GEJ_CONST(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) \
    {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), \
     SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), \
     SECP256K1_FE_CONST(0,0,0,0,0,0,0,1), 0}

#define SECP256K1_GE_STORAGE_CONST(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p) \
    {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), \
     SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

/* Magnitude bounds, from upstream's group.h. The test bodies assert against these. */
#define SECP256K1_GE_X_MAGNITUDE_MAX  4
#define SECP256K1_GE_Y_MAGNITUDE_MAX  3
#define SECP256K1_GEJ_X_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Y_MAGNITUDE_MAX 4
#define SECP256K1_GEJ_Z_MAGNITUDE_MAX 1

/* Test-failure reporting. Upstream routes this through its own harness; here it records the
 * failure and keeps going, so one bad assertion does not hide the rest of the run. */
extern int shim_failures;
extern const char *shim_current_test;

#define CHECK(cond) do { \
    if (!(cond)) { \
        printf("  FAIL %s: %s (%s:%d)\n", \
               shim_current_test ? shim_current_test : "?", #cond, __FILE__, __LINE__); \
        shim_failures++; \
    } \
} while (0)

#define VERIFY_CHECK(cond) CHECK(cond)
#define VERIFY_SETUP(stmt) do { } while (0)

/* ---------------------------------------------------------------------------------------
 * The csuite exports.
 * ------------------------------------------------------------------------------------ */

void secp256k1_csuite_layout(uint64_t out[9]);

/* Must be called before anything else: it runs the library's lazy initialization, which the
 * Odin runtime would otherwise do at program start — and a C program never starts it. */
void secp256k1_csuite_init(void);

/* The generator context, opaque on this side. 168 bytes in this build; the size is checked
 * against `secp256k1_csuite_layout` at start-up rather than trusted. */
typedef struct { unsigned char blob[256]; } secp256k1_ecmult_gen_context;

void secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng);
void secp256k1_ecmult_const(secp256k1_gej *r, const secp256k1_ge *a, const secp256k1_scalar *q);
void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn);
void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx);
void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32);
int  secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w);
void secp256k1_scalar_split_lambda(secp256k1_scalar *r1, secp256k1_scalar *r2, const secp256k1_scalar *k);
void secp256k1_scalar_split_128(secp256k1_scalar *r1, secp256k1_scalar *r2, const secp256k1_scalar *k);
int  secp256k1_ecdsa_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid);
int  secp256k1_ecdsa_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message);

void secp256k1_fe_normalize(secp256k1_fe *r);
void secp256k1_fe_normalize_weak(secp256k1_fe *r);
void secp256k1_fe_normalize_var(secp256k1_fe *r);
int  secp256k1_fe_normalizes_to_zero(secp256k1_fe *r);
int  secp256k1_fe_normalizes_to_zero_var(secp256k1_fe *r);
void secp256k1_fe_set_int(secp256k1_fe *r, uint32_t a);
int  secp256k1_fe_is_zero(const secp256k1_fe *a);
int  secp256k1_fe_is_odd(const secp256k1_fe *a);
int  secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b);
int  secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b);
void secp256k1_fe_set_b32_mod(secp256k1_fe *r, const unsigned char *a);
int  secp256k1_fe_set_b32_limit(secp256k1_fe *r, const unsigned char *a);
void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a);
void secp256k1_fe_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m);
void secp256k1_fe_mul_int_unchecked(secp256k1_fe *r, int a);
void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a);
void secp256k1_fe_add_int(secp256k1_fe *r, int a);
void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe *b);
void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);
void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a);
void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a);
int  secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a);
int  secp256k1_fe_is_square_var(const secp256k1_fe *a);
void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag);
void secp256k1_fe_half(secp256k1_fe *r);
void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a);
void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a);
void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag);

void secp256k1_scalar_set_int(secp256k1_scalar *r, uint32_t v);
int  secp256k1_scalar_is_zero(const secp256k1_scalar *a);
int  secp256k1_scalar_is_one(const secp256k1_scalar *a);
int  secp256k1_scalar_is_even(const secp256k1_scalar *a);
int  secp256k1_scalar_is_high(const secp256k1_scalar *a);
int  secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);
void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b);
void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a);
int  secp256k1_scalar_cond_negate(secp256k1_scalar *r, int flag);
void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *a);
void secp256k1_scalar_inverse_var(secp256k1_scalar *r, const secp256k1_scalar *a);
void secp256k1_scalar_half(secp256k1_scalar *r, const secp256k1_scalar *a);
void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow);
int  secp256k1_scalar_set_b32_seckey(secp256k1_scalar *r, const unsigned char *b32);
void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar *a);
int  secp256k1_scalar_eq(const secp256k1_scalar *a, const secp256k1_scalar *b);
void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag);

void secp256k1_ge_set_xy(secp256k1_ge *r, const secp256k1_fe *x, const secp256k1_fe *y);
void secp256k1_ge_set_gej(secp256k1_ge *r, secp256k1_gej *a);
int  secp256k1_ge_is_infinity(const secp256k1_ge *a);
int  secp256k1_ge_is_valid_var(const secp256k1_ge *a);
void secp256k1_ge_neg(secp256k1_ge *r, const secp256k1_ge *a);
void secp256k1_gej_set_ge(secp256k1_gej *r, const secp256k1_ge *a);
void secp256k1_gej_set_infinity(secp256k1_gej *r);
int  secp256k1_gej_is_infinity(const secp256k1_gej *a);
void secp256k1_gej_neg(secp256k1_gej *r, const secp256k1_gej *a);
void secp256k1_gej_double_var(secp256k1_gej *r, const secp256k1_gej *a, secp256k1_fe *rzr);
void secp256k1_gej_add_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_gej *b, secp256k1_fe *rzr);
void secp256k1_gej_add_ge(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b);
void secp256k1_gej_add_ge_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, secp256k1_fe *rzr);
void secp256k1_ge_to_storage(secp256k1_ge_storage *r, const secp256k1_ge *a);
void secp256k1_ge_from_storage(secp256k1_ge *r, const secp256k1_ge_storage *a);
void secp256k1_ge_storage_cmov(secp256k1_ge_storage *r, const secp256k1_ge_storage *a, int flag);
int  secp256k1_ge_set_xo_var(secp256k1_ge *r, const secp256k1_fe *x, int odd);
extern const secp256k1_fe secp256k1_fe_one;
extern const secp256k1_ge secp256k1_ge_const_g;
extern const secp256k1_scalar secp256k1_const_lambda;
extern const secp256k1_scalar secp256k1_ecmult_const_K;
extern const secp256k1_scalar secp256k1_scalar_zero;
extern const secp256k1_scalar secp256k1_scalar_one;
void secp256k1_ge_set_infinity(secp256k1_ge *r);
void secp256k1_ge_set_gej_var(secp256k1_ge *r, secp256k1_gej *a);
int  secp256k1_ge_eq_var(const secp256k1_ge *a, const secp256k1_ge *b);
int  secp256k1_gej_eq_var(const secp256k1_gej *a, const secp256k1_gej *b);
int  secp256k1_gej_eq_ge_var(const secp256k1_gej *a, const secp256k1_ge *b);
void secp256k1_gej_double(secp256k1_gej *r, const secp256k1_gej *a);
void secp256k1_gej_add_zinv_var(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_ge *b, const secp256k1_fe *bzinv);
void secp256k1_ge_mul_lambda(secp256k1_ge *r, const secp256k1_ge *a);
void secp256k1_ge_set_all_gej_var(secp256k1_ge *r, const secp256k1_gej *a, uint64_t len);
void secp256k1_ge_set_all_gej(secp256k1_ge *r, const secp256k1_gej *a, uint64_t len);
int  secp256k1_ge_x_on_curve_var(const secp256k1_fe *x);
int  secp256k1_ge_x_frac_on_curve_var(const secp256k1_fe *xn, const secp256k1_fe *xd);
void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag);
int  secp256k1_scalar_check_overflow(const secp256k1_scalar *a);
uint32_t secp256k1_scalar_get_bits_limb32(const secp256k1_scalar *a, unsigned int offset, unsigned int count);
uint32_t secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count);
void secp256k1_gej_rescale(secp256k1_gej *r, const secp256k1_fe *s);
void secp256k1_fe_get_bounds(secp256k1_fe *r, int m);

/* Upstream's test bodies pass `&CTX->error_callback` to the allocator. There is no context
 * object on this side and the callback is unused, so a stand-in keeps the call sites
 * verbatim rather than requiring the bodies to be edited. */
typedef struct {
    int error_callback;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
} shim_ctx_t;
static shim_ctx_t shim_ctx_storage;
#define CTX (&shim_ctx_storage)

#define SECP256K1_GEJ_CONST_INFINITY {SECP256K1_FE_CONST(0,0,0,0,0,0,0,0), \
                                      SECP256K1_FE_CONST(0,0,0,0,0,0,0,0), \
                                      SECP256K1_FE_CONST(0,0,0,0,0,0,0,0), 1}

/* A branch-free int select, from upstream's util.h. */
static void secp256k1_int_cmov(int *r, const int *a, int flag) {
    unsigned int mask0, mask1, r_masked, a_masked;
    volatile int vflag = flag;
    mask0 = (unsigned int)vflag + ~0u;
    mask1 = ~mask0;
    r_masked = ((unsigned int)*r & mask0);
    a_masked = ((unsigned int)*a & mask1);
    *r = (int)(r_masked | a_masked);
}

/* Upstream's tests allocate scratch space through this helper. */
static void *checked_malloc(void *cb, size_t size) {
    void *p;
    (void)cb;
    p = malloc(size);
    if (p == NULL) {
        printf("  FAIL: out of memory\n");
        exit(2);
    }
    return p;
}

/* Upstream spells the magnitude-checked negation `secp256k1_fe_negate` and the unchecked one
 * `_unchecked`; with the VERIFY layer absent the two coincide. */
#define secp256k1_fe_negate(r, a, m) secp256k1_fe_negate_unchecked((r), (a), (m))
#define secp256k1_fe_mul_int(r, a)   secp256k1_fe_mul_int_unchecked((r), (a))

/* ---------------------------------------------------------------------------------------
 * Support helpers that upstream's test bodies call but which are not the code under test.
 *
 * `secp256k1_memcmp_var` is copied from upstream's `util.h` verbatim. The `testrand` family
 * is backed by this implementation's own xoshiro256++ generator, which is the same
 * algorithm upstream's `testrand_impl.h` uses — so a seed produces the same stream on both
 * sides and a failure found in one suite replays in the other.
 * ------------------------------------------------------------------------------------ */

static int secp256k1_memcmp_var(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1, *p2 = s2;
    size_t i;
    for (i = 0; i < n; i++) {
        int diff = p1[i] - p2[i];
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

void     testrand_seed(const unsigned char *seed16);
uint64_t testrand64(void);
uint32_t testrand32(void);
uint32_t testrand_bits(int bits);
uint32_t testrand_int(uint32_t range);
void     testrand256(unsigned char *b32);
void     testrand256_test(unsigned char *b32);
void     testrand_bytes_test(unsigned char *bytes, size_t len);
void     testrand_flip(unsigned char *b, size_t len);

#endif /* SECP256K1_SHIM_H */
