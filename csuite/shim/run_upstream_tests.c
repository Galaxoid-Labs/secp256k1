/*
 * Runs upstream's test bodies against this implementation.
 *
 * This is option B from `TODO.md` item 5. Upstream's `tests.c` cannot be linked against a
 * foreign implementation — it `#include`s the whole C library rather than linking one — so
 * the test *bodies* are lifted verbatim by `tools/extract_upstream_tests.py` and compiled
 * against `secp256k1_shim.h`, which declares upstream's internal API backed by `csuite`.
 *
 * What that licenses precisely: **runs upstream's test bodies against this implementation.**
 * Not "passes libsecp256k1's tests" — the assertions are upstream's and unmodified, but the
 * file they live in is not, so the stronger phrase stays reserved.
 *
 * The generator is upstream's own algorithm (xoshiro256++) so that a seed produces the same
 * stream on both sides and a failure found here replays in upstream's suite.
 *
 *   ./csuite/build.sh
 */

#include "secp256k1_shim.h"

int shim_failures = 0;
const char *shim_current_test = NULL;

/* ---------------------------------------------------------------------------------------
 * xoshiro256++, matching upstream's testrand_impl.h.
 * ------------------------------------------------------------------------------------ */

static uint64_t rng_state[4];
static uint64_t rng_bitcache;
static int rng_bitcache_used;

static uint64_t rotl(uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static uint64_t xoshiro256pp(void) {
    uint64_t result = rotl(rng_state[0] + rng_state[3], 23) + rng_state[0];
    uint64_t t = rng_state[1] << 17;
    rng_state[2] ^= rng_state[0];
    rng_state[3] ^= rng_state[1];
    rng_state[1] ^= rng_state[2];
    rng_state[0] ^= rng_state[3];
    rng_state[2] ^= t;
    rng_state[3] = rotl(rng_state[3], 45);
    return result;
}

void testrand_seed(const unsigned char *seed16) {
    /* SplitMix64 expansion, as upstream does, so a 16-byte seed gives a well-distributed
     * 256-bit state that is never all zero. */
    uint64_t s = 0;
    int i;
    for (i = 0; i < 8; i++) {
        s = (s << 8) | seed16[i];
    }
    for (i = 0; i < 4; i++) {
        uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        rng_state[i] = z ^ (z >> 31);
    }
    rng_bitcache = 0;
    rng_bitcache_used = 0;
}

uint64_t testrand64(void) {
    return xoshiro256pp();
}

uint32_t testrand32(void) {
    return (uint32_t)(xoshiro256pp() >> 32);
}

uint32_t testrand_bits(int bits) {
    uint32_t out;
    if (bits == 0) {
        return 0;
    }
    if (rng_bitcache_used < bits) {
        rng_bitcache = xoshiro256pp();
        rng_bitcache_used = 64;
    }
    out = (uint32_t)(rng_bitcache & (((uint64_t)1 << bits) - 1));
    rng_bitcache >>= bits;
    rng_bitcache_used -= bits;
    return out;
}

uint32_t testrand_int(uint32_t range) {
    uint32_t mask = 0, r;
    uint32_t range_copy = range - 1;
    while (range_copy) {
        mask = (mask << 1) | 1;
        range_copy >>= 1;
    }
    do {
        r = testrand32() & mask;
    } while (r >= range);
    return r;
}

void testrand256(unsigned char *b32) {
    int i;
    for (i = 0; i < 4; i++) {
        uint64_t v = xoshiro256pp();
        int j;
        for (j = 0; j < 8; j++) {
            b32[i * 8 + j] = (unsigned char)(v >> (8 * j));
        }
    }
}

void testrand_bytes_test(unsigned char *bytes, size_t len) {
    /* Upstream biases towards long runs of zero and one bits, which is what reaches carry
     * and normalization edges that uniform bytes essentially never hit. */
    size_t bits = 0;
    memset(bytes, 0, len);
    while (bits < len * 8) {
        int now = 1 + (testrand_bits(6) * testrand_bits(5) + 16) / 31;
        int val = testrand_bits(1);
        while (now > 0 && bits < len * 8) {
            bytes[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

void testrand256_test(unsigned char *b32) {
    testrand_bytes_test(b32, 32);
}

void testrand_flip(unsigned char *b, size_t len) {
    b[testrand_int(len)] ^= (1 << testrand_int(8));
}

/* Upstream's test bodies use COUNT for iteration counts. */
static int COUNT = 64;

#include "upstream_bodies.h"

/*
 * Upstream's `run_ge` wrapper also calls `test_ge_bytes`, which exercises a musig-internal
 * point serialization (`secp256k1_ge_to_bytes`) that this implementation does not have. The
 * wrapper is therefore not lifted; its three applicable components are driven directly, with
 * upstream's own iteration count. Stubbing `test_ge_bytes` to a no-op inside a verbatim body
 * would have been the wrong call — a silently empty assertion in a green run is worse than
 * an absent one.
 */
/*
 * Upstream's `run_wnaf` also drives `test_fixed_wnaf` and `test_fixed_wnaf_small`, which
 * exercise `secp256k1_wnaf_fixed` — a routine this implementation does not have. Only the
 * applicable part is driven, with upstream's iteration count.
 */
static void run_wnaf_applicable(void) {
    int i;
    secp256k1_scalar n;
    for (i = 0; i < COUNT; i++) {
        testutil_random_scalar_order(&n);
        test_wnaf(&n, 4 + (i % 10));
    }
}

static void run_ge_applicable(void) {
    int i;
    for (i = 0; i < COUNT * 32; i++) {
        test_ge();
    }
    test_add_neg_y_diff_x();
    test_initialized_inf();
}

#define RUN(name) do { \
    shim_current_test = #name; \
    int before = shim_failures; \
    name(); \
    printf("  %-24s %s\n", #name, shim_failures == before ? "ok" : "FAILED"); \
} while (0)

int main(void) {
    unsigned char seed[16] = {
        0x5c, 0x40, 0xbb, 0x34, 0x07, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb
    };
    uint64_t layout[9];

    printf("upstream test bodies, run against this implementation\n\n");

    /* Refuse to run on a layout mismatch. Every body below reads these structs directly, so
     * a disagreement here would make the whole run meaningless rather than merely wrong. */
    secp256k1_csuite_layout(layout);
    if (layout[0] != sizeof(secp256k1_fe) || layout[1] != sizeof(secp256k1_ge) ||
        layout[3] != sizeof(secp256k1_gej) || layout[5] != sizeof(secp256k1_scalar)) {
        printf("  ABORT: struct layout mismatch between C and the library\n");
        return 2;
    }

    if (layout[8] > sizeof(((shim_ctx_t *)0)->ecmult_gen_ctx)) {
        printf("  ABORT: ecmult_gen_context is larger than the C-side storage\n");
        return 2;
    }

    secp256k1_csuite_init();
    testrand_seed(seed);
    secp256k1_ecmult_gen_context_build(&CTX->ecmult_gen_ctx);

    RUN(run_field_convert);
    RUN(run_field_half);
    RUN(run_field_misc);
    RUN(run_sqrt);
    RUN(run_scalar_tests);
    RUN(run_scalar_set_b32_seckey_tests);
    RUN(run_ge_applicable);
    RUN(run_ecmult_chain);
    RUN(run_wnaf_applicable);
    RUN(run_fe_mul);
    RUN(run_sqr);
    RUN(run_field_be32_overflow);
    RUN(run_group_decompress);
    RUN(run_endomorphism_tests);
    RUN(run_cmov_tests);
    RUN(run_point_times_order);
    RUN(run_ecmult_near_split_bound);
    RUN(run_ecdsa_sign_verify);

    printf("\n");
    if (shim_failures) {
        printf("%d upstream assertion(s) failed\n", shim_failures);
        return 1;
    }
    printf("all upstream assertions passed\n");
    return 0;
}
