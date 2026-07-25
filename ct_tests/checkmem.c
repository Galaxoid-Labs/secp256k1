/*
 * Memory-checking shim for the constant-time harness.
 *
 * Constant-time verification works by lying to a memory checker: secret buffers are marked
 * "undefined", and the checker then reports any branch or memory access whose outcome
 * depends on undefined data. Those reports are exactly the secret-dependent control flow
 * and secret-indexed loads we must not have.
 *
 * Two backends, matching upstream's `src/checkmem.h`:
 *
 *   - valgrind (memcheck) via client requests. Works on an ordinary build, no
 *     recompilation of dependencies needed. This is the primary route.
 *   - MemorySanitizer via __msan_allocated_memory. Faster and more precise, but requires
 *     the whole program — including the Odin runtime — to be MSan-instrumented, which Odin
 *     does not currently expose.
 *
 * When neither is available every function here is a no-op and `ct_checkmem_enabled()`
 * returns 0, so the harness can report honestly that it verified nothing rather than
 * silently passing.
 */

#include <stddef.h>

#if defined(VALGRIND)
#  include <valgrind/memcheck.h>
#  define CT_CHECKMEM_ENABLED 1
#  define CT_UNDEFINE(p, len) VALGRIND_MAKE_MEM_UNDEFINED((p), (len))
#  define CT_DEFINE(p, len)   VALGRIND_MAKE_MEM_DEFINED((p), (len))
#elif defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#    include <sanitizer/msan_interface.h>
#    define CT_CHECKMEM_ENABLED 1
#    define CT_UNDEFINE(p, len) __msan_allocated_memory((p), (len))
#    define CT_DEFINE(p, len)   __msan_unpoison((p), (len))
#  endif
#endif

#ifndef CT_CHECKMEM_ENABLED
#  define CT_CHECKMEM_ENABLED 0
#  define CT_UNDEFINE(p, len) do { (void)(p); (void)(len); } while (0)
#  define CT_DEFINE(p, len)   do { (void)(p); (void)(len); } while (0)
#endif

/*
 * Reports whether a checker is compiled in.
 *
 * The harness refuses to claim success when this returns 0. A constant-time test that
 * silently verifies nothing is worse than no test, because it produces a green result that
 * means nothing.
 */
int ct_checkmem_enabled(void) {
    return CT_CHECKMEM_ENABLED;
}

/*
 * Marks a buffer as secret. Any subsequent branch or memory index derived from it is a
 * finding.
 */
void ct_checkmem_undefine(void *p, size_t len) {
    CT_UNDEFINE(p, len);
}

/*
 * Marks a buffer as public again.
 *
 * Used for values that are legitimately published — a signature, a public key, the result
 * of a deliberate declassification. Without this the harness would flag the act of
 * returning a signature to the caller, since the signature is derived from secret input.
 *
 * Every call is a claim that the value really is safe to publish, so each one in the
 * harness carries a comment justifying it.
 */
void ct_checkmem_define(void *p, size_t len) {
    CT_DEFINE(p, len);
}
