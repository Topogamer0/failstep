/*
 * failstep -- systematic allocation-failure testing for C, compatible with
 * AddressSanitizer.
 *
 * This header declares the public runtime API. Link against `failstep` (the
 * static or shared runtime) and, for the common case, force-include
 * <failstep/override.h> so that malloc()/calloc()/realloc()/free()/strdup()/
 * strndup()/aligned_alloc() in your code are routed through the runtime.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef FAILSTEP_H
#define FAILSTEP_H

#include <stddef.h>

#if defined(_WIN32) && defined(FAILSTEP_SHARED)
#  ifdef FAILSTEP_BUILDING_SHARED
#    define FAILSTEP_API __declspec(dllexport)
#  else
#    define FAILSTEP_API __declspec(dllimport)
#  endif
#else
#  define FAILSTEP_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Semantic version of the runtime. */
#define FAILSTEP_VERSION_MAJOR 0
#define FAILSTEP_VERSION_MINOR 1
#define FAILSTEP_VERSION_PATCH 1

#define FAILSTEP_STR_(x) #x
#define FAILSTEP_STR(x) FAILSTEP_STR_(x)
/* "MAJOR.MINOR.PATCH", derived from the numbers above. */
#define FAILSTEP_VERSION_STRING                                               \
    FAILSTEP_STR(FAILSTEP_VERSION_MAJOR) "." FAILSTEP_STR(FAILSTEP_VERSION_MINOR) "." \
        FAILSTEP_STR(FAILSTEP_VERSION_PATCH)

/* Returns the runtime version as "MAJOR.MINOR.PATCH". */
FAILSTEP_API const char *failstep_version(void);

/*
 * A call site: a stable, process-independent fingerprint of the call stack at
 * the point an allocation is requested. The same source location produces the
 * same value across separate runs of the same binary, so the CLI can first
 * enumerate the sites of a program and then, in a later run, ask the runtime to
 * fail one in particular.
 */
typedef unsigned long long failstep_site_t;

/* ---- decision API ------------------------------------------------------- */

/*
 * The decision an allocator must make. Returns non-zero when the current
 * allocation should be made to fail (the caller must then behave as if the
 * underlying allocator returned NULL), and zero when it should proceed.
 *
 * Calling it also advances failstep's internal allocation counter and records
 * the call site, exactly as the intercepted malloc() family does, so a custom
 * allocator wired through this function is driven by every mode (enumerate,
 * sites, continue, fuzz) with no extra work.
 *
 * Projects with their own allocator -- PHP's emalloc, an arena, a pool --
 * enable failstep in a single line:
 *
 *     void *emalloc(size_t n) {
 *         if (failstep_should_fail()) return NULL;
 *         return real_emalloc(n);
 *     }
 *
 * The site is computed from the caller's stack, so distinct call paths into the
 * same allocator are distinguished.
 */
FAILSTEP_API int failstep_should_fail(void);

/*
 * Same decision for a site you have already computed with failstep_site(). Use
 * this when the allocation site is better described by a point other than the
 * immediate caller (for example a macro wrapper), or to key the decision on a
 * caller-chosen tag instead of the stack.
 */
FAILSTEP_API int failstep_should_fail_at(failstep_site_t site);

/*
 * Computes the call site of the caller (skipping `skip` extra frames: pass 0
 * for the direct caller of failstep_site). Combine with
 * failstep_should_fail_at() when you need the site value itself, e.g. to log
 * it or to fail a specific site deterministically from your own harness.
 */
FAILSTEP_API failstep_site_t failstep_site(int skip);

/*
 * A stable site computed from an explicit string tag rather than the stack.
 * Useful for allocators where the stack is uninformative (tail calls, a single
 * shared slow path) but a meaningful label is available at the call.
 */
FAILSTEP_API failstep_site_t failstep_site_tag(const char *tag);

/* ---- continue-mode harness ---------------------------------------------- */

/*
 * The "continue" mode runs long-lived state through an allocation failure and
 * then keeps using it, in the same process, so that AddressSanitizer and
 * LeakSanitizer can observe damage that only surfaces later -- the class of bug
 * where a failed allocation leaves a dangling pointer or half-updated global
 * that a *subsequent* operation trips over (see the PHP2Shell CVEs).
 *
 * Provide setup/step/teardown. For each targeted allocation N, failstep runs:
 *
 *     void *ctx = setup();
 *     step(ctx, 0);        // step with a failure injected at allocation N
 *     step(ctx, 1); ...    // `continue_steps` further *normal* steps
 *     teardown(ctx);
 *
 * `step`'s second argument is the 0-based index within the run (0 is the
 * fault-injected step). Return 0 from step to continue, non-zero to stop early.
 * The failing allocation index and the number of follow-up steps are chosen by
 * the CLI through the environment; running the harness binary directly (no
 * failstep environment) performs a single clean pass, which is handy under a
 * debugger.
 */
typedef void *(*failstep_setup_fn)(void);
typedef int (*failstep_step_fn)(void *ctx, int step_index);
typedef void (*failstep_teardown_fn)(void *ctx);

typedef struct {
    failstep_setup_fn setup;       /* may be NULL */
    failstep_step_fn step;         /* required */
    failstep_teardown_fn teardown; /* may be NULL */
    const char *name;              /* optional label for reports */
} failstep_harness_t;

/*
 * Runs the harness according to the current failstep environment and returns a
 * process exit code suitable for main():
 *
 *     int main(void) { return failstep_run_harness(&harness); }
 */
FAILSTEP_API int failstep_run_harness(const failstep_harness_t *harness);

/* ---- libFuzzer integration ---------------------------------------------- */

/*
 * Seeds the failure oracle from fuzzer-controlled bytes. Call once at the start
 * of LLVMFuzzerTestOneInput, before exercising the code under test:
 *
 *     int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 *         size_t used = failstep_fuzz_begin(data, size);
 *         data += used; size -= used;      // rest is the real input
 *         exercise(data, size);
 *         failstep_fuzz_end();
 *         return 0;
 *     }
 *
 * The consumed prefix deterministically decides which allocations fail, so a
 * crash found by the fuzzer is reproducible from the same input. Returns the
 * number of leading bytes consumed (0 when `size` is 0).
 */
FAILSTEP_API size_t failstep_fuzz_begin(const unsigned char *data, size_t size);

/* Resets the oracle after one fuzz iteration. */
FAILSTEP_API void failstep_fuzz_end(void);

/* ---- introspection ------------------------------------------------------ */

/*
 * The total number of allocation decisions made so far in this process
 * (whether or not they were failed). Mainly useful to harnesses and tests.
 */
FAILSTEP_API unsigned long long failstep_alloc_count(void);

/*
 * Whether failstep is active in this process (the CLI set a mode in the
 * environment). When inactive, failstep_should_fail() always returns 0 and the
 * intercepted allocators behave exactly like the C library.
 */
FAILSTEP_API int failstep_active(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FAILSTEP_H */
