/*
 * failstep runtime -- internal declarations shared by the runtime sources.
 * SPDX-License-Identifier: MIT
 */
#ifndef FAILSTEP_RUNTIME_INTERNAL_H
#define FAILSTEP_RUNTIME_INTERNAL_H

/* The runtime calls the real allocation functions, so it must never see the
 * override macros, whatever the build system force-includes. */
#define FAILSTEP_NO_OVERRIDE 1

#include <failstep/failstep.h>

#include <stddef.h>
#include <stdint.h>

/* Maximum stack depth captured per allocation site. */
#define FAILSTEP_MAX_FRAMES 64

/* One captured stack frame, resolved enough to be hashed stably across runs
 * (module + offset, not the ASLR-randomised absolute address) and symbolised
 * later by the CLI. */
typedef struct {
    void *addr;            /* absolute return address */
    unsigned long long off; /* offset within its module (addr - module base) */
    const char *module;    /* module path, or NULL if unknown */
    const char *symbol;    /* best-effort symbol name, or NULL */
} failstep_frame_t;

/* Captures the current call stack into `frames` (up to FAILSTEP_MAX_FRAMES),
 * dropping leading frames that belong to the failstep runtime itself so the
 * first recorded frame is the user's allocation call. Returns the number of
 * frames stored. `extra_skip` drops that many additional user frames from the
 * top (used by failstep_site(skip)). */
int failstep_capture(failstep_frame_t *frames, int max, int extra_skip);

/* A stable 64-bit fingerprint of a captured stack. */
failstep_site_t failstep_hash_frames(const failstep_frame_t *frames, int n);

/*
 * Registers a failstep-internal function so that capture can recognise (and
 * drop) the leading frames that belong to the runtime itself. Detection is by
 * address window -- a return address inside one of these small functions -- so
 * it is robust whether the runtime is linked statically or as a shared library,
 * and whether or not symbols survive. Call for each interceptor / entry before
 * the first capture. Passing NULL (e.g. an unused weak __wrap_ symbol) is
 * ignored. */
void failstep_mark_internal(uintptr_t fn);

/*
 * The shared decision entry used by the intercepted allocators, by
 * failstep_should_fail() and by the --wrap wrappers. Returns non-zero when the
 * current allocation should fail. Kept at a fixed call depth (it captures with
 * skip=3) so that all three callers resolve the same user frame as the site.
 */
int failstep__decide(void);

/* The interceptors (defined in runtime.c; prototypes also in override.h, which
 * the runtime does not include because it needs the real functions). */
void *failstep_malloc(size_t size);
void *failstep_calloc(size_t nmemb, size_t size);
void *failstep_realloc(void *ptr, size_t size);
void failstep_free(void *ptr);
char *failstep_strdup(const char *s);
char *failstep_strndup(const char *s, size_t n);
void *failstep_aligned_alloc(size_t alignment, size_t size);

/* Serialises the symbol strings held by a frame array so they survive past the
 * lifetime of transient backtrace buffers. Returns a malloc'd deep copy array
 * (using the real allocator) or NULL; free with failstep_frames_free. */
failstep_frame_t *failstep_frames_dup(const failstep_frame_t *frames, int n);
void failstep_frames_free(failstep_frame_t *frames, int n);

#endif /* FAILSTEP_RUNTIME_INTERNAL_H */
