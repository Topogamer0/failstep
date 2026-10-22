/*
 * failstep runtime -- the failure oracle and the allocation interceptors.
 *
 * The CLI drives the runtime through environment variables so that each run of
 * the target is an ordinary separate process:
 *
 *   FAILSTEP_MODE      off | count | index | site | fuzz
 *   FAILSTEP_FAIL_INDEX   N   (index mode: fail the N-th decision, 1-based)
 *   FAILSTEP_FAIL_SITE    H   (site mode: fail the first decision at site H)
 *   FAILSTEP_SCOPED       1   (only count/fail while the harness is "armed")
 *   FAILSTEP_CONTINUE_STEPS K (continue mode: follow-up steps after the fault)
 *   FAILSTEP_REPORT    path   (where to record the injected failure)
 *   FAILSTEP_STATS     path   (count mode: where to write the site inventory)
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(__linux__)
/* aligned_alloc() is C11; expose it under -std=c99 on glibc. */
#  define _ISOC11_SOURCE 1
#endif

#include "runtime_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#  define FS_NOINLINE __declspec(noinline)
#  define FS_TLS __declspec(thread)
#else
#  define FS_NOINLINE __attribute__((noinline))
#  define FS_TLS __thread
#endif

/*
 * Re-entrancy guard. When the runtime is linked statically and the target uses
 * -Wl,--wrap=malloc, the runtime's OWN bookkeeping allocations (the site
 * registry, the fuzz bitmap, backtrace/dladdr internals) are diverted to
 * __wrap_malloc too, which would call back into the decision path -- deadlocking
 * on the non-recursive lock and, worse, deciding on the runtime's internal
 * allocations. This per-thread flag makes a nested decision a no-op pass-through
 * so __wrap_* calls __real_* for those. It is thread-local so a genuine
 * concurrent decision on another thread is never suppressed.
 */
static FS_TLS int g_in_decide;

/* ---- lock --------------------------------------------------------------- */

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
static SRWLOCK g_lock = SRWLOCK_INIT;
static void lock(void) { AcquireSRWLockExclusive(&g_lock); }
static void unlock(void) { ReleaseSRWLockExclusive(&g_lock); }
#else
#  include <pthread.h>
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void lock(void) { pthread_mutex_lock(&g_lock); }
static void unlock(void) { pthread_mutex_unlock(&g_lock); }
#endif

/* ---- state -------------------------------------------------------------- */

typedef enum { MODE_OFF = 0, MODE_COUNT, MODE_INDEX, MODE_SITE, MODE_FUZZ } fs_mode_t;

typedef struct {
    failstep_site_t site;
    unsigned long long first_index;
    unsigned long long count;
    failstep_frame_t *frames;
    int nframes;
} fs_site_rec_t;

static struct {
    int inited;
    fs_mode_t mode;
    int scoped;          /* only act while armed (continue mode) */
    int armed;           /* currently inside a fault-injected step */
    unsigned long long fail_index;
    failstep_site_t fail_site;
    const char *report_path;
    const char *stats_path;
    int continue_steps;

    unsigned long long total;   /* every decision, for failstep_alloc_count */
    unsigned long long counter; /* decisions while counting; reset on arm */
    int site_fired;             /* site mode: already failed once */
    int report_written;         /* a report has been emitted */

    fs_site_rec_t *sites;
    size_t nsites, cap_sites;

    /* fuzz oracle */
    int fuzz_active;
    unsigned char *fuzz_bits;
    size_t fuzz_nbits;
} g;

static fs_mode_t parse_mode(const char *s) {
    if (!s) return MODE_OFF;
    if (strcmp(s, "count") == 0) return MODE_COUNT;
    if (strcmp(s, "index") == 0) return MODE_INDEX;
    if (strcmp(s, "site") == 0) return MODE_SITE;
    if (strcmp(s, "fuzz") == 0) return MODE_FUZZ;
    return MODE_OFF;
}

static void write_stats(void);

/* Weak so these resolve to NULL (and are skipped) when --wrap is not used. */
#if !defined(_WIN32) && !defined(__APPLE__)
extern void *__wrap_malloc(size_t) __attribute__((weak));
extern void *__wrap_calloc(size_t, size_t) __attribute__((weak));
extern void *__wrap_realloc(void *, size_t) __attribute__((weak));
extern char *__wrap_strdup(const char *) __attribute__((weak));
extern char *__wrap_strndup(const char *, size_t) __attribute__((weak));
extern void *__wrap_aligned_alloc(size_t, size_t) __attribute__((weak));
#endif

/* Convert a function pointer to its numeric address without the (ISO C
 * forbidden) function-to-object pointer cast, by copying the representation. */
static uintptr_t fn_addr(void (*fn)(void)) {
    uintptr_t a = 0;
    size_t n = sizeof(fn) < sizeof(a) ? sizeof(fn) : sizeof(a);
    memcpy(&a, &fn, n);
    return a;
}

static void register_internal_frames(void) {
    failstep_mark_internal(fn_addr((void (*)(void))failstep_capture));
    failstep_mark_internal(fn_addr((void (*)(void))failstep__decide));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_should_fail));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_should_fail_at));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_site));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_malloc));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_calloc));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_realloc));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_strdup));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_strndup));
    failstep_mark_internal(fn_addr((void (*)(void))failstep_aligned_alloc));
#if !defined(_WIN32) && !defined(__APPLE__)
    if (__wrap_malloc) failstep_mark_internal(fn_addr((void (*)(void))__wrap_malloc));
    if (__wrap_calloc) failstep_mark_internal(fn_addr((void (*)(void))__wrap_calloc));
    if (__wrap_realloc) failstep_mark_internal(fn_addr((void (*)(void))__wrap_realloc));
    if (__wrap_strdup) failstep_mark_internal(fn_addr((void (*)(void))__wrap_strdup));
    if (__wrap_strndup) failstep_mark_internal(fn_addr((void (*)(void))__wrap_strndup));
    if (__wrap_aligned_alloc) failstep_mark_internal(fn_addr((void (*)(void))__wrap_aligned_alloc));
#endif
}

static void ensure_init_locked(void) {
    if (g.inited) return;
    g.inited = 1;
    register_internal_frames();
    g.mode = parse_mode(getenv("FAILSTEP_MODE"));
    g.scoped = getenv("FAILSTEP_SCOPED") != NULL;
    const char *idx = getenv("FAILSTEP_FAIL_INDEX");
    if (idx) g.fail_index = strtoull(idx, NULL, 10);
    const char *site = getenv("FAILSTEP_FAIL_SITE");
    if (site) g.fail_site = strtoull(site, NULL, 0);
    g.report_path = getenv("FAILSTEP_REPORT");
    g.stats_path = getenv("FAILSTEP_STATS");
    const char *k = getenv("FAILSTEP_CONTINUE_STEPS");
    g.continue_steps = k ? atoi(k) : 2;
    if (g.mode == MODE_COUNT && g.stats_path) atexit(write_stats);
}

/* ---- site registry (count mode) ---------------------------------------- */

static void registry_add(failstep_site_t site, unsigned long long index,
                         const failstep_frame_t *frames, int n) {
    for (size_t i = 0; i < g.nsites; i++) {
        if (g.sites[i].site == site) {
            g.sites[i].count++;
            return;
        }
    }
    if (g.nsites == g.cap_sites) {
        size_t cap = g.cap_sites ? g.cap_sites * 2 : 64;
        fs_site_rec_t *p = (fs_site_rec_t *)realloc(g.sites, cap * sizeof(*p));
        if (!p) return; /* out of memory while cataloguing: drop silently */
        g.sites = p;
        g.cap_sites = cap;
    }
    fs_site_rec_t *r = &g.sites[g.nsites++];
    r->site = site;
    r->first_index = index;
    r->count = 1;
    r->frames = failstep_frames_dup(frames, n);
    r->nframes = r->frames ? n : 0;
}

/* ---- report / stats output --------------------------------------------- */

static void write_frames(FILE *f, const failstep_frame_t *frames, int n) {
    for (int i = 0; i < n; i++) {
        /* tab-separated: offset, absolute addr, module, symbol */
        fprintf(f, "frame\t0x%llx\t%p\t%s\t%s\n", frames[i].off, frames[i].addr,
                frames[i].module ? frames[i].module : "", frames[i].symbol ? frames[i].symbol : "");
    }
}

static void write_report(unsigned long long index, failstep_site_t site,
                         const failstep_frame_t *frames, int n) {
    if (!g.report_path || g.report_written) return;
    FILE *f = fopen(g.report_path, "w");
    if (!f) return;
    fprintf(f, "failstep-report 1\n");
    fprintf(f, "index %llu\n", index);
    fprintf(f, "site 0x%llx\n", (unsigned long long)site);
    fprintf(f, "frames %d\n", n);
    write_frames(f, frames, n);
    fclose(f);
    g.report_written = 1;
}

static void write_stats(void) {
    lock();
    if (!g.stats_path) {
        unlock();
        return;
    }
    FILE *f = fopen(g.stats_path, "w");
    if (!f) {
        unlock();
        return;
    }
    fprintf(f, "failstep-stats 1\n");
    fprintf(f, "allocs %llu\n", g.counter);
    fprintf(f, "sites %zu\n", g.nsites);
    for (size_t i = 0; i < g.nsites; i++) {
        fs_site_rec_t *r = &g.sites[i];
        fprintf(f, "site 0x%llx %llu %llu %d\n", (unsigned long long)r->site, r->first_index,
                r->count, r->nframes);
        write_frames(f, r->frames, r->nframes);
    }
    fclose(f);
    unlock();
}

/* ---- fuzz oracle -------------------------------------------------------- */

static int fuzz_should_fail(unsigned long long index) {
    if (!g.fuzz_bits || g.fuzz_nbits == 0) return 0;
    unsigned long long bit = (index - 1) % g.fuzz_nbits;
    return (g.fuzz_bits[bit >> 3] >> (bit & 7)) & 1;
}

/* ---- the decision core (called with the lock held) --------------------- */

static int decide_core(failstep_site_t site, const failstep_frame_t *frames, int n) {
    g.total++;

    int counting = (g.mode != MODE_OFF) && (!g.scoped || g.armed);
    if (g.fuzz_active) counting = 1;
    if (!counting) return 0;

    g.counter++;
    unsigned long long idx = g.counter;

    if (g.fuzz_active) {
        if (fuzz_should_fail(idx)) {
            write_report(idx, site, frames, n);
            return 1;
        }
        return 0;
    }

    switch (g.mode) {
    case MODE_COUNT:
        registry_add(site, idx, frames, n);
        return 0;
    case MODE_INDEX:
        if (idx == g.fail_index) {
            write_report(idx, site, frames, n);
            return 1;
        }
        return 0;
    case MODE_SITE:
        if (!g.site_fired && site == g.fail_site) {
            g.site_fired = 1;
            write_report(idx, site, frames, n);
            return 1;
        }
        return 0;
    default:
        return 0;
    }
}

/*
 * The single decision entry for the intercepted allocators and for
 * failstep_should_fail(). Kept noinline so the captured stack has a fixed shape
 * (capture, failstep__decide, <public wrapper>, <user frame>, ...) and skip=3 always
 * lands on the user's allocation call.
 */
FS_NOINLINE int failstep__decide(void) {
    if (g_in_decide) return 0; /* re-entrant (runtime's own allocation): pass through */
    g_in_decide = 1;

    lock();
    ensure_init_locked();
    int off = (g.mode == MODE_OFF) && !g.fuzz_active;
    unlock();
    if (off) {
        g_in_decide = 0;
        return 0;
    }

    failstep_frame_t frames[FAILSTEP_MAX_FRAMES];
    int n = failstep_capture(frames, FAILSTEP_MAX_FRAMES, 0);
    failstep_site_t site = failstep_hash_frames(frames, n);

    lock();
    int r = decide_core(site, frames, n);
    unlock();
    g_in_decide = 0;
    return r;
}

/* ---- public decision API ------------------------------------------------ */

const char *failstep_version(void) {
    return "0.1.0";
}

FS_NOINLINE int failstep_should_fail(void) {
    return failstep__decide();
}

int failstep_should_fail_at(failstep_site_t site) {
    if (g_in_decide) return 0;
    g_in_decide = 1;

    lock();
    ensure_init_locked();
    int off = (g.mode == MODE_OFF) && !g.fuzz_active;
    unlock();
    if (off) {
        g_in_decide = 0;
        return 0;
    }

    failstep_frame_t frames[FAILSTEP_MAX_FRAMES];
    int n = failstep_capture(frames, FAILSTEP_MAX_FRAMES, 0);
    lock();
    int r = decide_core(site, frames, n);
    unlock();
    g_in_decide = 0;
    return r;
}

failstep_site_t failstep_site(int skip) {
    lock();
    ensure_init_locked(); /* ensures internal frames are registered for trimming */
    unlock();
    failstep_frame_t frames[FAILSTEP_MAX_FRAMES];
    int n = failstep_capture(frames, FAILSTEP_MAX_FRAMES, (skip > 0 ? skip : 0));
    return failstep_hash_frames(frames, n);
}

failstep_site_t failstep_site_tag(const char *tag) {
    if (!tag) tag = "";
    unsigned long long h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)tag; *p; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

unsigned long long failstep_alloc_count(void) {
    lock();
    unsigned long long t = g.total;
    unlock();
    return t;
}

int failstep_active(void) {
    lock();
    ensure_init_locked();
    int a = (g.mode != MODE_OFF) || g.fuzz_active;
    unlock();
    return a;
}

/* ---- allocation interceptors ------------------------------------------- */

FS_NOINLINE void *failstep_malloc(size_t size) {
    if (failstep__decide()) return NULL;
    return malloc(size);
}

FS_NOINLINE void *failstep_calloc(size_t nmemb, size_t size) {
    if (failstep__decide()) return NULL;
    return calloc(nmemb, size);
}

FS_NOINLINE void *failstep_realloc(void *ptr, size_t size) {
    /* A failing realloc must leave the original block untouched, exactly as the
     * C standard requires, so we never call the real realloc on failure. */
    if (failstep__decide()) return NULL;
    return realloc(ptr, size);
}

#if defined(_WIN32)
/* On Windows an aligned_alloc of alignment > 16 is served by _aligned_malloc,
 * which must be released with _aligned_free, not free(). Since the override
 * routes both aligned_alloc and free through the runtime, we remember the
 * _aligned_malloc'd pointers so failstep_free can release each correctly. */
static void **g_aligned;
static size_t g_aligned_n, g_aligned_cap;

static void aligned_remember(void *p) {
    if (!p) return;
    lock();
    if (g_aligned_n == g_aligned_cap) {
        size_t cap = g_aligned_cap ? g_aligned_cap * 2 : 32;
        void **q = (void **)realloc(g_aligned, cap * sizeof(*q));
        if (q) {
            g_aligned = q;
            g_aligned_cap = cap;
        }
    }
    if (g_aligned_n < g_aligned_cap) g_aligned[g_aligned_n++] = p;
    unlock();
}

static int aligned_forget(void *p) {
    int found = 0;
    lock();
    for (size_t i = 0; i < g_aligned_n; i++) {
        if (g_aligned[i] == p) {
            g_aligned[i] = g_aligned[--g_aligned_n];
            found = 1;
            break;
        }
    }
    unlock();
    return found;
}
#endif

FS_NOINLINE void failstep_free(void *ptr) {
#if defined(_WIN32)
    if (ptr && aligned_forget(ptr)) {
        _aligned_free(ptr);
        return;
    }
#endif
    free(ptr);
}

FS_NOINLINE char *failstep_strdup(const char *s) {
    if (failstep__decide()) return NULL;
    if (!s) s = "";
    size_t n = strlen(s) + 1;
    char *p = (char *)malloc(n);
    if (p) memcpy(p, s, n);
    return p;
}

FS_NOINLINE char *failstep_strndup(const char *s, size_t n) {
    if (failstep__decide()) return NULL;
    size_t len = 0;
    if (s)
        while (len < n && s[len]) len++;
    char *p = (char *)malloc(len + 1);
    if (!p) return NULL;
    if (len) memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

FS_NOINLINE void *failstep_aligned_alloc(size_t alignment, size_t size) {
    if (failstep__decide()) return NULL;
#if defined(_WIN32)
    /* MSVC's malloc is already 16-byte aligned; use it when that suffices so the
     * block is freeable with the normal free() the override routes to. Larger
     * alignments need _aligned_malloc (and _aligned_free). */
    if (alignment <= 16) return malloc(size);
    void *p = _aligned_malloc(size, alignment);
    aligned_remember(p);
    return p;
#elif defined(__APPLE__)
    void *p = NULL;
    if (alignment < sizeof(void *)) alignment = sizeof(void *);
    if (posix_memalign(&p, alignment, size) != 0) return NULL;
    return p;
#else
    return aligned_alloc(alignment, size);
#endif
}

/* ---- continue-mode harness --------------------------------------------- */

static void arm(void) {
    lock();
    ensure_init_locked();
    g.armed = 1;
    g.counter = 0;
    g.site_fired = 0;
    unlock();
}

static void disarm(void) {
    lock();
    g.armed = 0;
    unlock();
}

int failstep_run_harness(const failstep_harness_t *h) {
    if (!h || !h->step) return 2;

    lock();
    ensure_init_locked();
    int active = (g.mode != MODE_OFF) || g.fuzz_active;
    int steps = g.continue_steps;
    unlock();

    void *ctx = h->setup ? h->setup() : NULL;

    if (!active) {
        /* Direct run (no failstep environment): a single clean pass. */
        int rc = h->step(ctx, 0);
        if (h->teardown) h->teardown(ctx);
        return rc == 0 ? 0 : 1;
    }

    arm();
    int rc = h->step(ctx, 0);
    disarm();

    for (int i = 1; rc == 0 && i <= steps; i++) rc = h->step(ctx, i);

    if (h->teardown) h->teardown(ctx);
    return rc == 0 ? 0 : 1;
}

/* ---- fuzz integration --------------------------------------------------- */

size_t failstep_fuzz_begin(const unsigned char *data, size_t size) {
    lock();
    ensure_init_locked();
    g.fuzz_active = 1;
    g.counter = 0;
    free(g.fuzz_bits);
    g.fuzz_bits = NULL;
    g.fuzz_nbits = 0;

    size_t used = 0;
    if (size > 0) {
        size_t nctl = data[0];
        used = 1;
        if (nctl > size - 1) nctl = size - 1;
        if (nctl > 0) {
            g.fuzz_bits = (unsigned char *)malloc(nctl);
            if (g.fuzz_bits) {
                memcpy(g.fuzz_bits, data + 1, nctl);
                g.fuzz_nbits = nctl * 8;
            }
            used += nctl;
        }
    }
    unlock();
    return used;
}

void failstep_fuzz_end(void) {
    lock();
    free(g.fuzz_bits);
    g.fuzz_bits = NULL;
    g.fuzz_nbits = 0;
    g.fuzz_active = 0;
    g.counter = 0;
    unlock();
}
