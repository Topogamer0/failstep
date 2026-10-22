/*
 * failstep runtime -- call-stack capture, stable hashing and symbol lookup.
 *
 * The hash is computed from each frame's module name and its offset within that
 * module, never the absolute (ASLR-randomised) address, so the same source
 * location yields the same site across separate runs of the same binary.
 *
 * SPDX-License-Identifier: MIT
 */
#if defined(__linux__) || defined(__APPLE__)
#  define _GNU_SOURCE 1
#endif

#include "runtime_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---- FNV-1a ------------------------------------------------------------- */

static unsigned long long fnv1a(unsigned long long h, const void *data, size_t n) {
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static const char *base_name(const char *path) {
    if (!path) return "";
    const char *b = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/' || *p == '\\') b = p + 1;
    }
    return b;
}

failstep_site_t failstep_hash_frames(const failstep_frame_t *frames, int n) {
    unsigned long long h = 1469598103934665603ULL;
    for (int i = 0; i < n; i++) {
        const char *mod = base_name(frames[i].module);
        h = fnv1a(h, mod, strlen(mod));
        unsigned long long off = frames[i].off;
        h = fnv1a(h, &off, sizeof(off));
    }
    /* Never return 0: the CLI uses 0 as "no site". */
    return h ? h : 1;
}

/* dladdr strings live for the lifetime of the process, so a shallow copy of the
 * frame array is safe to keep in the registry and to read at exit. */
failstep_frame_t *failstep_frames_dup(const failstep_frame_t *frames, int n) {
    if (n <= 0) return NULL;
    failstep_frame_t *out = (failstep_frame_t *)malloc((size_t)n * sizeof(*out));
    if (!out) return NULL;
    memcpy(out, frames, (size_t)n * sizeof(*out));
    return out;
}

void failstep_frames_free(failstep_frame_t *frames, int n) {
    (void)n;
    free(frames);
}

/*
 * Internal-frame detection by address window. The runtime registers the entry
 * of each of its own small functions; a captured return address lands inside
 * one of them exactly when the frame belongs to the runtime. These frames sit
 * contiguously at the top of the stack, so trimming them is robust against
 * inlining and against the extra frame some sanitizer builds introduce -- where
 * a fixed skip count would drift -- and it needs neither symbols nor module
 * names, so it works for static and shared linkage alike.
 */
#define FS_INTERNAL_WINDOW 0x1000u
#define FS_INTERNAL_MAX 32
static uintptr_t g_internal[FS_INTERNAL_MAX];
static int g_ninternal;

void failstep_mark_internal(uintptr_t fn) {
    if (!fn) return;
    for (int i = 0; i < g_ninternal; i++)
        if (g_internal[i] == fn) return;
    if (g_ninternal < FS_INTERNAL_MAX) g_internal[g_ninternal++] = fn;
}

static int frame_is_internal(const failstep_frame_t *f) {
    uintptr_t a = (uintptr_t)f->addr;
    for (int i = 0; i < g_ninternal; i++) {
        if (a >= g_internal[i] && (a - g_internal[i]) < FS_INTERNAL_WINDOW) return 1;
    }
    /* Secondary cue for shared-library builds. */
    const char *b = base_name(f->module);
    if (b[0] && strstr(b, "failstep")) return 1;
    return 0;
}

/* A sanitizer runtime interposes backtrace(), so its own frame sits at the very
 * top, above failstep's. Recognise it by module (shared runtime) or symbol so
 * it can be trimmed along with the failstep frames. */
static int frame_is_sanitizer(const failstep_frame_t *f) {
    const char *b = base_name(f->module);
    if (b[0] && (strstr(b, "libasan") || strstr(b, "libclang_rt") || strstr(b, "clang_rt") ||
                 strstr(b, "libtsan") || strstr(b, "libubsan") || strstr(b, "libhwasan")))
        return 1;
    if (f->symbol &&
        (strncmp(f->symbol, "__asan", 6) == 0 || strncmp(f->symbol, "__interceptor", 13) == 0 ||
         strncmp(f->symbol, "__sanitizer", 11) == 0))
        return 1;
    return 0;
}

static int frame_skippable(const failstep_frame_t *f) {
    return frame_is_internal(f) || frame_is_sanitizer(f);
}

/* =======================================================================
 * POSIX implementation (Linux, macOS): execinfo + dladdr.
 * ===================================================================== */
#if defined(__linux__) || defined(__APPLE__)

#include <dlfcn.h>
#include <execinfo.h>

int failstep_capture(failstep_frame_t *frames, int max, int skip) {
    void *raw[FAILSTEP_MAX_FRAMES];
    int got = backtrace(raw, FAILSTEP_MAX_FRAMES);
    if (got <= 0) return 0;

    failstep_frame_t tmp[FAILSTEP_MAX_FRAMES];
    for (int i = 0; i < got; i++) {
        Dl_info info;
        tmp[i].addr = raw[i];
        tmp[i].off = (unsigned long long)(uintptr_t)raw[i];
        tmp[i].module = NULL;
        tmp[i].symbol = NULL;
        if (dladdr(raw[i], &info)) {
            tmp[i].module = info.dli_fname;
            tmp[i].symbol = info.dli_sname;
            if (info.dli_fbase)
                tmp[i].off = (unsigned long long)((uintptr_t)raw[i] - (uintptr_t)info.dli_fbase);
        }
    }

    /* Trim the contiguous block of runtime + sanitizer frames at the top (the
     * sanitizer's backtrace interceptor, failstep_capture, failstep__decide and
     * the interceptor), leaving the user's allocation call as the first frame.
     * `skip` drops additional *user* frames (only failstep_site uses it). */
    int start = 0;
    while (start < got && frame_skippable(&tmp[start])) start++;
    start += skip;
    if (start > got) start = got;

    int n = 0;
    for (int i = start; i < got && n < max; i++) frames[n++] = tmp[i];
    return n;
}

#elif defined(_WIN32)

/* =======================================================================
 * Windows implementation: RtlCaptureStackBackTrace + module lookup.
 * Symbols are left to the CLI (which runs on the .pdb); the hash only needs a
 * stable module + offset, which GetModuleHandleEx provides without dbghelp.
 * ===================================================================== */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

int failstep_capture(failstep_frame_t *frames, int max, int skip) {
    void *raw[FAILSTEP_MAX_FRAMES];
    USHORT got = RtlCaptureStackBackTrace(0, (ULONG)FAILSTEP_MAX_FRAMES, raw, NULL);
    if (got == 0) return 0;
    static char modbuf[FAILSTEP_MAX_FRAMES][MAX_PATH];

    failstep_frame_t tmp[FAILSTEP_MAX_FRAMES];
    for (USHORT i = 0; i < got; i++) {
        tmp[i].addr = raw[i];
        tmp[i].off = (unsigned long long)(uintptr_t)raw[i];
        tmp[i].module = NULL;
        tmp[i].symbol = NULL;
        HMODULE mod = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCSTR)raw[i], &mod) &&
            mod) {
            if (GetModuleFileNameA(mod, modbuf[i], MAX_PATH)) tmp[i].module = modbuf[i];
            tmp[i].off = (unsigned long long)((uintptr_t)raw[i] - (uintptr_t)mod);
        }
    }

    int start = 0;
    while (start < (int)got && frame_skippable(&tmp[start])) start++;
    start += skip;
    if (start > (int)got) start = (int)got;

    int n = 0;
    for (int i = start; i < (int)got && n < max; i++) frames[n++] = tmp[i];
    return n;
}

#else

int failstep_capture(failstep_frame_t *frames, int max, int skip) {
    (void)frames;
    (void)max;
    (void)skip;
    return 0;
}

#endif
