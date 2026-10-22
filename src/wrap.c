/*
 * failstep runtime -- linker --wrap interceptors (Linux/GNU ld, lld).
 *
 * For code that cannot be recompiled with <failstep/override.h>, GNU ld and lld
 * can divert the allocation symbols at link time:
 *
 *   cc obj.o -lfailstep \
 *      -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free \
 *      -Wl,--wrap=strdup,--wrap=strndup,--wrap=aligned_alloc
 *
 * Each __wrap_X consults the same oracle as the header interceptors and then
 * calls __real_X, so AddressSanitizer stays the underlying allocator.
 *
 * SPDX-License-Identifier: MIT
 */
#if !defined(_WIN32)

#include "runtime_internal.h"

#include <stdlib.h>
#include <string.h>

#define FS_NOINLINE __attribute__((noinline))

extern void *__real_malloc(size_t size);
extern void *__real_calloc(size_t nmemb, size_t size);
extern void *__real_realloc(void *ptr, size_t size);
extern void __real_free(void *ptr);
extern char *__real_strdup(const char *s);
extern char *__real_strndup(const char *s, size_t n);
extern void *__real_aligned_alloc(size_t alignment, size_t size);

FS_NOINLINE void *__wrap_malloc(size_t size) {
    if (failstep__decide()) return NULL;
    return __real_malloc(size);
}

FS_NOINLINE void *__wrap_calloc(size_t nmemb, size_t size) {
    if (failstep__decide()) return NULL;
    return __real_calloc(nmemb, size);
}

FS_NOINLINE void *__wrap_realloc(void *ptr, size_t size) {
    /* Standard behaviour: a failed realloc leaves the original block intact. */
    if (failstep__decide()) return NULL;
    return __real_realloc(ptr, size);
}

FS_NOINLINE void __wrap_free(void *ptr) {
    __real_free(ptr);
}

FS_NOINLINE char *__wrap_strdup(const char *s) {
    if (failstep__decide()) return NULL;
    return __real_strdup(s);
}

FS_NOINLINE char *__wrap_strndup(const char *s, size_t n) {
    if (failstep__decide()) return NULL;
    return __real_strndup(s, n);
}

FS_NOINLINE void *__wrap_aligned_alloc(size_t alignment, size_t size) {
    if (failstep__decide()) return NULL;
    return __real_aligned_alloc(alignment, size);
}

#endif /* !_WIN32 */
