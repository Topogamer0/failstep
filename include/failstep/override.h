/*
 * failstep -- allocation override header.
 *
 * Force-include this header into the code under test so that its calls to the
 * C allocation functions are routed through the failstep runtime, which decides
 * whether to fail them and otherwise calls the real function:
 *
 *     cc -include failstep/override.h ...        (GCC/Clang)
 *     cl /FI failstep/override.h ...             (MSVC)
 *
 * Because the real allocator is still called underneath, AddressSanitizer (or
 * any other allocator) stays in charge of the actual memory -- failstep only
 * sits in front of it. No LD_PRELOAD, no relinking of libc.
 *
 * The runtime itself must NOT see these macros; it defines FAILSTEP_NO_OVERRIDE
 * before including anything. A translation unit that is force-included with this
 * header but needs the real functions must opt out on the command line
 * (-DFAILSTEP_NO_OVERRIDE / /DFAILSTEP_NO_OVERRIDE), because a `#define` inside
 * the source runs after the force-include has already taken effect.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef FAILSTEP_OVERRIDE_H
#define FAILSTEP_OVERRIDE_H

#include <failstep/failstep.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The interceptors, defined in the runtime. They forward to the real C library
 * function unless the current mode decides this call should fail. */
FAILSTEP_API void *failstep_malloc(size_t size);
FAILSTEP_API void *failstep_calloc(size_t nmemb, size_t size);
FAILSTEP_API void *failstep_realloc(void *ptr, size_t size);
FAILSTEP_API void failstep_free(void *ptr);
FAILSTEP_API char *failstep_strdup(const char *s);
FAILSTEP_API char *failstep_strndup(const char *s, size_t n);
FAILSTEP_API void *failstep_aligned_alloc(size_t alignment, size_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifndef FAILSTEP_NO_OVERRIDE

/*
 * The redirections are *object-like* macros that rename the identifier, not
 * function-like macros. This matters: a system header declaration such as
 *     extern void *malloc(size_t) __THROW __attribute_malloc__;
 * then becomes a compatible redeclaration of failstep_malloc (a function-like
 * macro would instead turn it into `failstep_malloc((size_t))`, which is a
 * syntax error). Pulling in <stdlib.h>/<string.h> after this header is
 * therefore harmless, and `&malloc`, assignment to a function pointer, etc.
 * keep working. The trade-off is that an identifier named `malloc`/`free`/...
 * anywhere -- including a struct member or local variable -- is also renamed;
 * such code can `#undef` the specific name, or define FAILSTEP_KEEP_FREE below.
 */
#define malloc failstep_malloc
#define calloc failstep_calloc
#define realloc failstep_realloc
#define strdup failstep_strdup
#define strndup failstep_strndup
#define aligned_alloc failstep_aligned_alloc

/* free() is redirected too, so the runtime observes every release; it forwards
 * straight to the real free(). Define FAILSTEP_KEEP_FREE to leave free() alone
 * (for rare code that names a field or variable `free`). */
#ifndef FAILSTEP_KEEP_FREE
#define free failstep_free
#endif

#endif /* FAILSTEP_NO_OVERRIDE */

#endif /* FAILSTEP_OVERRIDE_H */
