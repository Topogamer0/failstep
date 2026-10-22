/*
 * Category: libFuzzer integration.
 *
 * A tiny parser exercised by libFuzzer, with failstep driving the allocation
 * failures. A prefix of each fuzzer input deterministically decides which
 * allocations fail (failstep_fuzz_begin), so any crash the fuzzer finds is
 * reproducible by re-running the target on the same input file.
 *
 * BUG: the result of strdup() is used without a NULL check, so when failstep
 * fails that allocation the parser dereferences NULL.
 *
 * Build with Clang:
 *   cmake -DFAILSTEP_BUILD_FUZZERS=ON ...     (adds -fsanitize=fuzzer,address)
 * Run:
 *   failstep fuzz -- ./ex_fuzz -runs=200000
 * Reproduce a crash:
 *   ./ex_fuzz crash-<hash>
 *
 * SPDX-License-Identifier: MIT
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <failstep/failstep.h>

static int parse(const uint8_t *data, size_t size) {
    char *copy = malloc(size + 1);
    if (!copy) return -1; /* handled */
    memcpy(copy, data, size);
    copy[size] = '\0';

    char *dup = strdup(copy);
    size_t length = strlen(dup); /* BUG: no NULL check on strdup */

    free(dup);
    free(copy);
    return (int)length;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t used = failstep_fuzz_begin(data, size);
    if (used <= size) parse(data + used, size - used);
    failstep_fuzz_end();
    return 0;
}
