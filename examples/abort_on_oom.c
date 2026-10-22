/*
 * Category: abnormal exit.
 *
 * BUG: the program aborts the whole process when an allocation fails. Turning a
 * recoverable out-of-memory condition into a crash is a denial of service.
 * failstep reports this as "abnormal-exit" (killed by SIGABRT).
 *
 * (A real program might write this as assert(p), but assert is compiled out
 * under NDEBUG; abort() shows the category regardless of build type.)
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(256);
    if (!p) abort(); /* BUG: aborts on out-of-memory */
    memset(p, 0, 256);
    free(p);
    return 0;
}
