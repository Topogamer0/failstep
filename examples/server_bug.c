/*
 * Category: use-after-free that only surfaces on a LATER request -- the
 * PHP2Shell pattern (CVE-2026-109618 / CVE-2026-109619).
 *
 * A long-lived worker keeps per-session state in a global, the way a PHP-FPM
 * worker does across requests. When an allocation fails in the middle of one
 * request, the handler frees the old buffer but leaves the global pointer and
 * length behind. The worker keeps serving, and the NEXT request reads the
 * session back out -- through a pointer to freed memory.
 *
 * A one-shot "fail and exit" tester never sees this: the damage is dormant
 * until a subsequent request reuses the corrupted state in the same process.
 * failstep's `continue` mode reproduces exactly that: it fails the allocation
 * during request 0, then serves K more requests in the same process, and
 * AddressSanitizer flags the use-after-free on request 1.
 *
 *   failstep continue -- ./ex_server
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <failstep/failstep.h>

typedef struct {
    char *body;
    size_t len;
} session_t;

static session_t g_session; /* survives across requests, like a PHP worker */

/* Start the worker with a small session already populated. */
static void *setup(void) {
    g_session.body = malloc(32);
    if (g_session.body) {
        memcpy(g_session.body, "welcome", 8);
        g_session.len = 7;
    }
    return NULL;
}

/* Handle one request. Request 0 grows the session; later requests read it. */
static int handle(int request_no) {
    if (request_no == 0) {
        size_t want = g_session.len + 4096;
        char *bigger = realloc(g_session.body, want);
        if (!bigger) {
            /*
             * BUG: realloc failed and left the original block intact, but we
             * free it here and leave g_session.body dangling (and g_session.len
             * unchanged). The worker returns and keeps running.
             */
            free(g_session.body);
            return 0;
        }
        g_session.body = bigger;
    } else {
        /* A later request serves the session back to the client, reading the
         * buffer byte by byte -- a use-after-free when request 0 freed it. */
        if (g_session.body && g_session.len) {
            unsigned long sum = 0;
            for (size_t k = 0; k < g_session.len; k++)
                sum += (unsigned char)g_session.body[k]; /* use-after-free read */
            printf("200 OK: %lu bytes (checksum %lu)\n", (unsigned long)g_session.len, sum);
        }
    }
    return 0;
}

static int step(void *ctx, int i) {
    (void)ctx;
    return handle(i);
}

static void teardown(void *ctx) {
    (void)ctx;
    free(g_session.body);
    g_session.body = NULL;
}

int main(void) {
    failstep_harness_t h = {setup, step, teardown, "toy-server"};
    return failstep_run_harness(&h);
}
