/*
 * Fixed version of server_bug.c.
 *
 * On realloc failure the handler keeps the original, still-valid buffer (which
 * realloc left untouched) instead of freeing it and stranding a dangling
 * pointer in the global session. Later requests read valid memory, and
 * failstep's `continue` mode reports no problem.
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

static session_t g_session;

static void *setup(void) {
    g_session.body = malloc(32);
    if (g_session.body) {
        memcpy(g_session.body, "welcome", 8);
        g_session.len = 7;
    }
    return NULL;
}

static int handle(int request_no) {
    if (request_no == 0) {
        size_t want = g_session.len + 4096;
        char *bigger = realloc(g_session.body, want);
        if (!bigger) {
            /* FIX: realloc left the old block intact; keep serving with it. */
            return 0;
        }
        g_session.body = bigger;
    } else {
        if (g_session.body && g_session.len) {
            unsigned long sum = 0;
            for (size_t k = 0; k < g_session.len; k++)
                sum += (unsigned char)g_session.body[k];
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
