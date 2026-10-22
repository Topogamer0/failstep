/*
 * failstep harness for Ollama-C -- reproduces the real use-after-free in
 * ollama_stream_message() that Ollama-C v0.1.0 had and v0.2.0 fixed.
 *
 * The bug (from the v0.2.0 changelog): "when a part made the assembled content
 * grow and a later append ran out of memory, ollama_stream_message() pointed to
 * freed memory." In v0.1.0's accumulate(), growing the content buffer frees the
 * old block, but the assembled message is only re-pointed at the new block on
 * the success path; if a later allocation in the same part fails, the message
 * is left pointing at the freed block.
 *
 * This harness, under failstep's `continue` mode, opens a streaming chat and
 * drains it (step 0, where the failure is injected), then reads the assembled
 * message back (step 1, a later "request" on the same connection/worker). On
 * v0.1.0 that read is a use-after-free, which AddressSanitizer flags; on v0.2.0
 * the message points at live memory and nothing is reported.
 *
 * The companion ollama_mock.py serves a chat stream shaped to trigger the bug:
 * a first part that allocates the content buffer, then a second part whose
 * content forces the buffer to grow (freeing the old block) and which also
 * carries a `thinking` fragment -- the append failstep fails.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>

#include <failstep/failstep.h>
#include <ollama.h>

typedef struct {
    ollama_client_t *client;
    ollama_stream_t *stream;
} ctx_t;

static void *setup(void) {
    ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->client = ollama_client_new(NULL); /* reads OLLAMA_HOST, set by the mock */
    return c;
}

/* step 0: open and drain the stream (the failure is injected here).
 * step >=1: read the assembled message -- the later "request" that trips the
 * use-after-free on v0.1.0. */
static int step(void *vctx, int i) {
    ctx_t *c = (ctx_t *)vctx;
    if (!c || !c->client) return 0;

    if (i == 0) {
        ollama_message_t msg = {0};
        msg.role = "user";
        msg.content = "hello";
        ollama_chat_request_t req = {0};
        req.model = "demo";
        req.messages = &msg;
        req.messages_count = 1;
        req.think = "true";

        if (ollama_chat_stream(c->client, &req, &c->stream) != OLLAMA_OK) return 0;
        const ollama_chat_response_t *part;
        while ((part = ollama_stream_next_chat(c->stream)) != NULL) {
            /* draining; accumulate() runs per part inside the library */
        }
    } else {
        /* Read the assembled message back, as a later request would. */
        const ollama_message_t *m = c->stream ? ollama_stream_message(c->stream) : NULL;
        if (m && m->content) {
            unsigned long acc = 0;
            for (int k = 0; k < 16 && m->content[k]; k++) /* reads freed memory on v0.1.0 */
                acc += (unsigned char)m->content[k];
            if (acc == 0x1234567ul) puts("unreachable");
        }
    }
    return 0;
}

static void teardown(void *vctx) {
    ctx_t *c = (ctx_t *)vctx;
    if (!c) return;
    ollama_stream_free(c->stream);
    ollama_client_free(c->client);
    free(c);
}

int main(void) {
    failstep_harness_t h = {setup, step, teardown, "ollama-chat-stream"};
    return failstep_run_harness(&h);
}
