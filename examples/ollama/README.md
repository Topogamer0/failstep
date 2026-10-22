# Ollama-C use-after-free demo

This directory reproduces a real, fixed bug with failstep.

[Ollama-C](https://github.com/Topogamer0/Ollama-C) v0.1.0 had a use-after-free in
`ollama_stream_message()`. From the v0.2.0 changelog:

> Chat streams: when a part made the assembled content grow and a later append
> ran out of memory, `ollama_stream_message()` pointed to freed memory.

In v0.1.0's `accumulate()`, appending a chat part can grow the assembled-content
buffer — freeing the old block — but the assembled message is only re-pointed at
the new block on the success path. If a *later* allocation in the same part
fails, the message is left pointing at the freed old block, and any later read of
it is a use-after-free.

## Files

- `ollama_chat_harness.c` — a `failstep_run_harness()` target. Step 0 opens a
  streaming chat and drains it (where the failure is injected); step 1 reads the
  assembled message back, as a later request would.
- `ollama_mock.py` — a fake Ollama server (modelled on Ollama-C's own
  `tests/mock_server.py`) that serves a chat stream shaped to trigger the bug: a
  first part that allocates the content buffer, then a second part whose content
  forces the buffer to grow and which also carries a `thinking` fragment — the
  append failstep makes fail.
- `run_demo.sh` — builds Ollama-C at a given tag under the failstep override
  header and AddressSanitizer, builds the harness, and runs `failstep continue`.

## Running

Build failstep first (`cmake --build build` at the repo root), then:

```sh
examples/ollama/run_demo.sh v0.1.0          # clones Ollama-C at the tag
examples/ollama/run_demo.sh v0.2.0

# or point it at a local checkout to avoid cloning:
examples/ollama/run_demo.sh v0.1.0 /path/to/Ollama-C
```

## Expected result

- **v0.1.0** — one `heap-use-after-free`. The injected failure is an allocation
  inside `buf_reserve` (`src/util.c`), reached from `accumulate` while assembling
  the stream; the error is the later read of `ollama_stream_message()`'s content,
  which points at freed memory.
- **v0.2.0** — clean: every injected allocation failure is handled correctly.
