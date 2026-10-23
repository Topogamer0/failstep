# failstep

**Systematic allocation-failure testing for C — compatible with AddressSanitizer.**

`failstep` makes a program's allocations fail, one at a time and on purpose, and
reports what breaks. It drives `malloc`, `calloc`, `realloc`, `strdup`,
`strndup` and `aligned_alloc` to return `NULL` at chosen points, runs your code
under AddressSanitizer, and groups the resulting crashes, leaks, hangs and
use-after-frees by root cause, each with an exact command to reproduce it.

It is a defensive tool for developers: a way to exercise the error paths that
tests almost never reach, before an attacker does.

- Zero source changes for the common case (a force-included header), or a
  one-line hook for projects with their own allocator.
- Keeps AddressSanitizer as the real allocator — no `LD_PRELOAD`.
- Finds the bug class where a failed allocation leaves dangling or half-updated
  state that a *later* operation trips over (see below).
- Linux, macOS and Windows (MSVC `/fsanitize=address`).

---

## The problem

Allocation-failure paths are the least-tested code in most C programs. They run
only when memory runs out, so they rarely see a debugger — yet they are reached
in production under memory pressure, with `RLIMIT_AS`/`RLIMIT_DATA` limits, or
when an attacker can steer allocation sizes. A single unchecked `malloc`, or a
cleanup path that frees the wrong thing, turns "out of memory" into a crash, an
information leak, or remote code execution.

The sharpest recent example is **PHP2Shell** (CVE-2026-109618 /
CVE-2026-109619, disclosed October 2026): an allocation that fails in the middle
of handling one request leaves PHP's request-owned state pointing at memory that
is then freed. The worker keeps running, and a *later* request on the same
process consumes that stale state — a use-after-free that leads to remote code
execution. Rated CVSS 9.2, reachable in default configurations.

This is exactly the class of bug that a "fail an allocation and watch it crash"
tester cannot see: nothing crashes in the request that failed. The damage is
dormant until a subsequent request reuses the corrupted long-lived state. Catching
it requires keeping the process alive across the failure and then exercising it
again — which is what failstep's `continue` mode does.

## How it compares

failstep is not the first allocation-failure injector, and it borrows good ideas
from the ones before it. Here is an honest comparison.

| | interception | ASan-compatible | stateful "next request" bug | fuzzer-driven | platforms |
|---|---|---|---|---|---|
| **mallocfail** | `LD_PRELOAD` | no (fights ASan for `malloc`) | no | no | Linux |
| **FAINT** | `LD_PRELOAD` | no | no | no | Linux |
| **libfailinj** | `LD_PRELOAD` | no | no | no | Linux |
| **libfiu** | `LD_PRELOAD` / API | no | no | no | Linux/Unix |
| **failstep** | force-include header, `--wrap`, or a 1-line hook | **yes** | **yes (`continue` mode)** | **yes (libFuzzer)** | Linux, macOS, Windows |

What the earlier tools do well, and where failstep differs:

- **mallocfail** hashes the call stack and fails each distinct allocation site
  once — failstep's `sites` mode is the same idea. **FAINT** profiles first and
  then fails one allocation per run — that is failstep's `enumerate` mode.
  failstep keeps both.
- All of them interpose the C library with `LD_PRELOAD`. AddressSanitizer *also*
  interposes `malloc`; a second `LD_PRELOAD` allocator fights it, so in practice
  you cannot combine those tools with ASan — and ASan is what actually proves a
  dangling pointer is a use-after-free rather than a lucky non-crash. failstep
  instead sits *in front of* the real allocator (via a header or the linker's
  `--wrap`), so ASan stays underneath and remains the allocator of record.
- None of them keep the process running past the failure to surface corruption
  that a later operation reads. failstep's `continue` mode is built for servers,
  interpreters and long-lived libraries — the PHP2Shell shape.
- **libfiu** is broader than failstep (it injects faults across the whole POSIX
  API, not just allocation). If you need `open`/`read`/`close` fault injection,
  reach for libfiu. If you need allocation failures that compose with ASan and
  catch latent, cross-request corruption, reach for failstep.

## Quick start

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build                     # builds libfailstep and the `failstep` CLI
cc -g -fsanitize=address \
   -Iinclude -include failstep/override.h \   # route this file's allocations through failstep
   myprog.c build/libfailstep.a -ldl -lpthread -o myprog
build/failstep enumerate -- ./myprog    # fail allocation 1, then 2, ... one per run
```

Exit code is `0` when every injected failure was handled cleanly, `1` when
problems were found. That is all you need in CI.

## The four modes

```
failstep <mode> [options] -- <target> [args...]
```

1. **`enumerate`** — run the target failing the 1st allocation, then the 2nd,
   and so on, one failure per run. The most thorough; one run per allocation.
2. **`sites`** — fail each *distinct* allocation site (by call stack) once. Far
   faster than `enumerate` on large programs, with nearly the same coverage.
3. **`continue`** — the important one. Your target provides `setup`/`step`/
   `teardown` via `failstep_run_harness()`. failstep runs one `step` with a
   failure injected, then runs *K more normal steps in the same process*, then
   `teardown`. AddressSanitizer catches the use-after-frees and corruption that
   only a later step triggers; LeakSanitizer catches the leaks. This is the mode
   that finds the PHP2Shell class.
4. **`fuzz`** — integrate with libFuzzer. A prefix of each fuzzer input
   deterministically decides which allocations fail, so a crash the fuzzer finds
   is reproducible by re-running the target on the same input.

Useful options: `-j N` (parallel workers), `-t SEC` (per-run timeout), `-k N`
(`continue` follow-up steps), `-f text|json|sarif`, `-o DIR` (work dir; runs are
resumable — re-run with `-r` after an interruption), `--out FILE`, and
`--ok-exit LIST` / `--strict-exit` (see [Orderly exits](#orderly-exits-are-not-problems)).

### Projects with their own allocator

If your code allocates through its own function (an arena, a pool, PHP's
`emalloc`), wire it to failstep in one line — no header needed:

```c
#include <failstep/failstep.h>

void *emalloc(size_t n) {
    if (failstep_should_fail()) return NULL;   // driven by every mode
    return real_emalloc(n);
}
```

`failstep_should_fail()` identifies the call site from the stack, counts the
allocation, and applies whatever mode the CLI selected.

### Code you cannot recompile (Linux)

Use the linker's `--wrap` instead of the header:

```sh
cc obj.o build/libfailstep.a \
   -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free \
   -Wl,--wrap=strdup,--wrap=strndup,--wrap=aligned_alloc -ldl -lpthread
```

## Reading a report

The bundled toy server (`examples/server_bug.c`) reproduces the PHP2Shell shape:
a worker keeps a session in a global; when a `realloc` fails mid-request it frees
the old buffer but leaves the global pointing at it, and the next request reads
it back.

```
$ failstep continue -- ./ex_server

[1] ASan error  (1 occurrence)
    error type: heap-use-after-free
    injected failure: allocation #1 at examples/server_bug.c:48
        handle                   examples/server_bug.c:48      <- the realloc that failed
        step                     examples/server_bug.c:75
        main                     examples/server_bug.c:86
    error stack:
        handle                   examples/server_bug.c:65      <- the later request that read freed memory
        step                     examples/server_bug.c:74
        main                     examples/server_bug.c:85
    reproduce:
        FAILSTEP_MODE=index FAILSTEP_SCOPED=1 FAILSTEP_FAIL_INDEX=1 FAILSTEP_CONTINUE_STEPS=2 ./ex_server
```

Each problem shows **where the failed allocation was** (file:line and stack),
**the kind of error** AddressSanitizer reported, **where the error happened**,
and **the exact command to reproduce it**. Identical problems — same failed site
and same error stack — are grouped, with an occurrence count.

failstep distinguishes these problem types:

- **`asan-error`** — memory corruption (use-after-free, buffer overflow,
  double-free, …) reported by AddressSanitizer.
- **`leak`** — memory leaked on the failure path (LeakSanitizer).
- **`null-deref`** — the program dereferenced the `NULL` the failed allocation
  returned (a missing NULL check).
- **`hang`** — the run exceeded the timeout (e.g. an infinite retry loop).
- **`abnormal-exit`** — the process was killed by a signal without an ASan
  report (e.g. `abort()` or `assert(ptr)` on out-of-memory — a self-inflicted
  denial of service); or, with `--ok-exit`/`--strict-exit`, it exited with a
  status you did not declare as expected. The report says which:
  `killed by signal 6 (SIGABRT)` or `exited with status 3, unexpected under --ok-exit 1`.

Crashes by signal, ASan errors, leaks and hangs are always problems, whatever
the options.

### Orderly exits are not problems

A program that notices the failed allocation, cleans up and stops with an error
status — `if (!p) return 1;` — is handling out-of-memory correctly. When a run
ends that way (a non-zero status, but no signal, no ASan report, no leak, no
hang), failstep does not report a problem; it lists the run as info:

```
$ failstep enumerate -- ./ex_exit_on_oom
failstep: mode=enumerate  runs=2  failing=0  problems=0  clean-exits=2

No problems found: every injected allocation failure was handled cleanly.

Info (not problems): orderly exits with an expected status
  - exits cleanly with code 1 when allocation #1 or #2 fails (2 runs)
```

In JSON these runs appear in the `info` array (and `clean_exits`); in SARIF as
notes on the invocation rather than results, so they raise no code-scanning
alert. They never change failstep's exit status.

To be stricter:

- **`--ok-exit LIST`** — the statuses your program uses to report
  out-of-memory, e.g. `--ok-exit 1,2`. An orderly exit with any *other* non-zero
  status is then reported as `abnormal-exit`: it usually means the failure
  escaped into some other error path.
- **`--strict-exit`** — report every orderly non-zero exit not listed in
  `--ok-exit` (with no list, every one — the behaviour of failstep 0.1.0).

| options | orderly exit with status N ≠ 0 |
|---|---|
| none | info |
| `--ok-exit 1,2` | info if N is 1 or 2, otherwise `abnormal-exit` |
| `--strict-exit` | `abnormal-exit` |
| `--strict-exit --ok-exit 1` | info if N is 1, otherwise `abnormal-exit` |

## CI integration

Run failstep in CI and fail the job when it finds anything:

```yaml
- run: cmake --build build
- run: build/failstep sites -f sarif --out failstep.sarif -- ./myprog
# exit code 1 fails the step; upload failstep.sarif to code scanning if you like
```

- **Exit codes**: `0` clean, `1` problems found, `2` usage/internal error.
- **Output**: `text` (default), `json` (machine-readable), `sarif` (SARIF 2.1.0
  for GitHub code scanning and other dashboards).
- **Resumable**: `-o DIR -r` reuses completed runs, so a long `enumerate` sweep
  survives a cancelled job.

## A real-world case: Ollama-C

[Ollama-C](https://github.com/Topogamer0/Ollama-C) v0.1.0 had a use-after-free in
`ollama_stream_message()`: when a chat part made the assembled content buffer
grow and a *later* append in the same part ran out of memory, the assembled
message was left pointing at the freed old buffer. It was fixed in v0.2.0.

`examples/ollama/` contains a harness that opens a streaming chat against a fake
Ollama server (`ollama_mock.py`, modelled on Ollama-C's own test server) and then
reads the assembled message back — the "later request" that trips the bug. Run it
with `continue` mode:

```sh
examples/ollama/run_demo.sh v0.1.0    # clones/builds Ollama-C at the tag under failstep
examples/ollama/run_demo.sh v0.2.0
```

Results:

- **Ollama-C v0.1.0** — failstep reports **1 problem: a heap-use-after-free**.
  The injected failure is allocation #74 inside `buf_reserve` (`src/util.c:38`),
  reached from `accumulate` while assembling a chat stream; the error is the
  later read of `ollama_stream_message()`'s content, which points at freed
  memory. This is precisely the bug the v0.2.0 changelog describes.
- **Ollama-C v0.2.0** — **clean**: 102 allocations across 48 distinct sites, every
  injected failure handled correctly.
- **[ollama-c-rag](https://github.com/Topogamer0/ollama-c-rag)** (indexing and
  searching a document through the library) — **clean** in both `sites` and
  `enumerate` mode: 49 allocations across 43 sites, no problems. (failstep was
  scoped to the project's own code; bundled SQLite and Ollama-C were left as the
  trusted allocator underneath, still watched by ASan.)

## Installation

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --install build          # installs the CLI, libfailstep, headers, CMake and pkg-config files
```

From CMake:

```cmake
find_package(failstep REQUIRED)
add_executable(mytests mytests.c)
failstep_instrument(mytests)        # adds the override header, ASan, and links the runtime
```

Or with pkg-config (remember the override header and AddressSanitizer, exactly as
in the Quick Start — without them the target allocates normally and failstep has
nothing to drive):

```sh
cc -fsanitize=address -include failstep/override.h \
   $(pkg-config --cflags failstep) myprog.c $(pkg-config --libs failstep) -o myprog
```

Prebuilt CLI binaries for Linux, macOS and Windows are attached to each release.

## Limitations

- **Symbolization of the injected stack** uses `addr2line` (Linux) when present;
  build the target with `-g`. On macOS and Windows the injected frames fall back
  to the symbol name without a file:line (the AddressSanitizer error stack is
  always fully symbolized). LeakSanitizer is Linux-only, so the `leak` type is
  reported there.
- failstep intercepts the C allocation functions and `failstep_should_fail()`
  call sites. It does not see allocations made by code compiled without the
  header and not routed through `--wrap` or the hook (by design — that is how you
  scope it to your own code and leave third-party libraries as the trusted
  allocator).
- `continue` mode requires the target to use `failstep_run_harness()`; it is an
  API, not a drop-in. The other modes need no code changes.
- Making one allocation fail is a model of memory pressure, not a proof of its
  absence: failstep exercises the failure of each site independently, not every
  combination of simultaneous failures.
- failstep tells a crash from an orderly exit by how the target process ended.
  If the target is a **wrapper script**, make it propagate the real program's
  termination signal: a shell reports a child killed by signal N as status
  128+N (139 for SIGSEGV), which would otherwise look like an orderly exit. ASan
  reports are still caught through the captured output; the info line flags
  statuses in the 128+N range. `examples/ollama/ollama_mock.py` shows how to
  re-raise the child's signal.
- On **Windows** there are no signals: crashes (access violations, fast-fail)
  end the process with an NTSTATUS exception code and are always reported. But
  depending on the CRT's abort behaviour, `abort()` can instead end it with
  status 3, indistinguishable from `exit(3)`; declare your real out-of-memory
  status with `--ok-exit` so that such a 3 is reported.

## License

MIT. See [LICENSE](LICENSE). Code, comments and documentation are in English.
