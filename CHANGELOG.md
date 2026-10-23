# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-23

### Changed

- An orderly exit with a non-zero status — no signal, no AddressSanitizer report, no leak, no
  hang — is no longer reported as a problem. It means the program noticed the failed allocation
  and stopped (`if (!p) return 1;`), which is correct behaviour. Such runs are listed as info,
  "exits cleanly with code N when allocation #K fails": in the text report, in a new `info` array
  of the JSON report, and as notes on the SARIF invocation (not as results, so they raise no
  code-scanning alert). They do not affect failstep's exit status. In 0.1.0 they were reported as
  `abnormal-exit` problems.
- Crashes by signal, AddressSanitizer errors, leaks and hangs remain problems whatever the options.
- An `abnormal-exit` problem now says how the process ended — `killed by signal 6 (SIGABRT)`, or
  `exited with status 3, unexpected under --ok-exit 1` — instead of `exit=N signal=N`.
- JSON report: new top-level `version`, `clean_exits` and `info`; each result carries `exit_code`
  and `signal`.

### Added

- `--ok-exit LIST` (for example `--ok-exit 1,2`): the exit statuses the target uses to report
  out-of-memory. An orderly exit with any other non-zero status is reported as `abnormal-exit`.
- `--strict-exit`: report every orderly non-zero exit not listed in `--ok-exit` (with no list,
  every one, as 0.1.0 did).
- `examples/exit_on_oom.c`: exits with `EXIT_FAILURE` when memory runs out, and must give zero
  problems. Tests cover the default, `--ok-exit` (expected and unexpected status) and
  `--strict-exit`, and check that a crash by signal stays a problem whatever statuses are
  declared expected.
- `FAILSTEP_VERSION_STRING` in `<failstep/failstep.h>`. The version is now defined once (the
  header) and the unit test checks that the runtime, the header and the CMake project agree.

### Fixed

- Windows: a crash ends the process with an NTSTATUS exception code (`0xC0000005`, `0xC0000409`,
  ...) rather than a signal. It is classified as a crash, never as an orderly exit.
- The fake Ollama server of the Ollama-C demo (`examples/ollama/ollama_mock.py`) re-raises the
  harness's termination signal instead of turning it into an exit status, so a crash cannot pass
  for an orderly exit.

## [0.1.0] - 2026-10-22

First release: a C99 runtime and the `failstep` CLI. Allocation interception that keeps
AddressSanitizer as the real allocator (force-included override header, Linux `--wrap`, or the
`failstep_should_fail()` hook); the `enumerate`, `sites`, `continue` and `fuzz` modes; parallel,
resumable runs with timeouts; problems grouped by failed site and error stack, with text, JSON and
SARIF output and CI exit codes; examples, CTest suite, CMake and pkg-config packages; CI on Linux,
macOS and Windows (MSVC `/fsanitize=address`).

[0.1.1]: https://github.com/Topogamer0/failstep/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Topogamer0/failstep/releases/tag/v0.1.0
