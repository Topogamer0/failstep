#!/usr/bin/env bash
#
# Build Ollama-C at a given tag under the failstep override header and
# AddressSanitizer, then run the chat-stream harness through failstep's
# `continue` mode against the fake Ollama server.
#
# Usage:
#   run_demo.sh <tag> [ollama-c-source-dir]
#
# With a source dir, the tag is taken from it with `git archive` (no network);
# otherwise Ollama-C is cloned at the tag. Environment overrides:
#   FAILSTEP_BUILD   failstep build dir (default: <repo>/build)
#   OLLAMA_REPO      git URL to clone when no source dir is given
#   CC               C compiler (default: cc)
#
# SPDX-License-Identifier: MIT
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TAG="${1:?usage: run_demo.sh <tag> [ollama-c-source-dir]}"
SRCDIR="${2:-}"

FAILSTEP_BUILD="${FAILSTEP_BUILD:-$ROOT/build}"
CLI="$FAILSTEP_BUILD/failstep"
LIB="$FAILSTEP_BUILD/libfailstep.a"
INC="$ROOT/include"
OLLAMA_REPO="${OLLAMA_REPO:-https://github.com/Topogamer0/Ollama-C}"
CC="${CC:-cc}"

[ -x "$CLI" ] || { echo "failstep CLI not found at $CLI (build failstep first)"; exit 2; }
[ -f "$LIB" ] || { echo "libfailstep.a not found at $LIB (build failstep first)"; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/src"

echo ">> fetching Ollama-C $TAG"
if [ -n "$SRCDIR" ]; then
    git -C "$SRCDIR" archive "$TAG" | tar -x -C "$WORK/src"
else
    GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --branch "$TAG" "$OLLAMA_REPO" "$WORK/src"
fi
SRC="$WORK/src"

ASAN="-fsanitize=address -g -fno-omit-frame-pointer"
CURL_CFLAGS="$(pkg-config --cflags libcurl)"
CURL_LIBS="$(pkg-config --libs libcurl)"

echo ">> compiling Ollama-C under failstep + ASan"
OBJS=""
for f in "$SRC"/src/*.c; do
    o="$WORK/$(basename "$f").o"
    # -w: do not fail on the target's own warnings; failstep intercepts its allocations.
    $CC $ASAN -w -std=c99 -I"$SRC/include" -I"$SRC/src" -I"$INC" \
        -include failstep/override.h $CURL_CFLAGS -c "$f" -o "$o"
    OBJS="$OBJS $o"
done

echo ">> compiling the harness"
$CC $ASAN -w -std=c99 -I"$SRC/include" -I"$INC" -include failstep/override.h \
    -c "$HERE/ollama_chat_harness.c" -o "$WORK/harness.o"

echo ">> linking"
$CC $ASAN "$WORK/harness.o" $OBJS "$LIB" $CURL_LIBS -ldl -lpthread -o "$WORK/harness"

echo ">> running: failstep continue -- python3 ollama_mock.py harness"
set +e
"$CLI" continue -k 2 -t 20 -o "$WORK/out" -f text -- \
    python3 "$HERE/ollama_mock.py" "$WORK/harness"
rc=$?
set -e
echo ">> failstep exit code: $rc  (0 = clean, 1 = problems found)"
exit $rc
