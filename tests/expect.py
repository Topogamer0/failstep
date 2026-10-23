#!/usr/bin/env python3
"""
Run the failstep CLI against a target and assert the outcome.

Used by CTest to check that each buggy example is reported (with the expected
problem type) and each fixed example comes back clean.
"""
import argparse
import json
import subprocess
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--failstep", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--outdir", required=True)
    ap.add_argument("--expect", required=True, choices=["problem", "clean"])
    ap.add_argument("--type", default=None)
    ap.add_argument("--steps", default=None)
    ap.add_argument("--timeout", default="15")
    ap.add_argument("--arg", action="append", default=[],
                    help="extra failstep option (repeatable), e.g. --arg=--strict-exit")
    ap.add_argument("--info-exit", type=int, default=None,
                    help="require an info entry for an orderly exit with this status")
    ap.add_argument("--info-runs", type=int, default=None,
                    help="with --info-exit: the number of runs that entry must cover")
    ap.add_argument("rest", nargs=argparse.REMAINDER)
    a = ap.parse_args()

    target = a.rest
    if target and target[0] == "--":
        target = target[1:]
    if not target:
        print("expect.py: no target given", file=sys.stderr)
        return 2

    cmd = [a.failstep, a.mode, "-f", "json", "-o", a.outdir, "-t", a.timeout, "-q"]
    if a.steps:
        cmd += ["-k", a.steps]
    cmd += a.arg
    cmd += ["--"] + target

    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("expect.py: failstep did not emit JSON", file=sys.stderr)
        print("stdout:\n" + proc.stdout, file=sys.stderr)
        print("stderr:\n" + proc.stderr, file=sys.stderr)
        return 2

    problems = data.get("problems", 0)
    types = [r.get("type") for r in data.get("results", [])]

    if a.info_exit is not None:
        entries = [i for i in data.get("info", []) if i.get("exit_code") == a.info_exit]
        if not entries:
            print(f"expect.py: expected an info entry for exit status {a.info_exit}, got "
                  f"{data.get('info')}", file=sys.stderr)
            return 1
        if a.info_runs is not None and entries[0].get("runs") != a.info_runs:
            print(f"expect.py: expected {a.info_runs} run(s) for exit status {a.info_exit}, "
                  f"got {entries[0].get('runs')}", file=sys.stderr)
            return 1

    if a.expect == "clean":
        if problems != 0:
            print(f"expect.py: expected clean, got {problems} problem(s): {types}",
                  file=sys.stderr)
            print(proc.stdout, file=sys.stderr)
            return 1
        print("OK: clean")
        return 0

    # expect problem
    if problems < 1:
        print("expect.py: expected a problem, got none", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        return 1
    if a.type and a.type not in types:
        print(f"expect.py: expected a '{a.type}' problem, got {types}", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        return 1
    print(f"OK: problem(s) {types}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
