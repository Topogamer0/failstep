#!/usr/bin/env python3
"""
A fake Ollama server for the failstep demo, modelled on Ollama-C's own
tests/mock_server.py.

Usage: ollama_mock.py <harness-binary> [args...]

Starts an HTTP server on a free local port, runs the harness with OLLAMA_HOST
pointing at it, and exits with the harness's exit code. failstep runs this
script as its target, so the FAILSTEP_* environment it sets is inherited by the
harness.

The /api/chat response is a streaming (ndjson) chat shaped to trigger the
Ollama-C v0.1.0 use-after-free:

  part 1: content of ~200 bytes      -> allocates the assembled content buffer
  part 2: content of ~100 bytes      -> forces the buffer to grow (frees the old
          plus a `thinking` fragment    block), and the thinking append is the
                                         allocation failstep makes fail
  final : done + statistics
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def chat_parts():
    return [
        {"model": "demo", "message": {"role": "assistant", "content": "a" * 200}, "done": False},
        {"model": "demo",
         "message": {"role": "assistant", "content": "b" * 100, "thinking": "reasoning"},
         "done": False},
        {"model": "demo", "message": {"role": "assistant", "content": ""}, "done": True,
         "done_reason": "stop", "total_duration": 1, "eval_count": 3},
    ]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if self.path != "/api/chat":
            body = b'{"error":"not found"}'
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for part in chat_parts():
            line = (json.dumps(part) + "\n").encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(line), line))
            self.wfile.flush()
            time.sleep(0.005)
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if not isinstance(exc, (ConnectionError, BrokenPipeError)):
            super().handle_error(request, client_address)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    server = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, OLLAMA_HOST="127.0.0.1:%d" % server.server_address[1])
    env.pop("OLLAMA_API_KEY", None)
    try:
        rc = subprocess.run(sys.argv[1:], env=env).returncode
    finally:
        server.shutdown()
    if rc < 0 and os.name == "posix":
        # The harness was killed by a signal: die by the same signal, so that
        # failstep sees a crash and not an orderly exit status of this wrapper.
        signal.signal(-rc, signal.SIG_DFL)
        os.kill(os.getpid(), -rc)
    return rc


if __name__ == "__main__":
    sys.exit(main())
