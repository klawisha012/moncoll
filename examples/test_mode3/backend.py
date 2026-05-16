"""Reference backend for the test_mode3 example (source_type='container').

Run locally:
    python backend.py            # listens on 0.0.0.0:9003

Pair with a Connection of source_type='container' whose backend_url points
at host:9003 — Angie will reverse-proxy every request to this server, which
serves index.html at "/" and a JSON probe at "/api/health".
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

INDEX_HTML = (Path(__file__).parent / "index.html").read_bytes()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/health":
            body = b'{"service": "test_mode3_backend", "ok": true}'
            ctype = "application/json"
        else:
            body = INDEX_HTML
            ctype = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9003), Handler).serve_forever()
