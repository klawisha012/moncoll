"""Reference backend for the test_mode2 example (source_type='static_generate').

Run locally:
    python backend.py            # listens on 0.0.0.0:9002

This backend is *not* deployed by the WAF in static_generate mode — that mode
only serves index.html through Angie. It is included here so the example is a
complete full-stack reference: a developer can run this alongside index.html
to see what an API-paired static site would look like.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"service": "test_mode2_backend", "ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9002), Handler).serve_forever()
