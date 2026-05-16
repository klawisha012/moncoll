"""Sample backend service for the test_mode1 example.

Run locally:
    python backend.py            # listens on 0.0.0.0:9001

This is a *reference* backend that pairs with index.html + nginx.conf in this
directory. The WAF "nginx_config" connection mode deploys nginx.conf as-is
(includes are expanded), so any proxy_pass to this backend lives in the conf.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"service": "test_mode1_backend", "ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9001), Handler).serve_forever()
