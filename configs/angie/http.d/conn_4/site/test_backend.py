#!/usr/bin/env python3
"""
Simple test backend for WAF Connections feature.
This demonstrates a backend service that can be proxied through Angie WAF.

Run: python3 test_backend.py
Then connect to it via the WAF Connections tab with:
- Backend URL: http://host.docker.internal:5000 (Mac/Windows) or http://172.17.0.1:5000 (Linux)
- Domains: local.waf.test, test.waf.local
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse


class TestBackendHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Log with WAF-relevant headers
        print(f"[Backend] {self.address_string()} - {format % args}")

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            with open("examples/example.html", "r") as f:
                self.wfile.write(f.read().encode())
        elif self.path == "/api/status":
            self.send_json_response(
                {
                    "status": "ok",
                    "message": "Backend is running",
                    "waf_proxied": True,
                    "timestamp": self.date_time_string(),
                }
            )
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def do_POST(self):
        if self.path == "/api/test":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)

            try:
                data = json.loads(post_data.decode())
            except:
                data = {"message": "invalid json"}

            self.send_json_response(
                {
                    "status": "received",
                    "data": data,
                    "waf_protected": True,
                    "note": "This request passed through Angie WAF with ModSecurity",
                }
            )
        elif self.path == "/api/echo":
            # Echo back all headers for debugging
            headers = dict(self.headers)
            self.send_json_response(
                {
                    "headers": headers,
                    "message": "Headers echoed",
                    "client_ip": self.client_address[0],
                }
            )
        else:
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Not found"}).encode())

    def send_json_response(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 5000), TestBackendHandler)
    print("🚀 Test backend started on http://0.0.0.0:5000")
    print("📝 Available endpoints:")
    print("   GET  /           - Serve example.html")
    print("   GET  /api/status - Status check")
    print("   POST /api/test   - Test request (WAF will inspect)")
    print("   POST /api/echo   - Echo headers")
    print("\n🔧 To connect through WAF:")
    print(
        "   Backend URL: http://host.docker.internal:5000 (or http://172.17.0.1:5000 on Linux)"
    )
    print("   Domains: local.waf.test, test.waf.local")
    print("   Don't forget to add entries to your /etc/hosts file!")
    server.serve_forever()
