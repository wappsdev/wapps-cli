#!/usr/bin/env python3
"""secrets-gate'in SAHTE'si. Gercek bir gate'e HIC baglanmiyoruz ve hicbir
gercek sir kullanilmiyor: degerler bu dosyada uretilen sabit test dizeleri."""
import json, sys, re
from http.server import BaseHTTPRequestHandler, HTTPServer

# Anahtar -> (status, govde). Degerler TEST dizeleri; gercek sir DEGIL.
SCRIPT = {}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        m = re.match(r"^/v1/projects/([^/]+)/read$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
        keys = (json.loads(body or b"{}") or {}).get("keys") or []
        key = keys[0] if keys else ""
        status, payload = SCRIPT.get(key, (404, {"error": "KEY_NOT_FOUND", "key": key}))
        return self._send(status, payload)
    def _send(self, status, obj):
        raw = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

if __name__ == "__main__":
    SCRIPT.update({k: tuple(v) for k, v in json.loads(sys.argv[2]).items()})
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
