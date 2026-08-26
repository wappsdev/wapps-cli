#!/usr/bin/env python3
"""secrets-gate'in SAHTE'si. Gercek bir gate'e HIC baglanmiyoruz ve hicbir
gercek sir kullanilmiyor: degerler bu dosyada uretilen sabit test dizeleri.

Iki rota tasiniyor:
  POST /v1/projects/{p}/read        -> okuma (get)
  PUT  /v1/projects/{p}/keys/{KEY}  -> tek anahtar yazimi (set)

YAZILAN DEGER ASLA KAYDEDILMIYOR: PUT govdesi Content-Length kadar okunup
ATILIYOR. Bir sahte gate'in bile bir degeri diske/loga yazmasi, bu portun
kapatmaya calistigi yuzeyin ta kendisi olurdu (log_message zaten susturulmus).
"""
import json, sys, re
from urllib.parse import unquote
from http.server import BaseHTTPRequestHandler, HTTPServer

# Anahtar -> (status, govde). Degerler TEST dizeleri; gercek sir DEGIL.
SCRIPT = {}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _drain(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n)

    def do_POST(self):
        body = self._drain()
        m = re.match(r"^/v1/projects/([^/]+)/read$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
        keys = (json.loads(body or b"{}") or {}).get("keys") or []
        key = keys[0] if keys else ""
        status, payload = SCRIPT.get(key, (404, {"error": "KEY_NOT_FOUND", "key": key}))
        return self._send(status, payload)

    def do_PUT(self):
        # Govde OKUNUYOR ama SAKLANMIYOR — istemci yazimi tamamlayabilsin diye.
        self._drain()
        m = re.match(r"^/v1/projects/([^/]+)/keys/([^/]+)$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
        # Yazim sonucu, okuma ile AYNI senaryo haritasindan surulur: 200 basari,
        # digerleri Go'nun mapHTTPError dallarini gezdirir.
        #
        # unquote: Go'nun url.PathEscape'i ile Rust'in kacisi ayni anahtari FARKLI
        # baytlarla kodlayabilir (Go path segmentinde `$&+,;=:@` gibi karakterleri
        # birakiyor, Rust hepsini yuzdeliyor). Gate her ikisini de AYNI anahtara
        # cozer; yani bu differential URL kodlamasini DEGIL verb davranisini olcer.
        # Kodlama ayrismasi ayri bir olcumun isi (bugun test anahtarlari
        # unreserved kumede tutuluyor, iki taraf orada birebir ayni).
        key = unquote(m.group(2))
        status, payload = SCRIPT.get(key, (404, {"error": "KEY_NOT_FOUND", "key": key}))
        if status == 200:
            payload = {"ok": True}
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
