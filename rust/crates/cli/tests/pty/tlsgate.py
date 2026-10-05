#!/usr/bin/env python3
"""secrets-gate'in TLS'li SAHTE'si — guven deposu olcumu icin.

fakegate.py'nin `http://` kardesidir; ayri duruyor cunku olctugu sey farkli:
o taraf HTTP DURUM KODU eslemesini olcuyor, bu taraf SERTIFIKA DOGRULAMASINI.
Adim 6'nin 32 differential vakasinin tamami `http://` uzerinden kosuyor, yani
Go ile Rust arasindaki bir guven-deposu ayrismasi bugun HICBIR kapida gorunmez.
Bu dosya o kapiyi kuruyor.

GERCEK HICBIR SEY YOK: CA ve sunucu sertifikasi kosum aninda uretiliyor,
gecici bir dizine yaziliyor ve kosum bitince siliniyor. Agaca hicbir sertifika,
anahtar ya da gercek alan adi yazilmiyor. Dondurulen deger sabit bir test
dizesi."""
import json, ssl, sys
from http.server import BaseHTTPRequestHandler
from gateproc import Server


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        # El sikisma GECTIYSE gorulen govde. Deger TEST dizesi; gercek sir DEGIL.
        raw = json.dumps({"epoch": 7, "values": {"PLAIN_KEY": "value-for-plain"}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


if __name__ == "__main__":
    port, crt, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = Server(("127.0.0.1", port), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()
