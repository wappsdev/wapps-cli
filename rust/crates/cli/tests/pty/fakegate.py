#!/usr/bin/env python3
"""secrets-gate'in SAHTE'si. Gercek bir gate'e HIC baglanmiyoruz ve hicbir
gercek sir kullanilmiyor: degerler bu dosyada uretilen sabit test dizeleri.

Tasinan rotalar:
  GET    /v1/projects/{p}/keys        -> anahtar ADLARI (list, exec/apply 1. adim)
  POST   /v1/projects/{p}/read        -> okuma (get, ve exec/apply'in 2. adimi)
  PUT    /v1/projects/{p}/keys/{KEY}  -> tek anahtar yazimi (set)
  POST   /v1/projects/{p}/import      -> TOPLU atomik yazim (import-env)
  DELETE /v1/projects/{p}/keys/{KEY}  -> tek anahtar silme (rm)
  GET    /v1/projects                 -> proje ADLARI (projects list)
  DELETE /v1/admin/projects/{p}       -> projeyi tumuyle silme (projects rm)
  GET    /v1/whoami                   -> status'un canlilik probu

TEL ADI `keyName` (camelCase) — bu bir AYRINTI DEGIL. Bu dosya bir sure
`key_name` yaydi (Rust'in alan adi) ve o yanlis ad GERCEK bir ayrismayi
gizledi: Go `keyName` okudugu icin BOS adlar aliyordu, Rust ise dolu.
`POST /read` coklu istekleri tek bir `__ALL__` senaryosuna cevirdiginden iki
taraf da ayni degerleri geri aliyor ve karsilastirma HICBIR SEY olcmuyordu.
Oracle: internal/store/store.go:54, worker/test/admin-policy.test.ts.
Bu yuzden /read artik ISTENEN ad kumesini onurlandiriyor: yanlis bir ad
kumesi bos bir sonuc verir ve GORUNUR.

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

    def do_GET(self):
        # GET /v1/whoami — status'un canlilik probu. Govde onemsiz: Go
        # HERHANGI bir HTTP yanitini (401 dahil) "online" sayiyor, yalnizca
        # tasima hatasi offline demek.
        if self.path == "/v1/whoami":
            return self._send(200, {"principal": "probe@example.invalid"})

        # GET /v1/projects — principal'in GOREBILDIGI proje ADLARI.
        # Filtreleme SUNUCUDA yapilir; istemci sirayi da BOZMAZ, o yuzden
        # bilincli olarak alfabetik OLMAYAN bir sira donuyor: istemci
        # tarafinda gizli bir sort olsaydi bu gorunurdu.
        if self.path == "/v1/projects":
            return self._send(200, {"projects": ["vaulter", "lumira", "navlun-app"]})

        # GET /v1/projects/{p}/keys — METADATA duzlemi (deger DONMEZ).
        # Read'in "tum anahtarlar" yolu IKI ADIMLI: once bu rota ad kumesini
        # verir, sonra POST /read o adlarla cagrilir. Bu rota olmadan olcum
        # 501'e dusuyordu ve exec/apply'in gercek hattini HIC gezmiyordu.
        m = re.match(r"^/v1/projects/([^/]+)/keys$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
        status, payload = SCRIPT.get("__ALL__", (404, {"error": "KEY_NOT_FOUND"}))
        if status != 200:
            return self._send(status, payload)
        vals = payload.get("values") or {}
        return self._send(200, {"project": unquote(m.group(1)),
                                "epoch": payload.get("epoch", 0),
                                "keys": [{"keyName": k, "keyVersion": 1}
                                         for k in sorted(vals)]})

    def do_POST(self):
        body = self._drain()

        # POST /v1/projects/{p}/import — TOPLU atomik yazim (import-env).
        #
        # BU ROTA BILEREK MUSKUL: bir sahte gate'in en kolay hatasi, YANLIS bir
        # isteğe DOGRU cevabi vermektir. Onceki bir dilimde `POST /read` tam
        # olarak bunu yapiyordu (her coklu istegi kosulsuz `__ALL__`e cevirip
        # BOS bir ad kumesi gonderen istemciye de tam sonucu donuyordu) ve
        # CANLI bir `keyName` hatasini gizliyordu. Bu yuzden burada:
        #
        #   1. ZARFIN ADI dogrulaniyor. Govde `{"values": {...}}` DEGILSE
        #      (ornegin duz bir harita, ya da `secrets:`/`keys:` gibi baska bir
        #      ad) 400 doner — yani yanlis bir tel bicimi GORUNUR.
        #   2. BOS kume 400. "Hicbir sey gondermek" basari SAYILMAZ.
        #   3. Sonuc, GERCEKTEN GONDERILEN ad kumesinden surulur: adlardan biri
        #      SCRIPT'te hata tasiyorsa o hata doner. Bir istemci yanlis/bos
        #      adlar gonderirse beklenen hata YERINE 200 alir ve fark
        #      differential'da yuzeye cikar.
        #
        # DEGERLER OKUNUYOR AMA SAKLANMIYOR: bir sahte gate'in bile bir degeri
        # diske/loga yazmasi, bu portun kapatmaya calistigi yuzeyin ta kendisi.
        m = re.match(r"^/v1/projects/([^/]+)/import$", self.path)
        if m:
            try:
                doc = json.loads(body or b"{}") or {}
            except ValueError:
                return self._send(400, {"error": "MALFORMED_IMPORT"})
            vals = doc.get("values")
            if not isinstance(vals, dict) or not vals:
                return self._send(400, {"error": "MALFORMED_IMPORT"})
            if any(not isinstance(v, str) for v in vals.values()):
                return self._send(400, {"error": "MALFORMED_IMPORT"})
            for k in sorted(vals):
                status, payload = SCRIPT.get(k, (200, None))
                if status != 200:
                    return self._send(status, payload)
            return self._send(200, {"ok": True, "imported": len(vals)})

        m = re.match(r"^/v1/projects/([^/]+)/read$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
        keys = (json.loads(body or b"{}") or {}).get("keys") or []
        # Tek anahtarli istekler (get/set) kendi senaryolarina gider.
        if len(keys) == 1:
            key = keys[0]
            status, payload = SCRIPT.get(key, (404, {"error": "KEY_NOT_FOUND", "key": key}))
            return self._send(status, payload)
        # COKLU istek = bulk okuma (exec/apply, GET /keys'ten aldiklari adlarla).
        # Govde ISTENEN ad kumesine FILTRELENIYOR. Bu bir incelik degil olcumun
        # gecerliligi: eskiden her coklu istek kosulsuz "__ALL__" senaryosunu
        # donuyordu, yani BOS ya da YANLIS bir ad kumesi gonderen bir istemci
        # de tam sonucu aliyordu ve `keyName`/`key_name` ayrismasi gorunmuyordu.
        status, payload = SCRIPT.get("__ALL__", (404, {"error": "KEY_NOT_FOUND"}))
        if status != 200:
            return self._send(status, payload)
        vals = payload.get("values") or {}
        return self._send(200, {"epoch": payload.get("epoch", 0),
                                "values": {k: vals[k] for k in keys if k in vals}})

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

    def do_DELETE(self):
        self._drain()
        # DELETE /v1/admin/projects/{p} — KONTROL DUZLEMI (projects rm).
        # Ayri bir onek: kenarda /v1/admin AYRI bir CF Access uygulamasidir
        # (write-AUD). Sahte gate AUD dogrulamiyor — o kenarin isi — ama rotanin
        # AYRI olmasi Go'nun URL'iyle birebir ayni kalsin diye korunuyor.
        m = re.match(r"^/v1/admin/projects/([^/]+)$", self.path)
        if m:
            return self._send(200, {"project": unquote(m.group(1)),
                                    "deleted_objects": 17,
                                    "pointer_events_kept": True})
        # DELETE /v1/projects/{p}/keys/{KEY} — tek anahtar silme (rm).
        # Silme sonucu okuma ile AYNI senaryo haritasindan surulur, tipki
        # PUT gibi: 200 basari, digerleri mapHTTPError dallarini gezdirir.
        m = re.match(r"^/v1/projects/([^/]+)/keys/([^/]+)$", self.path)
        if not m:
            return self._send(404, {"error": "NO_ROUTE"})
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
