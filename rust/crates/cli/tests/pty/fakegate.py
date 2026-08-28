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
  GET    /v1/audit/head                -> audit zincir head'i (dr accept-epoch-reset)
  GET    /v1/admin/policy             -> aktif policy (policy show/set)
  GET    /v1/admin/rotate-plan        -> audit-ledger rotate-set oracle (rotate-plan)
  PUT    /v1/admin/policy             -> CAS'li policy yazimi (policy set)

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
import json, sys, re, hashlib
from urllib.parse import unquote, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

# Anahtar -> (status, govde). Degerler TEST dizeleri; gercek sir DEGIL.
SCRIPT = {}

# AKTIF POLICY. Bir sir DEGIL — yetki kurallari. Version 3 SABIT: `policy set`
# CAS'i current+1 istiyor, yani istemcinin 4 gondermesi bekleniyor ve bunu
# gondermeyen bir istemci 412 aliyor (asagiya bak).
POLICY_VERSION = 3
POLICY_SHA = "abc123def456789abcdef"
POLICY_DOC = {
    "schema": "wapps-secrets/policy/v1",
    "version": POLICY_VERSION,
    "rules": [
        {"group": "developers@wapps.co", "projects": ["*"],
         "keys": ["*", "!*_PROD_*"], "verbs": ["read"]},
        {"service": "ci-runner", "projects": ["vaulter"],
         "keys": ["DB_*"], "verbs": ["read", "write"]},
    ],
}

# AUDIT HEAD SENARYOLARI — `dr accept-epoch-reset` seremonisinin CANLI referansi.
#
# SENARYO SECICI `cf-access-token` BASLIGI, ve bu bir kolaylik degil bir OLCU:
# `GET /v1/audit/head`in ne bir yol parametresi ne de bir sorgu dizesi var,
# yani istemcinin GONDERDIGI tek degisken alan kimlik basligidir. Senaryoyu
# oradan surmek, basligin GERCEKTEN enjekte edildigini de olcer — basligi
# gondermeyen (ya da yanlis adla gonderen) bir istemci DAIMA varsayilan
# senaryoyu alir ve senaryo vakalarinin tamami ayrisir.
#
# GERCEK SIR YOK: asagidaki jetonlar da hash'ler de uydurma test dizeleridir.
AUDIT_HEADS = {
    # Kisa hash: seremoni `len(hash) < 12` dalinda duser, Keys'e HIC gitmez.
    "audit-short": (200, {"seq": 11, "hash": "abc"}),
    # Audit DO erisilemez: fail-closed, seremoni ilerleyemez.
    "audit-down": (503, {"error": "AUDIT_UNAVAILABLE"}),
    # BUYUK HARFLI hash: kagittan yazilan deger kucuk harf olsa bile
    # eslesmeli (Go: strings.ToLower(hash[:12])). Kiyaslamayi ham baytlar
    # uzerinde yapan bir port burada AYRISIR.
    "audit-upper": (200, {"seq": 4217, "hash": "AB12CD34EF56aa77bb88cc99dd00ee11"}),
    # /keys COKMUS ama audit head SAGLAM: seremoninin on kontrolunde
    # EPOCH_DOWNGRADE OLMAYAN bir hatanin YUTULMADIGINI olcer.
    "audit-keysdown": (200, {"seq": 4217, "hash": "ab12cd34ef56aa77bb88cc99dd00ee11"}),
}
AUDIT_HEAD_DEFAULT = (200, {"seq": 4217, "hash": "ab12cd34ef56aa77bb88cc99dd00ee11"})

# EPOCH_RESET_EPOCH, `X-Wapps-Intent: epoch-reset` TASIYAN bir /keys okumasinin
# gordugu epoch. Sabit epoch'tan (7) FARKLI olmasi bilincli ve bu dosyanin
# rotate-plan rotasiyla ayni gerekce: basligi gondermeyen bir istemci FARKLI
# bir govde alir ve differential'da GORUNUR. Baslik aksi halde hicbir yerde
# olculmezdi — audit etiketi sunucu tarafinda kalir, ciktiya hic girmez.
EPOCH_RESET_EPOCH = 5

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

        # GET /v1/audit/head — global audit zincir head'i ({seq, hash}).
        # `dr accept-epoch-reset`in kagit zarfla karsilastirdigi CANLI deger.
        if self.path == "/v1/audit/head":
            status, payload = AUDIT_HEADS.get(
                self.headers.get("cf-access-token") or "", AUDIT_HEAD_DEFAULT)
            return self._send(status, payload)

        # GET /v1/admin/policy — aktif policy dokumani.
        #
        # AYRI BIR ONEK: kenarda /v1/admin AYRI bir CF Access uygulamasidir
        # (write-AUD). Sahte gate AUD dogrulamiyor — o kenarin isi — ama
        # rotanin AYRI olmasi Go'nun URL'iyle birebir ayni kalsin diye
        # korunuyor: bir istemci /v1/policy'ye giderse 404 alir ve GORUNUR.
        if self.path == "/v1/admin/policy":
            return self._send(200, {"version": POLICY_VERSION, "sha256": POLICY_SHA,
                                    "policy": POLICY_DOC})

        # GET /v1/admin/rotate-plan — audit-ledger rotate-set oracle.
        #
        # BU ROTA DA BILEREK MUSKUL, ve muskulluk SORGU DIZESINDE: donen govde
        # istemcinin GONDERDIGI parametrelerden surulur, sabit degil. Yani
        # `--identity`yi gondermeyen, `--assume-policy`yi `1` yerine baska bir
        # sey yapan ya da `--since`i yanlis adla yollayan bir istemci FARKLI
        # bir govde alir ve differential'da GORUNUR. Sabit bir govde donseydi
        # sorgu dizesini kuran kod HIC olculmezdi.
        #
        # GERCEK SIR YOK: donen satirlar (project, key) ADLARI ve sayaclardir —
        # rotate-plan zaten tanimi geregi deger DONDURMEZ.
        u = urlparse(self.path)
        if u.path == "/v1/admin/rotate-plan":
            q = parse_qs(u.query, keep_blank_values=True)
            items = [
                {"project": "vaulter", "key": "DB_PASSWORD",
                 "last_read": "2026-01-02T03:04:05Z", "reads": 12},
                # last_read BOS: istemci bunu "(assume-policy)" olarak
                # yazdirmali — bos dize DEGIL.
                {"project": "lumira", "key": "API_TOKEN", "last_read": "", "reads": 0},
            ]
            # `assume_policy=1` GONDERILDIYSE bir satir daha. Bayragi hic
            # gondermeyen ya da baska bir deger gonderen istemci bunu GORMEZ.
            if (q.get("assume_policy") or [""])[0] == "1":
                items.append({"project": "navlun-app", "key": "TF_VAR_REGION",
                              "last_read": "", "reads": 0})
            # `since` GONDERILDIYSE ilk satir dusuyor — alt sinirin gercekten
            # tel'e bindigini gosteren tek gozlem bu.
            if (q.get("since") or [""])[0]:
                items = items[1:]
            # BOS PLAN dali icin bir kaldirac. Bu kimlik icin ledger'da
            # duz-metin-bilen satir YOK, ve istemci o durumda TABLO YERINE tek
            # bir cumle basmali — kolayca bos bir baslik satiri basip
            # gecilebilecek bir dal.
            if (q.get("identity") or [""])[0] == "human:nobody@example.invalid":
                items = []
            return self._send(200, {
                # identity AYNEN geri: sorgu parametresinin adini yanlis yazan
                # bir istemci bos bir baslik satiri basar ve GORUNUR.
                "identity": (q.get("identity") or [""])[0],
                "generated_at": "2026-08-26T00:00:00Z",
                "items": items,
            })

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
        # `audit-keysdown` senaryosu: audit head SAGLAM, metadata duzlemi COKMUS.
        if (self.headers.get("cf-access-token") or "") == "audit-keysdown":
            return self._send(503, {"error": "AUDIT_UNAVAILABLE"})
        status, payload = SCRIPT.get("__ALL__", (404, {"error": "KEY_NOT_FOUND"}))
        if status != 200:
            return self._send(status, payload)
        vals = payload.get("values") or {}
        # `X-Wapps-Intent: epoch-reset` -> DAHA DUSUK bir epoch. Basligi
        # gondermeyen bir istemci 7 gorur, gonderen 5; seremoninin basari
        # satiri ve DISKE YAZILAN pin bu yuzden basligin varligini olcer.
        epoch = payload.get("epoch", 0)
        if self.headers.get("X-Wapps-Intent") == "epoch-reset":
            epoch = EPOCH_RESET_EPOCH
        return self._send(200, {"project": unquote(m.group(1)),
                                "epoch": epoch,
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
        body = self._drain()

        # PUT /v1/admin/policy — CAS'li policy yazimi.
        #
        # BU ROTA BILEREK MUSKUL, ve sebebi bu harness'in gecmisinde yazili: bir
        # sahte gate'in en kolay hatasi YANLIS bir isteğe DOGRU cevabi vermektir.
        # Burada UC sey govdeye BAGLI, yani govdeyi yanlis ureten bir istemci
        # farkli bir cevap alir ve differential'da GORUNUR:
        #
        #   1. CAS. version == current+1 DEGILSE 412 POLICY_CONFLICT. Yani
        #      current'i cekmeden ya da yanlis hesaplayan bir istemci duser.
        #   2. Donen `version`, GOVDEDEN okunuyor — sabit degil. Yanlis bir
        #      surum basilan basari satirini degistirir.
        #   3. Donen `sha256`, ALINAN BAYTLARIN sha256'si. Bu, dokumanin JSON
        #      SERILESTIRMESINI olculebilir yapar: alan SIRASI ya da bos
        #      selector'lerin omitempty'si Go'dan ayrisirsa sha ayrisir ve
        #      "✓ policy v4 active (sha256 ...)" satiri farklilasir. Okuma
        #      tarafindaki `keyName` hatasinin YAZIM tarafindaki karsiligi tam
        #      olarak budur.
        if self.path == "/v1/admin/policy":
            try:
                doc = json.loads(body or b"{}") or {}
            except ValueError:
                return self._send(400, {"error": "MALFORMED_POLICY"})
            want = POLICY_VERSION + 1
            if doc.get("version") != want:
                return self._send(412, {"error": "POLICY_CONFLICT",
                                        "current_version": POLICY_VERSION})
            return self._send(200, {"version": doc["version"],
                                    "sha256": hashlib.sha256(body).hexdigest()})

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
            # COMMIT YANITI, gercek writer-do'nun sekliyle: {project, epoch,
            # manifestSha256, keyVersions} (worker/src/writer-do.ts). Onceden
            # burasi {"ok": true} donuyordu — gercek gate'in ASLA donmedigi bir
            # sekil. O uydurma sekil, "bir yazim epoch GORMUYOR" yanlisini
            # olculemez kiliyordu: istemci epoch'u atiyordu, sahte gate de
            # gondermiyordu, yani kimse farki goremiyordu.
            payload = {"project": unquote(m.group(1)),
                       "epoch": payload.get("epoch", 0),
                       "manifestSha256": "a" * 64,
                       "keyVersions": {key: 1}}
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
