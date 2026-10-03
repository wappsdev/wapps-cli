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
  GET    /v1/whoami                   -> principal + gruplar + grant'ler (whoami)
                                         VE status'un canlilik probu
  POST   /v1/token                    -> kisa omurlu makine jetonu (token exchange)
  GET    /v1/audit/head                -> audit zincir head'i (dr accept-epoch-reset)
  GET    /v1/admin/policy             -> aktif policy (policy show/set)
  GET    /v1/admin/rotate-plan        -> audit-ledger rotate-set oracle (rotate-plan)
  PUT    /v1/admin/policy             -> CAS'li policy yazimi (policy set)

And a fake COOLIFY v4 API under /api/v1 (cases set COOLIFY_URL to
"{GATE}/api/v1"; see COOLIFY_* and _coolify below):
  PATCH  /api/v1/applications/{uuid}       -> custom_labels (coolify set-labels)
  POST   /api/v1/applications/{uuid}/envs  -> create one env (coolify update-env)
  PATCH  /api/v1/applications/{uuid}/envs  -> update one env after a 409
  GET    /api/v1/applications/{uuid}/envs  -> the app's env table (secrets sync --target=coolify)
  DELETE /api/v1/applications/{uuid}/envs/{env} -> remove one env (sync --force)
  POST   /api/v1/applications/dockercompose -> create (coolify deploy-app)
  POST   /api/v1/applications/{uuid}/start -> start (coolify deploy-app)
  POST   /api/v1/applications/private-github-app -> create (coolify deploy-app-git)
  GET    /api/v1/deploy?uuid=               -> trigger a deploy (deploy-app-git)
  GET    /api/v1/applications               -> list (coolify import-app)

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
import json, sys, re, hashlib, base64
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

# WHOAMI SENARYOLARI — `wapps whoami`in gordugu principal/grup/grant govdesi.
#
# SENARYO SECICI `cf-access-token` BASLIGI (AUDIT_HEADS ile AYNI gerekce):
# `GET /v1/whoami`in ne yol parametresi ne sorgu dizesi var, yani istemcinin
# gonderdigi TEK degisken alan kimlik basligidir. Senaryoyu oradan surmek,
# basligin bu rotaya da GERCEKTEN enjekte edildigini olcer.
#
# VARSAYILAN 200 KALMALI ve bu bir zevk meselesi degil: `secrets status`in
# canlilik probu bu rotayi BASLIKSIZ cagiriyor (iki ikilide de duz bir GET),
# yani "" anahtarina duser. Varsayilani 4xx yapmak status vakalarini
# sessizce cevirirdi.
#
# GERCEK SIR YOK: asagidaki adresler, gruplar ve grant'ler uydurma test
# dizeleridir; whoami zaten tanimi geregi DEGER dondurmez.
WHOAMI = {
    # Zengin insan govdesi — uc SECICI turu birden (group / service / aud).
    "__default__": (200, {
        "principal": "human:dev@example.invalid",
        "kind": "human",
        "email": "dev@example.invalid",
        "groups": ["developers@example.invalid", "admins@example.invalid"],
        "policy_version": 3,
        "is_root_admin": False,
        "grants": [
            {"group": "developers@example.invalid", "projects": ["*"],
             "keys": ["*", "!*_PROD_*"], "verbs": ["read"]},
            {"service": "ci-runner", "projects": ["vaulter"],
             "keys": ["DB_*"], "verbs": ["read", "write"]},
            {"aud": "write-aud-1", "projects": ["lumira"],
             "keys": [], "verbs": ["read", "write", "rotate"]},
        ],
    }),
    # Servis principal'i: `email` BOS (satir DUSMELI), `common_name` DOLU
    # (satir CIKMALI), gruplar BOS ("-"), root_admin TRUE, grant YOK.
    "who-service": (200, {
        "principal": "service:ci-runner",
        "kind": "service",
        "common_name": "ci-runner.example.invalid",
        "groups": [],
        "policy_version": 9,
        "is_root_admin": True,
        "grants": [],
    }),
    # BOS govde: her alan sifir degerinde. `principal:` satiri BOS basilir —
    # atlanmaz (yalnizca email/common_name kosullu).
    "who-min": (200, {}),
    # SECICI KENARLARI, ve ucu de ayri bir daldir:
    #   1. group+service+aud BIRLIKTE -> `aud:` KAZANIR (Go'daki atama sirasi);
    #   2. HICBIR secici yok -> 28 karakterlik BOS sutun (%-28s), atlama YOK;
    #   3. 28'den UZUN secici -> KIRPILMAZ, sutun tasar.
    "who-edge": (200, {
        "principal": "human:edge@example.invalid",
        "groups": [],
        "policy_version": 0,
        "grants": [
            {"group": "G", "service": "S", "aud": "A",
             "projects": ["x"], "keys": ["y"], "verbs": ["read"]},
            {"projects": [], "keys": None, "verbs": ["read"]},
            {"group": "a-very-long-group-name-that-exceeds-twentyeight",
             "projects": ["p"], "keys": ["k"], "verbs": ["read"]},
        ],
    }),
    # Kimlik cozulemedi -> fail-closed (mapHTTPError'in 503 dali).
    "who-identdown": (503, {"error": "IDENTITY_UNAVAILABLE"}),
    # 403 ve govde BOS. Bu vaka `safeCode`u olcuyor: Go BOS bir kodu
    # "unknown" yaziyor, temizlenince bos kalan bir kodu da. Bir port
    # bunu bos dize basarsa iki parantez de ayrisir.
    "who-denied-bare": (403, {}),
    # 403 ve kod KIRLI: `safeCode` 48 bayta kirpiyor ve [A-Za-z0-9_-.] disini
    # ATIYOR (silmiyor, ayirmiyor — bitistiriyor).
    "who-denied-dirty": (403, {"error": "DENIED <b>x</b>\nsecond", "dimension": "aud"}),
}

# TOKEN SENARYOLARI — `POST /v1/token`in GOVDEDEN SURULMEYEN dallari.
#
# SECICI `CF-Access-Client-Id` BASLIGI: `token exchange` zaten service-token
# ciftini SART kosuyor, yani bu baslik her cagrida var ve vakadan surulebilir.
# Basligi hic gondermeyen (ya da yanlis adla gonderen) bir istemci
# `__default__`a duser ve govde-surulen yola girer.
#
# GERCEK SIR YOK: basilan "jeton" asagida govdeden URETILEN uydurma bir
# JWT-bicimli dizedir.
TOKEN_SCENARIOS = {
    # exp YOK -> istemci stderr'e metadata satirini BASMAMALI.
    "tok-noexp": (200, {"token": "minted-token-without-an-exp"}),
    # Yalnizca bosluk: Go TrimSpace ile bos sayiyor -> TOKEN_EXCHANGE_FAILED.
    "tok-blank": (200, {"token": "   ", "exp": 5}),
    # `token` alani HIC YOK -> ayni ret.
    "tok-absent": (200, {"exp": 5}),
    # 400 ve govde BOS -> safeCode("") == "unknown".
    "tok-reject-bare": (400, {}),
    # 400 ve kod KIRLI -> safeCode temizligi mint yolunda da gecerli.
    "tok-reject-dirty": (400, {"error": "BAD <b>code</b>\nsecond line"}),
    # 403 + makine-jetonu kodu: mapHTTPError'in SESSION_EXPIRED dali.
    "tok-scope": (403, {"error": "TOKEN_SCOPE_EXCEEDED"}),
    # 5xx ve 4xx'in mint'e OZEL OLMAYAN dallari da bu rotadan gecmeli.
    "tok-miscfg": (503, {"error": "WHATEVER_ELSE"}),
    "tok-teapot": (418, {"error": "TEAPOT"}),
    # exp KENARI: gun/ay/yil tasmasi olan bir zaman damgasi. Bir port
    # RFC3339'u elde uretiyorsa (ve bu portta oyle) burada ayrisir.
    "tok-exp-edge": (200, {"token": "minted-token-at-the-edge", "exp": 1767225599}),
}

# TOKEN_EXP, govde-surulen basari yolunun SABIT son kullanma damgasi.
TOKEN_EXP = 1793318400  # 2026-10-30T00:00:00Z

# TOKEN_TTL_MAX, mint'in ust siniri (§5.3 "<=600"). Bu sinir ISTEMCIDE DEGIL
# GATE'te yasiyor ve bu OLCULDU: Go `--ttl`i hic dogrulamiyor, oldugu gibi
# tel'e koyuyor. Sinir burada durunca `--ttl`in gercekten govdeye bindigi
# gorunur hale geliyor.
TOKEN_TTL_MAX = 600

# TOKEN_VERBS, mint'in kabul ettigi verb kumesi. `--verb` dogrulamasi da
# ISTEMCIDE YOK (olculdu) — burada durmasi bayragin tel'e bindigini olcer.
TOKEN_VERBS = ("read", "write", "rotate")

# --- FAKE COOLIFY v4 API --------------------------------------------------------
#
# What the client must send, checked on EVERY request, each refusal with its
# own body so a client that gets one wrong prints a different error:
#   * `Authorization: Bearer <COOLIFY_TOKEN>` (the COOLIFY_API_TOKEN cases
#     set) -> 401 otherwise. The token may carry a `:<tag>` suffix: the tag
#     picks the scenario of a route the client sends nothing else to
#     (`GET /applications`, see COOLIFY_LIST_SCENARIOS);
#   * `User-Agent: curl/8` and `Content-Type: application/json` (Go sets both
#     on every request, GET and DELETE included) -> 400 otherwise.
#
# Bodies are validated field by field: `custom_labels` and
# `docker_compose_raw` must be STRICT standard base64, an env body must carry
# exactly Go's five fields with Go's constant flags (`is_buildtime` true only
# on an app this fake created from GitHub, uuid "gh-*": that is
# `--build-arg`), the create bodies exactly Go's field sets, and a request Go
# sends WITHOUT a body (start, deploy, the GETs, DELETE) must arrive empty. A
# body that is wrong in shape gets a 422 naming the problem.
#
# The scenario is chosen by what the client sends:
#   app "app-missing"   -> 404 on every route;
#   app "app-longbody"  -> 500 with a body over 200 bytes (Go cuts it at 200
#                          and appends "…");
#   app "app-echo"      -> 422 that ECHOES the decoded labels and the sha256
#                          of the raw request bytes. A successful PATCH prints
#                          only a count; this is how a case sees WHAT went out
#                          (the "\n" join, the strip filter, Go's JSON bytes);
#   key "EXISTS_*"      -> 409 on POST, so the client must PATCH (so does any
#                          key the app's env table already holds);
#   key "GONE_*"        -> 409 on POST and 404 on the PATCH that follows;
#   key "BROKEN_*"      -> 500 on POST;
#   key "ECHO_*"        -> 422 echoing the decoded env body and the sha256 of
#                          the raw bytes (on POST, or on the PATCH after a 409
#                          for "EXISTS_ECHO_*");
#   create name         -> see COOLIFY_CREATE_SCENARIOS; otherwise the new app
#                          is "dc-<name>" (compose) or "gh-<name>" (GitHub);
#   app "dc-fail-start" -> 500 on start; uuid "gh-fail-deploy" -> 500 on deploy;
#   app env tables      -> COOLIFY_APP_ENVS (the state `secrets sync
#                          --target=coolify` diffs against). An app uuid
#                          ending in "-j" serves its base table plus one more
#                          entry, ZZ_JOURNAL (env uuid "env-journal").
#
# THE JOURNAL. An apply prints only counts, so what it SENT is invisible. The
# fake keeps, per app, the list of env writes it received since that app's
# envs were last listed: [method, key, value, is_buildtime] or ["DELETE",
# env uuid]. Deleting "env-journal" is refused with a 422 carrying the length
# and a sha256 of that list. ZZ_JOURNAL sorts after every other key, so its
# DELETE is the last request of an apply and the digest covers every value,
# flag, env uuid and the ORDER the client used. The list is reset when the app
# is listed, so one case never sees another's writes.
#
# NO REAL SECRET: the token and every value are made-up test strings, and only
# the bodies the cases themselves wrote are echoed.
COOLIFY_TOKEN = "coolify-test-token-not-a-secret"
COOLIFY_ENV_FIELDS = {"key", "value", "is_preview", "is_buildtime", "is_literal"}
COOLIFY_LONG_BODY = {"message": "Server Error", "detail": "x" * 240}
COOLIFY_COMPOSE_FIELDS = {"project_uuid", "server_uuid", "name", "docker_compose_raw"}
COOLIFY_GITHUB_FIELDS = {"project_uuid", "environment_name", "server_uuid",
                         "github_app_uuid", "git_repository", "git_branch",
                         "build_pack", "name", "base_directory",
                         "dockerfile_location", "ports_exposes", "watch_paths",
                         "instant_deploy"}

# A create's response, by the `name` the client sent. "noid" answers without
# a uuid (Go prints the decoded body with %v); "notjson" answers with a body
# that is not JSON at all; "badid" hands back a uuid the client must refuse
# before putting it in a path.
COOLIFY_CREATE_SCENARIOS = {
    "noid": (201, {"message": "created", "id": 7, "ok": True,
                   "tags": ["a b", 1.5, 1e21, 0.00001], "none": None,
                   "nested": {"z": 1, "a": "x"}}),
    "notjson": (201, b"created, but not as JSON"),
    "badid": (201, {"uuid": "../x"}),
    "broken": (500, {"message": "Server Error"}),
}

# `GET /applications`, by the token's tag. The client sends nothing else, and
# Go accepts both a bare array and a {"data": [...]} envelope and turns any
# other 2xx body into an empty list.
COOLIFY_APPS = [
    {"uuid": "aaaaaaaa-1111", "name": "Web App",
     "destination": {"server": {"uuid": "srv-1"}}},
    {"uuid": "bbbbbbbb-2222", "name": "api_v2.internal",
     "destination": {"server": {"uuid": "srv-2"}}},
    {"uuid": "cccccccc-3333", "name": "  Trailing--Dash!! ",
     "destination": {"server": {"uuid": "srv-1"}}},
    # Go lowercases rune by rune (unicode.ToLower): "İ" becomes a plain "i".
    {"uuid": "dddddddd-4444", "name": "İstanbul Üni",
     "destination": {"server": {"uuid": "srv-1"}}},
    {"uuid": "eeeeeeee-5555", "name": "no-destination"},
    {"uuid": "ffffffff-6666", "name": "", "destination": {"server": {"uuid": "srv-1"}}},
    {"name": "no-uuid", "destination": {"server": {"uuid": "srv-1"}}},
    {"uuid": 12, "name": "uuid-is-a-number"},
    "not-an-object",
    # The Kelvin sign lowercases to an ASCII "k".
    {"uuid": "gggggggg-7777", "name": "KelvinK", "destination": {"server": "srv-1"}},
    {"uuid": "hhhhhhhh-8888", "name": "web app",
     "destination": {"server": {"uuid": "srv-1"}}},
]
COOLIFY_LIST_SCENARIOS = {
    "": (200, COOLIFY_APPS),
    "data": (200, {"data": COOLIFY_APPS[:2]}),
    "object": (200, {"message": "no list here"}),
    "notjson": (200, b"<html>not json</html>"),
    "missing": (404, {"message": "Not found."}),
}


def _env(uuid, key, value, **flags):
    return dict({"uuid": uuid, "key": key, "value": value,
                 "is_buildtime": False, "is_preview": False}, **flags)


# The env state of the apps `secrets sync --target=coolify` is pointed at.
# Against the store's `coolproj` set (cases.py, GATE_SCRIPT "__ALL__@coolproj").
COOLIFY_APP_ENVS = {
    # Single-app: one of each kind.
    "app-sync": [
        _env("env-alpha", "ALPHA", "alpha-test-value-long"),          # unchanged
        _env("env-beta", "BETA", "beta-old-test-value"),              # changed
        _env("env-old", "OLD_KEY", "old-test-value"),                 # removed
        _env("env-managed", "MANAGED_URL", "https://m.example.test",  # managed,
             is_coolify=True),                                         # also desired
        _env("env-svc", "SERVICE_FQDN_WEB", "web.example.test", is_coolify=True),
        _env("env-prev-rt", "PREVIEWED", "runtime-test-value"),       # runtime copy
        _env("env-prev-pv", "PREVIEWED", "preview-test-value", is_preview=True),
        _env("env-prevonly", "PREVONLY", "p", is_preview=True),       # preview only
        _env("env-num", "NUMERIC", 5),                                # value not a string
        "not-an-object",
    ],
    # Multi-app, prefix WEB_.
    "app-web": [
        _env("env-w-port", "PORT", "8080"),
        _env("env-w-host", "HOST", "old.example.test"),
        _env("env-w-legacy", "LEGACY", "legacy-test-value"),
        _env("env-w-sentry", "SENTRY_RELEASE", "r0"),
        _env("env-w-svc", "SERVICE_FQDN_WEB", "web.example.test", is_coolify=True),
    ],
    # Multi-app, prefix API_.
    "app-api": [
        _env("env-a-port", "PORT", "9090"),
        _env("env-a-extra", "EXTRA", "extra-test-value"),
    ],
    # An env uuid the client must refuse before it builds the DELETE path.
    "app-badenv": [
        _env("../x", "OLD_KEY", "old-test-value"),
    ],
    # A key held TWICE at runtime: Go keeps the LAST entry, for the value
    # compared and for the env uuid deleted.
    "app-dup": [
        _env("env-a1", "ALPHA", "an-older-test-value"),
        _env("env-a2", "ALPHA", "alpha-test-value-long"),
        _env("env-o1", "OLD_KEY", "old-test-value"),
        _env("env-o2", "OLD_KEY", "old-test-value"),
    ],
    # A DELETE the API refuses.
    "app-delfail": [
        _env("env-broken", "OLD_KEY", "old-test-value"),
    ],
}
COOLIFY_JOURNAL_ENTRY = _env("env-journal", "ZZ_JOURNAL", "journal-test-value")
JOURNAL = {}


def _app_envs(app):
    base = app[:-2] if app.endswith("-j") else app
    table = list(COOLIFY_APP_ENVS.get(base, []))
    if app.endswith("-j"):
        table.append(COOLIFY_JOURNAL_ENTRY)
    return table


def _b64_strict(raw):
    """Decodes STRICT padded standard base64 or returns None."""
    if not isinstance(raw, str) or len(raw) % 4:
        return None
    try:
        return base64.b64decode(raw, validate=True).decode()
    except ValueError:
        return None


def _coolify(h, method, rawpath, body):
    """Serves one Coolify request; returns False if the path is not Coolify's."""
    u = urlparse(rawpath)
    path = u.path
    if not path.startswith("/api/v1/"):
        return False
    auth = h.headers.get("Authorization") or ""
    base = "Bearer " + COOLIFY_TOKEN
    if auth == base:
        tag = ""
    elif auth.startswith(base + ":"):
        tag = auth[len(base) + 1:]
    else:
        h._send(401, {"message": "Unauthenticated."})
        return True
    if h.headers.get("User-Agent") != "curl/8":
        h._send(400, {"message": "unexpected User-Agent"})
        return True
    if h.headers.get("Content-Type") != "application/json":
        h._send(400, {"message": "unexpected Content-Type"})
        return True
    sha = hashlib.sha256(body).hexdigest()[:16]

    # --- routes Go calls WITHOUT a body -----------------------------------
    if method in ("GET", "DELETE") or path.endswith("/start"):
        if body:
            h._send(422, {"message": "unexpected body"})
            return True
    if method == "GET" and path == "/api/v1/applications":
        status, payload = COOLIFY_LIST_SCENARIOS.get(tag, (418, {"message": "no such tag"}))
        if isinstance(payload, bytes):
            h._send_raw(status, payload)
        else:
            h._send(status, payload)
        return True
    if method == "GET" and path == "/api/v1/deploy":
        uuid = (parse_qs(u.query).get("uuid") or [""])[0]
        if not uuid:
            h._send(400, {"message": "uuid is required"})
        elif uuid == "gh-fail-deploy":
            h._send(500, {"message": "deploy failed"})
        else:
            h._send(200, {"deployments": [{"message": "queued", "resource_uuid": uuid}]})
        return True
    m = re.match(r"^/api/v1/applications/([^/]+)(/envs(?:/([^/]+))?|/start)?$", path)
    if not m:
        return False
    app, sub, env_uuid = m.group(1), m.group(2) or "", m.group(3)

    if app == "app-missing":
        h._send(404, {"message": "Application not found."})
        return True
    if app == "app-longbody":
        h._send(500, COOLIFY_LONG_BODY)
        return True

    if sub == "/start":
        if method != "POST":
            h._send(405, {"message": "method not allowed"})
        elif app == "dc-fail-start":
            h._send(500, {"message": "start failed"})
        else:
            h._send(200, {"message": "Deployment request queued.", "deployment_uuid": "dep-1"})
        return True

    if sub == "/envs" and method == "GET":
        table = _app_envs(app)
        JOURNAL[app] = []
        if app == "app-data":
            h._send(200, {"data": _app_envs("app-sync")})
        elif app == "app-object":
            h._send(200, {"message": "no data here"})
        else:
            h._send(200, table)
        return True

    if env_uuid is not None:
        if method != "DELETE":
            h._send(405, {"message": "method not allowed"})
            return True
        JOURNAL.setdefault(app, []).append(["DELETE", env_uuid])
        if env_uuid == "env-journal":
            j = JOURNAL[app]
            digest = hashlib.sha256(json.dumps(j, separators=(",", ":"),
                                               ensure_ascii=False).encode()).hexdigest()[:16]
            h._send(422, {"journal": len(j), "sha": digest})
        elif env_uuid == "env-broken":
            h._send(500, {"message": "Server Error"})
        elif env_uuid not in [e["uuid"] for e in _app_envs(app) if isinstance(e, dict)]:
            h._send(404, {"message": "env not found"})
        else:
            h._send(200, {"message": "Environment variable deleted."})
        return True

    try:
        doc = json.loads(body or b"null")
    except ValueError:
        h._send(422, {"message": "body is not JSON"})
        return True
    if not isinstance(doc, dict):
        h._send(422, {"message": "body is not an object"})
        return True

    # --- the two creates ---------------------------------------------------
    if app in ("dockercompose", "private-github-app") and sub == "":
        if method != "POST":
            h._send(405, {"message": "method not allowed"})
            return True
        if app == "dockercompose":
            if set(doc) != COOLIFY_COMPOSE_FIELDS or not all(isinstance(v, str) for v in doc.values()):
                h._send(422, {"message": "bad compose body"})
                return True
            compose = _b64_strict(doc["docker_compose_raw"])
            if compose is None:
                h._send(422, {"message": "docker_compose_raw is not padded base64"})
                return True
            name = doc["name"]
            if name == "echo":
                h._send(422, {"compose": compose, "project": doc["project_uuid"],
                              "server": doc["server_uuid"], "sha": sha})
                return True
            prefix = "dc-"
        else:
            if (set(doc) != COOLIFY_GITHUB_FIELDS or not isinstance(doc["instant_deploy"], bool)
                    or not all(isinstance(v, str) for k, v in doc.items() if k != "instant_deploy")
                    or doc["environment_name"] != "production"):
                h._send(422, {"message": "bad github body"})
                return True
            name = doc["name"]
            if name == "echo":
                h._send(422, {"sha": sha, "instant_deploy": doc["instant_deploy"],
                              "base_directory": doc["base_directory"],
                              "watch_paths": doc["watch_paths"],
                              "git_branch": doc["git_branch"]})
                return True
            prefix = "gh-"
        if name in COOLIFY_CREATE_SCENARIOS:
            status, payload = COOLIFY_CREATE_SCENARIOS[name]
            if isinstance(payload, bytes):
                h._send_raw(status, payload)
            else:
                h._send(status, payload)
            return True
        h._send(201, {"uuid": prefix + name})
        return True

    if sub == "":
        if method != "PATCH":
            h._send(405, {"message": "method not allowed"})
            return True
        if set(doc) != {"custom_labels"} or not isinstance(doc["custom_labels"], str):
            h._send(422, {"message": "custom_labels missing"})
            return True
        raw = doc["custom_labels"]
        try:
            labels = base64.b64decode(raw, validate=True).decode()
        except ValueError:
            h._send(422, {"message": "custom_labels is not base64"})
            return True
        # Strictness: b64decode accepts a missing pad; Go's encoder never omits it.
        if len(raw) % 4:
            h._send(422, {"message": "custom_labels is not padded"})
            return True
        if app == "app-echo":
            h._send(422, {"labels": labels, "sha": sha})
            return True
        h._send(200, {"uuid": app})
        return True

    if method not in ("POST", "PATCH"):
        h._send(405, {"message": "method not allowed"})
        return True
    if (set(doc) != COOLIFY_ENV_FIELDS or not isinstance(doc["key"], str)
            or not isinstance(doc["value"], str) or doc["is_preview"] is not False
            or doc["is_buildtime"] is not app.startswith("gh-") or doc["is_literal"] is not True):
        h._send(422, {"message": "bad env body"})
        return True
    key = doc["key"]
    JOURNAL.setdefault(app, []).append([method, key, doc["value"], doc["is_buildtime"]])
    echo = {"echo": {"method": method, "key": key, "value": doc["value"]}, "sha": sha}
    held = {e["key"] for e in _app_envs(app) if isinstance(e, dict) and not e["is_preview"]}
    if method == "POST":
        if key.startswith(("EXISTS_", "GONE_")) or key in held:
            h._send(409, {"message": "env already exists"})
        elif key.startswith("BROKEN_"):
            h._send(500, {"message": "Server Error"})
        elif key.startswith("ECHO_"):
            h._send(422, echo)
        else:
            h._send(201, {"uuid": "env-" + key.lower()})
        return True
    if key.startswith("GONE_"):
        h._send(404, {"message": "env not found"})
    elif key.startswith("EXISTS_ECHO_"):
        h._send(422, echo)
    else:
        h._send(201, {"uuid": "env-" + key.lower()})
    return True


def _bulk(project):
    """The bulk set a project reads: "__ALL__@<project>" when the corpus gives
    that project one of its own (`coolproj`, the Coolify sync cases), else the
    shared "__ALL__"."""
    return SCRIPT.get("__ALL__@" + project) or SCRIPT.get(
        "__ALL__", (404, {"error": "KEY_NOT_FOUND"}))


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_PATCH(self):
        body = self._drain()
        if _coolify(self, "PATCH", self.path, body):
            return
        return self._send(404, {"error": "NO_ROUTE"})

    def _drain(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n)

    def do_GET(self):
        if _coolify(self, "GET", self.path, self._drain()):
            return
        # GET /v1/whoami — principal + gruplar + efektif grant'ler.
        #
        # AYNI ROTA IKI MUSTERIYE HIZMET EDIYOR ve ikisi de bilincli:
        #   * `wapps whoami` govdeyi OKUYOR ve satir satir basiyor;
        #   * `secrets status` yalnizca BIR YANIT geldigine bakiyor (Go
        #     HERHANGI bir HTTP yanitini — 401 dahil — "online" sayiyor,
        #     yalnizca tasima hatasi offline demek) ve basliksiz cagiriyor,
        #     yani DAIMA varsayilan senaryoyu alir.
        if self.path == "/v1/whoami":
            status, payload = WHOAMI.get(
                self.headers.get("cf-access-token") or "", WHOAMI["__default__"])
            return self._send(status, payload)

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
        status, payload = _bulk(unquote(m.group(1)))
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
        if _coolify(self, "POST", self.path, body):
            return

        # POST /v1/token — kisa omurlu makine jetonu (`token exchange`).
        #
        # BU ROTA BILEREK MUSKUL ve muskulluk GOVDEDE: donen jeton istemcinin
        # GONDERDIGI kapsamdan URETILIYOR, sabit degil. Yani yanlis bir proje,
        # eksik bir anahtar, gonderilmeyen bir `--ttl` ya da `--verb` FARKLI
        # bir jeton baytina cikar ve differential'da GORUNUR. Sabit bir jeton
        # donseydi `--key`in tekrarlanabilirligi de `--ttl`in tel'e binmesi de
        # HIC olculmezdi.
        #
        # UC RET GATE'E AIT, ISTEMCIYE DEGIL, ve bu OLCULDU: Go ne `--ttl`i ne
        # `--verb`i dogruluyor — ikisini de oldugu gibi tel'e koyuyor. Sinirlar
        # burada durunca "istemci dogrulamiyor" iddiasi da olculebilir hale
        # geliyor: dogrulayan bir port gate'in reddini HIC gormezdi.
        #
        # BASILAN JETON JWT-BICIMLI (uc base64url segment) ve bu bir susleme
        # DEGIL bir OLCU: safelog'un JWT deseni tam olarak bu sekli
        # `[REDACTED]` yapiyor. Jeton STDOUT'a HAM basildigi icin vaka,
        # stdout yolunun redaksiyondan GECMEDIGINI de olcer — bir gun biri
        # onu zarf yoluna baglarsa bu vakalarin hepsi ayrisir.
        if self.path == "/v1/token":
            scenario = TOKEN_SCENARIOS.get(
                self.headers.get("CF-Access-Client-Id") or "")
            if scenario:
                return self._send(scenario[0], scenario[1])
            try:
                doc = json.loads(body or b"{}") or {}
            except ValueError:
                return self._send(400, {"error": "MALFORMED_TOKEN_REQUEST"})
            scope = doc.get("scope")
            if not isinstance(doc.get("project"), str) or not isinstance(scope, dict):
                return self._send(400, {"error": "MALFORMED_TOKEN_REQUEST"})
            keys, verbs = scope.get("keys"), scope.get("verbs")
            if not isinstance(keys, list) or not keys:
                return self._send(400, {"error": "EMPTY_SCOPE"})
            if not isinstance(verbs, list) or any(v not in TOKEN_VERBS for v in verbs):
                return self._send(400, {"error": "BAD_VERB"})
            ttl = doc.get("ttl_seconds")
            if ttl is not None and (not isinstance(ttl, int) or ttl > TOKEN_TTL_MAX):
                return self._send(400, {"error": "TTL_TOO_LONG"})
            claim = json.dumps({"project": doc["project"], "keys": keys,
                                "verbs": verbs, "ttl": ttl},
                               separators=(",", ":"), sort_keys=True).encode()
            payload = base64.urlsafe_b64encode(claim).decode().rstrip("=")
            token = ("eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3Qta2lkIn0."
                     + payload + ".c2lnbmF0dXJlLXBsYWNlaG9sZGVyLW5vdC1hLXNlY3JldA")
            return self._send(200, {"token": token, "exp": TOKEN_EXP})

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
            # `__DIGEST__` in the set: refuse with a 409 whose code digests
            # the intent header and every value received. A successful import
            # prints only a COUNT, so this is the one way a case can see WHAT
            # went out (`secrets sync` stringifies tofu values and merges
            # sources) and that the write was tagged `X-Wapps-Intent: sync`.
            # Only a digest is printed — never a value.
            if "__DIGEST__" in vals:
                intent = self.headers.get("X-Wapps-Intent") or "none"
                canon = json.dumps(vals, sort_keys=True, separators=(",", ":"))
                h = hashlib.sha256((intent + "\n" + canon).encode()).hexdigest()[:16]
                return self._send(409, {"error": f"DIGEST-{intent}-{h}"})
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
        status, payload = _bulk(unquote(m.group(1)))
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
        body = self._drain()
        if _coolify(self, "DELETE", self.path, body):
            return
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
        self._send_raw(status, json.dumps(obj).encode())

    def _send_raw(self, status, raw):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

if __name__ == "__main__":
    SCRIPT.update({k: tuple(v) for k, v in json.loads(sys.argv[2]).items()})
    HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
