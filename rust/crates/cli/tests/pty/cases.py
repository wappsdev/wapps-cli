# Differential VAKALARI. Her vaka: ad, argv, ek env.
# GERCEK SIR YOK: gate'in dondugu degerler bu dosyada yazili test dizeleri.
GATE_SCRIPT = {
    "PLAIN_KEY":  [200, {"epoch": 7, "values": {"PLAIN_KEY": "value-for-plain"}}],
    "ANGLE<K>EY": [200, {"epoch": 7, "values": {"ANGLE<K>EY": "val-<tag>-&-amp"}}],
    "DENIED_KEY": [403, {"error": "GRANT_DENIED", "key": "DENIED_KEY", "dimension": "env"}],
    "GONE_KEY":   [404, {"error": "KEY_NOT_FOUND", "key": "GONE_KEY"}],
    "BIG_KEY":    [413, {"error": "RESPONSE_TOO_LARGE"}],
    "AUDIT_KEY":  [503, {"error": "AUDIT_UNAVAILABLE"}],
    "IDENT_KEY":  [503, {"error": "IDENTITY_UNAVAILABLE"}],
    "MISCFG_KEY": [503, {"error": "WHATEVER_ELSE"}],
    "RATE_KEY":   [429, {"error": "RATE_LIMITED"}],
    "CONFLICT_KEY":[409, {"error": "MIGRATION_FREEZE"}],
    "EPOCH_KEY":  [412, {"error": "EPOCH_CONFLICT"}],
    "BADREQ_KEY": [400, {"error": "MALFORMED"}],
    "TEAPOT_KEY": [418, {"error": "TEAPOT"}],
    "UNAUTH_KEY": [401, {"error": "NO_SESSION"}],
    "MISSING_VAL":[200, {"epoch": 7, "values": {}}],
}

# set --from-file fikstur dosyalari. GERCEK SIR YOK: bunlar uydurma test
# dizeleri. Dosya ADI ve UZUNLUK differential'a girer, deger GIRMEZ (basari
# satiri yalnizca anahtar adi + proje basiyor).
FIXTURE_FILES = {
    "plain.txt":    "file-sourced-test-string",
    # Sondaki newline SOYULUYOR (trimTrailingNewline) — `printf %s > f` yerine
    # `echo > f` yazan operator ayni degeri yazmis olsun diye.
    "trailing.txt": "file-sourced-test-string\n",
    # Bos dosya -> "empty value rejected".
    "empty.txt":    "",
    # YALNIZCA newline -> soyulunca bos kalir -> ayni ret.
    "newline.txt":  "\n",
}

AGENT = {"CLAUDECODE": "1"}          # pty'de stdin TTY ama ajan isareti VAR
HUMAN = {"WAPPS_AGENT_MODE": "0"}    # override YALNIZCA TTY'de onurlandirilir
P = ["--project", "testproj"]

# Bir vaka 3 ya da 4 elemanli: (ad, argv, ek_env[, pin_dosyasi_tohumu]).
# Tohum verilirse XDG_CONFIG_HOME/wapps/epochs.json kosumdan ONCE bu baytlarla
# yazilir; verilmezse dizin silinir (pin YOK). Her iki ikili de AYNI baytlari
# okur, ve kosumdan SONRA dosyanin son hali de karsilastirilir.
def pinfile(epoch, project="testproj"):
    """Go'nun json.MarshalIndent(p, "", "  ") ciktisi — sonda newline YOK.
    Bicim tahmin edilmedi, Go ikilisinden sahte gate ile OLCULDU."""
    return ('{\n  "schema": "wapps-epoch-pins/v1",\n  "pins": {\n'
            '    "%s": %d\n  }\n}' % (project, epoch))

def h(name, key): return (f"human_{name}", P + ["secrets", "get", key], HUMAN)
def a(name, key): return (f"agent_{name}", P + ["secrets", "get", key], AGENT)
def hp(name, key, pins): return (f"human_{name}", P + ["secrets", "get", key], HUMAN, pins)

# DIFFERENTIAL DISI BIRAKILAN IKI VAKA — sessizce atlanmiyor, BURADA yaziliyor:
#
#  agent_unknown_subcommand: `wapps secrets nosuchverb`. cobra, alt komutu olan
#      ve kendi Run'i olmayan bir komutta YARDIMI basip 0 ile cikiyor. Rust
#      tarafi zarf basip 1 ile cikiyor. Bunu esitlemek `secrets`in 14 alt
#      komutunun tamamini ve cobra'nin yardim duzenini port etmek demek — bu
#      dilimin kapsami `secrets get`, tum CLI degil. ACIK bir ayrisma olarak
#      raporlaniyor.
#
#  human_gate_down: tasima hatasi metni. Go, net/http'nin hata dizesini
#      ("Post \"...\": dial tcp ...: connect: connection refused") mesaja
#      gomuyor; ureq kendi dizesini gomuyor. Kod (NETWORK_REQUIRED), onek
#      ("secrets gate unreachable: "), kurtarma satiri ve cikis kodu EŞIT;
#      ayrisan tek sey isletim sistemi seviyesindeki ayrinti. Go'nun hata
#      dizesini elle taklit etmek sahte bir sadakat olurdu.
EXCLUDED = {"agent_unknown_subcommand", "human_gate_down"}

CASES = [
    # --- ajan modu: ZARF yolu (tek satir JSON, stderr) ---
    a("refuses_get", "PLAIN_KEY"),
    a("refuses_angle_key", "ANGLE<K>EY"),
    ("agent_missing_arg",   P + ["secrets", "get"],            AGENT),
    ("agent_too_many_args", P + ["secrets", "get", "A", "B"],  AGENT),
    # clap/cobra BAYRAK hatalari: kullanicinin kontrol ettigi metin ZARFA girer.
    # <,> ve & kacisinin gercekten erisilebilir oldugu yer burasi.
    ("agent_unknown_flag",       P + ["secrets", "get", "--bogus"],   AGENT),
    ("agent_unknown_flag_angle", P + ["secrets", "get", "--<a>&b"],   AGENT),
    ("agent_unknown_subcommand", P + ["secrets", "nosuchverb"],       AGENT),

    # --- insan modu: gate yolu (Error: + kurtarma satiri) ---
    h("reads_value", "PLAIN_KEY"),
    h("reads_angle_value", "ANGLE<K>EY"),
    h("grant_denied", "DENIED_KEY"),
    h("not_found", "GONE_KEY"),
    h("response_too_big", "BIG_KEY"),
    h("audit_unavailable", "AUDIT_KEY"),
    h("identity_unavailable", "IDENT_KEY"),
    h("service_miscfg", "MISCFG_KEY"),
    h("rate_limited", "RATE_KEY"),
    h("cas_conflict", "CONFLICT_KEY"),
    h("epoch_conflict", "EPOCH_KEY"),
    h("bad_request", "BADREQ_KEY"),
    h("unexpected_status", "TEAPOT_KEY"),
    h("unauthorized", "UNAUTH_KEY"),
    h("value_missing", "MISSING_VAL"),
    ("human_missing_arg",   P + ["secrets", "get"],           HUMAN),
    ("human_unknown_flag",  P + ["secrets", "get", "--bogus"], HUMAN),
    ("human_no_session",    P + ["secrets", "get", "PLAIN_KEY"], dict(HUMAN, WAPPS_SESSION_TOKEN="")),
    ("agent_no_session",    P + ["secrets", "get", "PLAIN_KEY"], dict(AGENT, WAPPS_SESSION_TOKEN="")),
    ("human_gate_down",     P + ["secrets", "get", "PLAIN_KEY"], dict(HUMAN, WAPPS_SECRETS_GATE="http://127.0.0.1:1")),

    # --- epoch pinning: bir DAVRANIS degil bir REDDETME ---
    # PLAIN_KEY 7. epoch'u sunuyor. Pin dosyasi kosumdan once tohumlanarak
    # rollback saldirisi (sunulan < pinli) ve mesru ilerleme ayni gate ile
    # olculuyor. Pin dosyasinin SON HALI de bayt-bayt karsilastiriliyor: bir
    # ikili reddedip pin'i yine de geri sarsaydi cikti esit gorunurdu.
    hp("epoch_downgrade_refused", "PLAIN_KEY", pinfile(9)),
    hp("epoch_advances_pin",      "PLAIN_KEY", pinfile(3)),
    hp("epoch_equal_is_accepted", "PLAIN_KEY", pinfile(7)),
    hp("epoch_of_another_project_is_untouched", "PLAIN_KEY",
       '{\n  "schema": "wapps-epoch-pins/v1",\n  "pins": {\n'
       '    "otherproj": 42,\n    "testproj": 3\n  }\n}'),

    # --- safelog redaksiyonu ---
    # Bayrak adi KULLANICININ kontrolunde ve dogrudan zarfin `message` alanina
    # giriyor. Buradaki dizeler uydurma BICIM ornekleri; gercek anahtar DEGIL.
    ("agent_redacted_token_flag", P + ["secrets", "get", "--AKIAIOSFODNN7EXAMPLEZZ12"], AGENT),
    ("agent_redacted_jwt_flag",
     P + ["secrets", "get",
          "--eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"], AGENT),
    # ASIMETRI PINI: Go'nun INSAN yolu RedactPatterns'tan gecmiyor. Iki tarafi
    # da redakte eden bir "duzeltme" sahadaki ikiliyle ayrisirdi; bu vaka onu
    # yakalar.
    ("human_unredacted_token_flag", P + ["secrets", "get", "--AKIAIOSFODNN7EXAMPLEZZ12"], HUMAN),
]


# --- `secrets set` ----------------------------------------------------------
#
# set'in get'ten AYRILDIGI uc yer, ve her birinin burada bir vakasi var:
#
#  1. AJAN MODU SERBEST. set'in politikasi `allow` (get'inki `refuse_agent`).
#     Yani ajan yolu Guard'i GECIYOR ve bir sonraki kapiya — repo->proje
#     baglamasina — dusuyor. `--project <ad>` + ajan = BINDING_UNPINNED. Bu
#     kapi get icin ERISILEMEZDI (Guard once reddediyordu), yani bu portun
#     ILK kez olctugu kod yolu.
#  2. DEGER YAKALAMA. --from-file ya da YANKISIZ prompt. Prompt dali bir TTY
#     istiyor; pty olmadan olculemez (borulu bir kosum non-TTY dalina duser).
#  3. YAZMA ROTASI. PUT /keys/{KEY}; hata baglami "set <KEY>" (get'te
#     "read <proje>").
#
# EPOCH PIN: Set epoch pin'ine DOKUNMAZ (Go'da yalnizca Keys/Read
# checkAndAdvanceEpochPin cagiriyor). Pin dosyasi differential'in dorduncu
# karsilastirilan alani oldugu icin, bir tarafin yazim sirasinda pin'i
# oynatmasi burada gorunur.
def s_h(name, argv, stdin=None):
    return (f"human_set_{name}", P + ["secrets", "set"] + argv, HUMAN, None, stdin)

def s_a(name, argv, stdin=None):
    return (f"agent_set_{name}", P + ["secrets", "set"] + argv, AGENT, None, stdin)

SET_CASES = [
    # --- ajan modu: baglama kapisi (yeni kod yolu) ---
    s_a("binding_refused",           ["PLAIN_KEY", "--from-file", "{FIX}/plain.txt"]),
    # Ajan reddi deger YAKALAMADAN ONCE olmali: var olmayan bir dosya versek
    # bile hata BINDING_UNPINNED kalmali, "read --from-file" DEGIL. Sira
    # bozulursa (once dosya okunursa) bu vaka ayrisir.
    s_a("binding_refused_before_file", ["PLAIN_KEY", "--from-file", "{FIX}/nope.txt"]),
    s_a("binding_refused_missing_arg", []),

    # --- insan modu: --from-file yolu ---
    s_h("from_file",                 ["PLAIN_KEY", "--from-file", "{FIX}/plain.txt"]),
    s_h("from_file_trailing_newline",["PLAIN_KEY", "--from-file", "{FIX}/trailing.txt"]),
    s_h("from_file_empty",           ["PLAIN_KEY", "--from-file", "{FIX}/empty.txt"]),
    s_h("from_file_only_newline",    ["PLAIN_KEY", "--from-file", "{FIX}/newline.txt"]),

    # --- insan modu: YANKISIZ prompt (pty'nin varlik sebebi) ---
    # Yazilan baytlar stdin pty'sine gidiyor; ECHO kapali oldugu icin ciktiya
    # GERI YANKILANMAMALI. Yankilansaydi deger stdout/stderr hex'ine girerdi ve
    # bu vaka onu gosterirdi.
    s_h("prompt_tty",        ["PLAIN_KEY"], b"prompted-test-string\n"),
    s_h("prompt_empty",      ["PLAIN_KEY"], b"\n"),
    # \r ICRNL ile \n'e cevrilir; ReadPassword ikisinde de satiri bitirir.
    s_h("prompt_cr",         ["PLAIN_KEY"], b"prompted-test-string\r"),
    # \b (backspace) ReadPassword'un dongusunde son bayti SILER.
    s_h("prompt_backspace",  ["PLAIN_KEY"], b"prompted-test-stringX\b\n"),

    # --- insan modu: gate hata dallari (baglam "set <KEY>") ---
    s_h("denied",            ["DENIED_KEY",   "--from-file", "{FIX}/plain.txt"]),
    s_h("not_found",         ["GONE_KEY",     "--from-file", "{FIX}/plain.txt"]),
    s_h("rate_limited",      ["RATE_KEY",     "--from-file", "{FIX}/plain.txt"]),
    s_h("cas_conflict",      ["CONFLICT_KEY", "--from-file", "{FIX}/plain.txt"]),
    s_h("epoch_conflict",    ["EPOCH_KEY",    "--from-file", "{FIX}/plain.txt"]),
    s_h("unauthorized",      ["UNAUTH_KEY",   "--from-file", "{FIX}/plain.txt"]),
    s_h("audit_unavailable", ["AUDIT_KEY",    "--from-file", "{FIX}/plain.txt"]),
    s_h("bad_request",       ["BADREQ_KEY",   "--from-file", "{FIX}/plain.txt"]),
    s_h("unexpected_status", ["TEAPOT_KEY",   "--from-file", "{FIX}/plain.txt"]),

    # --- arite + bayrak hatalari ---
    s_h("missing_arg",   []),
    s_h("too_many_args", ["A", "B"]),
    s_h("unknown_flag",  ["PLAIN_KEY", "--bogus"]),

    # --- oturum yoklugu: istek aga HIC cikmamali ---
    ("human_set_no_session", P + ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None),

    # --- epoch pin'e DOKUNULMADIGININ kaniti ---
    # Pin 3'te tohumlanip basarili bir yazim yapiliyor. Gate 7. epoch'u
    # "sunuyor" ama set okuma yapmadigi icin pin 3'te KALMALI. Bir taraf
    # yazim yolunda pin'i ilerletseydi dorduncu alan ayrisirdi.
    ("human_set_leaves_pin_alone",
     P + ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, pinfile(3), None),

    # --- --project YOKKEN: config kapisi ---
    # Bu iki vaka SIRAYI pinliyor. Go'da baglama kontrolu (PersistentPreRunE)
    # RunE'den ONCE kosuyor ama `--project` bossa ve ortada .wapps.yaml YOKSA
    # sessizce geciyor; ret bir adim sonra, storeProject'ten "no .wapps.yaml
    # found" olarak geliyor. Yani AJAN modunda bile burada BINDING_UNPINNED
    # DEGIL NOT_FOUND bekleniyor — bu portun kolayca yanlis yapabilecegi yer.
    # (probe cwd'yi workdir'e sabitliyor; orada .wapps.yaml yok.)
    ("human_set_no_project", ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, None, None),
    ("agent_set_no_project", ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     AGENT, None, None),

    # --from-file YOK: dosya sistemi hata metni. Go'nun *PathError'i
    # "open <yol>: no such file or directory" basiyor; Rust'in std hatasi
    # "No such file or directory (os error 2)". Bu POSIX dizesi ELDE
    # uretiliyor (bkz. src/setverb.rs) — Go'nun ic hata tablosunu taklit
    # etmek degil, AYNI mesaji yazmak.
    s_h("from_file_missing", ["PLAIN_KEY", "--from-file", "{FIX}/nope.txt"]),
]

CASES += SET_CASES
