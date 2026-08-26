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
