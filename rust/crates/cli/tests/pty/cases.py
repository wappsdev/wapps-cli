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
    # BULK READ (bos anahtar listesi) — exec ve apply bu yolu kullaniyor.
    # Degerler UYDURMA test dizeleri; gercek sir DEGIL. Uzunluklar bilincli:
    # SCRUB_FLOOR'un (4) USTUNDE olanlar scrubber'a girer, ALTINDA olan
    # ("ab") giremez ve "atlandi" uyarisini tetikler — ikisi de olculuyor.
    "__ALL__": [200, {"epoch": 7, "values": {
        "ALPHA": "alpha-test-value-long",
        "BETA": "beta-test-value-long",
        "TINY": "ab",
    }}],
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
    # `tofu` SHIM'i — bir fikstur DEGIL bir PROGRAM (probe.py `#!` ile
    # baslayani 0755 yazar). `wapps tofu` argv[0]'i "tofu" olarak sabitliyor,
    # yani bu shim olmadan cocuk HIC kosmaz ve sarimin tek gercek vaadi
    # olculemez: degerleri VERBATIM enjekte etmesi.
    #
    # Uc sey basiyor ve ucu de sozlesmenin bir parcasi:
    #   1. argv — `plan -target=...` cocuga AYNEN gecti mi;
    #   2. ALPHA — store anahtari FINAL adiyla mi geldi (scrubber onu ***
    #      yapar, yani gorunen sey adin VARLIGI, degeri degil);
    #   3. TF_VAR_ALPHA — EKLENMEMIS olmali. Prefix "" yerine "TF_VAR_"
    #      olsaydi bu iki satir YER DEGISTIRIRDI, ve v0.23.0'da olan tam
    #      olarak buydu.
    #
    # `output -json` is the one argv `secrets sync` runs (a `tofu` source). It
    # prints `tofu-output.json` from its OWN cwd, so the case only passes if
    # the binary ran it in the source's workdir; a missing file fails with a
    # message on stderr that must never reach the terminal (Go discards it).
    "tofu": ("#!/bin/sh\n"
             "if [ \"$1 $2\" = \"output -json\" ]; then\n"
             "  cat tofu-output.json || exit 1\n"
             "  exit 0\n"
             "fi\n"
             "echo \"argv: $*\"\n"
             "echo \"ALPHA=${ALPHA-<unset>}\"\n"
             "echo \"TF_VAR_ALPHA=${TF_VAR_ALPHA-<unset>}\"\n"
             "exit 3\n"),
    # `cloudflared` SHIM — a program, written 0755 like the `tofu` one. `wapps
    # login` resolves "cloudflared" on PATH and runs it twice; this shim makes
    # both runs observable without a browser or a network:
    #   * `access login` prints its argv (`--quiet` must be there, the gate
    #     must be the read or the admin URL) and reports the ISOLATION it was
    #     given: HOME under the temp dir with the `wapps-cf-` prefix, every
    #     XDG/Windows home pinned to it, TUNNEL_*/CLOUDFLARED_* dropped. It
    #     records the gate in the isolated home;
    #   * `access token` fails unless it sees the SAME home and `-app=<that
    #     gate>`, writes the token to STDERR first (a leak canary — that stream
    #     must be discarded), then prints CF_SHIM_TOKEN on stdout.
    # CF_SHIM_LOGIN_EXIT / CF_SHIM_TOKEN_EXIT drive the failure branches.
    "cloudflared": ("#!/bin/sh\n"
                    "case \"$1 $2\" in\n"
                    "\"access login\")\n"
                    "  echo \"cloudflared $*\"\n"
                    "  case \"$HOME\" in\n"
                    "    \"${TMPDIR:-/tmp}\"/wapps-cf-*) echo 'home: isolated under the temp dir' ;;\n"
                    "    *) echo 'home: NOT isolated' ;;\n"
                    "  esac\n"
                    "  for v in XDG_CONFIG_HOME XDG_CACHE_HOME XDG_DATA_HOME USERPROFILE APPDATA LOCALAPPDATA; do\n"
                    "    eval \"x=\\${$v-}\"; [ \"$x\" = \"$HOME\" ] || echo \"$v: NOT pinned\"\n"
                    "  done\n"
                    "  echo \"overrides: TUNNEL_TRANSPORT=${TUNNEL_TRANSPORT-<unset>} CLOUDFLARED_HOME=${CLOUDFLARED_HOME-<unset>}\"\n"
                    "  printf '%s' \"$4\" > \"$HOME/.cf-gate\"\n"
                    "  exit \"${CF_SHIM_LOGIN_EXIT:-0}\" ;;\n"
                    "\"access token\")\n"
                    "  printf '%s\\n' \"$CF_SHIM_TOKEN\" >&2\n"
                    "  [ \"$3\" = \"-app=$(cat \"$HOME/.cf-gate\" 2>/dev/null)\" ] || exit 8\n"
                    "  printf '%s\\n' \"$CF_SHIM_TOKEN\"\n"
                    "  exit \"${CF_SHIM_TOKEN_EXIT:-0}\" ;;\n"
                    "esac\n"
                    "exit 99\n"),
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

    # --- epoch pin'i YAZIM yolunda da ILERLIYOR ---
    # Bu vaka eskiden "human_set_leaves_pin_alone" idi ve pin'in 3'te KALMASINI
    # bekliyordu; gerekcesi "bir yazim sunulan bir epoch OKUMUYOR" idi. Bu
    # OLCULDU ve YANLIS cikti: commit yaniti epoch tasiyor (writer-do.ts), yani
    # `set` epoch'u aliyor ve eskiden ATIYORDU.
    #
    # Pin 3'te tohumlaniyor, gate 7 sunuyor -> pin 7'ye ILERLEMELI (dorduncu
    # alan pin dosyasinin son baytlari).
    #
    # DIKKAT — bu vakanin TEK BASINA kanitlayabilecegi sey SINIRLI: iki ikili
    # de ayni anda degisti, yani DIFFERENT=0 hem duzeltmeden ONCE hem SONRA.
    # Karsilastirma bu kusuru bulamaz. Bulan sey, iki taraftaki IDDIA testleri:
    # Go'da TestSet_EpochDowngradeTripwire, Rust'ta storewire.rs'teki iki vaka.
    ("human_set_advances_the_pin",
     P + ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, pinfile(3), None),

    # GERI SARILMIS store'a yazim: pin 9, gate 7 sunuyor -> EPOCH_DOWNGRADE.
    # Yazim tarafinin rollback tripwire'i; okuma tarafindaki karsiligi
    # `human_get_*` pin vakalari.
    ("human_set_onto_a_rolled_back_store",
     P + ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, pinfile(9), None),
    ("agent_set_onto_a_rolled_back_store",
     P + ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     AGENT, pinfile(9), None),

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


# --- `secrets exec` ve `secrets apply` --------------------------------------
#
# Bu iki verb, ONCEKI dilimde OLCULEREK portlanmamis birakilmisti: onlerinde iki
# portlanmamis altsistem duruyordu (`.wapps.yaml` yukleme+dogrulama ve baglama
# pin defteri). Bu dilim ikisini de indirdi, ve asagidaki vakalar o iki kapinin
# ARTIK IKI IKILIDE DE AYNI davrandigini olcuyor.
#
# CONFIG TOHUMU (6. eleman): {"yaml": ..., "files": {...}} verilen vakalar KENDI
# dizinlerinde kosar. Verilmeyenler workdir'de kosar — orada `.wapps.yaml` YOK.

VALID_CFG = "version: 2\nproject: testproj\n"
CFG_TARGETS = VALID_CFG + "targets:\n  - path: .env.local\n"

def cfg(yaml, files=None):
    return {"yaml": yaml, "files": files or {}}

def e_h(name, argv, stdin=None, seedcfg=None):
    return (f"human_exec_{name}", P + ["secrets", "exec"] + argv, HUMAN, None, stdin, seedcfg)

def e_a(name, argv, stdin=None, seedcfg=None):
    return (f"agent_exec_{name}", P + ["secrets", "exec"] + argv, AGENT, None, stdin, seedcfg)

# Cocuk komut: PATH "/usr/bin:/bin" ile sinirli, o yuzden /bin/sh kullaniliyor.
ECHO_ALPHA = ["--", "/bin/sh", "-c", "echo $ALPHA"]

EXEC_APPLY_CASES = [
    # === KAPI 1: `--project` config gereksinimini ATLATMIYOR ===============
    # Onceki dilimin tests/verbgates.rs'te pinledigi kapi. Insan yolunda
    # baglama gecer (ciplak --project bir insan icin acik hedef beyanidir) ve
    # ret bir adim sonra requireStoreConfig'ten NOT_FOUND olarak gelir.
    ("human_exec_project_flag_no_config",
     P + ["secrets", "exec"] + ECHO_ALPHA, HUMAN, None, None, None),
    ("human_apply_project_flag_no_config",
     P + ["secrets", "apply"], HUMAN, None, None, None),
    # Ajan yolunda ayni cagri DAHA ONCE, baglama kapisinda duser:
    # BINDING_UNPINNED, NOT_FOUND DEGIL. Sira gozlemlenebilir.
    ("agent_exec_project_flag_no_config",
     P + ["secrets", "exec"] + ECHO_ALPHA, AGENT, None, None, None),
    ("agent_apply_project_flag_no_config",
     P + ["secrets", "apply"], AGENT, None, None, None),

    # === KAPI 2: config VAR, `--project` YOK → baglama ====================
    # --- KENDI .wapps.yaml'I OLAN bir dizinden `set` ---
    #
    # BU BIR KOR NOKTAYDI ve olcerek bulundu: yukaridaki set vakalarinin
    # HEPSI ya `--project testproj` veriyor ya da .wapps.yaml'I OLMAYAN
    # workdir'de kosuyor. Yani `set`in config COZUMU HIC gezilmemisti, ve
    # gezilmedigi icin su ayrisma yesil bir gate'in altinda duruyordu:
    #
    #   Go   -> BINDING_UNPINNED ("repo->project binding ... is not pinned")
    #   Rust -> NOT_FOUND        ("set: no .wapps.yaml found")
    #
    # Go .wapps.yaml'i OKUYUP baglama kapisina variyordu; Rust dosyaya HIC
    # bakmadan dusuyordu. exec/apply'in AYNI vakalari (agent_exec_config_
    # unpinned, human_exec_binding_accepted) zaten vardi — eksik olan set'ti.
    ("agent_set_config_unpinned",
     ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     AGENT, None, None, cfg(VALID_CFG)),
    ("human_set_binding_declined",
     ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, None, b"n\n", cfg(VALID_CFG)),
    ("human_set_binding_accepted",
     ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),

    # Ajan: pinsiz baglama fail-closed. Uydurulmus bir .wapps.yaml kendi basina
    # bir proje TALEP EDEMEZ.
    ("agent_exec_config_unpinned",
     ["secrets", "exec"] + ECHO_ALPHA, AGENT, None, None, cfg(VALID_CFG)),
    ("agent_apply_config_unpinned",
     ["secrets", "apply"], AGENT, None, None, cfg(CFG_TARGETS)),
    # Insan + TTY: SATIR ICI onay. "n" → reddedildi, pin YAZILMAMALI.
    ("human_exec_binding_declined",
     ["secrets", "exec"] + ECHO_ALPHA, HUMAN, None, b"n\n", cfg(VALID_CFG)),
    # Bos cevap da ret (varsayilan [y/N]).
    ("human_exec_binding_default_is_no",
     ["secrets", "exec"] + ECHO_ALPHA, HUMAN, None, b"\n", cfg(VALID_CFG)),
    # "y" → PINLENIR ve verb devam eder. repo-pins.json bayt-bayt
    # karsilastiriliyor: bir ikili reddedip yine de pinleseydi burada gorunurdu.
    ("human_exec_binding_accepted",
     ["secrets", "exec"] + ECHO_ALPHA, HUMAN, None, b"y\n", cfg(VALID_CFG)),
    ("human_apply_binding_accepted",
     ["secrets", "apply"], HUMAN, None, b"y\n", cfg(CFG_TARGETS)),

    # === exec'in KENDI kapilari ==========================================
    # --break-glass ajan modunda HARD-REFUSED (§7.4.2).
    ("agent_exec_break_glass",
     P + ["secrets", "exec", "--break-glass"] + ECHO_ALPHA, AGENT, None, None, None),
    # --intent deploy: sessiz no-op yerine FAIL LOUD — deploy guvenlik yuzeyi
    # islevsel sanilmasin.
    ("human_exec_intent_deploy",
     P + ["secrets", "exec", "--intent", "deploy"] + ECHO_ALPHA, HUMAN, None, None, None),
    ("human_exec_unknown_intent",
     P + ["secrets", "exec", "--intent", "wat"] + ECHO_ALPHA, HUMAN, None, None, None),
    # --break-glass insan yolunda da ACTION_UNAVAILABLE'a dusuyor.
    ("human_exec_break_glass",
     P + ["secrets", "exec", "--break-glass"] + ECHO_ALPHA, HUMAN, None, None, None),
    # Arite: cobra MinimumNArgs(1).
    ("human_exec_no_argv", P + ["secrets", "exec"], HUMAN, None, None, None),
    ("agent_exec_no_argv", P + ["secrets", "exec"], AGENT, None, None, None),

    # === apply'in KENDI kapilari =========================================
    # Hedef bildirilmemis → hata (env --write tek seferlikler icin).
    ("human_apply_no_targets",
     ["secrets", "apply"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
]

# === SCRUBBER: bugune dek YALNIZCA korpusa karsi dogrulanmisti ==============
#
# scrubber.rs bir modul olarak onceki dilimde indi ama CANLI bir `exec` ICINDE
# hic kosmadi. Asagidaki vakalar onu kosturur: cocugun BASTIGI enjekte deger
# *** olmali. Olmasaydi deger stdout hex'ine girerdi ve vaka ayrisirdi.
SCRUB_CASES = [
    # Cocuk, enjekte edilen bir degeri ECHO'luyor → *** gormeliyiz.
    ("human_exec_child_echo_is_scrubbed",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # stderr de ayni scrubber'dan geciyor.
    ("human_exec_child_stderr_is_scrubbed",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $BETA 1>&2"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # Deger CHUNK SINIRINA yayilsa bile yakalanmali (rolling boundary buffer).
    ("human_exec_child_multiline_is_scrubbed",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo x$ALPHA; echo y$BETA"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # FLOOR-ALTI deger ("ab", 2 < 4) redakte EDILMEZ ve tek seferlik bir
    # sizinti notu basilir. Uyari, cocuk spawn'dan ONCE.
    ("human_exec_subfloor_value_warns",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $TINY"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # Cocugun CIKIS KODU aynen yansitilmali.
    ("human_exec_child_exit_code",
     ["secrets", "exec", "--", "/bin/sh", "-c", "exit 42"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # Var olmayan komut → "exec: ..." sarmasi. IKI SEKIL var ve hangisinin
    # ciktigi ADIN icinde egik cizgi olup olmamasina bagli (Go, LookPath'i
    # yalnizca ayirac YOKSA yapiyor). Ikisi de olculuyor, cunku tek bir vaka
    # digerinin metnini sessizce yanlis birakirdi.
    ("human_exec_missing_command",
     ["secrets", "exec", "--", "/nonexistent/binary"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    ("human_exec_missing_command_on_path",
     ["secrets", "exec", "--", "nosuchbinary-xyz"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # --prefix enjekte edilen env ADLARINI degistirir (degerleri degil).
    ("human_exec_prefix_renames_vars",
     ["secrets", "exec", "--prefix", "TF_VAR_", "--", "/bin/sh", "-c", "echo $TF_VAR_ALPHA"],
     HUMAN, None, b"y\n", cfg(VALID_CFG)),
]

# === apply'in YAZICISI =======================================================
APPLY_WRITE_CASES = [
    # Hedef yazilir; icerik ve MOD (0600) karsilastiriliyor.
    ("human_apply_writes_target",
     ["secrets", "apply"], HUMAN, None, b"y\n", cfg(CFG_TARGETS)),
    # IDEMPOTENS: dosya zaten bayt-es → "unchanged", dosyaya DOKUNULMAZ.
    ("human_apply_unchanged_is_idempotent",
     ["secrets", "apply"], HUMAN, None, b"y\n",
     cfg(CFG_TARGETS, {".env.local": "export ALPHA='alpha-test-value-long'\n"
                                     "export BETA='beta-test-value-long'\n"
                                     "export TINY='ab'\n"})),
    # Icerik FARKLI → yeniden yazilir.
    ("human_apply_rewrites_stale_target",
     ["secrets", "apply"], HUMAN, None, b"y\n",
     cfg(CFG_TARGETS, {".env.local": "export STALE='old'\n"})),
    # Her hedef KENDI etkin onekini alir (default_prefix vs acikca bos).
    ("human_apply_per_target_prefix",
     ["secrets", "apply"], HUMAN, None, b"y\n",
     cfg("version: 2\nproject: testproj\ndefault_prefix: \"TF_VAR_\"\n"
         "targets:\n  - path: tf.env\n  - path: plain.env\n    prefix: \"\"\n")),
]

# === `.wapps.yaml` DOGRULAMASI ==============================================
#
# Go'nun REDDETTIGI her sekli Rust da reddetmeli — ve reddin METNI ayni olmali;
# bu dosyayi bir INSAN okuyor ve yanlis yapilandirilmis bir depoda elindeki tek
# ipucu o cumle. Verb olarak `apply` kullaniliyor cunku config'i o yukluyor.
def badcfg(name, yaml):
    return (f"agent_cfg_{name}", ["secrets", "apply"], AGENT, None, None, cfg(yaml))

CONFIG_CASES = [
    badcfg("version_three", "version: 3\nproject: p\n"),
    badcfg("v2_field_on_v1", "version: 1\nbackend: store\nproject: p\n"),
    badcfg("unknown_backend", "version: 2\nbackend: cloud-magic\nproject: x\n"),
    badcfg("legacy_git_backend", "version: 2\nbackend: legacy-git\nproject: x\n"),
    badcfg("no_project", "version: 2\nbackend: store\n"),
    badcfg("unknown_source_type", "version: 2\nproject: p\nsources:\n  - type: doppler\n"),
    badcfg("source_missing_type", "version: 2\nproject: p\nsources:\n  - prefix: X\n"),
    badcfg("tofu_source_with_path",
           "version: 2\nproject: p\nsources:\n  - type: tofu\n    path: .env\n"),
    badcfg("file_source_without_path",
           "version: 2\nproject: p\nsources:\n  - type: file\n"),
    badcfg("target_without_path",
           "version: 2\nproject: p\ntargets:\n  - prefix: \"TF_VAR_\"\n"),
    badcfg("target_path_traversal",
           "version: 2\nproject: p\ntargets:\n  - path: ../etc/passwd\n"),
    badcfg("duplicate_target_path",
           "version: 2\nproject: p\ntargets:\n  - path: .env.local\n  - path: .env.local\n"),
    # Bilinmeyen ust-duzey alanlar SESSIZCE atlanmali (Go yaml.v3 KnownFields
    # acik degil): sahadaki dosyalarda duran dest:/redact_in_logs: kirilmasin.
    badcfg("unknown_top_level_fields_are_ignored",
           "version: 2\nproject: testproj\ndest: secrets/all.enc.age\n"
           "redact_in_logs: true\nrequire_clean_git: true\n"),
]

CASES += EXEC_APPLY_CASES + SCRUB_CASES + APPLY_WRITE_CASES + CONFIG_CASES


# --- `list`, `status`, `rm`, `projects`, `init` ------------------------------
#
# Bu bes fiilin ORTAK sorusu — ve portun en sik ayristigi yer — su: HER FIILIN
# AJAN-MODU POLITIKASI NE, VE KAPI SIRASI NE? Cevap fiil basina FARKLI ve
# hicbiri digerinden tahmin edilemiyor. Olculdu:
#
#   fiil            ajan politikasi   baglama kapisi   config gereksinimi
#   ------------    ---------------   --------------   ------------------
#   list            allow             VAR              VAR (proje adi)
#   status          allow             MUAF             yok (hard-fail etmez)
#   rm              refuse_agent      erisilemez(*)    VAR (proje adi)
#   projects list   allow             YOK (kok mount)  VAR (kullanilmasa da!)
#   projects rm     control           YOK (kok mount)  yok
#   init            allow             VAR (yazimdan ONCE)  yok
#
#   (*) ajan kapisi once ates ettigi icin `rm`de baglama kapisi ajan yolunda
#       ERISILEMEZ — `get`teki ayni desen.
#
# En carpici ikisi:
#
#  1. `projects list` KOKTE mount'lu, yani depo→proje baglama kontrolu HIC
#     kosmuyor. Sonucu gozlemlenebilir: `--project testproj` ile AJAN modunda
#     `projects list` CALISIR, ama ayni bayrakla `secrets list`
#     BINDING_UNPINNED ile duser. Iki fiil de "yalnizca ADlar" sinifinda, ama
#     ayni kapinin arkasinda DEGILLER.
#
#  2. `rm`de ARITE ajan kapisindan ONCE kosuyor (cobra ValidateArgs,
#     PersistentPreRunE'dan once): ajan modunda eksik arguman
#     AGENT_MODE_REFUSED DEGIL bir arite hatasi veriyor.
#
# OLCULEMEYEN IKI SEY, ayrica EXCLUDED'da degil cunku vaka olarak HIC
# EKLENMEDILER — sessiz birakmamak icin burada yaziliyorlar:
#
#  * `wapps projects` (ciplak, alt komutsuz): cobra kendi yardim duzenini
#    basip 0 ile cikiyor, clap kendi duzenini. Esitlemek cobra'nin yardim
#    olusturucusunu port etmek demek — `agent_unknown_subcommand` ile AYNI
#    sinif, ayni sebeple disarida.
#
#  * `rm`in EOF (girdisiz) onay dali: bir pty ASLA EOF vermiyor, yani her iki
#    ikili de okumada bloklanip 30 sn sonra oldurulmus olarak (-9) donuyor.
#    "Esit" gorunurdu ama olculen sey bir zaman asimi olurdu, davranis degil.
#    Bos SATIR ("\n") dali olculuyor ve o gercek reddi geziyor.

def cfg_only_dir():
    """Vakaya KENDI dizinini verir ama oraya `.wapps.yaml` YAZMAZ.

    `init` icin sart: init o dosyayi URETIYOR. Ortak workdir'de kossaydi oraya
    yazar ve "config yok" dalini olcen butun diger vakalari bozardi."""
    return {"yaml": None, "files": {}}


VERB_CASES = [
    # === list ===============================================================
    # Ajan + ciplak `--project`: baglama kapisi fail-closed. `get`te bu kapi
    # ERISILEMEZDI (ajan kapisi once reddediyordu); `list` ajana serbest oldugu
    # icin buraya kadar geliyor.
    ("agent_list_project_flag",  P + ["secrets", "list"], AGENT, None, None, None),
    # Ayni cagri INSAN yolunda GECIYOR: ciplak --project bir insan icin acik
    # hedef beyanidir, pinin korudugu confused-deputy durumu degil.
    ("human_list_project_flag",  P + ["secrets", "list"], HUMAN, None, None, None),
    # Config YOK + --project YOK → baglama sessizce geciyor, ret bir adim
    # sonra storeProject'ten NOT_FOUND olarak geliyor. AJAN modunda da ayni:
    # BINDING_UNPINNED DEGIL.
    ("agent_list_no_config",     ["secrets", "list"], AGENT, None, None, None),
    ("human_list_no_config",     ["secrets", "list"], HUMAN, None, None, None),
    # Config VAR, pin YOK, ajan → fail-closed.
    ("agent_list_config_unpinned", ["secrets", "list"], AGENT, None, None, cfg(VALID_CFG)),
    # Insan + TTY: satir ici onay, "y" → pinlenir ve liste basilir.
    # repo-pins.json da karsilastiriliyor.
    ("human_list_binding_accepted", ["secrets", "list"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    ("human_list_binding_declined", ["secrets", "list"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    # cobra'da listCmd'in Args'i YOK → ArbitraryArgs: fazladan arguman SESSIZCE
    # yok sayiliyor. clap'e birakilsa "unexpected argument" ile 2 donerdi.
    ("human_list_extra_arg_is_ignored", P + ["secrets", "list", "EXTRA"], HUMAN, None, None, None),
    # GET /keys epoch pin'ini ILERLETIR (Go: WorkerStore.Keys →
    # checkAndAdvanceEpochPin). Pin 3'te tohumlaniyor, gate 7 sunuyor → 7.
    ("human_list_advances_the_epoch_pin",
     P + ["secrets", "list"], HUMAN, pinfile(3), None, None),
    # ...ve GERI SARMAZ: pin 9 iken sunulan 7 bir ROLLBACK'tir.
    ("human_list_epoch_downgrade_refused",
     P + ["secrets", "list"], HUMAN, pinfile(9), None, None),
    ("human_list_no_session",
     P + ["secrets", "list"], dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),

    # === status =============================================================
    # status HER modda ve her ag durumunda 0 ile cikar. Asagidaki vakalarin
    # HEPSI cikis 0 bekliyor; biri 1 donerse "asla hard-fail etmez" vaadi
    # kalkmis demektir.
    ("human_status",      ["secrets", "status"], HUMAN, None, None, None),
    ("agent_status",      ["secrets", "status"], AGENT, None, None, None),
    ("human_status_json", ["secrets", "status", "--json"], HUMAN, None, None, None),
    # BAGLAMA MUAFIYETININ KANITI: pinlenmemis bir config'in yaninda ajan
    # modunda. `list` ayni kosulda BINDING_UNPINNED veriyor; status 0 donmeli.
    ("agent_status_is_binding_exempt",
     ["secrets", "status"], AGENT, None, None, cfg(VALID_CFG)),
    # epoch_pin config'teki PROJE adiyla okunuyor.
    ("human_status_reports_the_pin",
     ["secrets", "status"], HUMAN, pinfile(5), None, cfg(VALID_CFG)),
    ("human_status_json_reports_the_pin",
     ["secrets", "status", "--json"], HUMAN, pinfile(5), None, cfg(VALID_CFG)),
    # Config YOKKEN proje adi "" → pin 0 (dosya dolu olsa bile).
    ("human_status_without_config_reports_no_pin",
     ["secrets", "status"], HUMAN, pinfile(5), None, None),
    # BOZUK config status'u DUSURMEZ — yalnizca pin 0 kalir. Ayni dosya
    # `apply`i yuksek sesle dusuruyor (agent_cfg_no_project).
    ("human_status_survives_a_broken_config",
     ["secrets", "status"], HUMAN, pinfile(5), None, cfg("version: 2\nbackend: store\n")),
    # Prob KAPALI → online false, deterministik (CI'da dis cagri yok).
    ("human_status_no_probe",
     ["secrets", "status"], dict(HUMAN, WAPPS_STATUS_NO_PROBE="1"), None, None, None),
    # Gate ERISILEMEZ → online false. `get`in gate_down vakasinin aksine burada
    # bir HATA METNI yok (status yutuyor), yani tasima dali metin ayrismasi
    # OLMADAN olculebiliyor — differential disi birakmaya gerek kalmiyor.
    ("human_status_gate_down",
     ["secrets", "status"], dict(HUMAN, WAPPS_SECRETS_GATE="http://127.0.0.1:1"),
     None, None, None),
    ("human_status_no_session",
     ["secrets", "status"], dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),
    # GECMISTE dolan bir oturum → gecersiz, kalan 0. Sabit bir unix damgasi
    # kullaniliyor ki olcum saate bagli OLMASIN.
    ("human_status_expired_session",
     ["secrets", "status"],
     dict(HUMAN, WAPPS_SESSION_EXPIRES="1000000000"), None, None, None),
    ("human_status_extra_arg_is_ignored",
     ["secrets", "status", "EXTRA"], HUMAN, None, None, None),

    # === rm =================================================================
    # Ajan modunda YAPISAL red: silme geri alinamaz.
    ("agent_rm_refused",  P + ["secrets", "rm", "PLAIN_KEY", "--yes"], AGENT, None, None, None),
    # ARITE, AJAN KAPISINDAN ONCE. Bu vaka o sirayi pinliyor: eksik arguman
    # AGENT_MODE_REFUSED degil bir arite hatasi vermeli.
    ("agent_rm_missing_arg_is_an_arity_error",
     P + ["secrets", "rm"], AGENT, None, None, None),
    # Ajan kapisi CONFIG kapisindan da once: config'i olmayan bir dizinde bile
    # ret AGENT_MODE_REFUSED, NOT_FOUND degil.
    ("agent_rm_refused_before_config",
     ["secrets", "rm", "PLAIN_KEY", "--yes"], AGENT, None, None, None),
    ("human_rm_yes_flag",  P + ["secrets", "rm", "PLAIN_KEY", "--yes"], HUMAN, None, None, None),
    ("human_rm_confirmed", P + ["secrets", "rm", "PLAIN_KEY"], HUMAN, None, b"yes\n", None),
    # Kabul edilen TEK cevap "yes". Asagidaki UCU de silmeyi IPTAL etmeli —
    # "y" bir kisaltma DEGIL, "YES" buyuk/kucuk harf toleransi DEGIL.
    ("human_rm_declined",           P + ["secrets", "rm", "PLAIN_KEY"], HUMAN, None, b"no\n", None),
    ("human_rm_y_is_not_yes",       P + ["secrets", "rm", "PLAIN_KEY"], HUMAN, None, b"y\n", None),
    ("human_rm_uppercase_is_not_yes", P + ["secrets", "rm", "PLAIN_KEY"], HUMAN, None, b"YES\n", None),
    ("human_rm_empty_line_is_not_yes", P + ["secrets", "rm", "PLAIN_KEY"], HUMAN, None, b"\n", None),
    ("human_rm_missing_arg",  P + ["secrets", "rm"], HUMAN, None, None, None),
    ("human_rm_too_many_args", P + ["secrets", "rm", "A", "B"], HUMAN, None, None, None),
    ("human_rm_no_config",    ["secrets", "rm", "PLAIN_KEY", "--yes"], HUMAN, None, None, None),
    # Gate hata dallari — baglam "delete <KEY>" (get'te "read <proje>").
    ("human_rm_not_found",    P + ["secrets", "rm", "GONE_KEY", "--yes"], HUMAN, None, None, None),
    ("human_rm_grant_denied", P + ["secrets", "rm", "DENIED_KEY", "--yes"], HUMAN, None, None, None),
    ("human_rm_rate_limited", P + ["secrets", "rm", "RATE_KEY", "--yes"], HUMAN, None, None, None),
    ("human_rm_unauthorized", P + ["secrets", "rm", "UNAUTH_KEY", "--yes"], HUMAN, None, None, None),
    ("human_rm_no_session",
     P + ["secrets", "rm", "PLAIN_KEY", "--yes"],
     dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),
    # rm epoch pin'ine DOKUNMAZ (`list`in aksine): silme sunulan bir epoch
    # OKUMUYOR. Pin 3'te tohumlanip basarili bir silme yapiliyor; pin 3'te
    # KALMALI.
    ("human_rm_leaves_the_epoch_pin_alone",
     P + ["secrets", "rm", "PLAIN_KEY", "--yes"], HUMAN, pinfile(3), None, None),

    # === projects ===========================================================
    # KOK MOUNT'UN GOZLEMLENEBILIR SONUCU: baglama kapisi HIC kosmuyor, o
    # yuzden ajan + ciplak `--project` BASARILI. Hemen ustteki
    # `agent_list_project_flag` AYNI bayrakla BINDING_UNPINNED aliyor.
    ("agent_projects_list_has_no_binding_gate",
     P + ["projects", "list"], AGENT, None, None, None),
    ("human_projects_list", P + ["projects", "list"], HUMAN, None, None, None),
    # Config gereksinimi YINE DE var (storeProject cagriliyor, donen ad
    # kullanilmasa bile) — "gereksiz gorunen" kapi aynen tasindi.
    ("agent_projects_list_still_needs_a_config",
     ["projects", "list"], AGENT, None, None, None),
    ("human_projects_list_needs_a_config", ["projects", "list"], HUMAN, None, None, None),
    # cobra.NoArgs → "unknown command" (arite hatasi DEGIL).
    ("human_projects_list_rejects_extra_args",
     P + ["projects", "list", "EXTRA"], HUMAN, None, None, None),
    ("human_projects_list_no_session",
     P + ["projects", "list"], dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),
    # KONTROL DUZLEMI: rm'in AGENT_MODE_REFUSED'i DEGIL, CONTROL_PLANE_REQUIRED.
    # Iki farkli sinif, iki farkli kurtarma satiri.
    ("agent_projects_rm_is_control_plane",
     ["projects", "rm", "vaulter", "--yes"], AGENT, None, None, None),
    ("human_projects_rm_yes_flag",
     ["projects", "rm", "vaulter", "--yes"], HUMAN, None, None, None),
    ("human_projects_rm_confirmed",
     ["projects", "rm", "vaulter"], HUMAN, None, b"yes\n", None),
    ("human_projects_rm_declined",
     ["projects", "rm", "vaulter"], HUMAN, None, b"no\n", None),
    ("human_projects_rm_missing_arg", ["projects", "rm"], HUMAN, None, None, None),
    # Oturum yoklugunda KURTARMA SATIRI farkli: admin app AYRI bir CF Access
    # uygulamasidir, yani "wapps login" YETMEZ — "wapps login --write".
    ("human_projects_rm_no_session",
     ["projects", "rm", "vaulter", "--yes"],
     dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),

    # === init ===============================================================
    # Bu vakalar KENDI dizinlerinde kosuyor (cfg_only_dir) ve yazilan
    # `.wapps.yaml` BAYT olarak karsilastiriliyor. Proje adi verilmezse DIZIN
    # adina duser — dizin adi vaka adidir, yani iki ikili icin AYNI.
    ("agent_init_writes_the_config",
     ["secrets", "init"], AGENT, None, None, cfg_only_dir()),
    ("human_init_writes_the_config",
     ["secrets", "init"], HUMAN, None, None, cfg_only_dir()),
    ("human_init_named_project",
     ["secrets", "init", "--project-name", "myproj"], HUMAN, None, None, cfg_only_dir()),
    # BAGLAMA KAPISI YAZIMDAN ONCE: mevcut ama pinlenmemis bir config'in
    # yaninda ajan modunda init BINDING_UNPINNED verir ve dosyaya DOKUNMAZ.
    ("agent_init_is_gated_before_it_writes",
     ["secrets", "init"], AGENT, None, None, cfg(VALID_CFG)),
    # ...ve `--force` bu kapiyi ACMAZ. Korudugu sey gercek: uydurulmus bir
    # `.wapps.yaml` bulunan bir depoda bir ajan onu yeniden yazip baska bir
    # projeyi hedefleyemesin.
    ("agent_init_force_does_not_open_the_gate",
     ["secrets", "init", "--force"], AGENT, None, None, cfg(VALID_CFG)),
    # Insan + TTY: baglama sorulur. "n" → ret, dosya DOKUNULMAZ.
    ("human_init_binding_declined",
     ["secrets", "init"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    # "y" → pinlenir, sonra "already exists" ile duser (--force yok).
    ("human_init_refuses_to_clobber",
     ["secrets", "init"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # --force ile EZER; yazilan sablon bayt-bayt karsilastiriliyor.
    ("human_init_force_overwrites",
     ["secrets", "init", "--force", "--project-name", "repl"], HUMAN, None, b"y\n",
     cfg(VALID_CFG)),
    ("human_init_extra_arg_is_ignored",
     ["secrets", "init", "EXTRA"], HUMAN, None, None, cfg_only_dir()),
]

CASES += VERB_CASES


# --- `trust-repo` ------------------------------------------------------------
#
# Baglamayi KURAN fiil, ve bu dilimin en kisa kapi zinciri:
#
#   ajan politikasi `tty`  ->  baglama kapisi MUAF  ->  config  ->  onay  ->  pin
#
# UC SEY BURADA OLCULUYOR ve hicbiri komsu fiillerden tahmin edilemiyor:
#
#  1. AJAN REDDININ METNI FARKLI. `get`/`rm` POLICY_REFUSE_AGENT ("surface
#     refused in agent mode ..."); trust-repo POLICY_TTY ("this command
#     requires a human terminal"). Ayni kod (AGENT_MODE_REFUSED), ayri cumle.
#  2. BAGLAMA MUAFIYETI ZORUNLU. Pini KURAN fiil pinin varligini sart kosamaz;
#     `human_trustrepo_pins` pinsiz bir config'in yaninda satir ici baglama
#     istemini HIC gormeden kendi istemine gidiyor.
#  3. ONAY KELIMESI YALNIZCA "y". `secrets exec`in satir ici istemi "yes"i de
#     kabul ediyor; bu etmiyor (`human_trustrepo_yes_is_not_y`). Iki istemi
#     tek fonksiyona indiren bir port bu vakada kirilir.
#
# ISTEM STDOUT'A gidiyor (satir ici baglama istemi stderr'e) — differential
# ikisini ayri pty'lerde yakaladigi icin bu da olculuyor.
#
# repo-pins.json her vakada bayt-bayt karsilastiriliyor: bir ikili reddedip
# yine de pinleseydi (ya da tersi) cikti esit gorunurdu.
TRUSTREPO_CASES = [
    ("agent_trustrepo_is_tty_only",
     ["secrets", "trust-repo"], AGENT, None, None, cfg(VALID_CFG)),
    # Config YOKKEN de ajan kapisi ONCE ates eder: ret AGENT_MODE_REFUSED,
    # "applies only to a backend: store" DEGIL.
    ("agent_trustrepo_gate_precedes_the_config_check",
     ["secrets", "trust-repo"], AGENT, None, None, None),
    # Insan + config YOK -> INTERNAL (NOT_FOUND DEGIL; Go'nun kendi cumlesi).
    ("human_trustrepo_without_a_config",
     ["secrets", "trust-repo"], HUMAN, None, None, None),
    ("human_trustrepo_declined",
     ["secrets", "trust-repo"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    ("human_trustrepo_empty_line_declines",
     ["secrets", "trust-repo"], HUMAN, None, b"\n", cfg(VALID_CFG)),
    # "yes" BURADA GECERSIZ — satir ici baglama isteminin aksine.
    ("human_trustrepo_yes_is_not_y",
     ["secrets", "trust-repo"], HUMAN, None, b"yes\n", cfg(VALID_CFG)),
    ("human_trustrepo_uppercase_y_confirms",
     ["secrets", "trust-repo"], HUMAN, None, b"Y\n", cfg(VALID_CFG)),
    ("human_trustrepo_pins",
     ["secrets", "trust-repo"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # Profiller bildirilmisse istem blogunda ALFABETIK siralanir.
    ("human_trustrepo_lists_profiles",
     ["secrets", "trust-repo"], HUMAN, None, b"n\n",
     cfg("version: 2\nproject: testproj\nprofiles:\n  web: [ALPHA]\n  api: [BETA]\n")),
    # cobra'da Args YOK -> ArbitraryArgs: fazladan arguman SESSIZCE yutulur.
    ("human_trustrepo_extra_arg_is_ignored",
     ["secrets", "trust-repo", "EXTRA"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    # `--project <ad>` ile: trust-repo baglama-muaf oldugu icin ciplak
    # `--project` reddi HIC kosmaz; ret config'in yoklugundan gelir.
    ("human_trustrepo_project_flag_still_needs_a_config",
     P + ["secrets", "trust-repo"], HUMAN, None, None, None),
]

CASES += TRUSTREPO_CASES


# --- `env` -------------------------------------------------------------------
#
# env'in KENDINE OZGU kapisi UCUNCU sirada ve komsu hicbir fiilde yok:
#
#   ajan `allow` -> baglama -> PRINT-FORM REDDI -> config -> store
#
# `--write FILE` YOKSA env gizli DUZ METIN basiyor, yani ajan modunda
# REFUSE_AGENT; `--write` ile ayni fiil SERBEST (§7.4.2 AI-safe yol). Iki dal
# da olculuyor.
#
# EN COK YANLIS YAPILACAK NOKTA — ve `agent_env_write_is_still_binding_gated`
# tam olarak bunu pinliyor: AI-safe yol baglama kapisini ATLATMIYOR. Pinsiz bir
# config'in yaninda ajan modunda `env --write out.env` cagirmak
# AGENT_MODE_REFUSED DEGIL BINDING_UNPINNED verir, cunku baglama kapisi
# PersistentPreRunE'da ve print-form reddi RunE'de.
#
# CF_ACCESS SERVICE-TOKEN CIFTI ile kosan vakalar baglama kapisini MESRU
# olarak atliyor (taze bir CI container'inda trust-repo/TTY imkansiz) ve
# boylece print-form reddine ULASILABILIYOR — o kapi aksi halde ajan yolunda
# ERISILEMEZ kalirdi. Jetonlar UYDURMA test dizeleri; sahte gate kimlik
# DOGRULAMIYOR.
CI_TOKENS = dict(AGENT, CF_ACCESS_CLIENT_ID="fake-id-not-a-secret",
                 CF_ACCESS_CLIENT_SECRET="fake-secret-not-a-secret")

ENV_CASES = [
    # === print-form reddi ===================================================
    # Config YOK + --project YOK: baglama sessizce gecer, ret RunE'nin ajan
    # kapisindan gelir — NOT_FOUND DEGIL. Yani print-form reddi CONFIG
    # kapisindan da ONCE.
    ("agent_env_print_form_is_refused",
     ["secrets", "env"], AGENT, None, None, None),
    # ...ve `--write` ayni kosulda o kapiyi GECER, config kapisina duser.
    ("agent_env_write_reaches_the_config_gate",
     ["secrets", "env", "--write", "out.env"], AGENT, None, None, None),

    # === baglama kapisi print-form reddinden ONCE ===========================
    ("agent_env_binding_precedes_the_print_refusal",
     ["secrets", "env"], AGENT, None, None, cfg(VALID_CFG)),
    # AI-safe yol da AYNI kapinin arkasinda.
    ("agent_env_write_is_still_binding_gated",
     ["secrets", "env", "--write", "out.env"], AGENT, None, None, cfg(VALID_CFG)),
    # Service-token cifti baglamayi atlar → print-form reddi ARTIK ERISILEBILIR.
    ("agent_env_print_refused_behind_a_service_token",
     ["secrets", "env"], CI_TOKENS, None, None, cfg(VALID_CFG)),
    # ...ve ayni muafiyetle `--write` CALISIR: dosya yazilir, stdout BOS kalir.
    ("agent_env_write_works_behind_a_service_token",
     ["secrets", "env", "--write", "out.env"], CI_TOKENS, None, None, cfg(VALID_CFG)),

    # === insan yolu =========================================================
    ("human_env_binding_accepted",
     ["secrets", "env"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    ("human_env_binding_declined",
     ["secrets", "env"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    ("human_env_prefix_renames_keys",
     ["secrets", "env", "--prefix", "TF_VAR_"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # --write: stdout BOS, dosya 0600. Icerik ve MOD karsilastiriliyor.
    ("human_env_write_emits_nothing_to_stdout",
     ["secrets", "env", "--write", "out.env"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # ESKI BULGU (bkz. src/envverb.rs), artik KAPALI: yazici O_EXCL'siz
    # O_CREATE|O_TRUNC kullaniyordu, onceden duran bir `<hedef>.tmp` YENIDEN
    # KULLANILIYORDU ve modu 0600'e CEKILMIYORDU — duz metin sir 0644 ile
    # kaliyordu. IKI ikili de duzeltildi (ayni commit), yani bu vaka ayrisma
    # gormedi ne once ne simdi. DIFFERENTIAL'IN KOR NOKTASI TAM OLARAK BURASI:
    # kusur PAYLASILDIGI icin bu vaka onu HIC gormedi ve yesil kaldi. Onu
    # yakalayan sey IDDIA testleriydi (Go: TestRunEnv_WriteCannotInheritAWide-
    # TempMode, Rust: a_preexisting_wide_temp_cannot_widen_the_secret).
    # Vaka yine de degerli: `out.env`in MODU karsilastiriliyor, yani iki taraf
    # duzeltmeyi AYNI sekilde uyguladi mi, onu olcuyor.
    ("human_env_write_ignores_a_preexisting_wide_temp",
     ["secrets", "env", "--write", "out.env"], HUMAN, None, b"y\n",
     cfg(VALID_CFG, {"out.env.tmp": ""})),
    # Bayat `.tmp` bir DIZIN ise: eski yazici onu acmaya calisip patlardi.
    # Yeni yazici o adi HIC kullanmiyor, yani yazim BASARILI olmali. Iki
    # tarafin ayni sonuca vardigini olcer.
    ("human_env_write_when_the_temp_name_is_a_directory",
     ["secrets", "env", "--write", "out.env"], HUMAN, None, b"y\n",
     cfg(VALID_CFG, {"out.env.tmp/keep": ""})),
    # Hedefin DIZINI yok: hata cumlesi HEDEFI adlandirir, rastgele temp adini
    # DEGIL. Deterministik olmasaydi bu vaka her kosuda ayrisirdi.
    ("human_env_write_into_a_missing_dir",
     ["secrets", "env", "--write", "nodir/out.env"], HUMAN, None, b"y\n",
     cfg(VALID_CFG)),
    # `--project <ad>` config gereksinimini ATLATMIYOR: env `store_project`
    # DEGIL `require_store_config` kullaniyor.
    ("human_env_project_flag_still_needs_a_config",
     P + ["secrets", "env"], HUMAN, None, None, None),
    ("human_env_no_config", ["secrets", "env"], HUMAN, None, None, None),
    # cobra'da Args YOK → fazladan arguman SESSIZCE yutulur.
    ("human_env_extra_arg_is_ignored",
     P + ["secrets", "env", "EXTRA"], HUMAN, None, None, None),
    ("human_env_unknown_flag",
     P + ["secrets", "env", "--bogus"], HUMAN, None, None, None),
    ("human_env_no_session",
     ["secrets", "env"], dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, b"y\n", cfg(VALID_CFG)),
    # POST /read epoch pin'ini ILERLETIR (env bulk okuma yapiyor). Pin 3'te
    # tohumlaniyor, gate 7 sunuyor → 7.
    ("human_env_advances_the_epoch_pin",
     ["secrets", "env"], HUMAN, pinfile(3), b"y\n", cfg(VALID_CFG)),
    # ...ve GERI SARMAZ.
    ("human_env_epoch_downgrade_refused",
     ["secrets", "env"], HUMAN, pinfile(9), b"y\n", cfg(VALID_CFG)),
]

CASES += ENV_CASES


# --- `import-env` ------------------------------------------------------------
#
# Bu dilimin SIR YAZAN fiili. Kapi sirasi:
#
#   arite -> ajan `allow` -> baglama -> config -> dosya -> GET /keys ->
#   POST /import -> hedefleri yaz (STDERR) -> basari satiri (STDOUT)
#
# UC SEY BURADA OLCULUYOR ve hicbiri baska bir fiilden tahmin edilemiyor:
#
#  1. HEDEF YAZIM RAPORU STDERR'E gidiyor. `apply` ayni yaziciyi cagiriyor ama
#     raporu STDOUT'a basiyor (Go: applyTargetsAfterWrite(..., os.Stderr) vs
#     applyTargets(..., cmd.OutOrStdout())). Differential ikisini ayri
#     pty'lerde yakaladigi icin bu bir ayrinti degil bir OLCUM.
#  2. AYRISTIRILAN DEGERLER hedef dosyaya iniyor, ve o dosya bayt-bayt
#     karsilastiriliyor. Yani `.env` ayristiricisinin DEGER tarafi burada
#     gorunur hale geliyor — aksi halde yalnizca ADLAR olculurdu.
#  3. `import-env` EPOCH PIN'INI ILERLETIYOR, ama import yuzunden DEGIL:
#     ondan once cagrilan GET /keys yuzunden. `human_import_advances_the_pin`
#     bunu pinliyor.
#
# SAHTE GATE'IN /import ROTASI KASITLI MUSKUL (bkz. fakegate.py): govde
# `{"values": {...}}` degilse ya da bos ise 400 doner, ve sonuc GERCEKTEN
# GONDERILEN ad kumesinden surulur. Yani "yanlis bir isteğe dogru cevap"
# vermiyor — onceki dilimin `POST /read`te bulup kapattigi vakumun aynisi.
#
# GERCEK SIR YOK: asagidaki dosyalarda gecen her deger uydurma bir test dizesi.
IMPORT_FILES = {
    "in.env": "# not a secret, a test string\nexport A_KEY=first-test-string\n"
              "B_KEY = \"second test string\"\n\nC_KEY='third-test-string'\n",
    "empty.env": "# only a comment\n\n   \n",
    "nodelim.env": "A_KEY=fine\nbaretokenplaceholder\n",
    # Gate'in SCRIPT'inde 403 tasiyan bir ad: /import sonucu GERCEKTEN
    # gonderilen adlardan suruldugu icin bu vaka GRANT_DENIED bekliyor.
    "denied.env": "DENIED_KEY=test-string\n",
    "rate.env": "RATE_KEY=test-string\n",
    # Gate'in __ALL__ kumesindeki adlar: UZERINE YAZMA uyarisi tetiklenir.
    "overlap.env": "ALPHA=new-test-string\nNEWKEY=other-test-string\n",
}

IMPORT_CASES = [
    # === arite, ajan kapisindan ONCE =======================================
    ("agent_import_env_missing_arg_is_an_arity_error",
     ["secrets", "import-env"], AGENT, None, None, None),
    ("human_import_env_too_many_args",
     ["secrets", "import-env", "a", "b"], HUMAN, None, None, None),

    # === baglama kapisi ====================================================
    # `--project <ad>` + ajan: baglama fail-closed (dosya HIC okunmadan).
    ("agent_import_env_binding_refused",
     P + ["secrets", "import-env", "in.env"], AGENT, None, None, None),
    ("agent_import_env_config_unpinned",
     ["secrets", "import-env", "in.env"], AGENT, None, None, cfg(VALID_CFG, IMPORT_FILES)),

    # === config kapisi dosya okumasindan ONCE ==============================
    # Var olmayan bir dosya verilse bile ret CONFIG'ten gelir, "read" DEGIL.
    ("human_import_env_config_precedes_the_file_read",
     P + ["secrets", "import-env", "nope.env"], HUMAN, None, None, None),
    ("human_import_env_no_config",
     ["secrets", "import-env", "in.env"], HUMAN, None, None, None),

    # === dosya yolu ========================================================
    ("human_import_env_missing_file",
     ["secrets", "import-env", "nope.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),
    # Bos girdi: UYARI + cikis 0, ve gate'e HIC gidilmez.
    ("human_import_env_empty_input_is_not_an_error",
     ["secrets", "import-env", "empty.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),
    # Ayirac YOK: hata SATIRIN UZUNLUGUNU verir, ICERIGINI ASLA.
    ("human_import_env_line_without_a_delimiter",
     ["secrets", "import-env", "nodelim.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),

    # === basari yolu =======================================================
    # Hedef bildirilmemis: yalnizca basari satiri (STDOUT).
    ("human_import_env_writes_the_store",
     ["secrets", "import-env", "in.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),
    # Hedef BILDIRILMIS: "wrote .env.local" STDERR'e, basari satiri STDOUT'a,
    # ve YAZILAN DOSYA bayt-bayt karsilastiriliyor (ayristiricinin DEGER
    # tarafinin olculdugu tek yer).
    ("human_import_env_auto_applies_targets_to_stderr",
     ["secrets", "import-env", "in.env"], HUMAN, None, b"y\n",
     cfg(CFG_TARGETS, IMPORT_FILES)),
    # UZERINE YAZMA uyarisi: gate'in ad duzlemiyle kesisim (STDERR).
    ("human_import_env_warns_about_overwritten_keys",
     ["secrets", "import-env", "overlap.env"], HUMAN, None, b"y\n",
     cfg(VALID_CFG, IMPORT_FILES)),

    # === gate hata dallari (baglam "import <proje>") =======================
    ("human_import_env_grant_denied",
     ["secrets", "import-env", "denied.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),
    ("human_import_env_rate_limited",
     ["secrets", "import-env", "rate.env"], HUMAN, None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),
    ("human_import_env_no_session",
     ["secrets", "import-env", "in.env"], dict(HUMAN, WAPPS_SESSION_TOKEN=""),
     None, b"y\n", cfg(VALID_CFG, IMPORT_FILES)),

    # === epoch pin =========================================================
    # ILERLER — ama import yuzunden DEGIL: ondan once cagrilan GET /keys
    # yuzunden. Pin 3'te tohumlaniyor, gate 7 sunuyor → 7.
    ("human_import_env_advances_the_pin_via_the_keys_call",
     ["secrets", "import-env", "in.env"], HUMAN, pinfile(3), b"y\n",
     cfg(VALID_CFG, IMPORT_FILES)),
    # ...ve GERI SARMAZ: pin 9 iken sunulan 7 bir ROLLBACK'tir.
    #
    # BU VAKA DIFFERENTIAL'IN KOR NOKTASININ KANITI. Eskiden GET /keys'in
    # hatasi TUMUYLE yutuluyordu, yani bu vaka IKI ikilide de `exit 0` +
    # "✓ Imported 3 keys" uretiyordu: geri sarilmis bir store'a SESSIZ yazim.
    # DIFFERENT=0'di. Duzeltmeden sonra iki ikili de `exit 1` + EPOCH_DOWNGRADE
    # uretiyor. DIFFERENT yine 0. Yani bu karsilastirma kusuru ne buldu ne de
    # duzeltmeyi dogruladi — iki tarafin AYNI seyi yaptigini olcuyor, DOGRU
    # seyi yaptigini degil. Kusuru bulan sey IDDIA testleriydi (Go:
    # TestRunImportEnv_RefusesAnEpochDowngradeAndWritesNothing, Rust:
    # an_epoch_downgrade_from_the_keys_call_is_a_gate_not_a_convenience).
    # Vakanin isi hala var: duzeltmenin IKI tarafa da AYNI sekilde indigini
    # olcuyor.
    ("human_import_env_with_a_rolled_back_pin",
     ["secrets", "import-env", "in.env"], HUMAN, pinfile(9), b"y\n",
     cfg(VALID_CFG, IMPORT_FILES)),
]

CASES += IMPORT_CASES


# --- `secrets policy` (show / set / lint) ------------------------------------
#
# KONTROL DUZLEMI. Bu aile diger her fiilden UC noktada ayriliyor, ve ucu de
# burada olculuyor:
#
#  1. AJAN POLITIKASI `control`, `refuse_agent` DEGIL. Ret kodu
#     CONTROL_PLANE_REQUIRED ve kurtarma satiri bir ADMIN SEREMONISINI
#     adlandiriyor. `secrets rm`in AGENT_MODE_REFUSED'iyle AYNI SEY DEGIL.
#  2. AILE ADIYLA KAPILANIYOR. Go'da gateKey, SecretsCmd'nin ALTINDAKI ILK
#     seviye adi ("policy") aliyor, yaprak adini ("set") DEGIL. Aksi halde
#     `policy set` data-plane `set`in `allow` iznini MIRAS ALIRDI ve bir ajan
#     yetki kurallarini yazabilirdi. `agent_policy_set_does_not_inherit_set`
#     tam olarak bunu pinliyor — bu, tek satirlik bir hatanin ajanlara policy
#     yazdirabilecegi yer.
#  3. BAGLAMA KAPISI YOK, config GEREKMIYOR. policy GLOBAL bir dokuman.
#     `human_policy_show_is_binding_exempt` pinsiz bir config'in yaninda
#     kosuyor ve baglama sorusunu HIC gormeden gate'e gidiyor — ayni dizinde
#     `secrets env` satir ici onay istiyor.
#
# SAHTE GATE'IN PUT ROTASI KASITLI MUSKUL (bkz. fakegate.py): donen `sha256`,
# ALINAN BAYTLARIN sha256'sidir. Yani `policy set`in bastigi basari satiri,
# dokumanin JSON SERILESTIRMESINE bagli — alan sirasi ya da bos selector'lerin
# omitempty'si Go'dan ayrisirsa sha ayrisir ve vaka kirmizi olur. Bu, okuma
# tarafindaki `keyName` hatasinin YAZIM tarafindaki karsiligi.
#
# GERCEK SIR YOK: policy dosyalari YETKI KURALLARI tasir, deger DEGIL.

# Gate'in aktif policy'si version 3, yani CAS current+1 = 4 bekliyor.
def _pol(rules, version=None):
    d = {"schema": "wapps-secrets/policy/v1", "rules": rules}
    if version is not None:
        d["version"] = version
    return json.dumps(d, indent=2)

import json  # noqa: E402  (yalnizca policy fikstürleri icin)

POLICY_FILES = {
    # Temiz ama (b) uyarisi ureten dosya: `*` prod anahtarlarina ulasabiliyor.
    "warns.json": _pol([{"group": "eng@wapps.co", "projects": ["vaulter"],
                         "keys": ["*"], "verbs": ["read"]}], 1),
    # Uyarisiz: kural-ici deny (b)'yi susturuyor.
    "clean.json": _pol([{"group": "eng@wapps.co", "projects": ["vaulter"],
                         "keys": ["*", "!*_PROD_*"], "verbs": ["read"]}], 1),
    # Bes uyari sinifindan dordunu birden ureten dosya (a/c/d/e).
    "noisy.json": _pol([
        {"group": "eng", "projects": ["*"], "keys": ["*"], "verbs": ["*"]},
        {"service": "ci", "projects": ["*"], "keys": ["*"], "verbs": ["*"]},
        {"group": "eng", "projects": ["p"], "keys": ["A*", "!*_PROD_*"], "verbs": ["read"]},
        {"group": "admins", "projects": ["vaulter"], "keys": ["*"], "verbs": ["admin"]},
    ], 1),
    # Gate'in AKTIF kurallarinin AYNISI -> diff "(no rule changes)" demeli.
    "same.json": _pol([
        {"group": "developers@wapps.co", "projects": ["*"],
         "keys": ["*", "!*_PROD_*"], "verbs": ["read"]},
        {"service": "ci-runner", "projects": ["vaulter"],
         "keys": ["DB_*"], "verbs": ["read", "write"]},
    ], 1),
    # Sema/dogrulama ihlalleri — her biri FARKLI bir cumle uretmeli.
    "badschema.json": json.dumps({"schema": "nope/v1", "version": 1, "rules": []}),
    "twosel.json": _pol([{"group": "g", "service": "s", "projects": ["p"],
                          "keys": ["*"], "verbs": ["read"]}], 1),
    "aud.json": _pol([{"aud": "abc", "projects": ["p"], "keys": ["*"], "verbs": ["read"]}], 1),
    "badservice.json": _pol([{"service": "-bad name", "projects": ["p"],
                              "keys": ["*"], "verbs": ["read"]}], 1),
    "badverb.json": _pol([{"group": "g", "projects": ["p"], "keys": ["*"],
                           "verbs": ["deploy"]}], 1),
    "denyonly.json": _pol([{"group": "g", "projects": ["p"], "keys": ["!x"],
                            "verbs": ["read"]}], 1),
    "noverbs.json": _pol([{"group": "g", "projects": ["p"], "keys": ["*"], "verbs": []}], 1),
    "denyproj.json": _pol([{"group": "g", "projects": ["!x"], "keys": ["*"],
                            "verbs": ["read"]}], 1),
    # `version` alani YOK -> 1 kabul edilir ve gecer.
    "noversion.json": _pol([]),
    # BILINMEYEN alan -> DisallowUnknownFields.
    "unknown.json": '{"schema":"wapps-secrets/policy/v1","version":1,"rules":[],"extra":1}',
    # BOZUK JSON — DIFFERENTIAL DISI (asagidaki EXCLUDED'a bak).
    "broken.json": "{ this is not json",
}


def pol(name, argv, env, stdin=None):
    return (name, ["secrets", "policy"] + argv, env, None, stdin,
            cfg(None if "cfg" not in name else VALID_CFG, POLICY_FILES))


POLICY_CASES = [
    # === ajan kapisi: CONTROL_PLANE_REQUIRED ==============================
    pol("agent_policy_show_is_control_plane", ["show"], AGENT),
    pol("agent_policy_lint_is_control_plane", ["lint", "clean.json"], AGENT),
    # EN ONEMLI VAKA: `policy set` data-plane `set`in `allow` iznini MIRAS
    # ALMAMALI. Alirsa bir ajan yetki kurallarini yazabilir.
    pol("agent_policy_set_does_not_inherit_set", ["set", "clean.json"], AGENT),
    # Arite ajan kapisindan ONCE: eksik arguman CONTROL_PLANE_REQUIRED DEGIL.
    pol("agent_policy_lint_missing_arg_is_an_arity_error", ["lint"], AGENT),
    pol("agent_policy_set_missing_arg_is_an_arity_error", ["set"], AGENT),
    # Ajan kapisi dosya okumasindan da ONCE: var olmayan bir dosyayla bile ret
    # CONTROL_PLANE_REQUIRED.
    pol("agent_policy_lint_gate_precedes_the_file_read", ["lint", "nope.json"], AGENT),

    # === baglama MUAFIYETI ================================================
    # Pinsiz bir config'in YANINDA, INSAN + TTY: baglama sorusu SORULMAMALI.
    # Ayni dizinde `secrets env` soruyor. (Ad "cfg" icerdigi icin pol() bu
    # vakaya bir `.wapps.yaml` tohumluyor.)
    pol("human_policy_show_is_binding_exempt_next_to_a_cfg", ["show"], HUMAN),

    # === lint (cevrimdisi; gate'e HIC gidilmez) ===========================
    pol("human_policy_lint_clean", ["lint", "clean.json"], HUMAN),
    pol("human_policy_lint_warns_about_prod_reach", ["lint", "warns.json"], HUMAN),
    # Dort uyari sinifi tek dosyada; SIRA da sozlesmenin parcasi ((c) daima en
    # sonda, cunku Go'da AYRI bir dongude kosuyor).
    pol("human_policy_lint_reports_every_class_in_order", ["lint", "noisy.json"], HUMAN),
    pol("human_policy_lint_absent_version_defaults_to_one", ["lint", "noversion.json"], HUMAN),
    pol("human_policy_lint_missing_file_is_internal", ["lint", "nope.json"], HUMAN),
    pol("human_policy_lint_unknown_field", ["lint", "unknown.json"], HUMAN),
    pol("human_policy_lint_too_many_args", ["lint", "a", "b"], HUMAN),

    # === dogrulama reddi: her biri FARKLI bir cumle ========================
    pol("human_policy_lint_bad_schema", ["lint", "badschema.json"], HUMAN),
    pol("human_policy_lint_two_selectors", ["lint", "twosel.json"], HUMAN),
    pol("human_policy_lint_aud_in_primary", ["lint", "aud.json"], HUMAN),
    pol("human_policy_lint_bad_service_name", ["lint", "badservice.json"], HUMAN),
    pol("human_policy_lint_unknown_verb", ["lint", "badverb.json"], HUMAN),
    pol("human_policy_lint_deny_only_keys", ["lint", "denyonly.json"], HUMAN),
    pol("human_policy_lint_empty_verbs", ["lint", "noverbs.json"], HUMAN),
    pol("human_policy_lint_deny_project_glob", ["lint", "denyproj.json"], HUMAN),
    # DIFFERENTIAL DISI — EXCLUDED'a bak (Go'nun JSON sozdizimi hata metni).
    pol("human_policy_lint_broken_json", ["lint", "broken.json"], HUMAN),

    # === show =============================================================
    pol("human_policy_show", ["show"], HUMAN),
    pol("human_policy_show_json", ["show", "--json"], HUMAN),
    pol("human_policy_show_extra_arg_is_ignored", ["show", "EXTRA"], HUMAN),
    # Oturum yokken KURTARMA SATIRI "wapps login" DEGIL "wapps login --write":
    # /v1/admin kenarda AYRI bir CF Access uygulamasi.
    ("human_policy_show_no_session", ["secrets", "policy", "show"],
     dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, cfg(None, POLICY_FILES)),

    # === set ==============================================================
    # Lint uyarilari gate'e GITMEDEN ONCE basiliyor; sonra diff, sonra onay.
    # "no" -> ACTION_UNAVAILABLE, PUT GITMEZ.
    pol("human_policy_set_declined", ["set", "clean.json"], HUMAN, b"no\n"),
    # Kabul edilen TEK cevap "yes" — `trust-repo`nun "y"si DEGIL.
    pol("human_policy_set_y_is_not_yes", ["set", "clean.json"], HUMAN, b"y\n"),
    # "yes" -> PUT v4. Basilan sha, gate'in ALDIGI BAYTLARIN sha256'si, yani
    # bu vaka dokumanin JSON serilestirmesini de olcuyor.
    pol("human_policy_set_confirmed", ["set", "clean.json"], HUMAN, b"yes\n"),
    # --yes: onay atlanir, "(--yes)" basilir ve stdin HIC okunmaz.
    #
    # `--yes`i UNUTMAK bu vakayi SESSIZCE bir ZAMAN ASIMI olcumune cevirir:
    # stdin'siz bir onay dali bir pty'de ASLA EOF gormez, iki ikili de okumada
    # bloklanir ve 30 sn sonra -9 ile doner. "EQUAL" gorunur ama olculen sey
    # bir davranis DEGIL bir timeout olur. Bir kez yazildi, cikis kodu -9
    # oldugu icin yakalandi, ve bu not onun yerinde duruyor.
    pol("human_policy_set_yes_flag", ["set", "clean.json", "--yes"], HUMAN),
    # Uyarili dosya: ⚠ satiri diff'ten ONCE.
    pol("human_policy_set_prints_warnings_before_the_diff", ["set", "warns.json"], HUMAN, b"yes\n"),
    # Gate'in AKTIF kurallariyla AYNI dosya -> "(no rule changes)".
    pol("human_policy_set_identical_rules_show_no_changes", ["set", "same.json"], HUMAN, b"yes\n"),
    # Sema ihlali gate'e GITMEDEN duser.
    pol("human_policy_set_bad_schema_never_reaches_the_gate", ["set", "badschema.json"], HUMAN),
]

CASES += POLICY_CASES

# BOZUK JSON, DIFFERENTIAL DISI ve sebebi burada yaziliyor:
#
#  human_policy_lint_broken_json: Go'nun encoding/json'u SOZDIZIMI hatalarini
#      ayristiricinin ic durumuyla anlatiyor ("invalid character 't' looking
#      for beginning of object key string"); serde_json bambaska bir cumle
#      kuruyor ("expected `,` or `}` at line 1 column 8"). Kod (POLICY_INVALID),
#      onek ("policy file <yol> not valid JSON: "), kurtarma satiri ve cikis
#      kodu EŞIT; ayrisan tek sey ayristiricinin kendi prozasi. Go'nun
#      metnini elle uretmek SAHTE bir sadakat olurdu — bir sonraki bozuk
#      dosyada kirilacak bir yalan. `human_gate_down` ile AYNI sinif.
#
#      DisallowUnknownFields dali AYRIDIR ve OLCULUYOR
#      (human_policy_lint_unknown_field): `json: unknown field "extra"` sabit,
#      kucuk ve TAM bir esleme, ve bir policy dosyasindaki en sik yazim
#      hatasinin dustugu dal o.
EXCLUDED.add("human_policy_lint_broken_json")


# --- `wapps tofu` ------------------------------------------------------------
#
# KOKTE mount'lu bir sarim, `secrets` altinda DEGIL — ve bu, `projects`teki
# gibi, bir duzenleme tercihi degil OLCULEBILIR bir kapi farki. Iki sonucu var
# ve ikisi de burada olculuyor:
#
#  1. SecretsCmd.PersistentPreRunE KOSMAZ. Go bu yuzden ajan kapisini ve depo
#     pinini runTofu'nun ICINDE ACIKCA yeniden uyguluyor (kaynakta "F1 fix").
#     Unutulsaydi `wapps tofu` her sirri okuyan, kapisiz bir yol olurdu —
#     `secrets exec`in confused-deputy korumasinin etrafindan dolasan bir yol.
#     `agent_tofu_binding_is_enforced_despite_the_root_mount` bunu pinliyor.
#
#  2. `DisableFlagParsing: true` (tofu'nun kendi `-target`/`-var` bayraklari
#     tofu'ya gitsin diye) GLOBAL bayraklari da ATIL yapiyor. `--project` HIC
#     ayristirilmiyor, yani degiskene HIC yazilmiyor. Bu GOZLEMLENEBILIR:
#     ayni bayrakla `secrets exec` ajan modunda BINDING_UNPINNED verirken
#     `tofu` NOT_FOUND veriyor — cunku biri projectOverride'i goruyor, digeri
#     gormuyor. Tahmin edilebilir bir sey degil; olculdu.
#
# HATA ONEKI "exec:", "tofu:" DEGIL: sarim runExec'in ORTAK yoluna giriyor ve
# o yolun baglami "exec". Bir port burada kolayca "tofu:" yazar ve ayrisir.
#
# args[0] "-h"/"--help" ya da hic arguman yoksa cobra YARDIMI basar — yardim
# duzeni bu differential'in KAPSAMI DISINDA (bkz. agent_unknown_subcommand),
# o yuzden o dal burada olculmuyor ve asagida ayrica yaziliyor.

# Fikstur dizinini PATH'e koyan cevre: `tofu` shim'i ANCAK boyle bulunur.
TOFU_PATH = {"PATH": "{FIX}:/usr/bin:/bin"}

TOFU_CASES = [
    # === kapi sirasi: ajan politikasi (`allow`) -> baglama -> config =======
    # Config YOK: baglama sessizce gecer (loadOrNil nil doner), ret runExec'in
    # config kapisindan gelir. ONEK "exec:".
    ("agent_tofu_no_config", ["tofu", "plan"], AGENT, None, None, None),
    ("human_tofu_no_config", ["tofu", "plan"], HUMAN, None, None, None),

    # === `--project` ATIL (DisableFlagParsing) ============================
    # EN SASIRTICI VAKA. Ayni bayrakla `secrets exec` ajan modunda
    # BINDING_UNPINNED veriyor (agent_exec_project_flag_no_config, yukarida);
    # `tofu` NOT_FOUND veriyor. Fark bir kapi sirasi degil, bayragin HIC
    # ayristirilmamis olmasi.
    ("agent_tofu_project_flag_is_inert", P + ["tofu", "plan"], AGENT, None, None, None),
    ("human_tofu_project_flag_is_inert", P + ["tofu", "plan"], HUMAN, None, None, None),

    # === baglama kapisi KOK MOUNT'A RAGMEN uygulaniyor ====================
    # Bu vakanin kirmizi olmasi demek, `wapps tofu`nun kapisiz bir sir yolu
    # olmasi demek.
    ("agent_tofu_binding_is_enforced_despite_the_root_mount",
     ["tofu", "plan"], AGENT, None, None, cfg(VALID_CFG)),
    # Insan + TTY: SATIR ICI onay istemi — `secrets exec` ile AYNI istem.
    ("human_tofu_binding_declined", ["tofu", "plan"], HUMAN, None, b"n\n", cfg(VALID_CFG)),

    # === cocuk GERCEKTEN kosuyor =========================================
    # Baglama "y" ile pinleniyor, store okunuyor, `tofu` shim'i kosuyor.
    # Cocugun bastigi uc satir sarimin tamamini olcuyor: argv gecisi, FINAL
    # anahtar adi, ve TF_VAR_ EKLENMEMIS olmasi.
    ("human_tofu_injects_values_verbatim",
     ["tofu", "plan", "-target=module.gate"], dict(HUMAN, **TOFU_PATH), None, b"y\n",
     cfg(VALID_CFG)),
    # Service-token cifti baglamayi MESRU olarak atlar (taze CI container'inda
    # trust-repo imkansiz) → ajan yolunda da cocuga ULASILIYOR.
    ("agent_tofu_runs_behind_a_service_token",
     ["tofu", "apply"], dict(CI_TOKENS, **TOFU_PATH), None, None, cfg(VALID_CFG)),
    # Cocugun cikis kodu AYNEN yansiyor: shim 3 ile cikiyor, wapps de 3.
    # Sifir-disi bir cikisin bir HATA ZARFINA cevrilmedigi ancak boyle gorunur.
    ("agent_tofu_propagates_the_child_exit_code",
     ["tofu", "plan"], dict(CI_TOKENS, **TOFU_PATH), None, None, cfg(VALID_CFG)),

    # === cocuk YOK: ad hatanin ICINDE gorunur ============================
    # PATH'te `tofu` olmadiginda mesaj "tofu"yu adlandiriyor — argv[0]'in
    # gercekten oraya eklendiginin kaniti.
    ("agent_tofu_names_itself_when_the_binary_is_missing",
     ["tofu", "plan"], CI_TOKENS, None, None, cfg(VALID_CFG)),

    # === oturum yok ======================================================
    ("agent_tofu_no_session", ["tofu", "plan"],
     dict(AGENT, WAPPS_SESSION_TOKEN="", CF_ACCESS_CLIENT_ID="", CF_ACCESS_CLIENT_SECRET=""),
     None, None, cfg(VALID_CFG)),

    # === epoch pini: tofu bulk okuma yapiyor, yani pini ILERLETIR =========
    ("agent_tofu_advances_the_epoch_pin",
     ["tofu", "plan"], dict(CI_TOKENS, **TOFU_PATH), pinfile(3), None, cfg(VALID_CFG)),
    # ...ve GERI SARMAZ: sunulan 7 < pinli 9 → EPOCH_DOWNGRADE.
    ("agent_tofu_epoch_downgrade_refused",
     ["tofu", "plan"], dict(CI_TOKENS, **TOFU_PATH), pinfile(9), None, cfg(VALID_CFG)),
]

CASES += TOFU_CASES


# --- `secrets rotate-plan` ---------------------------------------------------
#
# KONTROL DUZLEMI, `policy` ile AYNI sinif ama kapi sirasi FARKLI bir yerde
# gozlemlenebilir hale geliyor:
#
#   ajan politikasi (`control`) -> --identity kontrolu -> --since kontrolu -> GET
#
# AJAN KAPISI ARGUMAN DOGRULAMASINDAN ONCE, ve bu `rotate skip` ile TERS
# (orada `--reason` kontrolu ajan kapisindan ONCE kosuyor, cunku o fiil KOKTE
# mount'lu ve PersistentPreRunE'u YOK). Iki fiil ayni ailenin parcasi gibi
# gorunuyor ama kapi siralari birbirinin aynasi degil — tahmin edilemez,
# olculdu: `agent_rotate_plan_gate_precedes_the_identity_check`.
#
# BAGLAMA MUAF ve config GEREKMIYOR: rotate-plan GLOBAL bir admin sorgusu, bir
# depo->proje baglamasina bagli degil (Go: bindingExempt). Pinsiz bir config'in
# YANINDA kosuyor ve baglama sorusunu HIC gormuyor — ayni dizinde `secrets env`
# soruyor.
#
# GERCEK SIR YOK: rotate-plan tanimi geregi DEGER dondurmez; donen satirlar
# (project, key) ADLARI ve okuma sayaclaridir.

def rp(name, argv, env, seedcfg=None):
    return (name, ["secrets", "rotate-plan"] + argv, env, None, None, seedcfg)

IDENT = ["--identity", "human:a@b.co"]

ROTATE_PLAN_CASES = [
    # === ajan kapisi: CONTROL_PLANE_REQUIRED, `policy` ile AYNI sinif ======
    rp("agent_rotate_plan_is_control_plane", IDENT, AGENT),
    # ...ve kapi --identity KONTROLUNDEN ONCE: bayrak eksikken bile ret
    # CONTROL_PLANE_REQUIRED, INTERNAL DEGIL. `rotate skip`in TERSI.
    rp("agent_rotate_plan_gate_precedes_the_identity_check", [], AGENT),

    # === baglama MUAFIYETI ===============================================
    # Pinsiz bir config'in YANINDA, INSAN + TTY: baglama sorusu SORULMAMALI.
    rp("human_rotate_plan_is_binding_exempt_next_to_a_cfg", IDENT, HUMAN, cfg(VALID_CFG)),

    # === --identity zorunlu ==============================================
    rp("human_rotate_plan_requires_an_identity", [], HUMAN),

    # === basari yollari ==================================================
    # Metin tablosu: sabit genislikli sutunlar + bos `last_read` icin
    # "(assume-policy)" ikamesi.
    rp("human_rotate_plan_text_table", IDENT, HUMAN),
    # JSON: 2 bosluk girinti, HTML kacisi KAPALI, sonda newline.
    rp("human_rotate_plan_json", IDENT + ["--json"], HUMAN),
    # `<`/`>`/`&` tasiyan bir kimlik: HTML kacisi KAPALI oldugu icin JSON'da
    # CIPLAK cikmali. Go'da SetEscapeHTML(false) bunu yapiyor; unutulursa
    # < basilir ve vaka ayrisir.
    rp("human_rotate_plan_json_does_not_escape_html",
       ["--identity", "human:<a>&b", "--json"], HUMAN),
    # --assume-policy TEL'E BINIYOR: sahte gate bayragi gorunce bir satir daha
    # donuyor. Gondermeyen bir istemci o satiri GORMEZ.
    rp("human_rotate_plan_assume_policy_reaches_the_wire", IDENT + ["--assume-policy"], HUMAN),
    # --since de TEL'E BINIYOR: gate alt sinir verilince ilk satiri dusuruyor.
    rp("human_rotate_plan_since_reaches_the_wire",
       IDENT + ["--since", "2026-01-02T03:04:05Z"], HUMAN),
    # BOS --since "verilmemis" sayilir (Go: `if since != ""`), yani sorguya
    # HIC eklenmez ve satir sayisi degismez.
    rp("human_rotate_plan_empty_since_is_treated_as_unset", IDENT + ["--since", ""], HUMAN),
    # RFC3339 kabul kumesi: kesirli saniye ve sayisal offset GECERLI.
    rp("human_rotate_plan_since_accepts_fractional_seconds",
       IDENT + ["--since", "2026-01-02T03:04:05.123Z"], HUMAN),
    rp("human_rotate_plan_since_accepts_a_numeric_offset",
       IDENT + ["--since", "2026-01-02T03:04:05+03:00"], HUMAN),
    # BOS PLAN: tablo YERINE tek bir cumle. Kolayca bos bir baslik basip
    # gecilebilecek bir dal.
    rp("human_rotate_plan_empty_plan_prints_a_sentence_not_a_table",
       ["--identity", "human:nobody@example.invalid"], HUMAN),

    # === oturum ==========================================================
    # Kurtarma satiri "wapps login" DEGIL "wapps login --write": /v1/admin
    # kenarda AYRI bir CF Access uygulamasi.
    ("human_rotate_plan_no_session", ["secrets", "rotate-plan"] + IDENT,
     dict(HUMAN, WAPPS_SESSION_TOKEN=""), None, None, None),

    # === bayrak hatasi ===================================================
    rp("human_rotate_plan_unknown_flag", IDENT + ["--bogus"], HUMAN),
    # DIFFERENTIAL DISI — asagidaki EXCLUDED'a bak (Go'nun time.Parse prozasi).
    rp("human_rotate_plan_bad_since", IDENT + ["--since", "nope"], HUMAN),
]

CASES += ROTATE_PLAN_CASES

# BOZUK --since, DIFFERENTIAL DISI ve sebebi burada yaziliyor:
#
#  human_rotate_plan_bad_since: Go'nun time.Parse'i reddi AYRISTIRICININ IC
#      DURUMUYLA anlatiyor ve BES ayri cumle uretiyor — `cannot parse "1-02..."
#      as "01"`, `month out of range`, `day out of range`, `hour out of range`,
#      `extra text: "Z"`. Kod (INTERNAL), onek ("rotate-plan: --since must be
#      RFC3339: "), kurtarma satiri ve cikis kodu ESIT; ayrisan tek sey
#      ayristiricinin kendi prozasi. Go'nun bes cumlesini elle uretmek SAHTE
#      bir sadakat olurdu — bir sonraki bozuk girdide kirilacak bir yalan.
#      `human_gate_down` ve `human_policy_lint_broken_json` ile AYNI sinif.
#
#      KABUL/RET KARARININ KENDISI ayridir ve OLCULUYOR: kabul edilen bicimler
#      differential'da uc vakayla (Z, kesirli saniye, sayisal offset) ve
#      reddedilenler tests/rotateplan.rs'te Go'dan olculmus bir tabloyla
#      pinleniyor. Ayrisan sey CUMLE, KARAR DEGIL.
EXCLUDED.add("human_rotate_plan_bad_since")


# --- `wapps rotate skip` -----------------------------------------------------
#
# KAPI SIRASI, ve BIR ONCEKI FIILIN TAM TERSI:
#
#   arite (cobra ExactArgs(2)) -> --reason kontrolu -> AJAN KAPISI -> ret
#
# `rotate-plan`da ajan kapisi arguman kontrolunden ONCE kosuyordu; burada SONRA.
# Sebep yapisal: RotateCmd KOKTE mount'lu, yani SecretsCmd.PersistentPreRunE
# HIC kosmuyor ve ret RunE'nin ICINDE, `--reason` kontrolunun ALTINDA yaziyor.
# Iki fiil ayni ailenin parcasi gibi gorunuyor; kapi siralari birbirinin aynasi
# DEGIL. `agent_rotate_skip_reason_check_precedes_the_agent_gate` bunu pinliyor.
#
# BULGU — DUZELTILMIYOR, OLCULUYOR: rotateSkipCmd'de bir
# `Annotations: {wapps_agent_policy: refuse_agent}` DURUYORDU ama OLUYDU (artik
# SILINDI). O annotation'i secretsPreRunE bile OKUMUYORDU, ve o hook bu komut icin HIC
# kosmuyor (kok mount). Reddi gercekten yapan sey RunE'nin ICINDEKI elle
# yazilmis `agentmode.IsAgent()` kontrolu. Annotation silinince davranis
# DEGISMEDI — ve annotation'a GUVENIP elle kontrolu silen biri, `wapps rotate
# skip`i ajanlara acardi.
#
# BAGLAMA KAPISI YOK (kok mount'un dogrudan sonucu): pinsiz bir config'in
# yaninda bile hicbir sey sorulmuyor.
#
# GERCEK SIR YOK: bir SKIP attestation'i "bu anahtar neden dondurulmesin"
# gerekcesidir, deger DEGIL.

def rs(name, argv, env, seedcfg=None):
    return (name, ["rotate", "skip"] + argv, env, None, None, seedcfg)

SKIP_ARGS = ["run-2026-08", "vaulter/DB_PASSWORD"]
REASON = ["--reason", "public constant; rotates at its origin"]

ROTATE_SKIP_CASES = [
    # === arite HER SEYDEN ONCE (cobra ValidateArgs) =======================
    rs("agent_rotate_skip_arity_precedes_everything", ["run-2026-08"], AGENT),
    rs("human_rotate_skip_arity_precedes_everything", ["run-2026-08"], HUMAN),
    rs("human_rotate_skip_too_many_args", SKIP_ARGS + ["EXTRA"], HUMAN),

    # === --reason kontrolu AJAN KAPISINDAN ONCE ==========================
    # EN ONEMLI VAKA: ajan modunda, `--reason` YOKKEN ret AGENT_MODE_REFUSED
    # DEGIL INTERNAL. `rotate-plan`in TERSI, ve tahmin edilemez.
    rs("agent_rotate_skip_reason_check_precedes_the_agent_gate", SKIP_ARGS, AGENT),
    rs("human_rotate_skip_requires_a_reason", SKIP_ARGS, HUMAN),
    # BOS bir `--reason` de "verilmemis" sayilir.
    rs("human_rotate_skip_empty_reason_is_still_missing",
       SKIP_ARGS + ["--reason", ""], HUMAN),

    # === ajan kapisi (RunE'nin ICINDE, annotation'dan DEGIL) =============
    rs("agent_rotate_skip_is_refused_once_the_reason_is_supplied",
       SKIP_ARGS + REASON, AGENT),

    # === insan yolu: motor hazir, CLI baglamasi degil ====================
    # Sessiz bir no-op DEGIL, adlandirilmis bir ret. Mesaj IKI ARGUMANI DA
    # gomuyor — bir port kolayca yalnizca birini yazar.
    rs("human_rotate_skip_is_action_unavailable_and_names_both_args",
       SKIP_ARGS + REASON, HUMAN),

    # === baglama kapisi YOK (kok mount) ==================================
    # Pinsiz bir config'in YANINDA: hicbir sey sorulmuyor. Ayni dizinde
    # `secrets env` satir ici onay istiyor.
    rs("human_rotate_skip_asks_nothing_next_to_an_unpinned_cfg",
       SKIP_ARGS + REASON, HUMAN, cfg(VALID_CFG)),

    # === bayrak hatasi ===================================================
    rs("human_rotate_skip_unknown_flag", SKIP_ARGS + REASON + ["--bogus"], HUMAN),
]

CASES += ROTATE_SKIP_CASES


# --- `wapps doctor` ----------------------------------------------------------
#
# TESHIS FIILI, ve bu differential'da UC seyi ozel yapiyor:
#
#  1. AJAN KAPISI YOK. Kokte mount'lu (PersistentPreRunE kosmaz) ve RunE'de de
#     bir kontrol yok, yani ajan modunda AYNEN kosar. `agent_doctor_*` ile
#     `human_doctor_*` STDOUT'lari BIREBIR ayni; ayrisan tek sey stderr'in
#     BICIMI (zarf vs "Error:"). Bir kapi eklenseydi ajan tarafi bos stdout ile
#     donerdi ve fark aninda gorunurdu.
#
#  2. COOLIFY PROBU GERCEK BIR HTTP ISTEGI. Olculdu: dokunulmamis bir agacta Go
#     ikilisi bu probda CANLI INTERNETE (coolify.meapps.dev) cikiyor. Butun
#     vakalar COOLIFY_URL'i `{GATE}` ile sahte gate'e cevirir — hem harness'in
#     "gercek bir servise HIC baglanma" kurali icin, hem de olcum aga bagli
#     olmasin diye. Sahte gate bilinmeyen rotaya 404 doner ve doctor 5xx
#     ALTINI "canli" sayar, yani sonuc DETERMINISTIK "reachable".
#
#  3. GATE HOST'U CIKTIYA GIREBILIYOR. "oturum yok" ve "oturum dolmus"
#     satirlari host'u BASIYOR, ve sahte gate'in portu iki probe kosumunda
#     FARKLI. O iki vaka bu yuzden WAPPS_SECRETS_GATE'i SABIT bir dizeye
#     ceviriyor — doctor gate'e zaten HIC istek atmiyor, yalnizca host adini
#     okuyor.
#
# OLCULEMEYEN (ve bu yuzden tests/doctorverb.rs'e giden) IKI SEY:
#   * SIFIR OLMAYAN oturum TTL'i. TTL = expires_at - now, ve iki probe kosumu
#     arasinda ~40 sn geciyor; ayni env "59m59s" ve "59m20s" uretirdi. Go'nun
#     Duration bicimi orada Go'dan olculmus bir tabloyla pinli.
#   * "okuma oturumu CANLI ama admin oturumu YOK" bilesimi. session.Load env
#     jetonunu HOST'TAN BAGIMSIZ okuyor, yani WAPPS_SESSION_TOKEN doluyken
#     IKISI de canli; ayrik hale ancak dosya-tabanli oturumla gelinir ve
#     probe.py XDG altina dosya TOHUMLAMIYOR.
#
# GERCEK SIR YOK: buradaki jetonlar uydurma test dizeleridir ve doctor zaten
# hicbir jetonu BASMIYOR — tam olarak bunu olcen ayri bir test var
# (tests/doctorleak.rs), ve o differential'da DEGIL cunku IKI ikili de
# sizdirsaydi vaka "esit" gorunurdu.

COOLIFY = {"COOLIFY_URL": "{GATE}"}
# Fikstur dizini PATH'te: oradaki tek program `tofu` shim'i, yani "arac
# BULUNDU" dali da olculuyor. `/usr/bin:/bin` ile ayni dal ✗ tarafina duser.
TOFU_ON_PATH = dict(COOLIFY, PATH="{FIX}")
# Sabit gate: host CIKTIYA girecegi icin porta bagimli olamaz.
FIXED_GATE = {"WAPPS_SECRETS_GATE": "https://gate.example.invalid"}

DOCTOR_CASES = [
    # === tam batarya =====================================================
    ("human_doctor_full_battery", ["doctor"], dict(HUMAN, **COOLIFY)),
    # AJAN KAPISI YOK: stdout BIREBIR yukaridakiyle ayni olmali. Yalnizca
    # stderr bicimi degisir.
    ("agent_doctor_runs_without_any_agent_gate", ["doctor"], dict(AGENT, **COOLIFY)),
    # PATH'te bir arac VARSA ✓ dali: "opentofu" GORUNEN ad, "tofu" ARANAN ad.
    ("human_doctor_finds_a_tool_under_its_lookup_name",
     ["doctor"], dict(HUMAN, **TOFU_ON_PATH)),
    # `--for all`, bayraksiz cagriyla AYNI batarya.
    ("human_doctor_for_all_is_the_full_battery",
     ["doctor", "--for", "all"], dict(HUMAN, **COOLIFY)),
    # cobra'da Args YOK → fazladan arguman SESSIZCE yutulur.
    ("human_doctor_extra_arg_is_ignored", ["doctor", "EXTRA"], dict(HUMAN, **COOLIFY)),
    ("human_doctor_unknown_for_mode",
     ["doctor", "--for", "wat"], dict(HUMAN, **COOLIFY)),
    ("agent_doctor_unknown_flag", ["doctor", "--bogus"], dict(AGENT, **COOLIFY)),

    # === oturum dallari (host CIKTIYA girer → SABIT gate) ================
    ("human_doctor_no_session",
     ["doctor"], dict(HUMAN, **COOLIFY, **FIXED_GATE, WAPPS_SESSION_TOKEN="")),
    ("agent_doctor_no_session",
     ["doctor"], dict(AGENT, **COOLIFY, **FIXED_GATE, WAPPS_SESSION_TOKEN="")),
    # DOLMUS oturum "yok" ile AYNI CUMLE DEGIL — operator hangisinin oldugunu
    # bilmeli. Gecmiste bir expiry (1) veriliyor, yani sonuc saatten bagimsiz.
    ("human_doctor_expired_session_is_not_the_same_sentence_as_a_missing_one",
     ["doctor"], dict(HUMAN, **COOLIFY, **FIXED_GATE, WAPPS_SESSION_EXPIRES="1")),
    # Bozuk bir WAPPS_SESSION_EXPIRES ("expiry bilinmiyor"a duser, Go:
    # ParseInt hatasinda exp 0 kalir) → oturum CANLI, TTL 0s.
    ("human_doctor_unparsable_expiry_is_treated_as_unknown",
     ["doctor"], dict(HUMAN, **COOLIFY, **FIXED_GATE, WAPPS_SESSION_EXPIRES="not-a-number")),

    # === --for tofu ======================================================
    ("human_doctor_for_tofu_all_missing",
     ["doctor", "--for", "tofu"], dict(HUMAN, **COOLIFY)),
    # KISMI: mevcutlar kontrat SIRASINDA once, eksikler yine kontrat sirasinda
    # sonra. Iki blok Go'da AYRI dongulerden geliyor ve sira gozlemlenebilir.
    ("human_doctor_for_tofu_prints_present_before_missing_in_contract_order",
     ["doctor", "--for", "tofu"],
     dict(HUMAN, **COOLIFY, AWS_REGION="auto", AWS_ACCESS_KEY_ID="fake-id-not-a-secret")),
    # HEPSI hazir → cikis 0 ve KAPANIS satiri. Tek sifir-cikisli doctor dali.
    ("human_doctor_for_tofu_ready",
     ["doctor", "--for", "tofu"],
     dict(HUMAN, **TOFU_ON_PATH,
          AWS_ACCESS_KEY_ID="fake-id-not-a-secret",
          AWS_SECRET_ACCESS_KEY="fake-secret-not-a-secret",
          AWS_ENDPOINT_URL_S3="https://r2.example.invalid",
          AWS_REGION="auto",
          TF_VAR_state_passphrase="fake-passphrase-not-a-secret")),
    # Binary VAR ama env eksik: iki ✗ sinifi ayni raporda.
    ("human_doctor_for_tofu_finds_the_binary_but_not_the_env",
     ["doctor", "--for", "tofu"], dict(HUMAN, **TOFU_ON_PATH)),
    ("agent_doctor_for_tofu_all_missing",
     ["doctor", "--for", "tofu"], dict(AGENT, **COOLIFY)),
]

CASES += DOCTOR_CASES


# --- `secrets get`in YAPILANDIRMA KOLU --------------------------------------
#
# DOSYANIN EN SONUNDA olmasinin sebebi teknik: bu vakalar `cfg()`/`VALID_CFG`
# kullaniyor ve onlar yukarida, `exec`/`apply` blogunda tanimli. Anlam olarak
# bu blok dosyanin BASINDAKI `get` vakalarinin devamidir.
#
# BU KOL HIC GEZILMEMISTI. Bastaki 21 `get` vakasinin TAMAMI `--project
# testproj` geciriyor (P sabiti), yani `get` icin `.wapps.yaml` cozumu,
# projeler kayit defteri ve depo->proje baglamasi bir kez bile kosmadi.
#
# AYNI kor nokta `set`te OLCULDU ve GERCEK bir ayrisma sakliyordu. Burada da:
# asagidaki dort vakanin UCU duzeltmeden ONCE DIFFERENT=3 raporladi (dorduncusu,
# agent_get_config_unpinned, bir SIRA pinidir ve iki tarafta da esitti) —
#
#   Go   -> .wapps.yaml'i OKUYUP baglama kapisina variyor (BINDING_UNPINNED
#           ya da satir ici onay), sonra degeri basiyor
#   Rust -> dosyaya HIC bakmadan "get: no .wapps.yaml found" (NOT_FOUND)
#
# AJAN yolunun bu kolu YOK, ve bu bir eksiklik degil bir OLCUM: `get`in
# politikasi refuse_agent, yani Guard baglama kapisindan ONCE reddediyor.
# `agent_get_config_unpinned` tam olarak bunu pinliyor — `list` AYNI kosulda
# BINDING_UNPINNED veriyor (agent_list_config_unpinned), `get` ise
# AGENT_MODE_REFUSED vermeli. Iki vaka yan yana durunca kapi SIRASI gorunur.
#
# `--config` VAKALARI DA YENI: bu bayragin differential'da 309 vakalik korpus
# boyunca TEK BIR vakasi yoktu. Rust'in run_get'i `config` parametresini HIC
# almiyordu, yani bayrak sessizce yere dusuyordu. `--config`i bir ALT DIZINE
# gostermek ayrica repoIdentity'nin config KOKUNU (cwd'yi degil) kullandigini
# olcuyor: baglama istemindeki `repo:` satiri `<vaka>/sub` ile bitmeli.
GET_CONFIG_CASES = [
    # Config VAR, --project YOK, ajan → Guard baglama kapisindan ONCE reddeder.
    ("agent_get_config_unpinned",
     ["secrets", "get", "PLAIN_KEY"], AGENT, None, None, cfg(VALID_CFG)),
    # Insan + TTY: satir ici baglama onayi. "n" → BINDING_UNPINNED, defter bos.
    ("human_get_binding_declined",
     ["secrets", "get", "PLAIN_KEY"], HUMAN, None, b"n\n", cfg(VALID_CFG)),
    # "y" → pinlenir, DEGER basilir ve GET /read epoch pin'ini 7'ye kurar.
    # Karsilastirilan dort alanin UCU birden bu vakada oynuyor: cikti,
    # repo-pins.json ve epochs.json.
    ("human_get_binding_accepted",
     ["secrets", "get", "PLAIN_KEY"], HUMAN, None, b"y\n", cfg(VALID_CFG)),
    # --config bir ALT DIZINE: baglama kimligi CONFIG KOKUNDEN turuyor.
    ("human_get_config_flag_binding_accepted",
     ["--config", "sub/.wapps.yaml", "secrets", "get", "PLAIN_KEY"],
     HUMAN, None, b"y\n", {"yaml": None, "files": {"sub/.wapps.yaml": VALID_CFG}}),

    # --- SIRA PINLERI: bu ikisi duzeltmeden ONCE de SONRA da EQUAL ---
    # Config YOK + --project YOK → baglama kapisi SESSIZCE geciyor ve ret bir
    # adim sonra storeProject'ten NOT_FOUND olarak geliyor. Bir port burada
    # BINDING_UNPINNED verseydi ayrisirdi; `set`in ayni vakasiyla (human_set_
    # no_project) ayni kapiyi olcuyorlar.
    ("human_get_no_project", ["secrets", "get", "PLAIN_KEY"], HUMAN, None, None, None),
    # Ajan yolunda ayni cagri DAHA ONCE, Guard'da duser: config cozumu HIC
    # kosmaz, yani mesaj NOT_FOUND DEGIL AGENT_MODE_REFUSED.
    ("agent_get_no_project", ["secrets", "get", "PLAIN_KEY"], AGENT, None, None, None),
]

CASES += GET_CONFIG_CASES


# --- `wapps dr` ------------------------------------------------------------------
#
# BU BLOGUN VAKALARININ HICBIRI `--project` GECMIYOR, ve bu bilincli. `dr`
# KOKTE mount'lu: Go'da SecretsCmd.PersistentPreRunE kosmuyor, Ctx HIC
# cozulmuyor, yani baglama kapisi bu agac icin yok. Bir `--project` yardimcisi
# yazmak (`h`/`a`/`hp` kaliginda) bu fiilin BAYRAKSIZ kolunu — yani GERCEK
# kolunu — erisilemez kilardi. O kor nokta bu agacta `set` ve `get`te birer kez
# cikti ve ikisinde de gercek bir ayrisma gizlemisti.
#
# Bayragin ATIL oldugu ayrica OLCULUYOR (dr_verify_project_flag_is_inert):
# `--project` ile ve onsuz cikti BIREBIR ayni olmali. `tofu`daki inert-bayrak
# olcusuyle ayni fikir.
#
# DIFFERENTIAL DISI — sessizce atlanmiyor, BURADA yaziliyor:
#   `dr restore` / `dr bootstrap` / `dr accept-epoch-reset`: Rust ikilisi bu
#       alt komutlari TANIMIYOR (portlanmadi; `restore` icin sebep bir CRATE
#       karari — XChaCha20-Poly1305 `ring`de yok). Go onlari CALISTIRIYOR.
#       Ayrisma GERCEK ve bilincli; vaka yazmak "esit" ilan etmek olurdu.
#   `wapps dr` (alt komutsuz): iki taraf da yardim basip 0 ile cikiyor ama
#       DUZEN farkli (cobra vs clap). `agent_unknown_subcommand` ile ayni
#       gerekce.
import hashlib as _hashlib
import json as _json

def _dr_snapshot(projects):
    """Gecerli bir B2 replika snapshot'i uretir (cfgseed 'files' haritasi).

    GERCEK SIR YOK: blob'lar duz uydurma baytlar. Bu dilim onlari COZMUYOR
    (restore portlanmadi), yalnizca ICERIK ADRESLERINI dogruluyor.
    """
    files = {}
    for project, epoch in projects:
        blob = f"fake-blob-bytes-for-{project}".encode()
        bh = _hashlib.sha256(blob).hexdigest()
        files[f"snap/secrets/{project}/blobs/{bh}"] = blob.decode()
        man = _json.dumps({
            "schema": "wapps-secrets/data-manifest/v2",
            "project": project, "epoch": epoch,
            "entries": [{"keyName": "KEY_ONE", "keyVersion": 1, "blobHash": bh,
                         "wrap": {"recipient": "worker-kek:v1",
                                  "kid": "0123456789abcdef", "wrap": "AAAA"}}],
        }, separators=(",", ":"))
        files[f"snap/secrets/{project}/manifests/{epoch}.json"] = man
        files[f"snap/secrets/{project}/current"] = _json.dumps({
            "schema": "wapps-secrets/current/v1", "project": project, "epoch": epoch,
            "manifestSha256": _hashlib.sha256(man.encode()).hexdigest(),
        }, separators=(",", ":"))
    return files

_SNAP_OK = _dr_snapshot([("alpha", 4), ("beta", 9)])

def _snap_broken_chain():
    """Pointer'in tasidigi hash ile manifest'in baytlari UYUSMUYOR."""
    f = dict(_SNAP_OK)
    k = "snap/secrets/alpha/manifests/4.json"
    f[k] = f[k].replace("KEY_ONE", "KEY_TWO")  # ayni uzunluk, FARKLI hash
    return f

def _snap_bad_blob():
    """Blob'un ADI icerik adresi; icerigini bozunca adres YALAN olur."""
    f = dict(_SNAP_OK)
    for k in list(f):
        if k.startswith("snap/secrets/alpha/blobs/"):
            f[k] = "kurcalanmis-baytlar"
    return f

def _snap_bad_recipient():
    """Alici KAPALI bir kume; taninmayan alici reddedilmeli."""
    f = dict(_SNAP_OK)
    k = "snap/secrets/alpha/manifests/4.json"
    man = f[k].replace("worker-kek:v1", "someone-else")
    f[k] = man
    # Pointer'i DUZELT ki olculen sey zincir degil ALICI dali olsun.
    pk = "snap/secrets/alpha/current"
    ptr = _json.loads(f[pk])
    ptr["manifestSha256"] = _hashlib.sha256(man.encode()).hexdigest()
    f[pk] = _json.dumps(ptr, separators=(",", ":"))
    return f

# SABIT paylar: GERCEK ANAHTAR DEGIL — uydurma bir test vektoru (frozen
# vektordeki 0x42*32 sirrinin 2-of-3 paylari).
# `dr split`in kendisi differential'lanAMAZ (RNG -> her kosumda farkli paylar),
# o yuzden paylar BURADA statik. Uretimleri tests/cryptoid.rs'teki frozen
# vektorle ayni algoritmadan gelir ve round-trip'leri orada IDDIA olarak
# olculuyor.
_SHARE_1 = "e98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98fe98f01"
_SHARE_2 = "0fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc30fc302"
_SHARE_3 = "a40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40ea40e03"
_SHARE_FILES = {"s1.hex": _SHARE_1 + "\n", "s2.hex": _SHARE_2 + "\n",
                "s3.hex": _SHARE_3 + "\n"}

def dr_h(name, argv, files=None, stdin=None):
    return (f"human_{name}", argv, HUMAN, None, stdin, {"yaml": None, "files": files or {}})

def dr_a(name, argv, files=None, stdin=None):
    return (f"agent_{name}", argv, AGENT, None, stdin, {"yaml": None, "files": files or {}})


# --- dr accept-epoch-reset yardimcilari -----------------------------------------
#
# `dr_h`/`dr_a`dan AYRILAR ve sebebi olculdu: seremoni hicbir dosya YAZMIYOR
# (tek cikti pin dosyasi, o da XDG_CONFIG_HOME altinda), ama bir pin dosyasi
# TOHUMLAMAK zorunda. Yani 4. eleman (pin tohumu) dolu, 6. eleman (vaka
# dizini) BOS — `dr_h` bunun tam TERSINI yapiyor.
_AER = ["dr", "accept-epoch-reset"]
# Sahte gate'in varsayilan audit head hash'inin ILK 12 hex'i (fakegate.py
# AUDIT_HEAD_DEFAULT). GERCEK bir hash DEGIL, uydurma bir test dizesi.
_AER_TYPED = b"ab12cd34ef56\n"

def aer_h(name, argv, pins=None, stdin=None, env=None):
    return (f"human_{name}", argv, dict(HUMAN, **(env or {})), pins, stdin)

def aer_a(name, argv, pins=None, stdin=None, env=None):
    return (f"agent_{name}", argv, dict(AGENT, **(env or {})), pins, stdin)


# --- dr restore: GERCEK bir snapshot fikstuu -------------------------------------
#
# Yukaridaki `_dr_snapshot` blob'lari UYDURMA duz baytlar — `verify` yalnizca
# icerik ADRESINI dogruladigi icin bu yetiyordu. `restore` ise onlari GERCEKTEN
# ACIYOR, yani fikstuun gercek kripto tasimasi sart:
#   master = 0x42*32 (frozen `shamir.secret_hex`), kid = 425ed4e4a36b30ea
#   -> yani ASAGIDAKI _SHARE_1/_SHARE_2 tam da bu master'i geri kuruyor.
#   wrap  = GERCEK WKW1 (§2.4), blob = GERCEK WSB1 (§3.5.4)
# Baytlar Go implementasyonu (internal/cryptoid) tarafindan SABIT nonce'larla
# URETILDI ve buraya donduruldu. GERCEK SIR YOK: master bir test vektoru.
#
# Blob'lar BAYT olarak veriliyor (bytes.fromhex): sifreli veri metin degildir ve
# metin modunda yazilirsa UTF-8 kodlamasi onlari bozar (bkz. probe.py).
_RESTORE_KID = "425ed4e4a36b30ea"
_RESTORE_MANIFEST = (
    '{"entries":[{"blobHash":"be4ce647f3f370c5d9c42bb83eff3260d158d55a4ea1b469b06576146b1c499c","keyName":"DATABASE_URL","keyVersion":1,"wrap":{"kid":"425ed4e4a36b30ea","recipient":"worker-kek:v1","wrap":"V0tXMVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUDInofKxTr4Tynfzyvd/0HvLzwer6qk/Fg6opIcnfYZ2gTUvAoeDJg/KXpONFZEFrA=="}},{"blobHash":"dd71fe25146eb516321d0dfa7c05ba8d35835be38f6fd98d8639d24220193860","keyName":"API_TOKEN","keyVersion":2,"wrap":{"kid":"425ed4e4a36b30ea","recipient":"worker-kek:v1","wrap":"V0tXMVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUW7U06UZyWF7miDurmCyb10WAqaFFmpad3JqGOxbWzGSZeFGKoLkXFyQD/FAVG6+yQ=="}}],"epoch":7,"project":"alpha","schema":"wapps-secrets/data-manifest/v2"}'
)
_RESTORE_BLOBS = {
    "be4ce647f3f370c5d9c42bb83eff3260d158d55a4ea1b469b06576146b1c499c":
        "575342312020202020202020202020202020202020202020202020203c61b33bd0299d9839212c18c994315668e1a46d1e96a6281dd2c16cdc7be65a9e44efaeb230798557bdc8fced3f3d7d5ac0e244d7104cb30429a602674b997f9e31628805fe082b956fc144a46ced91b26b1b860093a7cf3750b3851f075a89f9bc5c6d7b537e02ad4357d9089928d543d9286a0309992fdac1cd7fb65102da492dfcd4b809f52a19d054575e72d970bbaaa75908c3d15ea5b8cfac575c311fe74860c76e67fe59035557023ae540bf1a8925d239c655e21d2834e3ba3bb1e4f10f670d8763a109877a3c48628fc61e4fbc0c7803cfc8d255697dc95f32fb107261c2a04387c08b5a3d295a41d8d8a1999ee18e1bcb2bf6e0c5a56604dab0b953fe212fce916b746df6030feb9f394e",
    "dd71fe25146eb516321d0dfa7c05ba8d35835be38f6fd98d8639d24220193860":
        "57534231212121212121212121212121212121212121212121212121826e90a05f585cf6a24d62245a26c8e2671925a9cd0af5a8aa740ee20ca7dcd50881ca1b8f144b696da263a57703a5770b1cd99ca0d0384263a5f4fc0589210ed36cb2e46764ff5c6139bd33a838d612a8cb4c105bcea140866ec711f48120c67c9ccd237c616093224d65fe02fa18cc8eda7eabcec14410193317d2641cbbd7e09abd28980360a4a280a65cb801983e36969d81d8e6688f8a911cd8dfa9cf2020b2aab8ef78fb0cce4d8e2e39bc9e3ae420097b5deb17570f78c7db707a2bf5d6f1c7487fe295b80c6da2683f01b08677eb2467837ace370985e99d81cbb683b87f47a0d4c495d248d9441f9292d678aec4e0424e03e00a5a22a1ff21accbdf4b859d47a1c476022d5a636e9b52cc9a",
}

def _restore_snapshot():
    """`restore` icin gercek, acilabilir bir replika snapshot'i."""
    f = {}
    for bh, hx in _RESTORE_BLOBS.items():
        f["snap/secrets/alpha/blobs/" + bh] = bytes.fromhex(hx)
    f["snap/secrets/alpha/manifests/7.json"] = _RESTORE_MANIFEST
    f["snap/secrets/alpha/current"] = _json.dumps({
        "schema": "wapps-secrets/current/v1", "project": "alpha", "epoch": 7,
        "manifestSha256": _hashlib.sha256(_RESTORE_MANIFEST.encode()).hexdigest(),
    }, separators=(",", ":"))
    f.update(_SHARE_FILES)
    return f

_SNAP_RESTORE = _restore_snapshot()

def _restore_bad_blob():
    """Blob'un icerigi bozuk -> icerik adresi YALAN. AEAD'den ONCE dusmeli."""
    f = dict(_SNAP_RESTORE)
    for k in list(f):
        if k.startswith("snap/secrets/alpha/blobs/"):
            f[k] = b"kurcalanmis-baytlar"
            break
    return f

def _restore_bad_wrap_b64():
    """wrap alani base64 DEGIL -> ayristirmada dusmeli."""
    f = dict(_SNAP_RESTORE)
    man = _json.loads(_RESTORE_MANIFEST)
    man["entries"][0]["wrap"]["wrap"] = "bu-base64-degil!!"
    mb = _json.dumps(man, separators=(",", ":"))
    f["snap/secrets/alpha/manifests/7.json"] = mb
    f["snap/secrets/alpha/current"] = _json.dumps({
        "schema": "wapps-secrets/current/v1", "project": "alpha", "epoch": 7,
        "manifestSha256": _hashlib.sha256(mb.encode()).hexdigest(),
    }, separators=(",", ":"))
    return f

def _restore_empty_manifest():
    """SIFIR girdili bir manifest — bos ama GECERLI bir proje.

    Go: strings.Join(nil, "\n") + "\n" == "\n", yani BOS proje de tek bir
    yenisatir yazar. Bu bir tuhaflik ve tam da bu yuzden olculuyor: bir port
    burada "hic dosya yazma" ya da "bos dosya yaz" diyebilirdi ve ucu de
    makul gorunurdu. Elle olculdu (iki ikili de b"\n", 0600, exit 0), sonra
    korpusa alindi ki bir daha ELLE olculmesin.
    """
    man = _json.dumps({"schema": "wapps-secrets/data-manifest/v2",
                       "project": "alpha", "epoch": 7, "entries": []},
                      separators=(",", ":"))
    f = dict(_SHARE_FILES)
    f["snap/secrets/alpha/manifests/7.json"] = man
    f["snap/secrets/alpha/current"] = _json.dumps({
        "schema": "wapps-secrets/current/v1", "project": "alpha", "epoch": 7,
        "manifestSha256": _hashlib.sha256(man.encode()).hexdigest(),
    }, separators=(",", ":"))
    return f

def _restore_tampered_share():
    """BULGUNUN TA KENDISI, ve burada bir OLCU haline geliyor.

    Bir payin ilk bayti degistirilince Shamir SESSIZCE yanlis bir 32 baytlik
    anahtar uretir — `dr combine` bunu HATA VERMEDEN yazar. `dr restore` ise
    manifest'teki `wrap.kid` ile karsilastirdigi icin ERKEN duser. Bu vaka o
    ayrimi sahada pinliyor: ayni kurcalanmis pay, iki farkli fiil, iki farkli
    sonuc — ve dogru olan restore'unki.
    """
    f = dict(_SNAP_RESTORE)
    bad = ("ff" + _SHARE_1[2:])
    f["s1.hex"] = bad + "\n"
    return f

DR_CASES = [
    # --- verify: AJAN KAPISI YOK. Bu bir bosluk degil bir KARAR ve burada
    # OLCULUYOR: ayni cagri insan ve ajan modunda AYNI seyi yapmali. Bir port
    # buraya "guvenli olsun" diye bir guard eklerse bu iki vaka ayrisir.
    dr_h("dr_verify_ok", ["dr", "verify", "--snapshot", "snap"], _SNAP_OK),
    dr_a("dr_verify_ok_in_agent_mode", ["dr", "verify", "--snapshot", "snap"], _SNAP_OK),

    # --snapshot YOK -> ACTION_UNAVAILABLE, ve iki bicimde de olculuyor.
    dr_h("dr_verify_no_snapshot", ["dr", "verify"]),
    dr_a("dr_verify_no_snapshot", ["dr", "verify"]),

    # Var olmayan dizin: hata METNI isletim sistemi dizesini tasiyor.
    dr_h("dr_verify_missing_dir", ["dr", "verify", "--snapshot", "yok-boyle-dizin"]),

    # Zincir kirilmasi / icerik adresi / alici — verify'in UC reddi.
    dr_h("dr_verify_broken_chain", ["dr", "verify", "--snapshot", "snap"], _snap_broken_chain()),
    dr_h("dr_verify_bad_blob", ["dr", "verify", "--snapshot", "snap"], _snap_bad_blob()),
    dr_h("dr_verify_bad_recipient", ["dr", "verify", "--snapshot", "snap"], _snap_bad_recipient()),

    # `--project` ATIL olmali: `dr` kokte mount'lu, Ctx cozulmuyor. Bu vakanin
    # ciktisi dr_verify_ok ile BIREBIR ayni olmali (diff.py ikisini de Go'ya
    # karsi olcer; esitlik zaten her iki ikilide de bekleniyor).
    dr_h("dr_verify_project_flag_is_inert", P + ["dr", "verify", "--snapshot", "snap"], _SNAP_OK),

    # --- split: PolicyTTY. Ajan modunda red DIGER HER SEYDEN ONCE gelir —
    # bayraklar EKSIK olsa bile ret ayni. Ikinci vaka bunu kanitliyor: eksik
    # --out-dir'e ragmen cikti "eksik bayrak" DEGIL, ajan reddi olmali.
    dr_a("dr_split_refused", ["dr", "split", "--out-dir", "sh", "--master-hex", "22" * 32]),
    dr_a("dr_split_refused_before_flag_check", ["dr", "split"]),

    dr_h("dr_split_no_outdir", ["dr", "split", "--master-hex", "22" * 32]),
    dr_h("dr_split_threshold_too_low",
         ["dr", "split", "--out-dir", "sh", "--threshold", "1", "--master-hex", "22" * 32]),
    dr_h("dr_split_parts_below_threshold",
         ["dr", "split", "--out-dir", "sh", "--parts", "2", "--threshold", "3",
          "--master-hex", "22" * 32]),
    dr_h("dr_split_master_not_64_hex",
         ["dr", "split", "--out-dir", "sh", "--master-hex", "deadbeef"]),
    dr_h("dr_split_master_not_hex_at_all",
         ["dr", "split", "--out-dir", "sh", "--master-hex", "zz" * 32]),
    # BASARILI split BILEREK YOK: cikti RNG'ye bagli, iki kosum ayni paylari
    # uretmez. Onun olcusu tests/cryptoid.rs'teki frozen vektor IDDIASI.

    # --- combine: PolicyTTY, ve BASARILI yol DETERMINISTIK (girdi paylar
    # sabit) -> yazilan dosyanin ICERIGI ve MODU da karsilastiriliyor.
    dr_a("dr_combine_refused",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex"],
         _SHARE_FILES),
    dr_h("dr_combine_ok",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex"],
         _SHARE_FILES),
    # Farkli pay CIFTI, AYNI anahtar: 2-of-3'un vaadi. Kid iki vakada da ayni
    # basilmali; farkli cikarsa Lagrange interpolasyonu ayrisiyordur.
    dr_h("dr_combine_other_pair",
         ["dr", "combine", "--share", "s1.hex", "--share", "s3.hex", "--out", "m.hex"],
         _SHARE_FILES),
    # UC pay (threshold'dan fazla) da ayni anahtari vermeli.
    dr_h("dr_combine_three_shares",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--share", "s3.hex",
          "--out", "m.hex"], _SHARE_FILES),

    dr_h("dr_combine_one_share", ["dr", "combine", "--share", "s1.hex", "--out", "m.hex"],
         _SHARE_FILES),
    dr_h("dr_combine_no_out", ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex"],
         _SHARE_FILES),
    dr_h("dr_combine_missing_share_file",
         ["dr", "combine", "--share", "yok.hex", "--share", "s2.hex", "--out", "m.hex"],
         _SHARE_FILES),
    dr_h("dr_combine_not_hex",
         ["dr", "combine", "--share", "junk.hex", "--share", "s2.hex", "--out", "m.hex"],
         dict(_SHARE_FILES, **{"junk.hex": "bu hex degil!!\n"})),
    dr_h("dr_combine_duplicate_share",
         ["dr", "combine", "--share", "s1.hex", "--share", "s1.hex", "--out", "m.hex"],
         _SHARE_FILES),
    # O_EXCL: var olan bir --out dosyasini EZMEZ. Dosya 0644 tohumlanIyor;
    # `written` MODU da tasidigi icin, bir ikili yazmis olsaydi mod 0600'e
    # DUSER ve vaka ayrisirdi.
    dr_h("dr_combine_out_exists",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex"],
         dict(_SHARE_FILES, **{"m.hex": "onceden var olan icerik\n"})),
    # Bosluk/yenisatir toleransi: operator paylari elle tasiyor.
    dr_h("dr_combine_whitespace_share",
         ["dr", "combine", "--share", "spaced.hex", "--share", "s2.hex", "--out", "m.hex"],
         dict(_SHARE_FILES, **{"spaced.hex": _SHARE_1[:32] + " \n " + _SHARE_1[32:] + "\n"})),

    # SESSIZ ARIZANIN DIFFERENTIAL'DAKI YUZU. Bozuk bir pay HATA VERMEZ:
    # komut 0 ile biter, 0600 bir dosya yazar, yalnizca KID farklidir. Iki
    # ikili de AYNI yanlis anahtari uretmeli — cunku yanlislik deterministik.
    # Bu vaka, `dr combine`in bir tore YANLIS tamamlandiginda bile "basarili"
    # gorundugunu KORPUSA yaziyor.
    dr_h("dr_combine_tampered_share_silently_succeeds",
         ["dr", "combine", "--share", "bad.hex", "--share", "s2.hex", "--out", "m.hex"],
         dict(_SHARE_FILES, **{"bad.hex": "ff" + _SHARE_1[2:] + "\n"})),

    # --- restore: PolicyTTY, ve BASARILI yol DETERMINISTIK (paylar sabit,
    # blob/wrap baytlari dondurulmus) -> yazilan env dosyasinin ICERIGI ve
    # MODU da karsilastiriliyor. O dosya duz metin SIR tasiyor, yani 0600
    # olmasi bir sozlesme ve `written` modu tasidigi icin OLCULUYOR.
    dr_a("dr_restore_refused",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    # Guard BAYRAKLARDAN ONCE: ajan modunda eksik bayrak hatasi bile SIZMAMALI.
    dr_a("dr_restore_refused_before_flag_check", ["dr", "restore"]),

    # Bayrak kapilari, Go'daki SIRAYLA: project/snapshot -> out -> pay -> confirm.
    dr_h("dr_restore_no_project",
         ["dr", "restore", "--snapshot", "snap", "--share", "s1.hex",
          "--share", "s2.hex", "--out", "env.out", "--confirm"], _SNAP_RESTORE),
    dr_h("dr_restore_no_snapshot",
         ["dr", "restore", "--project", "alpha", "--share", "s1.hex",
          "--share", "s2.hex", "--out", "env.out", "--confirm"], _SNAP_RESTORE),
    dr_h("dr_restore_no_out",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--confirm"], _SNAP_RESTORE),
    dr_h("dr_restore_one_share",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--out", "env.out", "--confirm"], _SNAP_RESTORE),
    # --confirm YOK: seremoni bir yanlislikla baslamamali.
    dr_h("dr_restore_no_confirm",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out"], _SNAP_RESTORE),

    # GERCEK TOREN: iki pay -> MASTER_KEK -> KEK -> WKW1 unwrap -> WSB1 acma
    # -> 0600 env dosyasi. Bu vaka Rust'in ELDE YAZILMIS HChaCha20'sini
    # Go'nun x/crypto chacha20poly1305'ine karsi SAHADA olcuyor: bir bit
    # kayarsa yazilan dosya ayrisir.
    dr_h("dr_restore_ok",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    # Farkli pay CIFTI, AYNI anahtar -> AYNI env dosyasi.
    dr_h("dr_restore_other_pair",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s3.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),

    # KURCALANMIS PAY: `dr combine` bunu SESSIZCE kabul ediyordu (yukaridaki
    # vaka). `restore` manifest'teki kid ile karsilastirdigi icin DUSER.
    dr_h("dr_restore_tampered_share_is_caught_by_the_kid",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _restore_tampered_share()),

    dr_h("dr_restore_unknown_project",
         ["dr", "restore", "--project", "yokboyle", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    dr_h("dr_restore_missing_snapshot_dir",
         ["dr", "restore", "--project", "alpha", "--snapshot", "yok-boyle-dizin",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    dr_h("dr_restore_missing_share_file",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "yok.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    # Icerik adresi AEAD'den ONCE dogrulanmali: hata BLOB_HASH_MISMATCH
    # olmali, "blob open failed" DEGIL.
    dr_h("dr_restore_bad_blob",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _restore_bad_blob()),
    # wrap alani base64 degil -> elde yazilmis cozumleyicinin KATILIGI burada
    # Go'nun StdEncoding'ine karsi olculuyor.
    dr_h("dr_restore_bad_wrap_base64",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _restore_bad_wrap_b64()),
    # BOS proje: tek bir yenisatir, 0600, exit 0. `written` icerigi de
    # tasidigi icin "hic yazma" ile "bos yaz" arasindaki fark GORUNUR.
    dr_h("dr_restore_empty_manifest",
         ["dr", "restore", "--project", "alpha", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _restore_empty_manifest()),

    # --- BULGUNUN KAPATILMASI: kid artik BASILIYOR ve KARSILASTIRILABILIYOR --
    #
    # `dr verify` kid'i basar (beklenen degerin KAYNAGI), `dr combine
    # --expect-kid` onu tuketir (KARSILASTIRICI). Bu vakalar ikisini de
    # sahada pinliyor; ikisi ayni commit'te iki tarafa da indi.
    dr_h("dr_combine_expect_kid_match",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex",
          "--expect-kid", _RESTORE_KID], _SHARE_FILES),
    # BUYUK HARF + BOSLUK tolere edilmeli: operator degeri elle tasiyor.
    dr_h("dr_combine_expect_kid_uppercase",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex",
          "--expect-kid", "  " + _RESTORE_KID.upper() + " "], _SHARE_FILES),
    # SESSIZ ARIZA ARTIK GURULTULU: ayni kurcalanmis pay, ayni fiil, ama
    # --expect-kid ile artik EXIT != 0 ve HICBIR DOSYA YAZILMIYOR. `written`
    # bu vakada m.hex'i GORMEMELI — fail-closed'un olcusu tam olarak bu.
    dr_h("dr_combine_expect_kid_mismatch_writes_nothing",
         ["dr", "combine", "--share", "bad.hex", "--share", "s2.hex", "--out", "m.hex",
          "--expect-kid", _RESTORE_KID],
         dict(_SHARE_FILES, **{"bad.hex": "ff" + _SHARE_1[2:] + "\n"})),
    # BOS --expect-kid, bayrak HIC verilmemis gibi davranmali (kontrol yok).
    # --- bootstrap: PolicyTTY + cobra.MinimumNArgs(1) ---------------------------
    #
    # SIRA ONCE OLCULUYOR ve `split` ile TERS: `bootstrap`in `Args` kisiti VAR,
    # yani cobra ariteyi RunE'den (ajan guard'i orada) ONCE dogruluyor.
    # Komutsuz bir ajan cagrisi bu yuzden AGENT_MODE_REFUSED DEGIL bir arite
    # hatasi verir. `dr_split_refused_before_flag_check` bunun tersini tutuyor;
    # ikisi bir arada olmadan bir port sirayi sessizce degistirebilirdi.
    dr_a("dr_bootstrap_refused", ["dr", "bootstrap", "--", "/bin/echo", "hi"]),
    dr_a("dr_bootstrap_arity_is_checked_before_the_agent_guard", ["dr", "bootstrap"]),
    dr_h("dr_bootstrap_no_command", ["dr", "bootstrap"]),

    # PREFLIGHT REDDI — ve bu vakanin tasidigi sey buyuk: `PreflightEnv`in TAM
    # metni (eksik liste + KURTARMA parcacigi) Rust'ta HIC yoktu. Butun
    # promptlar Enter ile geciliyor (stdin sekiz bos satir), yani kontratin
    # BES degiskeni de eksik kaliyor.
    #
    # Hata KODSUZ basilmali: Go'da `fmt.Errorf("dr bootstrap: %w", ...)`, yani
    # insan yolunda "Error: dr bootstrap: tofu preflight: ..." — kod oneki YOK.
    # `clierr`e sarilmis bir port burada "Error: INTERNAL: ..." basar ve AYRISIR.
    dr_h("dr_bootstrap_preflight_names_every_missing_var", ["dr", "bootstrap", "--", "/bin/echo", "hi"],
         stdin=b"\n" * 8),

    # Kontratin TAMAMI env'de: hicbiri promptlanmaz, hepsi "already set" notu
    # alir ve preflight GECER — komut calisir, epilogue basilir.
    ("human_dr_bootstrap_a_complete_contract_is_inherited_not_prompted",
     ["dr", "bootstrap", "--", "/bin/echo", "ok"],
     dict(HUMAN, AWS_ACCESS_KEY_ID="akid_value_1234", AWS_SECRET_ACCESS_KEY="asak_value_1234",
          AWS_ENDPOINT_URL_S3="https://ep.example", AWS_REGION="auto",
          TF_VAR_state_passphrase="passphrase_1234"),
     None, b"\n" * 4, {"yaml": None, "files": {}}),

    # --skip-preflight: eksik kontratla bile calisir (tofu-disi komutlar).
    dr_h("dr_bootstrap_skip_preflight_runs_the_command",
         ["dr", "bootstrap", "--skip-preflight", "--", "/bin/echo", "hello"], stdin=b"\n" * 8),

    # Her promptable katalog adi TAM ADIYLA ve KATALOG SIRASINDA soruluyor;
    # sabit AWS_REGION prompt akisinda GORUNMEMELI (stdin SEKIZ deger tasiyor,
    # dokuz DEGIL — dokuzuncu girdi sabittir).
    dr_h("dr_bootstrap_prompts_every_promptable_name_in_catalog_order",
         ["dr", "bootstrap", "--skip-preflight", "--", "/bin/echo", "done"],
         stdin=(b"akid_value_1234\nasak_value_1234\nhttps://ep.example\npassphrase_1234\n"
                b"cf_tok_value_1234\ncfr2_tok_value_1234\nhcloud_tok_value_1234\n"
                b"coolify_tok_value_1234\n")),

    # --var: katalog DISI bir ad promptlanip enjekte edilir; katalogla CAKISAN
    # bir --var ikinci kez promptlanMAZ (birlesim semantigi). Cakisma vakasinda
    # stdin yine SEKIZ satir: dokuzuncu bir prompt olsaydi akis kayardi ve
    # cikti ayrisirdi.
    dr_h("dr_bootstrap_an_extra_var_is_prompted_and_injected",
         ["dr", "bootstrap", "--skip-preflight", "--var", "TF_VAR_extra_token",
          "--", "/bin/echo", "x"], stdin=b"\n" * 9),
    dr_h("dr_bootstrap_a_catalog_overlapping_var_is_prompted_once",
         ["dr", "bootstrap", "--skip-preflight", "--var", "TF_VAR_hcloud_token",
          "--", "/bin/echo", "x"], stdin=b"\n" * 8),

    # --- SESSIZ ARIZA SINIFI: token sizintisi -------------------------------------
    #
    # BU IKI VAKA BU BLOGUN VAR OLMA SEBEBI. `bootstrap`in yanlis cevabi ile
    # dogru cevabi AYNI GORUNUR: komut calisir, cikis kodu 0'dir, epilogue
    # basilir. TEK fark, cocugun echo'ladigi token'in transcript'te `***` mi
    # yoksa ACIK METIN mi oldugudur — ve operator apply BASARILI oldugu icin o
    # satiri okumaz bile. Fark ancak token sizdiktan SONRA anlasilir.
    #
    # Cocuk `/bin/sh -c 'echo $VAR'`: enjekte edilen degeri GERCEKTEN yaziyor.
    # Deger scrub tabaninin (4 bayt) USTUNDE, yani atlanmasinin mesru bir
    # sebebi yok.
    dr_h("dr_bootstrap_a_child_echoing_a_prompted_token_prints_stars",
         ["dr", "bootstrap", "--skip-preflight", "--",
          "/bin/sh", "-c", "echo TOKEN=$TF_VAR_hcloud_token"],
         stdin=(b"akid_value_1234\nasak_value_1234\nhttps://ep.example\npassphrase_1234\n"
                b"cf_tok_value_1234\ncfr2_tok_value_1234\nhcloud_tok_value_1234\n"
                b"coolify_tok_value_1234\n")),

    # KALITILAN token da sizdiramaz — ve bu, ikisinin arasinda UNUTULMASI EN
    # KOLAY olani: kalitilan degisken hicbir prompt gormedigi icin scrub
    # kumesine eklenmesi atlanabilir ve atlandiginda HICBIR SEY dusmez.
    ("human_dr_bootstrap_a_child_echoing_an_inherited_token_prints_stars",
     ["dr", "bootstrap", "--skip-preflight", "--",
      "/bin/sh", "-c", "echo TOKEN=$TF_VAR_hcloud_token"],
     dict(HUMAN, TF_VAR_hcloud_token="inherited_hcloud_token_1234"),
     None, b"\n" * 7, {"yaml": None, "files": {}}),

    # Sabit AWS_REGION=auto scrub kumesine GIRMEZ: "auto" gibi bir sabiti
    # redakte etmek ilgisiz ciktiyi bozardi (asiri-redaksiyon). Cocuk onu ACIK
    # yazmali.
    dr_h("dr_bootstrap_the_constant_region_is_not_redacted",
         ["dr", "bootstrap", "--skip-preflight", "--", "/bin/sh", "-c", "echo REGION=$AWS_REGION"],
         stdin=b"\n" * 8),

    # Sifir-disi cocuk cikis kodu AYNEN yansir, ve epilogue BASILMAZ: is
    # bitmedi, burn talimati erken verilmez.
    dr_h("dr_bootstrap_a_nonzero_child_exit_code_is_mirrored",
         ["dr", "bootstrap", "--skip-preflight", "--", "/bin/sh", "-c", "exit 7"],
         stdin=b"\n" * 8),

    # Baslatilamayan komut: hata METNI Go'nun "fork/exec ...: ..." dizesi
    # (goerr::spawn_error). Kodsuz "exec: ..." onekiyle.
    dr_h("dr_bootstrap_a_missing_command_reports_gos_spawn_error",
         ["dr", "bootstrap", "--skip-preflight", "--", "yok-boyle-komut"], stdin=b"\n" * 8),

    # `--project` ATIL: `dr` kokte mount'lu, Ctx cozulmuyor. Kimlik kolu
    # taksonomisinin `proj` kolu da bu vakayla geziliyor.
    dr_h("dr_bootstrap_project_flag_is_inert",
         P + ["dr", "bootstrap", "--skip-preflight", "--", "/bin/echo", "x"], stdin=b"\n" * 8),

    dr_h("dr_combine_expect_kid_empty_is_inert",
         ["dr", "combine", "--share", "s1.hex", "--share", "s2.hex", "--out", "m.hex",
          "--expect-kid", ""], _SHARE_FILES),

    # --- accept-epoch-reset: `dr`in SON fiili, ve pin'i INDIREN TEK yol -------
    #
    # Bu seremoni digerlerinden bir seyle ayriliyor: BASARISI da BASARISIZLIGI
    # da CIKTIDA degil DISKTE. Sonuc `~/.config/wapps/epochs.json`in son hali,
    # ve probe.py o dosyayi her vakada bayt-bayt tasiyor. Bu yuzden asagidaki
    # vakalarin cogu ciktiyi degil PIN DOSYASINI olcuyor: kagit eslesmedigi
    # halde pin'i indiren bir port da, eslestigi halde INDIRMEYEN bir port da
    # ciktida DOGRU gorunurdu.
    #
    # `--project` BURADA YEREL bir bayrak, kalitilan kimlik bayragi DEGIL:
    # kokun `-p`sini golgeliyor ve `Ctx::resolve` HIC cagrilmiyor (Go:
    # runDrAcceptEpochReset dogrudan bayragi okuyor). `cfg`/`rooted` kollari
    # bu yuzden muaf (ARM_WAIVERS), `proj` ve `bare` GEZILIYOR.
    #
    # UC SENARYO `WAPPS_SESSION_TOKEN` UZERINDEN suruluyor ve bu bir hile
    # degil bir OLCU: `GET /v1/audit/head`in ne yolu ne sorgusu var, yani
    # istemcinin gonderdigi TEK degisken alan kimlik basligi. Senaryoyu oradan
    # surmek, basligin yeni rotaya GERCEKTEN enjekte edildigini de olcer
    # (fakegate.py AUDIT_HEADS).

    # AJAN KAPISI HER SEYDEN ONCE: gate'e tek bir istek bile cikmadan, ve pin
    # dosyasina DOKUNMADAN reddedilir. Ikinci vaka sirayi pinliyor — bayraklar
    # EKSIK olsa bile cikti "eksik bayrak" degil ajan reddi olmali (`dr split`
    # ile ayni yon, `dr bootstrap` ile TERS).
    aer_a("dr_accept_epoch_reset_refused", _AER + P, pinfile(9)),
    aer_a("dr_accept_epoch_reset_refused_before_flag_check", _AER),

    # `--project` YOK -> INTERNAL. Kimlik kolu taksonomisinin `bare` kolu.
    aer_h("dr_accept_epoch_reset_no_project", _AER),

    # Oturum yok: yeni rota da AYNI kimlik kapisindan geciyor, istek aga HIC
    # cikmiyor. Pin'e dokunulmuyor.
    aer_h("dr_accept_epoch_reset_no_session", _AER + P, pinfile(9),
          env={"WAPPS_SESSION_TOKEN": ""}),

    # Audit DO erisilemez -> fail-closed. Hata BAGLAMI "audit head" (Go:
    # mapHTTPError(r, "audit head")) ve pin DOKUNULMAMIS kaliyor.
    aer_h("dr_accept_epoch_reset_audit_head_unavailable", _AER + P, pinfile(9),
          env={"WAPPS_SESSION_TOKEN": "audit-down"}),

    # 12 hex'ten KISA bir head hash: seremoni Keys'e HIC gitmeden duser ve
    # uzunlugu METINDE isimlendirir ("len 3").
    aer_h("dr_accept_epoch_reset_malformed_head_hash", _AER + P, pinfile(9),
          env={"WAPPS_SESSION_TOKEN": "audit-short"}),

    # ON KONTROL: pin YOKKEN (0) sunulan 7 zaten buyuk -> seremoni NO-OP.
    # Ve bir YAN ETKI olculuyor: bu on kontrol default-false bir store ile
    # yapiliyor, yani pin'i INDIREMEZ ama ILERLETIR — dosya 7 ile bitmeli.
    # Pin'i hic yazmayan bir port da ciktida ayni gorunurdu.
    aer_h("dr_accept_epoch_reset_is_a_noop_when_there_is_no_pin", _AER + P),
    # served == pinned: yine no-op, ve bu kez dosyaya YAZIM DA YOK.
    aer_h("dr_accept_epoch_reset_is_a_noop_when_the_pin_equals_the_served_epoch",
          _AER + P, pinfile(7)),

    # ON KONTROLUN EPOCH_DOWNGRADE OLMAYAN HATASI YUTULMAZ. `audit-keysdown`
    # senaryosunda audit head SAGLAM ama /keys 503 doner: seremoni orada
    # durmali ve hatayi AYNEN yaymali ("list testproj" baglamiyla). `err !=
    # nil` gordugu her yerde promptla devam eden bir port burada AYRISIR.
    aer_h("dr_accept_epoch_reset_a_precheck_error_is_not_swallowed", _AER + P,
          pinfile(9), env={"WAPPS_SESSION_TOKEN": "audit-keysdown"}),

    # HARD ABORT — BU BLOGUN VAR OLMA SEBEBI. Kagit degeri tutmadiginda pin'e
    # DOKUNULMAZ ve accepting store HIC kurulmaz. Yanlis cevabin ciktisi
    # zaten bir hata satiri; TEK gercek fark pin dosyasinin 9'da kalmasi.
    aer_h("dr_accept_epoch_reset_a_paper_mismatch_hard_aborts_and_keeps_the_pin",
          _AER + P, pinfile(9), stdin=b"0000000000ab\n"),

    # Kagit onekinin BICIMI: 11 karakter (kisa), 12 karakter ama HEX DEGIL,
    # ve BOS. Ucu de ayni reddi vermeli — yani kontrol bir uzunluk kontrolu
    # DEGIL, bir hex sinifi kontrolu.
    aer_h("dr_accept_epoch_reset_a_short_paper_prefix_is_refused", _AER + P,
          pinfile(9), stdin=b"ab12cd34ef5\n"),
    aer_h("dr_accept_epoch_reset_a_non_hex_paper_prefix_is_refused", _AER + P,
          pinfile(9), stdin=b"ab12cd34efgh\n"),
    aer_h("dr_accept_epoch_reset_an_empty_paper_prefix_is_refused", _AER + P,
          pinfile(9), stdin=b"\n"),

    # ESLESME: TEK pin-indiren okuma. Sahte gate `X-Wapps-Intent: epoch-reset`
    # TASIYAN bir /keys okumasina DAHA DUSUK bir epoch (5) doner, yani basari
    # satirindaki sayi ve DISKE YAZILAN pin birlikte basligin gonderildigini
    # olcer. Basligi unutan bir port 7 basar ve 7 yazar.
    aer_h("dr_accept_epoch_reset_lowers_the_pin_on_a_paper_match", _AER + P,
          pinfile(9), stdin=_AER_TYPED),

    # YAZILAN degerin TrimSpace + ToLower'i: bosluklu ve BUYUK HARFLI bir
    # giris de eslesmeli (operator kagittan buyuk harf okuyabilir).
    aer_h("dr_accept_epoch_reset_the_typed_prefix_is_trimmed_and_lowercased",
          _AER + P, pinfile(9), stdin=b"  AB12CD34EF56  \n"),

    # GATE'ten gelen hash BUYUK HARFLI oldugunda da eslesmeli — ToLower iki
    # tarafa da uygulaniyor. Ekrana basilan satir ham hash'i AYNEN tasir.
    aer_h("dr_accept_epoch_reset_an_uppercase_gate_hash_still_matches", _AER + P,
          pinfile(9), stdin=_AER_TYPED, env={"WAPPS_SESSION_TOKEN": "audit-upper"}),

    # --- YEREL `--project` KOKUNKINI GOLGELIYOR ------------------------------
    #
    # BU BLOK BIR TUZAGI KAPATIYOR ve tuzak `dr accept-epoch-reset`e OZEL
    # DEGIL: `dr restore` de yillardir ayni sekilde ayrisiyordu, kimse
    # olcmedigi icin gorunmuyordu.
    #
    # cobra'da bir yapragin YEREL bayragi, kokun ayni adli PERSISTENT
    # bayragini GOLGELER — ve golge KOMUT SATIRINDAKI YERDEN BAGIMSIZDIR:
    # butun bayraklar yapragin flagset'ine karsi ayristirilir. clap'te ise
    # kokun ve yapragin `--project`i IKI AYRI arguman ve hangisinin dolacagini
    # KONUM belirler. Iki gozlemlenebilir sonuc dogar ve ikisi de asagida:
    #
    #   1. Alt komuttan ONCE yazilan `--project` Go'da yapraga ULASIR,
    #      Rust'ta kokte KALIR (ve yaprak "--project is required" der);
    #   2. `--config` + `--project` bu iki yaprakta KARSILIKLI DISLAYAN
    #      DEGILDIR — cunku Go'da kokun `--project`i hic dolmaz. Rust ise
    #      KIMLIK kuralini KIMLIK OLMAYAN bir bayraga karsi ateslerdi.
    #
    # DOGRU TARAF OLCULEREK secildi, hizalanarak degil: bu iki yaprakta
    # `--project` bir KIMLIK bayragi degil (`Ctx::resolve` cagrilmiyor),
    # seremoninin/kurtarmanin KENDI zorunlu argumani. Bir kimlik kuralinin
    # ona carpmasi yanlis. Kontrol vakasi `dr verify`: YEREL `--project`i
    # OLMAYAN bir yaprakta ret IKI IKILIDE DE surmeli, yani kural
    # kaldirilmiyor, yalnizca golgelenen yerde uygulanmiyor.
    aer_h("dr_accept_epoch_reset_a_root_project_flag_reaches_the_local_one",
          ["--project", "testproj"] + _AER),
    aer_h("dr_accept_epoch_reset_config_and_a_shadowed_project_are_not_exclusive",
          ["--config", "x.yaml", "--project", "testproj"] + _AER),
    # SONUNCU KAZANIR: ikisi birden verildiginde yaprak kendi degerini alir.
    aer_h("dr_accept_epoch_reset_the_local_project_wins_over_the_root_one",
          ["--project", "yokboyle"] + _AER + ["--project", "testproj"]),
]

# `dr restore` AYNI GOLGEYI YASIYOR ve duzeltme onu da tasiyor, yani olcusu de
# burada olmali: davranisi degistirilen her yaprak korpusta gorunur.
DR_CASES += [
    dr_h("dr_restore_a_root_project_flag_reaches_the_local_one",
         ["--project", "alpha", "dr", "restore", "--snapshot", "snap",
          "--share", "s1.hex", "--share", "s2.hex", "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    dr_h("dr_restore_config_and_a_shadowed_project_are_not_exclusive",
         ["--config", "x.yaml", "--project", "alpha", "dr", "restore",
          "--snapshot", "snap", "--share", "s1.hex", "--share", "s2.hex",
          "--out", "env.out", "--confirm"],
         _SNAP_RESTORE),
    # KONTROL: `dr verify`in YEREL `--project`i YOK, yani golge de yok ve
    # karsilikli dislama IKI IKILIDE DE surmeli. Bu vaka olmadan yukaridaki
    # duzeltme kurali topyekun kaldirabilirdi ve gate yine yesil kalirdi.
    dr_h("dr_verify_config_and_project_are_still_mutually_exclusive",
         ["--config", "x.yaml", "--project", "p", "dr", "verify", "--snapshot", "snap"],
         _SNAP_OK),
]

CASES += DR_CASES


# --- `--config` KOLU: kalan ON BIR fiil -------------------------------------
#
# BRIEF'IN ONERMESI OLCULDU VE YANLIS CIKTI. Iddia: "korpustaki her vaka
# `--project` geciren bir yardimcidan doguyor". Olcum (bkz. armcheck asagida):
# 359 vakanin 119'u `--project` geciriyor, 239'u HICBIR kimlik bayragi
# gecirmiyor, ve `--config` geciren TEK BIR vaka var (`get`in). Dahasi korpus
# elemanlarinin 199'u SATIR ICI TUPLE, 164'u yardimci cagrisi — yani
# "yardimciyi duzeltmek" korpusun %45'ine dokunurdu. `exec`in sekiz
# `--project` vakasi elle `P` yazan SATIR ICI tuple'lardir; P ekleyen
# yardimcilarin ikisi (`e_h`/`e_a`) HIC CAGRILMIYOR.
#
# Gercek boslugu adlandiralim: kor nokta YARDIMCIDA degil, bir fiilin
# KIMLIK KOLLARININ hangilerinin gezildiginin HIC SAYILMAMASINDA. Dort kol
# var ve hepsi ayri kod yolu:
#     proj  : `--project <ad>`  -> projects::resolve, cozulmezse override
#     cfg   : `--config <yol>`  -> config_path SABITLENIR, cwd ILGISIZ
#     rooted: bayrak yok + cwd'de `.wapps.yaml` VAR -> load_or_none dolu
#     bare  : bayrak yok + `.wapps.yaml` YOK        -> load_or_none bos
#
# `Ctx::resolve`den gecen ON IKI fiil var (13.'su `tofu`, `resolve(None, None)`
# cagiriyor — iki bayragi da BILEREK almiyor). Bu blok yazilmadan once
# `--config` kolu o on ikiden YALNIZCA `get` icin geziliyordu; kalan on birde
# bayragin differential'da tek bir vakasi yoktu.
#
# `--config` bir ALT DIZINE gosteriliyor. Bu bir kolaylik degil bir olcu:
# baglama kimligi CONFIG KOKUNDEN turemeli (cwd'den degil), yani istemdeki
# `repo:` satiri `<vaka>/sub` ile bitmeli; ve `apply`/`env --write` hedef
# yollarini o koke gore cozmeli.
CFG_SUB = ["--config", "sub/.wapps.yaml"]

def _sub(yaml=VALID_CFG, files=None):
    f = {"sub/.wapps.yaml": yaml}
    f.update(files or {})
    return {"yaml": None, "files": f}

def cf(name, argv, env, stdin=None, yaml=VALID_CFG, files=None):
    """`--config sub/.wapps.yaml` ile bir vaka. `.wapps.yaml` KOKE YAZILMAZ —
    aksi halde cwd-goreli varsayilan da bulunur ve bayragin GERCEKTEN
    onurlandirildigi olculemez; iki ikili de ayni dosyaya duser ve vaka
    sessizce bos gezerdi."""
    return (name, CFG_SUB + argv, env, None, stdin, _sub(yaml, files))

CONFIG_FLAG_CASES = [
    # === list ===============================================================
    cf("agent_list_config_flag_unpinned", ["secrets", "list"], AGENT),
    cf("human_list_config_flag_binding_accepted", ["secrets", "list"], HUMAN, b"y\n"),

    # === status =============================================================
    # status proje adini YEREL config'ten okur; `--config` ile o ad alt
    # dizinden gelmeli. Baglama kapisi status'ta YOK, yani stdin de gerekmez.
    cf("human_status_config_flag", ["secrets", "status"], HUMAN, None),
    cf("human_status_config_flag_json", ["secrets", "status", "--json"], HUMAN, None),

    # === rm =================================================================
    cf("agent_rm_config_flag_refused", ["secrets", "rm", "PLAIN_KEY", "--yes"], AGENT),
    cf("human_rm_config_flag_binding_accepted",
       ["secrets", "rm", "PLAIN_KEY", "--yes"], HUMAN, b"y\n"),

    # === projects list ======================================================
    # Baglama kapisi YOK (kokte mount'lu) ama config GEREKSINIMI VAR: bayrak
    # onurlandirilmazsa "no .wapps.yaml found" ile duser.
    cf("human_projects_list_config_flag", ["projects", "list"], HUMAN, None),
    cf("agent_projects_list_config_flag", ["projects", "list"], AGENT, None),

    # === import-env =========================================================
    # OLCULDU: dosya yolu CWD'ye gore cozuluyor, CONFIG KOKUNE gore DEGIL.
    # `in.env` YALNIZCA `sub/` altinda var; baglama kapisi config kokunu
    # (`.../sub`) kullaniyor ama okuma bir adim sonra cwd-goreli `in.env` ile
    # duşuyor. IKI IKILI DE AYNI: bu bir ayrisma degil, PINLENEN bir asimetri.
    cf("human_import_env_config_flag_reads_the_file_from_cwd",
       ["secrets", "import-env", "in.env"],
       HUMAN, b"y\n", files={"sub/in.env": IMPORT_FILES["in.env"]}),
    cf("agent_import_env_config_flag_unpinned", ["secrets", "import-env", "in.env"],
       AGENT, None, files={"sub/in.env": IMPORT_FILES["in.env"]}),

    # === env ================================================================
    cf("human_env_config_flag_binding_accepted", ["secrets", "env"], HUMAN, b"y\n"),
    # `--write`: OLCULDU, hedef yol CWD'ye gore cozuluyor (`out.env` vaka
    # KOKUNE dusuyor, `sub/` altina DEGIL) — oysa `apply`in `targets` yollari
    # CONFIG KOKUNE gore cozuluyor (asagida `sub/.env.local`). Bu asimetri iki
    # ikilide de AYNI; vaka onu pinliyor ki bir taraf "duzeltip" ayrismasin.
    cf("agent_env_config_flag_write_lands_next_to_cwd_behind_a_service_token",
       ["secrets", "env", "--write", "out.env"], CI_TOKENS),

    # === trust-repo =========================================================
    cf("human_trustrepo_config_flag_pins", ["secrets", "trust-repo"], HUMAN, b"y\n"),
    cf("agent_trustrepo_config_flag_is_tty_only", ["secrets", "trust-repo"], AGENT),

    # === init ===============================================================
    # OLCULDU ve BEKLENENIN TERSI: `init` `--config`i YAZMA yolunda HIC
    # kullanmiyor — sablon CWD'deki `.wapps.yaml`a dusuyor, `sub/` altindaki
    # dosyaya DOKUNULMUYOR. Bayrak yine de ETKISIZ DEGIL: baglama kapisi onu
    # onurlandiriyor (istemdeki `repo:` satiri `.../sub` ile bitiyor). Yani
    # tek bir cagride bayrak BIR kapida gecerli, digerinde yok.
    # Sonuc: "already exists" dali BU KOLDA ERISILEMEZ ve `--force`un
    # ezecegi bir sey YOK. Iki vaka da ayni yola giriyor; ayirdiklari sey
    # proje ADININ nereden geldigi (dizin adi vs `--project-name`).
    cf("human_init_config_flag_writes_to_cwd_not_the_config_path",
       ["secrets", "init"], HUMAN, b"y\n"),
    cf("human_init_config_flag_named_project_also_writes_to_cwd",
       ["secrets", "init", "--force", "--project-name", "repl"], HUMAN, b"y\n"),
    cf("agent_init_config_flag_is_gated", ["secrets", "init"], AGENT),

    # === set ================================================================
    cf("human_set_config_flag_binding_accepted",
       ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"], HUMAN, b"y\n"),
    cf("agent_set_config_flag_unpinned",
       ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"], AGENT),

    # === exec ===============================================================
    cf("human_exec_config_flag_binding_accepted",
       ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"], HUMAN, b"y\n"),
    cf("agent_exec_config_flag_unpinned",
       ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"], AGENT),

    # === apply ==============================================================
    # Hedef `.env.local` CONFIG KOKUNE gore cozulmeli → `sub/.env.local`.
    cf("human_apply_config_flag_writes_under_the_config_root",
       ["secrets", "apply"], HUMAN, b"y\n", yaml=CFG_TARGETS),
    cf("agent_apply_config_flag_unpinned", ["secrets", "apply"], AGENT, yaml=CFG_TARGETS),
]

CASES += CONFIG_FLAG_CASES


# --- ONCEDEN VAR OLAN BAGLAMA: `bindPrompt`in olculmemis IKI dali ------------
#
# Korpustaki her pin KOSUM ICINDE doguyordu (insan "y" diyor), yani her zaman
# ESLESEN bir pin. Iki dal bu yuzden HICBIR fiil icin gezilmemisti:
#
#   UYUSMAZLIK : defterde pin VAR ama `.wapps.yaml` BASKA bir proje isimliyor
#                -> her modda hard fail, satir ici COZUM YOK (pinin var olma
#                sebebi tam olarak bu).
#   ZATEN PINLI: pin VAR ve ESLESIYOR -> kapi SESSIZCE gecer, istem YOK. Bu
#                dal AJANIN gercekten calistigi tek yol, ve differential'da
#                tek bir vakasi yoktu.
#
# Engel harness'taydi, uygulamada degil: probe.py `repo-pins.json` yazamiyordu.
# Kapatildi (7. vaka elemani); parmak izi sha256(config kokunun mutlak yolu) ve
# o yolu probe.py zaten kuruyor.
#
# ISTEM YOKLUGUNUN KANITI stdin'in None olmasi: pinin ESLESTIGI vakalar girdi
# ALMADAN 0 ile bitiyor. Kapi sorsaydi bir pty EOF vermez, iki ikili de
# bloklanir ve diff.py bunu TIMEOUT diye UNSOUND sayardi — yani "sormadi"
# iddiasi bir yorum degil, olcumun kendisi.
def bs(project="otherproj", sub=None, backend="store"):
    return {"project": project, "sub": sub, "backend": backend}

MISMATCH = bs("otherproj")
MATCHES = bs("testproj")

BINDSTATE_CASES = [
    # === UYUSMAZLIK: her modda hard fail ====================================
    ("human_get_binding_mismatch",
     ["secrets", "get", "PLAIN_KEY"], HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    # `get` refuse_agent: AJAN kapisi baglama kapisindan ONCE — mesaj
    # AGENT_MODE_REFUSED olmali, "different project" DEGIL.
    ("agent_get_binding_mismatch_hits_the_agent_gate_first",
     ["secrets", "get", "PLAIN_KEY"], AGENT, None, None, cfg(VALID_CFG), MISMATCH),
    ("agent_list_binding_mismatch",
     ["secrets", "list"], AGENT, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_list_binding_mismatch",
     ["secrets", "list"], HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_set_binding_mismatch",
     ["secrets", "set", "PLAIN_KEY", "--from-file", "{FIX}/plain.txt"],
     HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_rm_binding_mismatch",
     ["secrets", "rm", "PLAIN_KEY", "--yes"], HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_exec_binding_mismatch",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"],
     HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_apply_binding_mismatch",
     ["secrets", "apply"], HUMAN, None, None, cfg(CFG_TARGETS), MISMATCH),
    ("human_env_binding_mismatch",
     ["secrets", "env"], HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    ("human_import_env_binding_mismatch",
     ["secrets", "import-env", "in.env"], HUMAN, None, None,
     cfg(VALID_CFG, IMPORT_FILES), MISMATCH),
    # Baglama kapisi init'in YAZIMINDAN once: dosya DOKUNULMAZ.
    ("human_init_binding_mismatch",
     ["secrets", "init"], HUMAN, None, None, cfg(VALID_CFG), MISMATCH),
    # `--config` kolu: parmak izi CONFIG KOKUNDEN (`sub/`) turemeli. Vaka
    # KOKUNE pinlenmis olsaydi kapi "pinsiz" derdi; `sub`a pinli oldugu icin
    # "different project" diyor — yani bu vaka anahtarlamayi da olcuyor.
    ("human_get_config_flag_binding_mismatch",
     CFG_SUB + ["secrets", "get", "PLAIN_KEY"], HUMAN, None, None,
     _sub(VALID_CFG), bs("otherproj", sub="sub")),
    # `trust-repo` baglama-MUAF: uyusmazligi satir ici cozebilen TEK yol.
    ("human_trustrepo_repins_over_a_mismatch",
     ["secrets", "trust-repo"], HUMAN, None, b"y\n", cfg(VALID_CFG), MISMATCH),

    # === ZATEN PINLI: kapi sessizce gecer (stdin YOK = istem YOK) ===========
    ("human_get_binding_already_pinned",
     ["secrets", "get", "PLAIN_KEY"], HUMAN, None, None, cfg(VALID_CFG), MATCHES),
    ("human_list_binding_already_pinned",
     ["secrets", "list"], HUMAN, None, None, cfg(VALID_CFG), MATCHES),
    # AJANIN GERCEKTEN CALISTIGI YOL: eslesen bir pin, service-token muafiyeti
    # OLMADAN. Bu dalin differential'da tek bir vakasi yoktu.
    ("agent_exec_binding_already_pinned",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"],
     AGENT, None, None, cfg(VALID_CFG), MATCHES),
    ("agent_apply_binding_already_pinned",
     ["secrets", "apply"], AGENT, None, None, cfg(CFG_TARGETS), MATCHES),
    ("agent_env_write_binding_already_pinned",
     ["secrets", "env", "--write", "out.env"], AGENT, None, None, cfg(VALID_CFG), MATCHES),
    # Pinin `backend` alani KONTROLE GIRMIYOR (check yalnizca project'e bakiyor).
    # Bir port burada backend'i de karsilastirsaydi bu vaka ayrisirdi.
    ("human_get_binding_pinned_with_another_backend",
     ["secrets", "get", "PLAIN_KEY"], HUMAN, None, None, cfg(VALID_CFG),
     bs("testproj", backend="legacy-git")),
]

CASES += BINDSTATE_CASES


# --- ARM MATRISINDEKI BOSLUKLAR ---------------------------------------------
#
# Asagidaki armcheck, `Ctx::resolve`den gecen ON IKI fiil icin DORT kimlik
# kolunun da gezilmis olmasini SART kosuyor. Ilk kosuldugunda bes boslugu
# adlandirdi; bu blok onlari kapatiyor. (Bulundugu an DIFFERENT olcusu
# raporda.)
ARMGAP_CASES = [
    # `apply` ve `exec`in BAYRAKSIZ + CONFIGSIZ kolu: baglama kapisi SESSIZCE
    # gecer (loadOrNil nil), ret bir adim sonraki config kapisindan gelir.
    ("human_apply_bare_has_no_config", ["secrets", "apply"], HUMAN, None, None, None),
    ("agent_apply_bare_has_no_config", ["secrets", "apply"], AGENT, None, None, None),
    ("human_exec_bare_has_no_config",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"], HUMAN, None, None, None),
    ("agent_exec_bare_has_no_config",
     ["secrets", "exec", "--", "/bin/sh", "-c", "echo $ALPHA"], AGENT, None, None, None),

    # `init`in `--project` kolu: ad kayit defterinde YOK -> project_override.
    # Ortada baglanacak depo olmadigi icin ajan fail-closed, insan gecer.
    ("agent_init_project_flag", P + ["secrets", "init"], AGENT, None, None, cfg_only_dir()),
    ("human_init_project_flag", P + ["secrets", "init"], HUMAN, None, None, cfg_only_dir()),

    # `status`un `--project` kolu: statusProject projeyi YALNIZCA yerel
    # config'ten okuyor, yani ciplak `--project` adi ciktiya GIRMEMELI.
    ("human_status_project_flag", P + ["secrets", "status"], HUMAN, None, None, None),
    ("agent_status_project_flag", P + ["secrets", "status"], AGENT, None, None, None),

    # `projects list`in KOKLU kolu: cwd'de `.wapps.yaml` VAR. Baglama kapisi
    # bu fiilde HIC kosmadigi icin pinsiz bir config'te bile istem YOK.
    ("human_projects_list_rooted", ["projects", "list"], HUMAN, None, None, cfg(VALID_CFG)),
    ("agent_projects_list_rooted", ["projects", "list"], AGENT, None, None, cfg(VALID_CFG)),

    # `tofu`nun `--config` kolu: bayrak ATIL olmali (DisableFlagParsing).
    # `--project`in atilligi zaten olculuyordu; `--config`inki olculmuyordu ve
    # ikisi AYNI sebepten atil — birinin olculup digerinin olculmemesi bir
    # tercih degil, bir bosluktu.
    ("agent_tofu_config_flag_is_inert",
     CFG_SUB + ["tofu", "plan"], AGENT, None, None, _sub(VALID_CFG)),
    ("human_tofu_config_flag_is_inert",
     CFG_SUB + ["tofu", "plan"], HUMAN, None, None, _sub(VALID_CFG)),
]

CASES += ARMGAP_CASES


# --- `whoami` ----------------------------------------------------------------
#
# AGA CIKAN EN UCUZ FIIL, ve kapisi YOK: ne ajan guard'i, ne baglama kapisi, ne
# `Ctx::resolve`. Go'da `whoamiCmd` KOKTE mount'lu ve RunE'si dogrudan
# `store.Whoami`ye gidiyor — yani ajan modunda da INSAN modunda da AYNI yolu
# yuruyor, ve ikisi arasindaki TEK fark bir HATA ciktiginda basilan BICIM.
# Iki mod da yaziliyor cunku o bicim ayrimi olculmeden bilinemez.
#
# KIMLIK KOLLARI: `bare` ve `proj` GEZILIYOR; `cfg` ile `rooted` MUAF ve
# gerekce ARM_WAIVERS'ta. `proj` kolu bir kimlik cozumu DEGIL bir ATILLIK
# olcusu (`dr verify`/`dr bootstrap` ile ayni sinif): bayrak kabul edilir ve
# ciktiya HIC girmez.
#
# GOVDE SENARYOLARI `WAPPS_SESSION_TOKEN` uzerinden suruluyor (fakegate.py
# WHOAMI) — `GET /v1/whoami`in ne yolu ne sorgusu var, yani istemcinin
# gonderdigi tek degisken alan kimlik basligi.
#
# GERCEK SIR YOK: whoami tanimi geregi DEGER dondurmez; donen sey principal,
# grup ve grant ADLARIDIR.
def wh(name, argv=None, env=HUMAN, token=None):
    e = dict(env)
    if token is not None:
        e["WAPPS_SESSION_TOKEN"] = token
    return (name, (argv or []) + ["whoami"], e)

WHOAMI_CASES = [
    # === TABAN: 2 kol x 2 mod ============================================
    # `bare` — hicbir kimlik bayragi yok. whoami'nin GERCEK kolu bu.
    wh("human_whoami_prints_the_gates_view"),
    wh("agent_whoami_prints_the_gates_view", env=AGENT),
    # `proj` — bayrak ATIL. Ciktida `--project`in izi OLMAMALI: whoami bir
    # projeye degil bir PRINCIPAL'a bakiyor.
    wh("human_whoami_project_flag_is_inert", P),
    wh("agent_whoami_project_flag_is_inert", P, env=AGENT),

    # === GOVDE DALLARI ===================================================
    # Servis principal'i: `email` satiri DUSER, `common_name` satiri CIKAR,
    # gruplar "-" olur, root_admin true, ve grant listesi BOSKEN tablo
    # YERINE "grants:         (none)" basilir. Dort kosullu dal tek vakada.
    wh("human_whoami_a_service_principal_has_no_email_and_no_grants",
       token="who-service"),
    # BOS govde: her alan sifir degerinde ve `principal:` satiri BOS basilir.
    # Bos bir principal'i ATLAYAN bir port burada ayrisir.
    wh("human_whoami_an_empty_body_still_prints_every_unconditional_line",
       token="who-min"),
    # SECICI KENARLARI: aud > service > group onceligi, seciciSIZ bir kural
    # (28 karakterlik bos sutun) ve 28'den UZUN bir secici (KIRPILMAZ).
    wh("human_whoami_selector_precedence_padding_and_overflow", token="who-edge"),

    # === HATA DALLARI ====================================================
    # Oturum YOK: istek aga HIC cikmiyor, kurtarma satiri "wapps login"
    # (whoami bir /v1/admin rotasi DEGIL).
    wh("human_whoami_no_session", token=""),
    wh("agent_whoami_no_session", env=AGENT, token=""),
    # Kimlik cozulemedi -> fail-closed 503 dali, hata BAGLAMI "whoami".
    wh("agent_whoami_identity_unavailable", env=AGENT, token="who-identdown"),
    # 403 ve govde BOS: `safeCode` BOS bir kodu "unknown" yaziyor — ve bunu
    # IKI kez, cunku `dimension` da bos. Bos dize basan bir port ayrisir.
    wh("agent_whoami_a_bare_denial_names_the_code_unknown", env=AGENT,
       token="who-denied-bare"),
    # 403 ve kod KIRLI: `safeCode` [A-Za-z0-9_-.] disini ATIYOR (ayirmiyor,
    # bitistiriyor) ve 48 bayta kirpiyor.
    wh("agent_whoami_a_dirty_denial_code_is_stripped_not_escaped", env=AGENT,
       token="who-denied-dirty"),

    # === FAZLADAN ARGUMAN ================================================
    # cobra'da whoamiCmd'in Args'i YOK -> ArbitraryArgs: fazladan arguman
    # SESSIZCE yutulur ve cikis 0 kalir. clap'e birakilsa 1 donerdi.
    # (`wh` yardimcisi argv'yi fiilden ONCE koyuyor — bayraklar icin dogru,
    # bir KONUMSAL arguman icin degil. O yuzden satir ici.)
    ("human_whoami_extra_args_are_silently_ignored", ["whoami", "EXTRA"], HUMAN),

    # === BESINCI DURUM ===================================================
    # whoami'nin YEREL `--project`i YOK, yani kokun bayragi golgelenmiyor ve
    # karsilikli dislama SURUYOR. `token exchange`in TERSI, ve iki fiilin
    # ayni turda inmesinin sebebi tam olarak bu karsitlik.
    ("human_whoami_config_and_project_are_still_mutually_exclusive",
     ["--config", "sub/.wapps.yaml"] + P + ["whoami"], HUMAN, None, None,
     _sub(VALID_CFG)),
]

CASES += WHOAMI_CASES


# --- `token exchange` --------------------------------------------------------
#
# BU FIIL BIR JETON BASIYOR, ve estate'in kurali burada bir ISTISNA ALMIYOR:
# basilan sey bir SIR ve stdout'a HAM gidiyor (pipeline adimi onu yakaliyor).
# Sahte gate JWT-BICIMLI bir jeton uretiyor — yani safelog'un `[REDACTED]`
# yapacagi seklin ta kendisi. Vaka bu yuzden iki seyi birden olcuyor: jetonun
# DOGRU baytlari, ve stdout yolunun redaksiyondan GECMEDIGI.
#
# KIMLIK KOLLARI: `bare` ve `proj` GEZILIYOR, `cfg`/`rooted` MUAF. Ama `proj`
# burada BASKA bir sey: `--project` bu yapragin KENDI bayragi (Go:
# `tokenExchangeCmd.Flags().StringVar`), kokun kalitilan bayragi DEGIL. Dort
# gozlemlenebilir sonucu asagida ayri ayri pinlendi.
#
# KAPI SIRASI, ve olculdu: service-token cifti kontrolu `--project`/`--key`
# kontrolunden ONCE. Yani cift YOKKEN eksik bayrak TOKEN_EXCHANGE_FAILED
# "not set" verir, "needs --project" DEGIL.
#
# GERCEK SIR YOK: CF_ACCESS_CLIENT_ID/SECRET degerleri senaryo ADLARIDIR ve
# basilan jeton sahte gate'in govdeden urettigi uydurma bir dizedir.
CI = {"CF_ACCESS_CLIENT_ID": "tok-ok", "CF_ACCESS_CLIENT_SECRET": "not-a-real-secret"}
TX = ["token", "exchange"]

def tx(name, argv, env=HUMAN, client_id=None):
    e = dict(env)
    e.update(CI)
    if client_id is not None:
        e["CF_ACCESS_CLIENT_ID"] = client_id
    return (name, TX + argv, e)

def tx_raw(name, argv, env=HUMAN):
    """argv'yi OLDUGU GIBI kullanir — kok bayraklari `token`den ONCE gelsin diye."""
    e = dict(env)
    e.update(CI)
    return (name, argv, e)

TOKEN_CASES = [
    # === TABAN: 2 kol x 2 mod ============================================
    # `proj` — yapragin KENDI `--project`i. Basari yolu: jeton stdout'a,
    # metadata satiri stderr'e. Iki akim AYRI pty'de olculuyor, yani
    # birini digerine yazan bir port GORUNUR.
    tx("human_token_exchange_mints_and_prints_the_token",
       ["--project", "testproj", "--key", "K"]),
    tx("agent_token_exchange_mints_and_prints_the_token",
       ["--project", "testproj", "--key", "K"], AGENT),
    # `bare` — hicbir kimlik bayragi yok. Bu ayni zamanda "--project zorunlu"
    # dali: cift VAR, bayrak YOK.
    tx("human_token_exchange_needs_a_project", ["--key", "K"]),
    tx("agent_token_exchange_needs_a_project", ["--key", "K"], AGENT),

    # === KAPI SIRASI =====================================================
    # Service-token cifti YOK: bayraklar da eksik olsa bile ret "not set".
    ("human_token_exchange_missing_service_creds_precede_the_flag_check",
     TX, dict(HUMAN, CF_ACCESS_CLIENT_ID="", CF_ACCESS_CLIENT_SECRET="")),
    # Ciftin YARISI: Go ikisini de SART kosuyor (id != "" && secret != "").
    ("agent_token_exchange_half_a_service_token_pair_is_not_enough",
     TX + ["--project", "testproj", "--key", "K"],
     dict(AGENT, CF_ACCESS_CLIENT_ID="tok-ok", CF_ACCESS_CLIENT_SECRET="")),
    # Cift BOSLUKTAN ibaret: Go TrimSpace ediyor -> yine "not set".
    ("agent_token_exchange_a_whitespace_service_token_pair_is_not_enough",
     TX + ["--project", "testproj", "--key", "K"],
     dict(AGENT, CF_ACCESS_CLIENT_ID="  ", CF_ACCESS_CLIENT_SECRET="  ")),
    # `--project` VAR ama `--key` YOK -> AYNI cumle (tek kontrol, iki kosul).
    tx("human_token_exchange_needs_at_least_one_key", ["--project", "testproj"]),
    # BOS bir `--key` bir anahtardir: `len(keys) != 0`, yani kontrol GECER ve
    # bos ad TEL'E biner. Uzunluga bakan bir port burada ayrisir.
    tx("human_token_exchange_an_empty_key_still_counts_as_one",
       ["--project", "testproj", "--key", ""]),

    # === KAPSAM TEL'E BINIYOR ============================================
    # `--key` TEKRARLANABILIR ve SIRA korunur (pflag StringArrayVar).
    # Basilan jeton govdeden uretildigi icin sira ciktida GORUNUR.
    tx("human_token_exchange_keys_are_repeatable_and_ordered",
       ["--project", "testproj", "--key", "B_KEY", "--key", "A_KEY"]),
    # `--verb` varsayilani ["read"], ve ILK `--verb` varsayilani EZER
    # (pflag stringArray: ilk Set replace, sonrakiler append). Bu OLCULDU.
    tx("human_token_exchange_the_first_verb_replaces_the_default",
       ["--project", "testproj", "--key", "K", "--verb", "write"]),
    tx("human_token_exchange_verbs_accumulate_after_the_first",
       ["--project", "testproj", "--key", "K", "--verb", "read", "--verb", "rotate"]),
    # `--ttl` govdeye YALNIZCA >0 iken giriyor (Go: `if ttlSeconds > 0`).
    tx("human_token_exchange_a_positive_ttl_rides_the_wire",
       ["--project", "testproj", "--key", "K", "--ttl", "300"]),
    tx("human_token_exchange_a_zero_ttl_is_omitted_from_the_body",
       ["--project", "testproj", "--key", "K", "--ttl", "0"]),
    tx("human_token_exchange_a_negative_ttl_is_omitted_from_the_body",
       ["--project", "testproj", "--key", "K", "--ttl", "-5"]),

    # === `-` ILE BASLAYAN DEGERLER =======================================
    # pflag'de bosluklu bir uzun bayrak SONRAKI jetonu KOSULSUZ deger sayar.
    # `--ttl -5` bunu zaten yukarida gezdi; ucu de ayri bayrak, ucu de ayri
    # vaka — cunku bir port bayraklardan yalnizca birini isaretleyebilir.
    tx("human_token_exchange_a_hyphen_leading_key_is_a_value_not_a_flag",
       ["--project", "testproj", "--key", "-K"]),
    tx("human_token_exchange_a_hyphen_leading_project_is_a_value_not_a_flag",
       ["--project", "-p1", "--key", "K"]),
    tx("human_token_exchange_a_hyphen_leading_verb_reaches_the_gate",
       ["--project", "testproj", "--key", "K", "--verb", "-x"]),

    # === SINIRLAR GATE'IN, ISTEMCININ DEGIL ==============================
    # Ikisi de OLCULDU: Go ne `--ttl`i ne `--verb`i dogruluyor. Reddi gate
    # veriyor, ve istemci onu `token exchange rejected (...)` diye basiyor.
    # Dogrulayan bir port bu reddi HIC gormezdi.
    tx("human_token_exchange_the_ttl_ceiling_belongs_to_the_gate",
       ["--project", "testproj", "--key", "K", "--ttl", "9999"]),
    tx("human_token_exchange_an_unknown_verb_is_rejected_by_the_gate",
       ["--project", "testproj", "--key", "K", "--verb", "delete"]),

    # === `--ttl` BIR TAMSAYI BAYRAGI =====================================
    # Ret cobra'nin AYRISTIRICISINDAN geliyor (RunE'ye HIC girilmiyor) ve
    # metin Go'nun `strconv.ParseInt(s, 0, 64)` prozasi. TABAN 0: onaltilik
    # ve sekizlik onekler GECERLI, ve bu da olculdu.
    tx("human_token_exchange_a_non_numeric_ttl_is_a_parse_error",
       ["--project", "testproj", "--key", "K", "--ttl", "abc"]),
    tx("agent_token_exchange_an_out_of_range_ttl_is_a_parse_error",
       ["--project", "testproj", "--key", "K", "--ttl", "99999999999999999999"], AGENT),
    tx("human_token_exchange_a_hex_ttl_parses_because_the_base_is_zero",
       ["--project", "testproj", "--key", "K", "--ttl", "0x10"]),

    # === GATE YANITININ DALLARI ==========================================
    # exp YOK -> stderr'e metadata satiri BASILMAZ (yalnizca `exp > 0`).
    tx("human_token_exchange_without_an_exp_there_is_no_metadata_line",
       ["--project", "testproj", "--key", "K"], client_id="tok-noexp"),
    # exp KENARI: gun/ay/yil tasmasi. RFC3339'u elde ureten bir port burada
    # ayrisir (2025-12-31T23:59:59Z).
    tx("human_token_exchange_an_edge_exp_still_formats_as_rfc3339",
       ["--project", "testproj", "--key", "K"], client_id="tok-exp-edge"),
    # 200 ama jeton BOSLUK / HIC YOK -> TOKEN_EXCHANGE_FAILED, ve stdout'a
    # BOS SATIR BILE basilmamali.
    tx("agent_token_exchange_a_blank_token_is_refused",
       ["--project", "testproj", "--key", "K"], AGENT, client_id="tok-blank"),
    tx("agent_token_exchange_an_absent_token_is_refused",
       ["--project", "testproj", "--key", "K"], AGENT, client_id="tok-absent"),
    # 400 ve govde BOS -> `safeCode("")` == "unknown".
    tx("human_token_exchange_a_bare_rejection_names_the_code_unknown",
       ["--project", "testproj", "--key", "K"], client_id="tok-reject-bare"),
    # 400 ve kod KIRLI -> `safeCode` temizligi mint yolunda da gecerli.
    tx("human_token_exchange_a_dirty_rejection_code_is_stripped",
       ["--project", "testproj", "--key", "K"], client_id="tok-reject-dirty"),
    # 400 DISINDAKI statuler mint'e OZEL DEGIL: mapHTTPError'a duserler.
    tx("agent_token_exchange_a_403_scope_error_is_a_session_error",
       ["--project", "testproj", "--key", "K"], AGENT, client_id="tok-scope"),
    tx("agent_token_exchange_a_503_is_a_service_misconfiguration",
       ["--project", "testproj", "--key", "K"], AGENT, client_id="tok-miscfg"),
    tx("agent_token_exchange_an_unexpected_status_is_named",
       ["--project", "testproj", "--key", "K"], AGENT, client_id="tok-teapot"),

    # === FAZLADAN ARGUMAN ================================================
    # Ayni sey mint yolunda da gecerli, ve orada bir SIR basiliyor: fazladan
    # bir arguman yuzunden reddeden bir port, calisan bir pipeline'i durdurur.
    tx("human_token_exchange_extra_args_are_silently_ignored",
       ["--project", "testproj", "--key", "K", "EXTRA"]),

    # === YEREL `--project` KOKUNKINI GOLGELIYOR ==========================
    #
    # `dr accept-epoch-reset`/`dr restore` ile AYNI TUZAK, ve bu yaprakta
    # DORDUNCU bir yuzu var. cobra'da bir yapragin YEREL bayragi kokun ayni
    # adli persistent bayragini GOLGELER, ve golge KOMUT SATIRINDAKI YERDEN
    # BAGIMSIZDIR — butun bayraklar yapragin flagset'ine karsi ayristirilir.
    #
    # DOGRU TARAF GO ve gerekce OLCULDU, hizalama degil: karsilikli dislama
    # bir KIMLIK kurali ve bu yaprakta `--project` kimlik bayragi DEGIL
    # (`Ctx::resolve` cagrilmiyor; deger dogrudan mint kapsamina giriyor).
    # Kontrol vakasi hemen yukarida: `whoami`nin YEREL `--project`i YOK ve
    # orada karsilikli dislama SURUYOR.
    #
    #   1. Alt komuttan ONCE yazilan `--project` yapraga ULASIR;
    tx_raw("human_token_exchange_a_root_project_flag_reaches_the_local_one",
           ["--project", "testproj"] + TX + ["--key", "K"]),
    #   2. `--config` + `--project` bu yaprakta KARSILIKLI DISLAYAN DEGIL,
    #      cunku kokun `--project`i HIC dolmuyor;
    tx_raw("human_token_exchange_config_and_a_shadowed_project_are_not_exclusive",
           ["--config", "x.yaml", "--project", "testproj"] + TX + ["--key", "K"]),
    #   3. SONUNCU KAZANIR: ikisi birden verildiginde yaprak kendi degerini
    #      alir (cobra tek degiskene yaziyor).
    tx_raw("human_token_exchange_the_local_project_wins_over_the_root_one",
           ["--project", "yokboyle"] + TX + ["--key", "K", "--project", "testproj"]),
    #   4. KISA BICIM YOK. Yerel `--project`in shorthand'i olmadigi icin
    #      golge `-p`yi de KALDIRIYOR: cobra "unknown shorthand flag" der.
    #      Bu, tuzagin OLCULMEMIS dorduncu yuzuydu — `-p` bu uc yaprakta
    #      (token exchange, dr restore, dr accept-epoch-reset) REDDEDILIYOR,
    #      yerel `--project`i olmayan yapraklarda ise CALISIYOR.
    tx_raw("human_token_exchange_the_shadow_also_removes_the_short_form",
           ["-p", "testproj"] + TX + ["--key", "K"]),
]

CASES += TOKEN_CASES

# GOLGENIN KISA-BICIM YUZU `dr`in IKI yapraginda da var, ve davranisi
# DEGISTIRILEN her yaprak korpusta gorunmeli — `dr restore`un golge vakalari
# nasil bu dosyaya girdiyse, bu da oyle. Kontrol vakasi UCUNCU satir:
# `dr verify`in YEREL `--project`i YOK, yani orada `-p` CALISMALI.
SHADOW_SHORT_FLAG_CASES = [
    ("agent_dr_accept_epoch_reset_rejects_the_short_project_form",
     ["-p", "testproj", "dr", "accept-epoch-reset"], AGENT),
    ("agent_dr_restore_rejects_the_short_project_form",
     ["-p", "testproj", "dr", "restore", "--snapshot", "snap", "--confirm"], AGENT),
    ("agent_dr_verify_still_accepts_the_short_project_form",
     ["-p", "testproj", "dr", "verify", "--snapshot", "snap"], AGENT),
]

CASES += SHADOW_SHORT_FLAG_CASES



# --- `wapps login` ------------------------------------------------------------
#
# ROOT-MOUNTED and without `Ctx::resolve`: `-p` is accepted and inert (the
# `proj` arm), `cfg`/`rooted` are waived in ARM_WAIVERS. The plain verb is
# TTY-only (agent mode refuses it BEFORE cloudflared runs); `--check` is
# allowed everywhere and wins over `--write`.
#
# Every case pins the gate to a FIXED, unreachable URL: login never talks to
# the gate, and the host it prints (and names the session file after) must
# not carry the per-binary fake-gate port.
#
# DETERMINISM: login prints `time.Until(exp)` with nanosecond precision, so a
# realistic expiry would print a different TTL on every run. The success
# cases use exp = 99999999999999, which Go SATURATES to maxDuration — a fixed
# string that also pins the saturation itself. `--check` prints whole seconds
# and uses `{NOW+N}` instead (see probe.py).
#
# NO REAL SECRET: every token below is an unsigned, made-up JWT.
def _b64u(raw):
    import base64
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

def fake_jwt(payload):
    return ".".join([_b64u('{"alg":"none"}'), _b64u(payload), _b64u("not-a-signature")])

LOGIN_GATE = {"WAPPS_SECRETS_GATE": "https://gate.example.invalid"}
CF_PATH = {"PATH": "{FIX}:/usr/bin:/bin"}
FAR_EXP = 99999999999999
DEV_JWT = fake_jwt('{"email":"dev@example.test","sub":"u1","exp":%d}' % FAR_EXP)
ADMIN_JWT = fake_jwt('{"email":"admin@example.test","exp":%d}' % FAR_EXP)

def sess(token, expires_at):
    """A session file exactly as Go's session.Save writes it."""
    return '{"token":"%s","expires_at":%s}' % (token, expires_at)

READ_FILE = "gate.example.invalid.json"
ADMIN_FILE = "gate.example.invalid-admin.json"

def lg(name, argv, env, token=None, sessions=None, **extra):
    e = dict(env, **LOGIN_GATE, **extra)
    if token is not None:
        e.update(CF_PATH, CF_SHIM_TOKEN=token)
    return (name, argv, e, None, None, None, None, sessions)

# The check cases read FILES, so the out-of-band env token is cleared.
NO_ENV_TOKEN = {"WAPPS_SESSION_TOKEN": ""}

LOGIN_CASES = [
    # === the SSO itself ====================================================
    lg("human_login_writes_the_read_session", ["login"], HUMAN, DEV_JWT,
       TUNNEL_TRANSPORT="quic", CLOUDFLARED_HOME="/elsewhere"),
    # --write: admin URL, admin label, its OWN file — the seeded read session
    # must survive byte-for-byte.
    lg("human_login_write_targets_the_admin_app_and_keeps_the_read_session",
       ["login", "--write"], HUMAN, ADMIN_JWT,
       sessions={READ_FILE: sess(DEV_JWT, 0)}),
    lg("human_login_without_exp_or_email_has_a_bare_success_line",
       ["login"], HUMAN, fake_jwt("{}")),
    # Go's json.Unmarshal accepts `null` into a struct as a no-op: a null
    # payload logs in with an unknown expiry instead of failing.
    lg("human_login_a_null_payload_logs_in_with_an_unknown_expiry",
       ["login"], HUMAN, fake_jwt("null")),
    # `proj` arm: the root flag is accepted and changes nothing.
    lg("human_login_project_flag_is_inert", P + ["login"], HUMAN, DEV_JWT),

    # === refusals before anything runs =====================================
    lg("agent_login_is_refused_before_cloudflared_runs", ["login"], AGENT, DEV_JWT),
    # No shim on PATH: ACTION_UNAVAILABLE, measured WITHOUT a shim.
    lg("human_login_without_cloudflared_is_action_unavailable", ["login"], HUMAN),

    # === the token cloudflared printed =====================================
    lg("human_login_an_empty_token_is_not_usable", ["login"], HUMAN, ""),
    lg("human_login_a_decorated_token_is_not_usable", ["login"], HUMAN, "token: " + DEV_JWT),
    lg("human_login_a_two_segment_token_is_not_usable", ["login"], HUMAN, "e30.e30"),
    lg("human_login_a_padded_segment_is_not_usable", ["login"], HUMAN, "e30.e30=.e30"),
    lg("human_login_a_payload_that_is_not_json", ["login"], HUMAN, fake_jwt("x")),
    lg("human_login_a_claim_of_the_wrong_type", ["login"], HUMAN, fake_jwt('{"exp":"soon"}')),

    # === cloudflared failing ===============================================
    lg("human_login_a_failing_sso_names_the_exit_status", ["login"], HUMAN, DEV_JWT,
       CF_SHIM_LOGIN_EXIT="3"),
    # The shim writes the token to stderr before failing: none of it may
    # reach the terminal.
    lg("human_login_a_failing_token_fetch_discards_its_stderr", ["login"], HUMAN, DEV_JWT,
       CF_SHIM_TOKEN_EXIT="4"),

    # === --check ===========================================================
    lg("human_login_check_with_no_session", ["login", "--check"], HUMAN, **NO_ENV_TOKEN),
    lg("agent_login_check_with_no_session", ["login", "--check"], AGENT, **NO_ENV_TOKEN),
    lg("human_login_check_reads_both_sessions_from_disk", ["login", "--check"], HUMAN,
       sessions={READ_FILE: sess(DEV_JWT, "{NOW+7200}"),
                 ADMIN_FILE: sess(ADMIN_JWT, "{NOW+900}")}, **NO_ENV_TOKEN),
    lg("human_login_check_an_expired_read_session", ["login", "--check"], HUMAN,
       sessions={READ_FILE: sess(DEV_JWT, 1)}, **NO_ENV_TOKEN),
    lg("human_login_check_without_an_admin_session", ["login", "--check"], HUMAN,
       sessions={READ_FILE: sess(DEV_JWT, 0)}, **NO_ENV_TOKEN),
    lg("human_login_check_an_expired_admin_session_is_reported_missing",
       ["login", "--check"], HUMAN,
       sessions={READ_FILE: sess(DEV_JWT, 0), ADMIN_FILE: sess(ADMIN_JWT, 1)}, **NO_ENV_TOKEN),
    # The out-of-band env token is key-independent: it stands in for the
    # read AND the admin session, and an opaque token has no subject.
    lg("human_login_check_the_env_token_stands_in_for_both_sessions",
       ["login", "--check"], HUMAN, WAPPS_SESSION_EXPIRES="{NOW+3600}"),
    lg("human_login_check_wins_over_write", ["login", "--check", "--write"], HUMAN),
    lg("agent_login_check_is_allowed_in_agent_mode", P + ["login", "--check"], AGENT),
    lg("human_login_extra_args_are_silently_ignored", ["login", "EXTRA", "--check"], HUMAN),
]
CASES += LOGIN_CASES

# --- the session FILE behind every store call -----------------------------------
#
# A login is only real if the next verb presents what it cached. These run
# against the LIVE fake gate, so the read file is named `{GATEFILE}` (probe.py
# builds 127.0.0.1_<port>) and the env token is cleared. `whoami`'s body is
# keyed by the token it receives, so "who-service" proves the FILE's token
# went out. The admin cases pin the split: /v1/admin is a separate CF Access
# app and its session lives under its own key.
SESSION_FILE_CASES = [
    ("human_whoami_presents_the_cached_read_session", ["whoami"], dict(HUMAN, **NO_ENV_TOKEN),
     None, None, None, None, {"{GATEFILE}.json": sess("who-service", 0)}),
    ("human_whoami_an_expired_cached_session_is_not_sent", ["whoami"], dict(HUMAN, **NO_ENV_TOKEN),
     None, None, None, None, {"{GATEFILE}.json": sess("who-service", 1)}),
    ("human_whoami_an_admin_session_alone_is_not_a_read_session", ["whoami"],
     dict(HUMAN, **NO_ENV_TOKEN),
     None, None, None, None, {"{GATEFILE}-admin.json": sess("who-service", 0)}),
    ("human_policy_show_presents_the_cached_admin_session", ["secrets", "policy", "show"],
     dict(HUMAN, **NO_ENV_TOKEN),
     None, None, None, None, {"{GATEFILE}-admin.json": sess("admin-token", 0)}),
    ("human_policy_show_a_read_session_alone_is_refused", ["secrets", "policy", "show"],
     dict(HUMAN, **NO_ENV_TOKEN),
     None, None, None, None, {"{GATEFILE}.json": sess("read-token", 0)}),
]
CASES += SESSION_FILE_CASES


# ============================================================================
# ARM KAPSAMI — HATIRLANAN BIR KURAL DEGIL, BIR MEKANIZMA
# ============================================================================
#
# AYNI KOR NOKTA IKI KEZ CIKTI (`set`, sonra `get`): bir fiilin vakalari hep
# `--project` geciriyor, yapilandirma kolu HIC gezilmiyor, ve o kolda GERCEK
# bir ayrisma saklaniyor (her ikisinde de DIFFERENT=3). Ikinci sefer sebep
# ADLANDIRILDI ama DUZELTILMEDI, cunku onerilen sebep YANLISTI.
#
# OLCUM (bkz. rapor): "korpustaki her vaka `--project` geciren bir yardimcidan
# doguyor" iddiasi yanlis. 359 vakanin 119'u `--project` geciriyordu, 239'u
# hicbir kimlik bayragi gecirmiyordu. Korpus elemanlarinin 199'u SATIR ICI
# TUPLE (164'u yardimci cagrisi), ve `P` ekleyen yardimcilarin IKISI (`e_h`,
# `e_a`) HIC CAGRILMIYOR. Yani "yardimci kalibini duzeltmek" korpusun
# yarisina bile dokunmazdi: `exec`in sekiz `--project` vakasi elle `P` yazan
# satir ici tuple'lardir.
#
# Gercek bosluk sayimda: bir fiilin KIMLIK KOLLARINDAN kacinin gezildigi HIC
# SAYILMIYORDU. Dort kol var, dordu de AYRI kod yolu:
#
#   proj   `--project <ad>`  -> projects::resolve; defterde yoksa override
#   cfg    `--config <yol>`  -> config_path SABITLENIR, cwd ILGISIZ
#   rooted bayrak yok, cwd'de `.wapps.yaml` VAR -> load_or_none DOLU
#   bare   bayrak yok, `.wapps.yaml` YOK        -> load_or_none BOS
#
# BU KONTROL IMPORT ANINDA KOSAR. Bir kol eksikse cases.py YUKLENMEZ; probe.py
# duser, differential.rs duser. Yani yeni bir fiilin bir kolunu unutmak
# IFADE EDILEMEZ — kolu atlamanin TEK yolu asagiya bir GEREKCE yazmaktir.
# Tabloda HIC yer almayan bir fiil DORT KOLU DA yurumek zorundadir; yani
# sessizlik "muaf" degil "gerekli" anlamina gelir.
#
# Kontrol yardimcilara DEGIL, uretilen VAKALARA bakiyor — satir ici tuple da,
# yardimci cagrisi da ayni kapiya girer.

# Bir fiilin YURUMESI GEREKEN kollar. `both` (--config + --project) bu
# listede DEGIL: o bir kimlik kolu degil, bir RET. Yine de arm_of onu
# ayri adlandiriyor ki `cfg`/`proj` sayimlarini SISIRMESIN.
ARM_NAMES = ("proj", "cfg", "rooted", "bare")


# Kimlik bayraklarinin HER IKI YAZIMI. KISA BICIMLER de burada, ve bu bir
# tamamlayicilik susu degil bir SAGLAMLIK duzeltmesi: ilk surum yalnizca
# `--config`/`--project` ariyordu, yani `-p testproj` gecen bir vaka `bare`
# (bayraksiz) sayilirdi — kontrol o fiilin bayraksiz kolunu GEZILMIS gorur ve
# tam da yakalamak icin var oldugu boslugu ONAYLARDI. Bugun korpusta kisa
# bicim kullanan vaka YOK (olculdu), yani bu bir hata duzeltmesi degil bir
# TUZAK kapatmasi.
IDENT_CONFIG = ("--config", "-c")
IDENT_PROJECT = ("--project", "-p")


def arm_verb(argv):
    """Bir argv'den fiil adini cikarir. Bayraklar ve `--` sonrasi ATILIR."""
    out, i = [], 0
    while i < len(argv):
        if argv[i] in IDENT_CONFIG or argv[i] in IDENT_PROJECT:
            i += 2
            continue
        if argv[i] == "--":
            break
        if argv[i].startswith("-"):
            i += 1
            continue
        out.append(argv[i])
        i += 1
    if not out:
        return "<none>"
    if out[0] in ("secrets", "rotate", "dr", "projects", "token", "coolify"):
        return out[0] + " " + (out[1] if len(out) > 1 else "?")
    return out[0]


def arm_of(case):
    """Vakanin gezdigi KIMLIK KOLU. Sira `Ctx::resolve` ile AYNI: once
    `--config` (ikisi birlikte verilirse `both`), sonra `--project`.

    `--` SONRASI ATILIR — ve bu bir ayrinti degil, bu dosyanin kendi
    kusuruydu: ilk surumde `arm_verb` `--`da duruyor ama `arm_of` DURMUYORDU.
    `secrets exec -- sh -c '... --config ...'` gibi bir vaka fiili dogru,
    KOLU YANLIS siniflanirdi; ve yanlis siniflanan bir kol "gezildi" sayilip
    kontrolun kendisini sessizce delerdi. Bugun etkilenen vaka sayisi OLCULDU
    ve SIFIR; yine de duzeltildi, cunku bu kontrolun tek isi tam olarak
    "gezilmis gorunen ama gezilmeyen kol"u yakalamak."""
    argv = case[1]
    if "--" in argv:
        argv = argv[: argv.index("--")]
    seed = case[5] if len(case) > 5 else None
    has_c = any(a in IDENT_CONFIG for a in argv)
    has_p = any(a in IDENT_PROJECT for a in argv)
    # BESINCI DURUM: ikisi birlikte. Dort kollu taksonomi bunu GORMUYORDU —
    # bir taksonominin kendi kor noktasi. Ayri bir kol degil (kod yolu bir
    # RET), ama sayilmasi sart ki `cfg` ya da `proj` diye YANLIS sayilmasin.
    if has_c and has_p:
        return "both"
    if has_c:
        return "cfg"
    if has_p:
        return "proj"
    files = (seed or {}).get("files") or {}
    if seed is not None and (seed.get("yaml") is not None
                             or any(k.endswith(".wapps.yaml") for k in files)):
        return "rooted"
    return "bare"


# ARM_WAIVERS: fiil -> {kol: GEREKCE}. Bir kolu atlamanin TEK yolu burasi ve
# GEREKCE bos olamaz. Her gerekce OLCULDU, tahmin edilmedi: asagidaki fiillerin
# hicbiri `Ctx::resolve` cagirmiyor (main.rs'te imzalarinda `config`/`project`
# parametresi YOK), yani onlar icin `--config`/`--project` gecen bir vaka
# yazmak bir kod yolu DEGIL, yalnizca clap/cobra'nin bayragi yutmasini olcerdi.
ARM_WAIVERS = {
    "doctor": {
        "proj": "run_doctor(mode) — Ctx::resolve YOK, imzasinda config/project yok",
        "cfg": "ayni sebep: doctor yerel `.wapps.yaml`e HIC bakmiyor",
        "rooted": "ayni sebep",
    },
    "dr split": {
        "proj": "run_dr_split — kokte mount'lu, Ctx hic cozulmuyor",
        "cfg": "ayni sebep",
        "rooted": "ayni sebep",
    },
    "dr combine": {
        "proj": "run_dr_combine — kokte mount'lu, Ctx hic cozulmuyor",
        "cfg": "ayni sebep",
        "rooted": "ayni sebep",
    },
    "dr verify": {
        "cfg": "run_dr_verify(snapshot) — Ctx::resolve YOK; buradaki tek "
               "`--project` vakasi bayragin ATIL oldugunu olcuyor",
        "rooted": "ayni sebep: yerel config bu fiile girmiyor",
    },
    "dr restore": {
        "cfg": "run_dr_restore — `--project` burada DR'IN KENDI zorunlu "
               "bayragi (snapshot icindeki proje adi), kimlik bayragi DEGIL; "
               "Ctx::resolve cagrilmiyor",
        "rooted": "ayni sebep",
    },
    "projects rm": {
        "proj": "run_projects_rm(project, yes) — storeProject cagirmiyor, "
                "config GEREKMIYOR (projects list'in AKSINE, ve bu olculdu)",
        "cfg": "ayni sebep",
        "rooted": "ayni sebep",
    },
    "dr accept-epoch-reset": {
        "cfg": "run_dr_accept_epoch_reset(project) — `--project` burada "
               "SEREMONININ KENDI zorunlu bayragi (kokun `-p`sini golgeliyor), "
               "kimlik bayragi DEGIL; Ctx::resolve cagrilmiyor",
        "rooted": "ayni sebep: yerel `.wapps.yaml` bu fiile hic girmiyor",
    },
    "dr bootstrap": {
        "cfg": "run_dr_bootstrap(argv, extra_vars, skip_preflight) — Ctx::resolve "
               "CAGRILMIYOR; buradaki tek `--project` vakasi bayragin ATIL "
               "oldugunu olcuyor, kimlik cozdugunu DEGIL",
        "rooted": "ayni sebep: yerel config bu fiile hic girmiyor",
    },
    "whoami": {
        "cfg": "run_whoami() — Ctx::resolve YOK, imzasinda config/project "
               "parametresi yok; buradaki `--project` vakalari bayragin ATIL "
               "oldugunu olcuyor, kimlik cozdugunu DEGIL",
        "rooted": "ayni sebep: whoami bir PROJEYE degil bir PRINCIPAL'a bakiyor, "
                  "yerel `.wapps.yaml`e HIC dokunmuyor",
    },
    "login": {
        "cfg": "run_login(check, write) — no Ctx::resolve, no config/project "
               "parameter; the `-p` cases measure that the flag is INERT",
        "rooted": "same reason: login targets the gate (a principal's session), "
                  "never a project, and does not read a local `.wapps.yaml`",
    },
    "token exchange": {
        "cfg": "run_token_exchange — `--project` burada YAPRAGIN KENDI bayragi "
               "(mint kapsaminin proje alani, kokun `-p`sini golgeliyor), kimlik "
               "bayragi DEGIL; Ctx::resolve cagrilmiyor",
        "rooted": "ayni sebep: yerel config bu fiile hic girmiyor — kapsam "
                  "bayraklardan, servis kimligi env'den geliyor",
    },
    "secrets policy": {
        "proj": "policy GLOBAL bir dokuman; run_policy_* config almiyor",
        "cfg": "ayni sebep",
    },
    "secrets rotate-plan": {
        "proj": "run_rotate_plan — Ctx::resolve YOK",
        "cfg": "ayni sebep",
    },
    "rotate skip": {
        "proj": "run_rotate_skip(run_id, target, reason) — proje adi "
                "ARGUMANDAN geliyor (`<proje>/<anahtar>`), bayraktan degil",
        "cfg": "ayni sebep",
    },
}


def _armcheck():
    seen = {}
    for c in CASES:
        if c[0] in EXCLUDED:
            continue
        seen.setdefault(arm_verb(c[1]), set()).add(arm_of(c))

    problems = []
    for verb in sorted(seen):
        waived = ARM_WAIVERS.get(verb, {})
        for arm in ARM_NAMES:
            if arm in seen[verb]:
                continue
            reason = waived.get(arm)
            if not reason:
                problems.append(
                    f"  {verb!r}: `{arm}` kolunun TEK VAKASI YOK. Ya bir vaka "
                    f"yaz, ya ARM_WAIVERS[{verb!r}][{arm!r}]'a bir GEREKCE."
                )
    # Tablo CURUMESIN: artik gerekmeyen ya da artik var olmayan bir muafiyet
    # sessizce durmasin — yoksa bir sonraki fiil onun arkasina saklanabilir.
    for verb, waived in sorted(ARM_WAIVERS.items()):
        if verb not in seen:
            problems.append(f"  {verb!r}: ARM_WAIVERS'ta ama korpusta VAKASI YOK (olu muafiyet)")
            continue
        for arm, reason in sorted(waived.items()):
            if not reason:
                problems.append(f"  {verb!r}/{arm}: muafiyetin GEREKCESI BOS")
            elif arm in seen[verb]:
                problems.append(
                    f"  {verb!r}/{arm}: muaf ama kol ARTIK GEZILIYOR — muafiyeti SIL")
    if problems:
        raise SystemExit(
            "cases.py: KIMLIK KOLU KAPSAMI EKSIK\n" + "\n".join(problems) +
            "\n\nDort kol: proj (--project) / cfg (--config) / rooted "
            "(bayraksiz + .wapps.yaml VAR) / bare (bayraksiz + config YOK).\n"
            "Bu kontrol iki kez ayni kor noktaya dusuldugu icin var: `set` ve "
            "`get`in yapilandirma kolu hic gezilmemisti ve IKISINDE DE gercek "
            "bir ayrisma sakliyordu."
        )



# --- BESINCI DURUM: `--config` ve `--project` BIRLIKTE ----------------------
#
# Dort kollu taksonominin GORMEDIGI durum, ve differential'da TEK BIR vakasi
# yoktu. Iki yerde birden reddediliyor ve hangisinin once atesledigi
# GOZLEMLENEBILIR: cobra `MarkFlagsMutuallyExclusive("config","project")`,
# clap `.conflicts_with("config")` — yani ret AYRISTIRMA aninda geliyor ve
# `Ctx::resolve`in kendi programatik korumasi ("--config and --project are
# mutually exclusive") bu yoldan ERISILEMEZ kaliyor. Iki ayri katmanda iki
# ayri metin var; hangisinin konustugu ancak boyle olculur.
BOTH_FLAG_CASES = [
    ("human_both_identity_flags_are_rejected",
     ["--config", "sub/.wapps.yaml"] + P + ["secrets", "get", "PLAIN_KEY"],
     HUMAN, None, None, _sub(VALID_CFG)),
    ("agent_both_identity_flags_are_rejected",
     ["--config", "sub/.wapps.yaml"] + P + ["secrets", "list"],
     AGENT, None, None, _sub(VALID_CFG)),
]

CASES += BOTH_FLAG_CASES

BOTH_FLAG_CASES += [
    # Fiilden BAGIMSIZ: `Ctx::resolve` CAGIRMAYAN bir fiil de ayni reddi
    # aliyor. Bu vaka olmadan ret `Ctx::resolve`in icine geri tasinabilir ve
    # `doctor`/`dr`/`policy`/`rotate`/`projects rm` sessizce iki bayragi da
    # kabul eder hale gelirdi.
    ("agent_doctor_both_identity_flags_are_rejected",
     ["--config", "sub/.wapps.yaml"] + P + ["doctor"], AGENT, None, None, _sub(VALID_CFG)),
    # ...`tofu` HARIC. Go'da TofuCmd root'a mount'lu ve DisableFlagParsing
    # acik, yani root'un hook'u kosmuyor: ret mutual-exclusion DEGIL,
    # "exec: no .wapps.yaml found". Istisnayi tutan sey bu vaka.
    ("agent_tofu_both_identity_flags_are_inert",
     ["--config", "sub/.wapps.yaml"] + P + ["tofu", "plan"], AGENT, None, None,
     _sub(VALID_CFG)),
]
CASES += BOTH_FLAG_CASES[-2:]


# `dr bootstrap` de BESINCI DURUMU almali, ve bunu VARSAYMAK yetmez.
#
# Go'da `DrCmd` KOKE mount'lu, yani root'un `PersistentPreRunE`u (mutual
# exclusion oradan geliyor) BU AGAC ICIN DE kosuyor — `doctor` ile ayni
# yapisal sebep. Rust'ta ret dispatch'ten ONCE ve FIILDEN BAGIMSIZ. Ikisi de
# ayni yere varmali ve ret DUZ olmali (kod oneki YOK).
#
# Bu vaka `agent_tofu_both_identity_flags_are_inert`in TERSINI pinliyor:
# `tofu` root'a mount'lu AMA `DisableFlagParsing` acik oldugu icin muaf;
# `dr` root'a mount'lu ve muaf DEGIL. Ikisi ayni cumleyle aciklanamaz, o
# yuzden ikisinin de vakasi var.
BOOTSTRAP_BOTH_FLAG_CASES = [
    ("human_dr_bootstrap_both_identity_flags_are_rejected",
     ["--config", "sub/.wapps.yaml"] + P + ["dr", "bootstrap", "--", "/bin/echo", "hi"],
     HUMAN, None, None, _sub(VALID_CFG)),
]
CASES += BOOTSTRAP_BOTH_FLAG_CASES


# --- KISA BICIMLER: `-p` / `-c` ----------------------------------------------
#
# Korpusta 359 vaka boyunca kisa bicimin TEK ornegi yoktu; kimlik bayraklari
# hep uzun yazilmisti. Iki tarafta da kayitli (`StringVarP`/`.short()`), yani
# atil degiller — yalnizca olculmemislerdi.
SHORT_FLAG_CASES = [
    ("agent_short_project_flag_behaves_like_the_long_one",
     ["-p", "testproj", "secrets", "list"], AGENT),
    ("human_short_config_flag_behaves_like_the_long_one",
     ["-c", "sub/.wapps.yaml", "secrets", "list"], HUMAN, None, b"y\n", _sub(VALID_CFG)),
]
CASES += SHORT_FLAG_CASES


# --- `secrets sync` (without --target) -----------------------------------------
#
# Gate order, measured from the Go oracle:
#
#   agent policy `allow` -> binding -> --target check -> require config ->
#   tofu preflight (only when a tofu source is declared) -> read every source
#   in order -> merge (later wins, one stderr line per overridden key) ->
#   envelopes to plain strings -> "no source keys" -> --dry-run report OR one
#   POST /import tagged `X-Wapps-Intent: sync`
#
# THE HELP TEXT IS NOT THE ORACLE: it says sync writes "an encrypted archive
# to dest"; the code writes the store. These cases follow the code.
#
# A sync never prints a value, and a successful import only prints a COUNT. So
# what was sent is made visible by the fake gate: an import that carries the
# key `__DIGEST__` is refused with a 409 whose code is a digest of the intent
# header and every value received (fakegate.py). Two binaries that send
# different values, or one that drops the intent, print different codes. The
# digest cases run in HUMAN mode: the agent envelope redacts the code.
#
# NO REAL SECRET: every value below is a made-up test string.
SYNC_FILE_CFG = VALID_CFG + "sources:\n  - type: file\n    path: sync.env\n"
SYNC_TOFU_CFG = VALID_CFG + "sources:\n  - type: tofu\n"
SYNC_FILES = {
    # ALPHA matches the gate's __ALL__ value, BETA differs, NEWKEY is new.
    "sync.env": "# a test file\nALPHA=alpha-test-value-long\n"
                "export BETA='changed-test-value'\nNEWKEY=\"new test value\"\n",
    # Every key of the gate's __ALL__ set, with the same values.
    "insync.env": "ALPHA=alpha-test-value-long\nBETA=beta-test-value-long\nTINY=ab\n",
    "nodelim.env": "ALPHA=fine\nbaretokenplaceholder\n",
    "comments.env": "# nothing but a comment\n\n",
    "denied.env": "DENIED_KEY=test-string\n",
    # Two sources, one shared key: the later one wins and the earlier value
    # must not reach the gate (the digest pins which value went out).
    "first.env": "__DIGEST__=first-test-string\nSHARED=from-the-first-file\n",
    "second.env": "SHARED=from-the-second-file\n",
}
# The tofu output: a string, a list with spaces, a null, a number, a bool and
# an object whose keys are NOT in sorted order. Go stringifies non-strings
# with json.Compact (whitespace dropped, key order and number text kept) and
# null as "". A port that re-serializes reorders `{"b":..,"a":..}`.
TOFU_OUT = ('{"__DIGEST__": {"value": "d", "type": "string"},\n'
            ' "ALPHA": {"value": "alpha-test-value-long", "type": "string", "sensitive": true},\n'
            ' "LIST": {"value": ["a b", 1, 2.50], "type": ["tuple", ["string", "number"]]},\n'
            ' "NOTHING": {"value": null},\n'
            ' "NUM": {"value": 1e3},\n'
            ' "FLAG": {"Value": true},\n'
            ' "OBJ": {"value": {"b": 1, "a": {"c": [ ]}}},\n'
            ' "NOVALUE": {"type": "string"}}\n')
TOFU_ENV = dict(TOFU_PATH,
                AWS_ACCESS_KEY_ID="fake-not-a-secret",
                AWS_SECRET_ACCESS_KEY="fake-not-a-secret",
                AWS_ENDPOINT_URL_S3="https://r2.example.invalid",
                AWS_REGION="auto",
                TF_VAR_state_passphrase="fake-not-a-secret")

def sy(name, argv, env, stdin=None, seed=None, pins=None):
    return (name, argv, env, pins, stdin, seed)

SYNC = ["secrets", "sync"]

SYNC_CASES = [
    # === the four identity arms x two modes ================================
    # `bare`: no flag, no config -> NOT_FOUND from requireStoreConfig("sync").
    sy("human_sync_no_config", SYNC, HUMAN),
    sy("agent_sync_no_config", SYNC, AGENT),
    # `proj`: `--project` does not stand in for a config (sync reads
    # `sources:`). Human -> NOT_FOUND; agent -> the binding gate fires first.
    sy("human_sync_project_flag_still_needs_a_config", P + SYNC, HUMAN),
    sy("agent_sync_project_flag_binding_refused", P + SYNC, AGENT),
    # `rooted`: an unpinned config refuses an agent; a human pins it with "y"
    # and the store is written.
    sy("agent_sync_config_unpinned", SYNC, AGENT, seed=cfg(SYNC_FILE_CFG, SYNC_FILES)),
    sy("human_sync_file_source_writes_the_store", SYNC, HUMAN, b"y\n",
       cfg(SYNC_FILE_CFG, SYNC_FILES)),
    # `cfg`: the source path resolves against the CONFIG's directory, not the
    # cwd. `sync.env` exists only under sub/.
    cf("human_sync_config_flag_resolves_sources_against_the_config_dir", SYNC, HUMAN,
       b"y\n", SYNC_FILE_CFG, {"sub/sync.env": SYNC_FILES["sync.env"]}),
    cf("agent_sync_config_flag_unpinned", SYNC, AGENT, None, SYNC_FILE_CFG,
       {"sub/sync.env": SYNC_FILES["sync.env"]}),

    # === service token: the binding is legitimately skipped =================
    sy("agent_sync_behind_a_service_token_writes_the_store", SYNC, CI_TOKENS,
       seed=cfg(SYNC_FILE_CFG, SYNC_FILES)),

    # === --dry-run: NAMES only, compared against the store =================
    # One bulk read, so the epoch pin ADVANCES (the plain sync never reads and
    # leaves it alone — the cases above pin that too).
    sy("human_sync_dry_run_names_new_and_changed_keys", SYNC + ["--dry-run"], HUMAN,
       b"y\n", cfg(SYNC_FILE_CFG, SYNC_FILES)),
    sy("agent_sync_dry_run_in_sync", SYNC + ["--dry-run"], CI_TOKENS, None,
       cfg(VALID_CFG + "sources:\n  - type: file\n    path: insync.env\n", SYNC_FILES)),
    sy("agent_sync_dry_run_epoch_downgrade_refused", SYNC + ["--dry-run"], CI_TOKENS, None,
       cfg(SYNC_FILE_CFG, SYNC_FILES), pins=pinfile(9)),

    # === sources failing ===================================================
    # `./nope.env`: the printed path is Go's filepath.Join, which CLEANS it
    # (no "/./" in the name).
    sy("human_sync_missing_source_file", SYNC, HUMAN, b"y\n",
       cfg(VALID_CFG + "sources:\n  - type: file\n    path: ./nope.env\n", SYNC_FILES)),
    # The error names the line and its LENGTH, never its text.
    sy("human_sync_malformed_env_line", SYNC, HUMAN, b"y\n",
       cfg(VALID_CFG + "sources:\n  - type: file\n    path: nodelim.env\n", SYNC_FILES)),
    sy("agent_sync_no_sources_declared", SYNC, CI_TOKENS, None, cfg(VALID_CFG)),
    sy("agent_sync_a_source_with_no_keys", SYNC, CI_TOKENS, None,
       cfg(VALID_CFG + "sources:\n  - type: file\n    path: comments.env\n", SYNC_FILES)),

    # === merge: later source wins, and the wire carries the sync intent ====
    sy("human_sync_later_source_overrides_and_the_import_is_tagged_sync", SYNC, HUMAN,
       b"y\n", cfg(VALID_CFG + "sources:\n  - type: file\n    path: first.env\n"
                 "  - type: file\n    path: second.env\n", SYNC_FILES)),

    # === gate errors carry the "import <project>" context ==================
    sy("human_sync_grant_denied", SYNC, HUMAN, b"y\n",
       cfg(VALID_CFG + "sources:\n  - type: file\n    path: denied.env\n", SYNC_FILES)),
    sy("human_sync_no_session", SYNC, dict(HUMAN, WAPPS_SESSION_TOKEN=""), b"y\n",
       cfg(SYNC_FILE_CFG, SYNC_FILES)),

    # === tofu source, through the `tofu` shim ==============================
    # The preflight runs BEFORE any source is read and lists what is missing.
    sy("agent_sync_tofu_preflight_names_the_missing_env", SYNC, dict(CI_TOKENS, **TOFU_PATH),
       None, cfg(SYNC_TOFU_CFG, {"tofu-output.json": TOFU_OUT})),
    # Values reach the wire stringified exactly as Go does (digest). HUMAN
    # mode on purpose: the agent envelope's scrubber redacts the digest (and
    # the workdir paths below) as high-entropy text, which would leave the
    # case comparing two "[REDACTED:28]" strings.
    sy("human_sync_reads_tofu_through_the_shim", SYNC, dict(HUMAN, **TOFU_ENV), b"y\n",
       cfg(SYNC_TOFU_CFG, {"tofu-output.json": TOFU_OUT})),
    # No output file in the workdir: the shim fails with a message on its
    # stderr, which is discarded; only "exit status 1" is reported.
    sy("human_sync_tofu_failure_discards_its_stderr", SYNC, dict(HUMAN, **TOFU_ENV), b"y\n",
       cfg(SYNC_TOFU_CFG)),
    sy("agent_sync_tofu_missing_binary", SYNC,
       dict(CI_TOKENS, **dict(TOFU_ENV, PATH="/usr/bin:/bin")), None,
       cfg(SYNC_TOFU_CFG, {"tofu-output.json": TOFU_OUT})),
    sy("human_sync_tofu_workdir_does_not_exist", SYNC, dict(HUMAN, **TOFU_ENV), b"y\n",
       cfg(SYNC_TOFU_CFG + "    workdir: infra\n", {"tofu-output.json": TOFU_OUT})),
    sy("agent_sync_tofu_output_is_not_an_object", SYNC, dict(CI_TOKENS, **TOFU_ENV), None,
       cfg(SYNC_TOFU_CFG, {"tofu-output.json": "[]"})),
    sy("agent_sync_tofu_envelope_is_not_an_object", SYNC, dict(CI_TOKENS, **TOFU_ENV), None,
       cfg(SYNC_TOFU_CFG, {"tofu-output.json": '{"A": "bare-string"}'})),

    # === --target ==========================================================
    # Only `coolify` is known; anything else is refused after the gates.
    sy("human_sync_unknown_target", SYNC + ["--target", "vault"], HUMAN, b"y\n",
       cfg(SYNC_FILE_CFG, SYNC_FILES)),
    # syncCmd has no Args: extra arguments are silently ignored.
    sy("agent_sync_extra_args_are_ignored", SYNC + ["EXTRA"], CI_TOKENS, None,
       cfg(SYNC_FILE_CFG, SYNC_FILES)),
]
CASES += SYNC_CASES


# --- `wapps skill` (install / status / uninstall) ------------------------------
#
# The skill lives under $HOME (user scope: ~/.claude/skills/wapps-secrets,
# linked to the materialized source ~/.config/wapps/skills/wapps-secrets) or
# under a project directory (--local, default the cwd). Every case gets its OWN
# home: `HOME={CASE}/home` puts it inside the case directory, which probe.py
# rebuilds for each binary and snapshots afterwards, symlinks recorded as their
# targets. So what each binary wrote (link vs copy, the refreshed source, the
# fingerprint marker, what uninstall left behind) is compared, not just the
# printed lines, and no case can reach the real ~/.claude.
#
# No gate, no binding, no Ctx::resolve: the identity flags are inert, which
# the four arms below measure rather than waive.
import os, sys  # noqa: E402
# The Go asset, found from the pty directory. That directory is this file's
# own OR on the import path: tests/armcheck.rs imports a COPY of this module
# from a temp dir, with the pty directory on PYTHONPATH.
def _skill_asset():
    rel = os.path.join("..", "..", "..", "..", "..", "internal", "skill",
                       "assets", "wapps-secrets", "SKILL.md")
    for base in [os.path.dirname(os.path.abspath(__file__))] + sys.path:
        fp = os.path.join(base, rel)
        if base and os.path.exists(fp):
            return open(fp, "rb").read()
    raise SystemExit("cases.py: internal/skill/assets/wapps-secrets/SKILL.md not found")
_SKILL_MD = _skill_asset()
_SKILL_FP = _hashlib.sha256(b"SKILL.md\0" + _SKILL_MD + b"\0").hexdigest()
_SK_SRC = "home/.config/wapps/skills/wapps-secrets/"
_SK_USER = "home/.claude/skills/wapps-secrets/"
_SK_PROJ = ".claude/skills/wapps-secrets/"
# A symlink install that is current: source + marker + link.
_SK_CURRENT_SRC = {_SK_SRC + "SKILL.md": _SKILL_MD, _SK_SRC + ".fingerprint": _SKILL_FP}
_SK_LINK = {_SK_USER + "SKILL.md": "{CASE}/" + _SK_SRC + "SKILL.md"}
# The post-`brew upgrade` state: an older binary's source and marker.
_SK_STALE_SRC = {_SK_SRC + "SKILL.md": b"an older skill text\n",
                 _SK_SRC + ".fingerprint": "0" * 64}
SKILL = ["skill"]
SK_HOME = {"HOME": "{CASE}/home"}

def sk(name, argv, env, files=None, links=None, yaml=None):
    return (name, argv, dict(env, **SK_HOME) if "HOME" not in env else env,
            None, None, {"yaml": yaml, "files": files or {}, "links": links or {}})

SKILL_CASES = [
    # === install, user scope (the default): symlink mode =====================
    sk("human_skill_install_user_fresh", SKILL + ["install"], HUMAN),
    sk("agent_skill_install_user_fresh", SKILL + ["install"], AGENT),
    # A correct link is kept; the source and marker are rewritten anyway.
    sk("human_skill_install_user_already_current", SKILL + ["install"], HUMAN,
       _SK_CURRENT_SRC, _SK_LINK),
    sk("human_skill_install_refreshes_a_stale_source", SKILL + ["install"], HUMAN,
       _SK_STALE_SRC, _SK_LINK),
    sk("human_skill_install_replaces_a_dangling_link", SKILL + ["install"], HUMAN,
       None, {_SK_USER + "SKILL.md": "{CASE}/nowhere/SKILL.md"}),
    # Go compares the link's target as a STRING: an equivalent but uncleaned
    # target is not "correct" and is rewritten.
    sk("human_skill_install_rewrites_an_uncleaned_link", SKILL + ["install"], HUMAN,
       _SK_CURRENT_SRC,
       {_SK_USER + "SKILL.md": "{CASE}/home/.config/wapps/skills/./wapps-secrets/SKILL.md"}),
    # A real file from an older copy install becomes a link.
    sk("human_skill_install_replaces_a_copied_file_with_a_link", SKILL + ["install"], HUMAN,
       {_SK_USER + "SKILL.md": _SKILL_MD}),
    sk("human_skill_install_user_copy", SKILL + ["install", "--copy"], HUMAN),
    # --dir without --local is ignored: still the user scope.
    sk("human_skill_install_dir_without_local_is_ignored",
       SKILL + ["install", "--dir", "proj"], HUMAN),

    # === install, project scope ==============================================
    sk("human_skill_install_local_symlink_notes_the_machine_path",
       SKILL + ["install", "--local"], HUMAN),
    sk("human_skill_install_local_copy", SKILL + ["install", "--local", "--copy"], HUMAN),
    sk("agent_skill_install_local_copy_overwrites_a_stale_file",
       SKILL + ["install", "--local", "--copy"], AGENT,
       {_SK_PROJ + "SKILL.md": b"an older skill text\n"}),
    # --dir is made absolute AND cleaned (filepath.Abs), and created.
    sk("human_skill_install_local_dir_is_cleaned",
       SKILL + ["install", "--local", "--copy", "--dir", "./x/../proj/"], HUMAN),
    sk("human_skill_install_local_dir_absolute",
       SKILL + ["install", "--local", "--dir", "{CASE}/proj"], HUMAN),

    # === install failures ====================================================
    # MkdirAll names the first component that is not a directory.
    sk("human_skill_install_local_dir_is_a_file",
       SKILL + ["install", "--local", "--dir", "afile"], HUMAN, {"afile": "x"}),
    sk("agent_skill_install_local_dir_is_a_file",
       SKILL + ["install", "--local", "--copy", "--dir", "afile"], AGENT, {"afile": "x"}),
    sk("human_skill_install_without_home", SKILL + ["install"], dict(HUMAN, HOME="")),
    # A project copy install never needs $HOME...
    sk("human_skill_install_local_copy_without_home",
       SKILL + ["install", "--local", "--copy"], dict(HUMAN, HOME="")),
    # ...but a project SYMLINK install does, and fails only AFTER it created
    # the destination directory.
    sk("human_skill_install_local_symlink_without_home",
       SKILL + ["install", "--local", "--dir", "proj"], dict(HUMAN, HOME=""),
       {"proj/keep": "x"}),
    # The source cannot be materialized: ~/.config is a file.
    sk("human_skill_install_source_dir_is_blocked", SKILL + ["install"], HUMAN,
       {"home/.config": "not a dir"}),
    # The link slot is a non-empty directory: removing it fails silently, and
    # the symlink call reports the collision.
    sk("human_skill_install_link_slot_is_a_directory", SKILL + ["install"], HUMAN,
       {_SK_USER + "SKILL.md/inner": "x"}),
    # An EMPTY directory in the link slot is removed (os.Remove falls back to
    # rmdir) and the link is made.
    ("human_skill_install_link_slot_is_an_empty_directory", SKILL + ["install"],
     dict(HUMAN, **SK_HOME), None, None,
     {"yaml": None, "files": {}, "dirs": [_SK_USER + "SKILL.md"]}),
    # $HOME is joined, so CLEANED: the link target carries no `//` or `/./`.
    sk("human_skill_install_uncleaned_home", SKILL + ["install"],
       dict(HUMAN, HOME="{CASE}//home/./")),
    # cobra.NoArgs: the extra argument is named as an unknown command.
    sk("agent_skill_install_extra_arg", SKILL + ["install", "extra"], AGENT),

    # === status ==============================================================
    sk("human_skill_status_nothing_installed", SKILL + ["status"], HUMAN),
    sk("human_skill_status_both_current", SKILL + ["status"], HUMAN,
       dict(_SK_CURRENT_SRC, **{_SK_PROJ + "SKILL.md": _SKILL_MD}), _SK_LINK),
    sk("agent_skill_status_both_stale", SKILL + ["status"], AGENT,
       dict(_SK_STALE_SRC, **{_SK_PROJ + "SKILL.md": b"an older skill text\n"}), _SK_LINK),
    sk("human_skill_status_dangling_link_is_stale", SKILL + ["status"], HUMAN,
       None, _SK_LINK),
    # The destination directory alone is not an install.
    sk("human_skill_status_empty_destination_is_not_installed", SKILL + ["status"], HUMAN,
       {_SK_USER + "README": "x", _SK_PROJ + "other.md": "x"}),
    # A directory in the file's place: present (copy mode), unreadable, stale.
    sk("human_skill_status_file_slot_is_a_directory", SKILL + ["status"], HUMAN,
       {_SK_PROJ + "SKILL.md/inner": "x"}),
    sk("human_skill_status_without_home", SKILL + ["status"], dict(HUMAN, HOME="")),
    # status has no flags of its own.
    sk("agent_skill_status_rejects_dir", SKILL + ["status", "--dir", "x"], AGENT),

    # === uninstall ===========================================================
    # The materialized source is left in place.
    sk("human_skill_uninstall_user", SKILL + ["uninstall"], HUMAN,
       _SK_CURRENT_SRC, _SK_LINK),
    sk("human_skill_uninstall_nothing_installed", SKILL + ["uninstall"], HUMAN),
    sk("human_skill_uninstall_local_dir", SKILL + ["uninstall", "--local", "--dir", "proj"],
       HUMAN, {"proj/" + _SK_PROJ + "SKILL.md": _SKILL_MD, "proj/keep": "x"}),
    # Not a directory: RemoveAll removes a plain file too.
    sk("human_skill_uninstall_destination_is_a_file", SKILL + ["uninstall", "--local"], HUMAN,
       {".claude/skills/wapps-secrets": "x"}),
    # A symlinked destination: the link goes, what it points at stays.
    sk("human_skill_uninstall_destination_is_a_link", SKILL + ["uninstall"], HUMAN,
       {"elsewhere/SKILL.md": _SKILL_MD},
       {"home/.claude/skills/wapps-secrets": "{CASE}/elsewhere"}),
    sk("agent_skill_uninstall_rejects_copy", SKILL + ["uninstall", "--copy"], AGENT),
    sk("human_skill_uninstall_without_home", SKILL + ["uninstall"], dict(HUMAN, HOME="")),

    # === the identity arms: inert ============================================
    sk("agent_skill_status_project_flag_is_inert", P + SKILL + ["status"], AGENT),
    sk("human_skill_install_config_flag_is_inert",
       ["--config", ".wapps.yaml"] + SKILL + ["install", "--local", "--copy"], HUMAN,
       yaml=VALID_CFG),
    sk("human_skill_status_rooted_config_is_ignored", SKILL + ["status"], HUMAN,
       yaml=VALID_CFG),
    sk("agent_skill_both_identity_flags_are_rejected",
       ["--config", ".wapps.yaml"] + P + SKILL + ["status"], AGENT, yaml=VALID_CFG),
]
CASES += SKILL_CASES
# --- `coolify update-env` and `coolify set-labels` ------------------------------
#
# Order, measured from the Go oracle:
#
#   flag parsing (pflag: every --env/--label value is read as CSV, the bool
#   --strip-cert-resolver by strconv.ParseBool; the first bad value from the
#   left wins) -> root PersistentPreRunE (--config + --project) -> required
#   --app-uuid -> COOLIFY_API_TOKEN -> the verb's own checks -> the app uuid
#   check (internal/coolify validateUUID) -> the HTTP calls
#
# No agent gate, no binding, no Ctx: `-c`/`-p` are inert, a local
# `.wapps.yaml` is never read. The four identity arms are walked anyway, so a
# port that started reading config here would show.
#
# The Coolify API is the fake in fakegate.py: COOLIFY_URL points at it and the
# app uuid / env key picks the scenario. A success prints only a count, so the
# "echo" scenarios refuse with a body that repeats what was received and the
# sha256 of the raw request bytes. Those run in HUMAN mode, like the sync
# digest cases (the agent envelope's scrubber may redact high-entropy text).
#
# Go upserts env keys in RANDOM order (a map range), so no case has more than
# one failing key; `BROKEN_Z` sorts last and fails on POST, which proves every
# key was sent whatever the order.
#
# NO REAL SECRET: the token and every value are made-up test strings.
COOLIFY_ENV = {"COOLIFY_URL": "{GATE}/api/v1",
               "COOLIFY_API_TOKEN": "coolify-test-token-not-a-secret"}
CH = dict(HUMAN, **COOLIFY_ENV)
CA = dict(AGENT, **COOLIFY_ENV)
UE = ["coolify", "update-env"]
SL = ["coolify", "set-labels"]
UE_OK = UE + ["--app-uuid", "app-ok", "--env", "A=1", "--env", "EXISTS_B=2"]
SL_OK = SL + ["--app-uuid", "app-ok", "--label", "traefik.enable=true"]
CERT = "traefik.http.routers.x.tls.certresolver=letsencrypt"

COOLIFY_CASES = [
    # === the four identity arms x two modes, per verb ======================
    ("human_coolify_update_env_upserts_every_key", UE_OK, CH),
    ("agent_coolify_update_env_upserts_every_key", UE_OK, CA),
    ("human_coolify_update_env_project_flag_is_inert", P + UE_OK, CH),
    ("agent_coolify_update_env_project_flag_is_inert", P + UE_OK, CA),
    cf("human_coolify_update_env_config_flag_is_inert", UE_OK, CH),
    cf("agent_coolify_update_env_config_flag_is_inert", UE_OK, CA),
    ("human_coolify_update_env_local_config_is_not_read", UE_OK, CH, None, None,
     cfg(VALID_CFG)),
    ("agent_coolify_update_env_local_config_is_not_read", UE_OK, CA, None, None,
     cfg(VALID_CFG)),
    ("human_coolify_set_labels_sets_the_labels", SL_OK, CH),
    ("agent_coolify_set_labels_sets_the_labels", SL_OK, CA),
    ("human_coolify_set_labels_project_flag_is_inert", P + SL_OK, CH),
    ("agent_coolify_set_labels_project_flag_is_inert", P + SL_OK, CA),
    cf("human_coolify_set_labels_config_flag_is_inert", SL_OK, CH),
    cf("agent_coolify_set_labels_config_flag_is_inert", SL_OK, CA),
    ("human_coolify_set_labels_local_config_is_not_read", SL_OK, CH, None, None,
     cfg(VALID_CFG)),
    ("agent_coolify_set_labels_local_config_is_not_read", SL_OK, CA, None, None,
     cfg(VALID_CFG)),

    # === update-env: refusals before any request ===========================
    ("agent_coolify_update_env_requires_app_uuid", UE + ["--env", "A=1"], CA),
    # Both missing: the required flag is reported, not the token.
    ("agent_coolify_update_env_required_flag_before_token", UE,
     dict(CA, COOLIFY_API_TOKEN="")),
    ("human_coolify_update_env_without_token", UE_OK, dict(CH, COOLIFY_API_TOKEN="")),
    ("human_coolify_update_env_value_without_equals", UE + ["--app-uuid", "app-ok",
     "--env", "A=1", "--env", "FOO"], CH),
    ("agent_coolify_update_env_empty_key", UE + ["--app-uuid", "app-ok", "--env", "=v"], CA),
    # pflag splits each value as CSV: "A=1,B" is two entries, the second bad.
    ("agent_coolify_update_env_value_is_split_on_commas",
     UE + ["--app-uuid", "app-ok", "--env", "A=1,B"], CA),
    ("human_coolify_update_env_bare_quote_is_a_flag_error",
     UE + ["--app-uuid", "app-ok", "--env", 'a"b'], CH),
    ("agent_coolify_update_env_only_a_newline_is_eof",
     UE + ["--app-uuid", "app-ok", "--env", "\n"], CA),
    # The env is parsed BEFORE the uuid is checked.
    ("human_coolify_update_env_bad_env_before_bad_uuid",
     UE + ["--app-uuid", "../x", "--env", "FOO"], CH),
    ("human_coolify_update_env_uuid_traversal",
     UE + ["--app-uuid", "../x", "--env", "A=1"], CH),
    ("agent_coolify_update_env_uuid_bad_character",
     UE + ["--app-uuid", "a.b", "--env", "A=1"], CA),
    ("agent_coolify_update_env_uuid_empty", UE + ["--app-uuid=", "--env", "A=1"], CA),
    # Zero envs still validates the uuid...
    ("agent_coolify_update_env_no_env_still_checks_the_uuid",
     UE + ["--app-uuid", "../x"], CA),
    # ...and with a good one prints a zero count without a request.
    ("agent_coolify_update_env_no_env_is_a_zero_count",
     UE + ["--app-uuid", "app-ok"], dict(CA, COOLIFY_URL="http://127.0.0.1:1/api/v1")),

    # === update-env: the wire ==============================================
    ("human_coolify_update_env_patch_after_409_fails",
     UE + ["--app-uuid", "app-ok", "--env", "GONE_A=1"], CH),
    ("human_coolify_update_env_every_key_is_sent",
     UE + ["--app-uuid", "app-ok", "--env", "A=1", "--env", "BROKEN_Z=1"], CH),
    ("human_coolify_update_env_post_body_echo",
     UE + ["--app-uuid", "app-ok", "--env", "ECHO_A=v<&>é x"], CH),
    ("human_coolify_update_env_patch_body_echo",
     UE + ["--app-uuid", "app-ok", "--env", "EXISTS_ECHO_A=patched"], CH),
    # A quoted CSV field keeps its comma; the echo shows the value sent.
    ("human_coolify_update_env_quoted_csv_keeps_the_comma",
     UE + ["--app-uuid", "app-ok", "--env", '"ECHO_K=a,b"'], CH),
    # The last value of a repeated key wins.
    ("human_coolify_update_env_repeated_key_last_wins",
     UE + ["--app-uuid", "app-ok", "--env", "ECHO_A=1", "--env", "ECHO_A=2"], CH),
    # ONE key: with two, every request fails and Go names a random one.
    ("agent_coolify_update_env_wrong_token",
     UE + ["--app-uuid", "app-ok", "--env", "A=1"],
     dict(CA, COOLIFY_API_TOKEN="not-the-test-token")),
    ("human_coolify_update_env_app_missing",
     UE + ["--app-uuid", "app-missing", "--env", "A=1"], CH),

    # === update-env: pflag/cobra shape =====================================
    ("agent_coolify_update_env_extra_args_are_ignored", UE_OK + ["EXTRA"], CA),
    ("agent_coolify_update_env_repeated_app_uuid_last_wins",
     UE + ["--app-uuid", "../x", "--app-uuid", "app-ok", "--env", "A=1"], CA),
    # A spaced long flag takes the next token even when it starts with `-`.
    ("agent_coolify_update_env_values_may_start_with_a_dash",
     UE + ["--app-uuid", "-x", "--env", "-A=1"], CA),
    ("agent_coolify_update_env_unknown_flag", UE_OK + ["--bogus"], CA),
    ("agent_coolify_update_env_both_identity_flags_are_rejected",
     ["--config", "sub/.wapps.yaml"] + P + UE_OK, CA, None, None, _sub(VALID_CFG)),
    # A bad flag VALUE is a parse error: it beats the root's mutual exclusion.
    ("agent_coolify_update_env_flag_value_error_before_identity_flags",
     ["--config", "sub/.wapps.yaml"] + P + UE + ["--env", 'a"b'], CA, None, None,
     _sub(VALID_CFG)),

    # === set-labels: refusals before any request ===========================
    ("agent_coolify_set_labels_requires_app_uuid", SL + ["--label", "a"], CA),
    ("human_coolify_set_labels_without_token", SL_OK, dict(CH, COOLIFY_API_TOKEN="")),
    ("human_coolify_set_labels_no_labels_refused", SL + ["--app-uuid", "app-ok"], CH),
    # Every label stripped -> the same refusal (nothing left to set).
    ("agent_coolify_set_labels_all_stripped_refused",
     SL + ["--app-uuid", "app-ok", "--label", CERT], CA),
    ("human_coolify_set_labels_empty_label_value_refused",
     SL + ["--app-uuid", "app-ok", "--label="], CH),
    # The empty-set refusal comes before the uuid check.
    ("human_coolify_set_labels_no_labels_before_bad_uuid", SL + ["--app-uuid", "../x"], CH),
    ("agent_coolify_set_labels_uuid_traversal",
     SL + ["--app-uuid", "../x", "--label", "a"], CA),
    ("agent_coolify_set_labels_bad_bool",
     SL + ["--app-uuid", "app-ok", "--label", "a", "--strip-cert-resolver=nope"], CA),
    ("agent_coolify_set_labels_label_csv_error",
     SL + ["--app-uuid", "app-ok", "--label", '"x'], CA),
    # Two bad values: pflag reports the one further LEFT.
    ("agent_coolify_set_labels_first_bad_value_wins_bool_first",
     SL + ["--app-uuid", "app-ok", "--strip-cert-resolver=nope", "--label", 'a"b'], CA),
    ("agent_coolify_set_labels_first_bad_value_wins_label_first",
     SL + ["--app-uuid", "app-ok", "--label", 'a"b', "--strip-cert-resolver=nope"], CA),

    # === set-labels: the wire ==============================================
    # Joined with "\n", certresolver labels stripped, CSV split; the echo
    # carries the decoded labels and the sha of the raw JSON bytes.
    ("human_coolify_set_labels_body_echo",
     SL + ["--app-uuid", "app-echo", "--label", "traefik.enable=true",
           "--label", CERT, "--label", "a,b"], CH),
    ("human_coolify_set_labels_keep_cert_resolver_when_off",
     SL + ["--app-uuid", "app-echo", "--label", "traefik.enable=true",
           "--label", CERT, "--strip-cert-resolver=false"], CH),
    ("human_coolify_set_labels_non_ascii_and_html_bytes",
     SL + ["--app-uuid", "app-echo", "--label", "rule=Host(`a.example`)&&<é>"], CH),
    ("agent_coolify_set_labels_strip_off_sets_everything",
     SL + ["--app-uuid", "app-ok", "--label", "a", "--label", CERT,
           "--strip-cert-resolver=0"], CA),
    # `--strip-cert-resolver false` (spaced): a bool flag takes no next token,
    # so `false` is an ignored argument and the strip stays ON.
    ("agent_coolify_set_labels_spaced_bool_value_is_an_argument",
     SL + ["--app-uuid", "app-ok", "--label", CERT, "--strip-cert-resolver", "false"], CA),
    ("agent_coolify_set_labels_bare_bool_is_true",
     SL + ["--app-uuid", "app-ok", "--label", CERT, "--strip-cert-resolver"], CA),
    ("human_coolify_set_labels_app_missing",
     SL + ["--app-uuid", "app-missing", "--label", "a"], CH),
    # The error body is cut at 200 bytes and "…" appended.
    ("human_coolify_set_labels_long_error_body_is_cut",
     SL + ["--app-uuid", "app-longbody", "--label", "a"], CH),
    ("agent_coolify_set_labels_long_error_body_is_cut",
     SL + ["--app-uuid", "app-longbody", "--label", "a"], CA),
    ("agent_coolify_set_labels_wrong_token", SL_OK,
     dict(CA, COOLIFY_API_TOKEN="not-the-test-token")),
    ("agent_coolify_set_labels_extra_args_are_ignored", SL_OK + ["EXTRA"], CA),
]
CASES += COOLIFY_CASES


# --- `coolify deploy-app`, `deploy-app-git`, `import-app` -----------------------
#
# Same order as update-env/set-labels: pflag flag VALUES (the CSV slices
# --env-from-shell, --watch-path, --build-arg and the bool --instant-deploy;
# the leftmost bad value wins) -> the root's --config/--project check ->
# cobra's REQUIRED flags (all missing ones named, in sorted order) ->
# COOLIFY_API_TOKEN -> the verb. No agent gate, no binding, no Ctx; the four
# identity arms are walked so a port that started reading config would show.
#
# These verbs WRITE files relative to the cwd (deploy-app[-git]:
# `.outputs/<name>-uuid`; import-app: `imports.sh` + `apps.tf`), so every
# case runs in its own directory and the probe compares what was written,
# bytes and modes. The fake API answers by what the client sends: the create
# `name` picks the scenario (COOLIFY_CREATE_SCENARIOS), the new app is
# "dc-<name>"/"gh-<name>", and `GET /applications` answers by the token's
# `:<tag>` (COOLIFY_LIST_SCENARIOS).
#
# NO REAL SECRET: the token and every value are made-up test strings.
DA = ["coolify", "deploy-app"]
DA_REQ = ["--project-uuid", "proj-1", "--server-uuid", "srv-1",
          "--compose-file", "compose.yml"]
DA_OK = DA + DA_REQ + ["--name", "web"]
# Short on purpose: the echo scenario repeats it inside a body cut at 200 bytes.
DA_COMPOSE = {"compose.yml": "services: {w: {image: 'a<&>é'}}\n"}

def da_seed(files=None, yaml=None):
    return {"yaml": yaml, "files": dict(DA_COMPOSE, **(files or {}))}

def dc(name, argv, env, files=None, yaml=None):
    return (name, argv, env, None, None, da_seed(files, yaml))

DG = ["coolify", "deploy-app-git"]
DG_REQ = ["--project-uuid", "proj-1", "--server-uuid", "srv-1",
          "--github-app-uuid", "ghapp-1", "--git-repo", "wappsdev/api"]
DG_OK = DG + DG_REQ + ["--name", "api"]
DG_ECHO = DG + DG_REQ + ["--name", "echo"]

IA = ["coolify", "import-app"]

def ia(name, argv, env, files=None, yaml=None):
    return (name, argv, env, None, None, {"yaml": yaml, "files": files or {}})

def tagged(env, tag):
    return dict(env, COOLIFY_API_TOKEN="coolify-test-token-not-a-secret:" + tag)

COOLIFY_DEPLOY_CASES = [
    # === deploy-app: the four identity arms x two modes ====================
    dc("human_coolify_deploy_app_creates_starts_and_writes_the_uuid", DA_OK, CH),
    dc("agent_coolify_deploy_app_creates_starts_and_writes_the_uuid", DA_OK, CA),
    dc("human_coolify_deploy_app_project_flag_is_inert", P + DA_OK, CH),
    dc("agent_coolify_deploy_app_project_flag_is_inert", P + DA_OK, CA),
    cf("human_coolify_deploy_app_config_flag_is_inert", DA_OK, CH, files=DA_COMPOSE),
    cf("agent_coolify_deploy_app_config_flag_is_inert", DA_OK, CA, files=DA_COMPOSE),
    dc("human_coolify_deploy_app_local_config_is_not_read", DA_OK, CH, yaml=VALID_CFG),
    dc("agent_coolify_deploy_app_local_config_is_not_read", DA_OK, CA, yaml=VALID_CFG),

    # === deploy-app: refusals before any request ===========================
    # Every missing required flag is named, sorted (pflag's VisitAll order).
    dc("agent_coolify_deploy_app_required_flags_all_named", DA, CA),
    dc("agent_coolify_deploy_app_required_flags_some_named",
       DA + ["--name", "web", "--server-uuid", "srv-1"], CA),
    # An EMPTY value still counts as set (cobra checks Changed, not the value).
    dc("agent_coolify_deploy_app_empty_value_counts_as_set",
       DA + DA_REQ + ["--name="], dict(CA, COOLIFY_API_TOKEN="")),
    dc("agent_coolify_deploy_app_required_flags_before_token", DA,
       dict(CA, COOLIFY_API_TOKEN="")),
    dc("human_coolify_deploy_app_without_token", DA_OK, dict(CH, COOLIFY_API_TOKEN="")),
    dc("human_coolify_deploy_app_compose_file_missing",
       DA + ["--project-uuid", "p", "--server-uuid", "s", "--name", "web",
             "--compose-file", "nope.yml"], CH),
    dc("agent_coolify_deploy_app_compose_file_is_a_directory",
       DA + ["--project-uuid", "p", "--server-uuid", "s", "--name", "web",
             "--compose-file", "compose.d"], CA, files={"compose.d/x": "x"}),
    # The compose file is read BEFORE the shell env is checked.
    dc("agent_coolify_deploy_app_compose_read_before_env",
       DA + ["--project-uuid", "p", "--server-uuid", "s", "--name", "web",
             "--compose-file", "nope.yml", "--env-from-shell", "NOT_SET_HERE"], CA),
    dc("human_coolify_deploy_app_env_from_shell_not_set",
       DA_OK + ["--env-from-shell", "DA_ONE", "--env-from-shell", "NOT_SET_HERE"],
       dict(CH, DA_ONE="one-test-value")),
    # Set but EMPTY is refused the same way.
    dc("agent_coolify_deploy_app_env_from_shell_empty_value",
       DA_OK + ["--env-from-shell", "DA_EMPTY"], dict(CA, DA_EMPTY="")),
    # A name with '=' is looked up as-is: no variable is called that.
    dc("agent_coolify_deploy_app_env_from_shell_name_with_equals",
       DA_OK + ["--env-from-shell", "DA_ONE=x"], dict(CA, DA_ONE="one-test-value")),
    dc("agent_coolify_deploy_app_env_from_shell_csv_error",
       DA_OK + ["--env-from-shell", 'a"b'], CA),
    dc("agent_coolify_deploy_app_flag_value_error_before_identity_flags",
       ["--config", "sub/.wapps.yaml"] + P + DA + ["--env-from-shell", 'a"b'], CA,
       files={"sub/.wapps.yaml": VALID_CFG}),
    dc("agent_coolify_deploy_app_both_identity_flags_are_rejected",
       ["--config", "sub/.wapps.yaml"] + P + DA_OK, CA,
       files={"sub/.wapps.yaml": VALID_CFG}),

    # === deploy-app: the wire ==============================================
    # The body: compose as padded base64, Go's sorted JSON keys and escaping.
    dc("human_coolify_deploy_app_create_body_echo", DA + DA_REQ + ["--name", "echo"], CH),
    # The env is upserted on the NEW app, from the shell, before the start.
    dc("human_coolify_deploy_app_env_from_shell_is_upserted",
       DA_OK + ["--env-from-shell", "DA_ONE,EXISTS_DA"],
       dict(CH, DA_ONE="one-test-value", EXISTS_DA="exists-test-value")),
    dc("human_coolify_deploy_app_env_from_shell_body_echo",
       DA_OK + ["--env-from-shell", "ECHO_DA"], dict(CH, ECHO_DA="v<&>é x")),
    dc("human_coolify_deploy_app_create_fails", DA + DA_REQ + ["--name", "broken"], CH),
    dc("agent_coolify_deploy_app_create_fails", DA + DA_REQ + ["--name", "broken"], CA),
    # No uuid in the answer: Go prints the decoded body with %v.
    dc("human_coolify_deploy_app_no_uuid_in_response", DA + DA_REQ + ["--name", "noid"], CH),
    dc("human_coolify_deploy_app_response_is_not_json",
       DA + DA_REQ + ["--name", "notjson"], CH),
    # The API's uuid is checked before it goes into a path.
    dc("human_coolify_deploy_app_bad_uuid_from_the_api_stops_the_start",
       DA + DA_REQ + ["--name", "badid"], CH),
    dc("human_coolify_deploy_app_bad_uuid_from_the_api_stops_the_env",
       DA + DA_REQ + ["--name", "badid", "--env-from-shell", "DA_ONE"],
       dict(CH, DA_ONE="one-test-value")),
    # A failed start writes nothing.
    dc("human_coolify_deploy_app_start_fails", DA + DA_REQ + ["--name", "fail-start"], CH),
    dc("agent_coolify_deploy_app_wrong_token", DA_OK,
       dict(CA, COOLIFY_API_TOKEN="not-the-test-token")),
    # `.outputs` is a FILE: both writes fail and Go ignores both.
    dc("human_coolify_deploy_app_output_write_errors_are_ignored", DA_OK, CH,
       files={".outputs": "in the way\n"}),
    # An existing uuid file is overwritten, not appended to.
    dc("agent_coolify_deploy_app_overwrites_the_uuid_file", DA_OK, CA,
       files={".outputs/web-uuid": "an-older-and-longer-uuid-value\n"}),
    dc("agent_coolify_deploy_app_empty_compose_file", DA_OK, CA,
       files={"compose.yml": ""}),
    dc("agent_coolify_deploy_app_extra_args_are_ignored", DA_OK + ["EXTRA"], CA),
    dc("agent_coolify_deploy_app_repeated_name_last_wins",
       DA + DA_REQ + ["--name", "other", "--name", "web"], CA),

    # === deploy-app-git: the four identity arms x two modes ================
    dc("human_coolify_deploy_app_git_creates_and_writes_the_uuid", DG_OK, CH),
    dc("agent_coolify_deploy_app_git_creates_and_writes_the_uuid", DG_OK, CA),
    dc("human_coolify_deploy_app_git_project_flag_is_inert", P + DG_OK, CH),
    dc("agent_coolify_deploy_app_git_project_flag_is_inert", P + DG_OK, CA),
    cf("human_coolify_deploy_app_git_config_flag_is_inert", DG_OK, CH),
    cf("agent_coolify_deploy_app_git_config_flag_is_inert", DG_OK, CA),
    dc("human_coolify_deploy_app_git_local_config_is_not_read", DG_OK, CH, yaml=VALID_CFG),
    dc("agent_coolify_deploy_app_git_local_config_is_not_read", DG_OK, CA, yaml=VALID_CFG),

    # === deploy-app-git: refusals before any request =======================
    dc("agent_coolify_deploy_app_git_required_flags_all_named", DG, CA),
    dc("agent_coolify_deploy_app_git_required_flags_some_named",
       DG + ["--name", "api", "--project-uuid", "p"], CA),
    dc("human_coolify_deploy_app_git_without_token", DG_OK, dict(CH, COOLIFY_API_TOKEN="")),
    dc("agent_coolify_deploy_app_git_bad_bool", DG_OK + ["--instant-deploy=nope"], CA),
    dc("agent_coolify_deploy_app_git_watch_path_csv_error",
       DG_OK + ["--watch-path", '"x'], CA),
    # Two bad values: the one further LEFT is reported.
    dc("agent_coolify_deploy_app_git_first_bad_value_wins_bool_first",
       DG_OK + ["--instant-deploy=nope", "--build-arg", 'a"b'], CA),
    dc("agent_coolify_deploy_app_git_first_bad_value_wins_slice_first",
       DG_OK + ["--build-arg", 'a"b', "--instant-deploy=nope"], CA),

    # === deploy-app-git: the create body ===================================
    # Defaults: branch main, dockerfile "Dockerfile", base "/", build pack
    # dockerfile, no watch paths, instant deploy ON (no build args to defer).
    dc("human_coolify_deploy_app_git_body_echo_defaults", DG_ECHO, CH),
    # With build args the create must NOT deploy: they are set first.
    dc("human_coolify_deploy_app_git_body_echo_build_args_defer_the_deploy",
       DG_ECHO + ["--build-arg", "A=1"], CH),
    dc("human_coolify_deploy_app_git_body_echo_instant_off",
       DG_ECHO + ["--instant-deploy=false"], CH),
    # A spaced bool value is an ignored argument: the deploy stays ON.
    dc("human_coolify_deploy_app_git_body_echo_spaced_bool_is_an_argument",
       DG_ECHO + ["--instant-deploy", "false"], CH),
    # Watch paths joined with "\n" (CSV split first); an empty --base-dir
    # falls back to "/".
    dc("human_coolify_deploy_app_git_body_echo_watch_paths_and_empty_base",
       DG_ECHO + ["--watch-path", "cmd/**", "--watch-path", "a,b", "--base-dir="], CH),
    dc("human_coolify_deploy_app_git_body_echo_every_value_flag",
       DG_ECHO + ["--git-branch", "dev", "--dockerfile", "/x/Dockerfile",
                  "--base-dir", "/svc", "--ports", "8080,3000",
                  "--build-pack", "nixpacks"], CH),

    # === deploy-app-git: build args and the deferred deploy ================
    dc("human_coolify_deploy_app_git_build_args_then_deploy",
       DG_OK + ["--build-arg", "A=1", "--build-arg", "EXISTS_B=x=y"], CH),
    dc("agent_coolify_deploy_app_git_build_args_then_deploy",
       DG_OK + ["--build-arg", "A=1,EXISTS_B=x=y"], CA),
    dc("human_coolify_deploy_app_git_build_args_without_deploy",
       DG_OK + ["--build-arg", "A=1", "--instant-deploy=false"], CH),
    # Malformed pairs are skipped but still COUNTED in the success line.
    dc("human_coolify_deploy_app_git_malformed_build_args_are_counted",
       DG_OK + ["--build-arg", "NOEQ", "--build-arg", "=v", "--build-arg", "A=1"], CH),
    # The build arg body: is_buildtime TRUE (the fake refuses anything else
    # on a "gh-*" app), PATCHed after a 409.
    dc("human_coolify_deploy_app_git_build_arg_body_echo",
       DG_OK + ["--build-arg", "EXISTS_ECHO_A=v<&>é"], CH),
    dc("human_coolify_deploy_app_git_build_arg_fails_after_the_create",
       DG_OK + ["--build-arg", "A=1", "--build-arg", "BROKEN_B=2"], CH),
    dc("human_coolify_deploy_app_git_deploy_fails",
       DG + DG_REQ + ["--name", "fail-deploy", "--build-arg", "A=1"], CH),
    dc("agent_coolify_deploy_app_git_create_fails", DG + DG_REQ + ["--name", "broken"], CA),
    dc("human_coolify_deploy_app_git_no_uuid_in_response",
       DG + DG_REQ + ["--name", "noid"], CH),
    # A bad uuid from the API is written to .outputs and printed; only the
    # build-arg call checks it.
    dc("human_coolify_deploy_app_git_bad_uuid_from_the_api",
       DG + DG_REQ + ["--name", "badid", "--build-arg", "A=1"], CH),
    dc("agent_coolify_deploy_app_git_extra_args_are_ignored", DG_OK + ["EXTRA"], CA),

    # === import-app: the four identity arms x two modes ====================
    ia("human_coolify_import_app_writes_imports_and_stubs", IA, CH),
    ia("agent_coolify_import_app_writes_imports_and_stubs", IA, CA),
    ia("human_coolify_import_app_project_flag_is_inert", P + IA, CH),
    ia("agent_coolify_import_app_project_flag_is_inert", P + IA, CA),
    cf("human_coolify_import_app_config_flag_is_inert", IA, CH),
    cf("agent_coolify_import_app_config_flag_is_inert", IA, CA),
    ia("human_coolify_import_app_local_config_is_not_read", IA, CH, yaml=VALID_CFG),
    ia("agent_coolify_import_app_local_config_is_not_read", IA, CA, yaml=VALID_CFG),

    # === import-app: filters, shapes, paths ================================
    ia("human_coolify_import_app_server_filter", IA + ["--server-uuid", "srv-1"], CH),
    ia("agent_coolify_import_app_server_filter_matches_nothing",
       IA + ["--server-uuid", "srv-none"], CA),
    ia("human_coolify_import_app_data_envelope", IA, tagged(CH, "data")),
    ia("agent_coolify_import_app_object_without_data_is_empty", IA, tagged(CA, "object")),
    ia("agent_coolify_import_app_body_not_json_is_empty", IA, tagged(CA, "notjson")),
    ia("human_coolify_import_app_list_fails", IA, tagged(CH, "missing")),
    ia("agent_coolify_import_app_list_fails", IA, tagged(CA, "missing")),
    ia("agent_coolify_import_app_wrong_token", IA,
       dict(CA, COOLIFY_API_TOKEN="not-the-test-token")),
    ia("human_coolify_import_app_without_token", IA, dict(CH, COOLIFY_API_TOKEN="")),
    # The printed paths are filepath.Join's: cleaned.
    ia("human_coolify_import_app_output_dir_is_cleaned",
       IA + ["--output-dir", "./a/../out//x/"], CH),
    ia("agent_coolify_import_app_empty_output_dir_is_the_cwd",
       IA + ["--output-dir="], CA),
    # Existing files are truncated.
    ia("agent_coolify_import_app_truncates_existing_files",
       IA + ["--output-dir", "out"], CA,
       files={"out/imports.sh": "x" * 4000, "out/apps.tf": "y" * 4000}),
    ia("human_coolify_import_app_output_dir_is_a_file",
       IA + ["--output-dir", "out"], CH, files={"out": "in the way\n"}),
    # apps.tf cannot be created: imports.sh is left behind, EMPTY.
    ia("human_coolify_import_app_stub_file_cannot_be_created",
       IA + ["--output-dir", "out"], CH, files={"out/apps.tf/keep": "x"}),
    ia("agent_coolify_import_app_extra_args_are_ignored", IA + ["EXTRA"], CA),
]
CASES += COOLIFY_DEPLOY_CASES


# --- `secrets sync --target=coolify` --------------------------------------------
#
# Order, measured from the Go oracle (cmd/secrets/sync_coolify.go):
#
#   agent policy `allow` -> binding (secretsPreRunE) -> --app/--all-apps
#   (exclusive, one required) -> COOLIFY_API_TOKEN -> .wapps.yaml (loaded, NOT
#   required through requireStoreConfig: its own sentence) -> ONE bulk store
#   read (the epoch pin advances) -> single-app: the app uuid check and the
#   env list, or multi-app: coolify_sync.apps -> per app: diff, print, apply.
#
# The Coolify URL comes ONLY from --coolify-url (never COOLIFY_URL), hence
# `{GATE}` in argv. `--dry-run` is ignored here: dry-run is the default and
# `--force` applies.
#
# The store answers project `coolproj` with its own set (GATE_SCRIPT
# "__ALL__@coolproj"); the fake API serves each app's env table
# (fakegate.py, COOLIFY_APP_ENVS). An apply prints only counts, so the
# journal apps (uuid "...-j") end every apply with a DELETE the fake refuses
# with a digest of every write it received, in order: values, flags, env
# uuids and the add -> change -> remove sequence.
#
# The diff is the destructive part and is walked as a matrix:
#   single-app (--app): the WHOLE archive, --prefix PREPENDED, Coolify keys
#     absent from it REMOVED (always), is_coolify keys skipped on both sides,
#     preview entries ignored, exclude_keys NOT applied;
#   multi-app (--all-apps): per app only the keys under its archive_prefix,
#     prefix STRIPPED (a key equal to the prefix dropped), exclude_keys
#     applied, removal only with delete_unmanaged; one app failing does not
#     stop the others, and any failure fails the command;
#   each x dry-run (default) / --force.
#
# NO REAL SECRET: every value is a made-up test string.
GATE_SCRIPT["__ALL__@coolproj"] = [200, {"epoch": 7, "values": {
    "ALPHA": "alpha-test-value-long",          # app-sync: unchanged
    "BETA": "beta-new-test-value",             # app-sync: changed
    "NEWKEY": "new test value",                # app-sync: added
    "MANAGED_URL": "stale-copy-test-value",    # app-sync: Coolify-managed
    "PREVIEWED": "runtime-test-value",         # app-sync: runtime equal, preview differs
    "PREVONLY": "p",                           # app-sync: only a preview entry
    "SENTRY_RELEASE": "r1",
    "WEB_PORT": "8080",                        # app-web: unchanged
    "WEB_HOST": "web.example.test",            # app-web: changed
    "WEB_SENTRY_RELEASE": "r2",                # app-web: excluded
    "WEB_SERVICE_FQDN_WEB": "x",               # app-web: Coolify-managed
    "WEB_": "strips-to-nothing",               # app-web: dropped (empty name)
    "API_PORT": "9090",                        # app-api: unchanged
    "API_SECRET_NAME": "api-test-string",      # app-api: added
}}]
COOL_CFG = "version: 2\nproject: coolproj\n"

def _multi(apps, delete=None, exclude=True):
    y = COOL_CFG + "coolify_sync:\n"
    if delete is not None:
        y += f"  delete_unmanaged: {delete}\n"
    if exclude:
        # A duplicate and two entries that never apply: counted once, and
        # only where the key is present and not already Coolify-managed.
        y += "  exclude_keys: [SENTRY_RELEASE, SERVICE_FQDN_WEB, UNUSED, SENTRY_RELEASE]\n"
    y += "  apps:\n"
    for uuid, name, prefix in apps:
        y += f"    - uuid: {uuid}\n"
        if name:
            y += f"      name: {name}\n"
        y += f"      archive_prefix: {prefix}\n"
    return y

MULTI_APPS = [("app-web", "web", "WEB_"), ("app-api", None, "API_"),
              ("app-none", "none", "NOPE_")]
COOL_MULTI = _multi(MULTI_APPS)
COOL_MULTI_DEL = _multi(MULTI_APPS, delete="true")

CS = ["secrets", "sync", "--target", "coolify", "--coolify-url", "{GATE}/api/v1"]
CS_APP = CS + ["--app", "app-sync"]
CS_ALL = CS + ["--all-apps"]
CSH = dict(HUMAN, COOLIFY_API_TOKEN="coolify-test-token-not-a-secret")
CSA = dict(CI_TOKENS, COOLIFY_API_TOKEN="coolify-test-token-not-a-secret")
CSAG = dict(AGENT, COOLIFY_API_TOKEN="coolify-test-token-not-a-secret")

def cs(name, argv, env, yaml=COOL_CFG, stdin=None, pins=None):
    """A sync case in its own dir with `yaml` as .wapps.yaml. A human case
    answers the binding prompt with "y"; an agent case runs behind the CI
    service token (the binding is legitimately skipped)."""
    if stdin is None and env.get("WAPPS_AGENT_MODE") == "0":
        stdin = b"y\n"
    return (name, argv, env, pins, stdin, cfg(yaml))

SYNC_COOLIFY_CASES = [
    # === the four identity arms x two modes ================================
    # `bare`: no config. Go's own sentence, not requireStoreConfig's NOT_FOUND.
    ("human_sync_coolify_no_config", CS_APP, CSH),
    ("agent_sync_coolify_no_config", CS_APP, CSAG),
    # `proj`: `--project` does not stand in for the config.
    ("human_sync_coolify_project_flag_still_needs_a_config", P + CS_APP, CSH),
    ("agent_sync_coolify_project_flag_binding_refused", P + CS_APP, CSAG),
    # `rooted`: an unpinned config refuses an agent; a human pins it.
    cs("agent_sync_coolify_config_unpinned", CS_APP, CSAG),
    cs("human_sync_coolify_single_app_dry_run", CS_APP, CSH),
    # `cfg`: the config is the flag's; the store is read for ITS project.
    cf("human_sync_coolify_config_flag", CS_APP, CSH, b"y\n", COOL_CFG),
    cf("agent_sync_coolify_config_flag_unpinned", CS_APP, CSAG, None, COOL_CFG),

    # === refusals before the store is read =================================
    cs("agent_sync_coolify_app_and_all_apps_are_exclusive",
       CS + ["--app", "app-sync", "--all-apps"], CSA),
    cs("agent_sync_coolify_needs_app_or_all_apps", CS, CSA),
    cs("human_sync_coolify_without_token", CS_APP, dict(CSH, COOLIFY_API_TOKEN="")),
    # The flag check comes before the token check.
    cs("agent_sync_coolify_flag_check_before_token", CS,
       dict(CSA, COOLIFY_API_TOKEN="")),
    # A config that fails to load: its error comes back plain. (A YAML SYNTAX
    # error is not used: yaml.v3 and the port's parser word it differently,
    # a known divergence of the shared loader, docs/PORT-kalan-yuzey.md.)
    cs("agent_sync_coolify_config_that_fails_to_load", CS_APP, CSA,
       yaml="version: 3\nproject: coolproj\n"),
    cs("human_sync_coolify_overlapping_prefixes_refused", CS_ALL, CSH,
       yaml=_multi([("app-web", "web", "WEB_"), ("app-api", None, "WEB_P")])),

    # === store errors =======================================================
    cs("human_sync_coolify_no_session", CS_APP,
       dict(CSH, WAPPS_SESSION_TOKEN="")),
    cs("agent_sync_coolify_epoch_downgrade_refused", CS_APP, CSA,
       pins=pinfile(9, "coolproj")),

    # === single-app: the diff ==============================================
    cs("agent_sync_coolify_single_app_dry_run", CS_APP, CSA),
    # `--dry-run` changes nothing here.
    cs("agent_sync_coolify_dry_run_flag_is_ignored", CS_APP + ["--dry-run"], CSA),
    # The list in a {"data": [...]} envelope diffs the same.
    cs("agent_sync_coolify_single_app_data_envelope",
       CS + ["--app", "app-data"], CSA),
    # A 2xx answer that is neither: an empty app, every key added.
    cs("agent_sync_coolify_single_app_empty_list", CS + ["--app", "app-object"], CSA),
    # --prefix is PREPENDED: every key is new and every Coolify key goes.
    cs("human_sync_coolify_single_app_prefix", CS_APP + ["--prefix", "X_"], CSH),
    cs("agent_sync_coolify_repeated_app_last_wins",
       CS + ["--app", "app-missing", "--app", "app-sync"], CSA),
    cs("agent_sync_coolify_extra_args_are_ignored", CS_APP + ["EXTRA"], CSA),

    # === single-app: --force ===============================================
    cs("human_sync_coolify_single_app_force", CS_APP + ["--force"], CSH),
    cs("agent_sync_coolify_single_app_force", CS_APP + ["--force"], CSA),
    # The journal: every write, in order, ends in the refused ZZ_JOURNAL delete.
    cs("human_sync_coolify_single_app_force_journal",
       CS + ["--app", "app-sync-j", "--force"], CSH),
    cs("human_sync_coolify_single_app_force_journal_with_prefix",
       CS + ["--app", "app-sync-j", "--force", "--prefix", "X_"], CSH),
    # Failures stop the apply where they happen (ADD, then a PATCH after 409,
    # then a DELETE), and nothing is reported as applied.
    cs("human_sync_coolify_single_app_add_fails",
       CS_APP + ["--force", "--prefix", "BROKEN_"], CSH),
    cs("agent_sync_coolify_single_app_patch_after_409_fails",
       CS_APP + ["--force", "--prefix", "GONE_"], CSA),
    cs("human_sync_coolify_single_app_remove_fails",
       CS + ["--app", "app-delfail", "--force"], CSH),
    # A key held twice at runtime: the LAST entry is compared (ALPHA is
    # unchanged) and its env uuid is the one deleted (the journal pins it).
    cs("human_sync_coolify_single_app_duplicate_runtime_key_last_wins",
       CS + ["--app", "app-dup-j", "--force"], CSH),
    # An env uuid from the API is checked before it goes into the path.
    cs("human_sync_coolify_single_app_bad_env_uuid",
       CS + ["--app", "app-badenv", "--force"], CSH),

    # === single-app: the app ===============================================
    # The uuid is checked AFTER the store read (the pin still advances).
    cs("human_sync_coolify_single_app_bad_uuid", CS + ["--app", "../x"], CSH),
    cs("agent_sync_coolify_single_app_missing", CS + ["--app", "app-missing"], CSA),
    cs("agent_sync_coolify_wrong_token", CS_APP,
       dict(CSA, COOLIFY_API_TOKEN="not-the-test-token")),

    # === multi-app ==========================================================
    cs("human_sync_coolify_all_apps_dry_run", CS_ALL, CSH, yaml=COOL_MULTI),
    cs("agent_sync_coolify_all_apps_dry_run", CS_ALL, CSA, yaml=COOL_MULTI),
    cs("human_sync_coolify_all_apps_force", CS_ALL + ["--force"], CSH, yaml=COOL_MULTI),
    cs("agent_sync_coolify_all_apps_force", CS_ALL + ["--force"], CSA, yaml=COOL_MULTI),
    cs("human_sync_coolify_all_apps_delete_unmanaged_dry_run", CS_ALL, CSH,
       yaml=COOL_MULTI_DEL),
    cs("agent_sync_coolify_all_apps_delete_unmanaged_force", CS_ALL + ["--force"], CSA,
       yaml=COOL_MULTI_DEL),
    # delete_unmanaged: false written out is the default.
    cs("agent_sync_coolify_all_apps_delete_unmanaged_false",
       CS_ALL + ["--force"], CSA, yaml=_multi(MULTI_APPS, delete="false")),
    # Without exclude_keys the excluded key is diffed like any other.
    cs("agent_sync_coolify_all_apps_without_exclude_keys", CS_ALL, CSA,
       yaml=_multi(MULTI_APPS, exclude=False)),
    # --prefix belongs to single-app and is ignored here.
    cs("agent_sync_coolify_all_apps_prefix_is_ignored",
       CS_ALL + ["--prefix", "X_"], CSA, yaml=COOL_MULTI),
    # Both journals: each app's writes, then each app's apply "fails" on the
    # digest; the second app still runs and the command fails naming both.
    cs("human_sync_coolify_all_apps_force_journal", CS_ALL + ["--force"], CSH,
       yaml=_multi([("app-web-j", "web", "WEB_"), ("app-api-j", None, "API_")],
                   delete="true")),
    # One app's list failing does not stop the next; dry-run line, then error.
    cs("human_sync_coolify_all_apps_list_failure_is_isolated", CS_ALL, CSH,
       yaml=_multi([("app-missing", "gone", "WEB_"), ("app-api", None, "API_")])),
    cs("agent_sync_coolify_all_apps_bad_app_uuid_in_config", CS_ALL + ["--force"], CSA,
       yaml=_multi([("a.b", "dotted", "WEB_"), ("app-api", None, "API_")])),
    # One app's apply failing does not stop the next.
    cs("human_sync_coolify_all_apps_apply_failure_is_isolated", CS_ALL + ["--force"], CSH,
       yaml=_multi([("app-delfail", "del", "WEB_"), ("app-api", None, "API_")],
                   delete="true")),
    cs("agent_sync_coolify_all_apps_no_coolify_sync_block", CS_ALL, CSA),
    cs("agent_sync_coolify_all_apps_empty_apps_list", CS_ALL, CSA,
       yaml=COOL_CFG + "coolify_sync:\n  delete_unmanaged: true\n  apps: []\n"),
]
CASES += SYNC_COOLIFY_CASES

_armcheck()
