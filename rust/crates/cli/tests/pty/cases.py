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
    "tofu": ("#!/bin/sh\n"
             "echo \"argv: $*\"\n"
             "echo \"ALPHA=${ALPHA-<unset>}\"\n"
             "echo \"TF_VAR_ALPHA=${TF_VAR_ALPHA-<unset>}\"\n"
             "exit 3\n"),
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
    # BULGU (bkz. src/envverb.rs): Go O_CREATE|O_TRUNC kullaniyor, O_EXCL DEGIL.
    # Onceden duran bir `<hedef>.tmp` YENIDEN KULLANILIYOR ve modu 0600'e
    # CEKILMIYOR — duz metin sir 0644 ile kaliyor. Vaka bunu DUZELTMIYOR,
    # iki ikilinin AYNI modu urettigini olcuyor. probe.py `.tmp` sonekli
    # dosyalari atliyor ama `out.env`in MODU karsilastiriliyor.
    ("human_env_write_reuses_a_wide_temp",
     ["secrets", "env", "--write", "out.env"], HUMAN, None, b"y\n",
     cfg(VALID_CFG, {"out.env.tmp": ""})),
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
    # ...ve GERI SARMAZ: pin 9 iken sunulan 7 bir ROLLBACK'tir. GET /keys'in
    # hatasi YUTULDUGU icin bu vaka o yutmanin SINIRINI da gosteriyor —
    # epoch reddi bir clierr hatasi olarak yuzeye cikiyor mu, yoksa yutulup
    # import yine mi kosuyor? Cevabi Go veriyor.
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
# `Annotations: {wapps_agent_policy: refuse_agent}` DURUYOR ama OLU. O
# annotation'i okuyan tek yer secretsPreRunE ve o hook bu komut icin HIC
# kosmuyor (kok mount). Reddi gercekten yapan sey RunE'nin ICINDEKI elle
# yazilmis `agentmode.IsAgent()` kontrolu. Annotation silinse davranis
# DEGISMEZDI — ve annotation'a GUVENIP elle kontrolu silen biri, `wapps rotate
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
