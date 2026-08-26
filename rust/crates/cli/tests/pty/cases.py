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
