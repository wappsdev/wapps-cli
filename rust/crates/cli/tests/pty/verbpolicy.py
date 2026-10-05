#!/usr/bin/env python3
"""HER FIILIN AJAN-MODU POLITIKASINI ve KAPI SIRASINI olcer.

Bu betigin varlik sebebi, portun en sik ayristigi sorunun tek bir yerde
adlandirilmasi: bir fiilin ajan modunda ne yaptigi, komsusundan TAHMIN
EDILEMEZ. Olculen alti nokta:

  secrets list       + ajan + --project  -> BINDING_UNPINNED   (allow, baglama VAR)
  secrets status     + ajan + pinsiz cfg -> cikis 0            (allow, baglama MUAF)
  secrets rm         + ajan              -> AGENT_MODE_REFUSED (refuse_agent)
  projects list      + ajan + --project  -> cikis 0            (KOK mount: kapi YOK)
  projects rm        + ajan              -> CONTROL_PLANE_REQUIRED
  secrets init       + ajan + mevcut cfg -> BINDING_UNPINNED   (kapi YAZIMDAN once)
  secrets trust-repo + ajan              -> AGENT_MODE_REFUSED (tty), FARKLI CUMLE
  secrets policy set + ajan              -> CONTROL_PLANE_REQUIRED (aile adiyla)
  secrets env        + ajan (print-form) -> AGENT_MODE_REFUSED (RunE'de)
  secrets env --write+ ajan              -> AGENT_MODE_REFUSED DEGIL: config kapisi
  secrets import-env + ajan + --project  -> BINDING_UNPINNED   (allow)
  wapps tofu         + ajan + pinsiz cfg -> BINDING_UNPINNED   (KOK mount, kapi ELLE)
  secrets rotate-plan+ ajan (bayraksiz)  -> CONTROL_PLANE_REQUIRED (kapi ARGUMANDAN once)
  rotate skip        + ajan (--reason'siz)-> INTERNAL          (kapi ARGUMANDAN SONRA)
  rotate skip        + ajan + --reason   -> AGENT_MODE_REFUSED (RunE'nin ICINDE)
  wapps doctor       + ajan              -> KAPI YOK (hicbir ret kodu yok)

`tofu` satiri `projects list` satiriyla YAN YANA okunmali: IKISI DE kokte
mount'lu, yani ikisinde de PersistentPreRunE kosmuyor — ama `projects list`
kapisiz kaliyor, `tofu` kapiyi RunE'de ELLE yeniden uyguluyor. Kok mount tek
basina "kapi yok" DEMEK DEGIL; hangisinin hangisi oldugu OLCULMEK zorunda.
Bu satirin duzelmesi `wapps tofu`yu her sirri okuyan, kapisiz bir yola cevirir.

`rotate-plan` ile `rotate skip` satirlari da YAN YANA: kardes gorunuyorlar ve
kapi siralari BIRBIRININ AYNASI. Birinde ajan kapisi arguman kontrolunden
ONCE, digerinde SONRA — cunku biri PersistentPreRunE'lu bir agacta, digeri
kokte.

Ucuncu ve dorduncu satir YAN YANA duruyor cunku carpici olan o: iki fiil de
"yalnizca ADlar" sinifinda ve ikisi de ajana serbest, ama `secrets list`
baglama kapisinin arkasinda, `projects list` DEGIL.

UC AYRI "AGENT_MODE_REFUSED" var ve METINLERI AYRI: `rm` (refuse_agent,
"surface refused..."), `trust-repo` (tty, "this command requires a human
terminal"), `env` print-form (refuse_agent, RunE'de — kapi sirasi farkli).
Ayni kodu paylasmalari onlari ayni yapmiyor; operator CUMLEYI okuyor.

`policy set` satiri bu tablonun EN KRITIK satiri: gating anahtari SecretsCmd'nin
ALTINDAKI ILK seviye ad ("policy"), YAPRAK ad ("set") DEGIL. Yaprak adla
anahtarlanan bir port, `policy set`e data-plane `set`in `allow` iznini MIRAS
ALDIRIR ve bir ajan yetki kurallarini yazabilir.

Gate SAHTE ve yereldir; gercek bir gate'e HIC baglanilmaz ve buradaki hicbir
deger gercek bir sir DEGILDIR.
"""
import json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import GATE_SCRIPT
import gateproc

CFG = "version: 2\nproject: testproj\n"

# (ad, argv, mevcut_config_var_mi[, ek_env])
#
# Ek env yalnizca `doctor` icin gerekiyor ve gercek bir sebebi var: doctor
# COOLIFY_URL'e GERCEK bir HTTP istegi atiyor ve ayarlanmazsa canli internete
# cikardi. Sahte gate'e ceviriliyor.
PROBES = [
    ("secrets_list",   ["--project", "testproj", "secrets", "list"], False),
    ("secrets_status", ["secrets", "status"], True),
    ("secrets_rm",     ["--project", "testproj", "secrets", "rm", "PLAIN_KEY", "--yes"], False),
    ("projects_list",  ["--project", "testproj", "projects", "list"], False),
    ("projects_rm",    ["projects", "rm", "vaulter", "--yes"], False),
    ("secrets_init",   ["secrets", "init"], True),
    ("secrets_trustrepo", ["secrets", "trust-repo"], True),
    ("secrets_policy_show", ["secrets", "policy", "show"], True),
    # AILE ADIYLA KAPILANMA: `set` yaprak adi data-plane `set`in izniyle
    # KARISTIRILMAMALI. Bu satirin duzelmesi, bir ajana policy yazdirir.
    ("secrets_policy_set", ["secrets", "policy", "set", "nope.json"], True),
    ("secrets_env_print", ["secrets", "env"], False),
    # `--write` print-form reddini GECER; ret bir sonraki kapidan gelir.
    ("secrets_env_write", ["secrets", "env", "--write", "out.env"], False),
    ("secrets_import_env", ["--project", "testproj", "secrets", "import-env", "x.env"], False),
    # KOK MOUNT ama KAPI VAR: `projects list` ile AYNI mount, TERS sonuc.
    ("tofu", ["tofu", "plan"], True),
    # Kapi ARGUMAN KONTROLUNDEN ONCE (PersistentPreRunE).
    ("secrets_rotate_plan", ["secrets", "rotate-plan"], False),
    # ...ve kardesinde TERSI: kapi `--reason` kontrolunden SONRA.
    ("rotate_skip_no_reason", ["rotate", "skip", "run1", "p/k"], False),
    ("rotate_skip_with_reason",
     ["rotate", "skip", "run1", "p/k", "--reason", "public constant"], False),
    # KAPI YOK: hicbir ret kodu cikmamali.
    ("doctor", ["doctor"], False, {"COOLIFY_URL": "__GATE__"}),
]


def main():
    binary, outpath, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
    here = os.path.dirname(os.path.abspath(__file__))
    # Her ikili KENDI dizininde kosar: paylasilan bir XDG dizini, ilk kosumun
    # biraktigi bir pin'i ikinciye miras birakirdi ve ikinci ikili kapiyi HIC
    # gormezdi (sessizce bos bir olcum).
    tag = os.path.basename(outpath).replace(".json", "")
    workdir = os.path.join(workdir, "policy", tag)
    os.makedirs(workdir, exist_ok=True)

    gate, port = gateproc.start(os.path.join(here, "fakegate.py"),
                                [json.dumps(GATE_SCRIPT)])

    res = {}
    try:
        for probe in PROBES:
            name, argv, with_cfg = probe[0], probe[1], probe[2]
            extra = probe[3] if len(probe) > 3 else {}
            casedir = os.path.join(workdir, name)
            os.makedirs(casedir, exist_ok=True)
            if with_cfg:
                with open(os.path.join(casedir, ".wapps.yaml"), "w") as f:
                    f.write(CFG)
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": os.path.join(workdir, "fakehome"),
                "XDG_CONFIG_HOME": os.path.join(workdir, "xdgcfg"),
                "TERM": "dumb",
                "WAPPS_SECRETS_GATE": f"http://127.0.0.1:{port}",
                "WAPPS_SESSION_TOKEN": "fake-token-not-a-secret",
                "WAPPS_NO_UPDATE_CHECK": "1",
                "GIT_CEILING_DIRECTORIES": workdir,
                "CLAUDECODE": "1",   # pty'de stdin TTY ama AJAN isareti var
            }
            env.update({k: v.replace("__GATE__", f"http://127.0.0.1:{port}")
                        for k, v in extra.items()})
            os.makedirs(env["HOME"], exist_ok=True)
            os.makedirs(env["XDG_CONFIG_HOME"], exist_ok=True)
            o, e, c = run([binary] + argv, env, cwd=casedir)
            res[name] = {"stdout": o.decode("utf-8", "replace"),
                         "stderr": e.decode("utf-8", "replace"), "exit": c}
    finally:
        gate.terminate(); gate.wait()

    with open(outpath, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print(f"wrote {len(res)} policy observations -> {outpath}")


main()
