#!/usr/bin/env python3
"""HER FIILIN AJAN-MODU POLITIKASINI ve KAPI SIRASINI olcer.

Bu betigin varlik sebebi, portun en sik ayristigi sorunun tek bir yerde
adlandirilmasi: bir fiilin ajan modunda ne yaptigi, komsusundan TAHMIN
EDILEMEZ. Olculen alti nokta:

  secrets list   + ajan + --project  -> BINDING_UNPINNED   (allow, baglama VAR)
  secrets status + ajan + pinsiz cfg -> cikis 0            (allow, baglama MUAF)
  secrets rm     + ajan              -> AGENT_MODE_REFUSED (refuse_agent)
  projects list  + ajan + --project  -> cikis 0            (KOK mount: kapi YOK)
  projects rm    + ajan              -> CONTROL_PLANE_REQUIRED
  secrets init   + ajan + mevcut cfg -> BINDING_UNPINNED   (kapi YAZIMDAN once)

Ucuncu ve dorduncu satir YAN YANA duruyor cunku carpici olan o: iki fiil de
"yalnizca ADlar" sinifinda ve ikisi de ajana serbest, ama `secrets list`
baglama kapisinin arkasinda, `projects list` DEGIL.

Gate SAHTE ve yereldir; gercek bir gate'e HIC baglanilmaz ve buradaki hicbir
deger gercek bir sir DEGILDIR.
"""
import json, os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import GATE_SCRIPT

CFG = "version: 2\nproject: testproj\n"

# (ad, argv, mevcut_config_var_mi)
PROBES = [
    ("secrets_list",   ["--project", "testproj", "secrets", "list"], False),
    ("secrets_status", ["secrets", "status"], True),
    ("secrets_rm",     ["--project", "testproj", "secrets", "rm", "PLAIN_KEY", "--yes"], False),
    ("projects_list",  ["--project", "testproj", "projects", "list"], False),
    ("projects_rm",    ["projects", "rm", "vaulter", "--yes"], False),
    ("secrets_init",   ["secrets", "init"], True),
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

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    gate = subprocess.Popen([sys.executable, os.path.join(here, "fakegate.py"),
                             str(port), json.dumps(GATE_SCRIPT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), 0.05).close(); break
        except OSError: time.sleep(0.02)
    else:
        raise SystemExit("fake gate did not come up")

    res = {}
    try:
        for name, argv, with_cfg in PROBES:
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
