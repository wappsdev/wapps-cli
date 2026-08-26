#!/usr/bin/env python3
"""`secrets exec` ve `secrets apply`in ONUNDEKI kapilari OLCER.

Bu bir port testi DEGIL — bir PREMIS pini. Bu dilim `set`i portladi ama
exec/apply'i portlamadi ve sebep bir tahmin degil, asagida olculen sey:

  1. `--project <ad>` bu iki verb icin config gereksinimini ATLATMIYOR.
     get/set `storeProject` kullaniyor (proje ADI yeter); exec/apply
     `requireStoreConfig` kullaniyor ve yerel bir .wapps.yaml SART.
  2. .wapps.yaml VARSA ve --project YOKSA, repo->proje baglamasi ETKILESIMLI
     bir onay istiyor ("Bind them? [y/N]").

Yani iki verb'un onunde iki AYRI portlanmamis altsistem var: .wapps.yaml
yukleme/dogrulama (bir YAML ayristiricisi = yeni bir bagimlilik karari) ve
baglama pin defteri. Biri degisirse bu test kirilir ve sonraki dilimi yazan
kisi planin degistigini OGRENIR — bir yorumun bayatlamasiyla degil.

Yalnizca GO ikilisi olculur: burada kanitlanan sey oracle'in on kosulu.
"""
import json, os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import GATE_SCRIPT

WITH_CFG = "version: 2\nbackend: store\nproject: testproj\ntargets:\n  - path: .env.local\n"


def main():
    go_bin, outpath, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
    here = os.path.dirname(os.path.abspath(__file__))

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

    nocfg = os.path.join(workdir, "nocfg")
    withcfg = os.path.join(workdir, "withcfg")
    os.makedirs(nocfg, exist_ok=True); os.makedirs(withcfg, exist_ok=True)
    with open(os.path.join(withcfg, ".wapps.yaml"), "w") as f:
        f.write(WITH_CFG)

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.path.join(workdir, "fakehome"),
        "XDG_CONFIG_HOME": os.path.join(workdir, "xdgcfg"),
        "TERM": "dumb",
        "WAPPS_SECRETS_GATE": f"http://127.0.0.1:{port}",
        "WAPPS_SESSION_TOKEN": "fake-token-not-a-secret",
        "WAPPS_NO_UPDATE_CHECK": "1",
        "WAPPS_AGENT_MODE": "0",          # pty + override => INSAN modu
    }
    os.makedirs(env["HOME"], exist_ok=True)
    os.makedirs(env["XDG_CONFIG_HOME"], exist_ok=True)

    verbs = {"exec": ["secrets", "exec", "--", "/bin/echo", "hi"],
             "apply": ["secrets", "apply"]}
    res = {}
    try:
        for vname, argv in verbs.items():
            # --project VERILMIS ama config YOK -> config kapisi
            o, e, c = run([go_bin, "--project", "testproj"] + argv, env, cwd=nocfg)
            res[f"{vname}_project_flag_no_config"] = {
                "stderr": e.decode("utf-8", "replace"), "exit": c}
            # config VAR ama --project YOK -> baglama onayi
            o, e, c = run([go_bin] + argv, env, cwd=withcfg, timeout=6)
            res[f"{vname}_config_no_project"] = {
                "stderr": e.decode("utf-8", "replace"), "exit": c}
    finally:
        gate.terminate(); gate.wait()

    with open(outpath, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print(f"wrote {len(res)} gate observations -> {outpath}")


main()
