#!/usr/bin/env python3
"""`secrets exec`, `secrets apply` ve `secrets get`in ONUNDEKI kapilari OLCER.

  1. `--project <ad>` exec/apply icin config gereksinimini ATLATMIYOR.
     get/set `storeProject` kullaniyor (proje ADI yeter); exec/apply
     `requireStoreConfig` kullaniyor ve yerel bir .wapps.yaml SART.
     Bu kapi `get` icin TERSINE olculuyor: ayni cagri exec/apply'i NOT_FOUND
     ile dusururken get'i GECIRMELI. Iki yon bir arada olmazsa "hepsini
     requireStoreConfig yap" diye bir sadelestirme sessizce gecerdi.
  2. .wapps.yaml VARSA ve --project YOKSA, repo->proje baglamasi ETKILESIMLI
     bir onay istiyor ("Bind them? [y/N]") — get icin de.
  3. `get`in ajan reddi baglama kontrolunden ONCE geliyor: config'i olan
     pinlenmemis bir dizinde ajan modunda mesaj AGENT_MODE_REFUSED olmali,
     BINDING_UNPINNED DEGIL. (`list` AYNI kosulda BINDING_UNPINNED veriyor —
     fark politikadan geliyor, kapi sirasindan degil.)

Onceki dilimde bu betik yalnizca GO'yu olcuyordu, cunku bu iki kapinin
arkasindaki altsistemler (config yukleme/dogrulama ve baglama pin defteri)
portlanmamisti. Ikisi de indi; betik artik ISTENEN ikiliyi olcuyor ve cagiran
taraf ikisini de gezip AYNI kapilari bekliyor.

Gate SAHTE ve yereldir; gercek bir gate'e HIC baglanilmaz ve buradaki hicbir
deger gercek bir sir DEGILDIR.
"""
import json, os, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import GATE_SCRIPT

WITH_CFG = "version: 2\nbackend: store\nproject: testproj\ntargets:\n  - path: .env.local\n"


def main():
    binary, outpath, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
    here = os.path.dirname(os.path.abspath(__file__))
    # Her ikili KENDI dizinlerinde kosar: paylasilan bir XDG dizini, ilk
    # kosumun biraktigi bir pin'i ikinciye miras birakirdi ve ikinci ikili
    # baglama sorusunu HIC gormezdi (sessizce bos bir olcum).
    tag = os.path.basename(outpath).replace(".json", "")
    workdir = os.path.join(workdir, "gates", tag)
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
            o, e, c = run([binary, "--project", "testproj"] + argv, env, cwd=nocfg)
            res[f"{vname}_project_flag_no_config"] = {
                "stderr": e.decode("utf-8", "replace"), "exit": c}
            # config VAR ama --project YOK -> baglama onayi.
            #
            # stdin'e "n" veriliyor: cevapsiz birakmak sureci timeout'a kadar
            # BLOKLARDI (okuma bir pty'den geliyor) ve olcum yavas + kill'e
            # bagli olurdu. "n" ile prompt METNI yine olculur, ret deterministik
            # olur ve pin YAZILMAZ.
            o, e, c = run([binary] + argv, env, cwd=withcfg, stdin_data=b"n\n")
            res[f"{vname}_config_no_project"] = {
                "stderr": e.decode("utf-8", "replace"), "exit": c}

        # --- `get`: AYNI kapilar, biri TERS yonde -------------------------
        #
        # KAPI 1 TERSINE, ve bu bir istisna degil kumenin TANIMI: get
        # storeProject kullaniyor (proje ADI yeter), exec/apply
        # requireStoreConfig kullaniyor (yerel dosya SART).
        #
        # DEGER STDOUT'A BASILIYOR ve BURAYA KAYDEDILMIYOR — yalnizca UZUNLUGU.
        # (Sahte gate'in dizesi zaten uydurma, ama bir olcum dosyasinin bir
        # "deger" alani tasimasi bu portun kapatmaya calistigi yuzeyin ta
        # kendisi olurdu.) Kapinin gecildigi, cikis 0 + stderr BOS ile
        # adlandiriliyor.
        o, e, c = run([binary, "--project", "testproj", "secrets", "get", "PLAIN_KEY"],
                      env, cwd=nocfg)
        res["get_project_flag_no_config"] = {
            "stderr": e.decode("utf-8", "replace"), "exit": c, "stdout_len": len(o)}

        # KAPI 2, get icin: config VAR, --project YOK -> baglama onayi.
        o, e, c = run([binary, "secrets", "get", "PLAIN_KEY"], env, cwd=withcfg,
                      stdin_data=b"n\n")
        res["get_config_no_project"] = {
            "stderr": e.decode("utf-8", "replace"), "exit": c}

        # KAPI 3: ajan reddi baglama kontrolunden ONCE. WAPPS_AGENT_MODE
        # override'i KALDIRILIYOR ve ajan isareti konuyor; stdin verilmiyor
        # cunku bu yol bir soru SORMAMALI (sorarsa timeout'ta olur ve
        # cagirandaki iddia bunu adlandirir).
        agent_env = {k: v for k, v in env.items() if k != "WAPPS_AGENT_MODE"}
        agent_env["CLAUDECODE"] = "1"
        o, e, c = run([binary, "secrets", "get", "PLAIN_KEY"], agent_env, cwd=withcfg)
        res["get_agent_config_unpinned"] = {
            "stderr": e.decode("utf-8", "replace"), "exit": c}
    finally:
        gate.terminate(); gate.wait()

    with open(outpath, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print(f"wrote {len(res)} gate observations -> {outpath}")


main()
