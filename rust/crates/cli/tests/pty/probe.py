#!/usr/bin/env python3
"""Bir ikiliyi tum vakalarda pty altinda kosturur ve sonucu JSON dokerler."""
import json, os, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import CASES, GATE_SCRIPT, FIXTURE_FILES

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def main():
    binary = sys.argv[1]
    outpath = sys.argv[2]
    workdir = sys.argv[3]
    port = free_port()
    here = os.path.dirname(os.path.abspath(__file__))
    gate = subprocess.Popen([sys.executable, os.path.join(here, "fakegate.py"),
                             str(port), json.dumps(GATE_SCRIPT)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # gate ayaga kalkana kadar bekle (kosula bagli bekleme, sabit uyku degil)
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), 0.05).close(); break
        except OSError: time.sleep(0.02)
    else:
        raise SystemExit("fake gate did not come up")

    cfg = os.path.join(workdir, "xdgcfg")
    os.makedirs(cfg, exist_ok=True)

    # Fikstur dosyalari (set --from-file icin). workdir IKI ikili icin de AYNI,
    # yani hata mesajlarina giren mutlak yollar da ayni — aksi halde yol farki
    # sahte bir ayrisma uretirdi.
    fixdir = os.path.join(workdir, "fixtures")
    os.makedirs(fixdir, exist_ok=True)
    for rel, content in FIXTURE_FILES.items():
        with open(os.path.join(fixdir, rel), "w") as f:
            f.write(content)

    results = {}
    try:
        for case in CASES:
            name, argv, extra = case[0], case[1], case[2]
            seed = case[3] if len(case) > 3 else None
            stdin_data = case[4] if len(case) > 4 else None
            # {FIX} -> fikstur dizini (mutlak). Iki ikili de ayni dizeyi gorur.
            argv = [a.replace("{FIX}", fixdir) for a in argv]
            env = {
                "PATH": "/usr/bin:/bin",
                "HOME": os.path.join(workdir, "fakehome"),
                "XDG_CONFIG_HOME": cfg,
                "TERM": "dumb",
                "WAPPS_SECRETS_GATE": f"http://127.0.0.1:{port}",
                # Sahte oturum jetonu: gercek DEGIL, sadece SESSION_EXPIRED
                # yolunu atlatmak icin.
                "WAPPS_SESSION_TOKEN": "fake-token-not-a-secret",
                "WAPPS_NO_UPDATE_CHECK": "1",
            }
            env.update(extra)
            env = {k: v for k, v in env.items() if v != ""}
            os.makedirs(env["HOME"], exist_ok=True)
            # her vaka temiz bir epoch-pin ile kossun; tohum verilmisse
            # dosya IKI ikili icin de AYNI baytlarla kuruluyor
            import shutil; shutil.rmtree(os.path.join(cfg, "wapps"), ignore_errors=True)
            pinpath = os.path.join(cfg, "wapps", "epochs.json")
            if seed is not None:
                os.makedirs(os.path.dirname(pinpath), exist_ok=True)
                with open(pinpath, "w") as f: f.write(seed)
            # cwd ACIKCA workdir: miras alinan bir cwd'de bir .wapps.yaml
            # bulunsaydi config-gerektiren dallar sessizce baska bir yola
            # saparsa ve olcum kosuma gore degisirdi. workdir'de .wapps.yaml
            # YOK, yani "config yok" dali DETERMINISTIK olarak olculuyor.
            out, err, code = run([binary] + argv, env, cwd=workdir,
                                 stdin_data=stdin_data)
            # Pin dosyasinin SON hali de sozlesmenin parcasi: reddedilen bir
            # okumanin pin'i geri sarmadigi ancak boyle gorunur.
            pin = open(pinpath, "rb").read().hex() if os.path.exists(pinpath) else None
            results[name] = {"stdout_hex": out.hex(), "stderr_hex": err.hex(),
                             "exit": code, "pinfile_hex": pin}
    finally:
        gate.terminate(); gate.wait()
    with open(outpath, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    print(f"wrote {len(results)} cases -> {outpath}")

main()
