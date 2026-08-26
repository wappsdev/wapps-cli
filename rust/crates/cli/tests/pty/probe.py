#!/usr/bin/env python3
"""Bir ikiliyi tum vakalarda pty altinda kosturur ve sonucu JSON dokerler."""
import json, os, socket, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import CASES, GATE_SCRIPT

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
    results = {}
    try:
        for name, argv, extra in CASES:
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
            # her vaka temiz bir epoch-pin ile kossun
            for f in ("wapps",):
                import shutil; shutil.rmtree(os.path.join(cfg, f), ignore_errors=True)
            out, err, code = run([binary] + argv, env)
            results[name] = {"stdout_hex": out.hex(), "stderr_hex": err.hex(), "exit": code}
    finally:
        gate.terminate(); gate.wait()
    with open(outpath, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    print(f"wrote {len(results)} cases -> {outpath}")

main()
