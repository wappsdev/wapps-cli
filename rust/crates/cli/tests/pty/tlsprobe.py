#!/usr/bin/env python3
"""Iki ikiliyi AYNI TLS gate'ine karsi kosturur ve reddi/kabulu kaydeder.

Neden pty: `secrets get` insan yolunu ancak stdin TTY iken calistiriyor; boru
ile kosan bir olcum AGENT_MODE_REFUSED'a takilir ve aga HIC cikmaz — yani
sertifika dogrulamasi hic denenmez. Olculdu: boru ile kosuldugunda iki ikili de
zarfi basip cikiyor, TLS yolu olculmemis kaliyor.

UC SENARYO:
  ca_nowhere           CA hicbir yerde         -> ikisinin de REDDETMESI beklenir
  ca_in_ssl_cert_file  CA yalnizca SSL_CERT_FILE'da
  ca_in_ssl_cert_dir   CA yalnizca SSL_CERT_DIR'de
  public_chain         gercek, herkesin guvendigi zincir (AG gerektirir)

`ca_in_ssl_cert_*`, "CA yalnizca sistem deposunda" senaryosunun OLCULEBILIR
yarisidir. Tam hali olculemiyor: kullanicinin guven deposunu degistirmek yasak
ve macOS'ta Go'nun crypto/x509'u SSL_CERT_FILE'i HIC okumuyor (root_unix.go'nun
build etiketi darwin'i disliyor), yani darwin'de bir CA'yi surece-yerel bir
kanalla Go'ya tanitmanin yolu YOK. Linux'ta o kanal ACIK, ve §9.5'in anlattigi
CI runner Linux'tur. Bu dosya bu yuzden platforma gore FARKLI bekliyor ve
beklentiyi kaydediyor — tahmin etmiyor, kosuldugu platformda olcuyor.

public_chain AG'a cikiyor, bu yuzden VARSAYILAN OLARAK KOSMUYOR: sessizce
atlanan bir vaka olmasin diye sonucu daima raporlaniyor ("skipped" olarak).
WAPPS_TLS_PUBLIC_CHAIN=1 ile acilir."""
import json, os, shutil, socket, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from mintca import mint

# Gercek bir servis DEGIL: IANA'nin dokumantasyon alan adi. Yalnizca "herkesin
# guvendigi bir zincir" uretmek icin; hicbir sir buraya gitmiyor (istek 405 ile
# doner, onemli olan EL SIKISMANIN gecmesi).
PUBLIC_CHAIN_HOST = "https://example.com"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_up(port):
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), 0.05).close()
            return True
        except OSError:
            time.sleep(0.02)
    return False


def main():
    go_bin, rs_bin, workdir, outpath = sys.argv[1:5]
    certs = mint(os.path.join(workdir, "tlscerts"))
    port = free_port()
    here = os.path.dirname(os.path.abspath(__file__))
    gate = subprocess.Popen(
        [sys.executable, os.path.join(here, "tlsgate.py"), str(port), certs["crt"], certs["key"]],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not wait_up(port):
        gate.terminate()
        raise SystemExit("tls fake gate did not come up")

    local = "https://127.0.0.1:%d" % port
    scenarios = [
        ("ca_nowhere", {"WAPPS_SECRETS_GATE": local}),
        ("ca_in_ssl_cert_file", {"WAPPS_SECRETS_GATE": local, "SSL_CERT_FILE": certs["ca"]}),
        ("ca_in_ssl_cert_dir", {"WAPPS_SECRETS_GATE": local, "SSL_CERT_DIR": certs["cadir"]}),
    ]
    if os.environ.get("WAPPS_TLS_PUBLIC_CHAIN") == "1":
        scenarios.append(("public_chain", {"WAPPS_SECRETS_GATE": PUBLIC_CHAIN_HOST}))

    results = {"_meta": {"platform": sys.platform,
                         "public_chain_ran": os.environ.get("WAPPS_TLS_PUBLIC_CHAIN") == "1"}}
    try:
        for name, extra in scenarios:
            for side, binary in (("go", go_bin), ("rs", rs_bin)):
                cfg = os.path.join(workdir, "cfg-%s-%s" % (name, side))
                home = os.path.join(workdir, "home-%s-%s" % (name, side))
                shutil.rmtree(cfg, ignore_errors=True)
                os.makedirs(cfg, exist_ok=True)
                os.makedirs(home, exist_ok=True)
                env = {"PATH": "/usr/bin:/bin", "HOME": home, "XDG_CONFIG_HOME": cfg,
                       "TERM": "dumb", "WAPPS_NO_UPDATE_CHECK": "1",
                       # Sahte oturum jetonu: gercek DEGIL, yalnizca
                       # SESSION_EXPIRED yolunu atlatmak icin.
                       "WAPPS_SESSION_TOKEN": "fake-token-not-a-secret",
                       # TTY'de onurlandirilir: insan yolu = ag yolu.
                       "WAPPS_AGENT_MODE": "0"}
                env.update(extra)
                out, err, code = run(
                    [binary, "--project", "testproj", "secrets", "get", "PLAIN_KEY"],
                    env, timeout=60)
                results.setdefault(name, {})[side] = {
                    "stdout": out.decode("utf-8", "replace"),
                    "stderr": err.decode("utf-8", "replace"),
                    "exit": code,
                }
    finally:
        gate.terminate()
        gate.wait()

    with open(outpath, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    print("wrote %d tls scenarios -> %s" % (len(results) - 1, outpath))


main()
