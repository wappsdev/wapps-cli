#!/usr/bin/env python3
"""Kosum aninda bir CA + sunucu sertifikasi uretir.

Neden `openssl` CLI: bu agacin python harness'i STDLIB disina cikmiyordu ve
sertifika uretimi stdlib'de YOK. `cryptography` paketi bu makinede var ama her
CI'da yok; `openssl` hem macOS'ta (LibreSSL) hem Linux'ta (OpenSSL) her zaman
var. Ikisinde de calisan bayrak kumesi kullaniliyor.

Uretilen her sey GECICI: dosyalar cagiranin verdigi dizine yaziliyor, o dizin
test bitince siliniyor. Agaca hicbir sertifika/anahtar yazilmiyor ve hicbir
gercek alan adi kullanilmiyor — SAN yalnizca localhost ve 127.0.0.1."""
import os, shutil, subprocess, sys

# CA'nin adi kazara guvenilmesini zorlastirmak icin acikca uyarici.
CA_CN = "wapps-tls-lane-throwaway-ca-DO-NOT-TRUST"

LEAF_EXT = """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
"""


def openssl_bin():
    return shutil.which("openssl") or "/usr/bin/openssl"


def run(args):
    p = subprocess.run(args, capture_output=True)
    if p.returncode != 0:
        raise SystemExit(
            "openssl failed (%d): %s\n%s"
            % (p.returncode, " ".join(args), p.stderr.decode("utf-8", "replace"))
        )


def mint(outdir):
    """outdir icine ca.crt/ca.key/leaf.crt/leaf.key yazar, yollari doner."""
    os.makedirs(outdir, exist_ok=True)
    o = openssl_bin()
    j = lambda n: os.path.join(outdir, n)
    run([o, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", j("ca.key"), "-out", j("ca.crt"), "-days", "1",
         "-subj", "/CN=" + CA_CN,
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-addext", "subjectKeyIdentifier=hash"])
    run([o, "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", j("leaf.key"), "-out", j("leaf.csr"), "-subj", "/CN=localhost"])
    with open(j("leaf.ext"), "w") as f:
        f.write(LEAF_EXT)
    run([o, "x509", "-req", "-in", j("leaf.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
         "-CAcreateserial", "-out", j("leaf.crt"), "-days", "1", "-sha256",
         "-extfile", j("leaf.ext")])
    # SSL_CERT_DIR kanali OpenSSL'in c_rehash duzenini istiyor: <hash>.0.
    subdir = j("cadir")
    os.makedirs(subdir, exist_ok=True)
    h = subprocess.run([o, "x509", "-hash", "-noout", "-in", j("ca.crt")],
                       capture_output=True).stdout.decode().strip()
    shutil.copyfile(j("ca.crt"), os.path.join(subdir, (h or "ca") + ".0"))
    return {"ca": j("ca.crt"), "cadir": subdir, "crt": j("leaf.crt"), "key": j("leaf.key")}


if __name__ == "__main__":
    import json
    print(json.dumps(mint(sys.argv[1])))
