#!/usr/bin/env python3
"""Every fake gate comes up while reverse DNS hangs.

On the hosted macOS runner (CI run 37292847891) `http.server.HTTPServer` took
about 35 s to listen: its `server_bind` resolves the bound address back to a
name (`socket.getfqdn("127.0.0.1")`), between bind(2) and listen(2), and the
runner's resolver answers that only after its timeouts. Meanwhile connects to
the bound, not yet listening port timed out and the probe gave up. A dev Mac
answers the lookup at once, so this script makes it hang on purpose: a
`sitecustomize` on the gates' PYTHONPATH turns both reverse lookups into a
60-second sleep. Each gate must still come up within gateproc's wait.

Exit 0 when every gate came up; otherwise gateproc's SystemExit names the gate
and why."""
import json, os, shutil, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
import gateproc
from cases import GATE_SCRIPT
from mintca import mint

HANG = """import socket, time
def _hang(*a, **k):
    time.sleep(60)
    raise OSError("reverse lookup hung (gateup.py)")
socket.getfqdn = _hang
socket.gethostbyaddr = _hang
"""


def main():
    work = tempfile.mkdtemp(prefix="wapps-gateup-")
    try:
        site = os.path.join(work, "site")
        os.makedirs(site)
        with open(os.path.join(site, "sitecustomize.py"), "w") as f:
            f.write(HANG)
        os.environ["PYTHONPATH"] = site
        certs = mint(os.path.join(work, "certs"))
        for script, args in (("fakegate.py", [json.dumps(GATE_SCRIPT)]),
                             ("tlsgate.py", [certs["crt"], certs["key"]])):
            gate, port = gateproc.start(os.path.join(here, script), args, label=script)
            gate.terminate()
            gate.wait()
            print(f"{script} came up on 127.0.0.1:{port}")
    finally:
        shutil.rmtree(work, ignore_errors=True)


main()
