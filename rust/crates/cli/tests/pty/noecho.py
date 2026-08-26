#!/usr/bin/env python3
"""`secrets set`in YANKISIZ okumasini OLCER.

NEDEN AYRI BIR OLCUM — ve bu bir uslup tercihi degil, olculmus bir bosluk:
ptyrun.py uc slave'in de ECHO bitini spawn'dan ONCE kapatiyor (cikti sadakati
icin) ve stdin master'ini HIC okumuyor. Yani ana differential'da ikilinin kendi
ECHO kapatmasi GORUNMEZ: ECHO'yu hic kapatmayan bir ikili de orada bayt-bayt
esit gorunur. Mutasyonla dogrulandi (M1) — ana differential o mutasyonu
YAKALAMADI, bu dosya onun icin var.

Burada tam tersi kuruluyor: stdin pty'sinde ECHO **ACIK** biraklyor, yani
degeri ekrana dusurmemek TAMAMEN ikilinin sorumlulugu. Olculen iki sey:

  echo_off        — cocuk, degeri okumadan ONCE ECHO'yu kapatti mi
  stdin_echo_hex  — terminal yazilan baytlardan neyi GERI yankiladi (bos olmali)

YARIS YOK: baytlar hemen yazilmiyor. Once prompt bekleniyor, sonra ECHO'nun
kapanmasi POLL ediliyor; ancak ondan sonra (ya da zaman asiminda — mutant bu
kola duser) yaziliyor. Boylece saglam ikili DAIMA temiz, yankilayan ikili
DAIMA kirli olcum verir.

GERCEK SIR YOK: yazilan dize bu dosyada duran uydurma bir test dizesidir.
"""
import json, os, pty, select, socket, subprocess, sys, termios, time

TYPED = b"prompted-test-string\n"
PROMPT_MARK = b"Value for "


def _read_ready(fd, timeout=0.05):
    r, _, _ = select.select([fd], [], [], timeout)
    if not r:
        return b""
    try:
        return os.read(fd, 65536)
    except OSError:
        return b""


def echo_is_on(fd):
    try:
        return bool(termios.tcgetattr(fd)[3] & termios.ECHO)
    except termios.error:
        return False


def measure(binary, port, workdir):
    m_in, s_in = pty.openpty()
    m_out, s_out = pty.openpty()
    m_err, s_err = pty.openpty()

    # stdout/stderr: yalnizca \n -> \r\n donusumu kapali (bayt sadakati).
    # stdin: ECHO'ya DOKUNULMUYOR — acik kalmasi bu olcumun ta kendisi.
    for fd in (s_out, s_err):
        a = termios.tcgetattr(fd)
        a[3] &= ~termios.ECHO
        a[1] &= ~termios.ONLCR
        termios.tcsetattr(fd, termios.TCSANOW, a)
    a = termios.tcgetattr(s_in)
    a[1] &= ~termios.ONLCR
    termios.tcsetattr(s_in, termios.TCSANOW, a)
    assert echo_is_on(s_in), "olcum gecersiz: stdin ECHO zaten kapali"

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.path.join(workdir, "fakehome"),
        "XDG_CONFIG_HOME": os.path.join(workdir, "xdgcfg"),
        "TERM": "dumb",
        "WAPPS_SECRETS_GATE": f"http://127.0.0.1:{port}",
        "WAPPS_SESSION_TOKEN": "fake-token-not-a-secret",
        "WAPPS_NO_UPDATE_CHECK": "1",
        "WAPPS_AGENT_MODE": "0",
    }
    os.makedirs(env["HOME"], exist_ok=True)
    os.makedirs(env["XDG_CONFIG_HOME"], exist_ok=True)

    p = subprocess.Popen(
        [binary, "--project", "testproj", "secrets", "set", "PLAIN_KEY"],
        stdin=s_in, stdout=s_out, stderr=s_err, env=env, cwd=workdir, close_fds=True)

    out, err, echoed = b"", b"", b""

    # 1) prompt bekle
    deadline = time.time() + 10
    while PROMPT_MARK not in err and time.time() < deadline and p.poll() is None:
        err += _read_ready(m_err)
        out += _read_ready(m_out, 0.0)

    # 2) ECHO kapanmasini POLL et (yaris kapatilir)
    echo_off = False
    deadline = time.time() + 2
    while time.time() < deadline and p.poll() is None:
        if not echo_is_on(s_in):
            echo_off = True
            break
        time.sleep(0.01)

    # 3) simdi yaz. Mutant hala ECHO acik oldugu icin geri yankilar.
    if p.poll() is None:
        os.write(m_in, TYPED)

    # 4) bosalt
    deadline = time.time() + 10
    while time.time() < deadline:
        got = False
        for fd, name in ((m_out, "out"), (m_err, "err"), (m_in, "echo")):
            d = _read_ready(fd, 0.02)
            if d:
                got = True
                if name == "out": out += d
                elif name == "err": err += d
                else: echoed += d
        if p.poll() is not None and not got:
            break
    code = p.wait(timeout=10)

    for fd in (s_in, s_out, s_err, m_in, m_out, m_err):
        try: os.close(fd)
        except OSError: pass

    return {"echo_off": echo_off, "stdin_echo_hex": echoed.hex(),
            "stdout_hex": out.hex(), "stderr_hex": err.hex(), "exit": code}


def main():
    binary, outpath, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)
    from cases import GATE_SCRIPT

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
    try:
        res = measure(binary, port, workdir)
    finally:
        gate.terminate(); gate.wait()
    with open(outpath, "w") as f:
        json.dump(res, f, indent=1, sort_keys=True)
    print(f"echo_off={res['echo_off']} echoed={len(res['stdin_echo_hex'])//2}B -> {outpath}")


main()
