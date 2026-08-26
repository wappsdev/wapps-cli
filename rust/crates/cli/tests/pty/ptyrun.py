#!/usr/bin/env python3
"""Bir komutu pty ALTINDA kosturur ve stdout/stderr'i AYRI yakalar.

Neden UC ayri pty: agentmode.IsAgent() stdin'in TTY olusuna bakiyor ve non-TTY
stdin'i DAIMA ajan sayiyor; boru ile kosmak insan yolunu hic calistirmaz. stdout
ve stderr ayri pty'lere baglanir, cunku tek pty'de ikisi karisir ve bayt-bayt
ayristirilamaz.

macOS YARISI — bu dosyanin en onemli ayrintisi: bir pty'nin SON slave fd'si
kapandiginda, master tarafinda HENUZ OKUNMAMIS veri ATILIR. Ebeveyn slave'leri
spawn'dan hemen sonra kapatirsa, hizli cikan bir cocugun ciktisi sessizce
kaybolabiliyor. Olculdu: `cargo test` altinda bir vaka bos stderr ile geldi,
ayni vaka tek basina 5 kez kosunca hic kirilmadi. Bu yuzden ebeveyn slave'leri
surec BITENE ve masterlar BOSALTILANA kadar acik tutuyor. Sessizce yanlis
"esit"/"farkli" ureten bir differential, hic differential olmamasindan kotudur.

STDIN YAZIMI (`stdin_data`) — `secrets set` icin SART: Go tarafi degeri
`term.ReadPassword` ile YANKISIZ okuyor, yani okuyucunun bir TTY olmasi
gerekiyor. Boru ile beslenen bir olcum non-TTY dalina duser (uyari satiri +
farkli okuma yolu) ve asil no-echo dalini HIC calistirmaz. Baytlar master
tarafina yaziliyor; slave'de ECHO kapali oldugu icin geri yankilanmiyorlar ve
cikti sayilmiyorlar.
"""
import os, pty, select, subprocess, sys, json, termios

def _drain(fds, buf, timeout):
    """Hazir olan her fd'yi okur; veri geldiyse True doner."""
    got = False
    r, _, _ = select.select(fds, [], [], timeout)
    for fd in r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        if data:
            buf[fd] += data
            got = True
    return got

def run(argv, env, cwd=None, timeout=30, stdin_data=None):
    m_in, s_in = pty.openpty()
    m_out, s_out = pty.openpty()
    m_err, s_err = pty.openpty()
    for fd in (s_in, s_out, s_err):
        a = termios.tcgetattr(fd)
        a[3] &= ~termios.ECHO      # yankı kapali: pty'nin geri yankisi cikti sayilmasin
        a[1] &= ~termios.ONLCR     # \n -> \r\n donusumu kapali (bayt sadakati)
        termios.tcsetattr(fd, termios.TCSANOW, a)

    p = subprocess.Popen(argv, stdin=s_in, stdout=s_out, stderr=s_err,
                         env=env, cwd=cwd, close_fds=True)

    # stdin baytlari master'a YAZILIYOR (slave'e degil): cocuk okuyana kadar
    # pty tamponunda bekler, yani spawn ile okuma arasindaki yaris onemsiz.
    if stdin_data:
        os.write(m_in, stdin_data)

    buf = {m_out: b"", m_err: b""}
    fds = [m_out, m_err]
    waited = 0.0
    while True:
        _drain(fds, buf, 0.05)
        if p.poll() is not None:
            # Surec bitti: kalanı bosalt. Ust uste bos okuma gorene kadar surer,
            # cunku cikis anindaki son yazim henuz master'a gecmemis olabilir.
            idle = 0
            while idle < 3:
                idle = 0 if _drain(fds, buf, 0.02) else idle + 1
            break
        waited += 0.05
        if waited > timeout:
            p.kill(); break
    code = p.wait(timeout=timeout)

    # Slave'ler ANCAK simdi kapaniyor (yukaridaki macOS yarisi).
    for fd in (s_in, s_out, s_err, m_in, m_out, m_err):
        try: os.close(fd)
        except OSError: pass
    return buf[m_out], buf[m_err], code

if __name__ == "__main__":
    spec = json.load(sys.stdin)
    sd = spec.get("stdin_hex")
    out, err, code = run(spec["argv"], dict(spec.get("env") or {}), spec.get("cwd"),
                         stdin_data=bytes.fromhex(sd) if sd else None)
    json.dump({"stdout_hex": out.hex(), "stderr_hex": err.hex(), "exit": code}, sys.stdout)
