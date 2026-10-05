#!/usr/bin/env python3
"""Runs a binary under a pty over every case and dumps the results as JSON."""
import calendar, datetime, hashlib, json, os, re, shutil, sys, time
from zoneinfo import ZoneInfo
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ptyrun import run
from cases import CASES, GATE_SCRIPT, FIXTURE_FILES
from workdir import demand_usable
import gateproc

def bindpath_for(cfg):
    return os.path.join(cfg, "wapps", "repo-pins.json")

# --- the update check's cache file (`<cache dir>/wapps/version-check.json`) ---
#
# Its `checked_at` is the binary's own clock, so two runs never write the same
# bytes. It is replaced by `{CHECKED_AT}` ONLY after it proved to be what Go
# writes: Go's RFC3339Nano shape (no trailing fraction zeros, `Z` for a zero
# offset), an instant inside the run's own window, and the offset Go's Local
# has at that instant for the case's TZ. A timestamp that fails any of these
# stays raw, so the two runs differ and the case reads DIFFERENT.
_TS = re.compile(r"\{TS:(-?\+?\d+)(?::([+-]\d\d:\d\d))?\}")
_CHECKED_AT = re.compile(rb'^\{"checked_at":"([^"]*)",')
_GO_TIME = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(\.\d{0,8}[1-9])?"
                      r"(Z|[+-]\d\d:\d\d)$")


def _zone(tz):
    """Go's Local for a TZ value (None: unset), as a ZoneInfo; None is UTC.
    Only the values the corpus uses: unset, a zone name, `UTC`."""
    if tz is None:
        with open("/etc/localtime", "rb") as f:
            return ZoneInfo.from_file(f)
    tz = tz[1:] if tz.startswith(":") else tz
    return None if tz in ("", "UTC") else ZoneInfo(tz)


def _offset(tz, t):
    z = _zone(tz)
    return 0 if z is None else int(datetime.datetime.fromtimestamp(t, z).utcoffset().total_seconds())


def _ts(content, now):
    """`{TS:<delta>}` -> now+delta as RFC 3339 in UTC; `{TS:<delta>:+03:00}`
    the same instant at that offset. For seeding fresh/stale caches."""
    def one(m):
        t = now + int(m.group(1))
        z = m.group(2)
        off = 0 if not z else (1 if z[0] == "+" else -1) * (int(z[1:3]) * 3600 + int(z[4:6]) * 60)
        wall = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t + off))
        return wall + (z or "Z")
    return _TS.sub(one, content)


def _norm_checked_at(body, tz, t0, t1):
    m = _CHECKED_AT.match(body)
    if not m:
        return body
    g = _GO_TIME.match(m.group(1).decode("ascii", "replace"))
    if not g:
        return body
    y, mo, d, hh, mm, ss = map(int, g.groups()[:6])
    z = g.group(8)
    off = 0 if z == "Z" else (1 if z[0] == "+" else -1) * (int(z[1:3]) * 3600 + int(z[4:6]) * 60)
    inst = calendar.timegm((y, mo, d, hh, mm, ss)) - off + float("0" + (g.group(7) or ""))
    if not (t0 - 1 <= inst <= t1 + 1) or _offset(tz, inst) != off:
        return body
    return body.replace(m.group(1), b"{CHECKED_AT}", 1)

def main():
    binary = sys.argv[1]
    outpath = sys.argv[2]
    workdir = sys.argv[3]
    # ILK IS: calisma dizini KANONIK olmali ve hicbir deponun ICINDE olmamali.
    # Ikisinin de belirtisi ayni: tohumlanan repo pini tutmaz, baglama kapisi
    # onay istemine girer, stdin'siz bir pty EOF vermez ve vaka 30 sn sonra
    # SIGKILL yer — yani olcum bir DAVRANIS degil bir ZAMAN ASIMI olur. Bu
    # SESSIZ arizaydi; artik 97 ile GURULTULU (bkz. workdir.py).
    demand_usable(workdir)
    here = os.path.dirname(os.path.abspath(__file__))
    gate, port = gateproc.start(os.path.join(here, "fakegate.py"),
                                [json.dumps(GATE_SCRIPT)])

    cfg = os.path.join(workdir, "xdgcfg")
    os.makedirs(cfg, exist_ok=True)

    # Fikstur dosyalari (set --from-file icin). workdir IKI ikili icin de AYNI,
    # yani hata mesajlarina giren mutlak yollar da ayni — aksi halde yol farki
    # sahte bir ayrisma uretirdi.
    fixdir = os.path.join(workdir, "fixtures")
    os.makedirs(fixdir, exist_ok=True)
    for rel, content in FIXTURE_FILES.items():
        fp = os.path.join(fixdir, rel)
        with open(fp, "w") as f:
            f.write(content)
        # `#!` ile BASLAYAN bir fikstur bir PROGRAMDIR ve calistirilabilir
        # yazilir. Bunun tek musterisi var ve gercek: `wapps tofu` argv[0]'i
        # "tofu" olarak SABITLIYOR, yani /bin/sh cagirarak olculemez. PATH'e
        # konabilen bir `tofu` shim'i olmadan verb'un VAR OLMA SEBEBI —
        # degerleri VERBATIM enjekte etmesi, TF_VAR_ eklememesi — hic
        # olculemezdi; v0.23.0'da tam olarak orada bir hata yasandi.
        if content.startswith("#!"):
            os.chmod(fp, 0o755)

    results = {}
    try:
        for case in CASES:
            name, argv, extra = case[0], case[1], case[2]
            seed = case[3] if len(case) > 3 else None
            stdin_data = case[4] if len(case) > 4 else None
            # 6. eleman: bu vaka icin bir `.wapps.yaml` (ve istege bagli
            # onceden yazilmis hedef dosyalari). Verilirse vaka KENDI dizininde
            # kosar; verilmezse workdir'de (orada .wapps.yaml YOK, yani
            # "config yok" dali DETERMINISTIK olculur).
            #
            # `{"yaml": None}` OZEL: vaka kendi dizininde kosar ama oraya
            # `.wapps.yaml` YAZILMAZ. `secrets init` icin sart — init'in
            # kendisi o dosyayi URETIYOR, ve workdir'de kosarsa oraya yazip
            # "config yok" dalini olcen BUTUN diger vakalari bozardi.
            cfgseed = case[5] if len(case) > 5 else None
            # 7. eleman: ONCEDEN VAR OLAN bir depo->proje pini.
            #
            # NEDEN GEREKLI: `bindPrompt`in UYUSMAZLIK dali (config PINLI
            # OLANDAN BASKA bir proje isimliyor) bu tohum olmadan HICBIR fiil
            # icin gezilemiyordu. Korpustaki her pin KOSUM SIRASINDA doguyor
            # (insan "y" diyor), yani her zaman EŞLESEN bir pin; uyusmazlik ve
            # "zaten pinli, SORMADAN gec" dallarinin ikisi de olculmemisti.
            #
            # NEDEN YAPILABILIR: parmak izi sha256(config KOKUNUN mutlak yolu)
            # ve o yol probe.py'nin ELINDE (casedir'i o kuruyor). Dosya bicimi
            # Go'nun MarshalIndent'i; python json.dumps(indent=2) ile BAYT
            # ESITLIGI olculdu (Go ikilisinin urettigi dosyayla karsilastirildi).
            # Yol iki ikili icin de AYNI workdir'den turedigi icin tohum da ayni.
            bindseed = case[6] if len(case) > 6 else None
            # 8th element: PRE-EXISTING session files `wapps login` would have
            # written, {file name: content}, seeded under
            # XDG_CONFIG_HOME/wapps/session (dir 0700, file 0600 — the modes
            # the binaries write). `{GATEFILE}` in a name is the live fake
            # gate's session key (127.0.0.1_<port>): the port differs per
            # binary, so the name is built here and normalized back below.
            sessseed = case[7] if len(case) > 7 else None
            # {FIX} -> fikstur dizini (mutlak). Iki ikili de ayni dizeyi gorur.
            # {GATE} -> the fake gate's root, in argv too: `secrets sync
            # --target=coolify` reads its Coolify URL from `--coolify-url` only
            # (never COOLIFY_URL). The port differs per binary, so no branch that
            # PRINTS the URL may be measured this way (HTTP errors print only
            # the path).
            argv = [a.replace("{FIX}", fixdir).replace("{GATE}", f"http://127.0.0.1:{port}")
                    for a in argv]
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
                # BURADA BIR ZAMANLAR `GIT_CEILING_DIRECTORIES` VARDI ve
                # YETMIYORDU: git tavani OZ ATA olarak arar, yani tavan ile
                # dizinin KENDISI ayni oldugunda (vaka workdir'de kosuyorsa —
                # korpusun cogunlugu oyle) hicbir sey yapmaz. Kimligin depoya
                # kacmasi artik TEK ve TEKBICIMLI bir hukumle kapali: calisma
                # dizini hicbir deponun icinde olmaz (workdir.py).
            }
            env.update(extra)
            # {GATE} -> sahte gate'in koku. argv'deki {FIX} ile AYNI mekanizma,
            # ama ENV degerleri icin ve bir sebebi var: `doctor` COOLIFY_URL'e
            # GERCEK bir HTTP istegi atiyor. Yerine konmazsa iki ikili de
            # canli internete (coolify.meapps.dev) cikardi — olcum aga bagli
            # olurdu ve bu harness'in "gercek bir gate'e HIC baglanma" kurali
            # kirilirdi. Sahte gate'e cevrilince prob DETERMINISTIK olarak
            # "reachable" doner (bilinmeyen rota 404, ve doctor 5xx ALTINI
            # canli sayiyor).
            #
            # Port her ikili icin AYRI (probe.py her kosumda free_port aliyor),
            # o yuzden PORTU CIKTIYA BASAN bir dal buradan gecmemeli — o
            # dallar (oturum yok/dolmus) WAPPS_SECRETS_GATE'i SABIT bir dizeye
            # cevirerek olculuyor.
            # {FIX} env tarafinda da cozuluyor (argv'de zaten cozuluyordu):
            # `PATH` degerine fikstur dizinini koyabilmek icin.
            env = {k: v.replace("{GATE}", f"http://127.0.0.1:{port}")
                        .replace("{FIX}", fixdir)
                   for k, v in env.items()}
            env = {k: v for k, v in env.items() if v != ""}
            # `{NOW+N}` -> unix seconds N from now, in env values AND session
            # seeds. The TTL lines `wapps login --check` prints are whole
            # seconds of (expiry - now), so the case starts right after a
            # second boundary: the binary then has ~0.95 s to read the clock
            # inside the SAME second, and the printed TTL is exactly N.
            if any("{NOW+" in v for v in env.values()) or \
               any("{NOW+" in c for c in (sessseed or {}).values()):
                while time.time() % 1 >= 0.05:
                    time.sleep(0.005)
                now = int(time.time())
                def _now(v):
                    while "{NOW+" in v:
                        i = v.index("{NOW+"); j = v.index("}", i)
                        v = v[:i] + str(now + int(v[i + 5:j])) + v[j + 1:]
                    return v
                env = {k: _now(v) for k, v in env.items()}
                sessseed = {k: _now(v) for k, v in (sessseed or {}).items()}
            # her vaka temiz bir epoch-pin ile kossun; tohum verilmisse
            # dosya IKI ikili icin de AYNI baytlarla kuruluyor
            shutil.rmtree(os.path.join(cfg, "wapps"), ignore_errors=True)
            pinpath = os.path.join(cfg, "wapps", "epochs.json")
            if seed is not None:
                os.makedirs(os.path.dirname(pinpath), exist_ok=True)
                with open(pinpath, "w") as f: f.write(seed)
            # cwd ACIKCA workdir: miras alinan bir cwd'de bir .wapps.yaml
            # bulunsaydi config-gerektiren dallar sessizce baska bir yola
            # saparsa ve olcum kosuma gore degisirdi. workdir'de .wapps.yaml
            # YOK, yani "config yok" dali DETERMINISTIK olarak olculuyor.
            casedir = workdir
            ts_seeded = {}
            if cfgseed is not None:
                # Vaka dizini HER kosumda sifirdan kuruluyor ki iki ikili AYNI
                # baslangic durumunu gorsun (apply idempotens vakalari icin sart).
                casedir = os.path.join(workdir, "cases", name)
                shutil.rmtree(casedir, ignore_errors=True)
                os.makedirs(casedir, exist_ok=True)
                seed_yaml = cfgseed.get("yaml")
                if seed_yaml is not None:
                    with open(os.path.join(casedir, ".wapps.yaml"), "w") as f:
                        f.write(seed_yaml)
                for rel, content in (cfgseed.get("files") or {}).items():
                    # `{TS:...}`: a time relative to now (a cache's
                    # `checked_at`). Such a seed is not the same bytes in the
                    # two runs, so it is recorded below as `seed-unchanged`
                    # when the binary left it alone.
                    if isinstance(content, str) and "{TS:" in content:
                        content = _ts(content, int(time.time()))
                        ts_seeded[rel] = content.encode()
                    fp = os.path.join(casedir, rel)
                    os.makedirs(os.path.dirname(fp), exist_ok=True)
                    # BAYT icerik BINARY yazilir. `dr restore` fikstuleri
                    # gercek WSB1 blob'lari tasiyor (sifreli, rastgele bayt) ve
                    # metin modunda yazmak onlari SESSIZCE bozardi: str
                    # icerikler UTF-8'e kodlanir, yani 0x80-0xFF araligindaki
                    # her bayt IKI bayta cikar ve blob'un icerik adresi tutmaz.
                    # O bozulma "iki ikili de ayni hatayi verdi" diye EQUAL
                    # gorunurdu — yani vakalar gecerdi ve HICBIR SEY olcmezdi.
                    mode = "wb" if isinstance(content, (bytes, bytearray)) else "w"
                    with open(fp, mode) as f:
                        f.write(content)
            # `{CASE}` -> the case's own directory, in env values and in
            # seeded symlink targets. Its one customer is `wapps skill`, which
            # writes under $HOME: `HOME={CASE}/home` gives every case a fresh
            # home that both binaries start from, and puts what the skill
            # wrote there inside the `written` snapshot below. Without it the
            # shared fakehome would carry one binary's install into the other
            # binary's run (and into the real ~/.claude if HOME leaked).
            env = {k: v.replace("{CASE}", casedir) for k, v in env.items()}
            argv = [a.replace("{CASE}", casedir) for a in argv]
            # HOME may be absent on purpose (`"HOME": ""` unsets it).
            if "HOME" in env:
                os.makedirs(env["HOME"], exist_ok=True)
            for rel in (cfgseed or {}).get("dirs") or []:
                os.makedirs(os.path.join(casedir, rel), exist_ok=True)
            for rel, target in ((cfgseed or {}).get("links") or {}).items():
                lp = os.path.join(casedir, rel)
                os.makedirs(os.path.dirname(lp), exist_ok=True)
                os.symlink(target.replace("{CASE}", casedir), lp)
            if bindseed is not None:
                # Pin, CONFIG KOKUNE gore anahtarlanir; `sub` verilirse
                # `--config sub/.wapps.yaml` kolunun kimligi olculur.
                broot = casedir
                if bindseed.get("sub"):
                    broot = os.path.join(casedir, bindseed["sub"])
                fp = hashlib.sha256(broot.encode()).hexdigest()
                doc = {"schema": "wapps-repo-pins/v1",
                       "pins": {fp: {"repo": broot,
                                     "project": bindseed["project"],
                                     "backend": bindseed.get("backend", "store")}}}
                os.makedirs(os.path.dirname(bindpath_for(cfg)), exist_ok=True)
                with open(bindpath_for(cfg), "w") as f:
                    f.write(json.dumps(doc, indent=2))

            gatefile = f"127.0.0.1_{port}"
            sessdir = os.path.join(cfg, "wapps", "session")
            if sessseed:
                # Both levels 0700, like Go's MkdirAll(dir, 0o700); python's
                # makedirs would give the INTERMEDIATE dir the default mode.
                for d in (os.path.dirname(sessdir), sessdir):
                    os.makedirs(d, exist_ok=True)
                    os.chmod(d, 0o700)
                for fn, content in sessseed.items():
                    fp = os.path.join(sessdir, fn.replace("{GATEFILE}", gatefile))
                    fd = os.open(fp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(content)

            t0 = time.time()
            out, err, code = run([binary] + argv, env, cwd=casedir,
                                 stdin_data=stdin_data)
            t1 = time.time()
            # The fake gate's root printed in full is normalized back to
            # `{GATE}`: its port differs per binary. `wapps deploy` prints the
            # endpoint it resolved ("Deploying ... via <ep>"), and the PATH
            # after the root is what tells the sources apart (--ep, env,
            # store). Only this exact string is rewritten; before this no case
            # could print it and stay EQUAL, so no existing comparison loosens.
            gate_root = f"http://127.0.0.1:{port}".encode()
            out = out.replace(gate_root, b"{GATE}")
            err = err.replace(gate_root, b"{GATE}")
            # Pin dosyasinin SON hali de sozlesmenin parcasi: reddedilen bir
            # okumanin pin'i geri sarmadigi ancak boyle gorunur.
            pin = open(pinpath, "rb").read().hex() if os.path.exists(pinpath) else None
            # BAGLAMA defteri de sozlesmenin parcasi: bir ikili reddedip yine de
            # pinleseydi (ya da tersi) cikti esit gorunurdu.
            bindpath = bindpath_for(cfg)
            bind = open(bindpath, "rb").read().hex() if os.path.exists(bindpath) else None
            # apply'in YAZDIGI hedef dosyalar: cikti satirlari ("wrote x")
            # esit olup dosya ICERIGI ayrisabilirdi. Mod da tasiniyor cunku
            # bu dosyalar duz metin sir tasiyor ve 0600 olmalari sozlesme.
            written = None
            if cfgseed is not None:
                written = {}
                for root_, ds, fs in os.walk(casedir):
                    # An EMPTY directory is an observable leftover too (an
                    # install that failed after creating its destination, the
                    # `.claude/skills` an uninstall leaves behind).
                    if root_ != casedir and not ds and not fs:
                        written[os.path.relpath(root_, casedir) + "/"] = [
                            "emptydir", oct(os.stat(root_).st_mode & 0o777)]
                    # A symlink to a directory is listed among the dirs and
                    # not descended; it is still an entry the binary made.
                    for fn in sorted(fs + [d for d in ds
                                           if os.path.islink(os.path.join(root_, d))]):
                        # `.tmp` sonekliler atomik yazicinin gecici
                        # dosyalaridir (normalde rename sonrasi kalmazlar;
                        # kalmislarsa da isim rastgele, yani karsilastirilamaz).
                        #
                        # `.wapps.yaml` ARTIK ATLANMIYOR. Eskiden atlaniyordu
                        # ("girdinin kendisi") ama `secrets init` icin o dosya
                        # CIKTININ ta kendisi — atlanirsa init'in urettigi
                        # sablon HIC karsilastirilmaz ve vakalar bos gezerdi.
                        # Seed'li vakalarda da atlamamak zararsiz ve daha
                        # gucludur: iki ikili AYNI baytlari aliyor, yani bir
                        # fark ancak biri config'i DEGISTIRDIYSE cikar — ki bu
                        # da bilinmesi gereken bir sey.
                        #
                        # DIKKAT: burada "nokta ile baslayanlari atla" YAZMAK
                        # olcumu SESSIZCE BOSALTIR — asil hedefin adi
                        # `.env.local`. Bu bir kez yazildi ve iki apply vakasi
                        # hicbir sey karsilastirmadan "esit" gorundu.
                        if fn.endswith(".tmp"):
                            continue
                        fp = os.path.join(root_, fn)
                        rel = os.path.relpath(fp, casedir)
                        # A symlink is recorded as WHERE it points, not as the
                        # bytes behind it: a link and a copy with the same
                        # content are different installs, and a dangling link
                        # has no content at all.
                        if os.path.islink(fp):
                            written[rel] = ["symlink", os.readlink(fp)]
                            continue
                        body = open(fp, "rb").read()
                        mode = oct(os.stat(fp).st_mode & 0o777)
                        if ts_seeded.get(rel) == body:
                            written[rel] = ["seed-unchanged", mode]
                            continue
                        if rel.endswith("wapps/version-check.json"):
                            body = _norm_checked_at(body, env.get("TZ"), t0, t1)
                        written[rel] = [body.hex(), mode]
            # The SESSION CACHE is part of the contract too: what `wapps
            # login` wrote (bytes AND modes — the file carries a bearer token
            # and must be 0600 under 0700 dirs), and that a read-only verb
            # left a seeded file untouched. `.tmp` names are the atomic
            # writer's (random) temp files and are skipped like above.
            session = None
            if os.path.isdir(sessdir):
                session = {"dir_modes": [oct(os.stat(d).st_mode & 0o777)
                                         for d in (os.path.dirname(sessdir), sessdir)]}
                seeded = {k.replace("{GATEFILE}", gatefile): v.encode()
                          for k, v in (sessseed or {}).items()}
                for fn in sorted(os.listdir(sessdir)):
                    if fn.endswith(".tmp"):
                        continue
                    fp = os.path.join(sessdir, fn)
                    body = open(fp, "rb").read()
                    # A seed the binary did not touch is recorded as such: a
                    # `{NOW+N}` seed carries a per-run timestamp, and its raw
                    # bytes would differ between the two binaries' runs.
                    shown = "seed-unchanged" if seeded.get(fn) == body else body.hex()
                    session[fn.replace(gatefile, "{GATEFILE}")] = [
                        shown, oct(os.stat(fp).st_mode & 0o777)]
            results[name] = {"stdout_hex": out.hex(), "stderr_hex": err.hex(),
                             "exit": code, "pinfile_hex": pin,
                             "bindfile_hex": bind, "written": written,
                             "session": session}
    finally:
        gate.terminate(); gate.wait()
    with open(outpath, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    print(f"wrote {len(results)} cases -> {outpath}")

main()
