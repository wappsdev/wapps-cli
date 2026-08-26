#!/usr/bin/env python3
"""Bir ikiliyi tum vakalarda pty altinda kosturur ve sonucu JSON dokerler."""
import json, os, shutil, socket, subprocess, sys, time
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
                # GIT_CEILING_DIRECTORIES — OLCUMUN GECERLILIGI icin, uslup
                # degil: baglama kimligi (repoIdentity) git'e soruyor, ve bu
                # scratch dizini bir git worktree'sinin ICINDE olabilir
                # (TMPDIR'in nereye baktigina bagli). O durumda kimlik, cevreleyen
                # deponun origin URL'i + alt yolu olurdu — yani olcum, calistigi
                # makinenin dizin agacina gore DEGISIRDI. Tavan, git'in workdir'in
                # uzerine cikmasini engeller: kimlik DAIMA mutlak yola duser.
                "GIT_CEILING_DIRECTORIES": workdir,
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
            os.makedirs(env["HOME"], exist_ok=True)
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
                    fp = os.path.join(casedir, rel)
                    os.makedirs(os.path.dirname(fp), exist_ok=True)
                    with open(fp, "w") as f:
                        f.write(content)
            out, err, code = run([binary] + argv, env, cwd=casedir,
                                 stdin_data=stdin_data)
            # Pin dosyasinin SON hali de sozlesmenin parcasi: reddedilen bir
            # okumanin pin'i geri sarmadigi ancak boyle gorunur.
            pin = open(pinpath, "rb").read().hex() if os.path.exists(pinpath) else None
            # BAGLAMA defteri de sozlesmenin parcasi: bir ikili reddedip yine de
            # pinleseydi (ya da tersi) cikti esit gorunurdu.
            bindpath = os.path.join(cfg, "wapps", "repo-pins.json")
            bind = open(bindpath, "rb").read().hex() if os.path.exists(bindpath) else None
            # apply'in YAZDIGI hedef dosyalar: cikti satirlari ("wrote x")
            # esit olup dosya ICERIGI ayrisabilirdi. Mod da tasiniyor cunku
            # bu dosyalar duz metin sir tasiyor ve 0600 olmalari sozlesme.
            written = None
            if cfgseed is not None:
                written = {}
                for root_, _, fs in os.walk(casedir):
                    for fn in sorted(fs):
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
                        written[rel] = [open(fp, "rb").read().hex(),
                                        oct(os.stat(fp).st_mode & 0o777)]
            results[name] = {"stdout_hex": out.hex(), "stderr_hex": err.hex(),
                             "exit": code, "pinfile_hex": pin,
                             "bindfile_hex": bind, "written": written}
    finally:
        gate.terminate(); gate.wait()
    with open(outpath, "w") as f:
        json.dump(results, f, indent=1, sort_keys=True)
    print(f"wrote {len(results)} cases -> {outpath}")

main()
