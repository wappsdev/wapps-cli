#!/usr/bin/env python3
"""Iki probe ciktisini BAYT-BAYT karsilastirir.

IKI SESSIZ YALAN, ve ikisi de artik BURADA MEKANIZMA:

 1. ZAMAN ASIMI, "esitlik" gibi gorunur. Onay bekleyen bir dal stdin'siz
    kosarsa bir pty ASLA EOF vermez: iki ikili de okumada bloklanir ve 30 sn
    sonra ayni negatif kodla (-9) oldurulur. Olculen sey bir davranis DEGIL bir
    timeout'tur. Bu tam olarak oldu (human_policy_set_yes_flag, `--yes`
    unutulmustu) ve yalnizca cikis kodu elle okundugu icin fark edildi. Artik
    NEGATIF cikis kodu HATA — ve o vaka EQUAL'e de SAYILMAZ: ozet satiri
    "EQUAL=419 DIFFERENT=0 UNSOUND=26" bir kez okuyan birine 419 vakanin
    karsilastirildigini soyledi, oysa on ucu yalnizca zaman asimi olcmustu.

 2. BOS VAKA, "esitlik" gibi gorunur. Hicbir sey basmayan, hicbir dosya
    yazmayan bir vaka da EQUAL doner. Onceki bir dilim bunu vaka basina bayt
    sayarak ELLE aradi; artik karsilastiriciya gomulu.

Ikisi de EXCLUDED'a saygi duyar: acikca disarida birakilmis bir vaka bu
kontrollerden de muaftir.
"""
import json, os, sys
go = json.load(open(sys.argv[1])); rs = json.load(open(sys.argv[2]))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import EXCLUDED as skip
eq = neq = 0
bad = []

# UNSOUND vakalarin ADLARI. Sayim BULGU degil VAKA uzerinden yapilir: bir
# timeout iki bulgu uretir (GO ve RS) ama bir tek vaka bozar.
unsound = set()


def _is_vacuum(v):
    """Vaka HICBIR SEY gozlemlemiyor mu?"""
    if v.get("stdout_hex") or v.get("stderr_hex"):
        return False
    if v.get("pinfile_hex") or v.get("bindfile_hex"):
        return False
    for _, entry in (v.get("written") or {}).items():
        if entry[0]:
            return False
    if v.get("session"):
        return False
    return True

for name in sorted(go):
    if name in skip: continue
    g, r = go[name], rs.get(name)
    if r is None:
        print(f"MISSING  {name}"); neq += 1; continue
    # Negatif cikis kodu = timeout'ta oldurulmus. Iki taraf da oyleyse
    # karsilastirma bir davranisi degil bir zaman asimini olcerdi.
    for tag, v in (("GO", g), ("RS", r)):
        if v["exit"] < 0:
            bad.append(f"TIMEOUT  {name}: {tag} cikis {v['exit']} — bu vaka bir "
                       f"DAVRANIS degil bir ZAMAN ASIMI olcuyor (onay dali "
                       f"stdin'siz mi kaldi?)")
            unsound.add(name)
    if _is_vacuum(g) and _is_vacuum(r):
        bad.append(f"VACUUM   {name}: sifir stdout + sifir stderr + yazilan dosya "
                   f"YOK + pin YOK + baglama defteri YOK — bu vaka HICBIR SEY "
                   f"karsilastirmiyor")
        unsound.add(name)
    same = (g["stdout_hex"] == r["stdout_hex"] and g["stderr_hex"] == r["stderr_hex"]
            and g["exit"] == r["exit"]
            and g.get("pinfile_hex") == r.get("pinfile_hex")
            # Baglama defteri: bir ikili reddedip yine de pinleseydi (ya da
            # tersi) yalnizca ciktiya bakan bir karsilastirma bunu KACIRIRDI.
            and g.get("bindfile_hex") == r.get("bindfile_hex")
            # apply'in yazdigi dosyalarin ICERIGI ve MODU.
            and g.get("written") == r.get("written")
            # The session cache `wapps login` writes (bytes + modes).
            and g.get("session") == r.get("session"))
    if same:
        # UNSOUND bir EQUAL DEGILDIR. Zaman asimina ugramis bir vaka iki
        # tarafta da AYNI gorunur ve eskiden EQUAL'e sayiliyordu: ozet satiri
        # "EQUAL=419 DIFFERENT=0 UNSOUND=26" diyordu ve onu okuyan biri 419
        # vakanin KARSILASTIRILDIGINI sanirdi — oysa on ucu bir davranis degil
        # bir timeout olcmustu. EQUAL artik yalnizca SAGLAM vakalari sayar,
        # yani differential.rs'teki taban esigi de bu tuzagi yakalar.
        if name not in unsound:
            eq += 1
        continue
    neq += 1
    print(f"DIFF {name}")
    for f in ("stdout", "stderr"):
        a = bytes.fromhex(g[f + "_hex"]); b = bytes.fromhex(r[f + "_hex"])
        if a != b:
            print(f"   {f} GO: {a.decode('utf-8','replace')!r}")
            print(f"   {f} RS: {b.decode('utf-8','replace')!r}")
    if g["exit"] != r["exit"]:
        print(f"   exit GO={g['exit']} RS={r['exit']}")
    if g.get("bindfile_hex") != r.get("bindfile_hex"):
        def dec(v): return None if v is None else bytes.fromhex(v).decode("utf-8", "replace")
        print(f"   repo-pins.json GO: {dec(g.get('bindfile_hex'))!r}")
        print(f"   repo-pins.json RS: {dec(r.get('bindfile_hex'))!r}")
    if g.get("written") != r.get("written"):
        def decw(w):
            if w is None: return None
            return {k: (tuple(v) if v[0] in ("symlink", "emptydir") else
                        (bytes.fromhex(v[0]).decode("utf-8", "replace"), v[1]))
                    for k, v in w.items()}
        print(f"   written GO: {decw(g.get('written'))!r}")
        print(f"   written RS: {decw(r.get('written'))!r}")
    if g.get("session") != r.get("session"):
        def decs(w):
            if w is None: return None
            def body(x):
                return x if x == "seed-unchanged" else bytes.fromhex(x).decode("utf-8", "replace")
            return {k: (v if k == "dir_modes" else (body(v[0]), v[1])) for k, v in w.items()}
        print(f"   session GO: {decs(g.get('session'))!r}")
        print(f"   session RS: {decs(r.get('session'))!r}")
    if g.get("pinfile_hex") != r.get("pinfile_hex"):
        def dec(v): return None if v is None else bytes.fromhex(v).decode("utf-8", "replace")
        print(f"   epochs.json GO: {dec(g.get('pinfile_hex'))!r}")
        print(f"   epochs.json RS: {dec(r.get('pinfile_hex'))!r}")
for line in bad:
    print(line)
print(f"\nEQUAL={eq} DIFFERENT={neq} UNSOUND={len(unsound)}")
if unsound:
    print(f"UYARI: {len(unsound)} vaka SAGLAM DEGIL ve EQUAL'e SAYILMADI — "
          f"olculen sey bir davranis degil (timeout ya da bos vaka). "
          f"DIFFERENT=0 bu kosumun gecerli oldugu ANLAMINA GELMEZ.")
sys.exit(1 if (neq or bad) else 0)
