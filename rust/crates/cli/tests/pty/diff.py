#!/usr/bin/env python3
"""Iki probe ciktisini BAYT-BAYT karsilastirir."""
import json, os, sys
go = json.load(open(sys.argv[1])); rs = json.load(open(sys.argv[2]))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import EXCLUDED as skip
eq = neq = 0
for name in sorted(go):
    if name in skip: continue
    g, r = go[name], rs.get(name)
    if r is None:
        print(f"MISSING  {name}"); neq += 1; continue
    same = (g["stdout_hex"] == r["stdout_hex"] and g["stderr_hex"] == r["stderr_hex"]
            and g["exit"] == r["exit"]
            and g.get("pinfile_hex") == r.get("pinfile_hex")
            # Baglama defteri: bir ikili reddedip yine de pinleseydi (ya da
            # tersi) yalnizca ciktiya bakan bir karsilastirma bunu KACIRIRDI.
            and g.get("bindfile_hex") == r.get("bindfile_hex")
            # apply'in yazdigi dosyalarin ICERIGI ve MODU.
            and g.get("written") == r.get("written"))
    if same:
        eq += 1; continue
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
            return {k: (bytes.fromhex(v[0]).decode("utf-8", "replace"), v[1]) for k, v in w.items()}
        print(f"   written GO: {decw(g.get('written'))!r}")
        print(f"   written RS: {decw(r.get('written'))!r}")
    if g.get("pinfile_hex") != r.get("pinfile_hex"):
        def dec(v): return None if v is None else bytes.fromhex(v).decode("utf-8", "replace")
        print(f"   epochs.json GO: {dec(g.get('pinfile_hex'))!r}")
        print(f"   epochs.json RS: {dec(r.get('pinfile_hex'))!r}")
print(f"\nEQUAL={eq} DIFFERENT={neq}")
sys.exit(1 if neq else 0)
