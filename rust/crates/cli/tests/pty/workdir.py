#!/usr/bin/env python3
"""Differential'in CALISMA DIZININI harness'in KENDISI secer.

NEDEN BU DOSYA VAR — bir olcum, tahmin degil: ayni agac, ayni commit, ayni iki
ikili, tek fark `TMPDIR`:

    TMPDIR bir git worktree'sinin ICINDE  -> exit 101, 26 ZAMAN ASIMI, 954 sn
    TMPDIR depo DISINDA                   -> exit 0,   0 zaman asimi,  121 sn

MEKANIZMA: baglama kimligi (`repoIdentity`) `git`e soruluyor. Calisma dizini
bir deponun icindeyse git YUKARI CIKIP o depoyu buluyor ve kimlik
`<ana depo koku>#<alt yol>` oluyor; korpusun tohumladigi pin ise
sha256(MUTLAK YOL) ile anahtarli. Pin bulunamaz, kapi "pinsiz" der, insan+TTY
dali onay istemine girer, stdin'siz bir pty EOF vermez ve iki ikili de 30 sn
sonra SIGKILL yer. diff.py bunu "iki taraf da ayni" diye EQUAL sayardi.

ONCEKI COZUM YETMEZDI ve sebebi OLCULDU: probe.py her vakaya
`GIT_CEILING_DIRECTORIES=<workdir>` veriyordu. Tavan yalnizca workdir'in
GERCEK ALTINDAKI dizinler icin is goruyor — git tavani "OZ ATA" olarak arar
(`longest_ancestor_length`), yani tavan ile dizin AYNI oldugunda hicbir sey
yapmaz:

    GIT_CEILING_DIRECTORIES=$W git -C $W/cases/x rev-parse --git-common-dir
        -> fatal: not a git repository   (korunuyor)
    GIT_CEILING_DIRECTORIES=$W git -C $W       rev-parse --git-common-dir
        -> /Users/.../wapps-platform/.git  (KORUNMUYOR)

Korpusun buyuk cogunlugu vakayi workdir'IN KENDISINDE kosuyor, yani tavanin
kapsami korpusun sekline bagliydi. Tavan KALDIRILDI.

IKINCI TUZAK — AYNI SINIF, AYRI SEBEP, ve o da OLCULDU: depo-disi olmak
YETMIYOR. Tohumlanan pin sha256(<MUTLAK YOL>) ile anahtarli ve o yolu PYTHON
uretiyor; cocuk surec ayni yolu `getcwd`den aliyor, yani DAIMA cozulmus
(kanonik) halinden. Yolda bir sembolik bag varsa iki dize ayrisir, pin
bulunamaz ve vaka yine onay isteminde asili kalir:

    workdir = /tmp/wapps-symtrap-88375          (/tmp -> /private/tmp)
    ...
    repo:    /private/tmp/wapps-symtrap-88375/cases/human_get_binding_...
    Bind them? [y/N]:                            <- 30 sn sonra SIGKILL

Bu, macOS'un VARSAYILAN TMPDIR'i icin de gecerlidir (/var -> /private/var) —
yani tuzak broker'a ozgu degil, sistemin kendisinde duruyordu.

Iki tuzak, TEK HUKUM: calisma dizini KANONIK olacak ve HICBIR DEPONUN ICINDE
olmayacak.
"""
import os
import subprocess
import sys

# Cikis kodu "olcum YAPILMADI" demek ve SECILMIS bir sayidir: cargo'nun test
# basarisizligi 101, gecen kosum 0. Ucu de ayri okunabilsin diye 97.
# (cargo test'in bu kodu oldugu gibi ilettigi olculdu.)
EXIT_NOT_MEASURED = 97


def inside_a_git_repo(path):
    """git BURADAN yukari cikip bir depo bulabiliyor mu?

    TAVAN YOK, bilerek: sorulan sey tam olarak git'in kendi kesif kurali."""
    r = subprocess.run(["git", "-C", path, "rev-parse", "--git-dir"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def _die(msg):
    sys.stderr.write(msg)
    sys.exit(EXIT_NOT_MEASURED)


def pick_in(bases, name):
    """`bases` icindeki ILK KULLANILABILIR tabanda `name` dizinini yaratir ve
    KANONIK yolunu doner.

    Kanoniklik bir sonuc degil bir SART: donen dize dogrudan cocuk surecin
    `getcwd`i ile karsilastirilacak. Aday bir deponun icindeyse yaratilan dizin
    GERI ALINIR: orasi cagiranin deposudur, harness iz birakmamalidir."""
    tried = []
    for base in bases:
        d = os.path.join(base, name)
        os.makedirs(d, exist_ok=True)
        # realpath ANCAK dizin var oldugunda dogru cevabi verir.
        d = os.path.realpath(d)
        if not inside_a_git_repo(d):
            return d
        tried.append(d)
        try:
            os.rmdir(d)
        except OSError:
            pass
    _die("differential: depo-DISI bir calisma dizini bulunamadi.\n"
         "Denenen adaylarin hepsi bir git deposunun ICINDE:\n"
         + "".join(f"  {t}\n" for t in tried) +
         "Calisma dizini bir deponun icindeyse baglama kimligi o depoya duser,\n"
         "tohumlanan pinler tutmaz ve vakalar onay isteminde ZAMAN ASIMINA ugrar\n"
         "— yani olcum bir davranis degil bir timeout olcer.\n"
         "TMPDIR'i depo disina alin.\n")


def candidates():
    """Aday tabanlar. Cagiranin TMPDIR'i bir ONERIDIR, HUKUM DEGIL: depo
    icindeyse atlanir. `/tmp` daima ikinci sirada denenir ve o da olculur —
    varsayilmaz."""
    out = []
    for b in (os.environ.get("TMPDIR"), "/tmp"):
        if b and b not in out:
            out.append(b)
    return out


def pick(name):
    return pick_in(candidates(), name)


def demand_usable(path):
    """Verilen calisma dizinini REDDEDER (97) — iki sarttan biri tutmuyorsa.

    Ikisi de AYNI belirtiyi uretir (onay isteminde 30 sn sonra SIGKILL), o
    yuzden ikisi de burada ve ikisi de GURULTULU."""
    real = os.path.realpath(path)
    if real != path:
        _die(f"differential: calisma dizini KANONIK degil: {path}\n"
             f"  gercek yol: {real}\n"
             "Tohumlanan pin python'un urettigi yola, cocuk surec ise\n"
             "`getcwd`in COZULMUS yoluna bakar; ikisi ayrisirsa pin bulunamaz\n"
             "ve vakalar onay isteminde ZAMAN ASIMINA ugrar.\n")
    if inside_a_git_repo(path):
        _die(f"differential: calisma dizini bir git deposunun ICINDE: {path}\n"
             "Baglama kimligi o depoya duser ve vakalar onay isteminde ZAMAN\n"
             "ASIMINA ugrar; olcum bir davranis degil bir timeout olcerdi.\n")


if __name__ == "__main__":
    # CLI: `workdir.py <ad>` -> depo-disi mutlak yolu stdout'a basar.
    print(pick(sys.argv[1]))
