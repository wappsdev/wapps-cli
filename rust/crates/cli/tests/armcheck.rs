// armcheck, KORPUSUN KENDI MEKANIZMASINI sinar.
//
// cases.py import aninda her fiilin DORT kimlik kolunu da (proj/cfg/rooted/
// bare) gezdigini sart kosuyor. O kontrol bu agacta iki kez ayni kor noktaya
// dusuldugu icin var: once `secrets set`, sonra `secrets get` — ikisinin de
// yapilandirma kolu HIC gezilmemisti ve IKISI DE gercek bir ayrisma
// sakliyordu (her seferinde DIFFERENT=3).
//
// BURADAKI TESTLER IDDIADIR, KARSILASTIRMA DEGIL. Iki ikiliyi kiyaslamiyorlar;
// korpusun kendi kapisinin GERCEKTEN kapandigini olcuyorlar. Bu ayrim onemli:
// differential iki ikilinin PAYLASTIGI bir kusuru goremez, ve "kolu unutmak"
// tam olarak oyle bir kusurdur — iki tarafta da olculmemis bir kod yolu
// birakir ve gate YESIL kalir.
//
// Mekanizmanin kendisi de curuyebilirdi (birisi `_armcheck()` cagrisini
// silebilir, ya da kontrol sessizce hicbir sey yapmaz hale gelebilir). Bu
// yuzden mutasyon ELLE bir kez degil, HER KOSUMDA yapiliyor.
use std::path::{Path, PathBuf};
use std::process::Command;

fn pty_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty")
}

/// Mutasyonu GECICI bir dizinde kosar: `cases.py`nin yanina, ondan tureyen ve
/// sonuna `extra` eklenmis bir modul yazar, sonra import etmeyi dener.
///
/// Kaynak dosya ACILMIYOR bile — kopya uzerinde calisiliyor, yani bir test
/// cokse de agacta iz kalmaz.
fn import_with(extra: &str) -> (bool, String) {
    // Dizin ve dosya adi HER CAGRI ICIN AYRI. Ilk surumde ikisi de sabitti
    // (surec id'si + `cases_mut.py`) ve cargo testleri PARALEL kostugu icin
    // bir testin mutanti digerininkinin uzerine yaziliyordu: mutasyonlu bir
    // import, BASKA bir testin saglam mutantini yukleyip "kabul edildi" diye
    // YESIL donuyordu. Yani testin kendisi tam da bu dosyanin uyardigi seyi
    // yapiyordu — olcmedigi bir seyi olcmus gibi gorunmek.
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let uniq = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("wapps-armcheck-{}-{}", std::process::id(), uniq));
    std::fs::create_dir_all(&dir).expect("gecici dizin");
    let src = std::fs::read_to_string(pty_dir().join("cases.py")).expect("cases.py okunamadi");
    // `_armcheck()` cagrisi dosyanin SONUNDA; mutasyon ondan ONCE girmeli ki
    // kontrol degisikligi gorsun.
    let marker = "\n_armcheck()\n";
    assert!(
        src.contains(marker),
        "cases.py sonunda `_armcheck()` cagrisi YOK — mekanizma kaldirilmis olabilir"
    );
    let mutated = src.replace(marker, &format!("\n{extra}\n_armcheck()\n"));
    let f = dir.join("cases_mut.py");
    std::fs::write(&f, mutated).expect("mutant yazilamadi");

    let out = Command::new("python3")
        .arg("-c")
        .arg("import cases_mut")
        .env(
            "PYTHONPATH",
            format!("{}:{}", dir.display(), pty_dir().display()),
        )
        .current_dir(&dir)
        .output()
        .expect("python3 kosturulamadi");
    let _ = std::fs::remove_dir_all(&dir);
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), msg)
}

// TABAN: dokunulmamis korpus IMPORT EDILEBILMELI. Bu olmadan asagidaki
// testlerin hepsi "her sey patliyor" diye YESIL gorunurdu — kontrolun
// ayirt edici oldugunu degil, yalnizca gurultulu oldugunu olcerlerdi.
#[test]
fn the_untouched_corpus_imports() {
    let (ok, msg) = import_with("");
    assert!(ok, "dokunulmamis cases.py import edilemedi:\n{msg}");
}

// ASIL MUTASYON: yeni bir fiil, YALNIZCA `--project` koluyla. Iki kez cikan
// kor noktanin ta kendisi. Mekanizma calisiyorsa import DUSER ve eksik UC
// kolu ADIYLA sayar.
#[test]
fn a_new_verb_with_only_the_project_arm_is_rejected() {
    let (ok, msg) = import_with(
        r#"CASES += [("agent_newverb_only_project", P + ["secrets", "newverb"], AGENT)]"#,
    );
    assert!(
        !ok,
        "YALNIZCA --project kolu olan yeni bir fiil KABUL EDILDI:\n{msg}"
    );
    for arm in ["cfg", "rooted", "bare"] {
        assert!(
            msg.contains(&format!("`{arm}` kolunun")),
            "eksik `{arm}` kolu ADLANDIRILMADI:\n{msg}"
        );
    }
    assert!(msg.contains("secrets newverb"), "fiil adi gecmiyor:\n{msg}");
}

// ...ve kollari TAMAMLAMAK kapiyi acmali. Aksi halde kontrol bir kapi degil
// bir duvar olurdu: her yeni fiili reddeden bir kontrol de "hep kirmizi" diye
// devre disi birakilir.
#[test]
fn the_same_verb_passes_once_all_four_arms_are_walked() {
    let (ok, msg) = import_with(
        r#"CASES += [
    ("agent_newverb_only_project", P + ["secrets", "newverb"], AGENT),
    ("agent_newverb_cfg", CFG_SUB + ["secrets", "newverb"], AGENT, None, None, _sub(VALID_CFG)),
    ("agent_newverb_rooted", ["secrets", "newverb"], AGENT, None, None, cfg(VALID_CFG)),
    ("agent_newverb_bare", ["secrets", "newverb"], AGENT),
]"#,
    );
    assert!(ok, "dort kolu da gezen bir fiil YINE reddedildi:\n{msg}");
}

// MUAFIYET bir kacis kapisi ama SESSIZ degil: gerekce yazmak zorunlu.
#[test]
fn an_arm_can_be_waived_only_with_a_written_reason() {
    let waived = |reason: &str| {
        import_with(&format!(
            r#"CASES += [("agent_newverb_only_project", P + ["secrets", "newverb"], AGENT)]
ARM_WAIVERS["secrets newverb"] = {{"cfg": "{reason}", "rooted": "{reason}", "bare": "{reason}"}}"#
        ))
    };
    let (ok, msg) = waived("bu fiil Ctx::resolve cagirmiyor");
    assert!(ok, "gerekceli muafiyet KABUL EDILMEDI:\n{msg}");

    let (ok, msg) = waived("");
    assert!(!ok, "BOS gerekceli muafiyet kabul edildi:\n{msg}");
    assert!(
        msg.contains("GEREKCESI BOS"),
        "bos gerekce ADLANDIRILMADI:\n{msg}"
    );
}

// Tablo CURUMESIN: artik gezilen bir kolun muafiyeti, bir sonraki fiilin
// arkasina saklanabilecegi olu bir satirdir.
#[test]
fn a_waiver_for_an_arm_that_is_now_walked_is_rejected() {
    let (ok, msg) = import_with(r#"ARM_WAIVERS["secrets get"] = {"cfg": "bahane"}"#);
    assert!(
        !ok,
        "gezilen bir kola yazilan muafiyet kabul edildi:\n{msg}"
    );
    assert!(msg.contains("ARTIK GEZILIYOR"), "beklenen tani yok:\n{msg}");
}

#[test]
fn a_waiver_for_a_verb_with_no_cases_is_rejected() {
    let (ok, msg) = import_with(r#"ARM_WAIVERS["secrets ghost"] = {"proj": "hayalet"}"#);
    assert!(!ok, "olu muafiyet kabul edildi:\n{msg}");
    assert!(msg.contains("olu muafiyet"), "beklenen tani yok:\n{msg}");
}

// ON IKI FIILIN HICBIRI MUAF DEGIL. `Ctx::resolve`den gecen fiiller listesi
// main.rs'ten OLCULEREK alindi (`grep -n 'Ctx::resolve' main.rs` -> 13 cagri;
// 13.'su `tofu`nun `resolve(None, None)`i). Bu test o on ikisi icin dort kolun
// da GERCEKTEN gezildigini pinliyor: yarin biri bir kolu silip yerine muafiyet
// yazarsa burasi kirmizi olur.
#[test]
fn every_ctx_resolving_verb_walks_all_four_arms_with_no_waiver() {
    let verbs = [
        "secrets list",
        "secrets status",
        "secrets rm",
        "projects list",
        "secrets import-env",
        "secrets env",
        "secrets trust-repo",
        "secrets init",
        "secrets set",
        "secrets get",
        "secrets exec",
        "secrets apply",
    ];
    let script = format!(
        r#"
import json, sys
sys.path.insert(0, {pty:?})
from cases import CASES, EXCLUDED, ARM_NAMES, ARM_WAIVERS, arm_verb, arm_of
seen = {{}}
for c in CASES:
    if c[0] in EXCLUDED: continue
    seen.setdefault(arm_verb(c[1]), set()).add(arm_of(c))
bad = []
for v in {verbs:?}:
    if v not in seen:
        bad.append(v + ": korpusta VAKASI YOK"); continue
    miss = [a for a in ARM_NAMES if a not in seen[v]]
    if miss: bad.append(v + ": eksik kollar " + ",".join(miss))
    if v in ARM_WAIVERS: bad.append(v + ": MUAFIYETI VAR ama olmamali")
print("\n".join(bad))
sys.exit(1 if bad else 0)
"#,
        pty = pty_dir().to_string_lossy(),
        verbs = verbs,
    );
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .output()
        .expect("python3");
    assert!(
        out.status.success(),
        "Ctx::resolve fiillerinde kol boslugu:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
