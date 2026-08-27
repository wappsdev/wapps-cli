// diffharness, DIFFERENTIAL'IN KENDI OLCUM ORTAMINI sinar.
//
// NEDEN VAR: ayni agacta, ayni commit'te, tek farki `TMPDIR` olan iki kosum
// TERS KARAR verdi. Depo-disi bir TMPDIR ile 121 sn ve exit 0; broker
// harness'inin verdigi TMPDIR ile (bir git worktree'sinin ICINDE) 954 sn ve
// exit 101, ON UC vaka x IKI ikili = 26 ZAMAN ASIMI. Yani "iki ikili ayni mi"
// sorusunun cevabi cagiranin cevre degiskenine baglaniyordu.
//
// MEKANIZMA (olculdu, tahmin degil): baglama kimligi `git`e soruluyor
// (`remote get-url origin`, yoksa `rev-parse --git-common-dir`). Calisma
// dizini bir deponun icindeyse git YUKARI CIKIP o depoyu buluyor ve kimlik
// `<ana depo koku>#<alt yol>` oluyor. Korpusun tohumladigi pin ise
// sha256(MUTLAK YOL) ile anahtarli — yani pin BULUNAMIYOR, kapi "pinsiz"
// diyor, insan+TTY dali `bindPrompt`e giriyor ve stdin'siz bir pty EOF
// vermedigi icin iki ikili de 30 sn sonra SIGKILL yiyor. Kanit metni:
//     This repo is not bound to a project yet.
//       repo:    /Users/.../wapps-platform#.broker-scratch/.../cases/<vaka>
//     Bind them? [y/N]:
//
// BURADAKI TESTLER IDDIADIR, KARSILASTIRMA DEGIL (bkz. armcheck.rs): iki
// ikiliyi kiyaslamiyorlar, harness'in kendi kapisinin gercekten kapandigini
// olcuyorlar.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn pty_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty")
}

/// Bu testler icin DEPO-DISI ve KANONIK oldugu OLCULMUS bir taban dizin.
///
/// `std::env::temp_dir()` KULLANILAMAZ: bu dosyanin var olma sebebi tam olarak
/// onun bir deponun icine dusebilmesi. Taban sartlari tutmuyorsa test anlamsiz
/// olurdu, o yuzden ikisi de olculuyor ve tutmuyorsa test PATLIYOR.
///
/// `canonicalize` SUS DEGIL: `/tmp` macOS'ta `/private/tmp`e bir sembolik
/// bagdir, ve kanonik olmayan bir taban tam da bu dosyanin olctugu ikinci
/// tuzagi uretir.
fn neutral_base(tag: &str) -> PathBuf {
    let d = PathBuf::from("/tmp").join(format!("wapps-diffharness-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("notr taban olusturulamadi");
    let d = d.canonicalize().expect("notr taban kanoniklestirilemedi");
    assert!(
        !inside_a_git_repo(&d),
        "notr taban ({}) bir deponun ICINDE — bu testler hicbir sey olcmez",
        d.display()
    );
    d
}

/// Bir deponun ICINDE bir dizin verir (`git init` ile taze bir depo kurar).
fn repo_base(tag: &str) -> PathBuf {
    let repo = neutral_base(&format!("repo-{tag}")).join("repo");
    std::fs::create_dir_all(&repo).expect("depo dizini");
    let out = Command::new("git")
        .arg("init")
        .arg("-q")
        .arg(&repo)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init basarisiz");
    let inner = repo.join("nested/base");
    std::fs::create_dir_all(&inner).expect("ic dizin");
    assert!(
        inside_a_git_repo(&inner),
        "kurulan dizin depo icinde GORUNMUYOR"
    );
    inner
}

fn inside_a_git_repo(d: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(d)
        .args(["rev-parse", "--git-dir"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn py(code: &str) -> Output {
    Command::new("python3")
        .arg("-c")
        .arg(code)
        .env("PYTHONPATH", pty_dir())
        .output()
        .expect("python3 kosturulamadi")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

// --- (a) HARNESS KENDI CALISMA DIZININI SECER ------------------------------

// Depo ICINDEKI bir taban ATLANIR ve depo-disi olan secilir. Cagiranin TMPDIR'i
// bir ONERIDIR, HUKUM DEGIL.
#[test]
fn a_base_inside_a_git_repo_is_skipped_for_a_repo_free_one() {
    let bad = repo_base("skip");
    let good = neutral_base("skip-good");
    let out = py(&format!(
        "import workdir; print(workdir.pick_in([{:?}, {:?}], 'wd'))",
        bad.display().to_string(),
        good.display().to_string()
    ));
    assert!(out.status.success(), "pick_in patladi:\n{}", text(&out));
    let picked = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        picked,
        good.join("wd").display().to_string(),
        "yanlis taban secildi"
    );
    assert!(Path::new(&picked).is_dir(), "secilen dizin YARATILMAMIS");
    assert!(
        !inside_a_git_repo(Path::new(&picked)),
        "secilen dizin bir deponun ICINDE"
    );
    // Elenen aday KULLANICININ DEPOSUNUN icindeydi: arkada iz birakilmamali.
    assert!(!bad.join("wd").exists(), "elenen aday depoda dizin BIRAKTI");
}

// --- (b) HICBIR ADAY UYMUYORSA GURULTULU PATLA -----------------------------

// Cikis kodu 97 ve bu SECILMIS bir sayi: "olcum YAPILMADI", cargo'nun test
// basarisizligi olan 101'den ve "gecti" olan 0'dan AYRI okunabilsin diye.
// (cargo'nun 97'yi oldugu gibi ilettigi olculdu.)
#[test]
fn every_base_inside_a_git_repo_blows_up_with_its_own_exit_code() {
    let bad = repo_base("all");
    let out = py(&format!(
        "import workdir; print(workdir.pick_in([{:?}], 'wd'))",
        bad.display().to_string()
    ));
    assert_eq!(
        out.status.code(),
        Some(97),
        "beklenen 97 degil:\n{}",
        text(&out)
    );
    assert!(
        text(&out).contains("git"),
        "patlama mesaji SEBEBI soylemiyor:\n{}",
        text(&out)
    );
}

// Kapi AYIRT EDICI mi: notr bir dizin GECMELI. Bu olmadan yukaridaki test
// yalnizca "her sey patliyor"u olcerdi.
#[test]
fn the_guard_lets_a_repo_free_workdir_through() {
    let good = neutral_base("guard-ok");
    let out = py(&format!(
        "import workdir; workdir.demand_usable({:?})",
        good.display().to_string()
    ));
    assert!(
        out.status.success(),
        "notr dizin reddedildi:\n{}",
        text(&out)
    );

    let bad = repo_base("guard-no");
    let out = py(&format!(
        "import workdir; workdir.demand_usable({:?})",
        bad.display().to_string()
    ));
    assert_eq!(
        out.status.code(),
        Some(97),
        "depo icindeki dizin GECTI:\n{}",
        text(&out)
    );
}

// probe.py o kapiyi GERCEKTEN cagiriyor mu, ve HERHANGI bir vaka kosmadan ONCE
// mi? Ikili yolu KASITLI olarak yok: kapi once kossaydi bile bir vaka kossa
// baska bir hatayla olurdu. 97 gorurusek kapi ilk sirada demektir.
#[test]
fn probe_refuses_a_workdir_inside_a_git_repo_before_running_a_case() {
    let bad = repo_base("probe");
    let outjson = neutral_base("probe-out").join("out.json");
    let out = Command::new("python3")
        .arg(pty_dir().join("probe.py"))
        .arg("/nonexistent/wapps-binary")
        .arg(&outjson)
        .arg(&bad)
        .output()
        .expect("python3 kosturulamadi");
    assert_eq!(
        out.status.code(),
        Some(97),
        "probe.py 97 ile cikmadi:\n{}",
        text(&out)
    );
    assert!(!outjson.exists(), "probe.py reddettigi halde CIKTI yazdi");
}

// --- IKINCI TUZAK: SEMBOLIK BAGLI YOL --------------------------------------
//
// Depo-disi olmak YETMIYOR. Korpus, tohumladigi repo pinini
// sha256(<MUTLAK YOL>) ile anahtarliyor ve o yolu PYTHON uretiyor; cocuk
// surec ise ayni yolu `getcwd`den aliyor, yani DAIMA cozulmus (kanonik)
// halinden. Yol bir sembolik bag tasiyorsa iki dize AYRISIR, pin bulunamaz ve
// vaka yine onay isteminde asili kalir. OLCULDU (`/tmp` -> `/private/tmp`):
//
//     repo:    /private/tmp/wapps-symtrap-88375/cases/human_get_binding_...
//     Bind them? [y/N]:            <- 30 sn sonra SIGKILL
//
// Bu, macOS'un VARSAYILAN TMPDIR'i icin de gecerlidir (/var -> /private/var).
#[test]
fn a_symlinked_base_yields_a_canonical_workdir() {
    let real = neutral_base("canon");
    let link = real.parent().unwrap().join(format!(
        "{}-link",
        real.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let out = py(&format!(
        "import workdir; print(workdir.pick_in([{:?}], 'wd'))",
        link.display().to_string()
    ));
    assert!(out.status.success(), "pick_in patladi:\n{}", text(&out));
    let picked = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
    assert_eq!(
        picked,
        picked.canonicalize().expect("canonicalize"),
        "secilen yol KANONIK degil: {}",
        picked.display()
    );
    assert!(picked.is_dir(), "secilen dizin yok");
}

// Kapi, kanonik OLMAYAN bir calisma dizinini de reddeder — cunku o dizinle
// yapilan olcum bir davranis degil bir timeout olcer.
#[test]
fn the_guard_refuses_a_workdir_that_is_not_canonical() {
    let real = neutral_base("canon-guard");
    let link = real.parent().unwrap().join(format!(
        "{}-link",
        real.file_name().unwrap().to_string_lossy()
    ));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let out = py(&format!(
        "import workdir; workdir.demand_usable({:?})",
        link.display().to_string()
    ));
    assert_eq!(
        out.status.code(),
        Some(97),
        "sembolik bagli yol GECTI:\n{}",
        text(&out)
    );

    // AYIRT EDICI: kanonik olan GECMELI.
    let out = py(&format!(
        "import workdir; workdir.demand_usable({:?})",
        real.display().to_string()
    ));
    assert!(
        out.status.success(),
        "kanonik dizin reddedildi:\n{}",
        text(&out)
    );
}

// --- OZET SATIRI: UNSOUND bir EQUAL DEGILDIR -------------------------------

// Zaman asimina ugramis bir vaka IKI tarafta da ayni gorunur ve eski ozet onu
// EQUAL'e sayiyordu: "EQUAL=419 DIFFERENT=0 UNSOUND=26" satirini okuyan biri
// 419 vakanin karsilastirildigini sanirdi — oysa on ucu bir DAVRANIS degil bir
// zaman asimi olcmustu.
#[test]
fn a_timed_out_case_is_not_counted_as_equal() {
    let d = neutral_base("summary");
    let mk = |p: &Path| {
        let doc = r#"{
 "zz_sound_case": {"stdout_hex": "6869", "stderr_hex": "", "exit": 0,
                   "pinfile_hex": null, "bindfile_hex": null, "written": null},
 "zz_timeout_case": {"stdout_hex": "6869", "stderr_hex": "", "exit": -9,
                     "pinfile_hex": null, "bindfile_hex": null, "written": null}
}"#;
        std::fs::write(p, doc).expect("json yazilamadi");
    };
    let a = d.join("go.json");
    let b = d.join("rs.json");
    mk(&a);
    mk(&b);
    let out = Command::new("python3")
        .arg(pty_dir().join("diff.py"))
        .arg(&a)
        .arg(&b)
        .output()
        .expect("python3 kosturulamadi");
    let report = text(&out);
    assert!(
        report.contains("EQUAL=1 "),
        "saglam vaka sayisi yanlis:\n{report}"
    );
    assert!(
        report.contains("UNSOUND=1"),
        "unsound VAKA sayisi yanlis:\n{report}"
    );
    assert!(
        !report.contains("EQUAL=2"),
        "zaman asimi EQUAL'e sayildi:\n{report}"
    );
    assert!(!out.status.success(), "unsound bir kosum SIFIR ile cikti");
}
