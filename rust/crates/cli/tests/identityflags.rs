// `--config` + `--project` BIRLIKTE — ve neden bu bir IDDIA testi.
//
// BULUNUS: bu ayrisma dort kollu kol-taksonomisinin GORMEDIGI bir durumdan
// cikti. Taksonomi bir vakayi `proj` / `cfg` / `rooted` / `bare` diye
// sinifliyor; iki bayrak BIRLIKTE verildiginde ortaya cikan BESINCI durumun
// adi yoktu, ve 359 vakalik korpusta tek bir ornegi de yoktu. Vaka yazilinca
// differential ANINDA DIFFERENT=2 verdi:
//
//   Go   -> "--config and --project are mutually exclusive"
//   Rust -> "the argument '--config <string>' cannot be used with
//            '--project <string>'"   (clap'in `conflicts_with` cumlesi)
//
// NEDEN IDDIA, KARSILASTIRMA DEGIL: duzeltmeden sonra differential 0'a doner
// ve ELDE KANIT KALMAZ. Asagidaki testler iki ikiliyi birbiriyle
// KARSILASTIRMIYOR; her birinin BEKLENEN metni bastigini AYRI AYRI soyluyor.
// Ayrica differential'in yapisal korlugu burada gercek bir risk: reddi iki
// tarafta da "sadelestirip" clap'e geri birakmak differential'i YESIL
// birakirdi.
//
// UC AYRINTI DA OLCULDU, TAHMIN EDILMEDI:
//  1. Ret `Ctx::resolve`e AIT DEGIL. Go'da root'un PersistentPreRunE'unda,
//     yani `Ctx::resolve` cagirmayan fiiller (`doctor`, `dr`, `policy`,
//     `rotate skip`, `projects rm`) de ayni hatayi veriyor.
//  2. `tofu` ISTISNA: root'a mount'lu + DisableFlagParsing → hook kosmuyor,
//     iki bayrak da ATIL kaliyor.
//  3. Hata DUZ (`Plain`), yapisal degil: insan yolunda kod oneki ve kurtarma
//     satiri YOK. Ilk duzeltme burayi kacirdi ve DIFFERENT=1 olarak geri
//     geldi — o yuzden rendering'in kendisi de asagida pinli.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use wapps::configctx::MUTUALLY_EXCLUSIVE;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

fn scratch() -> PathBuf {
    // HER CAGRI ICIN AYRI dizin. Ilk surum surec id'siyle anahtarliyordu ve
    // her test sonunda `remove_dir_all` cagiriyordu: cargo testleri PARALEL
    // kostugu icin bir test digerinin calisma dizinini ALTINDAN CEKIYORDU.
    // Tek tek kosarken gecti, `cargo test` icinde DUSTU — yani yesil olmasi
    // siraya bagliydi. (Ayni hata bu turda tests/armcheck.rs'te de yapildi.)
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let uniq = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("wapps-identflags-{}-{}", std::process::id(), uniq));
    std::fs::create_dir_all(&d).expect("scratch");
    assert!(
        !d.starts_with(repo_root()),
        "scratch depo agacinin ICINDE: {}",
        d.display()
    );
    d
}

/// go_oracle, Go ikilisini KAYNAKTAN derler. Sahadaki sozlesme Go'nun BUGUNKU
/// davranisi; bu yuzden metin bir sabitten degil IKILIDEN dogrulaniyor.
fn go_oracle(work: &Path) -> PathBuf {
    let bin = work.join("wapps-go-identflags");
    let out = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg("./main.go")
        .current_dir(repo_root())
        .output()
        .expect("go build kosturulamadi");
    assert!(
        out.status.success(),
        "go build basarisiz: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

/// agent_stderr, ikiliyi AJAN modunda kosar ve stderr'i doner. Ajan modu
/// bilincli: zarf TEK satir JSON, yani metin TTY'siz de bayt duzeyinde
/// okunabilir. (Insan yolunun rendering'i ayri bir testte, `report_error`
/// uzerinden — orasi bir TTY istemiyor.)
fn agent_stderr(bin: &Path, work: &Path, args: &[&str]) -> String {
    let out = Command::new(bin)
        .args(args)
        .current_dir(work)
        .env("CLAUDECODE", "1")
        .env("WAPPS_NO_UPDATE_CHECK", "1")
        .env("WAPPS_SECRETS_GATE", "http://127.0.0.1:1")
        .output()
        .expect("ikili kosturulamadi");
    String::from_utf8_lossy(&out.stderr).to_string()
}

// HER IKI IKILI DE ayni cumleyi basmali — ama test bunu KARSILASTIRARAK
// degil, ikisini de BEKLENEN metne karsi olcerek soyluyor.
#[test]
fn both_binaries_reject_the_two_identity_flags_with_the_same_sentence() {
    let work = scratch();
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));
    let args = [
        "--config",
        "a.yaml",
        "--project",
        "pp",
        "secrets",
        "get",
        "K",
    ];
    for (tag, bin) in [("go", go.as_path()), ("rust", rs.as_path())] {
        let err = agent_stderr(bin, &work, &args);
        assert!(
            err.contains(MUTUALLY_EXCLUSIVE),
            "{tag}: beklenen cumle YOK.\nbeklenen: {MUTUALLY_EXCLUSIVE}\ngelen: {err}"
        );
        assert!(
            err.contains(r#""error":"INTERNAL""#),
            "{tag}: zarf kodu INTERNAL degil: {err}"
        );
        // clap'in KENDI cumlesi geri gelmesin — duzeltme tam olarak onu
        // kaldirmakti.
        assert!(
            !err.contains("cannot be used with"),
            "{tag}: clap cumlesi geri geldi: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

// Ret `Ctx::resolve`e AIT DEGIL: onu cagirmayan bir fiil de reddi almali.
// Bu test kirmizi olursa kontrol muhtemelen `Ctx::resolve`in icine geri
// tasinmistir ve bes fiil sessizce iki bayragi da kabul ediyordur.
#[test]
fn a_verb_that_never_resolves_a_ctx_is_rejected_too() {
    let work = scratch();
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));
    let args = ["--config", "a.yaml", "--project", "pp", "doctor"];
    for (tag, bin) in [("go", go.as_path()), ("rust", rs.as_path())] {
        let err = agent_stderr(bin, &work, &args);
        assert!(
            err.contains(MUTUALLY_EXCLUSIVE),
            "{tag}: `doctor` reddi ALMADI: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

// ...ve `tofu` ISTISNA. Istisnayi tutan tek sey bu test: kaldiran biri
// "tutarlilik" adina onu kolayca silebilir.
#[test]
fn tofu_treats_both_identity_flags_as_inert() {
    let work = scratch();
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));
    let args = ["--config", "a.yaml", "--project", "pp", "tofu", "plan"];
    for (tag, bin) in [("go", go.as_path()), ("rust", rs.as_path())] {
        let err = agent_stderr(bin, &work, &args);
        assert!(
            !err.contains(MUTUALLY_EXCLUSIVE),
            "{tag}: `tofu` mutual-exclusion reddi ALDI, oysa bayraklar ATIL olmali: {err}"
        );
        assert!(
            err.contains("no .wapps.yaml found"),
            "{tag}: beklenen config reddi yok: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

/// human_stderr, ikiliyi INSAN yolunda — yani GERCEK bir pty altinda —
/// kosar. `agentmode::is_agent()` non-TTY stdin'i DAIMA ajan sayiyor, o
/// yuzden insan bicimi bir borudan ULASILAMAZ.
///
/// Agacin KENDI `ptyrun.py`si kullaniliyor (elle `script(1)` degil): vakum ve
/// zaman asimi korumalari onda, ve stdout/stderr AYRI pty'lere baglaniyor.
fn human_stderr(bin: &Path, work: &Path, args: &[&str]) -> String {
    let pty = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/ptyrun.py");
    let mut argv = vec![bin.to_string_lossy().to_string()];
    argv.extend(args.iter().map(|a| a.to_string()));
    let spec = serde_json::json!({
        "argv": argv,
        "cwd": work.to_string_lossy(),
        "env": {
            "PATH": "/usr/bin:/bin",
            "HOME": work.to_string_lossy(),
            "TERM": "dumb",
            // Insan override'i YALNIZCA TTY'de onurlandiriliyor — pty sart.
            "WAPPS_AGENT_MODE": "0",
            "WAPPS_NO_UPDATE_CHECK": "1",
            "WAPPS_SECRETS_GATE": "http://127.0.0.1:1",
        },
    });
    let mut c = Command::new("python3")
        .arg(&pty)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ptyrun.py kosturulamadi");
    c.stdin
        .as_mut()
        .unwrap()
        .write_all(spec.to_string().as_bytes())
        .expect("spec yazilamadi");
    let out = c.wait_with_output().expect("ptyrun.py bitmedi");
    assert!(
        out.status.success(),
        "ptyrun.py basarisiz: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("ptyrun.py JSON dondurmedi");
    let hex = v["stderr_hex"].as_str().unwrap_or("");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

// RENDERING: hata DUZ, yani insan yolunda kod oneki ve kurtarma satiri YOK.
//
// BU TEST BIR KEZ YANLIS YAZILDI VE O HATA BURAYA NOT EDILIYOR: ilk surumu
// `report_error`i ELLE kurulmus bir `CmdError::Plain` ile cagiriyordu. Yani
// `report_error`in davranisini olcuyordu, `main.rs`in NE URETTIGINI degil —
// olcmek istedigi seyin KARDESINI olcuyordu. Kanit: `main.rs`teki `Plain`
// yapisal `Cli`ye cevrildiginde (tam da duzeltmenin ilk turda kacirdigi
// hata) test YESIL kaldi. Artik GERCEK ikili, GERCEK bir pty altinda
// kosuyor ve o mutasyon KIRMIZI veriyor.
#[test]
fn the_human_rendering_carries_no_code_prefix_and_no_recovery_line() {
    let work = scratch();
    let go = go_oracle(&work);
    let rs = PathBuf::from(env!("CARGO_BIN_EXE_wapps"));
    let args = [
        "--config",
        "a.yaml",
        "--project",
        "pp",
        "secrets",
        "get",
        "K",
    ];
    // `\r` YOK: ptyrun.py slave pty'de ONLCR'i kapatiyor, yani \n -> \r\n
    // donusumu olmuyor ve bayt sadakati korunuyor.
    let want = format!("Error: {MUTUALLY_EXCLUSIVE}\n");
    for (tag, bin) in [("go", go.as_path()), ("rust", rs.as_path())] {
        let err = human_stderr(bin, &work, &args);
        assert_eq!(err, want, "{tag}: insan bicimi ayristi");
        assert!(!err.contains("INTERNAL"), "{tag}: kod oneki sizdi: {err}");
        assert!(
            !err.contains('\u{2192}'),
            "{tag}: kurtarma satiri sizdi: {err}"
        );
    }
    let _ = std::fs::remove_dir_all(&work);
}

// --- GOLGENIN KISA-BICIM YUZU ------------------------------------------------
//
// `short_project_token` KOK BAYRAK BOLGESINI tariyor: alt komuta kadar olan
// jetonlar. Neyi TANIDIGI kadar neyi TANIMADIGI da sozlesme — kapsam dar ve
// asagida ADLANDIRILMIS (kumeler HARIC), cunku olculmemis bir ekseni taklit
// etmek olculmus olani tasimaktan farkli bir istir.
use wapps::cli::short_project_token;

fn tok(args: &[&str]) -> Option<String> {
    short_project_token(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

#[test]
fn a_short_project_flag_in_the_root_region_is_reported_with_its_raw_token() {
    // Metin Go'nun hatasina AYNEN giriyor ("in -p", "in -ptestproj"), yani
    // jetonun KENDISI donuyor, bir bayrak adi degil.
    assert_eq!(
        tok(&["-p", "x", "token", "exchange"]).as_deref(),
        Some("-p")
    );
    assert_eq!(tok(&["-px", "token", "exchange"]).as_deref(), Some("-px"));
    assert_eq!(tok(&["-p=x", "dr", "restore"]).as_deref(), Some("-p=x"));
    // Kok bolgesindeki BASKA bayraklarin arkasindan da gorulur.
    assert_eq!(
        tok(&["-v", "-p", "x", "dr", "restore"]).as_deref(),
        Some("-p")
    );
    assert_eq!(
        tok(&["--verbose", "-p", "x", "dr", "restore"]).as_deref(),
        Some("-p")
    );
}

#[test]
fn a_value_that_merely_looks_like_the_flag_is_not_the_flag() {
    // `-c` DEGERINI YUTAR: `-p` burada bir DEGER, bir bayrak degil.
    assert_eq!(tok(&["-c", "-p", "secrets", "list"]), None);
    assert_eq!(tok(&["--config", "-p", "secrets", "list"]), None);
    assert_eq!(tok(&["--project", "-px", "secrets", "list"]), None);
    // ...ama `--config=x` bir sonraki jetonu YUTMAZ.
    assert_eq!(
        tok(&["--config=x", "-p", "secrets", "list"]).as_deref(),
        Some("-p")
    );
}

#[test]
fn the_scan_stops_where_the_root_flag_region_stops() {
    // Alt komuttan SONRAKI `-p` bu taramanin isi DEGIL: kok bolgesi orada
    // bitiyor. (Alt komut sonrasi kok bayraklari bu depoda OLCULMEMIS bir
    // eksen ve iki ikili orada zaten ayrisiyor — bkz. `secrets list -p x`.)
    assert_eq!(tok(&["token", "exchange", "-p", "x"]), None);
    assert_eq!(tok(&["dr", "restore", "-p", "x"]), None);
    // `--` de bolgeyi bitirir.
    assert_eq!(tok(&["--", "-p", "x"]), None);
    // Bos argv bir sey bulamaz.
    assert_eq!(tok(&[]), None);
}

#[test]
fn short_clusters_are_deliberately_out_of_scope() {
    // `-vp` pflag'de `-v` + `-p<kalan>` demek, ama kume semantigi bu depoda
    // HIC olculmedi ve iki ikili orada GOLGESIZ yapraklarda da ayrisiyor.
    // Bu satir bir eksigi degil bir SINIRI pinliyor: kapsam degistiginde
    // burasi da degismeli, sessizce degil.
    assert_eq!(tok(&["-vp", "x", "dr", "restore"]), None);
}
