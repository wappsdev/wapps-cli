// GUVEN DEPOSU KAPISI — plan §9.5'in sahibine biraktigi karari OLCULEBILIR
// yapan test.
//
// NEDEN VAR: Adim 6'nin 32 differential vakasinin TAMAMI `http://` uzerinden
// kosuyor. Sertifika dogrulamasi bugun hicbir kapi tarafindan sinanmiyor, yani
// Go ile Rust arasindaki bir guven-deposu ayrismasi yesil bir agacta GORUNMEZ.
// Olculdu: Rust ikilisi gomulu Mozilla koklerini tasiyor
// (webpki-roots <- ureq'in varsayilan `tls` ozelligi, kimse secmedi), Go tarafi
// ise uretimde RootCAs'i HIC set etmiyor (auth.go) — yani platform deposunu
// kullaniyor.
//
// BU TEST BIR DOGRULUK IDDIA ETMIYOR. Hangi tarafin "dogru" oldugu sahibinin
// karari; test yalnizca BUGUNKU hali pinliyor. Karar verildigi gun bu test
// KIRILIR, ve kirilmasi kararin gerceklestiginin kanitidir. Ozellikle
// `rs_refuses_ca_from_env`: platform/native koklere gecilirse Rust tarafi
// SSL_CERT_FILE'i onurlandirmaya baslar ve buradaki bekleyis duser.
//
// Gate SAHTE, TLS'li ve YEREL. CA + sunucu sertifikasi kosum aninda uretiliyor,
// gecici dizine yaziliyor, kosum sonunda siliniyor. Agaca hicbir sertifika,
// anahtar ya da gercek alan adi yazilmiyor.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("depo koku bulunamadi")
        .to_path_buf()
}

// scratch, depo AGACININ DISINDA calisma dizini verir; scratch bir git
// worktree'sinin icine duserse bu deponun binding testleri dokunulmamis bir
// agacta bile kiriliyor.
fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-tls-trust-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    assert!(
        !d.starts_with(repo_root()),
        "scratch dizini depo agacinin ICINDE ({}); binding testleri kirilir",
        d.display()
    );
    d
}

fn run(cmd: &mut Command, what: &str) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("{what} calistirilamadi: {e}"));
    assert!(
        out.status.success(),
        "{what} basarisiz (exit {:?})\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Side, tek bir ikilinin tek bir senaryodaki ham sonucudur.
struct Side {
    stdout: String,
    stderr: String,
    exit: i64,
}

fn side(v: &serde_json::Value, scenario: &str, which: &str) -> Side {
    let o = v
        .get(scenario)
        .and_then(|s| s.get(which))
        .unwrap_or_else(|| panic!("senaryo {scenario}/{which} raporda yok:\n{v}"));
    Side {
        stdout: o["stdout"].as_str().unwrap_or_default().to_string(),
        stderr: o["stderr"].as_str().unwrap_or_default().to_string(),
        exit: o["exit"].as_i64().unwrap_or(-1),
    }
}

// REFUSAL_CODE / REFUSAL_TAIL: reddin sozlesmeye ait yarisi. Ayrisan tek sey
// isletim sistemi seviyesindeki ayrinti (Go net/http'nin dizesini, ureq kendi
// dizesini gomuyor) — pty differential'inda `human_gate_down` ile AYNI aile.
const REFUSAL_CODE: &str = "NETWORK_REQUIRED: secrets gate unreachable: ";
const REFUSAL_RECOVERY: &str =
    "reconnect and retry; the store has no offline mode (values are server-decrypted)";

fn assert_refused(s: &Side, who: &str, scenario: &str) {
    assert_eq!(s.exit, 1, "{who}/{scenario}: cikis kodu 1 bekleniyordu\n{}", s.stderr);
    assert!(s.stdout.is_empty(), "{who}/{scenario}: stdout bos degil: {:?}", s.stdout);
    assert!(
        s.stderr.contains(REFUSAL_CODE),
        "{who}/{scenario}: red zarfi beklenen kodu tasimiyor:\n{}",
        s.stderr
    );
    assert!(
        s.stderr.contains(REFUSAL_RECOVERY),
        "{who}/{scenario}: red zarfi kurtarma satirini tasimiyor:\n{}",
        s.stderr
    );
}

#[test]
fn trust_store_divergence_is_pinned() {
    let root = repo_root();
    let work = scratch();
    let pty_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty");

    let go_bin = work.join("wapps-go");
    run(
        Command::new("go").arg("build").arg("-o").arg(&go_bin).arg("./main.go").current_dir(&root),
        "go build (oracle)",
    );

    let out_json = work.join("tls-report.json");
    let stdout = run(
        Command::new("python3")
            .arg(pty_dir.join("tlsprobe.py"))
            .arg(&go_bin)
            .arg(Path::new(env!("CARGO_BIN_EXE_wapps")))
            .arg(&work)
            .arg(&out_json),
        "tls probe",
    );
    println!("{stdout}");
    let raw = std::fs::read_to_string(&out_json).expect("tls raporu okunamadi");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("tls raporu JSON degil");

    // --- (b) CA HICBIR YERDE: ikisi de reddetmeli ---
    let go_b = side(&v, "ca_nowhere", "go");
    let rs_b = side(&v, "ca_nowhere", "rs");
    assert_refused(&go_b, "go", "ca_nowhere");
    assert_refused(&rs_b, "rs", "ca_nowhere");
    assert_eq!(go_b.exit, rs_b.exit, "ca_nowhere: cikis kodlari ayrisiyor");
    // Reddin GOVDESI ayrisiyor ve bu BILINEN bir ayrisma; "esit" diye
    // pinlemek sahte bir sadakat olurdu. Ayrismanin varligi pinleniyor ki
    // birisi ikisini esitlerse ya da ayrismayi buyutursa gorunsun.
    assert_ne!(
        go_b.stderr, rs_b.stderr,
        "ca_nowhere: red govdeleri artik AYNI — pin eskimis, yorumu guncelle"
    );

    // --- (a) CA yalnizca surece-yerel bir kanalda ---
    // Rust: HER platformda reddeder, cunku kokler ikiliye GOMULU ve hicbir
    // env degiskeni onlara ekleme yapamaz. Bu satir kararin tetigi.
    for sc in ["ca_in_ssl_cert_file", "ca_in_ssl_cert_dir"] {
        let rs = side(&v, sc, "rs");
        assert_refused(&rs, "rs", sc);
    }

    // Go: platform deposuna baglidir, yani beklenti PLATFORMA gore degisir.
    //   darwin  -> crypto/x509 SSL_CERT_FILE'i HIC okumaz (root_unix.go'nun
    //              build etiketi darwin'i disliyor); reddeder.
    //   diger unix -> okur; KABUL eder. §9.5'in anlattigi CI runner burasi.
    let go_file = side(&v, "ca_in_ssl_cert_file", "go");
    if cfg!(target_os = "macos") {
        assert_refused(&go_file, "go", "ca_in_ssl_cert_file");
    } else {
        assert_eq!(
            go_file.exit, 0,
            "go/ca_in_ssl_cert_file: bu platformda KABUL bekleniyordu\n{}",
            go_file.stderr
        );
    }

    // --- (c) gercek, herkesin guvendigi zincir ---
    // AG gerektirdigi icin varsayilan olarak kosmuyor. Sessizce atlanmiyor:
    // atlandigi rapora yaziliyor ve burada basiliyor.
    if v["_meta"]["public_chain_ran"].as_bool().unwrap_or(false) {
        let go_c = side(&v, "public_chain", "go");
        let rs_c = side(&v, "public_chain", "rs");
        assert_eq!(
            go_c.stderr, rs_c.stderr,
            "public_chain: gecerli bir zincirde iki taraf ayrisiyor"
        );
        assert_eq!(go_c.exit, rs_c.exit, "public_chain: cikis kodlari ayrisiyor");
    } else {
        println!(
            "public_chain ATLANDI (ag gerekiyor) — WAPPS_TLS_PUBLIC_CHAIN=1 ile acilir"
        );
    }

    let _ = std::fs::remove_dir_all(&work);
}
