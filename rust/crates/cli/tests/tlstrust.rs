// GUVEN DEPOSU KAPISI — plan §9.5'in sahibine biraktigi karar VERILDI, ve bu
// dosya kararin sonucunu kaydediyor.
//
// KARAR (sik C): gomulu `webpki-roots` TABAN olarak kaliyor, ve `SSL_CERT_FILE`
// ile `SSL_CERT_DIR` ayarliysa onlar da bu tabanin USTUNE ekleniyor
// (`crates/cli/src/store.rs`, `root_store`). Sik B (rustls-native-certs) OLCULDU
// ve REDDEDILDI: darwin'de alti crate ekliyor ve `cargo deny`yi dusuruyor
// (`rustls-pemfile` bakimsiz), yani secilmesi bir guvenlik uyarisina kalici
// `ignore` yazmak demekti.
//
// BU TEST HALA BIR DOGRULUK IDDIA ETMIYOR. "Dogru davraniyor" demiyor; "bugun
// boyle davraniyor, degisirse haberin olsun" diyor. Onceki surumunun kurdugu
// ayrim budur ve korunuyor — degisen tek sey PINLENEN davranis.
//
// KARARIN DURUST BILANCOSU — iki yarisi da burada yazili:
//
//   Linux'ta PARITE KAZANILDI. Go'nun crypto/x509'u (root_unix.go) SSL_CERT_FILE
//   ve SSL_CERT_DIR'i okuyor; Rust artik da okuyor. §9.5'in anlattigi "TLS
//   denetleyen proxy arkasindaki CI runner" Linux'ta kosuyor, yani kazanc tam
//   oraya dusuyor.
//
//   macOS'ta PARITE KAZANILMADI — AYRISMA TERS CEVRILDI. root_unix.go'nun build
//   etiketi darwin'i DISLIYOR, yani Go orada bu iki env degiskenini HIC okumuyor.
//   Once Rust katiydi (env'i yok sayiyordu) ve Go gevsekti (Linux'ta env'i
//   okuyordu); simdi darwin'de Rust env'i onurlandiriyor ve Go saymiyor. Ayrisma
//   KAPANMADI, yonu DEGISTI. Bunu olcen satirlar asagida `cfg!(target_os =
//   "macos")` dallarinda ve gerekcesi her birinin yaninda yazili.
//
//   Linux'ta bile parite TAM DEGIL, ve bu da saklanmiyor: Go env degiskenini
//   gorunce sistem demetinin YERINE koyuyor (loadSystemRoots: `files =
//   []string{f}`), Rust ise gomulu tabana EKLIYOR. Yani kabul yuzeyi Rust'ta
//   daha GENIS kaliyor. Bu sik C'nin tanimi, kazara degil.
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
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("{what} calistirilamadi: {e}"));
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

// REFUSAL_CODE / REFUSAL_RECOVERY: reddin sozlesmeye ait yarisi. Ayrisan tek sey
// isletim sistemi seviyesindeki ayrinti (Go net/http'nin dizesini, ureq kendi
// dizesini gomuyor) — pty differential'inda `human_gate_down` ile AYNI aile.
const REFUSAL_CODE: &str = "NETWORK_REQUIRED: secrets gate unreachable: ";
const REFUSAL_RECOVERY: &str =
    "reconnect and retry; the store has no offline mode (values are server-decrypted)";

// RS_REFUSAL_DETAIL, RET ZARFININ kok deposu degisiminden ETKILENMEYEN yarisi.
// Sik C secilmeden once olculdu: ret metni A, B ve C sikkinda BIREBIR ayni;
// degisen tek sey KABUL. Bu sabit o olcumu teste cakiyor — kok deposunu
// degistiren bir sonraki degisiklik reddi de kaydirirsa burada gorunur.
const RS_REFUSAL_DETAIL: &str =
    "Connection Failed: tls connection init failed: invalid peer certificate: UnknownIssuer";

// GATE_VALUE, sahte gate'in dondurdugu TEST dizesi (tlsgate.py). Gercek bir sir
// DEGIL. Kabulu `exit == 0` ile degil BUNUNLA olcuyoruz: cikis kodu el sikismanin
// gectigini soyler ama govdenin cozuldugunu soylemez.
const GATE_VALUE: &str = "value-for-plain";

fn assert_refused(s: &Side, who: &str, scenario: &str) {
    assert_eq!(
        s.exit, 1,
        "{who}/{scenario}: cikis kodu 1 bekleniyordu\n{}",
        s.stderr
    );
    assert!(
        s.stdout.is_empty(),
        "{who}/{scenario}: stdout bos degil: {:?}",
        s.stdout
    );
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

fn assert_accepted(s: &Side, who: &str, scenario: &str) {
    assert_eq!(
        s.exit, 0,
        "{who}/{scenario}: cikis kodu 0 bekleniyordu\nstderr:\n{}",
        s.stderr
    );
    assert!(
        s.stdout.contains(GATE_VALUE),
        "{who}/{scenario}: el sikisma gecti ama govde gelmedi\nstdout:\n{}\nstderr:\n{}",
        s.stdout,
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
        Command::new("go")
            .arg("build")
            .arg("-o")
            .arg(&go_bin)
            .arg("./main.go")
            .current_dir(&root),
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
    // Sik C bu vakayi DEGISTIRMEMELI. Gomulu taban tek basina yeterli olsaydi
    // kapinin kendisi olcmuyor olurdu.
    let go_b = side(&v, "ca_nowhere", "go");
    let rs_b = side(&v, "ca_nowhere", "rs");
    assert_refused(&go_b, "go", "ca_nowhere");
    assert_refused(&rs_b, "rs", "ca_nowhere");
    assert_eq!(go_b.exit, rs_b.exit, "ca_nowhere: cikis kodlari ayrisiyor");
    // RET ZARFI degismedi mi: sik C oncesi olculen metnin AYNISI bekleniyor.
    assert!(
        rs_b.stderr.contains(RS_REFUSAL_DETAIL),
        "ca_nowhere/rs: ret zarfi kok deposu degisimiyle KAYDI — sik C yanlis \
         uygulanmis olabilir:\n{}",
        rs_b.stderr
    );
    // Reddin GOVDESI ayrisiyor ve bu BILINEN bir ayrisma; "esit" diye
    // pinlemek sahte bir sadakat olurdu. Ayrismanin varligi pinleniyor ki
    // birisi ikisini esitlerse ya da ayrismayi buyutursa gorunsun.
    assert_ne!(
        go_b.stderr, rs_b.stderr,
        "ca_nowhere: red govdeleri artik AYNI — pin eskimis, yorumu guncelle"
    );

    // --- (a) CA yalnizca surece-yerel bir kanalda ---
    // Rust: HER platformda KABUL eder. Sik C'nin tetigi tam olarak bu satir;
    // onceki surumde burada `assert_refused` yaziyordu ve kararin verildigi gun
    // kirilmasi bekleniyordu. Kirildi, ve yerine kabul yazildi.
    for sc in ["ca_in_ssl_cert_file", "ca_in_ssl_cert_dir"] {
        let rs = side(&v, sc, "rs");
        assert_accepted(&rs, "rs", sc);
        // Ret zarfi degismedigi gibi kabul de SESSIZ olmali: gate'in ham
        // govdesi transcript'e sizmamali.
        assert!(
            !rs.stdout.contains("epoch"),
            "rs/{sc}: gate'in ham govdesi stdout'a sizdi:\n{}",
            rs.stdout
        );
    }

    // Go: platform deposuna baglidir, yani beklenti PLATFORMA gore degisir ve
    // Go URETIM KODU bu dilimde HIC DEGISMEDI — asagidaki iki dal sik C'den
    // once ne yaziyorsa aynisini yaziyor.
    //   darwin  -> crypto/x509 SSL_CERT_FILE'i HIC okumaz (root_unix.go'nun
    //              build etiketi darwin'i disliyor); reddeder.
    //   diger unix -> okur; KABUL eder. §9.5'in anlattigi CI runner burasi.
    for sc in ["ca_in_ssl_cert_file", "ca_in_ssl_cert_dir"] {
        let go_s = side(&v, sc, "go");
        let rs_s = side(&v, sc, "rs");
        if cfg!(target_os = "macos") {
            assert_refused(&go_s, "go", sc);
            // TERS CEVRILME, tek satirda olculmus hali: darwin'de artik KATI
            // olan taraf Go, GEVSEK olan taraf Rust. Sik C oncesi bu esitlik
            // TUTUYORDU (ikisi de reddediyordu). Kirilmasi kararin sahada
            // gerceklestiginin kanitidir; birisi bu ayrismayi kapatirsa —
            // Rust'i geri katilastirarak ya da Go'ya kok kumesi koyarak —
            // asagidaki satir onu yakalar.
            assert_ne!(
                go_s.exit, rs_s.exit,
                "{sc}: darwin'de iki taraf yine ayni sonucu veriyor — ters \
                 cevrilme kaybolmus, yorumu guncelle"
            );
        } else {
            assert_accepted(&go_s, "go", sc);
            // Linux: iki taraf da KABUL. Cikis kodu duzeyinde parite; kabul
            // YUZEYI hala esit degil (Go yer degistirir, Rust ekler) ve bu
            // ayrisma bu kapiyla olculemez — dosya basligindaki bilancoya
            // yazili.
            assert_eq!(
                go_s.exit, rs_s.exit,
                "{sc}: bu platformda iki taraf da kabul etmeliydi"
            );
        }
    }

    // --- (c) gercek, herkesin guvendigi zincir ---
    // AG gerektirdigi icin varsayilan olarak kosmuyor. Sessizce atlanmiyor:
    // atlandigi rapora yaziliyor ve burada basiliyor. Sik C bu vakayi da
    // DEGISTIRMEMELI: gomulu taban yerinde durdugu icin herkesin guvendigi
    // zincir iki tarafta da kabul olmayi surdurur.
    if v["_meta"]["public_chain_ran"].as_bool().unwrap_or(false) {
        let go_c = side(&v, "public_chain", "go");
        let rs_c = side(&v, "public_chain", "rs");
        assert_eq!(
            go_c.stderr, rs_c.stderr,
            "public_chain: gecerli bir zincirde iki taraf ayrisiyor"
        );
        assert_eq!(
            go_c.exit, rs_c.exit,
            "public_chain: cikis kodlari ayrisiyor"
        );
    } else {
        println!("public_chain ATLANDI (ag gerekiyor) — WAPPS_TLS_PUBLIC_CHAIN=1 ile acilir");
    }

    let _ = std::fs::remove_dir_all(&work);
}
