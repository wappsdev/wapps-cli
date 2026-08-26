// Depo→proje BAGLAMA PIN defteri.
//
// ORACLE: internal/binding/binding.go. Pinin ne ise yaradigi (SPEC §7.7, §2
// dikis 4): bir depodaki `.wapps.yaml` bir proje ADI verir, ama o dosya
// SALDIRGAN-YAZILABILIR icerktir. Bu yuzden baglama, depoda DEGIL GUVENILEN
// home-dir'de pinlenir. Uydurulmus bir `.wapps.yaml` kendi basina bir proje
// TALEP EDEMEZ.
//
// Bu dosyadaki BAYT beklentileri Go IKILISINDEN olculdu (pty altinda, baglama
// onayina "y" verilerek), kaynaktan turetilmedi: pin dosyasi iki ikilinin
// PAYLASTIGI bir dosya — ayni kullanicinin makinesinde biri yazip digeri
// okuyor. Bicim ayrisirsa deftere sessizce iki sema girer.
use std::path::PathBuf;
use wapps::binding::{self, Pin};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-binding-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch olusturulamadi");
    d
}

// --- parmak izi -------------------------------------------------------------

#[test]
fn fingerprint_is_the_sha256_hex_of_the_identity() {
    // Go: hex(sha256(repoIdentity)). Bu deger pin defterinin ANAHTARI, yani
    // iki ikilinin ayni girdiyi ayni gozde bulmasi buna bagli.
    assert_eq!(
        binding::fingerprint("x"),
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    );
}

// --- yukleme ----------------------------------------------------------------

#[test]
fn missing_file_loads_as_an_empty_store() {
    // ILK KULLANIM bir hata degil: dosya yoksa bos defter.
    let d = tmpdir("missing");
    let s = binding::load(&d.join("nope.json")).expect("eksik dosya hata olmamali");
    assert_eq!(s.schema, binding::SCHEMA);
    assert!(s.pins.is_empty());
}

#[test]
fn unexpected_schema_is_refused() {
    let d = tmpdir("schema");
    let p = d.join("repo-pins.json");
    std::fs::write(&p, br#"{"schema":"something-else/v9","pins":{}}"#).unwrap();
    let e = binding::load(&p).expect_err("yabanci sema kabul edilmemeli");
    assert!(e.contains("unexpected schema"), "olculen: {e}");
}

#[test]
fn unknown_fields_are_refused() {
    // Go tarafi dec.DisallowUnknownFields() kuruyor. Tanimadigi bir alani
    // SESSIZCE atmak, ileride eklenen bir alanin (ornegin bir kapsam
    // kisitinin) eski bir ikilide gorunmez olmasi demek olurdu.
    let d = tmpdir("unknown");
    let p = d.join("repo-pins.json");
    std::fs::write(&p, br#"{"schema":"wapps-repo-pins/v1","pins":{},"extra":true}"#).unwrap();
    assert!(binding::load(&p).is_err(), "bilinmeyen alan reddedilmeli");
}

// --- kontrol sozlesmesi -----------------------------------------------------

#[test]
fn no_pin_is_unpinned() {
    let s = binding::Store::empty();
    assert_eq!(s.check("fp", "proj"), Err(binding::CheckError::Unpinned));
}

#[test]
fn matching_pin_passes() {
    let mut s = binding::Store::empty();
    s.pin("fp", Pin { repo: "r".into(), project: "proj".into(), backend: "store".into() });
    assert_eq!(s.check("fp", "proj"), Ok(()));
}

#[test]
fn a_pin_naming_a_different_project_is_a_mismatch() {
    // Pinin VAR OLMA SEBEBI bu dal: config PINLI OLANDAN BASKA bir projeyi
    // talep ediyor. Satir ici cozulmez; bir insanin trust-repo kosmasi gerekir.
    let mut s = binding::Store::empty();
    s.pin("fp", Pin { repo: "r".into(), project: "pinned".into(), backend: "store".into() });
    assert_eq!(s.check("fp", "other"), Err(binding::CheckError::Mismatch));
}

// --- kayit BICIMI (Go ile PAYLASILAN dosya) ---------------------------------

#[test]
fn save_writes_gos_exact_bytes_at_0600() {
    let d = tmpdir("save");
    let p = d.join("sub").join("repo-pins.json");
    let mut s = binding::Store::empty();
    s.pin(
        "a9ac52733d008ffa8a60422f3db8c58330aac4a321ebd8fe518455f0ea4b3a6a",
        Pin { repo: "/tmp/d".into(), project: "p".into(), backend: "store".into() },
    );
    s.save(&p).expect("kaydedilemedi");

    // Go: json.MarshalIndent(s, "", "  ") — sonda newline YOK, alan sirasi
    // struct sirasi (repo, project, backend).
    let want = concat!(
        "{\n  \"schema\": \"wapps-repo-pins/v1\",\n  \"pins\": {\n",
        "    \"a9ac52733d008ffa8a60422f3db8c58330aac4a321ebd8fe518455f0ea4b3a6a\": {\n",
        "      \"repo\": \"/tmp/d\",\n      \"project\": \"p\",\n      \"backend\": \"store\"\n",
        "    }\n  }\n}"
    );
    assert_eq!(std::fs::read_to_string(&p).unwrap(), want);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600: defter, hangi deponun hangi projeyi talep edebilecegini
        // soyluyor — baska bir kullanicinin YAZABILMESI pinin anlamini bitirir.
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pin defteri 0600 olmali, olculen {mode:o}");
    }
}

#[test]
fn a_saved_store_round_trips() {
    let d = tmpdir("roundtrip");
    let p = d.join("repo-pins.json");
    let mut s = binding::Store::empty();
    s.pin("fp", Pin { repo: "r".into(), project: "proj".into(), backend: "store".into() });
    s.save(&p).unwrap();
    let back = binding::load(&p).expect("geri okunamadi");
    assert_eq!(back.check("fp", "proj"), Ok(()));
}

#[test]
fn re_pinning_the_same_repo_overwrites() {
    // Acik bir re-pin serbesttir (trust-repo bunu yapiyor).
    let mut s = binding::Store::empty();
    s.pin("fp", Pin { repo: "r".into(), project: "old".into(), backend: "store".into() });
    s.pin("fp", Pin { repo: "r".into(), project: "new".into(), backend: "store".into() });
    assert_eq!(s.check("fp", "new"), Ok(()));
    assert_eq!(s.check("fp", "old"), Err(binding::CheckError::Mismatch));
}

// --- varsayilan yol ---------------------------------------------------------

#[test]
fn default_path_honours_xdg_then_home() {
    assert_eq!(
        binding::default_path_from(Some("/x".into()), Some("/h".into())).unwrap(),
        PathBuf::from("/x/wapps/repo-pins.json")
    );
    assert_eq!(
        binding::default_path_from(None, Some("/h".into())).unwrap(),
        PathBuf::from("/h/.config/wapps/repo-pins.json")
    );
    assert!(binding::default_path_from(None, None).is_err());
}
