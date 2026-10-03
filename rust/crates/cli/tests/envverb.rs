// `secrets env --write <dosya>`in YAZICISI.
//
// ORACLE: cmd/secrets/env.go (writeEnvFileAtomic). Yazici artik `apply`in da
// kullandigi atomicfile::write'a devrediyor — eskiden AYRI bir yaziciydi ve
// farklar SIR TASIYAN bir dosyanin diskteki izin penceresini belirliyordu:
//
//   atomicfile::write        eski writeEnvFileAtomic
//   ----------------------   ------------------------------------------
//   `.{ad}.{pid}.{ns}.tmp`   `{ad}.tmp`  (SABIT, tahmin edilebilir ad)
//   create_new (O_EXCL)      O_CREATE|O_TRUNC  (VAR OLANI yeniden kullanir)
//   mode acikca verilir      0600 ISTENIR ama var olan dosyanin modu KALIR
//   fsync VAR                fsync YOK
//
// Ucuncu satir bir BULGUYDU: hedefin yaninda onceden 0644 bir `<hedef>.tmp`
// duruyorsa open(2) modu YOK SAYIYOR ("the mode argument shall be ignored if
// the file exists") ve rename sonrasi duz metin sir 0644 ile kaliyordu. Kusur
// IKI IKILIDE de canliydi, yani pty differential'in GOREMEDIGI sinifta:
// differential iki tarafin AYNI seyi yaptigini olcer, DOGRU seyi yaptigini
// degil. O yuzden asagidaki
// `a_preexisting_wide_temp_cannot_widen_the_secret` bir KARSILASTIRMA degil
// bir IDDIA'dir — ve karsiligi Go tarafinda
// TestRunEnv_WriteCannotInheritAWideTempMode olarak AYNI commit'te duruyor.
use std::os::unix::fs::PermissionsExt;
use wapps::envverb;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-envverb-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const ARCHIVE: &[u8] = br#"{"BETA":{"value":"b"},"ALPHA":{"value":"a"}}"#;

#[test]
fn it_writes_sorted_export_lines_at_0600() {
    let d = tmpdir("basic");
    let target = d.join("out.env");
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "export ALPHA='a'\nexport BETA='b'\n"
    );
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "duz metin sir dosyasi 0600 olmali, {mode:o} degil"
    );
}

#[test]
fn no_temp_file_survives_a_successful_write() {
    let d = tmpdir("notmp");
    let target = d.join("out.env");
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    assert!(
        !d.join("out.env.tmp").exists(),
        "gecici dosya rename'den sonra kalmamali"
    );
}

#[test]
fn the_prefix_is_applied_to_every_name() {
    let d = tmpdir("prefix");
    let target = d.join("out.env");
    envverb::write_env_file_atomic(&target, ARCHIVE, "TF_VAR_").expect("yazim");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "export TF_VAR_ALPHA='a'\nexport TF_VAR_BETA='b'\n"
    );
}

#[test]
fn an_existing_target_is_replaced_wholesale() {
    let d = tmpdir("replace");
    let target = d.join("out.env");
    std::fs::write(&target, "export STALE='old'\n").unwrap();
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "export ALPHA='a'\nexport BETA='b'\n"
    );
}

#[test]
fn a_preexisting_wide_temp_cannot_widen_the_secret() {
    // EskI BULGU, artik KAPALI: yazici O_EXCL'siz O_CREATE|O_TRUNC kullaniyordu
    // ve open(2) var olan bir dosyada mod argumanini YOK SAYIYOR, yani onceden
    // duran 0644 bir `<hedef>.tmp` duz metin sirri dunya-okunur birakiyordu.
    // Yazici artik atomicfile'a devrediyor: RASTGELE adli, O_EXCL ile acilan,
    // modu ACIKCA kurulan bir gecici dosya. Bayat dosya YENIDEN KULLANILMIYOR.
    //
    // Bu bir IDDIA testidir, bir karsilastirma DEGIL: kusur iki ikilide de
    // canliydi ve differential PAYLASILAN bir kusuru goremez.
    let d = tmpdir("widetmp");
    let target = d.join("out.env");
    let tmp = d.join("out.env.tmp");
    std::fs::write(&tmp, "bayat").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "bayat bir 0644 `.tmp` sirri GENISLETEMEZ");
    // Bayat dosyaya DOKUNULMAMIS olmali: yazici artik onu hic acmiyor.
    assert_eq!(
        std::fs::read_to_string(&tmp).unwrap(),
        "bayat",
        "bayat `.tmp` YENIDEN KULLANILDI"
    );
}

#[test]
fn a_bad_archive_names_the_parse_error_and_writes_nothing() {
    let d = tmpdir("badjson");
    let target = d.join("out.env");
    let err = envverb::write_env_file_atomic(&target, b"not json", "").unwrap_err();
    assert!(err.starts_with("env: parse values: "), "hata metni: {err}");
    assert!(!target.exists(), "ayristirma hatasinda hedef OLUSMAMALI");
    assert_eq!(
        std::fs::read_dir(&d).unwrap().count(),
        0,
        "ayristirma hatasinda diskte HICBIR sey olusmamali"
    );
}

#[test]
fn an_unwritable_target_names_the_target_with_the_go_sentence() {
    // Hata metni HEDEFI adlandirir, gecici dosyayi DEGIL: temp adi rastgele ve
    // ayni hata iki kosuda iki farkli cumle uretirdi. Beklenen cumle Go
    // ikilisinden OLCULDU, tahmin EDILMEDI.
    let d = tmpdir("noopen");
    let target = d.join("nodir").join("out.env");
    let err = envverb::write_env_file_atomic(&target, ARCHIVE, "").unwrap_err();
    assert_eq!(
        err,
        format!("env: write {}: no such file or directory", target.display()),
        "hata metni: {err}"
    );
}
