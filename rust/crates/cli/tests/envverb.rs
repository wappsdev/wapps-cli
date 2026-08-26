// `secrets env --write <dosya>`in YAZICISI.
//
// ORACLE: cmd/secrets/env.go (writeEnvFileAtomic). Bu yazici, `apply`in
// kullandigi atomicfile::write DEGIL, ve farklar SIR TASIYAN bir dosyanin
// diskteki izin penceresini belirledigi icin taklit edilmek zorunda:
//
//   atomicfile::write        writeEnvFileAtomic
//   ----------------------   ------------------------------------------
//   `.{ad}.{pid}.{ns}.tmp`   `{ad}.tmp`  (SABIT, tahmin edilebilir ad)
//   create_new (O_EXCL)      O_CREATE|O_TRUNC  (VAR OLANI yeniden kullanir)
//   mode acikca verilir      0600 ISTENIR ama var olan dosyanin modu KALIR
//   fsync VAR                fsync YOK
//
// Ucuncu satir bir BULGU ve bu dosyada `a_preexisting_temp_file_keeps_its_mode`
// ile PINLI: hedefin yaninda onceden 0644 bir `<hedef>.tmp` duruyorsa, O_CREATE
// o dosyanin modunu DEGISTIRMEZ ve rename sonrasi duz metin sir 0644 ile
// kalir. Bu Go'da BUGUN boyle; port onu ne genisletiyor ne daraltiyor —
// AYNISINI yapiyor, ve differential'da (human_env_write_reuses_a_wide_temp)
// iki ikilinin ayni modu urettigi olculuyor. Daraltmak "duzeltme" gibi
// gorunurdu ama sahadaki ikiliyle ayrisma demek olurdu; bulgu raporlaniyor.
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
    assert_eq!(mode, 0o600, "duz metin sir dosyasi 0600 olmali, {mode:o} degil");
}

#[test]
fn no_temp_file_survives_a_successful_write() {
    let d = tmpdir("notmp");
    let target = d.join("out.env");
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    assert!(!d.join("out.env.tmp").exists(), "gecici dosya rename'den sonra kalmamali");
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
fn a_preexisting_temp_file_keeps_its_mode() {
    // BULGU, taklit: Go O_CREATE|O_TRUNC kullaniyor, O_EXCL DEGIL. Var olan bir
    // `<hedef>.tmp` yeniden kullaniliyor ve modu 0600'e CEKILMIYOR.
    let d = tmpdir("widetmp");
    let target = d.join("out.env");
    let tmp = d.join("out.env.tmp");
    std::fs::write(&tmp, "").unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
    envverb::write_env_file_atomic(&target, ARCHIVE, "").expect("yazim");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o644,
        "Go'nun O_CREATE|O_TRUNC'i var olan modu korur; port AYNISINI yapmali"
    );
}

#[test]
fn a_bad_archive_names_the_parse_error_and_writes_nothing() {
    let d = tmpdir("badjson");
    let target = d.join("out.env");
    let err = envverb::write_env_file_atomic(&target, b"not json", "").unwrap_err();
    assert!(err.starts_with("env: parse values: "), "hata metni: {err}");
    assert!(!target.exists(), "ayristirma hatasinda hedef OLUSMAMALI");
    assert!(!d.join("out.env.tmp").exists(), "ayristirma hatasinda gecici dosya SILINMELI");
}

#[test]
fn an_unopenable_temp_path_names_it_with_the_go_sentence() {
    let d = tmpdir("noopen");
    let target = d.join("nodir").join("out.env");
    let err = envverb::write_env_file_atomic(&target, ARCHIVE, "").unwrap_err();
    assert!(
        err.starts_with(&format!("env: open temp {}.tmp: ", target.display())),
        "hata metni: {err}"
    );
}
