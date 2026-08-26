// Epoch pin'i bir DAVRANIS degil bir REDDETME: sunulan epoch yerel pin'in
// ALTINDAYSA cagri EPOCH_DOWNGRADE ile duser (rollback saldirisi). Buradaki
// beklenen bayt dizileri Go ikilisinden sahte gate ile OLCULDU, tahmin edilmedi.
use wapps::clierr::Code;
use wapps::epochpin;

// GO'DAN OLCULEN pin dosyasi bicimi (json.MarshalIndent(p, "", "  "),
// sonda newline YOK).
fn go_pinfile(project: &str, epoch: u64) -> String {
    format!(
        "{{\n  \"schema\": \"wapps-epoch-pins/v1\",\n  \"pins\": {{\n    \"{project}\": {epoch}\n  }}\n}}"
    )
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-epochpin-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

#[test]
fn a_missing_pin_file_pins_the_served_epoch() {
    let dir = scratch("fresh");
    let path = dir.join("wapps/epochs.json");
    epochpin::check_and_advance(&path, "testproj", 7, false).expect("ilk pin kabul edilmeli");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), go_pinfile("testproj", 7));
}

#[test]
fn a_lower_served_epoch_is_refused_as_epoch_downgrade() {
    let dir = scratch("downgrade");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, go_pinfile("testproj", 9)).unwrap();

    let err = epochpin::check_and_advance(&path, "testproj", 7, false)
        .expect_err("daha eski bir epoch KABUL EDILMEMELI");
    assert_eq!(err.code, Code::EpochDowngrade);
    // Go ikilisinden olculen metin.
    assert_eq!(err.message, "served epoch 7 < pinned 9 for \"testproj\"");
    assert_eq!(
        err.recovery,
        "possible rollback attack — do NOT force; if the store was LEGITIMATELY rebuilt, a human must run the paper-verified ceremony: wapps dr accept-epoch-reset --project testproj"
    );
    // Reddedilen bir okuma pin'i GERI ALMAZ.
    assert_eq!(std::fs::read_to_string(&path).unwrap(), go_pinfile("testproj", 9));
}

#[test]
fn a_higher_served_epoch_advances_the_pin() {
    let dir = scratch("advance");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, go_pinfile("testproj", 3)).unwrap();
    epochpin::check_and_advance(&path, "testproj", 7, false).expect("ileri gitmek serbest");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), go_pinfile("testproj", 7));
}

// Go, served == pinned oldugunda dosyaya HIC dokunmuyor. Bunu kanitlamak icin
// dosya, Go'nun YAZMAYACAGI bir bicimde (kompakt) birakiliyor: bir yazim olsaydi
// bicim degisirdi.
#[test]
fn an_equal_epoch_does_not_rewrite_the_file() {
    let dir = scratch("equal");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let compact = "{\"schema\":\"wapps-epoch-pins/v1\",\"pins\":{\"testproj\":7}}";
    std::fs::write(&path, compact).unwrap();
    epochpin::check_and_advance(&path, "testproj", 7, false).expect("esit epoch kabul");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), compact);
}

// TEK mesru non-monotonik gecis: kagit zarftaki audit-head hash'i out-of-band
// dogrulandiktan SONRA seremoni verb'unun kurdugu bayrak. Bu dilimde o verb
// YOK, yani tek cagri yeri false geciyor; mekanizma yine de tasindi ki `dr`
// portlandiginda yeniden kesfedilmesi gerekmesin.
#[test]
fn the_ceremony_flag_lowers_the_pin_instead_of_refusing() {
    let dir = scratch("ceremony");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, go_pinfile("testproj", 9)).unwrap();
    epochpin::check_and_advance(&path, "testproj", 7, true).expect("seremoni indirebilir");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), go_pinfile("testproj", 7));
}

// Pin'ler PER-PROJE: bir projenin ilerlemesi digerinin pin'ini silmez.
#[test]
fn pins_are_per_project_and_written_in_sorted_key_order() {
    let dir = scratch("multi");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        "{\n  \"schema\": \"wapps-epoch-pins/v1\",\n  \"pins\": {\n    \"zeta\": 4,\n    \"alpha\": 1\n  }\n}",
    )
    .unwrap();
    epochpin::check_and_advance(&path, "mid", 7, false).unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "{\n  \"schema\": \"wapps-epoch-pins/v1\",\n  \"pins\": {\n    \"alpha\": 1,\n    \"mid\": 7,\n    \"zeta\": 4\n  }\n}"
    );
}

// Go, DisallowUnknownFields ile cozuyor: tanimadigi bir alan HATA. Bir pin
// dosyasini kurcalayan biri, taninmayan bir alanla sessizce gecemez.
#[test]
fn an_unknown_field_in_the_pin_file_is_refused() {
    let dir = scratch("unknown");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{\"schema\":\"wapps-epoch-pins/v1\",\"pins\":{},\"extra\":1}").unwrap();
    let err = epochpin::check_and_advance(&path, "testproj", 7, false)
        .expect_err("tanimsiz alan FAIL-CLOSED olmali");
    assert_eq!(err.code, Code::Internal);
}

// Bozuk/eksik `pins` alani Go'da nil map → bos map. Fail-open DEGIL: pin 0
// kabul edilir ve sunulan epoch ilerletilir.
#[test]
fn a_null_pins_field_reads_as_an_empty_map() {
    let dir = scratch("nullpins");
    let path = dir.join("wapps/epochs.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "{\"schema\":\"wapps-epoch-pins/v1\",\"pins\":null}").unwrap();
    epochpin::check_and_advance(&path, "testproj", 7, false).unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), go_pinfile("testproj", 7));
}

#[cfg(unix)]
#[test]
fn the_pin_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("perms");
    let path = dir.join("wapps/epochs.json");
    epochpin::check_and_advance(&path, "testproj", 7, false).unwrap();
    let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let parent = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777;
    assert_eq!(file, 0o600, "pin dosyasi 0600 olmali");
    assert_eq!(parent, 0o700, "pin dizini 0700 olmali");
}

// XDG onurlandirilir; yoksa ~/.config/wapps/epochs.json (Go ile ayni sira).
#[test]
fn the_default_path_honours_xdg_then_home() {
    assert_eq!(
        epochpin::default_path_from(Some("/x/cfg".into()), Some("/h".into())).unwrap(),
        std::path::PathBuf::from("/x/cfg/wapps/epochs.json")
    );
    assert_eq!(
        epochpin::default_path_from(None, Some("/h".into())).unwrap(),
        std::path::PathBuf::from("/h/.config/wapps/epochs.json")
    );
    assert!(epochpin::default_path_from(None, None).is_err());
}
