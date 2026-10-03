// `--project <ad>`i besleyen OPSIYONEL kayit defteri
// (~/.config/wapps/projects.yaml).
//
// ORACLE: internal/projects/projects.go. Defter, --config uzerine ince bir
// KOLAYLIK katmani: --project <dir>/.wapps.yaml'a cozulur, oradan sonrasi ayni
// config-koku yol cozumlemesidir.
//
// Neden bu dilimde: `exec`/`apply` yerel bir `.wapps.yaml` SART kosuyor. Defter
// portlanmazsa, defteri OLAN bir operatorde `--project navlun apply` Go'da
// calisip Rust'ta "no .wapps.yaml found" derdi — sessiz bir ayrisma.
use wapps::projects;

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-projects-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_registered_name_resolves_to_its_directory() {
    let d = tmp("hit");
    let reg = d.join("projects.yaml");
    std::fs::write(&reg, "projects:\n  vaulter: /srv/infra/vaulter\n").unwrap();
    assert_eq!(
        projects::resolve_in(&reg, "vaulter").unwrap(),
        "/srv/infra/vaulter"
    );
}

#[test]
fn an_unregistered_name_is_a_typed_not_found() {
    // Metin sozlesmenin parcasi: operatorun bir sonraki adimi bu satirda.
    let d = tmp("miss");
    let reg = d.join("projects.yaml");
    std::fs::write(&reg, "projects:\n  vaulter: /srv/v\n").unwrap();
    let e = projects::resolve_in(&reg, "nosuch").unwrap_err();
    assert_eq!(
        e,
        "unknown project \"nosuch\" (add to ~/.config/wapps/projects.yaml or use --config)"
    );
}

#[test]
fn a_missing_registry_is_not_found_not_a_read_error() {
    // Defter OPSIYONEL: yoklugu "bilinmeyen proje"dir, bozuk dosya degil.
    let d = tmp("absent");
    let e = projects::resolve_in(&d.join("nope.yaml"), "x").unwrap_err();
    assert!(e.starts_with("unknown project \"x\""), "olculen: {e}");
}

#[test]
fn an_empty_directory_entry_counts_as_unregistered() {
    let d = tmp("empty");
    let reg = d.join("projects.yaml");
    std::fs::write(&reg, "projects:\n  vaulter: \"\"\n").unwrap();
    assert!(projects::resolve_in(&reg, "vaulter")
        .unwrap_err()
        .starts_with("unknown project"));
}

#[test]
fn a_corrupted_registry_surfaces_verbatim_instead_of_unknown_project() {
    // Bozuk bir dosyayi "bilinmeyen proje" diye gostermek, operatoru YANLIS
    // yere bakmaya gonderir.
    let d = tmp("corrupt");
    let reg = d.join("projects.yaml");
    std::fs::write(&reg, "projects: [this, is, not, a, map]\n").unwrap();
    let e = projects::resolve_in(&reg, "x").unwrap_err();
    assert!(e.starts_with("projects: parse "), "olculen: {e}");
}

#[test]
fn a_leading_tilde_expands_so_entries_stay_portable() {
    let d = tmp("tilde");
    let reg = d.join("projects.yaml");
    std::fs::write(&reg, "projects:\n  p: ~/Projects/p\n").unwrap();
    let got = projects::resolve_in(&reg, "p").unwrap();
    assert!(!got.starts_with('~'), "~ genisletilmeli; olculen: {got}");
    assert!(got.ends_with("/Projects/p"), "olculen: {got}");
}

#[test]
fn default_path_honours_xdg_then_home() {
    assert_eq!(
        projects::default_path_from(Some("/x".into()), Some("/h".into())).unwrap(),
        std::path::PathBuf::from("/x/wapps/projects.yaml")
    );
    assert_eq!(
        projects::default_path_from(None, Some("/h".into())).unwrap(),
        std::path::PathBuf::from("/h/.config/wapps/projects.yaml")
    );
}
