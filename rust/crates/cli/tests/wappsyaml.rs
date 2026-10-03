// .wapps.yaml YUKLEME + DOGRULAMA testi.
//
// ORACLE: Go'nun internal/config/wapps_yaml.go'su. Bu testteki her RET metni
// Go IKILISINDEN olculdu (bkz. differential'in config vakalari), kaynaktan
// TURETILMEDI — cunku operatorun gordugu sey metnin KENDISI.
//
// Neden ayri bir birim testi de var (differential yetmiyor mu): differential
// yalnizca bir verb'un YUZEYINDEN gecen sekilleri gezer. Burada sekil uzayinin
// tamami — surum/backend matrisi, prefix'in "yok" ile "acikca bos" ayrimi,
// hedef cozumleme — dogrudan olculuyor.
use wapps::wappsyaml::{self, WappsYaml};

fn parse_err(src: &str) -> String {
    match wappsyaml::parse(src.as_bytes()) {
        Ok(_) => panic!("ayristirma BASARILI oldu ama ret bekleniyordu:\n{src}"),
        Err(e) => e,
    }
}

fn parse_ok(src: &str) -> WappsYaml {
    wappsyaml::parse(src.as_bytes())
        .unwrap_or_else(|e| panic!("ayristirma reddedildi ama kabul bekleniyordu: {e}\n{src}"))
}

// --- surum / backend matrisi (SPEC §7.12) -----------------------------------

#[test]
fn absent_version_defaults_to_one() {
    // v2 alani TASIMAYAN bir dosya v1'dir. Ama project ZORUNLU oldugu icin
    // project'siz bir v1 yine de reddedilir — surum varsayilani, project
    // zorunlulugunu KALDIRMAZ.
    let e = parse_err("default_prefix: \"\"\n");
    assert_eq!(
        e,
        "config: 'project: <name>' is required — it names the project in the secrets gate"
    );
}

#[test]
fn version_three_is_refused() {
    assert_eq!(
        parse_err("version: 3\nproject: p\n"),
        "config: unsupported version 3 (only 1 and 2 are supported by this CLI)"
    );
}

#[test]
fn v2_fields_require_version_two() {
    // v1 + backend = malformed. Surum bump'i, ESKI bir ikilinin sessiz
    // misparse yerine yuksek sesle hata vermesini saglar.
    assert_eq!(
        parse_err("version: 1\nbackend: store\nproject: p\n"),
        "config: backend/project/profiles require version: 2 (got version 1)"
    );
}

#[test]
fn legacy_git_backend_is_an_explicit_error() {
    // Sessizce store'a DUSMEK, operatorun git'e commit edilen bir arsiv
    // sandigi yerde sunucuya yazmasi olurdu.
    assert_eq!(
        parse_err("version: 2\nbackend: legacy-git\nproject: x\n"),
        "config: backend: legacy-git was removed — the git-committed age archive is gone; \
         drop the 'backend:' and 'dest:' lines and set 'project: <name>' (values live in the gate)"
    );
}

#[test]
fn unknown_backend_is_refused() {
    assert_eq!(
        parse_err("version: 2\nbackend: cloud-magic\nproject: x\n"),
        "config: unknown backend \"cloud-magic\" (the only backend is 'store')"
    );
}

#[test]
fn absent_backend_becomes_store() {
    assert_eq!(parse_ok("version: 2\nproject: p\n").backend, "store");
}

#[test]
fn project_is_required() {
    assert_eq!(
        parse_err("version: 2\nbackend: store\n"),
        "config: 'project: <name>' is required — it names the project in the secrets gate"
    );
}

// --- sources ----------------------------------------------------------------

#[test]
fn unknown_source_type_names_its_index_and_the_bad_type() {
    assert_eq!(
        parse_err("version: 2\nproject: p\nsources:\n  - type: doppler\n"),
        "config: sources[0]: source: unknown type \"doppler\" (allowed: tofu, file)"
    );
}

#[test]
fn source_without_type_is_refused() {
    assert_eq!(
        parse_err("version: 2\nproject: p\nsources:\n  - prefix: X\n"),
        "config: sources[0]: source: missing required field 'type'"
    );
}

#[test]
fn tofu_source_refuses_path() {
    assert_eq!(
        parse_err("version: 2\nproject: p\nsources:\n  - type: tofu\n    path: .env\n"),
        "config: sources[0]: source[tofu]: unexpected field 'path' (use 'workdir')"
    );
}

#[test]
fn file_source_requires_path() {
    assert_eq!(
        parse_err("version: 2\nproject: p\nsources:\n  - type: file\n"),
        "config: sources[0]: source[file]: missing required field 'path'"
    );
}

#[test]
fn sources_are_optional_under_store() {
    assert!(parse_ok("version: 2\nbackend: store\nproject: lab\n")
        .sources
        .is_empty());
}

// --- targets ----------------------------------------------------------------

#[test]
fn target_without_path_is_refused() {
    assert_eq!(
        parse_err("version: 2\nproject: p\ntargets:\n  - prefix: \"TF_VAR_\"\n"),
        "config: targets[0]: missing required field 'path'"
    );
}

#[test]
fn target_path_traversal_is_refused() {
    // Yanlis yapilandirilmis bir yaml repo kokunun DISINA yazamasin.
    assert_eq!(
        parse_err("version: 2\nproject: p\ntargets:\n  - path: ../etc/passwd\n"),
        "config: targets[0]: path \"../etc/passwd\" contains '..' (path traversal not allowed)"
    );
}

#[test]
fn duplicate_target_path_names_both_indices() {
    assert_eq!(
        parse_err("version: 2\nproject: p\ntargets:\n  - path: .env.local\n  - path: .env.local\n"),
        "config: targets[1]: duplicate path \".env.local\" (also at targets[0])"
    );
}

// PREFIX'IN UC DURUMU. Go'da `Prefix *string`: "yok" ile "acikca bos" FARKLI
// seylerdir ve fark gozlemlenebilir — default_prefix='TF_VAR_' iken bir
// target'in '' istemesi gercek bir senaryo (terraform.tfvars icin TF_VAR_,
// .env.local icin duz). Option<String> ile Some("") ayni ayrimi tasir.
#[test]
fn absent_target_prefix_falls_back_to_the_default() {
    let cfg = parse_ok(
        "version: 2\nproject: p\ndefault_prefix: \"TF_VAR_\"\ntargets:\n  - path: .env.local\n",
    );
    assert!(cfg.targets[0].prefix.is_none(), "prefix ABSENT olmali");
    assert_eq!(
        cfg.targets[0].effective_prefix(&cfg.default_prefix),
        "TF_VAR_"
    );
}

#[test]
fn explicitly_empty_target_prefix_beats_a_non_empty_default() {
    let cfg = parse_ok(
        "version: 2\nproject: p\ndefault_prefix: \"TF_VAR_\"\ntargets:\n  - path: .env.local\n    prefix: \"\"\n",
    );
    assert_eq!(cfg.targets[0].prefix.as_deref(), Some(""));
    assert_eq!(cfg.targets[0].effective_prefix(&cfg.default_prefix), "");
}

#[test]
fn explicit_target_prefix_beats_an_empty_default() {
    let cfg = parse_ok(
        "version: 2\nproject: p\ntargets:\n  - path: terraform.tfvars.json\n    prefix: \"TF_VAR_\"\n",
    );
    assert_eq!(
        cfg.targets[0].effective_prefix(&cfg.default_prefix),
        "TF_VAR_"
    );
}

// --- profiller (§7.6) -------------------------------------------------------

#[test]
fn named_profile_returns_its_keys_and_empty_name_means_all() {
    let cfg = parse_ok(
        "version: 2\nbackend: store\nproject: vaulter\nprofiles:\n  deploy: [DATABASE_URL, COOLIFY_TOKEN]\n",
    );
    assert_eq!(
        cfg.profile_keys("deploy"),
        Some(vec![
            "DATABASE_URL".to_string(),
            "COOLIFY_TOKEN".to_string()
        ])
    );
    assert_eq!(cfg.profile_keys("nosuch"), None);
    // Bos ad → "tum granted anahtarlar": Some(bos liste).
    assert_eq!(cfg.profile_keys(""), Some(vec![]));
}

// --- bilinmeyen alanlar -----------------------------------------------------

#[test]
fn unknown_top_level_fields_are_ignored_like_gos_yaml_v3() {
    // Go'nun yaml.v3'u KnownFields ACIK DEGIL, yani tanimadigi alani SESSIZCE
    // atliyor. Rust tarafinda serde'nin varsayilani da ayni. Bunu bir teste
    // baglamak, ileride biri deny_unknown_fields eklerse sahadaki dosyalarin
    // (dest:, redact_in_logs:, require_clean_git:) kirilacagini gosterir.
    let cfg = parse_ok(
        "version: 2\nproject: p\ndest: secrets/all.enc.age\nredact_in_logs: true\nrequire_clean_git: true\n",
    );
    assert_eq!(cfg.project, "p");
}

// --- yol cozumleme ----------------------------------------------------------

#[test]
fn relative_target_paths_resolve_against_the_config_dir() {
    // --project ile baska bir dizinden kosulan bir apply, <proje>/.env.local
    // yazmali — <cwd>/.env.local DEGIL. Duz metin sir dosyalarini operatorun
    // o an bulundugu dizine sacmak, bu satirin engelledigi sey.
    let cfg = parse_ok("version: 2\nproject: p\ntargets:\n  - path: .env.local\n");
    assert_eq!(
        cfg.targets[0].resolve_path("/repo/proj"),
        "/repo/proj/.env.local"
    );
    // Mutlak yol AYNEN gecer.
    let abs = parse_ok("version: 2\nproject: p\ntargets:\n  - path: /tmp/x.env\n");
    assert_eq!(abs.targets[0].resolve_path("/repo/proj"), "/tmp/x.env");
    // configRoot bos (dosyadan yuklenmemis config) → goreli yol AYNEN kalir.
    assert_eq!(cfg.targets[0].resolve_path(""), ".env.local");
}
