// `apply`in yazicisi + `exec`in env kurucusu.
//
// ORACLE: cmd/secrets/env.go (writeTofuOutputsAsEnv, envName),
// cmd/secrets/exec.go (execEnvAndValues, valueToShellString) ve
// cmd/secrets/apply.go (applyTargets).
//
// `apply`in KISMI-BASARI garantisi burada pinleniyor ve dikkatle okunmali:
// hedef BASINA atomik (temp+fsync+rename, 0600) ve idempotent (bayt-es dosyaya
// DOKUNULMAZ, mtime korunur), ama hedefler ARASINDA atomik DEGIL — i'de
// patlarsa 0..i-1 yazilmis KALIR. Bu bir kusur degil bildirilen sozlesme;
// "duzeltmek" (hepsini geri almak) sahadaki ikiliyle ayrisirdi.
use std::io::Write;
use wapps::{applyverb, envwrite, execverb, wappsyaml};

fn env_str(json: &str, prefix: &str) -> String {
    let mut buf: Vec<u8> = Vec::new();
    envwrite::write_tofu_outputs_as_env(json.as_bytes(), prefix, &mut buf).expect("yazilamadi");
    String::from_utf8(buf).unwrap()
}

// --- envName: onek IDEMPOTENT ----------------------------------------------

#[test]
fn prefix_is_applied_once_never_twice() {
    // Karisik bir anahtar kumesi dogru kalsin diye: Tofu ciktilari CIPLAK
    // saklaniyor (coolify_uuid → TF_VAR_coolify_uuid) ama dosya kaynakli
    // sirlar ZATEN onekli geliyor (TF_VAR_gemini_api_key) ve
    // TF_VAR_TF_VAR_gemini_api_key olmamalilar.
    assert_eq!(
        envwrite::env_name("TF_VAR_", "coolify_uuid"),
        "TF_VAR_coolify_uuid"
    );
    assert_eq!(
        envwrite::env_name("TF_VAR_", "TF_VAR_gemini_api_key"),
        "TF_VAR_gemini_api_key"
    );
    assert_eq!(envwrite::env_name("", "ANY_KEY"), "ANY_KEY");
}

// --- env dosyasi bicimi -----------------------------------------------------

#[test]
fn keys_are_emitted_in_sorted_order() {
    // Siralama determinizm icin: testler ve git diff'i kararli kalsin.
    let out = env_str(
        r#"{"B":{"value":"2"},"A":{"value":"1"},"C":{"value":"3"}}"#,
        "",
    );
    assert_eq!(out, "export A='1'\nexport B='2'\nexport C='3'\n");
}

#[test]
fn single_quotes_in_a_value_are_shell_escaped() {
    // '\'' — tek tirnakli bir kabuk dizesinden cikip tirnak koyup geri girmek.
    // Bu kacis olmadan uretilen dosya `source` edilince KABUGU bozar.
    let out = env_str(r#"{"K":{"value":"it's"}}"#, "");
    assert_eq!(out, "export K='it'\\''s'\n");
}

#[test]
fn json_null_is_emitted_literally_so_the_signal_is_not_lost() {
    // Aksi halde unmarshal hedefi sessizce sifirlar ve "null idi" bilgisi
    // kaybolurdu.
    assert_eq!(env_str(r#"{"K":{"value":null}}"#, ""), "export K='null'\n");
}

#[test]
fn non_string_values_are_emitted_as_compact_json() {
    // Tofu TF_VAR_<ad>'i JSON olarak YENIDEN ayristiriyor, yani liste/harita/
    // bool/sayi kayipsiz gidip geliyor. Bosluklar SIKISTIRILIYOR ki yeniden
    // ayristirmada bosluk artifaktlari kalmasin.
    assert_eq!(
        env_str(r#"{"K":{"value":[1, 2, 3]}}"#, ""),
        "export K='[1,2,3]'\n"
    );
    assert_eq!(env_str(r#"{"K":{"value":true}}"#, ""), "export K='true'\n");
    assert_eq!(
        env_str(r#"{"K":{"value":{"a": 1}}}"#, ""),
        "export K='{\"a\":1}'\n"
    );
    assert_eq!(env_str(r#"{"K":{"value":42}}"#, ""), "export K='42'\n");
}

#[test]
fn malformed_archive_json_is_refused() {
    let mut buf: Vec<u8> = Vec::new();
    let e = envwrite::write_tofu_outputs_as_env(b"not json", "", &mut buf).unwrap_err();
    assert!(e.starts_with("env: parse values: "), "olculen: {e}");
}

// --- exec'in env kurucusu ---------------------------------------------------

#[test]
fn exec_env_entries_are_sorted_and_unquoted() {
    // exec, cocugun env'ine KEY=VALUE koyuyor — bir kabuk satiri DEGIL, yani
    // tirnak/kacis YOK. Bu, env dosyasi yazicisindan bilincli olarak farkli.
    let (env, _) =
        execverb::exec_env_and_values(br#"{"B":{"value":"2"},"A":{"value":"it's"}}"#, "").unwrap();
    assert_eq!(env, vec!["A=it's".to_string(), "B=2".to_string()]);
}

#[test]
fn exec_non_string_values_keep_their_original_spacing() {
    // OLCULEN AYRISMA — ve KORUNMASI gereken: env DOSYASI yazicisi JSON'u
    // SIKISTIRIYOR (json.Compact), exec'in env kurucusu yalnizca TrimSpace
    // yapiyor. Yani ayni girdi iki yolda farkli bayt uretir. "Tutarli" hale
    // getirmek sahadaki ikiliyle ayrisirdi.
    let (env, _) = execverb::exec_env_and_values(br#"{"K":{"value":[1, 2]}}"#, "").unwrap();
    assert_eq!(env, vec!["K=[1, 2]".to_string()]);
    assert_eq!(
        env_str(r#"{"K":{"value":[1, 2]}}"#, ""),
        "export K='[1,2]'\n"
    );
}

#[test]
fn exec_null_becomes_the_literal_string_null() {
    let (env, _) = execverb::exec_env_and_values(br#"{"K":{"value":null}}"#, "").unwrap();
    assert_eq!(env, vec!["K=null".to_string()]);
}

#[test]
fn every_non_empty_value_is_a_scrubber_candidate() {
    // Floor/entropi suzgeci DAHA SONRA (filter_scrubbable) uygulaniyor; burada
    // yalnizca BOS olanlar eleniyor. Suzgeci one almak, floor-alti bir degerin
    // "atlandi" uyarisini da yok ederdi.
    let (_, vals) =
        execverb::exec_env_and_values(br#"{"A":{"value":"aaa"},"B":{"value":""}}"#, "").unwrap();
    assert_eq!(vals, vec!["aaa".to_string()]);
}

// --- applyTargets -----------------------------------------------------------

fn cfg_with(targets: &str) -> wappsyaml::WappsYaml {
    wappsyaml::parse(format!("version: 2\nproject: p\ntargets:\n{targets}").as_bytes()).unwrap()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-apply-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn apply_writes_each_target_at_0600_and_reports_it() {
    let d = scratch("write");
    let cfg = cfg_with("  - path: .env.local\n");
    let mut out: Vec<u8> = Vec::new();
    applyverb::apply_targets(
        &cfg,
        br#"{"K":{"value":"v"}}"#,
        &d.to_string_lossy(),
        &mut out,
    )
    .unwrap();

    let f = d.join(".env.local");
    assert_eq!(std::fs::read_to_string(&f).unwrap(), "export K='v'\n");
    // Satir, target'in HAM (depo-goreli) yolunu tasir — okunabilirlik icin.
    assert_eq!(String::from_utf8(out).unwrap(), "wrote .env.local\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600: bu dosya DUZ METIN sir tasiyor.
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn a_byte_identical_target_is_left_alone_with_its_mtime_intact() {
    // IDEMPOTENS bir suslemeden ibaret degil: gereksiz bir mtime guncellemesi
    // dosya izleyicilerini (Next.js dev server, Vite HMR, fs.watch) tetikler.
    let d = scratch("idem");
    let cfg = cfg_with("  - path: .env.local\n");
    let f = d.join(".env.local");
    std::fs::write(&f, "export K='v'\n").unwrap();
    let before = std::fs::metadata(&f).unwrap().modified().unwrap();

    let mut out: Vec<u8> = Vec::new();
    applyverb::apply_targets(
        &cfg,
        br#"{"K":{"value":"v"}}"#,
        &d.to_string_lossy(),
        &mut out,
    )
    .unwrap();

    assert_eq!(String::from_utf8(out).unwrap(), "unchanged .env.local\n");
    assert_eq!(
        std::fs::metadata(&f).unwrap().modified().unwrap(),
        before,
        "bayt-es dosyanin mtime'i DEGISMEMELI"
    );
}

#[test]
fn each_target_gets_its_own_effective_prefix() {
    let d = scratch("prefix");
    let cfg = wappsyaml::parse(
        b"version: 2\nproject: p\ndefault_prefix: \"TF_VAR_\"\ntargets:\n  - path: tf.env\n  - path: plain.env\n    prefix: \"\"\n",
    )
    .unwrap();
    let mut out: Vec<u8> = Vec::new();
    applyverb::apply_targets(
        &cfg,
        br#"{"k":{"value":"v"}}"#,
        &d.to_string_lossy(),
        &mut out,
    )
    .unwrap();
    assert_eq!(
        std::fs::read_to_string(d.join("tf.env")).unwrap(),
        "export TF_VAR_k='v'\n"
    );
    assert_eq!(
        std::fs::read_to_string(d.join("plain.env")).unwrap(),
        "export k='v'\n"
    );
}

#[test]
fn targets_resolve_against_the_config_root_not_the_cwd() {
    // --project ile baska bir dizinden kosulan bir apply, <proje>/.env.local
    // yazmali. Aksi halde duz metin sir dosyalari operatorun o an bulundugu
    // dizine sacilirdi.
    let d = scratch("root");
    let sub = d.join("proj");
    std::fs::create_dir_all(&sub).unwrap();
    let cfg = cfg_with("  - path: .env.local\n");
    let mut out: Vec<u8> = Vec::new();
    applyverb::apply_targets(
        &cfg,
        br#"{"K":{"value":"v"}}"#,
        &sub.to_string_lossy(),
        &mut out,
    )
    .unwrap();
    assert!(sub.join(".env.local").exists(), "config kokune yazilmali");
    assert!(!d.join(".env.local").exists(), "cwd'ye YAZILMAMALI");
}

#[test]
fn a_failing_target_leaves_the_earlier_ones_written() {
    // KISMI-BASARI SOZLESMESI. targets[1] yazilamaz bir dizine bakiyor;
    // targets[0] yazilmis KALMALI. Bu bildirilen davranis, ve hata metni
    // operatorun tek ipucu: hangi indeks, hangi yol.
    let d = scratch("partial");
    let blocked = d.join("blocked");
    std::fs::create_dir_all(&blocked).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let cfg = cfg_with("  - path: first.env\n  - path: blocked/second.env\n");
    let mut out: Vec<u8> = Vec::new();
    let e = applyverb::apply_targets(
        &cfg,
        br#"{"K":{"value":"v"}}"#,
        &d.to_string_lossy(),
        &mut out,
    )
    .expect_err("yazilamayan hedef hata vermeli");

    assert!(d.join("first.env").exists(), "0..i-1 YAZILMIS kalmali");
    assert!(
        e.starts_with("apply: targets[1] blocked/second.env: write: "),
        "hata indeksi ve yolu adlandirmali; olculen: {e}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}

// --- store yazimi SONRASI sarma ---------------------------------------------

#[test]
fn the_post_write_hook_names_the_store_write_as_already_committed() {
    // Bu sarma metni operatorun TEK ipucu: sir YAZILDI, eksik olan yalnizca
    // yerel dosyalarin uretilmesi. Metin aynen tasiniyor.
    let d = scratch("hook");
    let blocked = d.join("nope");
    let cfg = cfg_with("  - path: nope/x.env\n");
    let mut out: Vec<u8> = Vec::new();
    let e = applyverb::apply_targets_after_write(
        &cfg,
        br#"{"K":{"value":"v"}}"#,
        &d.to_string_lossy(),
        &mut out,
    )
    .expect_err("hata bekleniyordu");
    assert!(
        e.starts_with("the store write succeeded but writing local targets failed: ")
            && e.ends_with(" (run 'wapps secrets apply' to retry)"),
        "olculen: {e}"
    );
    let _ = blocked;
}

#[test]
fn the_post_write_hook_is_a_no_op_without_targets() {
    let cfg = wappsyaml::parse(b"version: 2\nproject: p\n").unwrap();
    let mut out: Vec<u8> = Vec::new();
    applyverb::apply_targets_after_write(&cfg, br#"{"K":{"value":"v"}}"#, "", &mut out).unwrap();
    assert!(out.is_empty());
}

#[test]
fn writer_errors_propagate() {
    // Bir yazicinin hatasini yutmak, "wrote" satirini basip aslinda hicbir sey
    // yazmamis olmak demek olurdu.
    struct Fail;
    impl Write for Fail {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("nope"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut f = Fail;
    assert!(envwrite::write_tofu_outputs_as_env(br#"{"K":{"value":"v"}}"#, "", &mut f).is_err());
}
