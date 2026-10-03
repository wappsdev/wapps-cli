// `secrets status` — HER modda ve her ag durumunda GUVENLI olmasi gereken tek
// fiil. Sozlesmesi "dogru cevap ver" degil, "ASLA hard-fail etme": bir ajan
// baska her sey hata verdiginde ILK bunu kosuyor. Bu yuzden buradaki testlerin
// cogu "bozuk girdi verildiginde ne olur"u olcuyor.
//
// status ayrica baglama kapisindan MUAF (agentgate.go bindingExempt) ve ajan
// modunda SERBEST — ikisi de tests/verbpolicy.rs'te ayrica pinli.
use wapps::statusverb::{self, StatusReport};

#[test]
fn the_text_form_matches_the_go_field_layout() {
    let rep = StatusReport {
        online: true,
        session_valid: true,
        session_expires_in: 0,
        epoch_pin: 0,
    };
    assert_eq!(
        statusverb::render_text(&rep),
        "online:           true\n\
         session_valid:    true\n\
         session_expires:  0s\n\
         epoch_pin:        0\n"
    );
}

#[test]
fn the_text_form_carries_seconds_and_the_pin() {
    let rep = StatusReport {
        online: false,
        session_valid: false,
        session_expires_in: 3600,
        epoch_pin: 42,
    };
    assert_eq!(
        statusverb::render_text(&rep),
        "online:           false\n\
         session_valid:    false\n\
         session_expires:  3600s\n\
         epoch_pin:        42\n"
    );
}

// JSON semasi MAKINE okunur: alan adlari ve SIRASI Go struct'iyla ayni, ve
// HTML kacisi KAPALI (json.Encoder.SetEscapeHTML(false)).
#[test]
fn the_json_form_is_a_single_line_with_the_go_field_order() {
    let rep = StatusReport {
        online: true,
        session_valid: true,
        session_expires_in: 0,
        epoch_pin: 5,
    };
    assert_eq!(
        statusverb::render_json(&rep),
        "{\"online\":true,\"session_valid\":true,\"session_expires_in\":0,\"epoch_pin\":5}\n"
    );
}

// --- epoch pin okumasi: HER bozuk girdi 0'a duser, hicbiri hata DEGIL -------

#[test]
fn the_pin_is_read_for_the_named_project() {
    let dir = tempdir("status-pin");
    let p = dir.join("epochs.json");
    std::fs::write(
        &p,
        r#"{"schema":"wapps-epoch-pins/v1","pins":{"testproj":5,"other":9}}"#,
    )
    .unwrap();
    assert_eq!(statusverb::read_epoch_pin(&p, "testproj"), 5);
    assert_eq!(statusverb::read_epoch_pin(&p, "other"), 9);
    // Kayitli olmayan proje → 0, hata DEGIL.
    assert_eq!(statusverb::read_epoch_pin(&p, "nosuch"), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_project_name_reads_as_zero_without_touching_disk() {
    assert_eq!(
        statusverb::read_epoch_pin(std::path::Path::new("/nonexistent"), ""),
        0
    );
}

#[test]
fn a_missing_or_corrupt_pin_file_reads_as_zero() {
    let dir = tempdir("status-pin-bad");
    assert_eq!(
        statusverb::read_epoch_pin(&dir.join("nope.json"), "testproj"),
        0
    );
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{not json at all").unwrap();
    assert_eq!(statusverb::read_epoch_pin(&bad, "testproj"), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

// AYRISMA PINI — bu bir kopya-yapistir hatasi DEGIL, olculmus bir fark:
// store::read yolundaki pin okuyucusu `deny_unknown_fields` kullaniyor
// (Go: DisallowUnknownFields) ve tanimadigi bir alanda HATA veriyor. status'un
// okuyucusu Go'da ayri bir anonim struct ve o kisitlama YOK. Yani ayni bozuk
// dosya `exec`i dusurur ama `status`u dusurmez — status'un hicbir kosulda
// hard-fail etmemesi tam olarak bu demek.
#[test]
fn status_tolerates_pin_fields_that_the_read_path_would_reject() {
    let dir = tempdir("status-pin-extra");
    let p = dir.join("epochs.json");
    std::fs::write(
        &p,
        r#"{"schema":"wapps-epoch-pins/v1","pins":{"testproj":7},"future":1}"#,
    )
    .unwrap();
    assert_eq!(
        statusverb::read_epoch_pin(&p, "testproj"),
        7,
        "status bilinmeyen alanlari TOLERE etmeli"
    );
    // Ayni dosya okuma yolunda REDDEDILIR — ayrismanin gercekten var oldugunun kaniti.
    assert!(
        wapps::epochpin::check_and_advance(&p, "testproj", 7, false).is_err(),
        "okuma yolu bilinmeyen alani REDDETMELI (ayrisma gercek olmali)"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --- oturum okumasi --------------------------------------------------------

// Out-of-band env jetonu expiry'siz de GECERLI (kalan 0 raporlanir).
#[test]
fn an_out_of_band_env_token_is_valid_with_zero_remaining() {
    let (valid, rem) = statusverb::read_session_from(
        &|k| match k {
            "WAPPS_SESSION_TOKEN" => Some("tok-not-a-secret".to_string()),
            _ => None,
        },
        std::path::Path::new("/nonexistent/session.json"),
        1_000_000,
    );
    assert!(valid);
    assert_eq!(rem, 0);
}

#[test]
fn an_expired_env_token_reads_as_invalid() {
    let env = |k: &str| match k {
        "WAPPS_SESSION_TOKEN" => Some("tok-not-a-secret".to_string()),
        "WAPPS_SESSION_EXPIRES" => Some("500".to_string()),
        _ => None,
    };
    let (valid, rem) =
        statusverb::read_session_from(&env, std::path::Path::new("/nonexistent"), 1000);
    assert!(!valid, "dolmus oturum GECERSIZ okunmali");
    assert_eq!(rem, 0);
}

#[test]
fn a_live_env_token_reports_the_remaining_seconds() {
    let env = |k: &str| match k {
        "WAPPS_SESSION_TOKEN" => Some("tok-not-a-secret".to_string()),
        "WAPPS_SESSION_EXPIRES" => Some("1600".to_string()),
        _ => None,
    };
    let (valid, rem) =
        statusverb::read_session_from(&env, std::path::Path::new("/nonexistent"), 1000);
    assert!(valid);
    assert_eq!(rem, 600);
}

#[test]
fn a_session_file_is_used_when_no_env_token_is_set() {
    let dir = tempdir("status-session");
    let p = dir.join("gw.json");
    std::fs::write(&p, r#"{"token":"file-tok-not-a-secret","expires_at":1600}"#).unwrap();
    let (valid, rem) = statusverb::read_session_from(&|_| None, &p, 1000);
    assert!(valid);
    assert_eq!(rem, 600);
    let _ = std::fs::remove_dir_all(&dir);
}

// Jetonu BOS bir oturum dosyasi oturum SAYILMAZ (Go: s.Token == "" → ok=false).
#[test]
fn a_tokenless_session_file_is_not_a_session() {
    let dir = tempdir("status-session-empty");
    let p = dir.join("gw.json");
    std::fs::write(&p, r#"{"token":"","expires_at":1600}"#).unwrap();
    let (valid, _) = statusverb::read_session_from(&|_| None, &p, 1000);
    assert!(!valid);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_session_anywhere_reads_as_invalid() {
    let (valid, rem) =
        statusverb::read_session_from(&|_| None, std::path::Path::new("/nonexistent"), 1000);
    assert!(!valid);
    assert_eq!(rem, 0);
}

// Gate host'u oturum dosyasinin ADIDIR; yol ayirici karakterler temizlenir.
#[test]
fn the_gate_host_becomes_a_safe_file_name() {
    assert_eq!(statusverb::host_file("gw.meapps.dev"), "gw.meapps.dev.json");
    assert_eq!(
        statusverb::host_file("127.0.0.1:8080"),
        "127.0.0.1_8080.json"
    );
    assert_eq!(statusverb::host_file("a/b"), "a_b.json");
}

#[test]
fn the_gate_host_is_the_host_part_of_the_gate_url() {
    assert_eq!(
        statusverb::host_of("http://127.0.0.1:8080"),
        "127.0.0.1:8080"
    );
    assert_eq!(
        statusverb::host_of("https://gw.meapps.dev"),
        "gw.meapps.dev"
    );
    // Ayristirilamayan bir deger varsayilana duser — status hard-fail ETMEZ.
    assert_eq!(statusverb::host_of("::::"), "gw.meapps.dev");
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}
