// The session cache `wapps login` writes and every store call reads.
//
// ORACLE: internal/session/session.go (State, Load, Save, ParseClaims) and
// internal/session/auth.go (GateHost, AdminGateURL, AdminSessionKey).
//
// The JSON error sentences were measured from a Go 1.26 program decoding into
// the same struct shape; only the package qualifier was adapted ("main." ->
// "session."), because that is the package the oracle's type lives in.
//
// No test here touches the process environment: every reader takes the env
// as a function, so parallel tests cannot race on a global.
use std::collections::HashMap;
use std::path::Path;
use wapps::session::{self, Claims, State};

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let m: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned()
}

fn b64url(s: &str) -> String {
    // test-side encoder (RFC 4648 §5, unpadded)
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let b = s.as_bytes();
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        let take = c.len() + 1;
        for i in 0..take {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn jwt(payload: &str) -> String {
    format!(
        "{}.{}.{}",
        b64url("{\"alg\":\"none\"}"),
        b64url(payload),
        b64url("sig")
    )
}

// --- ParseClaims ---------------------------------------------------------------

#[test]
fn claims_are_read_from_the_payload_segment() {
    let c = session::parse_claims(&jwt(
        r#"{"email":"dev@example.test","sub":"s1","exp":42,"iss":"i"}"#,
    ))
    .unwrap();
    assert_eq!(
        c,
        Claims {
            email: "dev@example.test".into(),
            sub: "s1".into(),
            exp: 42,
            iss: "i".into()
        }
    );
}

#[test]
fn a_token_without_three_segments_is_not_a_jwt() {
    assert_eq!(
        session::parse_claims("a.b").unwrap_err(),
        "session: token is not a JWT"
    );
    assert_eq!(
        session::parse_claims("a.b.c.d").unwrap_err(),
        "session: token is not a JWT"
    );
}

#[test]
fn a_null_payload_is_an_empty_claim_set_not_an_error() {
    assert_eq!(
        session::parse_claims(&jwt("null")).unwrap(),
        Claims::default()
    );
}

#[test]
fn json_type_errors_use_go_sentences() {
    let cases = [
        ("[]", "json: cannot unmarshal array into Go value of type session.Claims"),
        ("\"x\"", "json: cannot unmarshal string into Go value of type session.Claims"),
        ("5", "json: cannot unmarshal number into Go value of type session.Claims"),
        ("true", "json: cannot unmarshal bool into Go value of type session.Claims"),
        (r#"{"exp":"soon"}"#, "json: cannot unmarshal string into Go struct field Claims.exp of type int64"),
        (r#"{"exp":1.5}"#, "json: cannot unmarshal number 1.5 into Go struct field Claims.exp of type int64"),
        (r#"{"exp":1e3}"#, "json: cannot unmarshal number 1e3 into Go struct field Claims.exp of type int64"),
        (
            r#"{"exp":99999999999999999999}"#,
            "json: cannot unmarshal number 99999999999999999999 into Go struct field Claims.exp of type int64",
        ),
        (r#"{"exp":{}}"#, "json: cannot unmarshal object into Go struct field Claims.exp of type int64"),
        (r#"{"email":[1]}"#, "json: cannot unmarshal array into Go struct field Claims.email of type string"),
        // FIRST error in document order wins.
        (r#"{"email":5,"exp":"x"}"#, "json: cannot unmarshal number into Go struct field Claims.email of type string"),
        (r#"{"exp":"x","email":5}"#, "json: cannot unmarshal string into Go struct field Claims.exp of type int64"),
    ];
    for (payload, want) in cases {
        assert_eq!(
            session::parse_claims(&jwt(payload)).unwrap_err(),
            format!("session: token payload not JSON: {want}"),
            "payload {payload}"
        );
    }
}

#[test]
fn the_two_common_syntax_errors_use_go_sentences() {
    assert_eq!(
        session::parse_claims(&jwt("x")).unwrap_err(),
        "session: token payload not JSON: invalid character 'x' looking for beginning of value"
    );
    assert_eq!(
        session::parse_claims(&format!("a.{}.c", "")).unwrap_err(),
        "session: token payload not JSON: unexpected end of JSON input"
    );
}

#[test]
fn keys_match_case_insensitively_and_the_last_one_wins() {
    let c = session::parse_claims(&jwt(r#"{"EMAIL":"a@b","Email":"c@d","Exp":7}"#)).unwrap();
    assert_eq!((c.email.as_str(), c.exp), ("c@d", 7));
    let c = session::parse_claims(&jwt(r#"{"email":"a@b","email":null}"#)).unwrap();
    assert_eq!(c.email, "a@b", "null leaves the field untouched");
}

// --- State: Expired / TTL --------------------------------------------------------

#[test]
fn a_zero_expiry_never_expires_and_has_no_ttl() {
    let s = State {
        token: "t".into(),
        expires_at: 0,
    };
    assert!(!s.expired(i64::MAX));
    assert_eq!(s.ttl_ns(1000), 0);
}

#[test]
fn expiry_is_inclusive_of_the_current_second() {
    let s = State {
        token: "t".into(),
        expires_at: 100,
    };
    assert!(s.expired(100));
    assert!(!s.expired(99));
    assert_eq!(s.ttl_ns(40), 60_000_000_000);
}

// --- hosts and keys --------------------------------------------------------------

#[test]
fn the_admin_session_has_its_own_key_and_url() {
    let env = env_of(&[("WAPPS_SECRETS_GATE", "https://gate.example.invalid/")]);
    assert_eq!(session::gate_host_with(&env), "gate.example.invalid");
    assert_eq!(
        session::admin_session_key_with(&env),
        "gate.example.invalid-admin"
    );
    assert_eq!(
        session::admin_gate_url_with(&env),
        "https://gate.example.invalid/v1/admin"
    );
}

// --- Load / Save -------------------------------------------------------------------

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-session-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn save_writes_go_json_0600_under_a_0700_dir() {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch("save");
    let cfg = d.join("xdg");
    let env = env_of(&[("XDG_CONFIG_HOME", cfg.to_str().unwrap())]);
    session::save_with(
        &env,
        "gw.example:8443",
        &State {
            token: "a.b.c".into(),
            expires_at: 9,
        },
    )
    .unwrap();
    let p = cfg.join("wapps/session/gw.example_8443.json");
    assert_eq!(
        std::fs::read_to_string(&p).unwrap(),
        r#"{"token":"a.b.c","expires_at":9}"#
    );
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    for dir in [cfg.join("wapps"), cfg.join("wapps/session")] {
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "{}",
            dir.display()
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn load_prefers_the_env_token_over_the_file() {
    let d = scratch("envwins");
    let cfg = d.join("xdg");
    let file_env = env_of(&[("XDG_CONFIG_HOME", cfg.to_str().unwrap())]);
    session::save_with(
        &file_env,
        "h",
        &State {
            token: "from-file".into(),
            expires_at: 5,
        },
    )
    .unwrap();
    let env = env_of(&[
        ("XDG_CONFIG_HOME", cfg.to_str().unwrap()),
        ("WAPPS_SESSION_TOKEN", "from-env"),
        ("WAPPS_SESSION_EXPIRES", "77"),
    ]);
    assert_eq!(
        session::load_with(&env, "h"),
        Some(State {
            token: "from-env".into(),
            expires_at: 77
        })
    );
    // An unparsable expiry falls back to "unknown" (0), it does not drop the token.
    let env = env_of(&[
        ("WAPPS_SESSION_TOKEN", "t"),
        ("WAPPS_SESSION_EXPIRES", "soon"),
    ]);
    assert_eq!(
        session::load_with(&env, "h"),
        Some(State {
            token: "t".into(),
            expires_at: 0
        })
    );
    assert_eq!(
        session::load_with(&file_env, "h"),
        Some(State {
            token: "from-file".into(),
            expires_at: 5
        })
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_empty_or_undecodable_file_is_no_session() {
    let d = scratch("bad");
    let cfg = d.join("xdg");
    let env = env_of(&[("XDG_CONFIG_HOME", cfg.to_str().unwrap())]);
    let dir = cfg.join("wapps/session");
    std::fs::create_dir_all(&dir).unwrap();
    for body in [
        &b""[..],
        b"null",
        br#"{"token":""}"#,
        br#"{"token":"t","expires_at":"x"}"#,
        b"[]",
    ] {
        std::fs::write(dir.join("h.json"), body).unwrap();
        assert_eq!(
            session::load_with(&env, "h"),
            None,
            "{}",
            String::from_utf8_lossy(body)
        );
    }
    std::fs::write(dir.join("h.json"), br#"{"Token":"t","EXPIRES_AT":3}"#).unwrap();
    assert_eq!(
        session::load_with(&env, "h"),
        Some(State {
            token: "t".into(),
            expires_at: 3
        })
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn without_xdg_the_dir_is_under_home_and_without_home_it_is_an_error() {
    let env = env_of(&[("HOME", "/h")]);
    assert_eq!(
        session::dir_with(&env).unwrap(),
        Path::new("/h/.config/wapps/session")
    );
    let env = env_of(&[]);
    assert_eq!(
        session::dir_with(&env).unwrap_err(),
        "session: resolve home: $HOME is not defined"
    );
}
