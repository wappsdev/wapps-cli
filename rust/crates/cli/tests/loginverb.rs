// `wapps login`'s pieces that the pty differential cannot reach on its own.
//
// ORACLE: cmd/login.go (looksLikeJWT, isolatedEnv, cloudflaredLogin,
// printSession).
//
// What lives here and why:
//   * looksLikeJWT vectors — measured from a Go 1.26 program;
//   * the cloudflared runner against a shim: the 5-minute timeout cannot be
//     measured in the corpus (a case would sit for five minutes), and the
//     isolated temp HOME is deleted after the run, which no case can observe
//     from the outside. Both are measured here with an injected timeout and an
//     injected temp base.
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use wapps::clierr::Code;
use wapps::loginverb::{self, CloudflaredRun};
use wapps::session::State;

#[test]
fn jwt_shape_matches_go() {
    for (s, want) in [
        ("a.b.c", false),
        ("e30.e30.e30", true),
        ("e30.e30", false),
        ("e30..e30", false),
        ("e30.e30.e30.e30", false),
        ("e30.e3 0.e30", false),
        ("e30.e30.e30\n", false),
        ("e30.e30.a", false),
        ("", false),
        ("e30.e30.e30=", false),
    ] {
        assert_eq!(loginverb::looks_like_jwt(s), want, "{s:?}");
    }
}

#[test]
fn the_isolated_env_pins_every_home_and_drops_cloudflared_overrides() {
    let base: Vec<(OsString, OsString)> = [
        ("HOME", "/real"),
        ("XDG_CONFIG_HOME", "/real/.config"),
        ("PATH", "/usr/bin"),
        ("TUNNEL_ORIGIN_CERT", "x"),
        ("CLOUDFLARED_TOKEN", "y"),
        ("WAPPS_SESSION_TOKEN", "kept"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    let mut got = loginverb::isolated_env(&base, "/tmp/wapps-cf-1");
    got.sort();
    let want: Vec<(OsString, OsString)> = [
        ("APPDATA", "/tmp/wapps-cf-1"),
        ("HOME", "/tmp/wapps-cf-1"),
        ("LOCALAPPDATA", "/tmp/wapps-cf-1"),
        ("PATH", "/usr/bin"),
        ("USERPROFILE", "/tmp/wapps-cf-1"),
        ("WAPPS_SESSION_TOKEN", "kept"),
        ("XDG_CACHE_HOME", "/tmp/wapps-cf-1"),
        ("XDG_CONFIG_HOME", "/tmp/wapps-cf-1"),
        ("XDG_DATA_HOME", "/tmp/wapps-cf-1"),
    ]
    .iter()
    .map(|(k, v)| (OsString::from(k), OsString::from(v)))
    .collect();
    assert_eq!(got, want);
}

// Go hands the child os.Environ() byte-for-byte; a value that is not UTF-8
// must pass through untouched, not panic or be replaced.
#[test]
fn a_non_utf8_value_is_inherited_verbatim() {
    let raw = OsString::from_vec(vec![b'a', 0xff, b'b']);
    let base = vec![(OsString::from("ODD"), raw.clone())];
    let got = loginverb::isolated_env(&base, "/t");
    assert!(got.contains(&(OsString::from("ODD"), raw)));
}

// --- the cloudflared runner, against a shim -----------------------------------------

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-loginverb-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("bin")).unwrap();
    std::fs::create_dir_all(d.join("tmp")).unwrap();
    d
}

fn shim(dir: &Path, body: &str) {
    let p = dir.join("bin/cloudflared");
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn run(dir: &Path, timeout: Duration) -> Result<String, wapps::clierr::Error> {
    loginverb::cloudflared_login(&CloudflaredRun {
        gate: "https://gate.example.invalid",
        path_env: dir.join("bin").to_str().unwrap(),
        temp_base: &dir.join("tmp"),
        base_env: &[],
        timeout,
    })
}

fn temp_entries(dir: &Path) -> usize {
    std::fs::read_dir(dir.join("tmp")).unwrap().count()
}

#[test]
fn no_cloudflared_on_path_is_action_unavailable() {
    let d = scratch("absent");
    let e = run(&d, Duration::from_secs(5)).unwrap_err();
    assert_eq!(e.code, Code::ActionUnavailable);
    assert!(
        e.message.starts_with("wapps login needs cloudflared"),
        "{}",
        e.message
    );
    assert_eq!(
        temp_entries(&d),
        0,
        "no temp home before the lookup succeeds"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_token_is_trimmed_and_the_temp_home_is_removed() {
    let d = scratch("ok");
    // The token step must see the SAME isolated home the login step used.
    shim(
        &d,
        r#"case "$2" in
login) touch "$HOME/cache" ;;
token) [ -f "$HOME/cache" ] && printf '  e30.e30.e30 \n' ;;
esac"#,
    );
    assert_eq!(run(&d, Duration::from_secs(10)).unwrap(), "e30.e30.e30");
    assert_eq!(temp_entries(&d), 0, "the isolated home must be deleted");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_failing_login_step_names_the_exit_status() {
    let d = scratch("loginfail");
    shim(&d, "exit 3");
    let e = run(&d, Duration::from_secs(10)).unwrap_err();
    assert_eq!(e.code, Code::Internal);
    assert_eq!(e.message, "cloudflared access login: exit status 3");
    assert_eq!(temp_entries(&d), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_failing_token_step_names_the_exit_status() {
    let d = scratch("tokenfail");
    shim(&d, r#"[ "$2" = token ] && exit 4; exit 0"#);
    let e = run(&d, Duration::from_secs(10)).unwrap_err();
    assert_eq!(
        e.message,
        "cloudflared access token failed; re-run wapps login: exit status 4"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_signal_is_named_like_go() {
    let d = scratch("signal");
    shim(&d, "kill -TERM $$");
    let e = run(&d, Duration::from_secs(10)).unwrap_err();
    assert_eq!(e.message, "cloudflared access login: signal: terminated");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_hung_sso_is_killed_at_the_deadline() {
    let d = scratch("hang");
    shim(&d, "exec sleep 30");
    let start = std::time::Instant::now();
    let e = run(&d, Duration::from_millis(300)).unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "the child was not killed"
    );
    assert_eq!(e.code, Code::SessionExpired);
    assert_eq!(
        e.message,
        "browser SSO not completed in time; re-run wapps login"
    );
    assert_eq!(temp_entries(&d), 0);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_hung_token_fetch_shares_the_same_deadline() {
    let d = scratch("hangtoken");
    shim(&d, r#"[ "$2" = token ] && exec sleep 30; exit 0"#);
    // 3 s, not 300 ms: the fast login step must FINISH inside the budget, and
    // the first exec of a fresh script on macOS can take hundreds of ms.
    let e = run(&d, Duration::from_secs(3)).unwrap_err();
    assert_eq!(e.code, Code::SessionExpired);
    assert_eq!(
        e.message,
        "cloudflared token fetch timed out; re-run wapps login"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// --- rendering ------------------------------------------------------------------------

#[test]
fn a_session_block_never_contains_token_bytes() {
    let token = format!("e30.{}.c2ln", "eyJlbWFpbCI6ImRldkBleGFtcGxlLnRlc3QifQ");
    let s = State {
        token: token.clone(),
        expires_at: 0,
    };
    let out = loginverb::render_session("gate", "gate.example.invalid", &s, 1_000);
    assert_eq!(
        out,
        "gate:     gate.example.invalid\nsubject:  dev@example.test\nexpires:  unknown (out-of-band token)\n"
    );
    assert!(!out.contains(&token));
    let s = State {
        token: "opaque".into(),
        expires_at: 4_600,
    };
    assert_eq!(
        loginverb::render_session("admin", "https://g/v1/admin", &s, 1_000),
        "admin:    https://g/v1/admin\nsubject:  (unknown subject)\nexpires:  in 1h0m0s\n"
    );
}
