// `wapps login` must not leak a single token byte — measured, not assumed.
//
// The differential proves Rust prints what Go prints; it does not prove that
// what Go prints is clean. This test asks the question directly, of BOTH
// binaries, under a pty (the plain verb is TTY-only): a cloudflared shim
// hands out a made-up JWT and ALSO writes it to stderr (a stream login must
// discard), then the test searches every byte the binary emitted for the
// token and for each of its three segments. It also checks that the token's
// only copy on disk is the 0600 session file: cloudflared's isolated temp HOME
// must be gone afterwards, which is measured by giving the binary a private
// TMPDIR and requiring it to be empty when the run ends.
//
// NO REAL SECRET: the token is an unsigned test string.
use broker_oracle::exe::write_executable;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TOKEN: &str =
    "eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImxlYWtAZXhhbXBsZS50ZXN0In0.bGVhay1jYW5hcnktc2lnbmF0dXJl";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap()
        .to_path_buf()
}

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-loginleak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// (name, argv, extra env, expected exit)
type Step<'a> = (&'a str, &'a [&'a str], &'a [(&'a str, &'a str)], i64);

struct Run {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i64,
}

fn pty_run(bin: &Path, argv: &[&str], env: &[(&str, String)], cwd: &Path) -> Run {
    let mut full = vec![bin.to_str().unwrap().to_string()];
    full.extend(argv.iter().map(|s| s.to_string()));
    let env: serde_json::Map<String, serde_json::Value> = env
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.clone())))
        .collect();
    let spec = serde_json::json!({"argv": full, "env": env, "cwd": cwd});
    let mut child = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/ptyrun.py"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("ptyrun.py");
    std::io::Write::write_all(child.stdin.as_mut().unwrap(), spec.to_string().as_bytes()).unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ptyrun.py failed");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let hex = |k: &str| {
        let s = v[k].as_str().unwrap();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    };
    Run {
        stdout: hex("stdout_hex"),
        stderr: hex("stderr_hex"),
        exit: v["exit"].as_i64().unwrap(),
    }
}

fn assert_no_token(label: &str, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes);
    assert!(
        !text.contains(TOKEN),
        "{label}: the whole token leaked:\n{text}"
    );
    for seg in TOKEN.split('.') {
        assert!(
            !text.contains(seg),
            "{label}: token segment {seg} leaked:\n{text}"
        );
    }
}

fn binaries(work: &Path) -> Vec<(&'static str, PathBuf)> {
    let go = work.join("wapps-go");
    let st = Command::new("go")
        .args(["build", "-o"])
        .arg(&go)
        .arg("./main.go")
        .current_dir(repo_root())
        .status()
        .expect("go build");
    assert!(st.success(), "go build (oracle) failed");
    vec![
        ("go", go),
        ("rust", PathBuf::from(env!("CARGO_BIN_EXE_wapps"))),
    ]
}

#[test]
fn login_never_prints_or_strays_a_token_byte() {
    let work = scratch();
    let bin_dir = work.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let shim = bin_dir.join("cloudflared");
    write_executable(
        &shim,
        b"#!/bin/sh\n\
         [ \"$2\" = token ] || exit \"${LOGIN_EXIT:-0}\"\n\
         printf '%s\\n' \"$CF_SHIM_TOKEN\" >&2\n\
         printf '%s\\n' \"$CF_SHIM_TOKEN\"\n\
         exit \"${TOKEN_EXIT:-0}\"\n",
    )
    .unwrap();

    for (label, bin) in binaries(&work) {
        let runs: [Step; 4] = [
            ("read login", &["login"], &[], 0),
            ("write login", &["login", "--write"], &[], 0),
            (
                "token fetch fails after printing",
                &["login"],
                &[("TOKEN_EXIT", "4")],
                1,
            ),
            ("check after login", &["login", "--check"], &[], 0),
        ];
        let cfg = work.join(format!("{label}-xdg"));
        let tmp = work.join(format!("{label}-tmp"));
        std::fs::create_dir_all(&tmp).unwrap();
        for (what, argv, extra, want_exit) in runs {
            let mut env = vec![
                ("PATH", format!("{}:/usr/bin:/bin", bin_dir.display())),
                ("HOME", work.join("home").display().to_string()),
                ("XDG_CONFIG_HOME", cfg.display().to_string()),
                ("TMPDIR", tmp.display().to_string()),
                ("TERM", "dumb".to_string()),
                (
                    "WAPPS_SECRETS_GATE",
                    "https://gate.example.invalid".to_string(),
                ),
                ("WAPPS_NO_UPDATE_CHECK", "1".to_string()),
                ("WAPPS_AGENT_MODE", "0".to_string()),
                ("CF_SHIM_TOKEN", TOKEN.to_string()),
            ];
            env.extend(extra.iter().map(|(k, v)| (*k, v.to_string())));
            let r = pty_run(&bin, argv, &env, &work);
            let tag = format!("{label}/{what}");
            assert_eq!(r.exit, want_exit, "{tag}: exit");
            assert_no_token(&format!("{tag} stdout"), &r.stdout);
            assert_no_token(&format!("{tag} stderr"), &r.stderr);
            assert_eq!(
                std::fs::read_dir(&tmp).unwrap().count(),
                0,
                "{tag}: cloudflared's isolated home was left behind in TMPDIR"
            );
        }
        // The ONLY persistent copies: the two 0600 session files.
        for f in [
            "gate.example.invalid.json",
            "gate.example.invalid-admin.json",
        ] {
            let p = cfg.join("wapps/session").join(f);
            let body = std::fs::read_to_string(&p).unwrap();
            assert!(body.contains(TOKEN), "{label}: {f} does not hold the token");
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    let _ = std::fs::remove_dir_all(&work);
}
