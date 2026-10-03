// loginverb, `wapps login` — CF Access SSO delegated to cloudflared.
//
// ORACLE: cmd/login.go (cloudflaredLogin, isolatedEnv, runLogin, runLoginCheck,
// printSession, looksLikeJWT).
//
// The CF Access CLI flow rejects a localhost callback, so the only supported
// browser flow is edge token transfer, and cloudflared is its reference
// implementation. login therefore delegates:
//   1. `cloudflared access login --quiet <gate>` drives the browser SSO
//      (--quiet: cloudflared must not print the JWT to the terminal);
//   2. `cloudflared access token -app=<gate>` prints the app token on stdout
//      (its stderr is DISCARDED: a diagnostic carrying the token must not
//      reach a log or an error message);
//   3. session.rs writes the token 0600; it is never printed.
//
// cloudflared runs in an ISOLATED, temporary HOME that is deleted afterwards,
// so the only persistent copy of the token is the session file. Browser
// org-session reuse is cookie-based and unaffected.
//
// No new crate: the child is a std::process::Command, the session file goes
// through atomicfile.rs, and the JWT segments through gobase64.rs.
use crate::clierr::{Code, Error};
use crate::goexec;
use crate::gotime;
use crate::session::{self, Claims, State};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// LOGIN_TIMEOUT, the upper bound for the interactive SSO (both children
/// share it, like Go's single context).
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// looks_like_jwt, Go's looksLikeJWT: ONE clean line of three non-empty,
/// base64url-decodable segments. Inner whitespace means a helper decorated
/// its output, and counting dots alone would accept that.
pub fn looks_like_jwt(s: &str) -> bool {
    if s.is_empty() || s.contains([' ', '\t', '\r', '\n']) {
        return false;
    }
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|seg| !seg.is_empty() && crate::gobase64::raw_url_decode(seg).is_some())
}

const PINNED: [&str; 7] = [
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_DATA_HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

/// isolated_env, the cloudflared child's environment: every home/config/cache
/// location (macOS/Linux and Windows names) pinned to `tmp_home`, and the
/// TUNNEL_* / CLOUDFLARED_* overrides that could move its token cache dropped.
/// Everything else is inherited.
pub fn isolated_env(base: &[(OsString, OsString)], tmp_home: &str) -> Vec<(OsString, OsString)> {
    let mut out: Vec<(OsString, OsString)> = base
        .iter()
        .filter(|(k, _)| {
            let k = k.to_string_lossy();
            !PINNED.contains(&k.as_ref())
                && !k.starts_with("TUNNEL_")
                && !k.starts_with("CLOUDFLARED_")
        })
        .cloned()
        .collect();
    out.extend(
        PINNED
            .iter()
            .map(|k| (OsString::from(k), OsString::from(tmp_home))),
    );
    out
}

/// CloudflaredRun, the inputs of one SSO run. Production passes the process
/// environment; tests inject PATH, the temp base and a short timeout.
pub struct CloudflaredRun<'a> {
    pub gate: &'a str,
    pub path_env: &'a str,
    pub temp_base: &'a Path,
    pub base_env: &'a [(OsString, OsString)],
    pub timeout: Duration,
}

/// cloudflared_login, runs the two cloudflared steps and returns the trimmed
/// app token. A missing cloudflared is ACTION_UNAVAILABLE and is decided
/// BEFORE anything is created on disk.
pub fn cloudflared_login(run: &CloudflaredRun<'_>) -> Result<String, Error> {
    let Some(cf) = goexec::look_path("cloudflared", run.path_env) else {
        return Err(Error::new(
            Code::ActionUnavailable,
            "wapps login needs cloudflared for the CF Access SSO flow (edge token transfer).\n  \
             install: brew install cloudflared\n  then re-run: wapps login",
        )
        .with_recovery(
            "install cloudflared (macOS: `brew install cloudflared`; other: \
             https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/), \
             then re-run: wapps login",
        ));
    };
    let home = TempHome::create(run.temp_base)
        .map_err(|e| Error::new(Code::Internal, format!("isolate cloudflared home: {e}")))?;
    let env = isolated_env(run.base_env, &home.0.to_string_lossy());
    let deadline = Instant::now() + run.timeout;

    // 1) interactive SSO: the user's own terminal on all three streams.
    let mut login = command(&cf, &env);
    login.args(["access", "login", "--quiet", run.gate]);
    login
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    match run_capturing(login, &cf, deadline).0 {
        Waited::Exited(None) => {}
        Waited::TimedOut => {
            return Err(Error::new(
                Code::SessionExpired,
                "browser SSO not completed in time; re-run wapps login",
            ))
        }
        Waited::Exited(Some(why)) => {
            return Err(Error::new(
                Code::Internal,
                format!("cloudflared access login: {why}"),
            ))
        }
    }

    // 2) the app token from the isolated cache: stdout only, through a pipe
    //    (never a file), and stderr dropped.
    let mut tok = command(&cf, &env);
    tok.args(["access", "token", &format!("-app={}", run.gate)]);
    tok.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let (waited, raw) = run_capturing(tok, &cf, deadline);
    match waited {
        Waited::Exited(None) => {}
        Waited::TimedOut => {
            return Err(Error::new(
                Code::SessionExpired,
                "cloudflared token fetch timed out; re-run wapps login",
            ))
        }
        Waited::Exited(Some(why)) => {
            return Err(Error::new(
                Code::Internal,
                format!("cloudflared access token failed; re-run wapps login: {why}"),
            ))
        }
    }
    Ok(String::from_utf8_lossy(&raw).trim().to_string())
}

fn command(cf: &Path, env: &[(OsString, OsString)]) -> Command {
    let mut c = Command::new(cf);
    c.env_clear();
    c.envs(env.iter().map(|(k, v)| (k, v)));
    c
}

enum Waited {
    /// None: exit 0. Some(text): Go's error text for the failure.
    Exited(Option<String>),
    TimedOut,
}

// run_capturing, spawns and waits until `deadline`; on the deadline the
// child is KILLED (Go's CommandContext sends SIGKILL) and reaped. A piped
// stdout is drained on a thread so a chatty child cannot block on a full
// pipe; the bytes stay in memory.
fn run_capturing(mut cmd: Command, cf: &Path, deadline: Instant) -> (Waited, Vec<u8>) {
    let mut child: Child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let why = crate::goerr::spawn_error(&cf.to_string_lossy(), &e);
            return (Waited::Exited(Some(why)), Vec::new());
        }
    };
    let reader = child.stdout.take().map(|mut out| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut out, &mut buf);
            buf
        })
    });
    let waited = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Waited::Exited(goexec::exit_text(st)),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break Waited::TimedOut;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => break Waited::Exited(Some(format!("wait: {e}"))),
        }
    };
    let out = reader.and_then(|h| h.join().ok()).unwrap_or_default();
    (waited, out)
}

// TempHome, Go's os.MkdirTemp(base, "wapps-cf-") + defer os.RemoveAll: a
// fresh 0700 directory that is removed when the run ends, on every path.
struct TempHome(PathBuf);

impl TempHome {
    fn create(base: &Path) -> std::io::Result<TempHome> {
        use std::os::unix::fs::DirBuilderExt;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for i in 0..10_000u32 {
            let n = seed.wrapping_add(i.wrapping_mul(7919)) ^ std::process::id();
            let p = base.join(format!("wapps-cf-{n}"));
            match std::fs::DirBuilder::new().mode(0o700).create(&p) {
                Ok(()) => return Ok(TempHome(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("could not create a unique directory"))
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// temp_base, Go's os.TempDir() on Unix: $TMPDIR, else "/tmp". NOT
/// std::env::temp_dir(), which on macOS may consult confstr instead.
pub fn temp_base() -> PathBuf {
    match std::env::var("TMPDIR") {
        Ok(v) if !v.is_empty() => PathBuf::from(v),
        _ => PathBuf::from("/tmp"),
    }
}

// --- output -------------------------------------------------------------------------

/// render_session, Go's printSession: target, subject and remaining TTL —
/// NEVER token bytes.
pub fn render_session(label: &str, target: &str, s: &State, now_unix: i64) -> String {
    let subject = match session::parse_claims(&s.token) {
        Ok(c) if !c.email.is_empty() => c.email,
        _ => "(unknown subject)".to_string(),
    };
    let expires = if s.expires_at == 0 {
        "unknown (out-of-band token)".to_string()
    } else {
        format!(
            "in {}",
            gotime::duration_string(gotime::round_second(s.ttl_ns(now_unix)))
        )
    };
    format!(
        "{:<9} {target}\nsubject:  {subject}\nexpires:  {expires}\n",
        format!("{label}:")
    )
}

/// ADMIN_MISSING, the --check lines for a missing/expired write session. Not
/// an error: most work never needs it, but control-plane verbs fail with
/// AUD_MISMATCH without it and this is where an operator looks.
pub const ADMIN_MISSING: &str = "admin:    no valid write-AUD session (control-plane verbs will fail)\n          get one with: wapps login --write\n";

/// success_line, the line printed after the token is cached.
pub fn success_line(c: &Claims, now: (i64, i64)) -> String {
    let subject = if c.email.is_empty() {
        String::new()
    } else {
        format!(" as {}", c.email)
    };
    if c.exp > 0 {
        let left = gotime::round_second(gotime::until_unix(c.exp, now.0, now.1));
        format!(
            "✓ logged in{subject} (session expires in {})\n",
            gotime::duration_string(left)
        )
    } else {
        format!("✓ logged in{subject}\n")
    }
}
