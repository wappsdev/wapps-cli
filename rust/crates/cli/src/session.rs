// session, the CF Access session cache and the identity headers built from it.
//
// ORACLE: internal/session/session.go (State, Dir, Path, Load, Save,
// ParseClaims) and internal/session/auth.go (GateURL, GateHost,
// AdminGateURL, AdminSessionKey, Auth, AuthAdmin).
//
// `wapps login` writes the app token 0600 to
// <XDG_CONFIG_HOME or ~/.config>/wapps/session/<gate-host>.json; the write
// (admin) session lives under its own key, <gate-host>-admin, because the edge
// protects <gate>/v1/admin with a SEPARATE CF Access app (15 min + WebAuthn,
// different AUD). The token is never printed and never written elsewhere.
//
// Every reader takes the environment as a function (`*_with`) so tests do not
// race on the process environment; the plain names are the production wiring.
use crate::clierr::{Code, Error};
use crate::gojson::{self, GoField, GoStruct, GoValue};
use std::path::PathBuf;

/// DEFAULT_GATE_URL, the default gate hostname.
pub const DEFAULT_GATE_URL: &str = "https://gw.meapps.dev";

/// ADMIN_API_PATH, the path prefix the WRITE Access app covers.
pub const ADMIN_API_PATH: &str = "/v1/admin";

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

fn process_env(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

// non_empty, Go's `os.Getenv(k) != ""`: an empty value counts as unset.
fn non_empty(env: Env<'_>, k: &str) -> Option<String> {
    env(k).filter(|v| !v.is_empty())
}

/// gate_url, WAPPS_SECRETS_GATE (trimmed, no trailing '/') or the default.
pub fn gate_url() -> String {
    gate_url_with(&process_env)
}

pub fn gate_url_with(env: Env<'_>) -> String {
    match env("WAPPS_SECRETS_GATE") {
        Some(v) if !v.trim().is_empty() => v.trim().trim_end_matches('/').to_string(),
        _ => DEFAULT_GATE_URL.to_string(),
    }
}

/// gate_host, the host part of the gate URL — the read session's key.
pub fn gate_host() -> String {
    gate_host_with(&process_env)
}

pub fn gate_host_with(env: Env<'_>) -> String {
    host_of(&gate_url_with(env))
}

/// admin_gate_url, the WRITE (admin) Access app's SSO URL.
pub fn admin_gate_url() -> String {
    admin_gate_url_with(&process_env)
}

pub fn admin_gate_url_with(env: Env<'_>) -> String {
    format!("{}{ADMIN_API_PATH}", gate_url_with(env))
}

/// admin_session_key, the write-AUD session's storage key. Kept APART from
/// the read session: the two apps issue different tokens with different
/// lifetimes (hours vs 15 min), and overwriting one with the other would lose
/// the long read session every 15 minutes.
pub fn admin_session_key() -> String {
    admin_session_key_with(&process_env)
}

pub fn admin_session_key_with(env: Env<'_>) -> String {
    format!("{}-admin", gate_host_with(env))
}

/// host_of, the host part of a gate URL (the session file's key).
///
/// An unparsable value falls back to the DEFAULT host — part of `secrets
/// status`'s rule that no input may make it fail.
pub fn host_of(gate_url: &str) -> String {
    const DEFAULT_HOST: &str = "gw.meapps.dev";
    // Go url.Parse + u.Host: the scheme is stripped and everything before
    // the first '/' kept. Userinfo (`user@host`) is unused in this estate and
    // Go's Host leaves it out anyway.
    let rest = match gate_url.split_once("://") {
        Some((scheme, rest)) if !scheme.is_empty() => rest,
        // A scheme-less value leaves Go's Host EMPTY → the default.
        _ => return DEFAULT_HOST.to_string(),
    };
    let host = rest.split('/').next().unwrap_or("");
    let host = host.rsplit_once('@').map(|(_, h)| h).unwrap_or(host);
    if host.is_empty() {
        return DEFAULT_HOST.to_string();
    }
    host.to_string()
}

/// host_file, reduces a gate host to a safe file name (<host>.json).
///
/// Path-separating characters become '_': a gate name must not be able to
/// place the session file anywhere else in the directory tree.
pub fn host_file(host: &str) -> String {
    let safe: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.json")
}

// --- State -----------------------------------------------------------------------

/// State, a resolved session. `token` is the CF Access app token (JWT) and is
/// NEVER printed. `expires_at` is unix seconds; 0 means unknown (an
/// out-of-band env token) and never expires locally — the edge still checks.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct State {
    pub token: String,
    pub expires_at: i64,
}

impl State {
    /// expired, Go's `ExpiresAt != 0 && ExpiresAt <= now.Unix()`.
    pub fn expired(&self, now_unix: i64) -> bool {
        self.expires_at != 0 && self.expires_at <= now_unix
    }

    /// ttl_ns, Go's `TTL(now)`: `Duration(ExpiresAt-now.Unix()) * Second`,
    /// with Go's wrapping int64 arithmetic; 0 when the expiry is unknown.
    pub fn ttl_ns(&self, now_unix: i64) -> i64 {
        if self.expires_at == 0 {
            return 0;
        }
        self.expires_at
            .wrapping_sub(now_unix)
            .wrapping_mul(1_000_000_000)
    }
}

/// dir, the session directory: $XDG_CONFIG_HOME/wapps/session, else
/// $HOME/.config/wapps/session.
pub fn dir_with(env: Env<'_>) -> Result<PathBuf, String> {
    if let Some(xdg) = non_empty(env, "XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("wapps").join("session"));
    }
    match non_empty(env, "HOME") {
        Some(home) => Ok(PathBuf::from(home)
            .join(".config")
            .join("wapps")
            .join("session")),
        None => Err("session: resolve home: $HOME is not defined".to_string()),
    }
}

/// path_with, the session file for a key (gate host or admin key).
pub fn path_with(env: Env<'_>, key: &str) -> Result<PathBuf, String> {
    Ok(dir_with(env)?.join(host_file(key)))
}

/// load, the session for a key: the out-of-band env token first
/// (WAPPS_SESSION_TOKEN, optional WAPPS_SESSION_EXPIRES), then the file.
///
/// The env token is KEY-INDEPENDENT, exactly as in Go: it stands in for the
/// read AND the admin session.
pub fn load(key: &str) -> Option<State> {
    load_with(&process_env, key)
}

pub fn load_with(env: Env<'_>, key: &str) -> Option<State> {
    if let Some(token) = non_empty(env, "WAPPS_SESSION_TOKEN") {
        // strconv.ParseInt(e, 10, 64); a bad value means "unknown", not "no session".
        let expires_at = non_empty(env, "WAPPS_SESSION_EXPIRES")
            .and_then(|e| e.parse::<i64>().ok())
            .unwrap_or(0);
        return Some(State { token, expires_at });
    }
    let raw = std::fs::read(path_with(env, key).ok()?).ok()?;
    let s = decode_state(&raw)?;
    if s.token.is_empty() {
        return None;
    }
    Some(s)
}

const STATE_FIELDS: GoStruct<'static> = GoStruct {
    go_type: "session.State",
    name: "State",
    fields: &[("token", GoField::Str), ("expires_at", GoField::Int64)],
};

fn decode_state(raw: &[u8]) -> Option<State> {
    let slots = gojson::decode_struct(raw, &STATE_FIELDS).ok()?;
    let mut s = State::default();
    if let Some(GoValue::Str(t)) = &slots[0] {
        s.token = t.clone();
    }
    if let Some(GoValue::Int64(e)) = slots[1] {
        s.expires_at = e;
    }
    Some(s)
}

/// save, writes the session 0600 under a 0700 directory, atomically.
pub fn save(key: &str, s: &State) -> Result<(), String> {
    save_with(&process_env, key, s)
}

pub fn save_with(env: Env<'_>, key: &str, s: &State) -> Result<(), String> {
    let path = path_with(env, key)?;
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    // Go's MkdirAll(dir, 0o700): EVERY directory it creates gets 0700 (under
    // the umask), the intermediate `wapps` included — not only the leaf.
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| {
                format!(
                    "session: mkdir: {}",
                    crate::goerr::path_error("mkdir", &dir.display().to_string(), &e)
                )
            })?;
    }
    let raw = gojson::to_string(s).map_err(|e| format!("session: encode: {e}"))?;
    crate::atomicfile::write(&path, raw.as_bytes(), 0o600)
        .map_err(|e| format!("session: write: {}", crate::goerr::bare_errno(&e)))
}

// --- Claims ------------------------------------------------------------------------

/// Claims, informational JWT payload fields read WITHOUT signature checks —
/// for local expiry and display only. Authorization always happens at the
/// edge/Worker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Claims {
    pub email: String,
    pub sub: String,
    pub exp: i64,
    pub iss: String,
}

const CLAIM_FIELDS: GoStruct<'static> = GoStruct {
    go_type: "session.Claims",
    name: "Claims",
    fields: &[
        ("email", GoField::Str),
        ("sub", GoField::Str),
        ("exp", GoField::Int64),
        ("iss", GoField::Str),
    ],
};

/// parse_claims, decodes a JWT's payload segment (signature NOT verified).
pub fn parse_claims(token: &str) -> Result<Claims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("session: token is not a JWT".to_string());
    }
    // Go names the offending byte offset here; the sentence is never shown
    // (login rejects an undecodable segment earlier, --check swallows it).
    let payload = crate::gobase64::raw_url_decode(parts[1])
        .ok_or_else(|| "session: token payload not base64url: illegal base64 data".to_string())?;
    let slots = gojson::decode_struct(&payload, &CLAIM_FIELDS)
        .map_err(|e| format!("session: token payload not JSON: {e}"))?;
    let s = |i: usize| match &slots[i] {
        Some(GoValue::Str(v)) => v.clone(),
        _ => String::new(),
    };
    let exp = match slots[2] {
        Some(GoValue::Int64(v)) => v,
        _ => 0,
    };
    Ok(Claims {
        email: s(0),
        sub: s(1),
        exp,
        iss: s(3),
    })
}

// --- identity headers ------------------------------------------------------------------

/// AuthHeader, a (name, value) header pair added to a request.
pub type AuthHeader = (String, String);

/// HEADER_ACCESS_TOKEN, the CF Access app-token header name.
pub const HEADER_ACCESS_TOKEN: &str = "cf-access-token";

const READ_RECOVERY: &str = "run 'wapps login'";
const ADMIN_RECOVERY: &str = "run 'wapps login --write' (admin app: 15 min + WebAuthn)";

/// auth_headers, the READ session's identity headers (data plane).
///
/// 1) CF_ACCESS_CLIENT_ID + CF_ACCESS_CLIENT_SECRET → service-token path
///    (+ Authorization: Bearer WAPPS_MACHINE_TOKEN when set);
/// 2) else the session under the gate host (env token, then the file
///    `wapps login` wrote) → cf-access-token;
/// 3) none, or expired → SESSION_EXPIRED and the request never leaves.
pub fn auth_headers() -> Result<Vec<AuthHeader>, Error> {
    auth_for(&gate_host(), READ_RECOVERY)
}

/// auth_headers_admin, the identity headers for CONTROL-PLANE calls
/// (`projects rm`, policy). They read the WRITE session — a separate key —
/// because the edge stamps the write app's AUD on everything under
/// /v1/admin; a valid read session cannot stand in. The recovery line names
/// `wapps login --write`, or an operator who ran `wapps login` stays stuck.
///
/// ORACLE: internal/session/auth.go (AuthAdmin → authFor(AdminSessionKey(), ...)).
pub fn auth_headers_admin() -> Result<Vec<AuthHeader>, Error> {
    auth_for(&admin_session_key(), ADMIN_RECOVERY)
}

fn auth_for(key: &str, recovery: &str) -> Result<Vec<AuthHeader>, Error> {
    let id = std::env::var("CF_ACCESS_CLIENT_ID").unwrap_or_default();
    let secret = std::env::var("CF_ACCESS_CLIENT_SECRET").unwrap_or_default();
    if !id.is_empty() && !secret.is_empty() {
        let mut h = vec![
            ("CF-Access-Client-Id".to_string(), id),
            ("CF-Access-Client-Secret".to_string(), secret),
        ];
        if let Ok(mt) = std::env::var("WAPPS_MACHINE_TOKEN") {
            if !mt.is_empty() {
                h.push(("Authorization".to_string(), format!("Bearer {mt}")));
            }
        }
        return Ok(h);
    }
    match load(key) {
        Some(s) if !s.expired(now_unix()) => Ok(vec![(HEADER_ACCESS_TOKEN.to_string(), s.token)]),
        _ => Err(Error::new(
            Code::SessionExpired,
            "no valid CF Access session for the secrets gate",
        )
        .with_recovery(recovery)),
    }
}

/// now_unix, wall-clock unix seconds (Go's `time.Now().Unix()`).
pub fn now_unix() -> i64 {
    now().0
}

/// now, wall-clock unix (seconds, nanoseconds).
pub fn now() -> (i64, i64) {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
        Err(_) => (0, 0),
    }
}
