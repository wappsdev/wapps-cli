// deployverb, `wapps deploy <service>` — the port of internal/deploy/deploy.go
// (the company-deploy-proxy client) and cmd/deploy/deploy.go (the verb).
//
// The proxy contract the Go client mirrors:
//
//   POST {EP}/v1/deploy/{service}  -> 200 {"deployment_uuid":"<20-32 lc-alnum>"}
//   GET  {EP}/v1/deployments/{id}  -> 200 {"status":"<coolify status>"}
//   every non-2xx that reached the proxy -> {"error":"<message>"}
//
// Every request carries `Authorization: Bearer <repo-scoped token>` plus
// `CF-Access-Client-Id` / `CF-Access-Client-Secret` (consumed by Cloudflare
// Access at the edge). Whether a failure carries the proxy's {"error":...}
// JSON is what tells a proxy refusal from an edge block.
//
// THE VERB OWNS ITS EXIT CODE: 0..8 below is a contract CI, runbooks and
// agents branch on. Go writes its own lines and calls os.Exit from RunE, so
// neither the root's error reporter nor its post-command hooks run. `run`
// returns the code; main carries it out through `CmdError::Exit`.
//
// AI-safe: no credential value is ever printed; messages name env KEYS only.
use crate::gojson::{self, GoField, GoStruct, GoValue};
use crate::gostrconv::{self, quote};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// DEFAULT_ENDPOINT, the company-deploy-proxy base URL.
pub const DEFAULT_ENDPOINT: &str = "https://deploy-proxy.meapps.dev";

pub const EXIT_OK: u8 = 0; // triggered (no --wait) or --wait reached "finished"
pub const EXIT_USAGE: u8 = 1; // unknown --repo, bad service shape (no network)
pub const EXIT_CREDS: u8 = 2; // token and/or CF Access id+secret unresolved
pub const EXIT_AUTH_SCOPE: u8 = 3; // proxy 401 / 403 (proxy JSON)
pub const EXIT_CF_ACCESS: u8 = 4; // Cloudflare Access edge block (403/302/5xx, no proxy JSON)
pub const EXIT_NETWORK: u8 = 5; // the call never completed
pub const EXIT_PROXY: u8 = 6; // any other proxy answer, or a bad deployment id
pub const EXIT_TIMEOUT: u8 = 7; // --wait deadline elapsed
pub const EXIT_FAILED: u8 = 8; // --wait saw failed / error / cancelled*

// REQUEST_TIMEOUT, Go's http.Client timeout: above the proxy's own 30 s
// upstream budget. The --wait deadline is enforced separately.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
const DEFAULT_TIMEOUT_SECS: i64 = 1200;
const DEFAULT_POLL_SECS: i64 = 15;
// MAX_BODY, Go's io.LimitReader(resp.Body, 1<<20).
const MAX_BODY: u64 = 1 << 20;

// REPOS, the keys of Go's repoAliases, sorted (knownRepos sorts them). The
// alias VALUES are used by nothing in Go but a deferred fallback, so only the
// names are ported: they validate --repo.
const REPOS: &[&str] = &[
    "kreeva-web",
    "labellens-api",
    "royco",
    "stitchsense",
    "streamkit",
    "supply-pro",
    "vaulter",
    "vibe-studio-backend",
];

/// DeployError, an exit code with its (AI-safe) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployError {
    pub code: u8,
    pub msg: String,
}

fn err(code: u8, msg: String) -> DeployError {
    DeployError { code, msg }
}

/// known_repos, the valid --repo values as Go's usage message lists them.
pub fn known_repos() -> String {
    REPOS.join(", ")
}

/// valid_service_name, Go's `^[a-z][a-z0-9-]{1,40}$` by hand (no regex crate,
/// docs/PORT-kalan-yuzey.md §4.1). RE2's `$` is end of text, so a trailing
/// newline fails like any other byte outside the class.
pub fn valid_service_name(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=41).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// valid_deployment_id, Go's `^[a-z0-9]{20,32}$` by hand.
pub fn valid_deployment_id(s: &str) -> bool {
    (20..=32).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// env_repo_suffix, the env key suffix rule: upper-case, dash to underscore.
/// Only ever called with a validated --repo, which is ASCII.
pub fn env_repo_suffix(repo: &str) -> String {
    repo.replace('-', "_").to_ascii_uppercase()
}

/// classify_status, (terminal, success) for a proxy status: "finished" is
/// success; "failed", "error" and any "cancelled*" are failure; anything
/// else keeps polling.
pub fn classify_status(status: &str) -> (bool, bool) {
    match status {
        "finished" => (true, true),
        "failed" | "error" => (true, false),
        s if s.starts_with("cancelled") => (true, false),
        _ => (false, false),
    }
}

/// parse_proxy_error, Go's parseProxyError: the body decoded into
/// `struct { Error string `json:"error"` }` — so the key matches
/// case-insensitively and the last match wins — and only a non-empty message
/// makes it the proxy's JSON.
pub fn parse_proxy_error(body: &[u8]) -> Option<String> {
    let st = GoStruct {
        go_type: "struct { Error string \"json:\\\"error\\\"\" }",
        name: "",
        fields: &[("error", GoField::Str)],
    };
    match gojson::decode_struct(body, &st) {
        Ok(slots) => match slots.into_iter().next().flatten() {
            Some(GoValue::Str(s)) if !s.is_empty() => Some(s),
            _ => None,
        },
        Err(_) => None,
    }
}

/// parse_field, Go's parseField: the body as `map[string]json.RawMessage`
/// (exact key, last duplicate wins), the value as a string; anything else is
/// "".
pub fn parse_field(body: &[u8], field: &str) -> String {
    let Ok(Some(pairs)) = gojson::decode_raw_object(body, "map[string]json.RawMessage") else {
        return String::new();
    };
    match pairs.iter().rev().find(|(k, _)| k == field) {
        Some((_, raw)) => serde_json::from_str::<String>(raw.get()).unwrap_or_default(),
        None => String::new(),
    }
}

/// classify_http, a non-200 proxy or edge answer as an exit code. `subject` is
/// the service name (trigger) or the deployment id (status).
pub fn classify_http(subject: &str, repo: &str, status: u16, body: &[u8]) -> DeployError {
    let Some(proxy_msg) = parse_proxy_error(body) else {
        // Not the proxy's JSON: a 403/302/5xx was stopped at the edge.
        if status == 403 || status == 302 || status >= 500 {
            return err(
                EXIT_CF_ACCESS,
                "error: blocked by Cloudflare Access — check DEPLOY_PROXY_CF_ACCESS_CLIENT_ID/_SECRET"
                    .to_string(),
            );
        }
        return err(
            EXIT_PROXY,
            format!("error: unexpected proxy response (HTTP {status})"),
        );
    };
    match status {
        401 => err(
            EXIT_AUTH_SCOPE,
            format!(
                "error: proxy rejected token (401 unauthorized) — check DEPLOY_PROXY_TOKEN_{}",
                env_repo_suffix(repo)
            ),
        ),
        403 => err(
            EXIT_AUTH_SCOPE,
            format!(
                "error: {} not in scope for repo {} (proxy 403)",
                quote(subject),
                quote(repo)
            ),
        ),
        400 => err(
            EXIT_PROXY,
            format!("error: proxy rejected request (400 {proxy_msg})"),
        ),
        404 => err(
            EXIT_PROXY,
            format!(
                "error: deployment {} not known to this token (404 {proxy_msg})",
                quote(subject)
            ),
        ),
        502 => err(
            EXIT_PROXY,
            format!("error: proxy upstream error (502 {proxy_msg})"),
        ),
        _ => err(
            EXIT_PROXY,
            format!("error: proxy error (HTTP {status} {proxy_msg})"),
        ),
    }
}

/// Creds, the three proxy credentials and the endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Creds {
    pub endpoint: String,
    pub token: String,
    pub cf_access_id: String,
    pub cf_access_secret: String,
}

fn token_keys(repo: &str) -> [String; 3] {
    [
        format!("DEPLOY_PROXY_TOKEN_{}", env_repo_suffix(repo)),
        "DEPLOY_PROXY_TOKEN".to_string(),
        "PROXY_TOKEN".to_string(),
    ]
}

const CF_ID_KEYS: [&str; 2] = ["DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "CF_ACCESS_CLIENT_ID"];
const CF_SECRET_KEYS: [&str; 2] = [
    "DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET",
    "CF_ACCESS_CLIENT_SECRET",
];
const EP_KEY: &str = "DEPLOY_PROXY_EP";

/// store_candidates, every key the ONE store read asks for, in Go's order.
pub fn store_candidates(repo: &str) -> Vec<String> {
    let mut all: Vec<String> = token_keys(repo).to_vec();
    all.extend(CF_ID_KEYS.iter().map(|k| k.to_string()));
    all.extend(CF_SECRET_KEYS.iter().map(|k| k.to_string()));
    all.push(EP_KEY.to_string());
    all
}

/// resolve_creds, Go's resolveCreds: each value from the env candidates in
/// order, then from the store candidates in order (an empty value counts as
/// unset in both tiers); the endpoint from --ep, then DEPLOY_PROXY_EP, then
/// the default. The second value names the first missing credential, or "".
pub fn resolve_creds(
    repo: &str,
    ep_override: &str,
    env: &dyn Fn(&str) -> String,
    stored: &BTreeMap<String, String>,
) -> (Creds, String) {
    let resolve = |keys: &[&str]| -> String {
        for k in keys {
            let v = env(k);
            if !v.is_empty() {
                return v;
            }
        }
        for k in keys {
            if let Some(v) = stored.get(*k).filter(|v| !v.is_empty()) {
                return v.clone();
            }
        }
        String::new()
    };
    let tk = token_keys(repo);
    let tk: Vec<&str> = tk.iter().map(String::as_str).collect();
    let mut creds = Creds {
        token: resolve(&tk),
        cf_access_id: resolve(&CF_ID_KEYS),
        cf_access_secret: resolve(&CF_SECRET_KEYS),
        endpoint: ep_override.to_string(),
    };
    if creds.endpoint.is_empty() {
        creds.endpoint = resolve(&[EP_KEY]);
    }
    if creds.endpoint.is_empty() {
        creds.endpoint = DEFAULT_ENDPOINT.to_string();
    }
    let missing = if creds.token.is_empty() {
        tk[0].to_string()
    } else if creds.cf_access_id.is_empty() {
        CF_ID_KEYS[0].to_string()
    } else if creds.cf_access_secret.is_empty() {
        CF_SECRET_KEYS[0].to_string()
    } else {
        String::new()
    };
    (creds, missing)
}

/// JsonResult, the --json line. Never carries a credential.
#[derive(serde::Serialize, Debug, Clone)]
pub struct JsonResult {
    pub service: String,
    pub repo: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub deployment_uuid: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    pub outcome: String,
    pub exit_code: u8,
}

impl JsonResult {
    pub fn new(service: &str, repo: &str) -> JsonResult {
        JsonResult {
            service: service.to_string(),
            repo: repo.to_string(),
            deployment_uuid: String::new(),
            status: String::new(),
            outcome: "error".to_string(),
            exit_code: 0,
        }
    }
}

/// json_line, Go's json.Marshal of the result (HTML-safe escaping).
pub fn json_line(r: &JsonResult) -> String {
    gojson::to_string(r).expect("a struct of strings and an int always serializes")
}

/// Client, the deploy-proxy client. Redirects are NOT followed: the contract
/// has none, a Cloudflare edge 302 must surface as exit 4, and following it
/// would replay the CF-Access-Client-* headers to the redirect target.
pub struct Client {
    creds: Creds,
    repo: String,
    agent: ureq::Agent,
}

// Answer, a request that completed: its status and (capped) body.
struct Answer {
    status: u16,
    body: Vec<u8>,
}

impl Client {
    pub fn new(creds: Creds, repo: &str) -> Client {
        let agent = ureq::AgentBuilder::new()
            .tls_config(crate::store::tls_config())
            .redirects(0)
            .build();
        Client {
            creds,
            repo: repo.to_string(),
            agent,
        }
    }

    fn base(&self) -> &str {
        self.creds.endpoint.trim_end_matches('/')
    }

    fn network_error(&self) -> DeployError {
        err(
            EXIT_NETWORK,
            format!(
                "error: cannot reach proxy at {} (network)",
                self.creds.endpoint
            ),
        )
    }

    // send, one request bounded by 45 s and by `deadline` when there is one
    // (Go: the client timeout and the --wait context). None is a call that
    // never completed. A body read error keeps what was read (Go ignores it).
    fn send(&self, method: &str, url: &str, deadline: Option<Instant>) -> Option<Answer> {
        let mut timeout = REQUEST_TIMEOUT;
        if let Some(d) = deadline {
            let left = d.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            timeout = timeout.min(left);
        }
        let req = self
            .agent
            .request(method, url)
            .timeout(timeout)
            .set("Authorization", &format!("Bearer {}", self.creds.token))
            .set("CF-Access-Client-Id", &self.creds.cf_access_id)
            .set("CF-Access-Client-Secret", &self.creds.cf_access_secret)
            .set("User-Agent", "wapps-cli");
        let resp = match req.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(_)) => return None,
        };
        let status = resp.status();
        let mut body = Vec::new();
        let _ = resp.into_reader().take(MAX_BODY).read_to_end(&mut body);
        Some(Answer { status, body })
    }

    /// trigger, POST the deploy and return the deployment id.
    pub fn trigger(&self, service: &str) -> Result<String, DeployError> {
        // The service is validated before this, so Go's PathEscape is the
        // identity on it.
        let url = format!("{}/v1/deploy/{service}", self.base());
        let a = self
            .send("POST", &url, None)
            .ok_or_else(|| self.network_error())?;
        if a.status != 200 {
            return Err(classify_http(service, &self.repo, a.status, &a.body));
        }
        let dep = parse_field(&a.body, "deployment_uuid");
        if dep.is_empty() {
            return Err(err(
                EXIT_PROXY,
                "error: proxy returned empty deployment_uuid".to_string(),
            ));
        }
        if !valid_deployment_id(&dep) {
            return Err(err(
                EXIT_PROXY,
                "error: proxy returned an invalid deployment id".to_string(),
            ));
        }
        Ok(dep)
    }

    /// status, one deployment status; an absent or empty one is "unknown".
    pub fn status(&self, id: &str, deadline: Instant) -> Result<String, DeployError> {
        let url = format!("{}/v1/deployments/{id}", self.base());
        let a = self
            .send("GET", &url, Some(deadline))
            .ok_or_else(|| self.network_error())?;
        if a.status != 200 {
            return Err(classify_http(id, &self.repo, a.status, &a.body));
        }
        let st = parse_field(&a.body, "status");
        Ok(if st.is_empty() {
            "unknown".to_string()
        } else {
            st
        })
    }
}

/// wait, Go's Client.Wait: poll until a terminal status or the deadline. Only
/// NON-terminal progress lines are written (to `progress`, when given); the
/// terminal line is the caller's. Returns the last status and the failure.
pub fn wait(
    client: &Client,
    id: &str,
    label: &str,
    interval: Duration,
    timeout_secs: i64,
    deadline: Instant,
    mut progress: Option<&mut dyn Write>,
) -> (String, Option<DeployError>) {
    let timed_out = || {
        err(
            EXIT_TIMEOUT,
            format!("  {label}: TIMEOUT ({timeout_secs}s)"),
        )
    };
    loop {
        let st = match client.status(id, deadline) {
            Ok(st) => st,
            // A failed status query is fail-closed; one cut by the deadline
            // is a timeout, not a network error.
            Err(e) => {
                if Instant::now() >= deadline {
                    return (String::new(), Some(timed_out()));
                }
                return (String::new(), Some(e));
            }
        };
        match classify_status(&st) {
            (true, true) => return (st, None),
            (true, false) => {
                let e = err(EXIT_FAILED, format!("  {label}: {st}"));
                return (st, Some(e));
            }
            _ => {}
        }
        if let Some(w) = progress.as_deref_mut() {
            let _ = writeln!(w, "  {label}: {st}");
            let _ = w.flush();
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left <= interval {
            std::thread::sleep(left);
            return (st, Some(timed_out()));
        }
        std::thread::sleep(interval);
    }
}

/// Options, the verb's flags after pflag-style parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub service: String,
    pub repo: String,
    pub wait: bool,
    pub timeout_secs: i64,
    pub interval_secs: i64,
    pub ep: String,
    pub json: bool,
}

/// StoreRead, the one store read for the credential candidates: the values
/// found, and the text of a read failure when a store IS configured but could
/// not be read (a missing config is not a failure).
pub type StoreRead<'a> = dyn Fn(&[String]) -> (BTreeMap<String, String>, Option<String>) + 'a;

/// run, Go's runDeploy: every human and JSON line, and the exit code.
pub fn run(
    opts: &Options,
    out: &mut dyn Write,
    errw: &mut dyn Write,
    env: &dyn Fn(&str) -> String,
    store: &StoreRead<'_>,
) -> u8 {
    let mut res = JsonResult::new(&opts.service, &opts.repo);

    // 1. Local validation, no network (exit 1).
    if !REPOS.contains(&opts.repo.as_str()) {
        let msg = format!(
            "usage: unknown repo {} (known: {})",
            quote(&opts.repo),
            known_repos()
        );
        return finish(&mut res, opts.json, EXIT_USAGE, "error", &msg, out, errw);
    }
    if !valid_service_name(&opts.service) {
        let msg = format!(
            "usage: invalid service name {} (must match ^[a-z][a-z0-9-]{{1,40}}$)",
            quote(&opts.service)
        );
        return finish(&mut res, opts.json, EXIT_USAGE, "error", &msg, out, errw);
    }

    // 2. Credentials: env first, then the store (exit 2). The store is read
    // whenever a config exists, even when the env supplies everything.
    let (stored, store_err) = store(&store_candidates(&opts.repo));
    let (creds, missing) = resolve_creds(&opts.repo, &opts.ep, env, &stored);
    if !missing.is_empty() {
        let mut msg = format!("error: could not resolve {missing} (tried env, store)");
        if let Some(e) = store_err {
            msg.push_str(&format!(
                "\n  note: store configured but could not be read: {e}"
            ));
        }
        return finish(&mut res, opts.json, EXIT_CREDS, "error", &msg, out, errw);
    }

    let endpoint = creds.endpoint.clone();
    let client = Client::new(creds, &opts.repo);
    if !opts.json {
        let _ = writeln!(
            out,
            "Deploying {} (repo {}) via {endpoint} …",
            quote(&opts.service),
            opts.repo
        );
        let _ = out.flush();
    }

    // 3. Trigger.
    let id = match client.trigger(&opts.service) {
        Ok(id) => id,
        Err(e) => return finish(&mut res, opts.json, e.code, "error", &e.msg, out, errw),
    };
    res.deployment_uuid = id.clone();
    if !opts.wait {
        let msg = format!("{}: triggered ({id})", opts.service);
        return finish(&mut res, opts.json, EXIT_OK, "triggered", &msg, out, errw);
    }

    // 4. Wait. A non-positive --timeout / --poll-interval takes the default.
    let timeout_secs = if opts.timeout_secs <= 0 {
        DEFAULT_TIMEOUT_SECS
    } else {
        opts.timeout_secs
    };
    let interval_secs = if opts.interval_secs <= 0 {
        DEFAULT_POLL_SECS
    } else {
        opts.interval_secs
    };
    // A --timeout too large for an Instant waits "forever" instead of
    // panicking (Go's Duration multiplication would wrap; not measured).
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(timeout_secs as u64))
        .unwrap_or_else(|| Instant::now() + Duration::from_secs(u64::from(u32::MAX)));
    let interval = Duration::from_secs(interval_secs as u64);
    // Under --json the progress lines would break the one-object stdout.
    let progress: Option<&mut dyn Write> = if opts.json { None } else { Some(&mut *out) };
    let (status, failure) = wait(
        &client,
        &id,
        &opts.service,
        interval,
        timeout_secs,
        deadline,
        progress,
    );
    res.status = status.clone();
    if let Some(e) = failure {
        let outcome = match e.code {
            EXIT_TIMEOUT => "timeout",
            EXIT_FAILED => "failed",
            _ => "error",
        };
        return finish(&mut res, opts.json, e.code, outcome, &e.msg, out, errw);
    }
    let msg = format!("✓ {} deployed ({status})", opts.service);
    finish(&mut res, opts.json, EXIT_OK, "success", &msg, out, errw)
}

// finish, Go's finish closure: the JSON line on stdout, or the human message
// on stdout (exit 0) / stderr (anything else).
fn finish(
    res: &mut JsonResult,
    json: bool,
    code: u8,
    outcome: &str,
    msg: &str,
    out: &mut dyn Write,
    errw: &mut dyn Write,
) -> u8 {
    res.exit_code = code;
    res.outcome = outcome.to_string();
    if json {
        let _ = writeln!(out, "{}", json_line(res));
    } else if !msg.is_empty() && code == EXIT_OK {
        let _ = writeln!(out, "{msg}");
    } else if !msg.is_empty() {
        let _ = writeln!(errw, "{msg}");
    }
    code
}

/// parse_flags, the flag values as pflag parses them, BEFORE the root's
/// checks: a bad int or bool value is refused with pflag's sentence, the
/// leftmost bad token first. `service` is filled by the caller.
pub fn parse_flags(m: &clap::ArgMatches) -> Result<Options, String> {
    use crate::coolifyverb::{bool_errors, bool_value, first_error, last, valued};
    let int_errors = |id: &str| -> Vec<(usize, String)> {
        valued(m, id)
            .into_iter()
            .filter_map(|(i, v)| {
                gostrconv::parse_int_base0(&v).err().map(|e| {
                    (
                        i,
                        format!(
                            "invalid argument {} for {} flag: {}",
                            quote(&v),
                            quote(&format!("--{id}")),
                            e.go_text(&v)
                        ),
                    )
                })
            })
            .collect()
    };
    let mut errs = int_errors("timeout");
    errs.extend(int_errors("poll-interval"));
    errs.extend(bool_errors(m, "wait"));
    errs.extend(bool_errors(m, "json"));
    first_error(errs)?;
    let int_value = |id: &str, default: i64| -> i64 {
        last(m, id)
            .and_then(|v| gostrconv::parse_int_base0(&v).ok())
            .unwrap_or(default)
    };
    Ok(Options {
        service: String::new(),
        repo: last(m, "repo").unwrap_or_else(|| "vaulter".to_string()),
        wait: bool_value(m, "wait", false)?,
        timeout_secs: int_value("timeout", DEFAULT_TIMEOUT_SECS),
        interval_secs: int_value("poll-interval", DEFAULT_POLL_SECS),
        ep: last(m, "ep").unwrap_or_default(),
        json: bool_value(m, "json", false)?,
    })
}
