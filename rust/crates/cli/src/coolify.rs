// coolify, the Coolify v4 REST client — the port of `internal/coolify`
// (client.go, envs.go). Errors are Go's error TEXT: the verbs print them as
// they are, so the wrapping chain ("coolify.UpdateAppEnvs[K]: coolify.UpsertAppEnv[K]
// POST: POST /applications/<uuid>/envs: HTTP 500: <body>") is part of the
// contract and is measured by the pty differential against a fake Coolify API.
use crate::gobase64;
use crate::gojson;
use crate::gostrconv::{quote, quote_rune};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::time::Duration;

/// validate_uuid, Go's `validateUUID`: refuses an empty value, a path
/// traversal token, and — unless the value is a canonical 8-4-4-4-12 hex UUID
/// — any rune outside ASCII letters, digits and '-'. It guards the uuid before
/// it is concatenated into an API path ("../servers" would reach another
/// endpoint).
///
/// Go tries the strict UUID pattern first and falls back to the lax rune
/// check; every canonical UUID passes the lax check too, so the strict pattern
/// never changes the outcome and is not modelled.
pub fn validate_uuid(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("coolify: {label} is empty"));
    }
    if ["/", "\\", "..", "?", "&", "#", " "]
        .iter()
        .any(|t| value.contains(t))
    {
        return Err(format!(
            "coolify: {label} contains invalid characters: {}",
            quote(value)
        ));
    }
    if let Some(c) = value
        .chars()
        .find(|&c| !(c == '-' || c.is_ascii_alphanumeric()))
    {
        return Err(format!(
            "coolify: {label} has invalid character {} in {}",
            quote_rune(c),
            quote(value)
        ));
    }
    Ok(())
}

// MAX_ERROR_BODY_BYTES, how much of a 4xx/5xx body Go keeps in the error
// (Coolify can echo request headers, credentials included, into an error body).
const MAX_ERROR_BODY_BYTES: usize = 200;

/// http_error_text, Go's `(*HTTPError).Error()`: "<METHOD> <path>: HTTP <n>:
/// <body>", the body cut at 200 BYTES with "…" appended.
///
/// Go prints the raw bytes. A cut through a multi-byte character leaves a
/// partial sequence, which a Rust `String` cannot hold: it becomes U+FFFD here
/// (a known divergence, see docs/PORT-kalan-yuzey.md slice 6a).
pub fn http_error_text(method: &str, path: &str, status: u16, body: &[u8]) -> String {
    let shown = if body.len() > MAX_ERROR_BODY_BYTES {
        format!(
            "{}…",
            String::from_utf8_lossy(&body[..MAX_ERROR_BODY_BYTES])
        )
    } else {
        String::from_utf8_lossy(body).into_owned()
    };
    format!("{method} {path}: HTTP {status}: {shown}")
}

// ReqError, a failed request: an HTTP status (callers branch on 409) or
// anything else, both carrying Go's text.
enum ReqError {
    Status(u16, String),
    Other(String),
}

impl fmt::Display for ReqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReqError::Status(_, text) | ReqError::Other(text) => f.write_str(text),
        }
    }
}

// EnvBody, the POST/PATCH /envs body. Fields in ALPHABETICAL order: Go
// marshals a map, which sorts its keys, and the fake API digests the raw bytes.
#[derive(serde::Serialize)]
struct EnvBody<'a> {
    is_buildtime: bool,
    is_literal: bool,
    is_preview: bool,
    key: &'a str,
    value: &'a str,
}

#[derive(serde::Serialize)]
struct LabelsBody {
    custom_labels: String,
}

// ComposeBody / GitHubBody, the two create bodies, fields in alphabetical
// order for the same reason as EnvBody.
#[derive(serde::Serialize)]
struct ComposeBody<'a> {
    docker_compose_raw: String,
    name: &'a str,
    project_uuid: &'a str,
    server_uuid: &'a str,
}

#[derive(serde::Serialize)]
struct GitHubBody<'a> {
    base_directory: &'a str,
    build_pack: &'a str,
    dockerfile_location: &'a str,
    environment_name: &'a str,
    git_branch: &'a str,
    git_repository: &'a str,
    github_app_uuid: &'a str,
    instant_deploy: bool,
    name: &'a str,
    ports_exposes: &'a str,
    project_uuid: &'a str,
    server_uuid: &'a str,
    watch_paths: &'a str,
}

/// GitHubApp, Go's `CreateGitHubAppAppRequest` as `deploy-app-git` fills it
/// (EnvironmentName and GitCommitSHA are never set by any caller, so the
/// body always says "production").
pub struct GitHubApp<'a> {
    pub project_uuid: &'a str,
    pub server_uuid: &'a str,
    pub github_app_uuid: &'a str,
    pub git_repository: &'a str,
    pub git_branch: &'a str,
    pub build_pack: &'a str,
    pub name: &'a str,
    pub base_directory: &'a str,
    pub dockerfile_location: &'a str,
    pub ports: &'a str,
    pub watch_paths: &'a str,
    pub instant_deploy: bool,
}

/// EnvEntry, Go's `coolify.EnvEntry`: the fields of one env record that sync
/// reads. A field of the wrong JSON type reads as its zero value (Go's
/// asString/asBool).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EnvEntry {
    pub uuid: String,
    pub key: String,
    pub value: String,
    pub is_buildtime: bool,
    pub is_coolify: bool,
    pub is_preview: bool,
}

impl EnvEntry {
    fn from_object(m: &Map<String, Value>) -> EnvEntry {
        let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let b = |k: &str| m.get(k).and_then(Value::as_bool).unwrap_or(false);
        EnvEntry {
            uuid: s("uuid"),
            key: s("key"),
            value: s("value"),
            is_buildtime: b("is_buildtime"),
            is_coolify: b("is_coolify"),
            is_preview: b("is_preview"),
        }
    }
}

/// go_fmt_v, Go's `%v` of a decoded JSON value (`map[string]interface{}` and
/// friends): maps as `map[k:v ...]` with sorted keys, arrays as `[a b]`, null
/// as `<nil>`, numbers as float64 `%v`. It is how Go prints a create answer
/// that has no uuid.
pub fn go_fmt_v(v: &Value) -> String {
    match v {
        Value::Null => "<nil>".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => go_float_v(n.as_f64().unwrap_or(0.0)),
        Value::String(s) => s.clone(),
        Value::Array(a) => format!("[{}]", a.iter().map(go_fmt_v).collect::<Vec<_>>().join(" ")),
        // serde_json's Map is a BTreeMap here: already in Go's sorted order.
        Value::Object(m) => format!(
            "map[{}]",
            m.iter()
                .map(|(k, v)| format!("{k}:{}", go_fmt_v(v)))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

// go_float_v, `%v` of a float64: the shortest representation, in exponent
// form ("1e+21", "1e-05") when the exponent is < -4 or >= 21.
fn go_float_v(f: f64) -> String {
    if f == 0.0 || !f.is_finite() {
        return format!("{f}");
    }
    let sci = format!("{f:e}");
    let (mant, exp) = sci.split_once('e').expect("{:e} always has an exponent");
    let exp: i32 = exp.parse().expect("{:e} exponent is an integer");
    if (-4..21).contains(&exp) {
        return format!("{f}");
    }
    let sign = if exp < 0 { '-' } else { '+' };
    format!("{mant}e{sign}{:02}", exp.abs())
}

/// Client, Go's `coolify.Client`.
pub struct Client {
    base_url: String,
    token: String,
    agent: ureq::Agent,
}

impl Client {
    /// new, Go's `coolify.New`: a 30 s timeout, and redirects followed with
    /// the Authorization header stripped on EVERY hop (Go's CheckRedirect;
    /// ureq's default `RedirectAuthHeaders::Never` does the same). Go's
    /// client follows up to 10.
    pub fn new(base_url: &str, token: &str) -> Client {
        let agent = ureq::AgentBuilder::new()
            .tls_config(crate::store::tls_config())
            .timeout(Duration::from_secs(30))
            .redirects(10)
            .build();
        Client {
            base_url: base_url.to_string(),
            token: token.to_string(),
            agent,
        }
    }

    // request, Go's `doBytes`: one request carrying the JSON `body`, or no
    // body at all (Go passes nil for start, deploy, the GETs and DELETE); the
    // Content-Type header is set either way. A status >= 400 is an error
    // carrying the (cut) body; otherwise the body is returned.
    fn request(&self, method: &str, path: &str, body: Option<&str>) -> Result<Vec<u8>, ReqError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self
            .agent
            .request(method, &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json")
            .set("User-Agent", "curl/8");
        let sent = match body {
            Some(raw) => req.send_bytes(raw.as_bytes()),
            None => req.call(),
        };
        match sent {
            Ok(resp) => {
                let mut bytes = Vec::new();
                let _ = resp.into_reader().read_to_end(&mut bytes);
                Ok(bytes)
            }
            Err(ureq::Error::Status(status, resp)) => {
                let mut bytes = Vec::new();
                let _ = resp.into_reader().read_to_end(&mut bytes);
                Err(ReqError::Status(
                    status,
                    http_error_text(method, path, status, &bytes),
                ))
            }
            // Go wraps a *url.Error: `<Op> "<url>": <cause>`, Op being the
            // method in title case. The cause is ureq's own text, not Go's
            // net error (not reproducible: Go names the resolved address).
            Err(ureq::Error::Transport(t)) => {
                let mut op = method[..1].to_string();
                op.push_str(&method[1..].to_ascii_lowercase());
                Err(ReqError::Other(format!(
                    "{method} {path}: {op} {}: {t}",
                    quote(&url)
                )))
            }
        }
    }

    // do_bytes, `request` with a JSON body marshalled like Go's json.Marshal.
    fn do_bytes<T: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<Vec<u8>, ReqError> {
        let raw =
            gojson::to_string(body).map_err(|e| ReqError::Other(format!("marshal body: {e}")))?;
        self.request(method, path, Some(&raw))
    }

    // do_object, Go's `do`: the 2xx body decoded as a JSON object; anything
    // else (not JSON, an array, null) decodes to Go's nil map, printed "map[]".
    fn do_object(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Map<String, Value>, ReqError> {
        let bytes = self.request(method, path, body)?;
        Ok(match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Object(m)) => m,
            _ => Map::new(),
        })
    }

    // do_raw, Go's `doRaw`: a top-level JSON array, or the array under an
    // object's "data"; any other 2xx body is an EMPTY list, not an error.
    fn do_raw(&self, method: &str, path: &str) -> Result<Vec<Value>, ReqError> {
        let bytes = self.request(method, path, None)?;
        Ok(match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Array(a)) => a,
            Ok(Value::Object(mut m)) => match m.remove("data") {
                Some(Value::Array(a)) => a,
                _ => Vec::new(),
            },
            _ => Vec::new(),
        })
    }

    // created_uuid, the "uuid" string of a create's answer, or Go's error
    // naming the whole answer.
    fn created_uuid(func: &str, resp: Map<String, Value>) -> Result<String, String> {
        match resp.get("uuid").and_then(Value::as_str) {
            Some(u) if !u.is_empty() => Ok(u.to_string()),
            _ => Err(format!(
                "coolify.{func}: no uuid in response: {}",
                go_fmt_v(&Value::Object(resp))
            )),
        }
    }

    /// create_docker_compose_app, Go's `CreateDockerComposeApp`: the compose
    /// text as standard base64. The project/server uuids are NOT checked.
    pub fn create_docker_compose_app(
        &self,
        project_uuid: &str,
        server_uuid: &str,
        name: &str,
        compose: &[u8],
    ) -> Result<String, String> {
        let body = ComposeBody {
            docker_compose_raw: gobase64::std_encode(compose),
            name,
            project_uuid,
            server_uuid,
        };
        let raw = gojson::to_string(&body).map_err(|e| format!("marshal body: {e}"))?;
        let resp = self
            .do_object("POST", "/applications/dockercompose", Some(&raw))
            .map_err(|e| format!("coolify.CreateDockerComposeApp: {e}"))?;
        Self::created_uuid("CreateDockerComposeApp", resp)
    }

    /// create_private_github_app_app, Go's `CreatePrivateGitHubAppApp`: an
    /// empty base directory is sent as "/".
    pub fn create_private_github_app_app(&self, req: &GitHubApp<'_>) -> Result<String, String> {
        let body = GitHubBody {
            base_directory: if req.base_directory.is_empty() {
                "/"
            } else {
                req.base_directory
            },
            build_pack: req.build_pack,
            dockerfile_location: req.dockerfile_location,
            environment_name: "production",
            git_branch: req.git_branch,
            git_repository: req.git_repository,
            github_app_uuid: req.github_app_uuid,
            instant_deploy: req.instant_deploy,
            name: req.name,
            ports_exposes: req.ports,
            project_uuid: req.project_uuid,
            server_uuid: req.server_uuid,
            watch_paths: req.watch_paths,
        };
        let raw = gojson::to_string(&body).map_err(|e| format!("marshal body: {e}"))?;
        let resp = self
            .do_object("POST", "/applications/private-github-app", Some(&raw))
            .map_err(|e| format!("coolify.CreatePrivateGitHubAppApp: {e}"))?;
        Self::created_uuid("CreatePrivateGitHubAppApp", resp)
    }

    /// set_build_args, Go's `SetBuildArgs`: every "KEY=VALUE" pair upserted
    /// as a BUILD-time env, in the order given; a pair with no '=' or an
    /// empty key is skipped silently.
    pub fn set_build_args(&self, app_uuid: &str, pairs: &[String]) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        for p in pairs {
            let Some((key, val)) = p.split_once('=') else {
                continue;
            };
            if key.is_empty() {
                continue;
            }
            self.upsert_app_env(app_uuid, key, val, true)
                .map_err(|e| format!("coolify.SetBuildArgs[{key}]: {e}"))?;
        }
        Ok(())
    }

    /// trigger_deploy, Go's `TriggerDeploy`: `GET /deploy?uuid=<uuid>`.
    pub fn trigger_deploy(&self, app_uuid: &str) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        self.request("GET", &format!("/deploy?uuid={app_uuid}"), None)
            .map(|_| ())
            .map_err(|e| format!("coolify.TriggerDeploy: {e}"))
    }

    /// start_app, Go's `StartApp`: a POST without a body.
    pub fn start_app(&self, app_uuid: &str) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        self.do_object("POST", &format!("/applications/{app_uuid}/start"), None)
            .map(|_| ())
            .map_err(|e| format!("coolify.StartApp: {e}"))
    }

    /// list_applications, Go's `ListApplications`: the JSON objects of the
    /// list, anything else in it dropped.
    pub fn list_applications(&self) -> Result<Vec<Map<String, Value>>, String> {
        let items = self
            .do_raw("GET", "/applications")
            .map_err(|e| format!("coolify.ListApplications: {e}"))?;
        Ok(items
            .into_iter()
            .filter_map(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .collect())
    }

    /// list_app_envs, Go's `ListAppEnvs`.
    pub fn list_app_envs(&self, app_uuid: &str) -> Result<Vec<EnvEntry>, String> {
        validate_uuid("appUUID", app_uuid)?;
        let items = self
            .do_raw("GET", &format!("/applications/{app_uuid}/envs"))
            .map_err(|e| format!("coolify.ListAppEnvs: {e}"))?;
        Ok(items
            .iter()
            .filter_map(|v| v.as_object().map(EnvEntry::from_object))
            .collect())
    }

    /// delete_app_env, Go's `DeleteAppEnv`: by the entry's uuid, both uuids
    /// checked first.
    pub fn delete_app_env(&self, app_uuid: &str, env_uuid: &str) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        validate_uuid("envUUID", env_uuid)?;
        self.request(
            "DELETE",
            &format!("/applications/{app_uuid}/envs/{env_uuid}"),
            None,
        )
        .map(|_| ())
        .map_err(|e| format!("coolify.DeleteAppEnv[{env_uuid}]: {e}"))
    }

    /// update_app_envs, Go's `UpdateAppEnvs`: every key upserted as a runtime
    /// env. Go ranges over a map, so its order is random; here it is sorted.
    /// Only which failing key is named can differ, and only when several fail.
    pub fn update_app_envs(
        &self,
        app_uuid: &str,
        envs: &BTreeMap<String, String>,
    ) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        for (key, val) in envs {
            self.upsert_app_env(app_uuid, key, val, false)
                .map_err(|e| format!("coolify.UpdateAppEnvs[{key}]: {e}"))?;
        }
        Ok(())
    }

    /// upsert_app_env, Go's `UpsertAppEnv`: POST, and on a 409 (the key
    /// exists) PATCH the same body.
    pub fn upsert_app_env(
        &self,
        app_uuid: &str,
        key: &str,
        value: &str,
        is_buildtime: bool,
    ) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        let body = EnvBody {
            is_buildtime,
            is_literal: true,
            is_preview: false,
            key,
            value,
        };
        let path = format!("/applications/{app_uuid}/envs");
        match self.do_bytes("POST", &path, &body) {
            Ok(_) => Ok(()),
            Err(ReqError::Status(409, _)) => self
                .do_bytes("PATCH", &path, &body)
                .map(|_| ())
                .map_err(|e| format!("coolify.UpsertAppEnv[{key}] PATCH after 409: {e}")),
            Err(e) => Err(format!("coolify.UpsertAppEnv[{key}] POST: {e}")),
        }
    }

    /// set_custom_labels, Go's `SetCustomLabels`: the labels joined with "\n",
    /// standard base64, PATCHed onto the application.
    pub fn set_custom_labels(&self, app_uuid: &str, labels: &[String]) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        let body = LabelsBody {
            custom_labels: gobase64::std_encode(labels.join("\n").as_bytes()),
        };
        self.do_bytes("PATCH", &format!("/applications/{app_uuid}"), &body)
            .map(|_| ())
            .map_err(|e| format!("coolify.SetCustomLabels: {e}"))
    }
}
