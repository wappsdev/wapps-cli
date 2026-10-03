// coolify, the Coolify v4 REST client — the port of `internal/coolify`
// (client.go, envs.go) for the calls `coolify update-env` and `coolify
// set-labels` make. Errors are Go's error TEXT: the verbs print them as they
// are, so the wrapping chain ("coolify.UpdateAppEnvs[K]: coolify.UpsertAppEnv[K]
// POST: POST /applications/<uuid>/envs: HTTP 500: <body>") is part of the
// contract and is measured by the pty differential against a fake Coolify API.
//
// Not ported yet (slice 6, later parts): create/start/deploy, ListApplications,
// ListAppEnvs, DeleteAppEnv, SetBuildArgs.
use crate::gobase64;
use crate::gojson;
use crate::gostrconv::{quote, quote_rune};
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

    // do_bytes, Go's `doBytes`: one JSON request; a status >= 400 is an error
    // carrying the (cut) body. The success body is not used by any caller.
    fn do_bytes<T: serde::Serialize>(
        &self,
        method: &str,
        path: &str,
        body: &T,
    ) -> Result<(), ReqError> {
        let raw =
            gojson::to_string(body).map_err(|e| ReqError::Other(format!("marshal body: {e}")))?;
        let url = format!("{}{}", self.base_url, path);
        let req = self
            .agent
            .request(method, &url)
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json")
            .set("User-Agent", "curl/8");
        match req.send_bytes(raw.as_bytes()) {
            Ok(_) => Ok(()),
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
            self.upsert_app_env(app_uuid, key, val)
                .map_err(|e| format!("coolify.UpdateAppEnvs[{key}]: {e}"))?;
        }
        Ok(())
    }

    // upsert_app_env, Go's `UpsertAppEnv` with isBuildtime=false: POST, and on
    // a 409 (the key exists) PATCH the same body.
    fn upsert_app_env(&self, app_uuid: &str, key: &str, value: &str) -> Result<(), String> {
        validate_uuid("appUUID", app_uuid)?;
        let body = EnvBody {
            is_buildtime: false,
            is_literal: true,
            is_preview: false,
            key,
            value,
        };
        let path = format!("/applications/{app_uuid}/envs");
        match self.do_bytes("POST", &path, &body) {
            Ok(()) => Ok(()),
            Err(ReqError::Status(409, _)) => self
                .do_bytes("PATCH", &path, &body)
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
            .map_err(|e| format!("coolify.SetCustomLabels: {e}"))
    }
}
