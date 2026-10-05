//! Owner-only HTTP: cached SSO, bounded reads, no redirects, proxy, retries or helper process.
use serde::Deserialize;
use serde_json::Value;
use std::{io::Read, net::ToSocketAddrs, path::Path, time::Duration};

const LIMIT: u64 = 4 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);
pub(super) struct Client {
    endpoint: url::Url,
    token: String,
    agent: ureq::Agent,
}
#[derive(Deserialize)]
struct Metadata {
    endpoint: Option<String>,
}
impl Client {
    pub fn load() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .ok_or("HOME is required")?;
        let path = Path::new(&home).join(".config/wapps-broker/client.yaml");
        let endpoint = match std::fs::read(path) {
            Ok(raw) => {
                serde_yaml_ng::from_slice::<Metadata>(&raw)
                    .map_err(|_| "invalid broker client metadata")?
                    .endpoint
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err("cannot read broker client metadata".into()),
        }
        .unwrap_or_else(|| "https://broker.meapps.dev".into());
        let endpoint = url::Url::parse(&endpoint).map_err(|_| "invalid broker endpoint")?;
        if !(endpoint.scheme() == "https"
            || endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("127.0.0.1" | "[::1]")))
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(
                "broker endpoint must be an HTTPS origin (HTTP only on numeric loopback)".into(),
            );
        }
        // Reuse the shipped session cache, but NOT its key-independent environment
        // token or the agent's service-token fallback. The owner logs in explicitly
        // with WAPPS_SECRETS_GATE=https://broker.meapps.dev wapps login.
        let session_env = |key: &str| match key {
            "HOME" | "XDG_CONFIG_HOME" => std::env::var(key).ok(),
            _ => None,
        };
        let state = crate::session::load_with(
            &session_env,
            &crate::session::host_of(endpoint.as_str()),
        )
        .ok_or("owner SSO session required; run WAPPS_SECRETS_GATE=https://broker.meapps.dev wapps login in a human terminal")?;
        let claims =
            crate::session::parse_claims(&state.token).map_err(|_| "invalid owner SSO session")?;
        if !crate::loginverb::looks_like_jwt(&state.token)
            || claims.email.is_empty()
            || state.token.len() > 16_384
        {
            return Err("owner SSO session must be a human app token".into());
        }
        if state.expired(crate::session::now().0) || claims.exp <= crate::session::now().0 {
            return Err("owner SSO session expired; log in again".into());
        }
        // Local claims are only a shape/expiry check. Access verifies signature,
        // audience and identity; the Worker enforces the owner's verb on each call.
        let host = endpoint
            .host_str()
            .expect("validated")
            .trim_matches(['[', ']'])
            .to_owned();
        let port = endpoint.port_or_known_default().expect("HTTP origin");
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = tx.send(
                (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|a| a.collect::<Vec<_>>()),
            );
        });
        let addresses = rx
            .recv_timeout(TIMEOUT)
            .map_err(|_| "broker DNS timed out")?
            .map_err(|_| "cannot resolve broker endpoint")?;
        if addresses.is_empty() {
            return Err("broker endpoint has no addresses".into());
        }
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .try_proxy_from_env(false)
            .resolver(move |_: &str| Ok(addresses.clone()))
            .build();
        Ok(Self {
            endpoint,
            token: state.token,
            agent,
        })
    }
    pub fn request(
        &self,
        mission: &str,
        route: &str,
        body: Option<&Value>,
    ) -> Result<Value, String> {
        if mission.contains(&self.token)
            || body.is_some_and(|body| body.to_string().contains(&self.token))
        {
            return Err("request contains the owner credential".into());
        }
        let mut url = self.endpoint.clone();
        url.path_segments_mut()
            .expect("origin")
            .clear()
            .extend(["v1", "missions", mission])
            .extend(route.split('/'));
        let request = self
            .agent
            .request(if body.is_some() { "POST" } else { "GET" }, url.as_str())
            .timeout(TIMEOUT)
            .set("CF-Access-Token", &self.token)
            .set("Accept", "application/json");
        let response = match body {
            Some(body) => request.send_json(body.clone()),
            None => request.call(),
        };
        let response = match response {
            Ok(response) if matches!(response.status(), 200 | 201) => response,
            Ok(response) => {
                return Err(format!(
                    "cloud HTTP {}; no redirect or retry was followed",
                    response.status()
                ))
            }
            Err(ureq::Error::Status(status, response)) => {
                let mut message = format!("cloud HTTP {status}; request refused, not retried");
                // Preserve the authoritative refusal and recovery, but never echo
                // an HTML login page or an unbounded/unparsed upstream response.
                if let Ok(mut value) = read_json(response) {
                    if value.is_object() {
                        self.redact(&mut value);
                        message.push_str(&format!("; {value}"));
                    }
                }
                return Err(message);
            }
            Err(ureq::Error::Transport(_)) => {
                return Err(
                    "cloud transport failed or timed out; outcome may be unknown; not retried"
                        .into(),
                )
            }
        };
        let value = read_json(response)?;
        if !value.is_object()
            || value.get("error").is_some()
            || value.get("code").is_some()
            || value.get("ok").is_some_and(|v| v != true)
        {
            return Err("cloud protocol: unexpected envelope; outcome may be unknown".into());
        }
        Ok(value)
    }
    pub fn redact(&self, value: &mut Value) {
        match value {
            Value::String(s) => *s = self.clean(s),
            Value::Array(values) => {
                for value in values {
                    self.redact(value);
                }
            }
            Value::Object(object) => {
                for (key, mut value) in std::mem::take(object) {
                    let lower = key.to_ascii_lowercase();
                    if [
                        "token",
                        "secret",
                        "password",
                        "credential",
                        "authorization",
                        "capability",
                        "apikey",
                        "api_key",
                        "api-key",
                    ]
                    .iter()
                    .any(|part| lower.contains(part))
                    {
                        value = Value::String("[REDACTED]".into());
                    } else {
                        self.redact(&mut value);
                    }
                    object.insert(self.clean(&key), value);
                }
            }
            _ => {}
        }
    }
    fn clean(&self, text: &str) -> String {
        let mut text = text.replace(&self.token, "[REDACTED]");
        for segment in self.token.split('.').filter(|s| s.len() >= 8) {
            text = text.replace(segment, "[REDACTED]");
        }
        text
    }
}

fn read_json(response: ureq::Response) -> Result<Value, String> {
    if response
        .header("Content-Type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        != "application/json"
    {
        return Err("cloud protocol: expected JSON; outcome may be unknown".into());
    }
    let mut bytes = vec![];
    response
        .into_reader()
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cloud response read failed; outcome may be unknown")?;
    if bytes.len() as u64 > LIMIT {
        return Err("cloud response exceeds 4 MiB; outcome may be unknown".into());
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| "cloud protocol: invalid JSON; outcome may be unknown".into())
}
