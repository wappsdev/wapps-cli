//! The fake cloud broker (seam 3, and the Worker side of seam 2).
//!
//! It answers from recorded exchanges of the real Worker, never from rules of
//! its own: a fake that decided what the cloud says would be a third definition
//! of the broker beside the plugin and the Worker (§6). The committed fixture,
//! `fixtures/cloud/surface-transcript.json`, is the platform's frozen surface
//! transcript (the 37 routes played through the real route table), cut by
//! `docs/broker-daemon-port.measure/cloud_fixture.py` to what is served.
//!
//! Exchanges are a storyline: a request is answered by the FIRST unconsumed
//! exchange with the same method, path (with its query) and body, the body
//! compared as JSON when both sides parse. A request nothing matches gets a 501
//! `ORACLE_UNMATCHED`, so a daemon that strays from the recording fails loudly
//! instead of being told something plausible.
//!
//! Every request is recorded: method, path, header NAMES, whether both Access
//! headers were present, the body, which exchange answered it, and whether the
//! service-token secret appeared anywhere but its own header. Header values are
//! never kept.
//!
//! HTTP/1.1 over `std::net`, one connection at a time, `Connection: close`:
//! sequential on purpose, so the record's order is the order of the requests.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    /// The request body as the recording sent it; `None` for no body.
    pub body: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Envelope {
    #[serde(rename = "contentType")]
    pub content_type: String,
    #[serde(rename = "retryAfter")]
    pub retry_after: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Exchange {
    pub id: String,
    /// The route pattern (`POST /v1/missions/:mission/jobs`).
    #[serde(default)]
    pub route: String,
    /// The Access principal the recording ran as.
    #[serde(default)]
    pub principal: Option<String>,
    pub request: Request,
    pub status: u16,
    pub envelope: Envelope,
    /// The answer's body, byte for byte.
    pub body: String,
}

#[derive(Deserialize)]
pub struct Fixture {
    pub provenance: Value,
    pub exchanges: Vec<Exchange>,
}

impl Fixture {
    pub fn load(path: &Path) -> io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text).map_err(io::Error::other)
    }
}

/// One request as the fake saw it.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    /// Header names, lower-cased and sorted. Never values.
    pub headers: Vec<String>,
    /// Both `CF-Access-Client-Id` and `CF-Access-Client-Secret` were sent.
    pub access: bool,
    pub body: String,
    /// The id of the exchange that answered, or `None` for a 501.
    pub answered: Option<String>,
    /// The configured secret appeared in the path, the body, or any header
    /// other than `CF-Access-Client-Secret`.
    pub leaked: bool,
}

struct State {
    exchanges: Vec<(Exchange, bool)>,
    recorded: Vec<Recorded>,
    secret: Option<String>,
}

pub struct FakeCloud {
    url: String,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeCloud {
    /// Listens on 127.0.0.1 at a free port. `secret` is the service-token
    /// secret whose appearance outside its header is flagged as a leak.
    pub fn start(exchanges: Vec<Exchange>, secret: Option<String>) -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        let state = Arc::new(Mutex::new(State {
            exchanges: exchanges.into_iter().map(|e| (e, false)).collect(),
            recorded: Vec::new(),
            secret,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    if let Ok(stream) = stream {
                        let _ = serve(stream, &state);
                    }
                }
            })
        };
        Ok(Self {
            url,
            state,
            stop,
            thread: Some(thread),
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.state
            .lock()
            .map(|s| s.recorded.clone())
            .unwrap_or_default()
    }

    /// Ids of the exchanges no request consumed.
    pub fn unanswered(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| {
                s.exchanges
                    .iter()
                    .filter(|(_, used)| !used)
                    .map(|(e, _)| e.id.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Drop for FakeCloud {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wakes the blocking accept so the thread sees the flag.
        let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn bodies_match(recorded: Option<&str>, got: &str) -> bool {
    let Some(recorded) = recorded else {
        return got.trim().is_empty();
    };
    match (
        serde_json::from_str::<Value>(recorded),
        serde_json::from_str::<Value>(got),
    ) {
        (Ok(want), Ok(have)) => want == have,
        _ => recorded == got,
    }
}

fn reason(status: u16) -> &'static str {
    if (200..300).contains(&status) {
        "OK"
    } else {
        "Oracle"
    }
}

fn serve(stream: TcpStream, state: &Mutex<State>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut start = String::new();
    reader.read_line(&mut start)?;
    let mut parts = start.split_whitespace();
    let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
        return Ok(());
    };
    let (method, path) = (method.to_string(), path.to_string());
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let chunked = header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    let length: usize = header("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8_lossy(&body).into_owned();

    let (status, content_type, retry_after, answer) = {
        let mut state = state.lock().map_err(|_| io::Error::other("poisoned"))?;
        let leaked = state.secret.as_deref().is_some_and(|secret| {
            path.contains(secret)
                || body.contains(secret)
                || headers
                    .iter()
                    .any(|(n, v)| n != "cf-access-client-secret" && v.contains(secret))
        });
        let found = if chunked {
            None
        } else {
            state.exchanges.iter_mut().find(|(e, used)| {
                !*used
                    && e.request.method == method
                    && e.request.path == path
                    && bodies_match(e.request.body.as_deref(), &body)
            })
        };
        let reply = match found {
            Some((exchange, used)) => {
                *used = true;
                (
                    Some(exchange.id.clone()),
                    exchange.status,
                    exchange.envelope.content_type.clone(),
                    exchange.envelope.retry_after.clone(),
                    exchange.body.clone(),
                )
            }
            None => {
                let why = if chunked {
                    "a chunked body is not supported by the oracle"
                } else {
                    "no recorded exchange for this method, path and body"
                };
                (
                    None,
                    501,
                    "application/json; charset=utf-8".to_string(),
                    None,
                    serde_json::json!({"error": "ORACLE_UNMATCHED", "message": why, "method": method, "path": path})
                        .to_string(),
                )
            }
        };
        let mut names: Vec<String> = headers.iter().map(|(n, _)| n.clone()).collect();
        names.sort();
        state.recorded.push(Recorded {
            access: header("cf-access-client-id").is_some()
                && header("cf-access-client-secret").is_some(),
            method: method.clone(),
            path: path.clone(),
            headers: names,
            body,
            answered: reply.0,
            leaked,
        });
        (reply.1, reply.2, reply.3, reply.4)
    };

    let mut out = format!(
        "HTTP/1.1 {status} {}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
        reason(status),
        answer.len()
    );
    if let Some(retry) = retry_after {
        out.push_str(&format!("retry-after: {retry}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(&answer);
    let mut stream = stream;
    stream.write_all(out.as_bytes())?;
    stream.flush()
}
