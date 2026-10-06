//! Residual owner cloud boundaries through the real Rust binary and synthetic PTYs.
//! These exchanges test client behavior, not Access signatures or deployed grants.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

// Unsigned synthetic cache token. Only the real Access edge verifies authority.
const TOKEN: &str = "eyJhbGciOiJub25lIn0.eyJlbWFpbCI6Im93bmVyQGV4YW1wbGUudGVzdCIsImV4cCI6NDEwMjQ0NDgwMH0.b3duZXItc2lnbmF0dXJl";
const AGENT: &str = "boundary-agent-secret-never-owner";
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[derive(Deserialize)]
struct Corpus {
    preflights: std::collections::HashMap<String, Value>,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    id: String,
    group: String,
    args: Vec<String>,
    preflight: Option<String>,
    mutation: Option<Mutation>,
    reply: Option<Reply>,
    outcome: Outcome,
    #[serde(default)]
    stderr_contains: Vec<String>,
}
#[derive(Deserialize)]
struct Mutation {
    path: String,
    body: Value,
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Success,
    Refused,
    Unknown,
}
#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Reply {
    Json { status: u16, body: Value },
    CloseAfterRequest,
    TruncatedJson { body: Value },
}

struct Home(PathBuf);
impl Home {
    fn new(endpoint: &str) -> Self {
        // Construct the guard first so even a setup panic cleans the private root.
        let home = Self(broker_oracle::hermetic::temp_root(&format!(
            "owner-boundary-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        fs::create_dir_all(home.0.join("project")).unwrap();
        fs::create_dir_all(home.0.join(".config/wapps-broker")).unwrap();
        fs::write(
            home.0.join(".config/wapps-broker/client.yaml"),
            format!("clientId: agent-only\nendpoint: {endpoint}\n"),
        )
        .unwrap();
        fs::write(home.0.join(".config/wapps-broker/agents.secret"), AGENT).unwrap();
        wapps::session::save_with(
            &|key| (key == "HOME").then(|| home.0.to_string_lossy().into_owned()),
            &wapps::session::host_of(endpoint),
            &wapps::session::State {
                token: TOKEN.into(),
                expires_at: 4102444800,
            },
        )
        .unwrap();
        home
    }
    fn run(&self, args: &[String]) -> Output {
        let mut argv = vec![env!("CARGO_BIN_EXE_wapps"), "broker"];
        argv.extend(args.iter().map(String::as_str));
        let spec = json!({
            "argv": argv,
            "env": {"HOME": self.0, "PATH": "/usr/bin:/bin", "WAPPS_NO_UPDATE_CHECK": "1"},
            "cwd": self.0.join("project")
        });
        // ptyrun.py supplies independent stdin/stdout/stderr PTYs, drains them,
        // and kills/reaps the binary on timeout. The guard also reaps the driver
        // if writing its input fails. Neither process inherits the real HOME.
        let mut driver = Driver(
            Command::new("python3")
                .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pty/ptyrun.py"))
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.0)
                .current_dir(self.0.join("project"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        driver
            .0
            .stdin
            .take()
            .unwrap()
            .write_all(spec.to_string().as_bytes())
            .unwrap();
        // Drain the small JSON result before wait; the driver owns the binary's
        // output pipes and timeout, so no child is left running after a case.
        let mut raw = String::new();
        driver
            .0
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut raw)
            .unwrap();
        let status = driver.0.wait().unwrap();
        assert!(status.success(), "PTY driver failed: {status}");
        let raw: Value = serde_json::from_str(&raw).expect("PTY driver's JSON result");
        let decode = |key: &str| {
            let hex = raw[key].as_str().unwrap();
            String::from_utf8(
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
            )
            .unwrap()
        };
        let output = Output {
            exit: raw["exit"].as_i64().unwrap(),
            stdout: decode("stdout_hex"),
            stderr: decode("stderr_hex"),
        };
        for secret in [TOKEN, AGENT].into_iter().chain(TOKEN.split('.')) {
            assert!(
                !output.stdout.contains(secret) && !output.stderr.contains(secret),
                "synthetic credential leaked"
            );
        }
        output
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("clean synthetic owner home");
    }
}
struct Driver(Child);
impl Drop for Driver {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
struct Output {
    exit: i64,
    stdout: String,
    stderr: String,
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
}
fn read_request(stream: &TcpStream) -> std::io::Result<Request> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let words: Vec<_> = first.split_whitespace().collect();
    if words.len() != 3 {
        return Err(std::io::Error::other("invalid HTTP request line"));
    }
    let mut headers = vec![];
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| std::io::Error::other("invalid HTTP request header"))?;
        let key = key.to_ascii_lowercase();
        let value = value.trim().to_string();
        if key == "content-length" {
            length = value
                .parse::<usize>()
                .map_err(|_| std::io::Error::other("invalid content length"))?;
        }
        headers.push((key, value));
    }
    if length > 64 * 1024 {
        return Err(std::io::Error::other("unexpectedly large boundary request"));
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let body = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).map_err(std::io::Error::other)?
    };
    Ok(Request {
        method: words[0].into(),
        path: words[1].into(),
        headers,
        body,
    })
}
fn respond(stream: &mut TcpStream, reply: Reply) -> std::io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    match reply {
        Reply::CloseAfterRequest => {
            // The complete mutation request has already been captured. Losing
            // its response tells the client nothing about whether it committed.
            stream.shutdown(Shutdown::Both)
        }
        Reply::Json { status, body } => {
            let body = body.to_string();
            write!(stream, "HTTP/1.1 {status} Result\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        }
        Reply::TruncatedJson { body } => {
            let body = body.to_string();
            write!(stream, "HTTP/1.1 200 Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())?;
            stream.write_all(&body.as_bytes()[..body.len() / 2])?;
            stream.shutdown(Shutdown::Both)
        }
    }
}
struct Cloud {
    endpoint: String,
    requests: Arc<Mutex<Vec<Request>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<std::io::Result<()>>>,
}
impl Cloud {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(vec![]));
        let captured = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(40);
            let mut replies = replies.into_iter();
            while !stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                stream.set_nonblocking(false)?;
                captured.lock().unwrap().push(read_request(&stream)?);
                // Keep listening after the planned reply, so any automatic retry,
                // lease fallback or result-consuming request is captured as well.
                let reply = replies.next().unwrap_or(Reply::Json {
                    status: 500,
                    body: json!({"error":"unexpected request"}),
                });
                respond(&mut stream, reply)?;
            }
            Ok(())
        });
        Self {
            endpoint,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn finish(mut self) -> Vec<Request> {
        self.stop.store(true, Ordering::Relaxed);
        self.thread
            .take()
            .unwrap()
            .join()
            .unwrap()
            .expect("loopback peer");
        std::mem::take(&mut *self.requests.lock().unwrap())
    }
}
impl Drop for Cloud {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_group(group: &str) {
    let corpus: Corpus =
        serde_json::from_str(include_str!("fixtures/broker-owner/boundary-cases.json")).unwrap();
    let cases: Vec<_> = corpus
        .cases
        .iter()
        .filter(|case| case.group == group)
        .collect();
    assert!(!cases.is_empty(), "no boundary cases for {group}");
    for case in cases {
        let mut replies = vec![];
        if let Some(key) = &case.preflight {
            replies.push(Reply::Json {
                status: 200,
                body: corpus.preflights.get(key).expect("known preflight").clone(),
            });
        }
        replies.extend(case.reply.clone());
        let cloud = Cloud::new(replies);
        let home = Home::new(&cloud.endpoint);
        let output = home.run(&case.args);
        let root = home.0.clone();
        drop(home);
        assert!(
            !root.exists(),
            "{}: synthetic HOME must be cleaned",
            case.id
        );
        let requests = cloud.finish();
        let expected_len =
            usize::from(case.preflight.is_some()) + usize::from(case.mutation.is_some());
        assert_eq!(
            requests.len(),
            expected_len,
            "{}: unexpected retry or route",
            case.id
        );
        assert!(
            requests.iter().filter(|r| r.method == "POST").count() <= 1,
            "{}: repeated mutation",
            case.id
        );
        for request in &requests {
            let tokens: Vec<_> = request
                .headers
                .iter()
                .filter(|(key, _)| key == "cf-access-token")
                .collect();
            assert_eq!(tokens.len(), 1, "{}: one owner token header", case.id);
            assert!(tokens[0].1 == TOKEN, "{}: wrong owner token", case.id);
            assert!(
                request.headers.iter().all(|(key, value)| {
                    !key.starts_with("cf-access-client-")
                        && !matches!(key.as_str(), "authorization" | "cookie")
                        && !value.contains(AGENT)
                }),
                "{}: only cached owner SSO may authenticate",
                case.id
            );
        }
        let mut index = 0;
        if case.preflight.is_some() {
            let request = &requests[index];
            assert_eq!(request.method, "GET", "{}", case.id);
            assert_eq!(
                request.path, "/v1/missions/selected/work/questions",
                "{}",
                case.id
            );
            assert_eq!(request.body, Value::Null, "{}", case.id);
            index += 1;
        }
        if let Some(mutation) = &case.mutation {
            let request = &requests[index];
            assert_eq!(request.method, "POST", "{}", case.id);
            assert_eq!(request.path, mutation.path, "{}", case.id);
            // Exact equality also rules out lease/capability or alternate target
            // fields. No GET job/result, claim door or lease acquisition fits.
            assert_eq!(request.body, mutation.body, "{}", case.id);
        }
        match case.outcome {
            Outcome::Success => {
                assert_eq!(output.exit, 0, "{}: {}", case.id, output.stderr);
                assert!(output.stderr.is_empty(), "{}: {}", case.id, output.stderr);
                let Some(Reply::Json { body, .. }) = &case.reply else {
                    panic!("{}: success needs a JSON acknowledgement", case.id);
                };
                assert_eq!(
                    serde_json::from_str::<Value>(&output.stdout).unwrap(),
                    *body,
                    "{}",
                    case.id
                );
            }
            Outcome::Refused | Outcome::Unknown => {
                assert_eq!(output.exit, 1, "{}: {}", case.id, output.stderr);
                assert!(
                    output.stdout.is_empty(),
                    "{}: no success output on failure",
                    case.id
                );
                if matches!(case.outcome, Outcome::Unknown) {
                    assert!(
                        output.stderr.contains("outcome may be unknown"),
                        "{}: {}",
                        case.id,
                        output.stderr
                    );
                }
                for expected in &case.stderr_contains {
                    assert!(
                        output.stderr.contains(expected),
                        "{}: missing {expected:?}: {}",
                        case.id,
                        output.stderr
                    );
                }
            }
        }
    }
}

// Removing the unique-selection guard would send a POST for these duplicates,
// even when only one duplicate belongs to the explicitly selected work item.
#[test]
fn duplicate_question_selection_never_mutates() {
    run_group("duplicate");
}
// Treating preflight as authority, swallowing a refusal, or replacing its target
// would lose the cloud's reason or add a request after the single exact POST.
#[test]
fn post_preflight_cloud_refusals_are_authoritative_and_not_retried() {
    run_group("refusal");
}
// Skipping question identity/channel checks or confirmation attribution would
// report success for these malformed replies; controls use real outward fields.
#[test]
fn question_acknowledgements_require_identity_channel_and_confirmation_attribution() {
    run_group("question_ack");
}
// Validating only the first row, ignoring length, or comparing sets instead of
// the platform's input order would accept a partial or reordered batch reply.
#[test]
fn multi_item_move_acknowledgements_are_complete_and_ordered() {
    run_group("move_ack");
}
// Retrying a POST after losing its response could duplicate a committed write;
// returning success instead would falsely claim the outcome is known.
#[test]
fn post_send_connection_loss_is_unknown_and_never_retried() {
    run_group("response_loss");
}
