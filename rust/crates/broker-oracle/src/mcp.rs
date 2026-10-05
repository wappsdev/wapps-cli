//! The MCP transcript runner (seam 2).
//!
//! Drives a stdio MCP server from a script and writes what crossed the pipe:
//! `in <request>` for every line it sent, `out <line>` for every line the server
//! wrote while that request was outstanding, the answer last.
//!
//! One request at a time, on purpose. The plugin answers concurrent requests in
//! whatever order they finish (measured: `agent_await` sent fourth answered
//! before `orchestrator_claim` sent second), so a transcript of pipelined
//! requests would record a race, not a behaviour.
//!
//! A script step is one of:
//!
//! - `{"notify": method, "params"?}`: a notification; nothing is awaited.
//! - `{"call": method, "params"?}`: a request; its view is `result` (or `error`).
//! - `{"tool": name, "arguments"?}`: a `tools/call`; its view is the JSON inside
//!   the first `text` content when it parses, otherwise `result` (or `error`).
//!
//! and may carry `capture` (`{var: dot.path}` into the view, used later as
//! `{{var}}` in params or arguments), `until` (a subset pattern the view must
//! match: the same request, with the same id, is repeated every `poll_ms` until
//! it does, and only the final exchange is written), and `timeout_ms`.
//! Ids count from 0, one per request step.
//!
//! The server is started with an empty environment plus `env`, so a transcript
//! never depends on the shell that ran it. After the script its stdin is closed
//! and, if it has not exited within a grace period, it is killed: the plugin's
//! stdio server never exits on its own.

use crate::template::{fill, matches, pointer_lookup};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub notify: Option<String>,
    pub call: Option<String>,
    pub tool: Option<String>,
    pub params: Option<Value>,
    pub arguments: Option<Value>,
    #[serde(default)]
    pub capture: BTreeMap<String, String>,
    pub until: Option<Value>,
    pub poll_ms: Option<u64>,
    pub timeout_ms: Option<u64>,
}

pub struct Server {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// The server's whole environment.
    pub env: Vec<(String, String)>,
}

const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_POLL_MS: u64 = 250;
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// Kills the server however the run ends.
struct Running {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Drop for Running {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let deadline = Instant::now() + EXIT_GRACE;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_reader(stdout: impl std::io::Read + Send + 'static) -> Receiver<Option<String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
                Ok(_) => {
                    if line.ends_with(b"\n") {
                        line.pop();
                    }
                    if tx
                        .send(Some(String::from_utf8_lossy(&line).into_owned()))
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }
    });
    rx
}

fn view(is_tool: bool, response: &Value) -> Value {
    if let Some(error) = response.get("error") {
        return error.clone();
    }
    let result = response.get("result").cloned().unwrap_or(Value::Null);
    if is_tool {
        if let Some(text) = result.pointer("/content/0/text").and_then(Value::as_str) {
            if let Ok(inner) = serde_json::from_str::<Value>(text) {
                return inner;
            }
        }
    }
    result
}

/// Sends one request and collects lines until its answer: (lines, answer).
fn exchange(
    stdin: &mut ChildStdin,
    output: &Receiver<Option<String>>,
    request: &str,
    id: u64,
    deadline: Instant,
) -> Result<(Vec<String>, Value), String> {
    writeln!(stdin, "{request}")
        .and_then(|()| stdin.flush())
        .map_err(|e| format!("cannot write to the server: {e}"))?;
    let mut lines = vec![format!("in {request}")];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match output.recv_timeout(left) {
            Ok(Some(line)) => {
                let parsed: Option<Value> = serde_json::from_str(&line).ok();
                lines.push(format!("out {line}"));
                if let Some(frame) = parsed {
                    let answers = frame.get("id").and_then(Value::as_u64) == Some(id)
                        && (frame.get("result").is_some() || frame.get("error").is_some());
                    if answers {
                        return Ok((lines, frame));
                    }
                }
            }
            Ok(None) | Err(RecvTimeoutError::Disconnected) => {
                return Err("the server closed its stdout before answering".to_string())
            }
            Err(RecvTimeoutError::Timeout) => {
                return Err("no answer before the timeout".to_string())
            }
        }
    }
}

pub fn run(server: &Server, script: &[Step]) -> Result<String, String> {
    let mut child = Command::new(&server.program)
        .args(&server.args)
        .current_dir(&server.cwd)
        .env_clear()
        .envs(server.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", server.program.display()))?;
    let output = spawn_reader(child.stdout.take().ok_or("no stdout")?);
    let stdin = child.stdin.take();
    let mut running = Running { child, stdin };
    let stdin = running.stdin.as_mut().ok_or("no stdin")?;

    let mut vars = Map::new();
    let mut transcript = String::new();
    let mut next_id = 0u64;
    for (index, step) in script.iter().enumerate() {
        let n = index + 1;
        let lookup_vars = Value::Object(vars.clone());
        let lookup = pointer_lookup(&lookup_vars);
        let at = |e: String| format!("step {n} ({}): {e}", describe(step));
        if let Some(method) = &step.notify {
            let mut frame = json!({"jsonrpc": "2.0", "method": method});
            if let Some(params) = &step.params {
                frame["params"] = fill(params, &lookup).map_err(at)?;
            }
            let line = frame.to_string();
            writeln!(stdin, "{line}")
                .and_then(|()| stdin.flush())
                .map_err(|e| at(e.to_string()))?;
            transcript.push_str(&format!("in {line}\n"));
            continue;
        }
        let id = next_id;
        next_id += 1;
        let (method, params, is_tool) = match (&step.call, &step.tool) {
            (Some(method), None) => (
                method.clone(),
                step.params
                    .as_ref()
                    .map(|p| fill(p, &lookup))
                    .transpose()
                    .map_err(at)?,
                false,
            ),
            (None, Some(tool)) => {
                let arguments =
                    fill(step.arguments.as_ref().unwrap_or(&json!({})), &lookup).map_err(at)?;
                (
                    "tools/call".to_string(),
                    Some(json!({"name": tool, "arguments": arguments})),
                    true,
                )
            }
            _ => {
                return Err(at(
                    "a step is exactly one of notify, call or tool".to_string()
                ))
            }
        };
        let mut frame = json!({"jsonrpc": "2.0", "id": id, "method": method});
        if let Some(params) = params {
            frame["params"] = params;
        }
        let request = frame.to_string();
        let deadline =
            Instant::now() + Duration::from_millis(step.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS));
        let poll = Duration::from_millis(step.poll_ms.unwrap_or(DEFAULT_POLL_MS));
        let mut last: Option<Value> = None;
        let never = |until: &Value, last: &Value| {
            format!("never reached {until}; last answer {}", view(is_tool, last))
        };
        let (lines, answer) = loop {
            let (lines, answer) = match exchange(stdin, &output, &request, id, deadline) {
                Ok(done) => done,
                Err(e) => match (&step.until, &last) {
                    (Some(until), Some(last)) => return Err(at(never(until, last))),
                    _ => return Err(at(e)),
                },
            };
            let Some(until) = &step.until else {
                break (lines, answer);
            };
            if matches(until, &view(is_tool, &answer)) {
                break (lines, answer);
            }
            if Instant::now() + poll >= deadline {
                return Err(at(never(until, &answer)));
            }
            last = Some(answer);
            std::thread::sleep(poll);
        };
        for line in lines {
            transcript.push_str(&line);
            transcript.push('\n');
        }
        let seen = view(is_tool, &answer);
        for (var, path) in &step.capture {
            let value = pointer_lookup(&seen)(path)
                .ok_or_else(|| at(format!("capture {var}: {path} is missing from {seen}")))?;
            vars.insert(var.clone(), value);
        }
    }
    Ok(transcript)
}

fn describe(step: &Step) -> String {
    step.notify
        .as_deref()
        .or(step.call.as_deref())
        .or(step.tool.as_deref())
        .unwrap_or("?")
        .to_string()
}
