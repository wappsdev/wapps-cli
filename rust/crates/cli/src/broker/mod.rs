//! Local stdio MCP bridge; cloud state and ownership remain authoritative.
mod config;
pub mod daemon;
mod forward;
pub mod owner;
use serde_json::{json, Value};
use std::{
    io::{BufRead, Read},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

const MAX_FRAME: u64 = 1024 * 1024;
const MAX_IN_FLIGHT: usize = 16;

// Extracted from wapps-platform dccbbf947fca45fc1a470e9d98eba15ad15dd8af,
// services/broker/test/frozen/mcp-transcript.json, tools/list result.
// Source SHA256: baf3ad7479f88a37ff924fba56e2dec6b6c0b0793f37a8fa3822a3c05f1e8abd.
fn catalog() -> Value {
    let mut catalog: Value =
        serde_json::from_str(include_str!("cloud-tools.json")).expect("frozen catalog");
    for tool in catalog["tools"].as_array_mut().expect("tools") {
        let schema = &mut tool["inputSchema"];
        schema["properties"]["missionId"] =
            json!({"type":"string","pattern":"^[a-z0-9][a-z0-9._-]{0,127}$","maxLength":128});
        if schema.get("required").is_none() {
            schema["required"] = json!([]);
        }
        schema["required"]
            .as_array_mut()
            .expect("required")
            .push(json!("missionId"));
        if tool["name"] == "agent_await" {
            tool["inputSchema"]["properties"]["waitMs"] =
                json!({"type":"integer","minimum":0,"maximum":55000});
            tool["description"] = json!("Poll this mission's attention every two seconds, for at most 55 seconds. Without sinceDigest, return immediately.");
        }
        if matches!(
            tool["name"].as_str(),
            Some("agent_submit" | "agent_cancel" | "agent_attach" | "agent_report")
        ) {
            tool["description"] = json!("Execution is not implemented in this slice. Always returns ACTION_UNAVAILABLE and does not change cloud state or launch a worker.");
        }
    }
    catalog
}

fn tool_error(code: &str, message: &str) -> Value {
    let error = json!({"error":code,"message":message,"retryable":false});
    json!({"isError":true,"content":[{"type":"text","text":error.to_string()}],"structuredContent":error})
}

// A partial frame poisons this session's output, including queued replies and
// the end trailer. Darwin can refuse shutdown(Both) after shutdown(Read).
struct OutputWriter {
    stream: std::os::unix::net::UnixStream,
    failed: bool,
}
impl OutputWriter {
    fn new(stream: std::os::unix::net::UnixStream) -> Self {
        Self {
            stream,
            failed: false,
        }
    }
    fn send(&mut self, value: Value) -> Result<(), String> {
        if self.failed {
            return Err("daemon output was interrupted; outcome may be unknown".into());
        }
        let result = daemon::send(&mut self.stream, value);
        self.failed = result.is_err();
        result
    }
}
type Output = Arc<Mutex<OutputWriter>>;

struct Pending {
    id: Value,
    cancelled: Arc<AtomicBool>,
    thread: JoinHandle<Result<(), String>>,
}

fn rpc_error(code: i32, message: &str) -> Value {
    json!({"error":{"code":code,"message":message}})
}

fn rpc_error_payload(value: &Value) -> Option<&Value> {
    // Validated CallToolResults always have content and may carry an extension
    // named error. Only our RPC-error wrappers omit content; never promote a
    // tool's application data to the response envelope or a polling decision.
    value
        .get("error")
        .filter(|_| value.get("content").is_none())
}

fn reply(output: &Output, id: &Value, result: Value) -> Result<(), String> {
    let response = if let Some(error) = rpc_error_payload(&result) {
        json!({"jsonrpc":"2.0","id":id,"error":error})
    } else {
        json!({"jsonrpc":"2.0","id":id,"result":result})
    };
    let mut out = output.lock().map_err(|_| "MCP output lock failed")?;
    out.send(response)
}

fn valid_id(id: &Value) -> bool {
    id.is_string() || id.is_i64() || id.is_u64()
}

pub fn serve() -> Result<(), String> {
    daemon::serve()
}

fn serve_connection(
    config: &Arc<config::Config>,
    input: &mut impl BufRead,
    output: &Output,
    session: Arc<daemon::Session>,
) -> Result<(), String> {
    let mut pending = Vec::<Pending>::new();
    let outcome = serve_frames(config, input, output, &mut pending, session);
    // EOF, oversize frames and output failure all terminate the outstanding polls.
    // A synchronous HTTP exchange can take at most its ten-second timeout.
    for call in &pending {
        call.cancelled.store(true, Ordering::Relaxed);
    }
    let mut outcome = outcome;
    for call in pending {
        if call
            .thread
            .join()
            .unwrap_or_else(|_| Err("MCP worker failed".into()))
            .is_err()
        {
            outcome = Err("MCP worker failed".into());
        }
    }
    outcome
}

fn serve_frames(
    config: &Arc<config::Config>,
    input: &mut impl BufRead,
    output: &Output,
    pending: &mut Vec<Pending>,
    session: Arc<daemon::Session>,
) -> Result<(), String> {
    let tools = catalog();
    loop {
        let mut line = Vec::new();
        let count = (&mut *input)
            .take(MAX_FRAME + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| "cannot read MCP stdin")?;
        if count == 0 {
            return Ok(());
        }
        if count as u64 > MAX_FRAME {
            return Err("MCP frame exceeds 1 MiB".into());
        }
        let request: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(_) => {
                reply(output, &Value::Null, rpc_error(-32700, "invalid JSON"))?;
                continue;
            }
        };
        let id = request.get("id");
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || !request["method"].is_string()
            || id.is_some_and(|id| !valid_id(id))
        {
            reply(output, &Value::Null, rpc_error(-32600, "invalid request"))?;
            continue;
        }
        let method = request["method"].as_str().expect("validated method");
        let Some(id) = id else {
            if method == "notifications/cancelled" {
                for call in pending.iter() {
                    if request["params"].get("requestId") == Some(&call.id) {
                        call.cancelled.store(true, Ordering::Relaxed);
                    }
                }
            }
            // Notifications never execute tools or produce responses.
            continue;
        };
        if id.as_str().is_some_and(|id| id.contains(&config.secret)) {
            reply(
                output,
                &Value::Null,
                rpc_error(-32600, "invalid request id"),
            )?;
            continue;
        }
        let mut index = 0;
        while index < pending.len() {
            if pending[index].thread.is_finished() {
                pending
                    .swap_remove(index)
                    .thread
                    .join()
                    .map_err(|_| "MCP worker failed")??;
            } else {
                index += 1;
            }
        }
        if pending.iter().any(|call| &call.id == id) {
            reply(
                output,
                &Value::Null,
                rpc_error(-32600, "request id already in flight"),
            )?;
            continue;
        }
        let result = match method {
            "initialize" => {
                json!({"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"wapps-broker","version":env!("CARGO_PKG_VERSION")}})
            }
            "ping" => json!({}),
            "tools/list" => tools.clone(),
            "tools/call" => {
                let name = request["params"]["name"].as_str().unwrap_or("");
                let args = request["params"]
                    .get("arguments")
                    .cloned()
                    .unwrap_or(json!({}));
                if !args.is_object()
                    || !tools["tools"]
                        .as_array()
                        .expect("catalog")
                        .iter()
                        .any(|t| t["name"] == name)
                {
                    rpc_error(-32602, "unknown tool or invalid arguments")
                } else if pending.len() >= MAX_IN_FLIGHT {
                    tool_error("SERVER_BUSY", "at most 16 calls may be in flight")
                } else {
                    let cancelled = Arc::new(AtomicBool::new(false));
                    let worker_cancel = Arc::clone(&cancelled);
                    let config = Arc::clone(config);
                    let output = Arc::clone(output);
                    let worker_id = id.clone();
                    let name = name.to_owned();
                    let session = Arc::clone(&session);
                    let thread = std::thread::spawn(move || {
                        let result = session.call(&config, &worker_id, &name, args, &worker_cancel);
                        reply(&output, &worker_id, result)
                    });
                    pending.push(Pending {
                        id: id.clone(),
                        cancelled,
                        thread,
                    });
                    continue;
                }
            }
            _ => rpc_error(-32601, "method not found"),
        };
        reply(output, id, result)?;
    }
}
