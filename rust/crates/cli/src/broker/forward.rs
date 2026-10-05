//! Stateless HTTP MCP calls. The Worker owns schemas, ownership and attention.
use super::{config::Config, rpc_error_payload, tool_error};
use serde_json::{json, Value};
use std::{
    io::Read,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);

pub(super) fn call(
    config: &Config,
    id: &Value,
    name: &str,
    mut args: Value,
    cancelled: &AtomicBool,
) -> Value {
    // Inspect decoded input before stripping routing metadata: the credential
    // must not reach either a request body or the mission's URL segment.
    if contains_secret(&args, &config.secret) || contains_secret(id, &config.secret) {
        return tool_error(
            "INVALID_ARGUMENT",
            "arguments contain the runtime credential",
        );
    }
    let Some(arguments) = args.as_object_mut() else {
        return tool_error("INVALID_ARGUMENT", "arguments must be an object");
    };
    let Some(Value::String(mission)) = arguments.remove("missionId") else {
        return tool_error("INVALID_ARGUMENT", "missionId is required on each call");
    };
    if !valid_mission(&mission) {
        return tool_error("INVALID_ARGUMENT", "invalid missionId");
    }
    if matches!(
        name,
        "agent_submit" | "agent_cancel" | "agent_attach" | "agent_report"
    ) {
        return tool_error(
            "ACTION_UNAVAILABLE",
            "Execution is not implemented in this slice; no worker was launched or changed",
        );
    }
    let wait = if name == "agent_await" {
        match arguments.remove("waitMs") {
            None => 55000,
            Some(v) => match v.as_u64() {
                Some(ms) if ms <= 55000 => ms,
                _ => {
                    return tool_error(
                        "INVALID_ARGUMENT",
                        "waitMs must be an integer from 0 to 55000",
                    )
                }
            },
        }
    } else {
        0
    };
    let waiting = name == "agent_await"
        && arguments.get("sinceDigest").is_some_and(Value::is_string)
        && wait > 0;
    let mut endpoint = config.endpoint.clone();
    endpoint
        .path_segments_mut()
        .expect("validated origin")
        .clear()
        .extend(["v1", "missions", &mission, "mcp"]);
    let addresses = config.addresses.clone();
    let agent = ureq::AgentBuilder::new()
        .resolver(move |_: &str| Ok(addresses.clone()))
        .redirects(0)
        .try_proxy_from_env(false)
        .build();
    let request = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":args}});
    let started = Instant::now();
    let deadline = started + Duration::from_millis(wait);
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return tool_error("CANCELLED", "request cancelled");
        }
        let timeout = if waiting {
            HTTP_TIMEOUT
                .min(deadline.saturating_duration_since(Instant::now()))
                .max(Duration::from_millis(1))
        } else {
            HTTP_TIMEOUT
        };
        let response = agent
            .post(endpoint.as_str())
            .timeout(timeout)
            .set("CF-Access-Client-Id", &config.client_id)
            .set("CF-Access-Client-Secret", &config.secret)
            .set("Accept", "application/json, text/event-stream")
            .set("MCP-Protocol-Version", "2025-06-18")
            .send_json(request.clone());
        let mut result = match response {
            Ok(response) if response.status() == 200 => match decode(response, id) {
                Ok(v) => v,
                Err(()) => return tool_error("CLOUD_PROTOCOL", "invalid cloud MCP response"),
            },
            Ok(_) => {
                return tool_error(
                    "CLOUD_HTTP",
                    "unexpected cloud HTTP status; no redirect or retry was followed",
                )
            }
            Err(ureq::Error::Status(status, _)) => {
                return tool_error(
                    "CLOUD_HTTP",
                    &format!("cloud HTTP {status}; request was not retried"),
                )
            }
            Err(ureq::Error::Transport(_)) => {
                return tool_error(
                    "CLOUD_TRANSPORT",
                    "cloud request failed or timed out; outcome may be unknown; not retried",
                )
            }
        };
        redact(
            &mut result,
            &config.secret,
            matches!(
                name,
                "orchestrator_status"
                    | "roles_list"
                    | "work_list"
                    | "agent_list"
                    | "agent_running"
                    | "agent_await"
                    | "agent_status"
                    | "agent_result"
            ),
        );
        if name != "agent_await"
            || rpc_error_payload(&result).is_some()
            || result["isError"] == true
        {
            return result;
        }
        let unchanged = result["structuredContent"]["changed"] == false;
        if !waiting || !unchanged || Instant::now() >= deadline {
            waited(&mut result, started);
            return result;
        }
        let next = (Instant::now() + Duration::from_secs(2)).min(deadline);
        while Instant::now() < next {
            if cancelled.load(Ordering::Relaxed) {
                return tool_error("CANCELLED", "request cancelled");
            }
            std::thread::sleep(
                Duration::from_millis(10).min(next.saturating_duration_since(Instant::now())),
            );
        }
        if Instant::now() >= deadline {
            waited(&mut result, started);
            return result;
        }
    }
}
fn contains_secret(value: &Value, secret: &str) -> bool {
    match value {
        Value::String(text) => text.contains(secret),
        Value::Array(items) => items.iter().any(|item| contains_secret(item, secret)),
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key.contains(secret) || contains_secret(value, secret)),
        _ => false,
    }
}

fn valid_mission(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

fn decode(response: ureq::Response, id: &Value) -> Result<Value, ()> {
    let content_type = response
        .header("Content-Type")
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    let mut body = String::new();
    response
        .into_reader()
        .take(MAX_RESPONSE + 1)
        .read_to_string(&mut body)
        .map_err(|_| ())?;
    if body.len() as u64 > MAX_RESPONSE {
        return Err(());
    }
    let messages: Vec<Value> = if content_type == "application/json" {
        vec![serde_json::from_str(&body).map_err(|_| ())?]
    } else if content_type == "text/event-stream" {
        let body = body.replace("\r\n", "\n");
        let mut messages = Vec::new();
        for event in body.split("\n\n") {
            let data = event
                .lines()
                .filter_map(|line| {
                    line.strip_prefix("data:")
                        .map(|s| s.strip_prefix(' ').unwrap_or(s))
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !data.is_empty() {
                messages.push(serde_json::from_str(&data).map_err(|_| ())?);
            }
        }
        messages
    } else {
        return Err(());
    };
    let mut answer = None;
    for message in messages {
        if message["jsonrpc"] != "2.0" {
            return Err(());
        }
        if message.get("id") == Some(id) {
            if answer.is_some() {
                return Err(());
            }
            answer = Some(match (message.get("result"), message.get("error")) {
                (Some(result), None) if valid_tool_result(result) => result.clone(),
                (None, Some(error)) if valid_rpc_error(error) => json!({"error":error}),
                _ => return Err(()),
            });
        }
    }
    answer.ok_or(())
}
// Validate the wire shapes of MCP 2025-06-18, which this bridge advertises.
// Keep the original Value: extension fields must survive validation, and the
// existing redaction policy must still run on all of them. In particular, do not
// default missing content to [] (some newer SDK deserializers do that).
fn valid_tool_result(value: &Value) -> bool {
    value
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().all(valid_content))
        && optional(value, "structuredContent", Value::is_object)
        && optional(value, "isError", Value::is_boolean)
        && optional(value, "_meta", Value::is_object)
}

fn valid_rpc_error(value: &Value) -> bool {
    // JSON-RPC requires an integer, not a string or a fractional number. JSON
    // numbers such as -32000.0 still represent integers; do not impose i32 bounds.
    value
        .get("code")
        .and_then(Value::as_f64)
        .is_some_and(|n| n.fract() == 0.0)
        && value.get("message").is_some_and(Value::is_string)
}

fn optional(value: &Value, key: &str, valid: impl FnOnce(&Value) -> bool) -> bool {
    value.get(key).is_none_or(valid)
}

fn valid_annotations(value: &Value) -> bool {
    value.is_object()
        && optional(value, "audience", |v| {
            v.as_array().is_some_and(|roles| {
                roles
                    .iter()
                    .all(|role| matches!(role.as_str(), Some("user" | "assistant")))
            })
        })
        && optional(value, "priority", |v| {
            v.as_f64().is_some_and(|n| (0.0..=1.0).contains(&n))
        })
        && optional(value, "lastModified", Value::is_string)
}

fn valid_content(value: &Value) -> bool {
    if !optional(value, "_meta", Value::is_object)
        || !optional(value, "annotations", valid_annotations)
    {
        return false;
    }
    match value.get("type").and_then(Value::as_str) {
        Some("text") => value.get("text").is_some_and(Value::is_string),
        Some("image" | "audio") => {
            value.get("data").is_some_and(Value::is_string)
                && value.get("mimeType").is_some_and(Value::is_string)
        }
        Some("resource") => value.get("resource").is_some_and(|resource| {
            resource.get("uri").is_some_and(Value::is_string)
                && optional(resource, "mimeType", Value::is_string)
                && optional(resource, "_meta", Value::is_object)
                && (resource.get("text").is_some_and(Value::is_string)
                    || resource.get("blob").is_some_and(Value::is_string))
        }),
        Some("resource_link") => {
            value.get("name").is_some_and(Value::is_string)
                && value.get("uri").is_some_and(Value::is_string)
                && ["title", "description", "mimeType"]
                    .iter()
                    .all(|key| optional(value, key, Value::is_string))
                && optional(value, "size", Value::is_number)
        }
        _ => false,
    }
}

fn waited(result: &mut Value, started: Instant) {
    if let Some(object) = result["structuredContent"].as_object_mut() {
        object.insert(
            "waitedMs".into(),
            json!(started.elapsed().as_millis() as u64),
        );
        result["content"] = json!([{"type":"text","text":result["structuredContent"].to_string()}]);
    }
}
fn secret_key(key: &str) -> bool {
    // A lease's public monotonic epoch is not its bearer capability.
    if key == "fencingToken" {
        return false;
    }
    let key = key.to_ascii_lowercase();
    [
        "capability",
        "token",
        "secret",
        "password",
        "authorization",
        "credential",
        "apikey",
        "api_key",
        "api-key",
    ]
    .iter()
    .any(|part| key.contains(part))
}
fn redact(value: &mut Value, secret: &str, read: bool) {
    match value {
        Value::String(text) => {
            // MCP's text content is itself JSON; apply the same read policy there.
            if let Ok(mut nested) = serde_json::from_str::<Value>(text) {
                if nested.is_object() || nested.is_array() {
                    let before = nested.clone();
                    redact(&mut nested, secret, read);
                    if nested != before {
                        *text = nested.to_string();
                    }
                    return;
                }
            }
            *text = text.replace(secret, "[REDACTED]");
        }
        Value::Array(items) => {
            for item in items {
                redact(item, secret, read);
            }
        }
        Value::Object(object) => {
            let old = std::mem::take(object);
            for (key, mut value) in old {
                if read && secret_key(&key) {
                    value = json!("[REDACTED]");
                } else {
                    redact(&mut value, secret, read);
                }
                object.insert(key.replace(secret, "[REDACTED]"), value);
            }
        }
        _ => {}
    }
}
