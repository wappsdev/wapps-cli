//! Pure JSON event parsing from the plugin's quota.ts, codex_mcp.ts and
//! runtime.ts. No storage, attention selection, clocks, or provider execution.

use super::types::Provider;
use serde::Serialize;
use serde_json::Value;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaStatus {
    Allowed,
    AllowedWarning,
    Rejected,
}

#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuotaReading {
    pub provider: Provider,
    /// Provider vocabulary, retained verbatim; not safe diagnostic text.
    pub window: String,
    pub used_percent: Option<u8>,
    /// Raw provider Unix seconds, including fractional or already expired data.
    pub resets_at: Option<f64>,
    pub status: QuotaStatus,
}

impl fmt::Debug for QuotaReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuotaReading")
            .field("provider", &self.provider)
            .field("window", &"[REDACTED]")
            .field("used_percent", &self.used_percent)
            .field("resets_at", &self.resets_at)
            .field("status", &self.status)
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub struct ParsedMessage {
    pub quota: Option<QuotaReading>,
    /// Applies to both transcript recording and progress notes in runtime.ts.
    pub suppress_progress: bool,
}

// JavaScript truthiness matters: {} and [] are truthy, false/0/"" are not.
// The source accepts truthy malformed info/primary values as status-only readings.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
}

// Math.round chooses the integer towards +infinity at a tie. Adding 0.5 first
// would incorrectly round values immediately below a tie; Rust round ties away
// from zero, which would change negative window labels.
fn js_round(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

fn bounded(value: f64) -> u8 {
    js_round(value).clamp(0.0, 100.0) as u8
}

fn from_percent(percent: Option<u8>) -> QuotaStatus {
    if percent.is_some_and(|percent| percent >= 90) {
        QuotaStatus::AllowedWarning
    } else {
        QuotaStatus::Allowed
    }
}

// This value is an integral, finite Math.round result: JS prints negative zero
// as zero and uses unpadded scientific exponents starting at magnitude 1e21.
fn window_number(value: f64) -> String {
    if value == 0.0 {
        "0".to_owned()
    } else if value.abs() >= 1e21 {
        let scientific = format!("{value:e}");
        let (mantissa, exponent) = scientific.split_once('e').expect("scientific exponent");
        format!("{mantissa}e+{exponent}")
    } else {
        value.to_string()
    }
}

pub fn read_quota(payload: &Value) -> Option<QuotaReading> {
    match payload.get("type")?.as_str()? {
        "rate_limit_event" => {
            let info = payload
                .get("rate_limit_info")
                .filter(|value| truthy(value))?;
            let used_percent = number(info.get("utilization")).map(|value| bounded(value * 100.0));
            Some(QuotaReading {
                provider: Provider::Claude,
                window: info
                    .get("rateLimitType")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified")
                    .to_owned(),
                used_percent,
                resets_at: number(info.get("resetsAt")),
                status: match info.get("status").and_then(Value::as_str) {
                    Some("rejected") => QuotaStatus::Rejected,
                    Some("allowed_warning") => QuotaStatus::AllowedWarning,
                    _ => from_percent(used_percent),
                },
            })
        }
        "token_count" => {
            // Only primary: a secondary-only event has no source quota reading.
            let primary = payload
                .get("rate_limits")?
                .get("primary")
                .filter(|value| truthy(value))?;
            let used_percent = number(primary.get("used_percent")).map(bounded);
            let window = match number(primary.get("window_minutes")) {
                Some(minutes) if minutes >= 1440.0 => {
                    format!("{}d", window_number(js_round(minutes / 1440.0)))
                }
                Some(minutes) => format!("{}h", window_number(js_round(minutes / 60.0))),
                None => "unspecified".to_owned(),
            };
            Some(QuotaReading {
                provider: Provider::Codex,
                window,
                used_percent,
                resets_at: number(primary.get("resets_at")),
                status: from_percent(used_percent),
            })
        }
        _ => None,
    }
}

/// Runtime filtering after event admission, not a storage or attention policy.
/// In particular, a token_count without a reading still earns progress/recording.
pub fn classify_message(payload: &Value) -> ParsedMessage {
    let quota = read_quota(payload);
    let suppress_progress =
        quota.is_some() && payload.get("type").and_then(Value::as_str) == Some("token_count");
    ParsedMessage {
        quota,
        suppress_progress,
    }
}

/// Borrow the source-watched message, dropping unknown/stream-fragment events.
/// This is intentionally separate from classify_message: Claude does not use
/// the Codex notification envelope, and admitted Codex counters can lack quota.
pub fn codex_event_payload(notification: &Value) -> Option<&Value> {
    if notification.get("method")?.as_str()? != "codex/event" {
        return None;
    }
    let message = notification.get("params")?.get("msg")?;
    match message.get("type")?.as_str()? {
        "session_configured" | "task_started" | "agent_message" | "exec_command_begin"
        | "patch_apply_begin" | "error" | "item_started" | "item_completed"
        | "exec_command_end" | "patch_apply_end" | "turn_aborted" | "token_count" => Some(message),
        _ => None,
    }
}
