//! Pure cloud request bodies and validated application replies, not transport.
//! Grounded in platform body.rs, mission_lane/payload.rs and broker_mcp.rs.
//! Encoded Values contain authority: never log them. Free text must already
//! have passed the outbound scrub; this codec only checks the wire contract.

use super::types::{
    CloudError, JobAuthority, LeaseAuthority, Provider, ReportStatus, SecretMaterial,
};
use serde::Serialize;
use serde_json::{json, Value};

pub struct Dispatch<'a> {
    pub authority: &'a LeaseAuthority,
    pub lane_id: &'a str,
    pub role: &'a str,
    pub dispatch_key: &'a str,
    pub base: &'a str,
    pub head: &'a str,
    pub task: &'a str,
    pub worker_provider: Provider,
    pub work_item_id: Option<&'a str>,
    pub reviews_job_id: Option<&'a str>,
    pub resumes_job_id: Option<&'a str>,
    pub answers_question_id: Option<&'a str>,
}

impl Dispatch<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        let mut body = json!({
            "authority": wire(self.authority.wire())?,
            "laneId": trimmed(self.lane_id, 128)?,
            "role": trimmed(self.role, 128)?,
            "dispatchKey": trimmed(self.dispatch_key, 200)?,
            "base": trimmed(self.base, 200)?,
            "head": trimmed(self.head, 200)?,
            "task": trimmed(self.task, 200_000)?,
            "workerProvider": self.worker_provider,
        });
        for (key, value) in [
            ("workItemId", self.work_item_id),
            ("reviewsJobId", self.reviews_job_id),
            ("resumesJobId", self.resumes_job_id),
            ("answersQuestionId", self.answers_question_id),
        ] {
            if let Some(value) = value {
                body[key] = json!(trimmed(value, 128)?);
            }
        }
        // The cloud validates bind exclusivity and declared role ceilings.
        // Local routing/review independence remains pending runtime integration;
        // this encoder enforces neither.
        Ok(body)
    }
}

pub struct Worktree<'a> {
    pub path: &'a str,
    pub branch: &'a str,
}

impl Worktree<'_> {
    fn encode(&self) -> Result<Value, CloudError> {
        Ok(json!({"path":trimmed(self.path, 1024)?, "branch":trimmed(self.branch, 256)?}))
    }
}

pub struct Attach<'a> {
    pub authority: &'a JobAuthority,
    pub provider_run_id: &'a str,
    pub worktree: Option<Worktree<'a>>,
}

impl Attach<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        let mut body = json!({
            "authority":wire(self.authority.wire())?,
            "providerRunId":trimmed(self.provider_run_id, 200)?,
        });
        if let Some(worktree) = &self.worktree {
            body["worktree"] = worktree.encode()?;
        }
        Ok(body)
    }
}

pub struct Progress<'a> {
    pub authority: &'a JobAuthority,
    pub note: Option<&'a str>,
}

impl Progress<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        let mut body = json!({"authority":wire(self.authority.wire())?});
        if let Some(note) = self.note {
            body["note"] = json!(trimmed(note, 500)?);
        }
        Ok(body)
    }
}

pub struct Finish<'a> {
    pub authority: &'a JobAuthority,
    pub status: ReportStatus,
    pub output: Option<&'a str>,
    pub error: Option<&'a str>,
}

impl Finish<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        let mut body = json!({"authority":wire(self.authority.wire())?, "status":self.status});
        for (key, value, limit) in [
            ("output", self.output, 200_000),
            ("error", self.error, 20_000),
        ] {
            if let Some(value) = value {
                body[key] = json!(bounded(value, 0, limit)?);
            }
        }
        Ok(body)
    }
}

pub struct Cancel<'a> {
    pub authority: &'a LeaseAuthority,
    pub job_id: &'a str,
}

impl Cancel<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        Ok(json!({"authority":wire(self.authority.wire())?, "jobId":trimmed(self.job_id, 128)?}))
    }
}

/// Explicit registration only. No principal, lease or automatic registration.
/// The platform advertises no MCP register/progress tool; these are HTTP bodies.
pub struct Register<'a> {
    pub mission_id: &'a str,
    pub repo: &'a str,
}

impl Register<'_> {
    pub fn encode(&self) -> Result<Value, CloudError> {
        mission_id(self.mission_id)?;
        Ok(json!({"missionId":self.mission_id, "repo":trimmed(self.repo, 128)?}))
    }
}

fn wire(value: impl Serialize) -> Result<Value, CloudError> {
    serde_json::to_value(value).map_err(|_| CloudError::Protocol)
}

fn js_trim(value: &str) -> &str {
    value.trim_matches(|c| {
        matches!(c,
            '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' |
            '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' |
            '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    })
}

fn bounded(value: &str, min: usize, max: usize) -> Result<&str, CloudError> {
    let length = value.encode_utf16().count();
    if (min..=max).contains(&length) {
        Ok(value)
    } else {
        Err(CloudError::Protocol)
    }
}

fn trimmed(value: &str, max: usize) -> Result<&str, CloudError> {
    bounded(js_trim(value), 1, max)
}

fn mission_id(value: &str) -> Result<&str, CloudError> {
    let mut bytes = value.bytes();
    let first = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if first
        && value.len() <= 128
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    {
        Ok(value)
    } else {
        Err(CloudError::Protocol)
    }
}

/// Successful application value plus the independent post-mutation attention
/// read. No Debug/Serialize: a task or nested diagnostic can contain secrets.
pub struct Reply<'a, T> {
    pub value: T,
    pub attention: Option<&'a Value>,
    pub attention_error: Option<&'a Value>,
}

fn reply<T>(source: &Value, value: T) -> Result<Reply<'_, T>, CloudError> {
    let attention = source.get("attention");
    let attention_error = source.get("attentionError");
    if attention.is_some_and(|v| !v.is_object())
        || attention_error.is_some_and(|v| valid_envelope(v).is_none())
        || (attention.is_some() && attention_error.is_some())
    {
        return Err(CloudError::Protocol);
    }
    Ok(Reply {
        value,
        attention,
        attention_error,
    })
}

/// A wire-state vocabulary, not a state machine or local settlement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Reserved,
    Running,
    ReviewPending,
    Completed,
    Rejected,
    Failed,
    TimedOut,
    Cancelled,
    Orphaned,
}

fn state(value: &Value) -> Result<JobState, CloudError> {
    match value.as_str() {
        Some("reserved") => Ok(JobState::Reserved),
        Some("running") => Ok(JobState::Running),
        Some("review_pending") => Ok(JobState::ReviewPending),
        Some("completed") => Ok(JobState::Completed),
        Some("rejected") => Ok(JobState::Rejected),
        Some("failed") => Ok(JobState::Failed),
        Some("timed_out") => Ok(JobState::TimedOut),
        Some("cancelled") => Ok(JobState::Cancelled),
        Some("orphaned") => Ok(JobState::Orphaned),
        _ => Err(CloudError::Protocol),
    }
}

pub enum Dispatched {
    Created(JobAuthority),
    Existing { job_id: String, state: JobState },
}

pub fn decode_dispatch(source: &Value) -> Result<Reply<'_, Dispatched>, CloudError> {
    application(source)?;
    let id = original_text(field(source, "jobId")?, 128)?;
    let state = state(field(source, "state")?)?;
    let created = field(source, "created")?
        .as_bool()
        .ok_or(CloudError::Protocol)?;
    let outcome = if created {
        if state != JobState::Reserved {
            return Err(CloudError::Protocol);
        }
        let capability = text(field(source, "capability")?)?;
        let secret =
            SecretMaterial::new(capability.to_owned()).map_err(|_| CloudError::Protocol)?;
        Dispatched::Created(
            JobAuthority::new(id.to_owned(), secret).map_err(|_| CloudError::Protocol)?,
        )
    } else {
        if source.get("capability").is_some_and(|v| !v.is_null()) {
            return Err(CloudError::Protocol);
        }
        Dispatched::Existing {
            job_id: id.to_owned(),
            state,
        }
    };
    reply(source, outcome)
}

pub struct ResumeFrom {
    pub job_id: String,
    pub provider_run_id: String,
    pub worktree: Option<AttachedWorktree>,
}

pub struct AttachedWorktree {
    pub path: String,
    pub branch: String,
}

pub struct Attached {
    pub job_id: String,
    pub task: String,
    pub role: String,
    pub lane_id: String,
    pub base: String,
    pub head: String,
    pub work_item_id: Option<String>,
    pub reviews_job_id: Option<String>,
    pub answers_question_id: Option<String>,
    pub deadline: u64,
    pub resume_from: Option<ResumeFrom>,
}

pub fn decode_attach<'a>(
    source: &'a Value,
    authority: &JobAuthority,
    resumes_job_id: Option<&str>,
) -> Result<Reply<'a, Attached>, CloudError> {
    // Attach returns the whole brief, including ok; the public dispatch,
    // progress, finish and cancel handlers project fields and omit that flag.
    matching_job(source, authority.job_id())?;
    if source.get("ok") != Some(&Value::Bool(true)) {
        return Err(CloudError::Protocol);
    }
    let task = text(field(source, "task")?)?;
    // The cloud appends instructions or builds a delegated-question brief.
    // It is not limited by the original dispatch's 200,000-unit task ceiling.
    if js_trim(task).is_empty() {
        return Err(CloudError::Protocol);
    }
    let resume = field(source, "resumeFrom")?;
    let resume_from = match resumes_job_id {
        None if resume.is_null() => None,
        Some(expected) if !resume.is_null() => {
            let id = original_text(field(resume, "jobId")?, 128)?;
            if id != expected {
                return Err(CloudError::Protocol);
            }
            let tree = field(resume, "worktree")?;
            let worktree = if tree.is_null() {
                None
            } else {
                Some(AttachedWorktree {
                    path: original_text(field(tree, "path")?, 1024)?.to_owned(),
                    branch: original_text(field(tree, "branch")?, 256)?.to_owned(),
                })
            };
            Some(ResumeFrom {
                job_id: id.to_owned(),
                provider_run_id: original_text(field(resume, "providerRunId")?, 200)?.to_owned(),
                worktree,
            })
        }
        _ => return Err(CloudError::Protocol),
    };
    reply(
        source,
        Attached {
            job_id: authority.job_id().to_owned(),
            task: task.to_owned(),
            role: original_text(field(source, "role")?, 128)?.to_owned(),
            lane_id: original_text(field(source, "laneId")?, 128)?.to_owned(),
            base: original_text(field(source, "base")?, 200)?.to_owned(),
            head: original_text(field(source, "head")?, 200)?.to_owned(),
            work_item_id: nullable_id(source, "workItemId")?,
            reviews_job_id: nullable_id(source, "reviewsJobId")?,
            answers_question_id: nullable_id(source, "answersQuestionId")?,
            deadline: integer(field(source, "deadline")?, 1)?,
            resume_from,
        },
    )
}

pub struct Progressed {
    pub deadline: u64,
}

pub fn decode_progress<'a>(
    source: &'a Value,
    authority: &JobAuthority,
) -> Result<Reply<'a, Progressed>, CloudError> {
    matching_job(source, authority.job_id())?;
    reply(
        source,
        Progressed {
            deadline: integer(field(source, "deadline")?, 1)?,
        },
    )
}

pub struct Subject {
    pub job_id: String,
    pub state: JobState,
}
pub struct Finished {
    pub state: JobState,
    pub subject: Option<Subject>,
}

pub fn decode_finish<'a>(
    source: &'a Value,
    authority: &JobAuthority,
) -> Result<Reply<'a, Finished>, CloudError> {
    matching_job(source, authority.job_id())?;
    let finished = state(field(source, "state")?)?;
    if !matches!(
        finished,
        JobState::Completed
            | JobState::Failed
            | JobState::TimedOut
            | JobState::Cancelled
            | JobState::ReviewPending
    ) {
        return Err(CloudError::Protocol);
    }
    let subject = field(source, "subject")?;
    let subject = if subject.is_null() {
        None
    } else {
        // settle_subject can return the observed state unchanged when the
        // verdict's transition is no longer allowed (e.g. a cancelled subject).
        // Validate the vocabulary without inferring that the verdict took effect.
        Some(Subject {
            job_id: original_text(field(subject, "jobId")?, 128)?.to_owned(),
            state: state(field(subject, "state")?)?,
        })
    };
    reply(
        source,
        Finished {
            state: finished,
            subject,
        },
    )
}

pub fn decode_cancel<'a>(
    source: &'a Value,
    expected_job_id: &str,
) -> Result<Reply<'a, JobState>, CloudError> {
    matching_job(source, expected_job_id)?;
    if state(field(source, "state")?)? != JobState::Cancelled {
        return Err(CloudError::Protocol);
    }
    reply(source, JobState::Cancelled)
}

pub struct Registered {
    pub created: bool,
    pub registered_at: u64,
    pub registered_by: String,
}

pub fn decode_register<'a>(
    source: &'a Value,
    request: &Register<'_>,
) -> Result<Reply<'a, Registered>, CloudError> {
    application(source)?;
    request.encode()?;
    let mission = field(source, "mission")?;
    let id = mission_id(text(field(mission, "missionId")?)?)?;
    let repo = original_text(field(mission, "repo")?, 128)?;
    if id != request.mission_id || repo != js_trim(request.repo) {
        return Err(CloudError::Protocol);
    }
    let by = text(field(mission, "registeredBy")?)?;
    if by.is_empty() {
        return Err(CloudError::Protocol);
    }
    reply(
        source,
        Registered {
            created: field(source, "created")?
                .as_bool()
                .ok_or(CloudError::Protocol)?,
            registered_at: integer(field(mission, "registeredAt")?, 0)?,
            registered_by: by.to_owned(),
        },
    )
}

fn field<'a>(source: &'a Value, key: &str) -> Result<&'a Value, CloudError> {
    source.get(key).ok_or(CloudError::Protocol)
}

fn text(source: &Value) -> Result<&str, CloudError> {
    source.as_str().ok_or(CloudError::Protocol)
}

/// Never silently normalize an identity returned by the cloud.
fn original_text(source: &Value, limit: usize) -> Result<&str, CloudError> {
    let value = text(source)?;
    if trimmed(value, limit)? != value {
        return Err(CloudError::Protocol);
    }
    Ok(value)
}

fn nullable_id(source: &Value, key: &str) -> Result<Option<String>, CloudError> {
    let value = field(source, key)?;
    if value.is_null() {
        Ok(None)
    } else {
        Ok(Some(original_text(value, 128)?.to_owned()))
    }
}

fn integer(source: &Value, min: u64) -> Result<u64, CloudError> {
    let number = source.as_f64().ok_or(CloudError::Protocol)?;
    // JS integral decimal notation is valid, but rounded unsafe integers are not.
    if number.is_finite()
        && number.fract() == 0.0
        && number >= min as f64
        && number <= 9_007_199_254_740_991.0
    {
        Ok(number as u64)
    } else {
        Err(CloudError::Protocol)
    }
}

fn application(source: &Value) -> Result<(), CloudError> {
    if !source.is_object() {
        return Err(CloudError::Protocol);
    }
    if source.get("error").is_some() {
        return Err(refusal(source));
    }
    // Success is established by each operation's required fields, not by a
    // private DO flag. An explicit negative or malformed flag contradicts it.
    if !optional(source, "ok", |value| value == &Value::Bool(true)) {
        return Err(CloudError::Protocol);
    }
    Ok(())
}

fn matching_job(source: &Value, expected: &str) -> Result<(), CloudError> {
    application(source)?;
    if original_text(field(source, "jobId")?, 128)? != expected {
        return Err(CloudError::Protocol);
    }
    Ok(())
}

/// Validate a single JSON-RPC response already selected by transport (no SSE,
/// batching, network, retry, request construction or text-to-JSON fallback).
/// The returned object is still untrusted until an application decoder accepts it.
pub fn decode_rpc<'a>(source: &'a Value, expected_id: &Value) -> Result<&'a Value, CloudError> {
    if source.get("jsonrpc") != Some(&json!("2.0")) || source.get("id") != Some(expected_id) {
        return Err(CloudError::Protocol);
    }
    let result = match (source.get("result"), source.get("error")) {
        (None, Some(error)) => {
            let integral = error
                .get("code")
                .and_then(Value::as_f64)
                .is_some_and(|n| n.is_finite() && n.fract() == 0.0);
            if integral && error.get("message").is_some_and(Value::is_string) {
                return Err(CloudError::Rpc);
            }
            return Err(CloudError::Protocol);
        }
        (Some(result), None) => result,
        _ => return Err(CloudError::Protocol),
    };
    if !result
        .get("content")
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().all(valid_content))
        || !optional(result, "isError", Value::is_boolean)
        || !optional(result, "_meta", Value::is_object)
    {
        return Err(CloudError::Protocol);
    }
    // These platform tools always supply structuredContent. Valid generic MCP
    // text-only output is not a validated application acknowledgement here.
    let application = field(result, "structuredContent")?;
    if !application.is_object() {
        return Err(CloudError::Protocol);
    }
    if result.get("isError") == Some(&Value::Bool(true)) {
        return Err(refusal(application));
    }
    if application.get("error").is_some() {
        return Err(CloudError::Protocol);
    }
    Ok(application)
}

fn optional(source: &Value, key: &str, check: impl FnOnce(&Value) -> bool) -> bool {
    source.get(key).is_none_or(check)
}

// MCP 2025-06-18, as advertised and validated by the existing forward.rs.
fn valid_content(source: &Value) -> bool {
    if !source.is_object()
        || !optional(source, "_meta", Value::is_object)
        || !optional(source, "annotations", valid_annotations)
    {
        return false;
    }
    match source.get("type").and_then(Value::as_str) {
        Some("text") => source.get("text").is_some_and(Value::is_string),
        Some("image" | "audio") => {
            source.get("data").is_some_and(Value::is_string)
                && source.get("mimeType").is_some_and(Value::is_string)
        }
        Some("resource") => source.get("resource").is_some_and(|resource| {
            resource.get("uri").is_some_and(Value::is_string)
                && optional(resource, "mimeType", Value::is_string)
                && optional(resource, "_meta", Value::is_object)
                && (resource.get("text").is_some_and(Value::is_string)
                    || resource.get("blob").is_some_and(Value::is_string))
        }),
        Some("resource_link") => {
            source.get("name").is_some_and(Value::is_string)
                && source.get("uri").is_some_and(Value::is_string)
                && ["title", "description", "mimeType"]
                    .iter()
                    .all(|key| optional(source, key, Value::is_string))
                && optional(source, "size", Value::is_number)
        }
        _ => false,
    }
}

fn valid_annotations(source: &Value) -> bool {
    source.is_object()
        && optional(source, "audience", |v| {
            v.as_array().is_some_and(|items| {
                items
                    .iter()
                    .all(|v| matches!(v.as_str(), Some("user" | "assistant")))
            })
        })
        && optional(source, "priority", |v| {
            v.as_f64().is_some_and(|n| (0.0..=1.0).contains(&n))
        })
        && optional(source, "lastModified", Value::is_string)
}

fn valid_envelope(source: &Value) -> Option<&str> {
    // Platform error envelopes have no application acknowledgement fields.
    if [
        "ok",
        "jobId",
        "created",
        "mission",
        "state",
        "task",
        "deadline",
        "capability",
    ]
    .iter()
    .any(|key| source.get(key).is_some())
    {
        return None;
    }
    let code = source.get("error")?.as_str()?;
    let retryable = match code {
        "INVALID_ARGUMENT"
        | "UNAUTHENTICATED"
        | "FORBIDDEN"
        | "NOT_FOUND"
        | "SERVICE_MISCONFIGURED"
        | "INTERNAL"
        | "OPERATION_KEY_CONFLICT" => false,
        "CONFLICT" | "RATE_LIMITED" | "NOT_AVAILABLE" => true,
        _ => return None,
    };
    if source.get("message").is_some_and(Value::is_string)
        && source.get("recovery").is_some_and(Value::is_string)
        && source.get("retryable") == Some(&Value::Bool(retryable))
    {
        Some(code)
    } else {
        None
    }
}

fn refusal(source: &Value) -> CloudError {
    match valid_envelope(source) {
        // Only the platform's validated nonmutating schema/auth/domain refusals
        // establish Refused. Generic isError, INTERNAL and availability errors
        // leave mutation outcome Unknown. This is not a retry decision.
        Some(
            "INVALID_ARGUMENT"
            | "UNAUTHENTICATED"
            | "FORBIDDEN"
            | "NOT_FOUND"
            | "CONFLICT"
            | "OPERATION_KEY_CONFLICT",
        ) => CloudError::Refused,
        _ => CloudError::Protocol,
    }
}
