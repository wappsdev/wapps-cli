//! Pure, source-grounded 13.3 vocabulary, not an execution engine.
//! Authority values deliberately have no generic serialization or display.

use serde::Serialize;
use std::{error::Error, fmt, str::FromStr};

/// `roles/types.ts` and the cloud's `broker/roles.rs`: no model defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Claude,
    Codex,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
}

impl FromStr for Provider {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "claude" => Ok(Self::Claude),
            "codex" => Ok(Self::Codex),
            _ => Err(ContractError::UnknownProvider),
        }
    }
}

/// Cloud `body.rs::REPORTED_STATUSES`, not job state or review verdict.
/// A completed report can leave the cloud row in `review_pending` or `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl ReportStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

impl FromStr for ReportStatus {
    type Err = ContractError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "timed_out" => Ok(Self::TimedOut),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(ContractError::InvalidReportStatus),
        }
    }
}

/// Invalid inputs are never retained in a diagnostic or error document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractError {
    UnknownProvider,
    InvalidReportStatus,
    EmptyCapability,
    InvalidFencingToken,
    InvalidJobId,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownProvider => "unknown provider",
            Self::InvalidReportStatus => "invalid report status",
            Self::EmptyCapability => "empty capability",
            Self::InvalidFencingToken => "fencing token must be a positive JavaScript-safe integer",
            Self::InvalidJobId => "job id must contain 1 to 128 UTF-16 units after JavaScript trim",
        })
    }
}

impl Error for ContractError {}

/// An opaque, nonempty capability. No trim, format assumption, raw getter,
/// `Display`, or `Serialize`. This is diagnostic containment, not zeroization.
pub struct SecretMaterial(String);

impl SecretMaterial {
    pub fn new(value: String) -> Result<Self, ContractError> {
        if value.is_empty() {
            return Err(ContractError::EmptyCapability);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretMaterial([REDACTED])")
    }
}

/// Cloud `body.rs::AUTHORITY`: the lease secret and its monotonic public epoch.
#[derive(Debug)]
pub struct LeaseAuthority {
    capability: SecretMaterial,
    fencing_token: u64,
}

impl LeaseAuthority {
    pub fn new(capability: SecretMaterial, fencing_token: u64) -> Result<Self, ContractError> {
        // `body.rs::check_int`: positive and at most Number.MAX_SAFE_INTEGER.
        if !(1..=9_007_199_254_740_991).contains(&fencing_token) {
            return Err(ContractError::InvalidFencingToken);
        }
        Ok(Self {
            capability,
            fencing_token,
        })
    }

    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Explicit authority-bearing wire encoding; never use this as a log value.
    pub fn wire(&self) -> LeaseAuthorityWire<'_> {
        LeaseAuthorityWire {
            capability: &self.capability.0,
            fencing_token: self.fencing_token,
        }
    }
}

/// Only this explicit borrowed wire view serializes a lease capability.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeaseAuthorityWire<'a> {
    capability: &'a str,
    fencing_token: u64,
}

impl fmt::Debug for LeaseAuthorityWire<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseAuthorityWire")
            .field("capability", &"[REDACTED]")
            .field("fencing_token", &self.fencing_token)
            .finish()
    }
}

/// Cloud `body.rs::JOB_AUTHORITY`: a worker's job id and capability, no epoch.
pub struct JobAuthority {
    job_id: String,
    capability: SecretMaterial,
}

impl JobAuthority {
    pub fn new(job_id: String, capability: SecretMaterial) -> Result<Self, ContractError> {
        // JavaScript trim differs from Rust trim (BOM is space; NEL is not).
        let job_id = job_id.trim_matches(|c| {
            matches!(c,
                '\u{0009}'..='\u{000d}' | '\u{0020}' | '\u{00a0}' | '\u{1680}' |
                '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' |
                '\u{205f}' | '\u{3000}' | '\u{feff}'
            )
        });
        if job_id.is_empty() || job_id.encode_utf16().count() > 128 {
            return Err(ContractError::InvalidJobId);
        }
        Ok(Self {
            job_id: job_id.to_owned(),
            capability,
        })
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Explicit authority-bearing wire encoding; never use this as a log value.
    pub fn wire(&self) -> JobAuthorityWire<'_> {
        JobAuthorityWire {
            job_id: &self.job_id,
            capability: &self.capability.0,
        }
    }
}

impl fmt::Debug for JobAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even the id is untrusted text and may have been a misplaced secret.
        f.write_str("JobAuthority([REDACTED])")
    }
}

/// Only this explicit borrowed wire view serializes a job capability.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobAuthorityWire<'a> {
    job_id: &'a str,
    capability: &'a str,
}

impl fmt::Debug for JobAuthorityWire<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JobAuthorityWire([REDACTED])")
    }
}

/// What a failed cloud mutation establishes, not a retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    Refused,
    Unknown,
}

/// The existing bridge's transport/HTTP/protocol failures, RPC error branch,
/// and validated cloud tool refusal. No URL, response body, recovery text,
/// request arguments, or nested provider error is retained here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudError {
    Transport,
    Http {
        status: u16,
    },
    Protocol,
    // The bridge accepts integral JSON numbers beyond i64; do not freeze a
    // narrower numeric representation just to keep diagnostics.
    Rpc,
    /// A validated schema, authorization, or domain refusal known not to have
    /// mutated. Not generic `isError`, an INTERNAL envelope, or an HTTP error.
    Refused,
}

impl CloudError {
    pub const fn outcome(self) -> MutationOutcome {
        match self {
            Self::Refused => MutationOutcome::Refused,
            // A request may have committed before a timeout, malformed answer,
            // gateway error, or RPC failure. None establishes safe replay.
            _ => MutationOutcome::Unknown,
        }
    }
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport => f.write_str("CLOUD_TRANSPORT: outcome may be unknown"),
            Self::Http { status } => write!(f, "CLOUD_HTTP: HTTP {status}"),
            Self::Protocol => f.write_str("CLOUD_PROTOCOL: invalid cloud response"),
            Self::Rpc => f.write_str("cloud RPC error"),
            Self::Refused => f.write_str("cloud mutation refused"),
        }
    }
}

impl Error for CloudError {}
