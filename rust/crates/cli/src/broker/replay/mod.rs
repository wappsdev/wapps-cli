//! OD10 open-work replay (slice 13.11), increment R1: SYNTHETIC only.
//!
//! Validation of a planner-shaped manifest, keyed allocation, a private durable
//! journal and the keyed execute state machine, per
//! docs/broker-rust-migration-executor-contract.txt (sections 3, 4 and 6). No
//! snapshot reader, transport backend or CLI entry point exists yet: the only
//! `ReplayBackend` is the test fake. Nothing here migrates anything.
//!
//! R1 deviations from the contract, closed by later increments:
//! - `validate` takes the typed `Manifest`; mapping and snapshot inputs are R2.
//! - `manifest_sha256` covers the canonical typed encoding, not file bytes.
//! - The journal omits `semantic_sha256`, `reason`, `mapping_sha256`,
//!   `allocation_sha256`, `verification_state` and `lease_disposition`, and
//!   `CallFailure` omits `KnownUnsent`, until their R2-R4 producers exist.
//! - `ReplayBackend::history` (gap G4) has no production implementation; one
//!   that cannot prove receipt-history continuity must fail closed.
//! - A `Start` that fails after publishing its journal leaves the journal and
//!   its lock file: only `ResumeSameKeys` can proceed from them.
//! - Process death is modelled in-process by the tests, not by a real exit.
mod canonical;
mod execute;
mod journal;
mod plan;
#[cfg(test)]
mod tests;

pub use execute::{
    execute, CallFailure, CreationReceipt, LiveLease, ReplayAction, ReplayBackend,
    ResolvedOperation, RunReport,
};
pub use plan::{
    allocate, validate, Allocation, ExecutionBinding, Horizon, ItemRecord, Kind, Manifest,
    ProjectPlan, QuestionRecord, ValidatedManifest,
};

/// Fixed stop codes. They carry no source text, path or underlying error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopCode {
    InvalidManifest,
    InvalidBinding,
    JournalUnsafe,
    JournalExists,
    JournalLocked,
    JournalCorrupt,
    JournalMismatch,
    JournalChanged,
    Durability,
    HistoryUnavailable,
    HistoryDiscontinuity,
    AuthorityRefused,
    Refused,
    OutcomeUnknown,
    ResultChanged,
}
