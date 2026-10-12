//! The keyed execute state machine (contract section 6).
use super::canonical::sha256_hex;
use super::journal::{DestinationBinding, Entry, Journal, JournalDoc, State, FORMAT};
use super::plan::{Allocation, Kind, Mappings, Operation};
use super::StopCode;
use serde_json::value::RawValue;
use std::{collections::HashSet, path::Path};

/// Largest integral fencing token a JSON number carries exactly.
const MAX_FENCING_TOKEN: u64 = 9_007_199_254_740_991;

/// Supplied by the approved operator entry point, never inferred from files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayAction {
    /// A new journal; refuses an existing one.
    Start,
    /// The separately authorized same-key recovery of an existing journal.
    ResumeSameKeys,
}

/// The current mission authority; held in memory only, never journaled.
/// No `Debug`: the capability can never be formatted.
#[derive(Clone)]
pub struct LiveLease {
    pub mission_id: String,
    pub principal: String,
    pub capability: String,
    pub fencing_token: u64,
}

pub struct ResolvedOperation<'a> {
    pub kind: Kind,
    pub operation_key: &'a str,
    pub target_mission_id: &'a str,
    /// Exact canonical authority-free request bytes.
    pub request: &'a [u8],
}

/// Ordered `workItemIds`, or the one `questionId`.
pub struct CreationReceipt {
    pub ids: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallFailure {
    /// The server answered with a refusal.
    Refused,
    /// No proof of commit or rollback.
    OutcomeUnknown,
}

pub trait ReplayBackend {
    /// Independent evidence of the destination's receipt-history identity
    /// (contract gap G4). A backend that cannot prove continuity fails.
    fn history(&mut self, target_mission_id: &str) -> Result<String, CallFailure>;
    fn claim(&mut self, target_mission_id: &str) -> Result<LiveLease, CallFailure>;
    fn create(
        &mut self,
        operation: &ResolvedOperation<'_>,
        lease: &LiveLease,
    ) -> Result<CreationReceipt, CallFailure>;
}

/// Accounting from the durable journal; `stop` is `None` only when every
/// operation is acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReport {
    pub stop: Option<StopCode>,
    pub acknowledged_items: usize,
    pub acknowledged_questions: usize,
    pub unknown_operations: usize,
    pub pending_operations: usize,
}

/// Runs or resumes the allocation; one creation at a time, no automatic retry.
///
/// `Err` means this run stopped before its first creation call. `Ok` carries
/// the durable journal's accounting; any uncertainty stops every later
/// operation. Recovery re-sends only the exact journaled key and request.
pub fn execute(
    plan: &Allocation,
    path: &Path,
    backend: &mut dyn ReplayBackend,
    action: ReplayAction,
) -> Result<RunReport, StopCode> {
    let mut targets: Vec<&str> = Vec::new();
    for operation in &plan.operations {
        if !targets.contains(&operation.target_mission_id.as_str()) {
            targets.push(&operation.target_mission_id);
        }
    }
    let mut history = |target: &str| match backend.history(target) {
        Ok(history) if !history.is_empty() => Ok(history),
        _ => Err(StopCode::HistoryUnavailable),
    };
    let (mut journal, mut doc) = match action {
        ReplayAction::Start => {
            let mut journal = Journal::create(path)?;
            let destination_bindings = targets
                .iter()
                .map(|target| {
                    Ok(DestinationBinding {
                        history: history(target)?,
                        target_mission_id: (*target).to_owned(),
                    })
                })
                .collect::<Result<_, StopCode>>()?;
            let doc = initial(plan, destination_bindings);
            journal.save(&doc)?;
            (journal, doc)
        }
        ReplayAction::ResumeSameKeys => {
            let (journal, doc) = Journal::open(path)?;
            check(plan, &targets, &doc)?;
            // Erased or restored receipt history would let a same-key call
            // create again: continuity is proven before anything is sent.
            for binding in &doc.destination_bindings {
                if history(&binding.target_mission_id)? != binding.history {
                    return Err(StopCode::HistoryDiscontinuity);
                }
            }
            (journal, doc)
        }
    };
    let mut leases = Vec::new();
    for target in &targets {
        let lease = backend
            .claim(target)
            .map_err(|_| StopCode::AuthorityRefused)?;
        let current = lease.mission_id == *target
            && lease.principal == plan.principal
            && !lease.capability.is_empty()
            && (1..=MAX_FENCING_TOKEN).contains(&lease.fencing_token);
        if !current {
            return Err(StopCode::AuthorityRefused);
        }
        leases.push(lease);
    }

    let mut accepted = Accepted::default();
    for (index, operation) in plan.operations.iter().enumerate() {
        let target = targets
            .iter()
            .position(|t| *t == operation.target_mission_id)
            .expect("every operation target was claimed");
        let acknowledged = doc.entries[index].state == State::Acknowledged;
        let request = match &doc.entries[index].request {
            Some(request) => request.get().as_bytes().to_vec(),
            None => {
                let request = match operation.request(&accepted.mappings) {
                    Ok(request) => request,
                    Err(code) => return Ok(report(&doc, Some(code))),
                };
                let mut next = doc.clone();
                let entry = &mut next.entries[index];
                entry.state = State::InFlight;
                entry.request_sha256 = Some(sha256_hex(&request));
                entry.request = Some(
                    RawValue::from_string(String::from_utf8(request.clone()).expect("ASCII"))
                        .expect("canonical JSON"),
                );
                // Never send unless the exact intent is durable.
                if let Err(code) = journal.save(&next) {
                    return Ok(report(&doc, Some(code)));
                }
                doc = next;
                request
            }
        };
        let resolved = ResolvedOperation {
            kind: operation.kind,
            operation_key: &operation.key,
            target_mission_id: &operation.target_mission_id,
            request: &request,
        };
        let outcome = backend
            .create(&resolved, &leases[target])
            .map_err(|failure| match failure {
                CallFailure::Refused => StopCode::Refused,
                CallFailure::OutcomeUnknown => StopCode::OutcomeUnknown,
            })
            .and_then(|receipt| accepted.fresh(operation, receipt.ids));
        match outcome {
            Ok(ids) if acknowledged => {
                if ids != doc.entries[index].destination_ids {
                    return Ok(report(&doc, Some(StopCode::ResultChanged)));
                }
            }
            Ok(ids) => {
                let mut next = doc.clone();
                next.entries[index].state = State::Acknowledged;
                next.entries[index].destination_ids = ids;
                if let Err(code) = journal.save(&next) {
                    return Ok(report(&doc, Some(code)));
                }
                doc = next;
            }
            // A refused replay of acknowledged work keeps the original IDs.
            Err(code) if acknowledged => return Ok(report(&doc, Some(code))),
            Err(code) => {
                let mut next = doc.clone();
                next.entries[index].state = State::Unresolved;
                if let Err(save) = journal.save(&next) {
                    return Ok(report(&doc, Some(save)));
                }
                return Ok(report(&next, Some(code)));
            }
        }
        accepted.record(operation, &doc.entries[index].destination_ids);
    }
    Ok(report(&doc, None))
}

/// Acknowledged results so far: parent substitutions and every returned ID
/// per mission and verb.
#[derive(Default)]
struct Accepted {
    mappings: Mappings,
    ids: HashSet<(String, Kind, String)>,
}

impl Accepted {
    /// Count, bounds and uniqueness within and across this mission's results.
    /// Content that fails them is uncertainty, never a proof of zero commits.
    fn fresh(&self, operation: &Operation, ids: Vec<String>) -> Result<Vec<String>, StopCode> {
        let mut seen = HashSet::new();
        let valid = ids.len() == operation.records()
            && ids.iter().all(|id| {
                (1..=128).contains(&id.len())
                    && seen.insert(id.as_str())
                    && !self.ids.contains(&(
                        operation.target_mission_id.clone(),
                        operation.kind,
                        id.clone(),
                    ))
            });
        valid.then_some(ids).ok_or(StopCode::OutcomeUnknown)
    }

    fn record(&mut self, operation: &Operation, ids: &[String]) {
        self.ids.extend(ids.iter().map(|id| {
            (
                operation.target_mission_id.clone(),
                operation.kind,
                id.clone(),
            )
        }));
        self.mappings.record(operation, ids);
    }
}

fn initial(plan: &Allocation, destination_bindings: Vec<DestinationBinding>) -> JournalDoc {
    JournalDoc {
        destination_bindings,
        entries: plan
            .operations
            .iter()
            .map(|operation| Entry {
                destination_ids: Vec::new(),
                kind: operation.kind,
                operation_key: operation.key.clone(),
                project: operation.project.clone(),
                request: None,
                request_sha256: None,
                snapshot_sha256: operation.snapshot_sha256.clone(),
                source_ids: operation.source_ids.clone(),
                source_mission_id: operation.source_mission_id.clone(),
                state: State::Pending,
                target_mission_id: operation.target_mission_id.clone(),
            })
            .collect(),
        format: FORMAT.to_owned(),
        manifest_sha256: plan.manifest_sha256.clone(),
        principal: plan.principal.clone(),
    }
}

/// The whole immutable history is validated before any call: bindings,
/// ordered identities, state order, exact requests and acknowledged IDs.
fn check(plan: &Allocation, targets: &[&str], doc: &JournalDoc) -> Result<(), StopCode> {
    let mismatch = Err(StopCode::JournalMismatch);
    let bound: Vec<&str> = doc
        .destination_bindings
        .iter()
        .map(|b| b.target_mission_id.as_str())
        .collect();
    if doc.format != FORMAT
        || doc.manifest_sha256 != plan.manifest_sha256
        || doc.principal != plan.principal
        || bound != targets
        || doc
            .destination_bindings
            .iter()
            .any(|b| b.history.is_empty())
        || doc.entries.len() != plan.operations.len()
    {
        return mismatch;
    }
    let mut accepted = Accepted::default();
    let mut stopped = false;
    for (operation, entry) in plan.operations.iter().zip(&doc.entries) {
        let identity = entry.operation_key == operation.key
            && entry.kind == operation.kind
            && entry.project == operation.project
            && entry.source_mission_id == operation.source_mission_id
            && entry.target_mission_id == operation.target_mission_id
            && entry.snapshot_sha256 == operation.snapshot_sha256
            && entry.source_ids == operation.source_ids;
        if !identity {
            return mismatch;
        }
        if entry.state == State::Pending {
            if entry.request.is_some()
                || entry.request_sha256.is_some()
                || !entry.destination_ids.is_empty()
            {
                return mismatch;
            }
            stopped = true;
            continue;
        }
        if stopped {
            return mismatch;
        }
        let expected = operation.request(&accepted.mappings)?;
        if entry.request.as_ref().map(|r| r.get().as_bytes()) != Some(expected.as_slice())
            || entry.request_sha256.as_deref() != Some(sha256_hex(&expected).as_str())
        {
            return mismatch;
        }
        if entry.state == State::Acknowledged {
            let ids = accepted
                .fresh(operation, entry.destination_ids.clone())
                .map_err(|_| StopCode::JournalMismatch)?;
            accepted.record(operation, &ids);
        } else {
            if !entry.destination_ids.is_empty() {
                return mismatch;
            }
            stopped = true;
        }
    }
    Ok(())
}

fn report(doc: &JournalDoc, stop: Option<StopCode>) -> RunReport {
    let mut report = RunReport {
        stop,
        acknowledged_items: 0,
        acknowledged_questions: 0,
        unknown_operations: 0,
        pending_operations: 0,
    };
    for entry in &doc.entries {
        match (entry.state, entry.kind) {
            (State::Acknowledged, Kind::WorkAdd) => {
                report.acknowledged_items += entry.destination_ids.len()
            }
            (State::Acknowledged, Kind::WorkAsk) => {
                report.acknowledged_questions += entry.destination_ids.len()
            }
            (State::InFlight | State::Unresolved, _) => report.unknown_operations += 1,
            (State::Pending, _) => report.pending_operations += 1,
        }
    }
    report
}
