//! R1 synthetic acceptance: O0 golden vectors and the root/root/child/question
//! trace against a fake cloud authority. SYNTHETIC: nothing migrates.
use super::canonical::{encode, sha256_hex};
use super::journal::Journal;
use super::plan::{operation_key, Mappings};
use super::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    os::unix::fs::PermissionsExt,
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const PRINCIPAL: &str = "svc:synthetic";
const VECTORS: &str = include_str!("o0-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

// --- synthetic input (synthetic_recovery.synthetic_manifest, typed) ---

fn item(id: &str, parent: Option<&str>, title: &str, intent: &str) -> ItemRecord {
    ItemRecord {
        horizon: parent.is_none().then_some(Horizon::Next),
        intent: intent.into(),
        parent_source_id: parent.map(Into::into),
        source_id: id.into(),
        title: title.into(),
    }
}

fn manifest() -> Manifest {
    let root = |id| item(id, None, "Same synthetic title", "Synthetic intent");
    Manifest {
        projects: vec![ProjectPlan {
            batches: vec![
                vec![root("root-a"), root("root-b")],
                vec![item(
                    "child",
                    Some("root-a"),
                    "Synthetic child",
                    "Child intent",
                )],
            ],
            project: "navlun".into(),
            questions: vec![QuestionRecord {
                proposal: Some("Proposal".into()),
                question: "Synthetic question?".into(),
                source_id: "q".into(),
                work_item_source_id: "child".into(),
            }],
            snapshot_sha256: "a".repeat(64),
            source_mission_id: "source".into(),
            target_mission_id: "target".into(),
        }],
    }
}

fn allocation(manifest: Manifest, principal: &str) -> Allocation {
    allocate(
        &validate(manifest).unwrap(),
        ExecutionBinding {
            principal: principal.into(),
        },
    )
    .unwrap()
}

/// A fresh allocation stands for a new client process: nothing but the
/// journal file and the cloud survives.
fn plan() -> Allocation {
    allocation(manifest(), PRINCIPAL)
}

// --- private journal directory ---

struct Dir(PathBuf);

impl Dir {
    fn new() -> Dir {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = broker_oracle::hermetic::temp_root(&format!(
            "replay-{}",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        // /tmp is a symlink on macOS; the journal refuses symlinked components.
        Dir(fs::canonicalize(root).unwrap())
    }
    fn journal(&self) -> PathBuf {
        self.0.join("journal.json")
    }
    fn mode(&self, mode: u32) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(mode)).unwrap();
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn journal(path: &Path) -> Value {
    serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["journal"].clone()
}

fn states(path: &Path) -> Vec<String> {
    journal(path)["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["state"].as_str().unwrap().to_owned())
        .collect()
}

fn ids(path: &Path, entry: usize) -> Vec<String> {
    serde_json::from_value(journal(path)["entries"][entry]["destination_ids"].clone()).unwrap()
}

// --- fake cloud authority ---

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireItem {
    title: String,
    intent: String,
    #[serde(rename = "parentId")]
    parent_id: Option<String>,
    horizon: Option<Horizon>,
    #[serde(rename = "discoveredFrom")]
    discovered_from: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAdd {
    items: Vec<WireItem>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAsk {
    #[serde(rename = "workItemId")]
    work_item_id: String,
    question: String,
    proposal: Option<String>,
}

/// The server's typed semantic fingerprint (contract section 3): NewWorkItem
/// fields in declaration order, absent optionals as null; ask as a tuple.
fn semantic_sha256(kind: Kind, request: &[u8]) -> Option<String> {
    let bytes = match kind {
        Kind::WorkAdd => {
            serde_json::to_vec(&serde_json::from_slice::<WireAdd>(request).ok()?.items)
        }
        Kind::WorkAsk => {
            let ask: WireAsk = serde_json::from_slice(request).ok()?;
            serde_json::to_vec(&(ask.work_item_id, ask.question, ask.proposal))
        }
    };
    Some(sha256_hex(&bytes.ok()?))
}

#[derive(Clone, Copy, PartialEq)]
enum At {
    Never,
    CrashBeforeCommit(usize),
    CrashAfterCommit(usize),
    LoseResponse(usize),
    InvalidIds(usize),
    RotateLease(usize),
    LockJournalAfterCommit(usize),
    LockJournalOnClaim,
}

struct Receipt {
    principal: String,
    kind: Kind,
    key: String,
    semantic: String,
    ids: Vec<String>,
}

/// One synthetic mission. Grant and lease are checked before the receipt
/// lookup; mutation and receipt commit together.
struct FakeCloud {
    mission: String,
    caller: String,
    granted: bool,
    lease: (String, u64),
    history: Option<String>,
    items: HashMap<String, WireItem>,
    questions: HashMap<String, WireAsk>,
    receipts: Vec<Receipt>,
    sequence: usize,
    claims: usize,
    creates: usize,
    at: At,
    journal_dir: Option<PathBuf>,
}

impl FakeCloud {
    fn new() -> FakeCloud {
        FakeCloud {
            mission: "target".into(),
            caller: PRINCIPAL.into(),
            granted: true,
            lease: ("synthetic-cap-1".into(), 1),
            history: Some("synthetic-history-1".into()),
            items: HashMap::new(),
            questions: HashMap::new(),
            receipts: Vec::new(),
            sequence: 0,
            claims: 0,
            creates: 0,
            at: At::Never,
            journal_dir: None,
        }
    }

    fn lock_journal(&self) {
        let dir = self.journal_dir.as_ref().unwrap();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o500)).unwrap();
    }

    /// A restore from backup: receipt history is gone, so is its identity.
    fn restore(&mut self) {
        self.receipts.clear();
        self.history = Some("synthetic-history-2".into());
    }

    fn commit(&mut self, operation: &ResolvedOperation<'_>) -> Result<Vec<String>, CallFailure> {
        let mut mint = |prefix: &str| {
            self.sequence += 1;
            format!("synthetic-{prefix}-{}", self.sequence)
        };
        match operation.kind {
            Kind::WorkAdd => {
                let add: WireAdd =
                    serde_json::from_slice(operation.request).map_err(|_| CallFailure::Refused)?;
                for row in &add.items {
                    if let Some(parent) = &row.parent_id {
                        if !self.items.contains_key(parent) || row.horizon.is_some() {
                            return Err(CallFailure::Refused);
                        }
                    }
                }
                let ids: Vec<String> = add.items.iter().map(|_| mint("item")).collect();
                self.items.extend(ids.iter().cloned().zip(add.items));
                Ok(ids)
            }
            Kind::WorkAsk => {
                let ask: WireAsk =
                    serde_json::from_slice(operation.request).map_err(|_| CallFailure::Refused)?;
                if !self.items.contains_key(&ask.work_item_id) {
                    return Err(CallFailure::Refused);
                }
                let id = mint("question");
                self.questions.insert(id.clone(), ask);
                Ok(vec![id])
            }
        }
    }
}

impl ReplayBackend for FakeCloud {
    fn history(&mut self, target: &str) -> Result<String, CallFailure> {
        match &self.history {
            Some(history) if target == self.mission => Ok(history.clone()),
            _ => Err(CallFailure::Refused),
        }
    }

    fn claim(&mut self, target: &str) -> Result<LiveLease, CallFailure> {
        self.claims += 1;
        if self.at == At::LockJournalOnClaim {
            self.lock_journal();
        }
        if target != self.mission || !self.granted {
            return Err(CallFailure::Refused);
        }
        Ok(LiveLease {
            mission_id: target.into(),
            principal: self.caller.clone(),
            capability: self.lease.0.clone(),
            fencing_token: self.lease.1,
        })
    }

    fn create(
        &mut self,
        operation: &ResolvedOperation<'_>,
        lease: &LiveLease,
    ) -> Result<CreationReceipt, CallFailure> {
        self.creates += 1;
        let call = self.creates;
        if self.at == At::CrashBeforeCommit(call) {
            panic!("synthetic process death before commit");
        }
        if self.at == At::RotateLease(call) {
            self.lease = ("synthetic-cap-2".into(), self.lease.1 + 1);
        }
        if operation.target_mission_id != self.mission
            || !self.granted
            || (lease.capability.as_str(), lease.fencing_token)
                != (self.lease.0.as_str(), self.lease.1)
        {
            return Err(CallFailure::Refused);
        }
        let semantic =
            semantic_sha256(operation.kind, operation.request).ok_or(CallFailure::Refused)?;
        if let Some(receipt) = self.receipts.iter().find(|r| {
            (r.principal.as_str(), r.kind, r.key.as_str())
                == (
                    self.caller.as_str(),
                    operation.kind,
                    operation.operation_key,
                )
        }) {
            return if receipt.semantic == semantic {
                Ok(CreationReceipt {
                    ids: receipt.ids.clone(),
                })
            } else {
                Err(CallFailure::Refused)
            };
        }
        let ids = self.commit(operation)?;
        self.receipts.push(Receipt {
            principal: self.caller.clone(),
            kind: operation.kind,
            key: operation.operation_key.into(),
            semantic,
            ids: ids.clone(),
        });
        match self.at {
            At::CrashAfterCommit(n) if n == call => panic!("synthetic process death after commit"),
            At::LoseResponse(n) if n == call => Err(CallFailure::OutcomeUnknown),
            At::InvalidIds(n) if n == call => Ok(CreationReceipt {
                ids: vec![ids[0].clone(); ids.len()],
            }),
            At::LockJournalAfterCommit(n) if n == call => {
                self.lock_journal();
                Ok(CreationReceipt { ids })
            }
            _ => Ok(CreationReceipt { ids }),
        }
    }
}

fn run(cloud: &mut FakeCloud, path: &Path, action: ReplayAction) -> Result<RunReport, StopCode> {
    execute(&plan(), path, cloud, action)
}

fn complete() -> RunReport {
    RunReport {
        stop: None,
        acknowledged_items: 3,
        acknowledged_questions: 1,
        unknown_operations: 0,
        pending_operations: 0,
    }
}

fn assert_trace(cloud: &FakeCloud, path: &Path) {
    let (roots, child, question) = (ids(path, 0), ids(path, 1), ids(path, 2));
    assert_eq!(cloud.items.len(), 3);
    assert_eq!(cloud.questions.len(), 1);
    assert_eq!(roots.len(), 2);
    assert_ne!(roots[0], roots[1], "equal titles never share an identity");
    assert_eq!(
        cloud.items[&child[0]].parent_id.as_deref(),
        Some(roots[0].as_str())
    );
    assert_eq!(cloud.questions[&question[0]].work_item_id, child[0]);
}

// --- O0 golden vectors ---

#[test]
fn o0_operation_keys_match_frozen_vectors() {
    for vector in vectors()["keys"].as_array().unwrap() {
        let kind: Kind = serde_json::from_value(vector["kind"].clone()).unwrap();
        let source_ids: Vec<String> = serde_json::from_value(vector["source_ids"].clone()).unwrap();
        let (canonical, key) = operation_key("navlun", "source", "target", kind, &source_ids);
        assert_eq!(canonical, vector["canonical"].as_str().unwrap().as_bytes());
        assert_eq!(key, vector["operation_key"].as_str().unwrap());
        assert_eq!(key.len(), 71);
    }
    let keys: Vec<String> = plan().operations.iter().map(|o| o.key.clone()).collect();
    let all = vectors();
    let frozen: Vec<&str> = all["keys"].as_array().unwrap()[..3]
        .iter()
        .map(|v| v["operation_key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, frozen);
}

#[test]
fn o0_keys_exclude_text_snapshot_and_principal() {
    let mut changed = manifest();
    changed.projects[0].batches[0][0].title = "Another title".into();
    changed.projects[0].snapshot_sha256 = "b".repeat(64);
    let other = allocation(changed, "human:someone");
    let keys = |plan: &Allocation| -> Vec<String> {
        plan.operations.iter().map(|o| o.key.clone()).collect()
    };
    assert_eq!(keys(&other), keys(&plan()));
    assert_ne!(other.manifest_sha256, plan().manifest_sha256);
}

#[test]
fn o0_request_bytes_and_semantic_hashes_match_frozen_vectors() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::Start),
        Ok(complete())
    );
    let entries = journal(&dir.journal())["entries"].clone();
    let frozen = vectors()["synthetic_requests"].clone();
    for (index, vector) in frozen.as_array().unwrap().iter().enumerate() {
        let entry = &entries[index];
        let request = encode(&entry["request"]);
        assert_eq!(request, vector["canonical"].as_str().unwrap().as_bytes());
        assert_eq!(entry["request_sha256"], vector["request_sha256"]);
        assert_eq!(entry["operation_key"], vector["operation_key"]);
        assert_eq!(
            cloud.receipts[index].semantic,
            vector["semantic_sha256"].as_str().unwrap()
        );
    }
    assert_eq!(cloud.receipts.len(), 3);
}

#[test]
fn o0_request_escaping_matches_frozen_vectors() {
    let frozen = vectors()["escaping_requests"].clone();
    let text = frozen[0]["text"].as_str().unwrap().to_owned();
    let mut tricky = manifest();
    let project = &mut tricky.projects[0];
    project.batches = vec![vec![ItemRecord {
        horizon: Some(Horizon::Later),
        intent: text.clone(),
        parent_source_id: None,
        source_id: "root-a".into(),
        title: text.clone(),
    }]];
    project.questions = vec![QuestionRecord {
        proposal: Some(text.clone()),
        question: text,
        source_id: "q".into(),
        work_item_source_id: "root-a".into(),
    }];
    let plan = allocation(tricky, PRINCIPAL);
    let mut mappings = Mappings::default();
    let add = plan.operations[0].request(&mappings).unwrap();
    mappings.record(&plan.operations[0], &["synthetic-item-1".into()]);
    let ask = plan.operations[1].request(&mappings).unwrap();
    for (bytes, vector) in [(add, &frozen[0]), (ask, &frozen[1])] {
        let kind: Kind = serde_json::from_value(vector["kind"].clone()).unwrap();
        assert_eq!(bytes, vector["canonical"].as_str().unwrap().as_bytes());
        assert_eq!(
            sha256_hex(&bytes),
            vector["request_sha256"].as_str().unwrap()
        );
        assert_eq!(
            semantic_sha256(kind, &bytes).unwrap(),
            vector["semantic_sha256"].as_str().unwrap()
        );
    }
}

// --- R1 vertical slice ---

#[test]
fn root_root_child_question_trace_completes_and_replays_with_original_ids() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::Start),
        Ok(complete())
    );
    assert_trace(&cloud, &dir.journal());
    assert_eq!(cloud.creates, 3);
    let before = fs::read(dir.journal()).unwrap();
    // Approved same-key replay of a complete journal confirms every result.
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_eq!(cloud.creates, 6);
    assert_eq!((cloud.items.len(), cloud.questions.len()), (3, 1));
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
    let mode = fs::metadata(dir.journal()).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn committed_response_loss_stops_and_same_key_resume_returns_original_ids() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::LoseResponse(1);
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(
        report,
        RunReport {
            stop: Some(StopCode::OutcomeUnknown),
            acknowledged_items: 0,
            acknowledged_questions: 0,
            unknown_operations: 1,
            pending_operations: 2,
        }
    );
    assert_eq!(cloud.creates, 1, "no later operation is sent");
    assert_eq!(states(&dir.journal()), ["unresolved", "pending", "pending"]);
    let committed: Vec<String> = cloud.receipts[0].ids.clone();
    // Starting over is never a recovery: the journal exists.
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::Start),
        Err(StopCode::JournalExists)
    );
    assert_eq!((cloud.claims, cloud.creates), (1, 1));
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_eq!(ids(&dir.journal(), 0), committed);
    assert_trace(&cloud, &dir.journal());
}

#[test]
fn question_response_loss_recovers_without_a_second_question() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::LoseResponse(3);
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(
        (
            report.stop,
            report.acknowledged_items,
            report.unknown_operations
        ),
        (Some(StopCode::OutcomeUnknown), 3, 1)
    );
    let question = cloud.receipts[2].ids.clone();
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_eq!(ids(&dir.journal(), 2), question);
    assert_eq!(cloud.questions.len(), 1);
}

#[test]
fn process_death_at_send_commit_and_ack_boundaries_resumes_from_journal() {
    for (at, committed, expected) in [
        (
            At::CrashBeforeCommit(1),
            0,
            ["in_flight", "pending", "pending"],
        ),
        (
            At::CrashAfterCommit(1),
            2,
            ["in_flight", "pending", "pending"],
        ),
        (
            At::CrashBeforeCommit(2),
            2,
            ["acknowledged", "in_flight", "pending"],
        ),
    ] {
        let dir = Dir::new();
        let mut cloud = FakeCloud::new();
        cloud.at = at;
        let died = catch_unwind(AssertUnwindSafe(|| {
            run(&mut cloud, &dir.journal(), ReplayAction::Start)
        }));
        assert!(died.is_err());
        assert_eq!(cloud.items.len(), committed);
        assert_eq!(states(&dir.journal()), expected);
        let original = cloud.receipts.first().map(|r| r.ids.clone());
        cloud.at = At::Never;
        assert_eq!(
            run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
            Ok(complete())
        );
        if let Some(original) = original {
            assert_eq!(ids(&dir.journal(), 0), original);
        }
        assert_trace(&cloud, &dir.journal());
    }
}

#[test]
fn intent_publication_failure_sends_nothing() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.journal_dir = Some(dir.0.clone());
    cloud.at = At::LockJournalOnClaim;
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(report.stop, Some(StopCode::Durability));
    assert_eq!(report.pending_operations, 3);
    assert_eq!(cloud.creates, 0);
    assert_eq!(states(&dir.journal()), ["pending", "pending", "pending"]);
    dir.mode(0o700);
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
}

#[test]
fn acknowledgment_publication_failure_stops_before_dependents() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.journal_dir = Some(dir.0.clone());
    cloud.at = At::LockJournalAfterCommit(1);
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(
        (report.stop, report.unknown_operations),
        (Some(StopCode::Durability), 1)
    );
    assert_eq!(cloud.creates, 1);
    assert_eq!(states(&dir.journal()), ["in_flight", "pending", "pending"]);
    let committed = cloud.receipts[0].ids.clone();
    dir.mode(0o700);
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_eq!(ids(&dir.journal(), 0), committed);
}

#[test]
fn invalid_receipt_ids_are_uncertainty_not_success() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::InvalidIds(1);
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(report.stop, Some(StopCode::OutcomeUnknown));
    assert_eq!(states(&dir.journal()), ["unresolved", "pending", "pending"]);
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_eq!(ids(&dir.journal(), 0), cloud.receipts[0].ids);
}

#[test]
fn missing_or_discontinuous_destination_history_sends_nothing() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.history = None;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::Start),
        Err(StopCode::HistoryUnavailable)
    );
    assert_eq!((cloud.claims, cloud.creates), (0, 0));
    assert!(!dir.journal().exists());

    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::LoseResponse(2);
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    let before = fs::read(dir.journal()).unwrap();
    cloud.at = At::Never;
    cloud.history = None;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Err(StopCode::HistoryUnavailable)
    );
    // Erased receipt history would let the same key create again.
    cloud.restore();
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Err(StopCode::HistoryDiscontinuity)
    );
    assert_eq!((cloud.claims, cloud.creates), (1, 2));
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
}

#[test]
fn current_grant_lease_and_principal_are_required() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.caller = "svc:other".into();
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::Start),
        Err(StopCode::AuthorityRefused)
    );
    assert_eq!(cloud.creates, 0);

    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    let before = fs::read(dir.journal()).unwrap();
    cloud.granted = false;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Err(StopCode::AuthorityRefused)
    );
    assert_eq!(cloud.creates, 3);
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
}

#[test]
fn stale_lease_after_preflight_stops_and_a_new_lease_recovers_same_keys() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::RotateLease(2);
    let report = run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    assert_eq!(report.stop, Some(StopCode::Refused));
    assert_eq!(cloud.creates, 2);
    assert_eq!(
        states(&dir.journal()),
        ["acknowledged", "unresolved", "pending"]
    );
    cloud.at = At::Never;
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Ok(complete())
    );
    assert_trace(&cloud, &dir.journal());
}

#[test]
fn changed_acknowledged_result_stops_and_keeps_original_ids() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    let before = fs::read(dir.journal()).unwrap();
    cloud.receipts[0].ids.reverse();
    let report = run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys).unwrap();
    assert_eq!(report.stop, Some(StopCode::ResultChanged));
    assert_eq!(cloud.creates, 4);
    assert_eq!(fs::read(dir.journal()).unwrap(), before);
}

#[test]
fn journal_corruption_drift_and_unsafe_paths_refuse_before_any_call() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::LoseResponse(2);
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    cloud.at = At::Never;
    let calls = (cloud.claims, cloud.creates);
    let original = fs::read(dir.journal()).unwrap();
    let resume = |cloud: &mut FakeCloud, plan: &Allocation| {
        execute(plan, &dir.journal(), cloud, ReplayAction::ResumeSameKeys)
    };

    // Non-canonical spelling, even with a valid checksum, is corruption.
    let mut spaced = original.clone();
    spaced.insert(1, b' ');
    fs::write(dir.journal(), &spaced).unwrap();
    assert_eq!(resume(&mut cloud, &plan()), Err(StopCode::JournalCorrupt));
    let mut flipped = String::from_utf8(original.clone()).unwrap();
    flipped = flipped.replacen("\"acknowledged\"", "\"in_flight\"", 1);
    fs::write(dir.journal(), flipped).unwrap();
    assert_eq!(resume(&mut cloud, &plan()), Err(StopCode::JournalCorrupt));
    fs::write(dir.journal(), &original).unwrap();

    assert_eq!(
        resume(&mut cloud, &allocation(manifest(), "svc:other")),
        Err(StopCode::JournalMismatch)
    );
    let mut changed = manifest();
    changed.projects[0].batches[1][0].intent = "Changed intent".into();
    assert_eq!(
        resume(&mut cloud, &allocation(changed, PRINCIPAL)),
        Err(StopCode::JournalMismatch)
    );

    let holder = Journal::open(&dir.journal()).unwrap();
    assert_eq!(resume(&mut cloud, &plan()), Err(StopCode::JournalLocked));
    drop(holder);

    let link = dir.0.join("link.json");
    std::os::unix::fs::symlink(dir.journal(), &link).unwrap();
    assert_eq!(
        execute(&plan(), &link, &mut cloud, ReplayAction::ResumeSameKeys).err(),
        Some(StopCode::JournalUnsafe)
    );
    assert_eq!(
        execute(
            &plan(),
            &dir.0.join("missing.json"),
            &mut cloud,
            ReplayAction::ResumeSameKeys
        )
        .err(),
        Some(StopCode::JournalUnsafe)
    );
    dir.mode(0o755);
    assert_eq!(resume(&mut cloud, &plan()), Err(StopCode::JournalUnsafe));
    dir.mode(0o700);

    assert_eq!((cloud.claims, cloud.creates), calls);
    assert_eq!(fs::read(dir.journal()).unwrap(), original);
    assert_eq!(resume(&mut cloud, &plan()), Ok(complete()));
}

#[test]
fn symlinked_directory_component_refuses_before_any_call() {
    let dir = Dir::new();
    let real = dir.0.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = dir.0.join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let mut cloud = FakeCloud::new();
    assert_eq!(
        run(&mut cloud, &alias.join("journal.json"), ReplayAction::Start),
        Err(StopCode::JournalUnsafe)
    );
    assert_eq!((cloud.claims, cloud.creates), (0, 0));
}

#[test]
fn external_journal_edit_is_never_replaced() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    let (mut journal, doc) = Journal::open(&dir.journal()).unwrap();
    fs::write(dir.journal(), b"external\n").unwrap();
    assert_eq!(journal.save(&doc).err(), Some(StopCode::JournalChanged));
    assert_eq!(fs::read(dir.journal()).unwrap(), b"external\n");
}

#[test]
fn tampered_request_with_valid_checksum_refuses_before_any_call() {
    let dir = Dir::new();
    let mut cloud = FakeCloud::new();
    cloud.at = At::LoseResponse(2);
    run(&mut cloud, &dir.journal(), ReplayAction::Start).unwrap();
    cloud.at = At::Never;
    let calls = (cloud.claims, cloud.creates);
    let mut doc = journal(&dir.journal());
    let request = r#"{"items":[{"intent":"Tampered","parentId":"synthetic-item-1","title":"Synthetic child"}]}"#;
    doc["entries"][1]["request"] = serde_json::from_str(request).unwrap();
    doc["entries"][1]["request_sha256"] = Value::String(sha256_hex(request.as_bytes()));
    let sha = sha256_hex(&encode(&doc));
    let mut bytes = encode(&serde_json::json!({"journal": doc, "sha256": sha}));
    bytes.push(b'\n');
    fs::write(dir.journal(), &bytes).unwrap();
    assert_eq!(
        run(&mut cloud, &dir.journal(), ReplayAction::ResumeSameKeys),
        Err(StopCode::JournalMismatch)
    );
    assert_eq!((cloud.claims, cloud.creates), calls);
}

#[test]
fn validation_refuses_scope_and_graph_errors() {
    type Edit = fn(&mut ProjectPlan);
    let cases: [Edit; 9] = [
        |p| p.project = "wapps-platform".into(),
        |p| p.target_mission_id = "Target".into(),
        |p| p.snapshot_sha256 = "A".repeat(64),
        |p| p.batches[0].clear(),
        |p| p.batches[1][0].parent_source_id = Some("missing".into()),
        |p| p.batches.swap(0, 1),
        |p| p.batches[1][0].horizon = Some(Horizon::Now),
        |p| p.batches[1][0].source_id = "root-a".into(),
        |p| p.project = "ecommerce".into(),
    ];
    for edit in cases {
        let mut invalid = manifest();
        edit(&mut invalid.projects[0]);
        assert!(matches!(validate(invalid), Err(StopCode::InvalidManifest)));
    }
    let mut twice = manifest();
    twice.projects.push(twice.projects[0].clone());
    assert!(matches!(validate(twice), Err(StopCode::InvalidManifest)));
    let mut oversized = manifest();
    oversized.projects[0].batches[0] = (0..501)
        .map(|n| item(&format!("r{n}"), None, "t", "i"))
        .collect();
    assert!(matches!(
        validate(oversized),
        Err(StopCode::InvalidManifest)
    ));
    let bad = allocate(
        &validate(manifest()).unwrap(),
        ExecutionBinding {
            principal: "nobody".into(),
        },
    );
    assert!(matches!(bad, Err(StopCode::InvalidBinding)));
}
