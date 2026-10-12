//! Planner-shaped manifest input, its structural validation, and the immutable
//! keyed allocation. Text/UTF-16/title/archive rules and planning from snapshot
//! rows belong to R2; this layer checks what allocation and request resolution
//! depend on.
use super::{canonical, StopCode};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const PROJECTS: [&str; 4] = [
    "ecommerce",
    "kick-clip-analyzer",
    "navlun",
    "real-estate-analysis",
];
const MAX_ITEMS: usize = 500;

// Every canonical struct below declares its fields in sorted key order.

#[derive(Clone, Debug, Serialize)]
pub struct Manifest {
    pub projects: Vec<ProjectPlan>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProjectPlan {
    /// Parent-first batches; a parent always sits in an earlier batch.
    pub batches: Vec<Vec<ItemRecord>>,
    pub project: String,
    pub questions: Vec<QuestionRecord>,
    pub snapshot_sha256: String,
    pub source_mission_id: String,
    pub target_mission_id: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ItemRecord {
    pub horizon: Option<Horizon>,
    pub intent: String,
    pub parent_source_id: Option<String>,
    pub source_id: String,
    pub title: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QuestionRecord {
    pub proposal: Option<String>,
    pub question: String,
    pub source_id: String,
    pub work_item_source_id: String,
}

/// `Deserialize` only for the test fake's wire decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(test, derive(Deserialize))]
#[serde(rename_all = "lowercase")]
pub enum Horizon {
    Now,
    Next,
    Later,
    Someday,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    WorkAdd,
    WorkAsk,
}

/// A manifest that passed `validate`; only `validate` constructs one.
pub struct ValidatedManifest {
    manifest: Manifest,
    sha256: String,
}

/// The principal the server must vouch for. It holds no credential.
pub struct ExecutionBinding {
    pub principal: String,
}

/// The complete ordered operation list, allocated before any send.
pub struct Allocation {
    pub(super) principal: String,
    pub(super) manifest_sha256: String,
    pub(super) operations: Vec<Operation>,
}

pub(super) struct Operation {
    pub(super) kind: Kind,
    pub(super) key: String,
    pub(super) project: String,
    pub(super) source_mission_id: String,
    pub(super) target_mission_id: String,
    pub(super) snapshot_sha256: String,
    pub(super) source_ids: Vec<String>,
    records: Records,
}

enum Records {
    Items(Vec<ItemRecord>),
    Question(QuestionRecord),
}

/// Acknowledged source item -> destination item, scoped to the full source
/// and target identity; titles never establish a match.
#[derive(Default)]
pub(super) struct Mappings(HashMap<[String; 5], String>);

pub fn validate(manifest: Manifest) -> Result<ValidatedManifest, StopCode> {
    let valid = (1..=PROJECTS.len()).contains(&manifest.projects.len())
        && distinct(manifest.projects.iter().map(|p| p.project.as_str()))
        && distinct(
            manifest
                .projects
                .iter()
                .map(|p| p.target_mission_id.as_str()),
        )
        && manifest.projects.iter().all(valid_project);
    if !valid {
        return Err(StopCode::InvalidManifest);
    }
    let sha256 = canonical::sha256_hex(&canonical::encode(&manifest));
    Ok(ValidatedManifest { manifest, sha256 })
}

fn distinct<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn mission_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    (1..=128).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

fn valid_project(plan: &ProjectPlan) -> bool {
    let hex = plan.snapshot_sha256.len() == 64
        && plan
            .snapshot_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !PROJECTS.contains(&plan.project.as_str())
        || !mission_id(&plan.source_mission_id)
        || !mission_id(&plan.target_mission_id)
        || !hex
    {
        return false;
    }
    // A parent must be acknowledged before its child's batch is resolved.
    let mut earlier = HashSet::new();
    for batch in &plan.batches {
        let valid_batch = (1..=MAX_ITEMS).contains(&batch.len())
            && batch.iter().all(|item| {
                !item.source_id.is_empty()
                    && !earlier.contains(item.source_id.as_str())
                    && match &item.parent_source_id {
                        Some(parent) => earlier.contains(parent.as_str()) && item.horizon.is_none(),
                        None => true,
                    }
            })
            && distinct(batch.iter().map(|item| item.source_id.as_str()));
        if !valid_batch {
            return false;
        }
        earlier.extend(batch.iter().map(|item| item.source_id.as_str()));
    }
    let question_limit = usize::from(plan.project == "navlun");
    plan.questions.len() <= question_limit
        && plan
            .questions
            .iter()
            .all(|q| !q.source_id.is_empty() && earlier.contains(q.work_item_source_id.as_str()))
}

pub fn allocate(
    manifest: &ValidatedManifest,
    binding: ExecutionBinding,
) -> Result<Allocation, StopCode> {
    let principal = binding.principal;
    let valid_principal = ["human:", "svc:"].iter().any(|prefix| {
        principal.strip_prefix(prefix).is_some_and(|rest| {
            !rest.is_empty() && !rest.chars().any(|c| c.is_whitespace() || c == ',')
        })
    });
    if !valid_principal {
        return Err(StopCode::InvalidBinding);
    }
    let mut operations = Vec::new();
    for plan in &manifest.manifest.projects {
        let records = plan
            .batches
            .iter()
            .map(|batch| (Kind::WorkAdd, Records::Items(batch.clone())))
            .chain(
                plan.questions
                    .iter()
                    .map(|q| (Kind::WorkAsk, Records::Question(q.clone()))),
            );
        for (kind, records) in records {
            let source_ids = match &records {
                Records::Items(items) => items.iter().map(|i| i.source_id.clone()).collect(),
                Records::Question(question) => vec![question.source_id.clone()],
            };
            let (_, key) = operation_key(
                &plan.project,
                &plan.source_mission_id,
                &plan.target_mission_id,
                kind,
                &source_ids,
            );
            operations.push(Operation {
                kind,
                key,
                project: plan.project.clone(),
                source_mission_id: plan.source_mission_id.clone(),
                target_mission_id: plan.target_mission_id.clone(),
                snapshot_sha256: plan.snapshot_sha256.clone(),
                source_ids,
                records,
            });
        }
    }
    if !distinct(operations.iter().map(|o| o.key.as_str())) {
        return Err(StopCode::InvalidManifest);
    }
    Ok(Allocation {
        principal,
        manifest_sha256: manifest.sha256.clone(),
        operations,
    })
}

#[derive(Serialize)]
struct KeyIdentity<'a> {
    kind: Kind,
    project: &'a str,
    source_ids: &'a [String],
    source_mission_id: &'a str,
    target_mission_id: &'a str,
    version: u8,
}

/// The frozen od10k1 key: canonical identity bytes and the 71-character key.
pub(super) fn operation_key(
    project: &str,
    source_mission_id: &str,
    target_mission_id: &str,
    kind: Kind,
    source_ids: &[String],
) -> (Vec<u8>, String) {
    let identity = canonical::encode(&KeyIdentity {
        kind,
        project,
        source_ids,
        source_mission_id,
        target_mission_id,
        version: 1,
    });
    let key = format!("od10k1-{}", canonical::sha256_hex(&identity));
    (identity, key)
}

#[derive(Serialize)]
struct AddRequest<'a> {
    items: Vec<NewItem<'a>>,
}

#[derive(Serialize)]
struct NewItem<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    horizon: Option<Horizon>,
    intent: &'a str,
    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    parent_id: Option<&'a str>,
    title: &'a str,
}

#[derive(Serialize)]
struct AskRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    proposal: Option<&'a str>,
    question: &'a str,
    #[serde(rename = "workItemId")]
    work_item_id: &'a str,
}

impl Operation {
    pub(super) fn records(&self) -> usize {
        match &self.records {
            Records::Items(items) => items.len(),
            Records::Question(_) => 1,
        }
    }

    fn mapping_key(&self, source_id: &str) -> [String; 5] {
        [
            self.project.clone(),
            self.source_mission_id.clone(),
            self.target_mission_id.clone(),
            self.snapshot_sha256.clone(),
            source_id.to_owned(),
        ]
    }

    fn destination(&self, mappings: &Mappings, source_id: &str) -> Result<String, StopCode> {
        let key = self.mapping_key(source_id);
        mappings
            .0
            .get(&key)
            .cloned()
            .ok_or(StopCode::JournalMismatch)
    }

    /// Exact authority-free request bytes with acknowledged IDs substituted.
    /// Optional fields are omitted, never sent as null.
    pub(super) fn request(&self, mappings: &Mappings) -> Result<Vec<u8>, StopCode> {
        match &self.records {
            Records::Items(items) => {
                let parents = items
                    .iter()
                    .map(|item| match &item.parent_source_id {
                        Some(parent) => self.destination(mappings, parent).map(Some),
                        None => Ok(None),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let items = items
                    .iter()
                    .zip(&parents)
                    .map(|(item, parent)| NewItem {
                        horizon: item.horizon,
                        intent: &item.intent,
                        parent_id: parent.as_deref(),
                        title: &item.title,
                    })
                    .collect();
                Ok(canonical::encode(&AddRequest { items }))
            }
            Records::Question(question) => {
                let item = self.destination(mappings, &question.work_item_source_id)?;
                Ok(canonical::encode(&AskRequest {
                    proposal: question.proposal.as_deref(),
                    question: &question.question,
                    work_item_id: &item,
                }))
            }
        }
    }
}

impl Mappings {
    pub(super) fn record(&mut self, operation: &Operation, destination_ids: &[String]) {
        if operation.kind == Kind::WorkAdd {
            for (source, destination) in operation.source_ids.iter().zip(destination_ids) {
                self.0
                    .insert(operation.mapping_key(source), destination.clone());
            }
        }
    }
}
