# Offline replay preparation

**Nothing has migrated. Slice 13.11 is not complete.** These standard-library Python
3.11+ tools are offline preparation, not a Rust daemon component or live executor.
There is no HTTP/MCP adapter, credential path, implicit installed-store discovery,
deployment, installation or retirement path. Platform operationKey is merged but
**NOT DEPLOYED** at this handoff; source agreement cannot authorize live replay.

## Modules and evidence

- `replay_plan.py`: read-only, explicitly supplied standalone SQLite snapshots;
  private manifest with original selected records, fingerprints, deterministic
  parent-first batches, diagnostics and unresolved source-ID references.
- `replay_recovery.py`: legacy in-memory `FakeWorkServer` and durable private client
  receipts; uncertain outcomes stop without retry or inventory-based adoption.
- `synthetic_recovery.py`, `recovery_demo.py`: canned synthetic inputs only. The demo
  has no real-manifest, URL, database or resume option.
- `replay_keyed.py`: separate private synthetic JSON destination, modeled current
  principal/grant/lease checks and result-on-retry receipts; imported only by tests.
- `test_replay.py`, `test_recovery.py`, `test_keyed.py`: all **98 original tests**,
  unchanged (38 planner, 29 legacy, 31 keyed). Use `../verify.py` to execute indexed
  sources in a private temporary home. Original logs remain local, not in this record.
- `source-contract.txt`: historical platform fingerprints plus a separately labeled
  source-only comparison. Production tests were read, not run by this preparation.

## Planner scope and private operator contract

Eligible projects are `navlun`, `ecommerce`, `kick-clip-analyzer` and
`real-estate-analysis`; `wapps-platform` is rejected. Explicit source and destination
mission IDs are required for every provided project. A subset is permitted for
preparation; `projects_not_provided` records the gap, and complete OD10 preparation
requires all four. Duplicate projects/shared destinations are refused. No project name
is treated as a verified mission mapping. Snapshot state determines counts, not old
planning counts. The source mission must exist exactly once and be active.

Select all open work. Only navlun may select a question, at most one, by exact source
ID. Any additional open question blocks planning rather than being dropped. If current
scope differs from OD10, return to the owner. Any semantic issue blocks **every**
project's batches/questions, while preserving original selected records and issues.

Input shape (illustrative placeholders, **not verified mappings**):

```json
{
  "sources": [{
    "project": "navlun",
    "snapshot": "/private/immutable/snapshots/synthetic.sqlite",
    "source_mission_id": "replace-source-mission",
    "target_mission_id": "replace-target-mission",
    "selected_question_ids": [],
    "approved_lossy_transformations": []
  }]
}
```

A separately authorized operator could invoke `replay_plan.py --config <absolute-private-file>
--output <new-private-file>`. This record runs only generated synthetic fixtures, not
real inputs. The output directory must already be private (normally `0700`); the new
file is `0600`, exclusive, flushed and fsynced. Existing files/symlinks are refused.
No force/stdout/live switch exists. Fixed diagnostics avoid printing work text or paths.
Exit `0` means a structurally reviewable manifest, `3` means a written blocked manifest,
`2` means invalid/unsafe input or I/O failure. Interrupted writes can leave partial
private files: preserve them and do not treat them as valid manifests.

Every manifest says `nothing_migrated: true`, `live_replay_safe: false`. It retains
complete selected source rows/text and inventory of metadata not replayed. That makes
real manifests sensitive: never commit, publish or log them. Source missions/items/
questions are the only interpreted tables; jobs, transcripts, leases and credentials
are not queried. Opaque file hashing is not a claim to exclude other tables' bytes.

Snapshots must be stable, consistent, standalone offline SQLite backups from stopped
writers. The planner uses escaped URI `mode=ro&immutable=1`, `query_only=ON` and
`trusted_schema=OFF`; existing WAL/SHM/journal sidecars are refused. `immutable=1` is
an assumption, not a freeze mechanism. Before/after hashes detect drift but cannot
make concurrent mutation safe. No checkpoint, copy, repair, upgrade or deletion occurs.

## Transformations and limits

Parents must precede children in earlier batches. Siblings are ordered by original
position/source ID; cycles, missing/closed/cross-mission parents and child horizons
block. Source IDs are not sendable destination IDs; only acknowledged receipts may
resolve them. Question item references resolve separately after item replay.

Cloud application limits: 500 items/batch; 500 UTF-16 units/title; 100,000/intent;
4,000/question or proposal; 128/parent ID. Roots may be unplaced/null in source or
`now`, `next`, `later`, `someday`. Optional absent fields are not invalid wire nulls.
Text trimming is ECMAScript-compatible, including BOM and excluding NEL. Padded text
is not silently trimmed; oversized intents/questions/proposals are never truncated.

Title shortening is lossless only when the complete original title is the complete
target intent and fits that ceiling. Otherwise the exact `title-shortening:<source-id>`
requires owner review of that item/snapshot before an operator adds its approval ID.
Approval strings are **assertions, not attested human consent**; automation cannot
add them for the owner. Original text remains preserved; unused approvals are refused.
Archive-only metadata (timestamps, job/index provenance, adoption links) is explicitly
listed. `discovered_from` is cloud-supported but outside OD10's selected field list,
not an unsupported cloud field. Review the archive-only treatment before live replay.

The 1 MiB body budget with 4 KiB authority reserve and worst-case escaped parent ID
is a conservative preparation policy, not an effective deployed HTTP or 13.1 frame
limit. A future executor must measure the **final** serialized authority/key/envelope
before publishing the immutable allocation. Re-batching after an attempted send can
change identity and duplicate work; it is not recovery.

## Legacy recovery: uncertainty remains unresolved

Legacy format `od10-fake-receipt-v1` is **fake-only**, never a live receipt. It binds
manifest digest and ordered operation identities derived from scope/snapshot/source IDs,
with exact resolved request/checksum, baseline IDs, ordered destination IDs and state.
Titles/counts never establish identity. Persist `in_flight` intent before the call;
persist verified ordered IDs after success. Acknowledged mappings are rechecked on
restart, including parent/question links. Pending later work may continue only when
earlier work is durably acknowledged.

Response loss, malformed acknowledgment, unexpected exceptions and an interrupted
`in_flight` entry become `unresolved`. Stop **all** later work. Even inventory absence
or a uniquely matching new row cannot prove original caller/rollback. No resend,
operator override or conversion to a keyed receipt exists. Explicit modeled whole-batch
refusals are `failed` and also stop. A question's uncertainty is independent of items.
Demo exits: `0` fake reconciliation, `3` stopped fake run, `2` unsafe/invalid/I/O failure;
a second invocation with the same receipt name refuses rather than inventing fresh
fake destination history.

## Keyed synthetic recovery: immutable identity, current authority

Client key = `od10k1-` + SHA-256 of compact, sorted-key ASCII JSON containing
`version:1`, project, source mission, target mission, fixed verb and ordered source IDs.
The result is 71 ASCII characters. Principal is server-scoped separately and explicitly
bound by the client journal. Mutable title/intent, snapshot hash, destination IDs,
capability/fence/time do **not** enter the key; they cannot silently mint new identities
for uncertain work. Snapshot/text/transformations/batch partition and question selection
remain immutable journal bindings. Do not re-plan, change target/principal or start a
fresh journal after an attempted send.

Separate `od10-keyed-fake-receipt-v1` binds fake-only status, manifest digest, principal
and the complete ordered key/verb allocation. `pending` becomes durably `in_flight`
before send. `in_flight`/`unresolved` stop; only the synthetic test action
`approved_retry=True` may repeat the original key/payload/scope. This flag is **not
owner consent**. Acknowledged operations also require matching original server IDs
under current authorization on approved restart. Revoked grants, expired/stale/wrong
leases, drift/corruption/conflict or invalid results stop without replacing keys.

The fake normalizes typed semantic values and hashes compact UTF-8 JSON, matching the
pinned source field/tuple ordering rather than arbitrary input-object ordering. Server
scope is mission database + principal + fixed verb + key. Current grant/live lease
checks precede receipt lookup. Mutation, receipt insert and lease touch are modeled
as one private atomic JSON publication. Same semantic key returns original IDs;
changed content conflicts. Refused creations do not reserve keys. Later item closure
or question withdrawal does not invalidate a creation receipt: **creation evidence is
not final-content verification**. The fake models no Access JWT verification, real
clock, alarms, DO scheduling, SQL rollback, HTTP/MCP, pagination or hardware power loss.

## Durability and unresolved boundaries

Receipts use private UID-owned directories, exclusive/no-follow `0600` regular files,
single links, persistent advisory lock inode, atomic replacement and file/directory
fsync. Corrupt/partial JSON, duplicate keys, unknown schema/states, reordered operations,
invalid references and changed bindings refuse without repair/force/truncation. Failed
intent persistence sends nothing. Hard exits can leave private temporary files; retain
for inspection, never adopt/auto-delete them. SHA-256 detects corruption, **not
origin/consent**; same-UID coherent tampering and rollback are not prevented. Advisory
locks assume cooperating writers. Tests cover modeled process death and I/O faults,
not hardware durability guarantees.

Still unsafe to auto-replay: any old unkeyed ambiguous creation; missing/corrupt journals
or committed results; principal/target/allocation drift; restored/deleted destination
receipt history or a new database under a reused mission identity. Source has no
pending/result-lookup endpoint or external history capable of repairing erased receipts.
Registry/roster admission and mission mutation are separate authorities, not a claimed
cross-object atomic revocation guarantee. Post-commit response/alarm failure remains
uncertain until an authorized same-key result is obtained; refusals never authorize
bypass of grants or lease.

## Live prerequisites remain closed

Before a separately approved live operation: independently review production Rust
client/receipt integration and real transport; verify deployed matching code, receipt
schema/migration/retention and effective limits; establish exact SSO/Access principal,
registration, mappings, per-request claim grants/capabilities and current lease without
taking over active leases; obtain owner cut-over consent and stop plugin writers; create
fresh verified private standalone snapshots; remeasure scope/questions/transformations;
publish immutable operation allocation; retain client/server history for recovery;
verify final source-to-target counts, every retained field and link, then release via
the planned flow. Plugin retirement is separately authorized slice 13.12; old stores
are not deleted here. Synthetic tests, source comparison and a zero preparation exit
prove none of these live prerequisites.
