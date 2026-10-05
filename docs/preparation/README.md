# Broker preparation index

This directory records offline preparation, not completed product slices. **Nothing
has migrated.** No Rust runtime, manifest, install, deployment, main merge, push,
credential operation, live store read or plugin retirement is part of this record.
The Python models are preparation tooling only, not an exception to the Rust product
language boundary.

| Area | Completed preparation | Still blocked / unverified |
|---|---|---|
| `replay-13-11/` | Offline planner, legacy recovery model, keyed synthetic model; all 98 original tests preserved | Production Rust client/journal, independently verified deployment, owner cut-over consent, exact SSO principal/grants/current lease, immutable private snapshots and final-content reconciliation |
| `worker-cli-13-5/` | Original English research synthesis, seven safe help/version cases, six synthetic probe tests | OD5: real main-thread skills/effort, fail-closed policy, NDJSON and cancellation behavior |
| `verify.py` | Git-indexed clean-source extraction; isolated synthetic tests and canned demos; individual subprocess exits | Not a deployed-service, production transport or independent review gate |

## Reproduce offline verification

Stage **only explicitly reviewed files under `docs/preparation/`** first (or use a
clean committed checkout). The verifier refuses missing indexed sources, conflicts,
symlinks and unstaged differences; it extracts the indexed inventory into a private
temporary directory, creates fresh HOME/config/tmp directories, supplies an environment
allowlist, then runs each suite separately and the combined replay suite. It never
invokes an installed model CLI. Synthetic fixture databases and receipts are created
only inside that disposable private copy, not in preserved evidence directories.

```sh
base=/absolute/path/to/your/wapps-cli-worktree
python3 -B "$base/docs/preparation/verify.py"
result=$?
printf 'PREPARATION_VERIFY_EXIT=%s\n' "$result"
```

Expected child exits: planner `0` (38 tests), legacy `0` (29), keyed `0` (31), combined
replay `0` (98), safe probe `0` (6); canned legacy success `0`, response-loss `3`,
failed-batch `3`. These latter nonzero exits are expected stop states, not passing live
replays. The verifier returns `0` only when all recorded expectations hold; `1` means
an unexpected gate exit, `2` means unsafe/missing indexed input or execution failure.
Each JSON result includes the SHA-256 of the indexed inventory used for that run.
Direct child statuses `47` and `71` at modeled process-interruption boundaries are
asserted inside the original tests; no broad process killing is used.

## Provenance and curation

The preserved source is the `broker-daemon-13-1` worktree's local
`docs/preparation/replay-13-11/` and `docs/preparation/worker-cli-13-5/` directories.
Eight inspected replay Python files were copied. The three replay test files remain
byte-identical to their originals; the legacy module's introductory comment was
corrected to distinguish legacy behavior from merged keyed source. No replay behavior
was changed. The indexes and worker synthesis are new, and the worker probe was
rewritten to avoid embedding native-CLI/SDK code, host paths or raw stdout/stderr.

Historical red/green logs, raw `evidence.json`, original worker `contract.json`, native
excerpts and original hardcoded `probe.py` remain only in the preserved local preparation
directory. They were neither copied into Git nor overwritten by rerunning the old probe.
Historical worker measurements and source inspection are labeled as historical, not
new runtime proof. See `replay-13-11/source-contract.txt` for the pinned fingerprints
and the separate bounded annotation-delta comparison.

Curation review found no real credential values or user work-item content in the
copied Python files. All records, principals and capability strings in tests are
synthetic. Original worker evidence contains machine paths and native/SDK source
excerpts: excluded rather than published as a machine dump. Project names explicitly
selected by OD10 remain part of the replay scope, not inferred private mappings.
Do not commit real snapshots, manifests, receipts, probe stdout, credentials or logs.

The optional challenge instructions were loaded, but no panel/model-backed helper ran
because this lane excludes model-backed sessions. **WARN: independent challenge not
run.** Local review and synthetic tests are not independent review. Sequential Astra
review follows this committed record; this lane does not start that review or another
slice. All live gates remain closed.
