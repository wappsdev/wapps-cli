# The broker's local execution plane in the `wapps` CLI: measured inventory and slice plan

**This document changes no code.** It is the input to a port lane, the broker's
platform-side **slice 13** (`wapps-platform/docs/broker-l5-pricing.md`, "OWNER
DECISION 2026-10-05: the broker's MCP surface, in Rust, in two pieces"). The owner
decided that the agent broker's local execution plane leaves the bun/TypeScript
plugin (`dual-orchestrator-agent-broker`) and moves into the Rust `wapps` binary,
for example as `wapps broker serve`. That binary serves stdio MCP, runs as the
daemon, talks to the live cloud broker (`services/broker`, going live at
`broker.meapps.dev`), and the plugin is retired.

**Every number here was found by running something in these trees.** Where a number
comes from reading source rather than running it, the text says "read, not run". §10
lists what was not measured. The scripts that produced the tables of §2.3, §3.5, §4.5,
§7.1 and OD7 are committed in `docs/broker-daemon-port.measure/` (§0), so a reader can
rerun them. A sum is called a sum, not a measurement, when it is computed from parts
that were measured separately.

Measurement record:

| | |
|---|---|
| source (oracle) | `dual-orchestrator-agent-broker` `c6d7e09fa0df9d8ad231fd56520a14fee4432ba5` (clean) |
| target | `wapps-cli` `765ca48` (`main`); this doc is on `lane/broker-daemon-pricing` |
| cloud broker | `wapps-platform` **`57b8bbb`**: see the note below |
| plugin test suite | `bun test` (bun 1.4.0) in a scratch copy: **585 pass, 0 fail, 107 files, 63.7 s** |
| plugin MCP transcript | recorded live from `bun src/main.ts` in a scratch copy (§3.1) |
| claude spawn seam | recorded with a fake `claude` binary in the scratch copy (§4.2) |
| scripts | `docs/broker-daemon-port.measure/` in this branch: `slices.py`, `schema_diff.py`, `tools_list.ts`, `od7.py`, `stores.sh`, `scrub_probe.ts` (§0) |

**`wapps-platform` `main` moved while this was being measured.** The task text was
written against `7cf2d20`. At 06:32 `57b8bbb` merged ("broker L5 slice 9b - the 37
handlers answer in Rust"), and `services/broker/src/http/` is gone. Every citation of
a cloud route or body below was **re-measured at `57b8bbb`**. Routes are in
`crates/workers/src/broker_routes.rs`, bodies in `crates/core/src/broker/body.rs`.

Baseline sizes (`wc -l`):

| tree | lines |
|---|---:|
| plugin `src/**/*.ts` (86 tracked files, 57 `.ts`) | **10,963** |
| plugin `src/storage/migrations/*.sql` (29 files) | 379 |
| plugin `test/**/*.test.ts` (107 files) | 12,828 |
| plugin `scripts/` (4 files) | 1,581 |
| plugin `skills/agent-broker/SKILL.md` | 513 |
| `wapps-cli` Rust `src/` today | 16,777 |

---

## 0. How it was measured

**Nothing ran in the source repository.** `rsync` copied it (without its git-ignored
`state/`) to `/tmp/broker-oracle.mw98/src-copy`, and every run happened there with
`HOME` pointed at a scratch directory. Afterwards `git status` in the source repository
was empty and its `state/fixture/worktrees` count was unchanged (156).

**Finding 0.1: the plugin's test suite is not hermetic.** With `HOME` isolated, the
first run failed **17 of 585** tests, all with one error: `declared skill not found in
any skill root: superpowers:test-driven-development`. The suite reads the owner's real
`~/.claude/plugins` to resolve skills that `projects/self/roles.json` declares. With
read-only symlinks to `~/.claude/{plugins,skills}` inside the scratch `HOME`, the
second run passed 585/585. An oracle that depends on what is installed on the machine
running it does not give the same verdict on every machine. §6 has to fix that before
it can use these tests.

**Finding 0.2: the task said 52 test files. That count does not reproduce.** `git ls-files test`
holds 107 `*.test.ts`: 46 under `test/`, 2 under `test/unit/` and 59 under
`test/mutation/`. They contain 573 `test(`/`it(` call sites (static count). Bun runs
**585**, because some tests are generated in loops. No grouping I tried produces 52.

**The live state was read through SQLite's read-only URI** (`file:...?mode=ro`) for
§2.3 and §8. Nothing was written to `~/.agent-broker`.

Crate deltas (§4.4) were measured in a scratch copy of `rust/`. The real
`Cargo.toml`/`Cargo.lock` were never edited.

**The scripts.** `docs/broker-daemon-port.measure/` holds what produced the tables
below. Each reads a tree and writes nothing in it. The two that run plugin code
(`tools_list.ts`, `scrub_probe.ts`) must be run from a scratch copy, like every
other run in this document.

| script | run as | prints | used by |
|---|---|---|---|
| `slices.py` | `python3 slices.py <plugin repo> [--table]` | the file-to-slice table, per-slice sums, the coverage check (57 `src` files, 0 unaccounted), the import-edge check and the scrub-ordering check; exits 1 on a violation | §7.1 |
| `tools_list.ts` | `bun tools_list.ts <plugin src>` (in a scratch copy) | the 26 `inputSchema`s as JSON, from an in-memory MCP client | §3.5 |
| `schema_diff.py` | `python3 schema_diff.py tools.json <body.rs>` | one line per compared field, then a tally: 51 compared, 7 equal, 44 differ | §3.5 |
| `od7.py` | `python3 od7.py` | the role tables of every enrolled project compared: tool sets, model/effort, skills, prompt hashes | OD7 |
| `stores.sh` | `sh stores.sh` | the read-only census of every `broker.sqlite` and the job split by provider | §2.3 |
| `scrub_probe.ts` | `bun scrub_probe.ts <plugin src>` (in a scratch copy) | what `redact` and the scrub do to a note, an output and a command line | §4.5 |

`slices.py` was also run with `skills.ts` and `rulebook.ts` moved back to 13.5, where
this document first had them: it reported exactly the two edges a reviewer found by
reading, `codex_mcp.ts` (13.3) importing both. With the scrub moved back to 13.5 it
fails its ordering assertion, because the first slice that sends free text is 13.3. The
checks can fail.

---

## 1. Source inventory: every module, classified

Buckets, from the task:

- **(a)** already in the cloud broker. The daemon forwards the call and ports nothing.
- **(b)** execution plane. It has to move into the Rust daemon.
- **(c)** local state that becomes the cloud broker's.
- **(d)** obsolete once the cloud broker holds the state.

In `services/broker/README.md` axis 5, "(b)" means *deliberately not ported to the
cloud*. Here it means *must be ported to the daemon*. The two sets overlap almost
entirely, but they are different statements.

### 1.1 Totals

| bucket | lines | what |
|---|---:|---|
| **(b)** port to the Rust daemon | **4,217** | 35 files + the execution half of `runtime.ts` (788 of its 1,071 lines). §7.1 assigns every one of those lines to a slice |
| **(a)** in the cloud; the daemon forwards | 232 + 264 | `mcp/schemas.ts`, `lifecycle/stages.ts`; `runtime.ts`'s `RuntimeControlBackend` (lines 808–1071) becomes a forwarding table |
| **(a), pending slice 12** | 98 | `roles/propose.ts` (`roles_propose`) |
| **(c)** becomes cloud state | 3,353 | `src/storage/*` except `evidence.ts` and `routing.ts`, + 379 lines of SQL |
| **(c), open in the cloud** | 166 | routing directives: `storage/routing.ts` 84, `roles/route.ts` 63, `runtime.ts#route` 19 |
| **(d)** obsolete | 119 | `process/recovery.ts` 9, `storage/evidence.ts` 58, `security/launcher_handshake.ts` 52 |
| **(d) or port: owner decision OD8** | 2,481 | `src/view/*`, the owner's terminal explorer |
| owner CLI: owner decision OD9 | 33 | `cli/commands.ts` (+ `scripts/work.ts` 693, `scripts/project.ts` 253, `bin/` 39) |
| **sum** | **10,963** | equals `wc -l src/**/*.ts` |

### 1.2 Per directory and file

| path | lines | bucket | note |
|---|---:|---|---|
| `src/mcp/schemas.ts` | 133 | a | the 26 zod schemas; the cloud's equivalents are `body.rs` (25 bodies) |
| `src/mcp/server.ts` | 146 | b | stdio MCP framing, read-tool redaction. Its `createControlPlane` is the gate the daemon still applies |
| `src/mcp/tool_names.ts` | 35 | b | the names; the parent-session hook matches on them |
| `src/daemon/server.ts` | 313 | b | unix socket server, `O_EXCL` single-instance claim, idle exit (10 min), session tracking |
| `src/daemon/client.ts` | 166 | b | spawns the daemon detached and connects |
| `src/daemon/protocol.ts` | 115 | b | newline-JSON frames, `FrameWriter`'s short-write lesson |
| `src/daemon.ts` | 66 | b | daemon entry; reaps every 30 s |
| `src/process/runtime.ts` 1–807 except 371–389 | 788 | b | types and options, `submit`, `#runRemote`, `resumeAbandoned`, release/terminalize/pause, roles/record/session/quota/note, subagent attach/report, `awaitChange`, `cancel`. Split into 12 line ranges over three slices (13.1, 13.3, 13.6) in §7.1 |
| `src/process/runtime.ts` 371–389 | 19 | c-open | `#route`: routing directives |
| `src/process/runtime.ts` 808–1071 | 264 | a | `RuntimeControlBackend`: tool → store call |
| `src/process/codex_mcp.ts` | 374 | b | `codex mcp-server` over MCP stdio |
| `src/process/claude_agent_sdk.ts` | 243 | b | Claude Agent SDK → the `claude` CLI's stream-json control protocol |
| `src/process/provider_types.ts` | 150 | b | event model, message summary, `reportedModel` |
| `src/process/quota.ts` | 100 | b | reads rate-limit events of both providers |
| `src/process/worktree.ts` | 77 | b | `git worktree add/remove`, `status --porcelain` |
| `src/process/scratch.ts` | 69 | b | per-job scratch, `info/exclude` |
| `src/process/liveness.ts` | 42 | b | `kill(pid,0)` + `ps -o lstart=` |
| `src/process/fake_provider.ts` | 38 | b | test provider |
| `src/process/native_attach.ts` | 36 | b | native (hand-back) lane attach |
| `src/process/cancel.ts` | 13 | b | bounded wait after abort |
| `src/process/recovery.ts` | 9 | d | wrapper over a store method |
| `src/storage/jobs.ts` | 1,026 | c | (`job_transcript`, quota and native parts are (b)/(d) in the cloud, see §2) |
| `src/storage/work.ts` | 960 | c | (`missionHistory`/`jobDurations` are an open (c) item in the cloud) |
| `src/storage/db.ts` | 558 | c | the 72-method `BrokerStore` facade (README axis 1) |
| `src/storage/attention.ts` | 332 | c | → cloud `attentionOf` (no `quota` list there, §3.3) |
| `src/storage/leases.ts` | 214 | c | |
| `src/storage/handoffs.ts` | 131 | c | |
| `src/storage/recovery.ts` | 71 | c | → the mission's alarm |
| `src/storage/missions.ts` | 61 | c | |
| `src/storage/routing.ts` | 84 | c-open | |
| `src/storage/evidence.ts` | 58 | d | native adapter evidence (cloud axis 3: (b)) |
| `src/roles/registry.ts` | 103 | b | role table loader. Its `tools` half is (a) (`role_variant`); model/effort/prompt/skills is the spawn spec (OD7) |
| `src/roles/skills.ts` | 100 | b | resolves skill names against local skill roots |
| `src/roles/propose.ts` | 98 | a-pending | `roles_propose`, slice 12 |
| `src/roles/rulebook.ts` | 75 | b | reads the repo's `CLAUDE.md`/`AGENTS.md` for the worker |
| `src/roles/route.ts` | 63 | c-open | |
| `src/roles/types.ts` | 47 | b | |
| `src/roles/resolve_role.ts` | 35 | b | |
| `src/roles/resolve_adapter.ts` | 32 | b | native vs broker-managed |
| `src/roles/provider_tools.ts` | 27 | b | tool vocabulary → Claude tool names |
| `src/policy/shell.ts` | 278 | b | shell-command classifier |
| `src/policy/claude_hook_root.ts` | 134 | b | path-within-root, command class for the parent hook |
| `src/policy/owner_pause.ts` | 91 | b | pause markers in the state dir / project |
| `src/policy/claude_hook.ts` | 56 | b | the parent session's PreToolUse hook entry |
| `src/policy/capability.ts` | 23 | b | `assertRoleToolAllowed` |
| `src/security/transcript_scrub.ts` | 63 | b | secret scrub (5 patterns, one with four look-aheads, §4.4). Today it guards only the local transcript; the port needs it on every free text that leaves the machine (§4.5) |
| `src/security/launcher_handshake.ts` | 52 | d | principal attestation from launcher manifests. The cloud's principal is the Access identity (§5) |
| `src/security/path_containment.ts` | 21 | b | |
| `src/security/redaction.ts` | 21 | b | key-name redaction of read answers |
| `src/security/argv.ts` | 10 | b | |
| `src/view/explorer.ts` | 1,998 | d / OD8 | terminal explorer over the local SQLite |
| `src/view/{width,transcript,markdown}.ts` | 483 | d / OD8 | |
| `src/lifecycle/stages.ts` | 99 | a | → `src/job.ts` |
| `src/cli/commands.ts` | 33 | OD9 | |
| `src/bootstrap.ts` | 192 | b | enrollment (`projects.json`), cwd → project, state home |
| `src/bootstrap_runtime.ts` | 95 | b | builds the runtime. Its attestation half is (d) with `launcher_handshake` |
| `src/main.ts` | 43 | b | stdio entry |

### 1.3 Everything outside `src/`

| path | size | bucket | becomes |
|---|---|---|---|
| `scripts/work.ts` | 693 | OD9 | 17 owner commands; README axis 5 splits them 11 (a) / 2 (b) / 4 (c) |
| `scripts/project.ts` | 253 | b + OD9 | `enroll list remove pause unpause role`. Enroll and pause are local facts (b); `role apply` → `POST /v1/roles` (a) + local spawn spec |
| `scripts/check-agent-broker-mutations.ts` | 617 | test infra | drives the 59 mutation tests |
| `scripts/check-agent-adapter-drift.ts` | 18 | d | |
| `bin/agent-broker.ts` | 39 | OD9 | the owner's global command |
| `generator/` (2 files) | 170 | d (launchers) / b (`.claude/agents` render) | launcher manifests die with the handshake (§5) |
| `launchers/*.generated.json` (2) | 30 | d | |
| `orchestrators.json` | 15 | d | the orchestrator profile the handshake attested |
| `hooks/hooks.json` | 16 | b | becomes an installed Claude Code hook running `wapps broker hook` (slice 13.7) |
| `skills/agent-broker/SKILL.md` | 513 | b (rewrite) | the orchestrators' protocol text. Tool shapes change (§3.2), so this is a rewrite, not a copy |
| `.claude-plugin/plugin.json`, `.mcp.json`, `.codex/config.toml` | — | d | replaced by `wapps broker install` (§7, 13.7) |
| `projects/*/roles.json` + `prompts/` (63 files) | — | b (templates) | installed copies live in `~/.agent-broker/projects/<id>/` |

---

## 2. Local state → the cloud broker

### 2.1 The 15 SQLite tables (`src/storage/migrations`, 29 files)

The mapping agrees with `services/broker/README.md` axis 3. It is restated here as a
statement about where the daemon reads and writes:

| plugin table | cloud home | how the daemon reaches it |
|---|---|---|
| `missions` | D1 `CATALOG` `mission_row` | `POST /v1/missions` (`claim`), `GET /v1/missions` |
| `orchestrator_leases` | `MissionDO` `lease` | `POST/GET …/lease`, `…/lease/renew`, `…/lease/release` |
| `mission_events` | `MissionDO` `lease_event` | `GET …/lease/ledger` |
| `jobs` | `MissionDO` `job` | `POST/GET …/jobs`, `…/jobs/{cancel,attach,progress,finish}`, `GET …/jobs/:job[/result]` |
| `job_progress` | `MissionDO` `job_progress` | `POST …/jobs/progress` (`note` ≤ 500 chars) |
| `work_items` | `MissionDO` `work_item` | `POST/GET …/work`, `…/work/{move,close,adopt}` |
| `work_questions` | `MissionDO` `work_question` | `…/work/questions[/delegate,/relay,/withdraw,/answer,/accept,/confirm]` |
| `handoff_packages` | `MissionDO` `handoff_package` | `POST …/handoff`, `…/handoff/takeover` |
| `routing_directives` | **(c), open in the cloud** | no route. `agent-broker route` and `#route` have no home |
| `job_attempts`, `job_events` | none | (d) |
| `mission_participants` | none | (d): a handoff names an Access principal |
| `native_adapter_evidence` | none | (d) |
| `job_transcript` | none | stays local or goes away: **OD8** |
| `provider_quota` | none | stays local or goes away: **OD8** |

Routes are `crates/workers/src/broker_routes.rs:287-340` (37 `route!` rows) at
`57b8bbb`.

### 2.2 Local files that stay local (b)

| file | today | after |
|---|---|---|
| `~/.agent-broker/projects.json` | enrollment: project id → root | stays. Which directory is which project is a fact about this machine |
| `~/.agent-broker/projects/<id>/roles.json` + `prompts/` | the full role table | spawn spec only (**OD7**). `tools` comes from the cloud's ceiling |
| `~/.agent-broker/state/<id>/broker.daemon.json`, `broker.sock`, `daemon.log` | single-instance claim, socket, log | stays (13.2) |
| `~/.agent-broker/state/<id>/worktrees/<job>` | writing jobs' checkouts | stays (13.4) |
| owner-pause markers (state dir + project) | read by the codex prompt and the runtime, and by the claude hook | stays (13.3; the claude gate in 13.5) |
| `~/.agent-broker/state/<id>/broker.sqlite` | **all state** | goes away (**OD10**) |

### 2.3 What is in the local stores today (read-only, measured)

`stores.sh`, through SQLite's read-only URI. `~/.agent-broker/projects.json` enrolls
**10** projects. **8** of them have a store. `apple-tv-remote-macos` has a state
directory and no `broker.sqlite`, and `tarim-atlas-frontend` has no state directory.
`self` has a store without being enrolled, so there are **9** stores. A job counts as
non-terminal when its state is not one of `completed rejected failed timed_out
cancelled orphaned` (`lifecycle/stages.ts:44`), which includes `review_pending`.

| project | missions | open work items | jobs | non-terminal jobs | open questions | db size |
|---|---:|---:|---:|---:|---:|---:|
| navlun | 1 | 203 | 836 | 1 | 1 | 750 MB |
| wapps-platform | 1 | 19 | 112 | 0 | 0 | 106 MB |
| real-estate-analysis | 1 | 15 | 5 | 0 | 0 | 512 KB |
| ecommerce | 1 | 4 | 63 | 0 | 0 | 49 MB |
| kick-clip-analyzer | 1 | 4 | 34 | 0 | 0 | 21 MB |
| self (not enrolled) | 1 | 0 | 0 | 0 | 0 | 192 KB |
| broker, dats-frontend, wapps-cli | 0 | 0 | 0 | 0 | 0 | 192 KB each |
| apple-tv-remote-macos, tarim-atlas-frontend | enrolled, no store | | | | | |

That is **245 open work items in 5 projects**. Every existing mission id (`ecommerce`,
`irl-relay`, `navlun`, `l0-walking-skeleton`, `daemon-probe`, `wapps-platform`)
matches the cloud's `MISSION_ID` (`/^[a-z0-9][a-z0-9._-]{0,127}$/`,
`services/broker/src/types.ts:81`). Jobs by provider and adapter, across all stores:
**claude/remote 1,002, codex/remote 32, claude/native 16**.

---

## 3. The MCP surface the daemon must serve over stdio

### 3.1 What the plugin serves (recorded, not read)

A live session in the scratch copy: `initialize`, `notifications/initialized`,
`tools/list`, then `orchestrator_claim`, `agent_await` and `roles_list`:

- `initialize` answers `protocolVersion: "2025-06-18"`, `capabilities.tools.listChanged:
  true`, `serverInfo {name: "dual-orchestrator-agent-broker", version: "0.1.0"}`.
- `tools/list` returns **26 tools, 16,966 bytes**. Every description is the placeholder
  `"Dual-orchestrator agent broker <tool>"`. Everything an agent learns, it learns from
  `inputSchema` (`$schema`, `properties`, `required`, `additionalProperties: false`).
- Every answer is one `text` content holding JSON. There is no `structuredContent` and
  no `isError` (a refusal reaches the client as a JSON-RPC error raised by the SDK).
- `agent_await` without a cursor answered in 2 ms with `{changed:false, waitedMs,
  attention:{…, quota:[], roundDrained:null, digest}}`.

The recording is `/tmp/broker-oracle.mw98/mcp-transcript.jsonl` (ephemeral).

### 3.2 The 26 tools, their inputs, and the cloud route each maps to

Fields are `src/mcp/schemas.ts`. `A` = `missionId, capability (≥32), fencingToken`
(the lease authority).

| tool | plugin input (beyond `missionId`) | cloud route (`57b8bbb`) | translation the daemon/Worker owes |
|---|---|---|---|
| `orchestrator_claim` | — | `POST /v1/missions` + `POST …/lease {provider}` | Claim does six things today (ensure mission, reap expired lease, release a gone owner's lease, register the participant, claim, **resume abandoned work**). The cloud does the claim. `already_claimed` (CONFLICT) has to come back as the plugin's `{standby:true, ownerProvider}`. Resuming is execution: the daemon (13.6) |
| `orchestrator_heartbeat` | A | `POST …/lease/renew` | body is `{capability, fencingToken}` |
| `orchestrator_prepare_handoff` | A, `targetProvider`, `targetSessionId`, `expiresAt` | `POST …/handoff {authority, targetPrincipal, targetProvider, note}` | **Schema changes.** Session id → Access principal, `expiresAt` dropped (no body carries time), `note` required. See OD1 |
| `orchestrator_takeover` | `handoffPackageId` | `POST …/handoff/takeover {handoffId, provider}` | rename + `provider` |
| `orchestrator_release` | A | `POST …/lease/release` | |
| `orchestrator_status` | — | `GET …/lease` (+ attention) | carries attention (§3.3) |
| `roles_list` | — | `GET /v1/roles` + local spawn spec | the plugin returns `model`, `mode`, `tools`, `description`. The cloud has `tools` only (OD7) |
| `roles_propose` | A, `roles` | **none** | §3.4 |
| `work_add` | A, `items[≤500]{title, intent, parentId?, horizon?, discoveredFrom?}` | `POST …/work` | lengths differ (§3.5) |
| `work_adopt` | A, `jobId`, `items[≤200]{…, relation}` | `POST …/work/adopt` | |
| `work_list` | — | `GET …/work` | |
| `work_close` | A, `workItemId`, `reason` | `POST …/work/close` | |
| `work_move` | A, `moves[]` | `POST …/work/move` | |
| `work_ask` | A, `workItemId`, `question ≤10,000`, `proposal?` | `POST …/work/questions` | cloud `question`/`proposal` ≤ **4,000** |
| `work_relay_answer` | A, `questionId`, `answer ≤10,000` | `POST …/work/questions/relay` | cloud ≤ 20,000 |
| `work_withdraw` | A, `questionId`, `reason` | `POST …/work/questions/withdraw` | |
| `work_delegate` | A, `questionId`, `provider` | `POST …/work/questions/delegate` | |
| `agent_submit` | A, `laneId role provider? dispatchKey base head task reviewsJobId? workItemId? answersQuestionId? resumesJobId? handBack?` | `POST …/jobs` + **local spawn** | The daemon resolves `provider` (routing, OD7) because the cloud requires `workerProvider`. It returns the job capability once and spawns. **`answersQuestionId` cannot be sent at all: Finding 3.6.** `handBack` is the native lane (OD12) |
| `agent_attach` | A, `jobId`, `attachCapability`, `providerRunId` | `POST …/jobs/attach {authority:{jobId, capability}, providerRunId, worktree?}` | `report` verb, job capability. The lease is not needed |
| `agent_report` | A, `jobId`, `status`, `output?`, `error?` | `POST …/jobs/finish` | `report` verb. The cloud also accepts `timed_out`. Free text: it leaves the machine, so it is scrubbed (§4.5). Ceilings differ (§3.5) |
| `agent_list` | — | `GET …/jobs` | |
| `agent_running` | — | `GET …/jobs` (the route has no filter) | **A projection, not a filter** (`storage/jobs.ts:935`): jobs in `reserved queued running checkpointed attached`, joined to the work item's title and to the last `job_progress` row, plus `startedAt` from `job_attempts`, which has no cloud home (§2.1). Wrapped `{running:[…]}` + attention. Whoever builds it (Worker, P12, or the daemon from `GET jobs` + `GET work` + the progress of each job) is open: §3.7 |
| `agent_await` | `sinceDigest?`, `waitMs ≤ 55,000` | **no wait route**; `GET …/attention?since=` is the cursor | §3.4 |
| `agent_status` | `jobId` | `GET …/jobs/:job` | + attention |
| `agent_result` | `jobId` | `GET …/jobs/:job/result` (marks it read) | |
| `agent_cancel` | A, `jobId` | `POST …/jobs/cancel` + **local kill** | the cloud writes the state and kills nothing: *"broker uzaktaki bir süreci öldüremez"* (`services/broker/src/http/routes.ts:589-590` at `7cf2d20`; the Rust `cancel_job`, `broker_handlers.rs:568`, keeps the behaviour, not the comment). The daemon kills |

**Read, not run:** the cloud bodies (`crates/core/src/broker/body.rs`) and their 12,376
frozen cases. No request was sent to a running Worker.

### 3.3 The attention block

The plugin appends `attention` to `agent_submit`, `agent_status`, `agent_running` and
`orchestrator_status` (`runtime.ts:140`), and `agent_await` answers with it as its main
content (the §3.1 recording). That is **five** answers. No cloud route carries
`attention` inside another answer (`broker_routes.rs:340` is its only route), so where it
is appended to those five is a P12 decision the platform doc does not make. Empty lists
are dropped and the digest is always present. The cloud's `MissionDO.attention` (`services/broker/src/attention.ts:89`)
has the same lists **except `quota`**, because `provider_quota` is (b) in the cloud.
Only the daemon sees quota. So either the daemon merges its own quota list into the
five answers, or the list disappears (OD8). Merging means the daemon reads and rewrites
those answers; it cannot be a verbatim forward (§3.7).

### 3.4 The two tools the cloud lacks

**`agent_await`.** The cloud README's own ruling ("The slice-4 ruling on
`agent_await`", line 1367) reads: *"the server owes a cheap, honest 'has anything
changed', and the waiting is a client loop."* The daemon is that client. It can serve
`agent_await` by polling `GET …/attention?since=<digest>` until the digest changes or
the deadline passes. The plugin's loop polls SQLite every 250 ms for up to
`MAX_AWAIT_MS` 55 s (`runtime.ts:132-134`). Against the network the interval has to be
coarser (OD4). **This needs nothing from the cloud.** It takes `agent_await` off slice
12's critical path for the daemon. Slice 12 still needs it for MCP clients that have no
daemon. The hibernatable WebSocket the README names is only needed for server push and
for `releaseLeaseOfGoneOwner`. The daemon can serve the second one locally: it sees its
sessions disconnect, and it proxied the claim, so it holds the capability.

**`roles_propose`.** It validates proposed roles against the registry's rules and
writes nothing. The rules that matter are the cloud registry's (`declareRole`,
`src/roles.ts`, `unknown_tool`). Validating them in the daemon would make a second copy
of them. It belongs on the Worker (slice 12), and the daemon forwards it. Its
`install` hint changes from `agent-broker project role apply …` to the new command
(13.8 / OD9).

### 3.5 Divergences the oracle must declare, not discover

Every one of these is a deliberate cloud decision. The differential has to list them
with a reason, the way `cases.py` excludes four cases. The list below is not read off
the two files by eye. `tools_list.ts` dumped the plugin's 26 `inputSchema`s and
`schema_diff.py` paired each field that exists on both sides with `body.rs`'s table
(`57b8bbb`): **51 fields compared, 7 equal, 44 differ**. The 7 that agree are
`work_add` `items` (500), `title` (500) and `intent` (100,000); `work_move` `moves`
(500); `work_adopt` `title` and `intent`; `work_withdraw` `reason` (2,000). The enums
(`horizon`, `relation`, close reason, provider) agree member for member.

| # | divergence | plugin → cloud | fields |
|---|---|---|---:|
| 1 | **Capability floor** | `capability` `min 32` → `min 1` (`AUTHORITY`); `attachCapability` `min 32` → the job capability, `min 1` | 14 |
| 2 | **Id ceiling 256 → 128** | `laneId`, `workItemId`, `reviewsJobId`, `resumesJobId`, `parentId`, `discoveredFrom`, `jobId`, `questionId`, `moves[].workItemId`, `handoffPackageId` → `handoffId` | 17 |
| 3 | **Id ceiling 256 → 200** | `dispatchKey`, `base`, `head` (submit) and `providerRunId` (attach). These four are not 128 | 4 |
| 4 | **Content ceilings** | `work_ask` `question` and `proposal` 10,000 → **4,000**; `work_relay_answer` `answer` 10,000 → **20,000**; `agent_submit` `task` 100,000 → **200,000**; `agent_report` `output` 100,000 → **200,000** and `error` 10,000 → **20,000** (both also lose `min 1`); `work_adopt` `items` max **200 → 500** | 7 |
| 5 | **Role name** | `^[a-z][a-z0-9-]{0,63}$` → any trimmed string ≤ 128. The registry's `bad_role_name` refuses it later, not the schema | 1 |
| 6 | **Handoff target** | `targetSessionId` (any id) → `targetPrincipal` (`^(human\|svc):[^\s,]+$`) | 1 |

The 44 are 14 + 17 + 4 + 7 + 1 + 1. Differences that have no field on the other side,
and so are not in the count:

7. **Whole-body shapes.** `orchestrator_prepare_handoff` loses `expiresAt` and gains a
   required `note` (≤ 20,000). `orchestrator_takeover` gains `provider`.
   `orchestrator_claim` gains `provider` (the plugin derived it from the launcher). The
   dispatch body takes `workerProvider` (required) where the tool takes `provider?`,
   and has no `answersQuestionId` (Finding 3.6) and no `handBack`. `agent_attach` and
   `agent_report` swap the lease authority for the job authority `{jobId, capability}`
   (no fencing token); attach gains `worktree {path ≤ 1024, branch ≤ 256}`; report's
   `status` gains `timed_out`.
8. **Trim.** The plugin counts `"   "` as a valid `min(1)` string. Every cloud field
   built with `trimmed(…)` trims first and stores the trimmed value (`body.rs`, "trimmed
   strings trimmed"), so a whitespace-only field is refused and a padded one comes back
   shorter.
9. **Mission id.** Any string ≤ 256 → `MISSION_ID`, lowercase and ≤ 128 (a URL segment
   and a Durable Object name). The six existing ids conform (§2.3).
10. `roles_list` loses or keeps `model`/`mode` depending on OD7.
11. `attention.quota` (OD8).
12. Error envelopes: the cloud's `{error, message, details, recovery}` against the
    SDK's JSON-RPC errors.
13. `orchestrator_claim` no longer resumes abandoned work inside the cloud call. The
    daemon does it around the call (13.6).
14. `agent_running` is a projection that includes `startedAt` from `job_attempts`,
    which the cloud does not have (§3.2).

Not compared: a field that exists on one side with no ceiling (`status` enums, booleans)
and the nested `roles_propose` schema, which has no cloud body (§3.4).

### 3.6 Finding: the dispatch body cannot carry `answersQuestionId`

`crates/core/src/broker/body.rs:204-216` (`DISPATCH`, at `57b8bbb`; its doc comment starts at 201) lists `authority
laneId role dispatchKey base head task workerProvider workItemId? reviewsJobId?
resumesJobId?`. There is **no `answersQuestionId`**. The body reader refuses unknown
keys ("unknown keys last"). Yet:

- `MissionDO`'s `NewJob` has `answersQuestionId` (`services/broker/src/mission.ts:351`),
  and the DO-level tests dispatch answer jobs (`test/job-family-lane.test.ts:187`).
- The `one_bind_only` recovery line tells the caller to *"send ONE of
  answersQuestionId, reviewsJobId and workItemId"* (`crates/core/src/broker/envelope.rs:326`).

So over HTTP the delegated-answer path (`work_delegate` → an answer job) cannot be
reached. That is the path README slice 7's `owesReview` finding was about. The Rust
body froze the TypeScript zod schema faithfully, so the gap is older than 9b. **Read,
not run.** This is a platform-side item (P-a in §7), and the daemon's 13.6 depends on
it.

### 3.7 What the daemon does to each of the 26 tools (OD3, restated)

OD3 first said the daemon forwards 19 tools verbatim and intercepts 7, and also that it
merges quota into 4 attention-carrying answers. Three of those 4 (`agent_status`,
`agent_running`, `orchestrator_status`) were in the "verbatim" 19, and a merge cannot be
verbatim. Going through `RuntimeControlBackend` (`runtime.ts:842-1071`) tool by tool
gives four classes, 26 in all:

| class | tools | n | what the daemon does |
|---|---|---:|---|
| **act** | `orchestrator_claim`, `agent_submit`, `agent_cancel`, `agent_attach`, `agent_report`, `agent_await`, `roles_list` | 7 | `claim`: supplies `provider`, turns `already_claimed` into `{standby}`, resumes after (13.6). `submit`: routes, calls the Worker, spawns. `cancel`: calls the Worker, kills. `attach`, `report`: the native lane (OD12). `await`: the cursor loop (OD4). `roles_list`: merges the local spawn spec (OD7) |
| **rewrite the answer** | `agent_status`, `agent_running`, `orchestrator_status` | 3 | forwards, parses the answer, merges its quota list into `attention` (OD8). `agent_running` may also have to be built from `GET jobs`, `GET work` and per-job progress (§3.2) |
| **observe** | `orchestrator_takeover`, `orchestrator_release` | 2 | forwards unchanged and reads the answer: the daemon keeps the capability of each lease it proxied, so it can release a gone owner's lease itself (§3.4). Taking over hands it a new one; release drops one |
| **verbatim** | `orchestrator_heartbeat`, `orchestrator_prepare_handoff`, `roles_propose`, `work_add`, `work_adopt`, `work_list`, `work_close`, `work_move`, `work_ask`, `work_relay_answer`, `work_withdraw`, `work_delegate`, `agent_list`, `agent_result` | 14 | nothing |

So the daemon touches **12** tools, not 7, and forwards **14**, not 19. Five answers
carry `attention` (§3.3): `submit` and `await` from the act class, the three above from
the rewrite class.

What that does to "one schema definition (the Worker's)":

- **The rules of validity stay single.** Lengths, enums and patterns (§3.5) live in the
  Worker for all 26 tools. The daemon defines none of them.
- **The shapes do not.** For 9 of the 12 touched tools the daemon only reads named
  fields. For 3, `agent_submit`, `agent_attach` and `agent_report`, the input the
  orchestrator sends is not the input the Worker takes (`provider?` and `handBack`
  against `workerProvider`; the lease authority and `attachCapability` against the job
  authority, §3.5 item 7). The daemon publishes its own `inputSchema` for those: **28 of
  the 102 top-level input properties** (15 + 6 + 7, from `tools_list.ts`). That is a
  second definition, kept small. It grows if P12 keeps `provider` as an argument of
  `claim` and `takeover`, which the platform doc does not say.
- **`tools/list` is therefore not a pure forward**: the Worker's list with at least 3
  entries replaced.
- **P12 has to settle two things OD3 assumed.** Where `attention` is appended to the five
  answers, and who builds `agent_running`'s projection. The platform doc's slice 12
  paragraph names only `agent_await` and `roles_propose` as new.

---

## 4. The process layer

### 4.1 What each part does and which OS calls it makes

| part | source | what it does | OS calls (today) | Rust |
|---|---|---|---|---|
| stdio entry | `main.ts` | MCP over stdin/stdout; connects to (or spawns) the daemon | stdio; `connect(AF_UNIX)` | `std::io`, `std::os::unix::net::UnixStream` |
| daemon spawn | `daemon/client.ts:144-163` | `bun src/daemon.ts`, `detached: true`, stdout/stderr → `daemon.log`, wait ≤ 15 s for record+socket | `fork/exec`, new session/process group | `std::process::Command` + `CommandExt::process_group(0)` or `rustix::process::setsid` (feature `process`, §4.4) |
| single instance | `daemon/server.ts:117-137` | `writeFile(record, {flag:"wx"})` = `O_EXCL`; a dead holder is detected with pid+start time | `open(O_CREAT\|O_EXCL)`, `unlink` | `OpenOptions::create_new` |
| socket server | `daemon/server.ts` | newline-JSON frames, hello → re-attested backend, idle exit 10 min (`DAEMON_IDLE_MS`) | `bind/listen/accept(AF_UNIX)` | `UnixListener`, one thread per connection |
| liveness | `process/liveness.ts` | `kill(pid,0)` + `ps -o lstart= -p` (pid-reuse guard, ±1 s) | `kill(2)` sig 0, spawn `ps` | `rustix::process::test_kill_process` + spawn `ps` (as today) |
| reaper | `daemon.ts:35` | every 30 s, mark jobs whose pid died | — | **changes meaning**: the cloud orphans a job whose worker stops speaking (deadline, §4.3). The daemon's job becomes *speaking for* live workers, not reaping dead ones |
| worktree | `process/worktree.ts` | `git worktree add -b broker/<job> <path> <base>`; remove only if `status --porcelain` is empty; env is `PATH`+`HOME` only | spawn `git` | spawn `git` (no `git2`) |
| scratch | `process/scratch.ts` | `<root>/.broker-scratch/<job>`, appended to the common dir's `info/exclude`, `TMPDIR` set to it | `mkdir`, `rm -r`, `rmdir`, append | `std::fs` |
| claude worker | `process/claude_agent_sdk.ts` | SDK `query()` → spawns the bundled `claude` (§4.2), in-process PreToolUse hook callback, `canUseTool`, `bypassPermissions`, `settingSources: []` | spawn + pipes | spawn + pipes. The protocol choice is **OD5** |
| codex worker | `process/codex_mcp.ts` | `codex mcp-server` (`:233`) as an MCP **client**; one `tools/call name=codex` with `sandbox`, `approval-policy: never`, `developer-instructions`, `config`; `codex/event` notifications; quiet timeout 10 min (`:34`); env allowlist of 9 names (`:49`) | spawn + pipes | spawn + pipes, JSON-RPC by hand (`serde_json`) |
| quota | `process/quota.ts` | parses claude `rate_limit_event` and codex `token_count` | — | pure |
| cancel | `runtime.ts:771-803`, `cancel.ts` | marks cancel requested, aborts, `adapter.cancel()` (claude: `close()`; codex: close the session), waits ≤ 5 s | closes pipes / child exits | close stdin + `kill` the child's process group |
| resume | `runtime.ts:514-553` | at claim, re-dispatch abandoned resumable jobs with `resumesJobId` | — | `POST …/jobs {resumesJobId}`; the cloud returns `resumeFrom {providerRunId, worktree}` in the brief |
| parent hook | `policy/claude_hook.ts` + `hooks/hooks.json` | PreToolUse on `Bash\|Write\|Edit\|mcp__dual-orchestrator-agent-broker__.*`; denies by owner-pause class | reads stdin JSON, writes a decision | `wapps broker hook` (same binary). The matcher's tool prefix changes with the server name (OD13) |
| launchers | `security/launcher_handshake.ts`, `launchers/`, `generator/` | attests the orchestrator's model/effort against `orchestrators.json` | — | (d) under OD1 (§5) |

### 4.2 The claude seam, recorded

The plugin passes no `pathToClaudeCodeExecutable`, so the SDK runs **its bundled
binary**,
`node_modules/@anthropic-ai/claude-agent-sdk-darwin-arm64/claude` (276 MB, `claude
--version` → **2.1.228**). The `claude` on `PATH` is **2.1.289**. The scratch copy's
bundled binary was swapped for a recorder, and `ClaudeAgentSdkAdapter.start()` ran with
a synthetic role. It recorded:

```
argv:  --output-format stream-json --verbose --input-format stream-json --model sonnet
       --agent builder --permission-prompt-tool stdio --allowedTools Read,Write
       --tools default --setting-sources= --permission-mode bypassPermissions
       --session-id=<uuid>
stdin: {"type":"control_request","request_id":…,"request":{"subtype":"initialize",
        "hooks":{"PreToolUse":[{"hookCallbackIds":["hook_0"]}]},"systemPrompt":[""],
        "agents":{"builder":{"description":…,"prompt":…,"model":"sonnet","effort":"high",
        "tools":["Read","Write"],"skills":[]}}}}
       then {"type":"user","message":{"role":"user","content":[{"type":"text","text":"do it"}]},…}
cwd:   the approved root
env:   74 variable names, the parent's whole environment (ANTHROPIC_AUTH_TOKEN, CLAUDECODE, …)
```

The SDK also warned `CLAUDE_SDK_CAN_USE_TOOL_SHADOWED`, which the adapter's own comment
anticipates. The hook is the gate, not `canUseTool`.

What this means for Rust:

- The PreToolUse gate is an **in-process callback** reached through a bidirectional
  control protocol (`control_request`/`control_response`, `hook_callback`). The protocol
  belongs to the SDK. `sdk.mjs` contains 40 distinct `subtype:"…"` literals
  (control requests plus their `success`/`error` responses). A Rust daemon either speaks
  this protocol (OD5-B) or drives `claude` through its public flags `--agents
  <json>` and `--settings <json>`, with a **command** hook that runs `wapps broker
  worker-gate` (OD5-A). `claude --help` lists both flags. **Not measured:** whether
  `--agents` carries `effort` and `skills` the way the `initialize` payload does.
- **Finding 4.2: claude workers inherit the daemon's whole environment.** Codex workers
  get an allowlist of 9 names (`codex_mcp.ts:49`). Claude workers get `{...process.env,
  TMPDIR}` (`claude_agent_sdk.ts:143`), and the recording shows 74 names. Once a cloud
  credential exists, **any secret in the daemon's environment reaches every claude
  worker**, and a worker could then call the broker as the orchestrator's principal
  (`claim` verb). The Rust daemon must give claude workers an allowlist as well, and the
  service-token secret must never be in the daemon's environment (§5).

### 4.3 Finding: the cloud's job deadline is shorter than codex's silence

The cloud writes a job `orphaned` unless its worker speaks within `JOB_WINDOW_MS =
LEASE_WINDOW_MS = 5 min` (`crates/workers/src/mission_lane/methods.rs:2073`,
`services/broker/src/lease.ts:54`). A codex worker can be silent for up to **10 min**
before the adapter gives up (`codex_mcp.ts:34`). So the daemon has to send `POST …/jobs/progress` (note optional) for **every running
job on its own timer**, well inside 5 min, independent of provider events. The plugin
has no such loop because its rows are local. The 30 s reaper turns into this heartbeat.

The same window raises a related point. Codex names its thread only in
`session_configured` (`codexSessionId`). The cloud's `attach` takes `providerRunId`
once, and no later route updates it. So a codex job attaches after its first event,
not at spawn. Codex conversations cannot be resumed anyway (`codex_mcp.ts`: *"codex
keeps it inside the process that opened it"*). The run id is informational for codex.

### 4.4 Crates: what exists, what is new, measured

`rust/deny.toml` bans `tokio`, `mio`, `socket2` and `uuid`, and denies unknown
registries and git sources. `Cargo.lock` holds **99** packages. Direct dependencies:
`clap serde serde_json ureq rustix(termios,stdio) rustls rustls-pki-types webpki-roots
serde_yaml_ng ring`.

| need | answer | measured |
|---|---|---|
| stdio JSON-RPC (server side, and the codex client side) | `serde_json`, by hand | — (MCP stdio is newline-delimited JSON-RPC) |
| HTTPS to `broker.meapps.dev` with Access headers | `ureq` (present, blocking, no tokio) | — |
| unix socket, `O_EXCL`, spawn, pipes | `std` | — |
| `kill(pid,0)`, `kill`, `setsid` | `rustix` + feature **`process`** | in a scratch copy: **0 new crates** (lock still 99), `cargo deny check` → `advisories ok, bans ok, licenses ok, sources ok` |
| random session ids / no `uuid` | `ring::rand::SystemRandom` (present) | — |
| SHA-256 | `ring` (present) | — |
| concurrency (N workers, M sessions, timers, long poll) | `std::thread` + channels | — (OD11: tokio stays banned) |
| secret scrub of every free text the daemon sends (`transcript_scrub.ts`, 5 patterns; §4.5) | hand-written matcher | `regex = "1"` adds **4 crates** (`aho-corasick regex regex-automata regex-syntax`), deny ok. **But** the high-entropy pattern (`OPAQUE`, `transcript_scrub.ts:26`) uses **four** look-aheads (the 40-character run, then one each for a lower-case letter, an upper-case letter and a digit), which `regex` cannot express. A hand-written matcher is needed anyway, so `regex` buys nothing |
| shell classifier (`policy/shell.ts`) | string matching | its regexes are fixed alternations (`:164-174`) |
| JSON Schema for `tools/list` | none under OD3 (the Worker owns `tools/list`) | without OD3, 26 hand-written schemas or `schemars` (not measured) |
| SIGTERM handling | none | the claim already tolerates a holder killed with SIGKILL (`server.ts:133-137`). `signal-hook`: not measured, not in the offline cache |
| WebSocket | none under OD4 | `tungstenite`: not measured, not in the offline cache |
| date parsing of `ps -o lstart=` | hand-written | the format is fixed: `Mon Oct  5 06:32:47 2026` |

**No new crate is required** under the recommended options. The only `Cargo.toml`
change is one `rustix` feature.

### 4.5 What leaves the machine, and what scrubs it

In the plugin nothing the worker said left the machine through the broker.
`recordProgress`, `finishJob` and `recordTranscript` wrote to a local SQLite file that
only the owner read. In the port the daemon sends the worker's words to the cloud, so
the scrub stops being a convenience for a local transcript and becomes the gate on an
outbound channel.

The daemon-originated free text that goes out, from the first slice that spawns a
worker (13.3):

| field | ceiling (`body.rs`) | what fills it | plugin source |
|---|---:|---|---|
| `progress.note` | 500 | `Bash: <the command>` for a codex command, the worker's own message text, the daemon's own lines (`could not be carried on: <error message>`) | `provider_types.ts:92-101`, `runtime.ts:476,549` |
| `finish.output` | 200,000 | the worker's final text | `runtime.ts:575` (`#terminalize`) |
| `finish.error` | 20,000 | the provider's error, an exception message, and for a pause kill the **whole command line** | `runtime.ts:470` |

**Measured** (`scrub_probe.ts`, in a scratch copy):

- The only text-level protection those three have today is `redact`. It blanks a value
  whose KEY names a secret and replaces exact known secret strings, and the plugin
  passes it no known secrets. Fed `AWS_SECRET_ACCESS_KEY=…` inside a note or an
  `{output}` object it removes nothing. So for notes, output and error the plugin had
  no scrub at all, only the transcript had one (`runtime.ts:647`).
- `scrubText` (the 5 patterns) removes the assignment, a `Bearer` token and an opaque
  run, and leaves a lower-case-hex sha alone. `scrubForTranscript` also **truncates
  every string to 8,192** (`transcript_scrub.ts:45`): a 20,000-character output comes
  back as 8,223 and a 200,000-character one as 8,224. That is right for a transcript
  row and wrong for `finish.output`, so the port takes `scrubText` and not the
  truncation. It costs about 1 ms on 200,000 characters (0.7 to 1.4 over three runs).
- **A hole**: `scrubText("Bash: AWS_SECRET_ACCESS_KEY=wJalr…")` returns the note
  unchanged. `ASSIGNMENT` is anchored to the start of a line, and a note starts with
  `Bash: `. Vendor-shaped values (`ghp_…`) and `Bearer` are caught anyway, because
  their patterns are not anchored. The plugin's own comment says the scrub "is a
  heuristic and is not claimed to be complete". Four probes (one sample text and
  three command lines) are not a recall figure (§10).

**What this does to the plan.**

1. The scrub is in **13.3**, with the first slice that sends any of these. `slices.py`
   asserts the ordering: the senders (`#note`, `#terminalize`) are in 13.3, and the
   scrub with them. The first draft put it in 13.5, after two slices of unscrubbed
   output.
2. **One function, called at every exit point**, not a step each sender remembers.
   Seam 3 (§6) plants a secret in a scripted worker's note, output and error and
   asserts it appears in no request body and no log line.
3. The Rust matcher does not have to be a transliteration. Making `ASSIGNMENT` match
   anywhere on a line closes the hole above; that is a deliberate divergence and the
   differential declares it (OD15).
4. Not covered by this scrub: text the **orchestrator** authored (work items, questions,
   the handoff note, the dispatch `task`). It is forwarded as written, as it always was,
   but it now leaves the machine too (OD15).

---

## 5. Auth to the cloud broker

**How the daemon authenticates.** The same way memory's agents do: a Cloudflare Access
**service token**, sent as `CF-Access-Client-Id` / `CF-Access-Client-Secret` on every
request. The gate turns it into the principal `svc:<client id>`. Memory's
`provision` mints `<worker>-agents` and its `non_identity` policy
(`services/memory/README.md:68-74`). The broker's provision is **in flight,
uncommitted**, in `.worktrees/broker-provision` (`crates/ops/src/provision/broker.rs`,
read 2026-10-05, not treated as fact). It mints the same single token and prints
*"svc:{client_id} holds no roster verbs yet: an admin grants them with POST
/v1/roster"* (`:102-103`).

**Verbs the daemon's principal needs** (`broker_routes.rs:287-340`): `read`, `claim`
(lease, work, dispatch, cancel, questions, handoff) and `report` (attach, progress,
finish). It must **not** hold `answer`: the owner's door has to stay human, and
`answer_from_holder` exists to stop exactly that. It must not hold `administer` either.

**Finding 5.1: one token per machine breaks claude ↔ codex handoff.**
`prepare_locked` refuses `handoff_to_self` when `target_principal == prepared_by`
(`crates/workers/src/mission_lane/methods.rs:1450`). If both orchestrators on a
machine authenticate with the one `-agents` token, they are **one principal**, and a
handoff between them always gets `handoff_to_self`. Handing over to the other provider
is the system's whole point (`SKILL.md`: "one Claude, one Codex"). The cloud's
"principal" replaces the plugin's launcher handshake, which is why
`launcher_handshake.ts` is (d). That only holds if each orchestrator has its own
principal. → **OD1**.

**Where the secret lives.** Provision writes the secret once to
`--token-sink file:<path>|wapps:<KEY>`. The `wapps:<KEY>` sink goes to the wapps
secrets gate through `wapps secrets set --from-file` (memory README `:71-73`). The
daemon runs under Claude Code or Codex, so `CLAUDECODE` is set or stdin is not a TTY,
which makes it **always agent mode** (`rust/crates/cli/src/agentmode.rs:11-45`). In
agent mode `secrets get` is refused. Reading from the gate also needs the owner's
`wapps login` SSO session to still be valid, while daemons live for days. → **OD2**.
Whatever is chosen, Finding 4.2 adds a rule: the secret is read from storage into
memory, never placed in an environment variable, and never passed to a child.

---

## 6. The oracle

wapps-cli's method is a differential against a running oracle on a seam both sides
share (Go ↔ Rust in a pty, `tests/differential.rs`, `tests/pty/*.py` 7,107 lines, fake
gate `fakegate.py`). The plugin cannot be compared that way end to end: its state is
local SQLite and the daemon's is the cloud, and §3.5 lists the deliberate
differences (14 items; 44 of 51 comparable fields). So the differential is held at **three seams**, and only the first is a byte-level
differential.

**Seam 1: provider spawn (byte differential, the pty method's analogue).** Fake
`claude` and fake `codex` binaries record argv, environment *names*, cwd and every
stdin frame, and answer from a script: stream-json for claude, an MCP server for codex.
The oracle side is the plugin's own adapters. For claude, the SDK's bundled binary is
replaced in a scratch copy, exactly as §4.2 did, so the plugin needs no change. For
codex, `codex` is put first on `PATH`. The Rust daemon runs against the same fakes.
Compared after normalising uuids and temp paths: argv, the set of env names, cwd, the
role prompt bytes (prompt + skills + rulebook + scratch + pause sections), the tool
ceiling, and how the daemon reacts to each scripted event (progress note text, quota,
model observed, terminal state, cancel). **Each slice compares only what it has ported.**
For codex that is the prompt bytes, and so `roles/skills.ts`, `roles/rulebook.ts`,
`process/scratch.ts` and `policy/owner_pause.ts` land in 13.3, with the worker that
calls them (`codex_mcp.ts:6-9,158-170`). Quota is compared from 13.6. Under OD5-A the claude half compares
**content** (the agent definition, the hook decision for each scripted tool call)
rather than the protocol frames, the way slice 9 compared Tab candidates instead of
completion script bytes.

**Seam 2: MCP over stdio (transcript differential with declared divergences).** A
corpus of recorded `tools/call` sequences, starting from the §3.1 recording. The oracle
side is `bun src/main.ts` in a scratch copy with an isolated `HOME`. The Rust side is
`wapps broker serve` against a **fake cloud broker**. The fake's answers are recorded
from the real Worker, the same `MissionDO` driven by the platform's vitest/workers
lane, so that the fake does not become a third definition of the cloud's rules. The
comparison is the answer JSON after normalisation, minus the §3.5 list, each item with
its reason written down. Mechanical floor: 26 tools × {accepted, refused by schema} +
`initialize`/`tools/list`/`ping` = **55 cases** before any tool's own branches.

**Seam 3: daemon → cloud (request-level, not a differential).** The fake cloud records
every request (method, path, body, Access headers present, secret never in a body or a
log), and the corpus asserts the sequence for each scenario (dispatch → attach →
progress every < 5 min → finish; cancel; resume at claim). One scenario plants a secret
in a scripted worker's note, output and error and asserts it is in no body and no log
line (§4.5). There is no oracle on this seam, because the plugin never spoke HTTP. Its guard is the platform's frozen body
ledger (`crates/core/tests/frozen/broker_bodies.ledger`, 12,376 cases): every body the
daemon sends must be one that `body.rs` accepts.

**What happens to the plugin's 107 test files.** They call `BrokerStore` and the
adapters in-process (73 files import `src/process|daemon|policy|security|bootstrap|mcp`),
so they cannot be pointed at a Rust binary. They become the **behaviour inventory**
each slice re-expresses as seam-1/2/3 cases. Assignment by imports and file name (my
judgment, not a proof):

| slice | plugin files | tests |
|---|---:|---:|
| 13.1 surface | 8 | 26 |
| 13.2 daemon | 6 | 26 |
| 13.3 execution core + codex | 16 | 89 |
| 13.4 writing roles | 5 | 20 |
| 13.5 claude worker + pause | 14 | 61 |
| 13.6 quota, resume, native | 12 | 40 |
| 13.7 install + hook | 2 | 9 |
| 13.8 owner CLI | 2 | 17 |
| cloud semantics (the cloud's own oracle covers them) | 37 | 137 |
| view (`explorer`, `markdown`, `width`) | 3 | 117 |
| `hardening.test.ts` (mixed, not split) + `differential-quality` | 2 | 31 |
| **sum** | **107** | **573** (static) |

The table was drawn by judgment before §7.1 existed. §7.1 moves some modules earlier
than the draft had them, so some of these files gate a different slice than the row
they are counted in. **19 test files (139 tests)** import one of `roles/skills`,
`roles/rulebook`, `security/transcript_scrub`, `policy/owner_pause`, `policy/shell`,
`process/scratch`, `process/worktree` or `security/path_containment`
(`grep -lE "src/(roles/skills|…)" test/**/*.test.ts`): `isolation`, `hardening`,
`owner-cli`, `owner-pause-contract`, `project-pause`, `provider-contract`,
`project-boundary`, `rulebook`, `security-policy`, `transcript`, and 9 mutation tests.
Their cases that need only those modules are due in 13.3. The totals (107 files, 573
tests) do not change; re-splitting those 19 files by slice was not done (§10).

**Before any of this, fix Finding 0.1.** The oracle run needs skill roots inside its
own fixture, not the owner's `~/.claude`.

---

## 7. Slices

Order is by dependency, not by size. "TS lines" means plugin lines the slice replaces.
"Cases" are mechanical floors where a mechanism exists, otherwise "not measured".

### Platform-side prerequisites (not priced here)

| # | what | why the daemon needs it |
|---|---|---|
| **P11** | slice 11: host classes and the Worker entry to Rust | slice 12 is built on it (platform doc) |
| **P12** | slice 12: the Worker's MCP endpoint (`mcp_lane` reused), `roles_propose`; `agent_await` for clients with no daemon | under OD3 the daemon forwards `tools/list` and the state tools to it (§3.7). P12 must also settle where `attention` is appended to five answers and who builds `agent_running`'s projection (§3.3, §3.2); the platform doc does not |
| **P-a** | add `answersQuestionId` to `DISPATCH` (Finding 3.6) | delegated answers (13.6) |
| **P-b** | provision mints one token per orchestrator provider (OD1) and documents the roster grants `read claim report` | handoff between providers (Finding 5.1) |
| **P-c** | (only if OD7 = cloud) spawn-spec columns on `role_variant`, plus a project dimension | — |
| **live** | `broker.meapps.dev` provisioned with `ACCESS_AUD` set (owner decision §9.1 of the platform doc) | every slice from 13.1 on talks to it |

### wapps-cli side

| # | slice | TS lines (§7.1) | depends on | behaviour inventory | cases |
|---|---|---:|---|---|---|
| **R0** | **The Rust binary ships.** The version rule already exists (owner decision 2026-10-05, `PORT-kalan-yuzey.md` §4.3, landed in its slice 9): `.goreleaser.yml`'s `before` hook `sh rust/check-version.sh {{ .Version }}` fails a release whose tag is not `rust/crates/cli/Cargo.toml`'s version. **What is still open is the build.** `builds:` has one entry, `main: ./main.go`, and `.github/workflows/{ci,release}.yml` mention `cargo` **0** times (re-measured). "One binary from Homebrew" means the Rust `wapps` replaces the Go one first. PORT-kalan-yuzey §6 item 6 left this as a distribution decision | — | PORT-kalan-yuzey slice 10 + `completion` | — | the existing differential |
| **13.0** | oracle harness: fake `claude`/`codex` recorders, fake cloud from recorded fixtures, MCP transcript runner, hermetic skill roots (Finding 0.1). Section 6 says it exists before any slice, so every slice below depends on it | 0 | — | Finding 0.1 | harness only |
| **13.1** | `wapps broker serve`: stdio MCP, enrollment (cwd → project), Access service token, `tools/list` and the 14 verbatim tools forwarded to the Worker MCP, the observe and rewrite classes without the quota merge, `orchestrator_claim` without resume, the `agent_await` cursor loop, read redaction (§3.7). `agent_submit`, `agent_cancel`, `agent_attach`, `agent_report` answer `ACTION_UNAVAILABLE`; `roles_list` is the Worker's answer | 501 | **13.0**, P12, R0 for install, OD1-3 | 8 files / 26 tests | ≥ 55 (seam 2) |
| **13.2** | the daemon: `wapps broker daemon`, unix socket, `O_EXCL` claim, detached spawn, idle exit, session tracking (gone-owner release) | 745 | 13.1 | 6 / 26 | not measured; inventory 26 |
| **13.3** | execution core + **codex** worker: `agent_submit` → `POST …/jobs` → spawn → attach after `session_configured` → progress heartbeat < 5 min → finish; `agent_cancel`; role spawn spec; **prompt delivery** (skills, repository rulebook, scratch, pause sections), which the codex seam compares byte for byte; **the scrub on every note, output and error that leaves the machine** (§4.5); the owner-pause classifier that stops a codex job; read-only roles only | 2,214 | 13.2, OD5 not needed, OD7, OD8 | 16 / 89, plus the 19 files of §6 | not measured; seam 1 codex + seam 3 |
| **13.4** | writing roles: `git worktree add/remove` per job, with the refusal to remove a dirty tree. Scratch, the pause gate and the scrub are already in 13.3 | 41 | 13.3 | 5 / 20 | not measured |
| **13.5** | **claude** worker: OD5's choice, the PreToolUse gate (ceiling, containment, pause), env allowlist (Finding 4.2). Skills, rulebook and the scrub arrive with 13.3 and are reused | 377 | 13.4, OD5, OD6 | 14 / 61 | not measured; seam 1 claude |
| **13.6** | quota (OD8) and its merge into the five attention answers, resume at claim, native hand-back lane (OD12), delegated answers | 283 | 13.5, P-a | 12 / 40 | not measured |
| **13.7** | `wapps broker install`: Claude Code user MCP config + PreToolUse hook (`wapps broker hook`), Codex `config.toml` `[mcp_servers]`, the rewritten `agent-broker` skill shipped through `wapps skill` | 56 (+ 513 lines of SKILL.md prose to rewrite) | 13.5, OD13, OD14 | 2 / 9 | not measured |
| **13.8** | owner CLI (OD9): `wapps broker answer/accept/confirm/…` with the owner's SSO principal, `project enroll/pause/role apply` | up to 1,018 (693 + 253 + 39 + 33) | 13.1 | 2 / 17 | not measured |
| **13.9** | cut-over and retirement (OD10): per project, the plugin's MCP entry removed and the daemon's installed; then the plugin repository is archived | 0 | everything above | — | — |

13.3 is the largest slice by far: 2,214 of 4,217 lines, 52%. The first figures hid
that; §7.1 shows why (the codex worker cannot pass its own seam without its prompt
delivery, its pause classifier and the scrub).

### 7.1 Which plugin lines each slice replaces

The slice figures this document first had (458, 797, 1,794, 167, 809, 136, 56) were
not published with a file list. Five reproduce from whole files: 13.2 (797) is the
daemon files, `liveness.ts` and `bootstrap_runtime.ts`; 13.4 (167) is `worktree.ts`,
`scratch.ts` and `path_containment.ts`; 13.5 (809) is `claude_agent_sdk.ts`,
`shell.ts`, `claude_hook_root.ts`, `owner_pause.ts` and `transcript_scrub.ts`; 13.6
(136) is `quota.ts` and `native_attach.ts`; 13.7 (56) is `claude_hook.ts`. 13.1 (458) and
13.3 (1,794) reproduce from no file list and together are exactly what remains of 4,217,
so "the sum equals bucket (b)" held by construction. The draft also left
`skills.ts`, `rulebook.ts`, `owner_pause.ts` and `scratch.ts` in 13.5 and 13.4 while
13.3's codex worker imports all four, and put `transcript_scrub.ts` in 13.5 while 13.3
already sends the text it guards.

The table below replaces them. `slices.py` computes it. It assigns every line of the 36
bucket-(b) files to exactly one slice (34 whole files, and `runtime.ts` and `worktree.ts`
by line range), and the 21 other `src` files are named as not ported, so all 57
accounted for. The rule:

- **A file belongs to the first slice whose worker, seam or daemon imports it** (the
  "why" column names the import). A range of a file belongs to the first slice that calls
  the method in it. A method is counted whole in that slice, and its branches that belong
  to later slices (worktree, native lane, routing) are stubs there.
- Two imports force the earliest slice: what the **prompt bytes** of a seam-1 comparison
  contain, and what a slice **sends off the machine** (§4.5).
- Something that is purely additive to an event loop (quota, resume, the native lane)
  stays in its own slice, because the earlier slice does not need it to pass its seam.

| slice | file (range) | lines | why it is here |
|---|---|---:|---|
| **13.1** | `bootstrap.ts` | 192 | enrollment, cwd → project, state home |
|  | `mcp/server.ts` | 146 | stdio MCP framing, read redaction |
|  | `roles/types.ts` | 47 | `bootstrap.ts` imports it |
|  | `mcp/tool_names.ts` | 35 | the 26 names; `server.ts` imports it |
|  | `process/runtime.ts` 132–160 | 29 | `agent_await` constants, `attentionBlock` |
|  | `process/runtime.ts` 735–761 | 27 | `awaitChange` |
|  | `security/redaction.ts` | 21 | `server.ts` imports it |
|  | `process/runtime.ts` 804–807 | 4 | `leaseFrom`: reads the lease authority of a call |
| | *13.1 total* | ***501*** | |
| **13.2** | `daemon/server.ts` | 313 | socket, `O_EXCL` claim, idle exit, sessions |
|  | `daemon/client.ts` | 166 | spawns the daemon detached and connects |
|  | `daemon/protocol.ts` | 115 | newline-JSON frames |
|  | `daemon.ts` | 66 | daemon entry, 30 s reaper |
|  | `main.ts` | 43 | connects to or spawns the daemon, so it arrives with it |
|  | `process/liveness.ts` | 42 | `daemon/server.ts` imports it |
| | *13.2 total* | ***745*** | |
| **13.3** | `process/codex_mcp.ts` | 374 | the codex worker |
|  | `policy/shell.ts` | 278 | `owner_pause.ts` imports it; `runtime.ts#pausedClassStarting` stops a codex job with it |
|  | `process/runtime.ts` 161–370 | 210 | class head, constructor, `submit` (its worktree, native and routing branches are stubs until 13.4 and 13.6) |
|  | `process/provider_types.ts` | 150 | imported by every adapter |
|  | `process/runtime.ts` 1–131 | 131 | types, `SubmitRequest`, `RuntimeOptions` |
|  | `process/runtime.ts` 390–503 | 114 | `#runRemote` |
|  | `process/runtime.ts` 555–661 | 107 | `#release` (scratch removal, every job), `#terminalize`, `#pausedClassStarting`, `roles`, `#record`, `#session` |
|  | `roles/registry.ts` | 103 | the role table loader (spawn spec, OD7) |
|  | `roles/skills.ts` | 100 | **`codex_mcp.ts:7,158`** |
|  | `bootstrap_runtime.ts` 1–95 | 95 | wires the runtime and its adapters (wiring edges, below) |
|  | `policy/owner_pause.ts` | 91 | `codex_mcp.ts:6,170`; codex has no per-command gate |
|  | `roles/rulebook.ts` | 75 | **`codex_mcp.ts:8,162`** |
|  | `process/scratch.ts` | 69 | `runtime.ts:402`: every job gets a scratch, read-only ones too; `codex_mcp.ts:9` |
|  | `security/transcript_scrub.ts` | 63 | every outbound free text (§4.5); the first sender is in 13.3 |
|  | `process/runtime.ts` 762–803 | 42 | `waitForJob` and `activeWorkerCount` (test hooks, called from tests only), `cancel` |
|  | `process/fake_provider.ts` | 38 | implements `ProviderAdapter`; replaced by 13.0's recorders |
|  | `process/worktree.ts` 1–36 | 36 | `gitCommonDir`, which `scratch.ts:3` imports |
|  | `roles/resolve_role.ts` | 35 | `provider_types.ts` imports it |
|  | `roles/provider_tools.ts` | 27 | `registry.ts` imports it |
|  | `policy/capability.ts` | 23 | `provider_types.ts` imports it |
|  | `security/path_containment.ts` | 21 | `codex_mcp.ts:10`, `provider_types.ts` |
|  | `process/cancel.ts` | 13 | bounded wait after abort |
|  | `security/argv.ts` | 10 | `codex_mcp.ts:5`, `worktree.ts:3` |
|  | `process/runtime.ts` 671–679 | 9 | `#note` |
| | *13.3 total* | ***2,214*** | |
| **13.4** | `process/worktree.ts` 37–77 | 41 | `createWorktree`, `removeWorktreeIfClean` |
| | *13.4 total* | ***41*** | |
| **13.5** | `process/claude_agent_sdk.ts` | 243 | the claude worker |
|  | `policy/claude_hook_root.ts` | 134 | the claude gate's path and command classes |
| | *13.5 total* | ***377*** | |
| **13.6** | `process/quota.ts` | 100 | reads both providers' rate-limit events |
|  | `process/runtime.ts` 680–734 | 55 | `attachSubagent`, `reportSubagent` |
|  | `process/runtime.ts` 504–554 | 51 | `resumeAbandoned` |
|  | `process/native_attach.ts` | 36 | the native (hand-back) lane |
|  | `roles/resolve_adapter.ts` | 32 | native vs broker-managed |
|  | `process/runtime.ts` 662–670 | 9 | `#quota` |
| | *13.6 total* | ***283*** | |
| **13.7** | `policy/claude_hook.ts` | 56 | the parent session's PreToolUse hook |
| | *13.7 total* | ***56*** | |
| | **13.1–13.7 total** | **4,217** | equals bucket (b); see the note below |

Checks `slices.py` runs, and what it printed:

- **Partition.** Every line of `runtime.ts` (1–1,071) and `worktree.ts` (1–77) falls in
  one range. The not-ported ranges are `runtime.ts` 371–389 (`#route`, 19, c-open) and
  808–1,071 (`RuntimeControlBackend`, 264, bucket a).
- **Coverage.** 57 `src` files: 36 assigned, 21 named as not ported (`storage/*`,
  `view/*`, `lifecycle/stages.ts`, `mcp/schemas.ts`, `roles/propose.ts`, `roles/route.ts`,
  `process/recovery.ts`, `security/launcher_handshake.ts`, `cli/commands.ts`), 0
  unaccounted. All 10,963 lines.
- **Import edges.** Between bucket-(b) files, **0** point at a later slice, except 3
  declared wiring edges: `main.ts` → `bootstrap_runtime.ts`, `daemon.ts` →
  `bootstrap_runtime.ts` and `bootstrap_runtime.ts` → `claude_agent_sdk.ts`. A file that
  constructs the runtime names every adapter, so it points forward by construction. The
  Rust side grows one registration per slice.
- **Scrub ordering.** The senders of free text (`#note`, `#terminalize` in 13.3;
  `reportSubagent` in 13.6) are not earlier than the scrub (13.3).

**Sum of 13.1–13.7 = 4,217 = bucket (b).** This is a partition check, not a
measurement: it says no line was dropped or counted twice. It does not say the
assignment is right. That is what the "why" column and the import check are for.
`RuntimeControlBackend` (264 lines) is replaced by the forwarding of §3.7, not ported.
Storage (3,353 + 379 SQL) is already the cloud's.

**Smallest end-to-end first.** 13.1 is useful on its own: an orchestrator can claim,
keep a work list, ask and hand over against the live broker, with no worker. 13.3 adds
one provider end to end. Codex goes first even though claude ran **1,002 of 1,050**
jobs. Codex's seam is a published protocol (MCP), while claude's needs OD5 settled
and, under OD5-B, a private one.

---

## 8. Owner decisions, each with a recommendation

| # | decision | options | recommendation |
|---|---|---|---|
| **OD1** | One Access service token per machine, or one per (machine, orchestrator provider) | (A) one `-agents` token, which the in-flight provision mints; (B) two, `…-claude` and `…-codex` | **B.** With A, claude ↔ codex handoff always gets `handoff_to_self` (Finding 5.1). B also makes `launcher_handshake` (d) honestly, because the principal *is* the orchestrator. Needs P-b |
| **OD2** | Where the daemon's token secret lives at run time | (A) read from the secrets gate at start (needs a live SSO session and an agent-mode exception for a read); (B) the gate keeps the record, and a human `wapps broker enroll` (TTY) writes a 0600 runtime copy under the state home; (C) macOS Keychain | **B.** Same shape as memory's default `file:` sink. The daemon's uptime does not depend on an SSO session. The gate stays the place to rotate from. Never in env (Finding 4.2) |
| **OD3** | The daemon forwards state tools to the Worker's MCP endpoint, or calls the HTTP routes itself | (A) forward `tools/list` and the Worker's answers, and act on **12** of the 26 tools (§3.7): **7** acted on (`orchestrator_claim`, `agent_submit`, `agent_cancel`, `agent_attach`, `agent_report`, `agent_await`, `roles_list`), **3** whose answers it rewrites to merge `quota` into `attention` (`agent_status`, `agent_running`, `orchestrator_status`), **2** it observes to keep lease capabilities (`orchestrator_takeover`, `orchestrator_release`); **14** pass verbatim. At least 3 `tools/list` entries are replaced (`agent_submit`, `agent_attach`, `agent_report`: 28 of 102 input properties); (B) translate all 26 to HTTP in Rust | **A.** The rules of validity (lengths, enums, patterns, §3.5) stay in one place, the Worker's, instead of two. That is the plugin's own rule (`main.ts`: "a second copy here would be a second definition of the same rules"). The shapes do not stay single: the daemon holds a second `inputSchema` for 3 tools and reads named fields of 9 more. The first draft said "19 verbatim, 7 intercepted" and also merged quota into three of the 19; both cannot hold. Cost: P12 becomes a hard prerequisite of 13.1, and it must settle where `attention` is appended and who builds `agent_running` |
| **OD4** | `agent_await` | (A) the daemon polls `GET …/attention?since=` (the cloud README's own "client loop" ruling); (B) hibernatable WebSocket | **A, every 2 s up to 55 s** (≤ 28 requests per call). B needs a WebSocket crate and an Access-gated upgrade for a gain nobody has measured. **Request cost was not measured** |
| **OD5** | How the daemon drives a claude worker | (A) public flags `--agents`/`--settings`/`--allowedTools`/`--permission-mode`/`--session-id` + a **command** PreToolUse hook (`wapps broker worker-gate`); (B) re-implement the SDK's `control_request` protocol (initialize, `hook_callback`) | **A, if 13.5's first measurement shows `--agents` carries `effort` and `skills`.** Otherwise B. A depends only on documented CLI surface; B depends on a protocol whose only spec is `sdk.mjs` |
| **OD6** | Which `claude` binary | (A) `claude` on `PATH` (2.1.289 here); (B) pin a version the way the SDK bundles 2.1.228 | **A + a version floor checked at daemon start.** B means shipping or locating a 276 MB binary |
| **OD7** | Where the role **spawn spec** (model, effort, prompt, skills, description) lives | (A) local per project, without `tools`; the ceiling comes from the cloud; (B) the cloud, with a project dimension | **A.** Measured by `od7.py` over the **10 enrolled projects** (each has a `roles.json`): 23 (role, provider) keys, and the `tools` **set** agrees across projects for all 23 (`verifier.claude` lists the same five tools in two orders), so one estate ceiling is true today. But `model`/`effort` differ for 3 keys (`verifier.claude`, `frame-critic.codex`, `reviewer.claude`), `skills` for 1 (`mechanic.claude`), and prompts differ per project: of the 23 prompt files, 11 have more than one distinct content (e.g. `builder.claude.md`, 4 distinct contents across 5 projects; `mechanic.claude.md` also 4 across 5). The spawn spec is per project and the ceiling is per estate. Dispatch fails closed when a role has no cloud ceiling |
| **OD8** | Transcript, the explorer view (2,481 lines), quota | keep a local transcript + port the explorer; or drop both and keep quota in daemon memory | **Drop the transcript and the explorer from this port** (the screen can come back later, over cloud reads). **Keep quota** (100 lines) in daemon memory, merged into `attention` (§3.3). The scrub stays and moves earlier: the note, the finish `output` and the finish `error` all leave the machine now, so all three go through it from 13.3 (§4.5) |
| **OD9** | The owner's terminal (`work.ts` + `project.ts` + `bin`, 1,018 lines) | port as `wapps broker …` using the owner's SSO principal; or rely on raw HTTP | **Port the subset that needs a human**: `answer accept confirm questions list running` + `project enroll pause unpause role apply`. The owner's door cannot be used by the daemon's principal (it must not hold `answer`) |
| **OD10** | The 245 open work items (navlun 203) and 1 open question | (A) no migration: finish or drop under the plugin, then cut over; (B) a one-shot replay of open items (title, intent, parent, horizon) through `work_add` at cut-over, deleted afterwards | **Owner's call, not mine.** Your backward-compatibility rule covers projects with nothing deployed. This plugin is in daily use. If asked: **B for navlun only**, the rest by A |
| **OD11** | `tokio` stays banned | stay sync with threads; or admit tokio | **Stay sync.** Nothing in §4 needs async. `ureq` is blocking, and N workers + M sessions + timers fit threads |
| **OD12** | Native hand-back lane (`handBack`, `agent_attach`, `agent_report`) | keep; or drop | **Keep.** 16 of 1,050 jobs used it, the cloud already has attach/finish, and it costs 36 lines (`native_attach.ts`) + 55 (`runtime.ts` 680–734) |
| **OD13** | MCP server name and install target | `wapps-broker` installed into Claude Code user scope and Codex `config.toml` by `wapps broker install` | **Yes.** The hook matcher becomes `mcp__wapps-broker__.*` |
| **OD14** | Ship the orchestrator skill through `wapps skill` | yes / separate | **Yes.** `wapps skill` already installs one embedded `SKILL.md` (PORT-kalan-yuzey slice 8) |
| **OD15** | What the scrub covers, and how strongly | (A) the daemon's own words (note, finish output, finish error), the plugin's 5 patterns with `ASSIGNMENT` matching anywhere on a line; (B) A plus text the orchestrator authors (work items, questions, the handoff note, the dispatch `task`); (C) the plugin's patterns as they are | **A** (judgment, not measured). Orchestrator text is what the orchestrator chose to write, not a tool result, and a heuristic that redacts any 40-character mixed-case run would also redact a legitimate identifier in a work item. C leaves the measured hole (§4.5). It is the owner's call whether orchestrator text should leave the machine unscrubbed, as it always could, now that it leaves the machine |

---

## 9. Findings, collected

1. **0.1** The plugin's test suite reads `~/.claude`. With an isolated `HOME`, 17/585 fail.
2. **0.2** The task's "52 test files" does not reproduce: 107 files, 585 tests.
3. **3.6** The cloud's dispatch body has no `answersQuestionId`, so delegated answers cannot be reached over HTTP. Read, not run.
4. **4.2** Claude workers inherit the daemon's whole environment (74 names recorded). Codex workers get 9.
5. **4.2b** The plugin runs the SDK-bundled `claude` 2.1.228, not the `PATH` 2.1.289.
6. **4.3** The cloud orphans a job after 5 min of silence, and codex may be silent for 10. The daemon must heartbeat every running job.
7. **5.1** A single agents token puts both orchestrators behind one principal, so handoff always gets `handoff_to_self`.
8. **R0** The shipped `wapps` is still the Go binary. The tag-equals-`Cargo.toml` rule exists
   already (owner decision 2026-10-05); the missing part is the build: one `builds:` entry
   (`./main.go`) and 0 `cargo` mentions in CI.
9. `wapps-platform` `main` moved during measurement (`7cf2d20` → `57b8bbb`). `src/http` was deleted and every cloud citation was re-measured.
10. **3.5** The plugin's schemas and the cloud's bodies differ in 44 of 51 comparable fields (capability floor 14, id ceilings 17 + 4, content ceilings 7, role name 1, handoff target 1), plus whole-body shapes, trim and the mission-id pattern. Found by `schema_diff.py`, not left to the differential.
11. **3.7** The daemon acts on 12 of the 26 tools, not 7 (7 acted on, 3 rewritten, 2 observed; 14 verbatim), and publishes a second `inputSchema` for at least 3. "One schema definition" holds for the rules of validity, not for the shapes.
12. **4.5** The plugin scrubbed only its local transcript. Progress notes, finish output and finish error had `redact` alone, which removes nothing from text. All three leave the machine from 13.3, so the scrub is a 13.3 dependency. `scrubForTranscript` truncates to 8,192 and cannot be used for output. The line-anchored `ASSIGNMENT` pattern misses `Bash: NAME=secret …` (measured).
13. **7.1** The first per-slice line figures could not be audited, and the slice order ignored what the 13.3 codex worker imports (`skills.ts`, `rulebook.ts`, `owner_pause.ts` and `shell.ts`, `scratch.ts` and the `worktree.ts` helper it needs, `path_containment.ts`) and the scrub it needs. Reassigned by import: 13.3 is 2,214 lines, 13.4 is 41.

---

## 10. What I did not measure

1. **No request reached a running cloud broker.** Every cloud statement comes from
   reading `57b8bbb`'s source and frozen ledgers. Finding 3.6 is read, not run.
2. **The codex seam was read, not recorded.** Only claude's spawn was recorded (§4.2).
3. **Whether `claude --agents` honours `effort` and `skills`.** That is OD5's deciding
   fact. It is 13.5's first measurement.
4. **The cost of OD4's polling** in Workers / Durable Object requests.
5. **`signal-hook`, `tungstenite` and `schemars` crate deltas.** They were not in the
   offline registry cache, and no option recommended here needs them.
6. **Rust line counts for any slice.** Sizes are TS lines replaced plus test inventory,
   in PORT-kalan-yuzey's units, not a forecast of Rust size.
7. **Case counts beyond 13.1's mechanical floor.** The other slices list the plugin
   behaviour they must re-express, not a case count.
8. **The slice-to-test assignment in §6** is judged from imports and file names, not
   from reading each test, and §7.1 has since moved some modules earlier. The 19 test
   files that import them (139 tests) were counted, not re-assigned.
9. **The in-flight `broker-provision` lane** was read uncommitted. If it changes,
   §5's quote and P-b move with it.
10. **What `hardening.test.ts`'s 30 tests split into.** Not split.
11. **Whether the daemon can run on Linux unchanged.** Everything is POSIX and
    `ps -o lstart=` exists on both, but only darwin/arm64 was run.
12. **Live-state contents beyond the counts in §2.3.** No row was read beyond those
    counts.
13. **What the Worker's MCP endpoint (P12) will answer.** It is unbuilt. §3.7 and the P12
    row state what OD3 needs from it (where `attention` is appended, `agent_running`'s
    projection, whether `claim` and `takeover` keep `provider` as an argument). The
    platform doc does not say, and there is nothing to run.
14. **The scrub's recall.** §4.5 ran one sample text and three command lines. That shows
    one hole and says nothing about how many others there are. The seam-3 planted-secret
    scenario is the only guard proposed.
15. **How many of the divergences in §3.5 an agent would hit in practice.** The list is
    complete for fields that carry a ceiling on both sides. How often a real orchestrator
    sends a 4,001-character question was not measured.

Scratch artifacts (ephemeral, not committed): `/tmp/broker-oracle.mw98/` holds
`bun-test.log`, `bun-test2.log`, `mcp-transcript.jsonl`, `rec/` (the claude spawn
recording) and `rustcopy/` (crate-delta runs). The scripts of §0 are committed in
`docs/broker-daemon-port.measure/` and regenerate everything else in this document
that is not named here.
