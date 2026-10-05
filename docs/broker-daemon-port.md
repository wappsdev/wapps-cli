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
lists what was not measured.

Measurement record:

| | |
|---|---|
| source (oracle) | `dual-orchestrator-agent-broker` `c6d7e09fa0df9d8ad231fd56520a14fee4432ba5` (clean) |
| target | `wapps-cli` `765ca48` (`main`); this doc is on `lane/broker-daemon-pricing` |
| cloud broker | `wapps-platform` **`57b8bbb`**: see the note below |
| plugin test suite | `bun test` (bun 1.4.0) in a scratch copy: **585 pass, 0 fail, 107 files, 63.7 s** |
| plugin MCP transcript | recorded live from `bun src/main.ts` in a scratch copy (§3.1) |
| claude spawn seam | recorded with a fake `claude` binary in the scratch copy (§4.2) |

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
| **(b)** port to the Rust daemon | **4,217** | 35 files + the execution half of `runtime.ts` (788 of its 1,071 lines) |
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
| `src/process/runtime.ts` 1–165, 166–807 | 788 | b | types; `submit` 205, `#runRemote` 122, `resumeAbandoned` 41, release/terminalize/pause 74, roles/record/note 54, subagent attach/report 57, `awaitChange` 21, cancel 47, blank 2 |
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
| `src/security/transcript_scrub.ts` | 63 | b | secret scrub (5 patterns, one with look-aheads, §4.4) |
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
| owner-pause markers (state dir + project) | read by the hook and the runtime | stays (13.5) |
| `~/.agent-broker/state/<id>/broker.sqlite` | **all state** | goes away (**OD10**) |

### 2.3 What is in the local stores today (read-only, measured)

| project | missions | open work items | jobs | non-terminal jobs | open questions | db size |
|---|---:|---:|---:|---:|---:|---:|
| navlun | 1 | 203 | 836 | 1 | 1 | 750 MB |
| wapps-platform | 1 | 19 | 112 | 0 | 0 | 106 MB |
| real-estate-analysis | 1 | 15 | 5 | 0 | 0 | 512 KB |
| ecommerce | 1 | 4 | 63 | 0 | 0 | 49 MB |
| kick-clip-analyzer | 1 | 4 | 34 | 0 | 0 | 21 MB |
| self, broker, dats-frontend, wapps-cli | 0–1 | 0 | 0 | 0 | 0 | ≤ 192 KB |

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
| `agent_report` | A, `jobId`, `status`, `output?`, `error?` | `POST …/jobs/finish` | `report` verb. The cloud also accepts `timed_out` |
| `agent_list` | — | `GET …/jobs` | |
| `agent_running` | — | `GET …/jobs` filtered | wrapped `{running:[…]}` + attention |
| `agent_await` | `sinceDigest?`, `waitMs ≤ 55,000` | **no wait route**; `GET …/attention?since=` is the cursor | §3.4 |
| `agent_status` | `jobId` | `GET …/jobs/:job` | + attention |
| `agent_result` | `jobId` | `GET …/jobs/:job/result` (marks it read) | |
| `agent_cancel` | A, `jobId` | `POST …/jobs/cancel` + **local kill** | the cloud writes the state and kills nothing: *"broker uzaktaki bir süreci öldüremez"* (`services/broker/src/http/routes.ts:589-590` at `7cf2d20`; the Rust `cancel_job`, `broker_handlers.rs:568`, keeps the behaviour, not the comment). The daemon kills |

**Read, not run:** the cloud bodies (`crates/core/src/broker/body.rs`) and their 12,376
frozen cases. No request was sent to a running Worker.

### 3.3 The attention block

The plugin appends `attention` to `agent_submit`, `agent_status`, `agent_running` and
`orchestrator_status` (`runtime.ts:140`). Empty lists are dropped and the digest is
always present. The cloud's `MissionDO.attention` (`services/broker/src/attention.ts:89`)
has the same lists **except `quota`**, because `provider_quota` is (b) in the cloud.
Only the daemon sees quota. So either the daemon merges its own quota list into the
answer, or the list disappears (OD8).

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
with a reason, the way `cases.py` excludes four cases:

1. `orchestrator_prepare_handoff` / `orchestrator_takeover`: the input shapes change (above).
2. Length ceilings: `work_ask` 10,000 → 4,000; `work_relay_answer` 10,000 → 20,000;
   `agent_submit.task` 100,000 → 200,000; `id` fields 256 → 128.
3. `roles_list` loses or keeps `model`/`mode` depending on OD7.
4. `attention.quota` (OD8).
5. Error envelopes: the cloud's `{error, message, details, recovery}` against the
   SDK's JSON-RPC errors.
6. `orchestrator_claim` no longer resumes abandoned work inside the cloud call. The
   daemon does it around the call (13.6).

### 3.6 Finding: the dispatch body cannot carry `answersQuestionId`

`crates/core/src/broker/body.rs:203-215` (`DISPATCH`, at `57b8bbb`) lists `authority
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
| cancel | `runtime.ts:771-807`, `cancel.ts` | marks cancel requested, aborts, `adapter.cancel()` (claude: `close()`; codex: close the session), waits ≤ 5 s | closes pipes / child exits | close stdin + `kill` the child's process group |
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
| secret scrub of progress notes (`transcript_scrub.ts`, 5 patterns) | hand-written matcher | `regex = "1"` adds **4 crates** (`aho-corasick regex regex-automata regex-syntax`), deny ok. **But** the high-entropy pattern uses three look-aheads (`transcript_scrub.ts:26`), which `regex` cannot express. A hand-written matcher is needed anyway, so `regex` buys nothing |
| shell classifier (`policy/shell.ts`) | string matching | its regexes are fixed alternations (`:164-174`) |
| JSON Schema for `tools/list` | none under OD3 (the Worker owns `tools/list`) | without OD3, 26 hand-written schemas or `schemars` (not measured) |
| SIGTERM handling | none | the claim already tolerates a holder killed with SIGKILL (`server.ts:133-137`). `signal-hook`: not measured, not in the offline cache |
| WebSocket | none under OD4 | `tungstenite`: not measured, not in the offline cache |
| date parsing of `ps -o lstart=` | hand-written | the format is fixed: `Mon Oct  5 06:32:47 2026` |

**No new crate is required** under the recommended options. The only `Cargo.toml`
change is one `rustix` feature.

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
local SQLite and the daemon's is the cloud, and §3.5 lists six deliberate differences.
So the differential is held at **three seams**, and only the first is a byte-level
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
model observed, terminal state, cancel). Under OD5-A the claude half compares
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
progress every < 5 min → finish; cancel; resume at claim). There is no oracle on this
seam, because the plugin never spoke HTTP. Its guard is the platform's frozen body
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
| **P12** | slice 12: the Worker's MCP endpoint (`mcp_lane` reused), `roles_propose`; `agent_await` for clients with no daemon | under OD3 the daemon forwards `tools/list` and every state tool to it |
| **P-a** | add `answersQuestionId` to `DISPATCH` (Finding 3.6) | delegated answers (13.6) |
| **P-b** | provision mints one token per orchestrator provider (OD1) and documents the roster grants `read claim report` | handoff between providers (Finding 5.1) |
| **P-c** | (only if OD7 = cloud) spawn-spec columns on `role_variant`, plus a project dimension | — |
| **live** | `broker.meapps.dev` provisioned with `ACCESS_AUD` set (owner decision §9.1 of the platform doc) | every slice from 13.1 on talks to it |

### wapps-cli side

| # | slice | TS lines | depends on | behaviour inventory | cases |
|---|---|---:|---|---|---|
| **R0** | **The Rust binary ships.** `.goreleaser.yml` builds `main: ./main.go` and nothing else; `.github/workflows/*.yml` mention `cargo`/`rust` **0** times (measured). "One binary from Homebrew" means the Rust `wapps` replaces the Go one first | — | PORT-kalan-yuzey slice 10 + `completion` | — | the existing differential |
| **13.0** | oracle harness: fake `claude`/`codex` recorders, fake cloud from recorded fixtures, MCP transcript runner, hermetic skill roots | 0 | — | Finding 0.1 | harness only |
| **13.1** | `wapps broker serve`: stdio MCP, enrollment (cwd → project), Access service token, forwarding to the Worker MCP, `agent_await` cursor loop, read redaction. Execution tools answer `ACTION_UNAVAILABLE` | 458 | P12, R0 for install, OD1-3 | 8 files / 26 tests | ≥ 55 (seam 2) |
| **13.2** | the daemon: `wapps broker daemon`, unix socket, `O_EXCL` claim, detached spawn, idle exit, session tracking (gone-owner release) | 797 | 13.1 | 6 / 26 | not measured; inventory 26 |
| **13.3** | execution core + **codex** worker: `agent_submit` → `POST …/jobs` → spawn → attach after `session_configured` → progress heartbeat < 5 min → finish; `agent_cancel`; role spawn spec; read-only roles only | 1,794 | 13.2, OD5 not needed, OD7 | 16 / 89 | not measured; seam 1 codex + seam 3 |
| **13.4** | writing roles: worktree per job, scratch, write containment | 167 | 13.3 | 5 / 20 | not measured |
| **13.5** | **claude** worker: OD5's choice, the PreToolUse gate (ceiling, containment, pause), rulebook/skills delivery, env allowlist (Finding 4.2), notes scrubbed before they leave the machine | 809 | 13.4, OD5, OD6 | 14 / 61 | not measured; seam 1 claude |
| **13.6** | quota (OD8), resume at claim, native hand-back lane (OD12), delegated answers | 136 (+ runtime parts counted in 13.3) | 13.5, P-a | 12 / 40 | not measured |
| **13.7** | `wapps broker install`: Claude Code user MCP config + PreToolUse hook (`wapps broker hook`), Codex `config.toml` `[mcp_servers]`, the rewritten `agent-broker` skill shipped through `wapps skill` | 56 (+ 513 lines of SKILL.md prose to rewrite) | 13.5, OD13, OD14 | 2 / 9 | not measured |
| **13.8** | owner CLI (OD9): `wapps broker answer/accept/confirm/…` with the owner's SSO principal, `project enroll/pause/role apply` | up to 1,018 | 13.1 | 2 / 17 | not measured |
| **13.9** | cut-over and retirement (OD10): per project, the plugin's MCP entry removed and the daemon's installed; then the plugin repository is archived | 0 | everything above | — | — |

**Sum of 13.1–13.7 = 4,217 TS lines = bucket (b) exactly** (458 + 797 + 1,794 + 167 +
809 + 136 + 56). The 264-line `RuntimeControlBackend` is replaced by a forwarding
table, not ported. Storage (3,353 + 379 SQL) is already the cloud's.

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
| **OD3** | The daemon forwards state tools to the Worker's MCP endpoint, or calls the HTTP routes itself | (A) forward `tools/list` and 19 tools verbatim; intercept 7: `orchestrator_claim` (resume around it), `agent_submit`, `agent_cancel`, `agent_attach` + `agent_report` (native lane), `agent_await` (cursor loop), `roles_list` (merge the local spawn spec); merge `quota` into the 4 attention-carrying answers; (B) translate all 26 to HTTP in Rust | **A.** One schema definition (the Worker's) instead of two. This is the plugin's own rule (`main.ts`: "a second copy here would be a second definition of the same rules"). Cost: P12 becomes a hard prerequisite of 13.1 |
| **OD4** | `agent_await` | (A) the daemon polls `GET …/attention?since=` (the cloud README's own "client loop" ruling); (B) hibernatable WebSocket | **A, every 2 s up to 55 s** (≤ 28 requests per call). B needs a WebSocket crate and an Access-gated upgrade for a gain nobody has measured. **Request cost was not measured** |
| **OD5** | How the daemon drives a claude worker | (A) public flags `--agents`/`--settings`/`--allowedTools`/`--permission-mode`/`--session-id` + a **command** PreToolUse hook (`wapps broker worker-gate`); (B) re-implement the SDK's `control_request` protocol (initialize, `hook_callback`) | **A, if 13.5's first measurement shows `--agents` carries `effort` and `skills`.** Otherwise B. A depends only on documented CLI surface; B depends on a protocol whose only spec is `sdk.mjs` |
| **OD6** | Which `claude` binary | (A) `claude` on `PATH` (2.1.289 here); (B) pin a version the way the SDK bundles 2.1.228 | **A + a version floor checked at daemon start.** B means shipping or locating a 276 MB binary |
| **OD7** | Where the role **spawn spec** (model, effort, prompt, skills, description) lives | (A) local per project, without `tools`; the ceiling comes from the cloud; (B) the cloud, with a project dimension | **A.** Measured over 10 projects: `tools` agree for all 23 (role, provider) keys, so one estate ceiling is true today. But model/effort differ for 3 keys and prompts differ per project (e.g. `builder.claude.md`, 4 distinct contents across 5 projects). The spawn spec is per project and the ceiling is per estate. Dispatch fails closed when a role has no cloud ceiling |
| **OD8** | Transcript, the explorer view (2,481 lines), quota | keep a local transcript + port the explorer; or drop both and keep quota in daemon memory | **Drop the transcript and the explorer from this port** (the screen can come back later, over cloud reads). **Keep quota** (100 lines) in daemon memory, merged into `attention` (§3.3). Progress notes leave the machine now, so they go through the scrub |
| **OD9** | The owner's terminal (`work.ts` + `project.ts` + `bin`, 1,018 lines) | port as `wapps broker …` using the owner's SSO principal; or rely on raw HTTP | **Port the subset that needs a human**: `answer accept confirm questions list running` + `project enroll pause unpause role apply`. The owner's door cannot be used by the daemon's principal (it must not hold `answer`) |
| **OD10** | The 245 open work items (navlun 203) and 1 open question | (A) no migration: finish or drop under the plugin, then cut over; (B) a one-shot replay of open items (title, intent, parent, horizon) through `work_add` at cut-over, deleted afterwards | **Owner's call, not mine.** Your backward-compatibility rule covers projects with nothing deployed. This plugin is in daily use. If asked: **B for navlun only**, the rest by A |
| **OD11** | `tokio` stays banned | stay sync with threads; or admit tokio | **Stay sync.** Nothing in §4 needs async. `ureq` is blocking, and N workers + M sessions + timers fit threads |
| **OD12** | Native hand-back lane (`handBack`, `agent_attach`, `agent_report`) | keep; or drop | **Keep.** 16 of 1,050 jobs used it, the cloud already has attach/finish, and it costs 36 + 57 lines |
| **OD13** | MCP server name and install target | `wapps-broker` installed into Claude Code user scope and Codex `config.toml` by `wapps broker install` | **Yes.** The hook matcher becomes `mcp__wapps-broker__.*` |
| **OD14** | Ship the orchestrator skill through `wapps skill` | yes / separate | **Yes.** `wapps skill` already installs one embedded `SKILL.md` (PORT-kalan-yuzey slice 8) |

---

## 9. Findings, collected

1. **0.1** The plugin's test suite reads `~/.claude`. With an isolated `HOME`, 17/585 fail.
2. **0.2** The task's "52 test files" does not reproduce: 107 files, 585 tests.
3. **3.6** The cloud's dispatch body has no `answersQuestionId`, so delegated answers cannot be reached over HTTP. Read, not run.
4. **4.2** Claude workers inherit the daemon's whole environment (74 names recorded). Codex workers get 9.
5. **4.2b** The plugin runs the SDK-bundled `claude` 2.1.228, not the `PATH` 2.1.289.
6. **4.3** The cloud orphans a job after 5 min of silence, and codex may be silent for 10. The daemon must heartbeat every running job.
7. **5.1** A single agents token puts both orchestrators behind one principal, so handoff always gets `handoff_to_self`.
8. **R0** The shipped `wapps` is still the Go binary, and CI has no Rust step. Slice 13's install story needs the Rust binary in the release train first.
9. `wapps-platform` `main` moved during measurement (`7cf2d20` → `57b8bbb`). `src/http` was deleted and every cloud citation was re-measured.

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
   from reading each test.
9. **The in-flight `broker-provision` lane** was read uncommitted. If it changes,
   §5's quote and P-b move with it.
10. **What `hardening.test.ts`'s 30 tests split into.** Not split.
11. **Whether the daemon can run on Linux unchanged.** Everything is POSIX and
    `ps -o lstart=` exists on both, but only darwin/arm64 was run.
12. **Live-state contents beyond the counts in §2.3.** No row was read beyond those
    counts.

Scratch artifacts (ephemeral, not committed): `/tmp/broker-oracle.mw98/` holds
`bun-test.log`, `bun-test2.log`, `mcp-transcript.jsonl`, `rec/` (the claude spawn
recording) and `rustcopy/` (crate-delta runs).
