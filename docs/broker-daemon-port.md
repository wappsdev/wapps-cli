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
§7.1, OD7, OD10 and OD15 are committed in `docs/broker-daemon-port.measure/` (§0), so a
reader can rerun them. A sum is called a sum, not a measurement, when it is computed from
parts that were measured separately.

**The owner decided OD1 to OD15 on 2026-10-05** (§8). This revision reshapes the slices to
those decisions: one Access token and no orchestrator handoff (OD1), the explorer ported
over cloud reads with the job transcript kept local (OD8, slices 13.9 and 13.10), the
owner's human commands only (OD9), and a one-shot replay of four projects' open work
(OD10, slice 13.11). One new question came out of measuring them, OD16; the owner decided it the same day (B: a leaseless owner door).

Measurement record:

| | |
|---|---|
| source (oracle) | `dual-orchestrator-agent-broker` `c6d7e09fa0df9d8ad231fd56520a14fee4432ba5` (clean) |
| target | `wapps-cli` `765ca48` (`main` is now `c8c7daf`, CLI completion); this doc is on `lane/broker-daemon-pricing` |
| cloud broker | `wapps-platform` **`57b8bbb`**, re-checked at **`cac8ede`**: see the note below |
| plugin test suite | `bun test` (bun 1.4.0) in a scratch copy: **585 pass, 0 fail, 107 files, 63.7 s** |
| plugin MCP transcript | recorded live from `bun src/main.ts` in a scratch copy (§3.1) |
| claude spawn seam | recorded with a fake `claude` binary in the scratch copy (§4.2) |
| scripts | `docs/broker-daemon-port.measure/` in this branch: `slices.py`, `schema_diff.py`, `tools_list.ts`, `od7.py`, `od10.py`, `od15_probe.ts`, `stores.sh`, `scrub_probe.ts` (§0) |

**`wapps-platform` `main` moved while this was being measured.** The task text was
written against `7cf2d20`. At 06:32 `57b8bbb` merged ("broker L5 slice 9b - the 37
handlers answer in Rust"), and `services/broker/src/http/` is gone. Every citation of
a cloud route or body below was **re-measured at `57b8bbb`**. Routes are in
`crates/workers/src/broker_routes.rs`, bodies in `crates/core/src/broker/body.rs`.
`main` then moved again, to `cac8ede` ("broker provision - one idempotent command").
`git diff --stat 57b8bbb..cac8ede` touches no file under `crates/workers/src/` and not
`crates/core/src/broker/`, so every route, body and method cited here is unchanged. What
did change is §5's source: the provision is now committed (`crates/ops/src/provision/broker.rs`).

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
| `slices.py` | `python3 slices.py <plugin repo> [--table] [--owner]` | the file-to-slice table, per-slice sums, the coverage check (57 `src` files, 0 unaccounted), the symbol-level dependency check over every importer (whole files **and** line ranges), the declared stubs with the seam cases each excludes, what replaces every use of unported code, and the scrub-ordering check; `--owner` sizes each command of `scripts/work.ts`; exits 1 on a violation | §7.1, 13.8, 13.10 |
| `tools_list.ts` | `bun tools_list.ts <plugin src>` (in a scratch copy) | the 26 `inputSchema`s as JSON, from an in-memory MCP client | §3.5 |
| `schema_diff.py` | `python3 schema_diff.py tools.json <body.rs>` | one line per compared field, then a tally: 51 compared, 7 equal, 44 differ | §3.5 |
| `od7.py` | `python3 od7.py` | the role tables of every enrolled project compared: tool sets, model/effort, skills, prompt hashes | OD7 |
| `od10.py` | `python3 od10.py` | read-only, counts and lengths only: `handoff_packages` and `job_transcript` sizes in every store; for the four migrating projects, the open items by parent depth, closed parents, parts with a horizon, title/intent lengths against the cloud's ceilings, and the open questions | OD1, OD8, OD10 |
| `od15_probe.ts` | `bun od15_probe.ts <plugin src>` (in a scratch copy) | how many of the replayed texts (open items' title and intent, open questions) the plugin's `scrubText` would change, and how many work-item texts an unanchored `ASSIGNMENT` would match; counts only | OD15 |
| `stores.sh` | `sh stores.sh` | the read-only census of every `broker.sqlite` and the job split by provider | §2.3 |
| `scrub_probe.ts` | `bun scrub_probe.ts <plugin src>` (in a scratch copy) | what `redact` and the scrub do to a note, an output and a command line | §4.5 |

`slices.py` was also run with `skills.ts` and `rulebook.ts` moved back to 13.5, where
this document first had them: it reported exactly the two edges a reviewer found by
reading, `codex_mcp.ts` (13.3) importing both. With the scrub moved back to 13.5 it
fails its ordering assertion, because the first slice that sends free text is 13.3.

**The second review found that the import check skipped the file with the most forward
edges.** It looped over whole files only, so `runtime.ts` and `worktree.ts`, split by line
range, were never checked as importers, and an import whose target was a split file was
skipped as "mixed". The check now resolves every imported symbol to the line that defines
it, finds the lines that use it, and assigns both ends to the slice of their range. It
also follows `this.method(` calls inside a split file and `this.store.x(` calls into
store lines that OD8 keeps local. Run against the earlier assignment (`quota.ts` and
`#quota` in 13.6), it fails with exactly the reviewer's two uses, `runtime.ts:447`
`readQuota` and `:448` `#quota`. Run with `roles/route.ts` and `#route` left unported, it
fails because `submit` (`:205`) calls `#route` and nothing names what replaces it. The
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
| **(b)** port to the Rust `wapps` binary | **6,957** | 39 whole files, `runtime.ts` 1–807, `worktree.ts`, and 177 store lines OD8 keeps on this machine (`storage/jobs.ts` 147: the transcript and quota; `storage/attention.ts` 30: the quota list and its digest part). §7.1 assigns every one of those lines to a slice |
| **(a)** in the cloud; the daemon forwards | 232 + 264 | `mcp/schemas.ts`, `lifecycle/stages.ts`; `runtime.ts`'s `RuntimeControlBackend` (lines 808–1071) becomes a forwarding table |
| **(a), pending slice 12** | 98 | `roles/propose.ts` (`roles_propose`) |
| **(c)** becomes cloud state | 3,176 | `src/storage/*` except `evidence.ts`, `routing.ts` and OD8's 177 lines, + 379 lines of SQL |
| **(c), open in the cloud** | 84 | routing directives: `storage/routing.ts`. The routing itself (`roles/route.ts`, `runtime.ts#route`) is (b): the cloud does not choose a worker's provider and does not check review independence (§7.1) |
| **(d)** obsolete | 119 | `process/recovery.ts` 9, `storage/evidence.ts` 58, `security/launcher_handshake.ts` 52 |
| owner CLI: OD9 | 33 | `cli/commands.ts` (+ `scripts/work.ts` 693, `scripts/project.ts` 253, `bin/` 39; 13.8 and 13.10) |
| **sum** | **10,963** | equals `wc -l src/**/*.ts` |

The first two revisions had (b) at 4,217. The difference is 2,740 lines, all from decisions
and from the routing finding: the explorer (2,481, OD8), the local transcript and quota store
lines (177, OD8), and routing (82), which the cloud does not do.

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
| `src/process/runtime.ts` 1–807 | 807 | b | types and options, `submit`, `#route`, `#runRemote`, `resumeAbandoned`, release/terminalize/pause, roles/record/session/quota/note, subagent attach/report, `awaitChange`, `cancel`. Split into 13 line ranges over four slices (13.1, 13.3, 13.6, 13.9) in §7.1 |
| `src/process/runtime.ts` 808–1071 | 264 | a | `RuntimeControlBackend`: tool → store call |
| `src/process/codex_mcp.ts` | 374 | b | `codex mcp-server` over MCP stdio |
| `src/process/claude_agent_sdk.ts` | 243 | b | Claude Agent SDK → the `claude` CLI's stream-json control protocol |
| `src/process/provider_types.ts` | 150 | b | event model, message summary, `reportedModel` |
| `src/process/quota.ts` | 100 | b | reads rate-limit events of both providers; 13.3, because it decides which codex events are notes (§7.1) |
| `src/process/worktree.ts` | 77 | b | `git worktree add/remove`, `status --porcelain` |
| `src/process/scratch.ts` | 69 | b | per-job scratch, `info/exclude` |
| `src/process/liveness.ts` | 42 | b | `kill(pid,0)` + `ps -o lstart=` |
| `src/process/fake_provider.ts` | 38 | b | test provider |
| `src/process/native_attach.ts` | 36 | b | native (hand-back) lane attach |
| `src/process/cancel.ts` | 13 | b | bounded wait after abort |
| `src/process/recovery.ts` | 9 | d | wrapper over a store method |
| `src/storage/jobs.ts` | 1,026 | c, 147 b | 787–882 the local transcript and observed model (13.9), 883–933 quota (13.3, 13.6); the rest is the cloud's |
| `src/storage/work.ts` | 960 | c | (`missionHistory`/`jobDurations` are an open (c) item in the cloud) |
| `src/storage/db.ts` | 558 | c | the 72-method `BrokerStore` facade (README axis 1) |
| `src/storage/attention.ts` | 332 | c, 30 b | → cloud `attentionOf`; its quota list (224–246) and the quota part of its digest (322–328) are the daemon's (13.6, §3.3) |
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
| `src/roles/route.ts` | 63 | b | routing: an explicit provider, review independence, continuity, the sole declared side (13.3). Its directive step has no cloud home and gets no directive |
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
| `src/security/launcher_handshake.ts` | 52 | d | compares a launcher manifest's model/effort with `orchestrators.json`, two files on one disk. The cloud's principal is the Access identity, and the orchestrator's provider is declared by the install (§5, OD1) |
| `src/security/path_containment.ts` | 21 | b | |
| `src/security/redaction.ts` | 21 | b | key-name redaction of read answers |
| `src/security/argv.ts` | 10 | b | |
| `src/view/explorer.ts` | 1,998 | b (OD8) | the owner's terminal explorer; 13.10 `wapps broker explore`, over cloud reads and the local transcript |
| `src/view/{width,transcript,markdown}.ts` | 483 | b (OD8) | 13.10 |
| `src/lifecycle/stages.ts` | 99 | a | → `src/job.ts` |
| `src/cli/commands.ts` | 33 | OD9 | |
| `src/bootstrap.ts` | 192 | b | enrollment (`projects.json`), cwd → project, state home |
| `src/bootstrap_runtime.ts` | 95 | b | builds the runtime. Its attestation half is (d) with `launcher_handshake` |
| `src/main.ts` | 43 | b | stdio entry |

### 1.3 Everything outside `src/`

| path | size | bucket | becomes |
|---|---|---|---|
| `scripts/work.ts` | 693 | OD9 | 17 owner commands; README axis 5 splits them 11 (a) / 2 (b) / 4 (c). 7 of them are ported in 13.8, `watch` (the explorer's driver, 244 lines) in 13.10 |
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
| `handoff_packages` | `MissionDO` `handoff_package` | not reached: **0 rows in all 9 stores** (`od10.py`), and the daemon does not serve the two handoff tools (OD1) |
| `routing_directives` | **(c), open in the cloud** | no route. `agent-broker route` and `#route` have no home |
| `job_attempts`, `job_events` | none | (d) |
| `mission_participants` | none | (d): a handoff names an Access principal |
| `native_adapter_evidence` | none | (d) |
| `job_transcript` | none | **stays local** (OD8): one scrubbed JSONL file per job, written by the daemon (13.9) |
| `provider_quota` | none | **daemon memory** (OD8): the newest reading per provider and window (13.3), merged into `attention` (13.6) |

Routes are `crates/workers/src/broker_routes.rs:287-340` (37 `route!` rows) at
`57b8bbb`.

### 2.2 Local files that stay local (b)

| file | today | after |
|---|---|---|
| `~/.agent-broker/projects.json` | enrollment: project id → root | stays. Which directory is which project is a fact about this machine |
| `~/.agent-broker/projects/<id>/roles.json` + `prompts/` | the full role table | spawn spec only (**OD7**). `tools` comes from the cloud's ceiling |
| `~/.agent-broker/state/<id>/broker.daemon.json`, `broker.sock`, `daemon.log` | single-instance claim, socket, log | stays (13.2) |
| `~/.agent-broker/state/<id>/worktrees/<job>` | writing jobs' checkouts | stays (13.4) |
| `~/.agent-broker/state/<id>/transcripts/<job>.jsonl` | (new) | the job's header (dispatched model and effort, observed model, worktree, codex thread id, handed back or not) and one scrubbed line per event (13.9). The cloud has no column for any of these |
| owner-pause markers (state dir + project) | read by the codex prompt and the runtime, and by the claude hook | stays (13.3; the claude gate in 13.5) |
| `~/.agent-broker/state/<id>/broker.sqlite` | **all state** | no longer written after cut-over (13.12). Open items of four projects are replayed (OD10). Nothing deletes the files: they hold every old transcript (table below), and removing them is the owner's act |

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

That is **245 open work items in 5 projects**. OD10 migrates 226 of them (navlun, ecommerce,
kick-clip-analyzer, real-estate-analysis); wapps-platform's 19 are tracked in its docs.

What the transcript and the handoff tables hold (`od10.py`, read-only; `dbstat` for the
table's own pages, index included):

| store | `handoff_packages` | transcript rows | transcript payload | transcript table | whole file |
|---|---:|---:|---:|---:|---:|
| navlun | 0 | 527,526 | 614.2 MB | 769.0 MB | 781.0 MB |
| wapps-platform | 0 | 69,411 | 86.2 MB | 106.5 MB | 108.4 MB |
| ecommerce | 0 | 35,717 | 39.4 MB | 49.1 MB | 50.1 MB |
| kick-clip-analyzer | 0 | 12,228 | 16.9 MB | 20.5 MB | 21.2 MB |
| real-estate-analysis | 0 | 198 | 0.2 MB | 0.2 MB | 0.5 MB |
| the other four | 0 | 0 | 0 | 0 | 0.2 MB each |

The transcript is **98%** of navlun's store (769.0 of 781.0 MB). No orchestrator handoff
has ever been prepared in any store.

Every existing mission id (`ecommerce`,
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
| `orchestrator_prepare_handoff` | A, `targetProvider`, `targetSessionId`, `expiresAt` | (`POST …/handoff`) | **Not served** (OD1): with one token both orchestrators are one principal, and the cloud refuses `handoff_to_self` (§5) |
| `orchestrator_takeover` | `handoffPackageId` | (`POST …/handoff/takeover`) | **Not served** (OD1): it spends a package only `prepare_handoff` makes |
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
Only the daemon sees quota. OD8 keeps it: the daemon merges its own quota list into the
five answers (13.6), so it reads and rewrites those answers; it cannot be a verbatim
forward (§3.7). The list is the plugin's, not every reading: a provider's `rejected`, or a
reading at or above 90%, and only while its window has not reset (`attention.ts:224-246`).
**The digest has to carry it too.** The plugin's digest includes the newest quota
*status* per provider (`attention.ts:322-328`), so a status change wakes `agent_await`.
The cloud's digest has no quota, so the daemon folds its own statuses into the digest it
returns, or a waiting orchestrator sleeps through a provider being refused. Both are 13.6,
and both are seam-2 cases.

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
(`57b8bbb`; rerun 2026-10-05 in the scratch copy, same tally): **51 fields compared, 7
equal, 44 differ**. Three of the 44 belong to the two handoff tools the daemon no longer
serves (OD1): `orchestrator_prepare_handoff` `capability` (item 1) and `targetSessionId`
(item 6), and `orchestrator_takeover` `handoffPackageId` (item 2). **On the 24 tools the
daemon serves, 48 fields are compared and 41 differ** (13 + 16 + 4 + 7 + 1). The 7 that agree are
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

7. **Whole-body shapes.** (The two handoff tools' shapes no longer matter: not served.)
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
11. `attention.quota`: kept (OD8), but only from 13.6, and only the daemon's own readings (§3.3).
12. Error envelopes: the cloud's `{error, message, details, recovery}` against the
    SDK's JSON-RPC errors.
13. `orchestrator_claim` no longer resumes abandoned work inside the cloud call. The
    daemon does it around the call (13.6).
14. `agent_running` is a projection that includes `startedAt` from `job_attempts`,
    which the cloud does not have (§3.2).
15. `tools/list` has 24 tools, not 26: `orchestrator_prepare_handoff` and
    `orchestrator_takeover` are not served (OD1).

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

### 3.7 What the daemon does to each of the 26 tools (OD3 and OD1, decided)

OD3 first said the daemon forwards 19 tools verbatim and intercepts 7, and also that it
merges quota into 4 attention-carrying answers. Three of those 4 (`agent_status`,
`agent_running`, `orchestrator_status`) were in the "verbatim" 19, and a merge cannot be
verbatim. Going through `RuntimeControlBackend` (`runtime.ts:842-1071`) tool by tool
gives four classes. OD1 (one token, no handoff) adds a fifth: two tools are not served.
26 in all:

| class | tools | n | what the daemon does |
|---|---|---:|---|
| **act** | `orchestrator_claim`, `agent_submit`, `agent_cancel`, `agent_attach`, `agent_report`, `agent_await`, `roles_list` | 7 | `claim`: supplies `provider`, turns `already_claimed` into `{standby}`, resumes after (13.6). `submit`: routes, calls the Worker, spawns. `cancel`: calls the Worker, kills. `attach`, `report`: the native lane (OD12). `await`: the cursor loop (OD4). `roles_list`: merges the local spawn spec (OD7) |
| **rewrite the answer** | `agent_status`, `agent_running`, `orchestrator_status` | 3 | forwards, parses the answer, merges its quota list into `attention` (OD8). `agent_running` may also have to be built from `GET jobs`, `GET work` and per-job progress (§3.2) |
| **observe** | `orchestrator_release` | 1 | forwards unchanged and reads the answer: the daemon keeps the capability of each lease it proxied, so it can release a gone owner's lease itself (§3.4). Release drops one |
| **verbatim** | `orchestrator_heartbeat`, `roles_propose`, `work_add`, `work_adopt`, `work_list`, `work_close`, `work_move`, `work_ask`, `work_relay_answer`, `work_withdraw`, `work_delegate`, `agent_list`, `agent_result` | 13 | nothing |
| **not served** | `orchestrator_prepare_handoff`, `orchestrator_takeover` | 2 | removed from `tools/list` (OD1, §5) |

So the daemon touches **11** tools, forwards **13** and serves **24**. Five answers carry
`attention` (§3.3): `submit` and `await` from the act class, the three above from the
rewrite class.

What that does to "one schema definition (the Worker's)":

- **The rules of validity stay single.** Lengths, enums and patterns (§3.5) live in the
  Worker for all 26 tools. The daemon defines none of them.
- **The shapes do not.** For 8 of the 11 touched tools the daemon only reads named
  fields. For 3, `agent_submit`, `agent_attach` and `agent_report`, the input the
  orchestrator sends is not the input the Worker takes (`provider?` and `handBack`
  against `workerProvider`; the lease authority and `attachCapability` against the job
  authority, §3.5 item 7). The daemon publishes its own `inputSchema` for those: **28 of
  the 102 top-level input properties** (15 + 6 + 7, from `tools_list.ts`). That is a
  second definition, kept small. It grows if P12 keeps `provider` as an argument of
  `claim`, which the platform doc does not say.
- **`tools/list` is therefore not a pure forward**: the Worker's list with at least 3
  entries replaced and 2 removed. Removing uses the same pass that replaces.
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
| launchers | `security/launcher_handshake.ts`, `launchers/`, `generator/` | the provider comes from `AGENT_BROKER_LAUNCHER_PROVIDER`, set by `.mcp.json` / `.codex/config.toml` (`bootstrap.ts:133-139`); the "attestation" compares the manifest's model/effort with `orchestrators.json` | — | (d), decided (OD1, §5). The install writes the provider into each client's MCP entry, as today |

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

**Finding 4.3b: the daemon attaches before it spawns, because the attach answer is the
worker's task.** The cloud builds the brief at attach (`methods.rs` `brief_task`, called
from `attach_locked`): a review gets `REVIEW_VERDICT_INSTRUCTION` appended, a delegated
answer gets the question's brief, and the `Attached` answer carries it as `task`
(`payload.rs:1079-1094`). The plugin built the same text itself (`runtime.ts:418-422`,
`reviewVerdictInstruction`, `delegatedQuestionTask`); in the port it comes from the cloud,
so the worker cannot start before the attach. `ATTACH` requires `providerRunId`
(`body.rs:219-223`), once. Claude's session is named by the job id before spawn
(`runtime.ts:409`). Codex names its thread only in `session_configured`
(`codexSessionId`), after it starts. So the daemon attaches every job with the **job id**
as `providerRunId`, and keeps a codex thread id in the job's local header (13.9). Codex
conversations cannot be resumed anyway (`codex_mcp.ts`: *"codex keeps it inside the
process that opened it"*). The second revision of this document said a codex job attaches
after its first event; that cannot work, and the attach also starts the 5-minute clock
("THE CLOCK STARTS HERE", `attach_locked`), which then runs while the worker starts.

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
3. The Rust matcher does not have to be a transliteration, and "anywhere on a line" is
   too wide. Measured (`od15_probe.ts`): an unanchored, case-insensitive
   `ASSIGNMENT` matches **13 of the 452** title and intent texts OD10 replays, which are
   prose. The plugin's own patterns change **0 of 454** (with the open question's two).
   So the matcher anchors `ASSIGNMENT` at the start of a line **or of the command in a
   `Bash: ` note**, which closes the measured hole without reading prose as secrets. That
   is a deliberate divergence and the differential declares it (OD15, decided).
4. Not covered by this scrub: text the **orchestrator** authored (work items, questions,
   the dispatch `task`). It is forwarded as written, as it always was. It now leaves the
   machine, by the owner's own decisions: the cloud holds the work list (slice 13), and
   OD10 replays 226 items' titles and intents to it. On those, the plugin's scrub would
   change nothing (0 of 454).

---

## 5. Auth to the cloud broker

**How the daemon authenticates.** The same way memory's agents do: a Cloudflare Access
**service token**, sent as `CF-Access-Client-Id` / `CF-Access-Client-Secret` on every
request. The gate turns it into the principal `svc:<client id>`. Memory's
`provision` mints `<worker>-agents` and its `non_identity` policy
(`services/memory/README.md:68-74`). The broker's provision is **committed** at
`wapps-platform` `cac8ede` (`crates/ops/src/provision/broker.rs`) and was run with
`--plan` only (nothing deployed). It mints one token, `wapps-broker-agents`, writes its
secret by default to `~/.config/wapps-broker/agents.secret` (`provision.rs:1002-1008`;
file mode 0600, directory 0700, `provision/sink.rs:74-114`), and prints *"svc:{client_id}
holds no roster verbs yet: an admin grants them with POST /v1/roster"*
(`broker.rs:102-103`). **One token is the owner's decision (OD1, 2026-10-05).**

**Verbs the daemon's principal needs** (`broker_routes.rs:287-340`): `read`, `claim`
(lease, work, dispatch, cancel, the orchestrator's question routes) and `report`
(attach, progress, finish). **`relay` is a `claim` route** (`broker_routes.rs:331`), so
the daemon relays an answer the owner gave in conversation; `answer`, `accept` and
`confirm` are `answer` routes (`:333-335`), and the daemon's principal must **not** hold
`answer`. The roster cannot even store it: `claim` and `answer` are an exclusive pair
(`roster_lane/methods.rs:45`, `EXCLUSIVE_VERBS`). It must not hold `administer` either.
This is also the daemon's answer to the platform doc's open provision question ("should
provision grant the agents' token a fixed verb set, and which?"): `read claim report`.

**The relay flow is preserved, and the cloud enforces what the plugin could not.**
`work_relay_answer` writes the answer with `answered_by = "relay"` and the relaying
principal (`relay_locked`, `methods.rs:949-967`); the question is answered, so the item
unblocks. The owner confirms later with `wapps broker confirm` under the owner's SSO
principal. `confirm_relay` (`methods.rs:1106-1148`) refuses `not_relayed`,
`already_confirmed`, and `confirm_own_relay` when the confirming principal is the one
that relayed, which the plugin's comment says it wrote and could not apply, because both
sides were session ids. The owner is in `ADMIN_PRINCIPALS`, which sits above the roster
(`roster_lane/methods.rs:42-43`), so the owner's principal reaches the `answer` routes.

**Finding 5.1: with one token, the orchestrator handoff cannot succeed, and it has never
been used.** `prepare_locked` refuses `handoff_to_self` when `target_principal ==
prepared_by` (`crates/workers/src/mission_lane/methods.rs:1450`). Both orchestrators on a
machine authenticate with the one `-agents` token, so they are **one principal**, and every
`prepare_handoff` gets `handoff_to_self`. `takeover` spends a package only `prepare` makes,
so it cannot succeed either. Measured: `handoff_packages` has **0 rows in all 9 stores**
(`od10.py`), over 1,050 jobs; the plugin's handoff was never used.

**Decision (OD1): the daemon does not serve `orchestrator_prepare_handoff` and
`orchestrator_takeover`.** The alternative, serving them and letting the cloud refuse, puts
two tools in every orchestrator's list that fail on every call, and keeps a SKILL.md
section for a path that cannot work. Removing them costs one filter in the `tools/list`
pass that already replaces three entries (§3.7). Either orchestrator still takes over a
mission the ordinary way: the lease expires or is released, and the next `claim` gets it.

**What happens to the launcher handshake.** It is (d). Its "attestation" checked the
launcher manifest's model and effort against `orchestrators.json` (`bootstrap_runtime.ts:34-54`),
two files on the same disk, not the running orchestrator. The cloud's principal is the
Access token, which does not say which provider holds it. The orchestrator's provider
stays what it is today, a declared fact: `.mcp.json` and `.codex/config.toml` set
`AGENT_BROKER_LAUNCHER_PROVIDER` (`bootstrap.ts:133-139`), and 13.7 writes the provider
into each client's MCP entry the same way. The daemon uses it for `claim`'s `provider`
and for the native lane (only the caller's own provider is handed back). `launchers/`,
`orchestrators.json` and the launcher half of `generator/` go with it.

**Where the secret lives.** Provision writes the secret once to
`--token-sink file:<path>|wapps:<KEY>`, by default the 0600 file above. The `wapps:<KEY>`
sink goes to the wapps secrets gate through `wapps secrets set --from-file` (memory
README `:71-73`). The
daemon runs under Claude Code or Codex, so `CLAUDECODE` is set or stdin is not a TTY,
which makes it **always agent mode** (`rust/crates/cli/src/agentmode.rs:11-45`). In
agent mode `secrets get` is refused. Reading from the gate also needs the owner's
`wapps login` SSO session to still be valid, while daemons live for days. → **OD2,
decided B**: the daemon reads a 0600 runtime file, which on the provisioning machine is
provision's default sink, and which `wapps broker enroll` (a human at a TTY) writes on any
other. The client id is not secret; provision prints it and enroll records it.
Whatever is chosen, Finding 4.2 adds a rule: the secret is read from storage into
memory, never placed in an environment variable, and never passed to a child.

---

## 6. The oracle

wapps-cli's method is a differential against a running oracle on a seam both sides
share (Go ↔ Rust in a pty, `tests/differential.rs`, `tests/pty/*.py` 7,107 lines, fake
gate `fakegate.py`). The plugin cannot be compared that way end to end: its state is
local SQLite and the daemon's is the cloud, and §3.5 lists the deliberate
differences (15 items; on the 24 served tools, 41 of 48 comparable fields). So the differential is held at **three seams**, and only the first is a byte-level
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
model observed, terminal state, cancel). **Each slice compares only what it has ported,
and every stub names the cases it excludes** (`slices.py`, §7.1). For codex that is the
prompt bytes, and so `roles/skills.ts`, `roles/rulebook.ts`, `process/scratch.ts` and
`policy/owner_pause.ts` land in 13.3, with the worker that calls them
(`codex_mcp.ts:6-9,158-170`). **Quota is compared in two steps.** From 13.3, which events
become notes: a codex `token_count` carrying `rate_limits.primary` is a reading, and
`runtime.ts:459` keeps it out of the notes and the transcript, so without `readQuota` the
daemon would post a `token_count message` note (`provider_types.ts:131`) for every counter
event the oracle drops. From 13.6, the readings themselves, once they appear in
`attention`. The observed model is compared from 13.9, where it is stored. Under OD5-A the claude half compares
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
its reason written down. Mechanical floor: 24 served tools × {accepted, refused by
schema} + `initialize`/`tools/list`/`ping` = **51 cases** before any tool's own branches.
`tools/list` lacking the two handoff tools is the 15th declared divergence.

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

| row (the draft's slice) | plugin files | tests | the slice that owns the code now (§7.1) |
|---|---:|---:|---|
| surface | 8 | 26 | 13.1 |
| daemon | 6 | 26 | 13.2 |
| codex worker and execution core | 16 | 89 | 13.3, which now also holds prompt delivery, the pause classifier, the scrub, routing and the quota reading |
| writing roles | 5 | 20 | 13.4 (worktrees only; scratch moved to 13.3) |
| claude worker, its gate, pause | 14 | 61 | 13.5 for the claude worker and its gate; the pause modules (`owner_pause`, `shell`) moved to 13.3 |
| resume, native lane, quota | 12 | 40 | 13.6 (the quota merge); the quota reading moved to 13.3 |
| install + hook | 2 | 9 | 13.7 |
| owner CLI | 2 | 17 | 13.8 |
| cloud semantics (the cloud's own oracle covers them) | 37 | 137 | none |
| view (`explorer`, `markdown`, `width`) | 3 | 117 | **13.10** (OD8: the explorer is ported) |
| `hardening.test.ts` (mixed, not split) + `differential-quality` | 2 | 31 | mixed |
| **sum** | **107** | **573** (static) | |

The rows are the files as the first draft grouped them, by imports and file name; the
last column says which slice owns that code after §7.1. A row's files therefore gate more
than one slice where the column names two. **19 test files (139 tests)** import one of `roles/skills`,
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
| **P-b** | the roster grants `read claim report` to `svc:<wapps-broker-agents>`, never `answer` or `administer` (an admin's `POST /v1/roster`, or provision's last step). The per-provider token the earlier revisions asked for is dropped (OD1) | every slice from 13.1 on: the token holds no verbs until granted (`broker.rs:102-103`) |
| **live** | `broker.meapps.dev` provisioned with `ACCESS_AUD` set (owner decision §9.1 of the platform doc; provision committed at `cac8ede`, run with `--plan` only) | every slice from 13.1 on talks to it |
| **P-e** | **OD16 = B, DECIDED 2026-10-05**: a leaseless owner door for filing and moving work, under the `answer` verb | the owner's `file` / `move` and the explorer's move key (OD16) |

P-c (spawn-spec columns in the cloud) is gone: OD7 is decided A, the spawn spec stays local.

### wapps-cli side

| # | slice | TS lines (§7.1) | depends on | behaviour inventory | cases |
|---|---|---:|---|---|---|
| **R0** | **The Rust binary ships. Being handled:** owner decision 2026-10-05, the Rust `wapps` replaces the Go binary in the Homebrew release when the CLI port is done. That release slice is running on `wapps-cli` `lane/cli-s10` (worktree `.worktrees/cli-s10`, no commit of its own yet; the branch is at `c8c7daf`). What it has to change was measured here: `.goreleaser.yml`'s `builds:` has one entry, `main: ./main.go`, and `.github/workflows/{ci,release}.yml` mention `cargo` **0** times. The version rule already exists (`before` hook `sh rust/check-version.sh {{ .Version }}`, `PORT-kalan-yuzey.md` §4.3). `goreleaser check` failing on the deprecated `brews` is a separate open owner decision (`64549cb`) | — | `lane/cli-s10` | — | the existing differential |
| **13.0** | oracle harness: fake `claude`/`codex` recorders, fake cloud from recorded fixtures, MCP transcript runner, hermetic skill roots (Finding 0.1). Section 6 says it exists before any slice, so every slice below depends on it | 0 | — | Finding 0.1 | harness only |
| **13.1** | `wapps broker serve`: stdio MCP, enrollment (cwd → project), the Access service token (OD2: a 0600 file), `tools/list` (the Worker's list with 3 entries replaced and the 2 handoff tools removed: 24 tools) and the 13 verbatim tools forwarded to the Worker MCP, the observe and rewrite classes without the quota merge, `orchestrator_claim` without resume, the `agent_await` cursor loop (OD4), read redaction (§3.7). `agent_submit`, `agent_cancel`, `agent_attach`, `agent_report` answer `ACTION_UNAVAILABLE`; `roles_list` is the Worker's answer | 501 | **13.0**, P12, P-b, live | 8 files / 26 tests | ≥ 51 (seam 2) |
| **13.2** | the daemon: `wapps broker daemon`, unix socket, `O_EXCL` claim, detached spawn, idle exit, session tracking (gone-owner release) | 745 | 13.1 | 6 / 26 | not measured; inventory 26 |
| **13.3** | execution core + **codex** worker: `agent_submit` → routing (an explicit provider, review independence, continuity, the sole declared side; never a directive) → `POST …/jobs` → `POST …/jobs/attach` with the job id as run id, whose answer is the worker's task (Finding 4.3b) → spawn → progress heartbeat < 5 min → finish; `agent_cancel`; role spawn spec (OD7); **prompt delivery** (skills, repository rulebook, scratch, pause sections), which the codex seam compares byte for byte; **the scrub on every note, output and error that leaves the machine** (§4.5, OD15); the owner-pause classifier that stops a codex job; **the quota reading** into daemon memory, because it decides which codex events are notes (§7.1). Read-only roles only. Five declared stubs: writing roles refused (13.4), `handBack` refused (13.6), the transcript and the observed model not recorded (13.9) | 2,416 | 13.2 | 16 / 89, plus the 19 files of §6 | not measured; seam 1 codex + seam 3 |
| **13.4** | writing roles: `git worktree add/remove` per job, with the refusal to remove a dirty tree; the worktree goes into the attach body. Scratch, the pause gate and the scrub are already in 13.3 | 41 | 13.3 | 5 / 20 | not measured |
| **13.5** | **claude** worker: OD5's choice, the PreToolUse gate (ceiling, containment, pause), env allowlist (Finding 4.2). Skills, rulebook and the scrub arrive with 13.3 and are reused | 377 | 13.4, OD5's first measurement, OD6 | 14 / 61 | not measured; seam 1 claude |
| **13.6** | the quota list merged into the five attention answers and folded into the digest (§3.3), resume at claim, native hand-back lane (OD12), delegated answers | 231 | 13.5, P-a | 12 / 40 | not measured |
| **13.7** | `wapps broker install`: Claude Code user MCP config + PreToolUse hook (`wapps broker hook`), Codex `config.toml` `[mcp_servers]`, each entry declaring its orchestrator's provider (OD1); the rewritten `agent-broker` skill, without its handoff section, shipped through `wapps skill` | 56 (+ 513 lines of SKILL.md prose to rewrite) | 13.5, R0, OD13, OD14 | 2 / 9 | not measured |
| **13.8** | owner CLI (OD9), with the owner's SSO principal: `wapps broker list questions running accept answer confirm relayed` and `wapps broker project enroll pause unpause role apply`. `relayed` lists the answers waiting for `confirm`, which the owner's confirm flow needs (§5). Not ported: `watch` (13.10), `show` and `done` (reads the explorer covers), `await` and `await-job` (an orchestrator's wait, which `agent_await` serves), `history` (open (c) in the cloud), `delegate` (a `claim` route, the orchestrator's), `route` (directives, open in the cloud), `file` and `move` arrive with P-e (OD16 = B) and join 13.8 then | up to 617: `work.ts` prelude 211 + the seven commands' bodies 81 (`slices.py --owner`), `project.ts` 253, `bin/` 39, `cli/commands.ts` 33 | 13.1 | 2 / 17 | not measured |
| **13.9** | **the local transcript store** (OD8): the daemon appends one scrubbed line per provider event (`scrubForTranscript`: the 5 patterns and the 8,192 truncation, which is right for a transcript row) to `<state>/<id>/transcripts/<job>.jsonl`, after a header line with what the cloud has no column for: the dispatched model and effort, the observed model, the worktree, the codex thread id, handed back or not. Reads: the page after a sequence number, and the newest N with the count left out (`jobTranscript`, `latestJobTranscript`). One file per job, no SQLite: every read is one job's, and no crate is added. No retention, as today: navlun's reached 614 MB of payload in 527,526 rows (§2.3) | 109 | 13.3 | `transcript.test.ts` / 19 | not measured; seam 1: the oracle's `job_transcript` rows against the lines, per scripted event |
| **13.10** | **`wapps broker explore`** (OD8): the mission's work items, each item's jobs, and what each did. From the cloud: `GET …/work` (items, progress), `GET …/jobs`, `GET …/attention`, `GET …/work/questions` (unconfirmed relays filtered here). Locally: each job's transcript and header (13.9). Writes with the owner's SSO principal: `answer`, `confirm`. Three declared changes: (1) the open job's report comes from the local transcript's result line, not from `GET …/jobs/:job/result`, which marks the result read (`methods.rs:2616-2623`) and would discharge the orchestrator's `settledUnread`; the plugin read it without marking (`work.ts:344-349`); (2) a job with no local transcript (another machine's daemon, a native job) shows its cloud row and progress only; (3) no quota line (daemon memory, OD8) and the move key arrives with P-e (OD16 = B) | 2,725: `src/view/*` 2,481 + `work.ts` `watch` 244 | 13.8, 13.9 | 3 / 117 | not measured |
| **13.11** | **replay of open work** (OD10): see below | 0 | 13.1, P-b, live | — | 4 missions' counts, 26 parent links, 1 question |
| **13.12** | cut-over and retirement: per project, the plugin's MCP entries are removed, 13.11 runs for the four projects, and the daemon's entries are installed (13.7); then the plugin repository is archived. The old stores stay on disk (§2.2) | 0 | everything above | — | — |

13.3 (2,416 of 6,957, 35%) and 13.10 (2,481 + 244) are the two largest slices. 13.3 is
large because a codex worker cannot pass its own seam without its prompt delivery, its
pause classifier, the scrub, routing and the quota reading (§7.1). 13.10 is mostly screen
code, pure functions over a model (`explorer.ts:10-13`), and needs nothing after 13.9, so it
can run beside 13.4–13.7.

**13.11, priced.** A one-shot script that reads the four stores read-only and drives
`wapps broker serve` over MCP in each project, so it adds no product code and exercises
the same forwarding as an orchestrator: `orchestrator_claim`, `work_add` once per parent
depth, `work_ask`, `work_list` to verify, `orchestrator_release`. What it meets, measured
(`od10.py`):

| project → mission | open items | depth 0 / 1 | `work_add` calls | titles over 500 | open questions |
|---|---:|---|---:|---:|---:|
| navlun → `navlun` | 203 | 191 / 12 | 2 | 57 (max 1,528) | 1 |
| real-estate-analysis → `l0-walking-skeleton` | 15 | 1 / 14 | 2 | 0 | 0 |
| ecommerce → `ecommerce` | 4 | 4 / 0 | 1 | 0 | 0 |
| kick-clip-analyzer → `irl-relay` | 4 | 4 / 0 | 1 | 0 | 0 |
| **sum** | **226** | 200 / 26 | **6** | 57 | 1 |

- **One batch per depth.** The cloud mints item ids, and a part cannot name a parent filed
  in the same batch (`add_locked`, `methods.rs:1703-1724`), so the script maps old ids to
  new ones level by level, siblings in their old `position` order. No open item sits under
  a closed parent (`parent_closed`), and no part carries a horizon (`child_horizon`): 0
  and 0.
- **57 navlun titles exceed the cloud's 500** (`body.rs:176`), up to 1,528. All 57 have
  title = intent, the shape `agent-broker work file` writes (`work.ts:664-675`, no length
  check). The script cuts the title to 500 characters; the intent keeps the whole text,
  so nothing is lost. All 57 are in the Basic Multilingual Plane, so a character count
  and the cloud's UTF-16 count agree. Intents reach 4,541 (ceiling 100,000); no text is
  blank or padded.
- **navlun's open question fits** `work_ask`: a 2,055-character question and a
  280-character proposal (ceiling 4,000 each), not relayed, not delegated, on an open item.
  The script asks it on the item's new id after that item is filed. The cloud stamps the
  replay time as when it was raised.
- **Not carried** (the owner's field list is title, intent, parent, horizon): 64 navlun
  `discovered_from` links (7 of them point at items that migrate), 2 adoption links
  (`source_job_id`), and every item's `created_at`.
- **Calls:** 4 claims, 6 `work_add`, 1 `work_ask`, 4 `work_list`, 4 releases = **19**.
  **Cases:** per mission, the open count equals the store's; each of the 26 parts sits
  under its parent's new id; navlun has one open question. **Size:** one script of about
  150 lines (judgment, not measured). It runs inside 13.12, after the plugin stops writing
  to that project, and is deleted with the retirement.

### 7.1 Which plugin lines each slice replaces

The slice figures this document first had (458, 797, 1,794, 167, 809, 136, 56) were
not published with a file list, and "the sum equals bucket (b)" held by construction. The
second revision published the table and `slices.py`, and the second review found that
its import check never looked at the split files as importers (§0). The table below is
the third assignment. `slices.py` computes it. It assigns every ported line of 43 files
(39 whole, and `runtime.ts`, `worktree.ts`, `storage/jobs.ts` and `storage/attention.ts`
by line range) to exactly one slice, and the 14 other `src` files are named as not
ported, so all 57 are accounted for. The rules:

- **A file belongs to the first slice whose worker, seam or daemon uses it**, and a range
  of a file to the first slice that calls a method in it. A method is counted whole in
  that slice.
- **Three uses force the earliest slice:** what the prompt bytes of a seam-1 comparison
  contain; what a slice sends off the machine (§4.5); and **what decides which events
  become notes**. The second revision called quota "purely additive to an event loop".
  It is not: `runtime.ts:459` sets `noisy` from `readQuota`, and a noisy codex
  `token_count` becomes neither a note nor a transcript row. So `quota.ts`, `#quota` and
  the store write it calls are 13.3 (the reading kept in daemon memory, OD8). Only the
  merge of readings into `attention` and the digest is additive, and that is 13.6.
- **A use of a later slice's code is allowed only as a declared stub**, and the stub names
  the seam cases it excludes. There are five, all from 13.3:

| use (in 13.3) | owned by | what 13.3 does instead | seam cases excluded until then |
|---|---|---|---|
| `submit` → `resolveAdapter` (`runtime.ts:217`) | 13.6 | answers `broker_managed`, refuses `handBack` | seam 2 `agent_submit` with `handBack: true`. Without `handBack` a fresh oracle store has no native evidence, so the oracle also answers `broker_managed`; the evidence path itself is (d) |
| `submit` → `createWorktree` (`:327`) | 13.4 | refuses a role that holds write, before reserving | every dispatch of a writing role (seams 1–3), the `working in` / `carrying on in` notes, a resume into an inherited tree |
| `#release` → `removeWorktreeIfClean` (`:561`) | 13.4 | unreachable: no job has a worktree | the `left <branch> checked out` note |
| `#runRemote` → `#record` (`:460`) | 13.9 | nothing | transcript rows, which no seam compares before 13.9 |
| `#runRemote` → `recordObservedModel` (`:456`) | 13.9 | nothing (the cloud has no column for it) | seam 1's "model observed" reaction |

- **A use of code that is never ported names what replaces it.** 96 uses into 7 targets,
  all named: the cloud's routes for `storage/db.ts`, `work.ts`, `attention.ts` and the
  rest of `jobs.ts` (the attach answer's `task` carries `reviewVerdictInstruction` and the
  delegated brief, Finding 4.3b); the Worker's `tools/list` for `mcp/schemas.ts`; the
  forwarding of §3.7 for `RuntimeControlBackend`; the Access principal and the declared
  provider for `launcher_handshake.ts`.
- **Routing is ported, not left open.** The earlier revisions counted `roles/route.ts` and
  `#route` as (c)-open with routing directives. But `submit` calls `#route` (`:205`), the
  cloud's dispatch takes `workerProvider` as given, and its review bind checks the
  subject's state and whether a review is already running, not the provider
  (`review_bind_refusal`, `methods.rs:2255-2294`, read, not run). Review independence is
  decided only in `route.ts:38-54`. So both are 13.3. Their inputs come from the cloud:
  `subject` is the reviewed job's `workerProvider` (`GET …/jobs/:job`), `continuity` the
  provider of the last completed job on the item (`GET …/jobs`). Only the directive
  (`store.activeRoutingDirective`, `storage/routing.ts`) has no home; the daemon passes no
  `prefer`, and every seam case with an active directive is excluded.
- **OD8 decides `#record`.** The transcript is ported, as 13.9, so `#record` (639–651) is
  13.9's and 13.3 calls a no-op. The scrub it uses, `scrubForTranscript`, is in 13.3 with
  the rest of `transcript_scrub.ts`.

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
|  | `process/runtime.ts` 161–370 | 210 | class head, constructor, `submit` (stubs above) |
|  | `process/provider_types.ts` | 150 | imported by every adapter |
|  | `process/runtime.ts` 1–131 | 131 | types, `SubmitRequest`, `RuntimeOptions` |
|  | `process/runtime.ts` 390–503 | 114 | `#runRemote` |
|  | `roles/registry.ts` | 103 | the role table loader (spawn spec, OD7) |
|  | `roles/skills.ts` | 100 | **`codex_mcp.ts:7,158`** |
|  | `process/quota.ts` | 100 | **`runtime.ts:447,459`**: `readQuota` decides which codex events are notes |
|  | `bootstrap_runtime.ts` | 95 | wires the runtime and its adapters (wiring edges, below) |
|  | `policy/owner_pause.ts` | 91 | `codex_mcp.ts:6,170`; codex has no per-command gate |
|  | `process/runtime.ts` 555–638 | 84 | `#release` (scratch removal, every job), `#worktreeRoot`, `#terminalize`, `#pausedClassStarting`, `roles`, `#skillRoots` |
|  | `roles/rulebook.ts` | 75 | **`codex_mcp.ts:8,162`** |
|  | `process/scratch.ts` | 69 | `runtime.ts:402`: every job gets a scratch, read-only ones too; `codex_mcp.ts:9` |
|  | `roles/route.ts` | 63 | **`runtime.ts:382`**: `#route` names the worker's provider |
|  | `security/transcript_scrub.ts` | 63 | every outbound free text (§4.5); the first sender is in 13.3 |
|  | `process/runtime.ts` 762–803 | 42 | `waitForJob` and `activeWorkerCount` (test hooks, called from tests only), `cancel` |
|  | `process/fake_provider.ts` | 38 | implements `ProviderAdapter`; replaced by 13.0's recorders |
|  | `process/worktree.ts` 1–36 | 36 | `gitCommonDir`, which `scratch.ts:3` imports; `isGitRepository` (`runtime.ts:233`) |
|  | `roles/resolve_role.ts` | 35 | `provider_types.ts` and `route.ts` import it |
|  | `process/runtime.ts` 652–679 | 28 | `#session`, `#quota` (**`runtime.ts:448`**), `#note` |
|  | `roles/provider_tools.ts` | 27 | `registry.ts` imports it |
|  | `storage/jobs.ts` 883–906 | 24 | `StoredQuota`, `recordQuota`: what `#quota` writes, kept in daemon memory (OD8) |
|  | `policy/capability.ts` | 23 | `provider_types.ts` imports it |
|  | `security/path_containment.ts` | 21 | `codex_mcp.ts:10`, `provider_types.ts` |
|  | `process/runtime.ts` 371–389 | 19 | **`#route`**, called by `submit` (`runtime.ts:205`) |
|  | `process/cancel.ts` | 13 | bounded wait after abort |
|  | `security/argv.ts` | 10 | `codex_mcp.ts:5`, `worktree.ts:3` |
| | *13.3 total* | ***2,416*** | |
| **13.4** | `process/worktree.ts` 37–77 | 41 | `createWorktree`, `removeWorktreeIfClean` |
| | *13.4 total* | ***41*** | |
| **13.5** | `process/claude_agent_sdk.ts` | 243 | the claude worker |
|  | `policy/claude_hook_root.ts` | 134 | the claude gate's path and command classes |
| | *13.5 total* | ***377*** | |
| **13.6** | `process/runtime.ts` 680–734 | 55 | `attachSubagent`, `reportSubagent` |
|  | `process/runtime.ts` 504–554 | 51 | `resumeAbandoned` |
|  | `process/native_attach.ts` | 36 | the native (hand-back) lane |
|  | `roles/resolve_adapter.ts` | 32 | native vs broker-managed |
|  | `storage/jobs.ts` 907–933 | 27 | `latestQuota`, read by the merge |
|  | `storage/attention.ts` 224–246 | 23 | which readings are worth saying (≥ 90% or `rejected`, window not reset) |
|  | `storage/attention.ts` 322–328 | 7 | the quota status in the digest, so `agent_await` wakes on it |
| | *13.6 total* | ***231*** | |
| **13.7** | `policy/claude_hook.ts` | 56 | the parent session's PreToolUse hook |
| | *13.7 total* | ***56*** | |
| **13.9** | `storage/jobs.ts` 787–882 | 96 | `recordTranscript`, `recordObservedModel`, `jobTranscript`, `latestJobTranscript` |
|  | `process/runtime.ts` 639–651 | 13 | `#record` |
| | *13.9 total* | ***109*** | |
| **13.10** | `view/explorer.ts` | 1,998 | the explorer: state, keys and screen as pure functions |
|  | `view/width.ts` | 172 | display width, clipping, wrapping |
|  | `view/transcript.ts` | 156 | `renderTranscript`: one transcript row as one line |
|  | `view/markdown.ts` | 155 | the report pane's markdown |
| | *13.10 total* | ***2,481*** | (+ `work.ts` `watch` 244, outside `src`) |
| | **13.1–13.10 total** | **6,957** | equals bucket (b); see the note below |

13.8 has no `src` lines beyond `cli/commands.ts` (33, counted with OD9 in §1.1); its size
is the owner scripts (13.8's row). 13.11 and 13.12 replace no plugin lines.

Checks `slices.py` runs, and what it printed:

- **Partition.** Every line of the four split files falls in one range. Not ported:
  `runtime.ts` 808–1,071 (`RuntimeControlBackend`, 264, bucket a); `storage/jobs.ts`
  1–786 and 934–1,026, `storage/attention.ts` 1–223, 247–321 and 329–332 (1,181, bucket c).
- **Coverage.** 57 `src` files: 43 with ported lines, 14 wholly not ported (`storage/*`
  except the two split files, `lifecycle/stages.ts`, `mcp/schemas.ts`, `roles/propose.ts`,
  `process/recovery.ts`, `security/launcher_handshake.ts`, `cli/commands.ts`; 2,561
  lines), 0 unaccounted. All 10,963 lines.
- **Dependencies, at symbol level, from every importer.** 360 uses between ported code,
  from 27 files, split files included. **0** point at a later slice undeclared. 3 declared
  wiring edges (`main.ts` → `bootstrap_runtime.ts`, `daemon.ts` → `bootstrap_runtime.ts`,
  `bootstrap_runtime.ts` → `claude_agent_sdk.ts`: a file that constructs the runtime names
  every adapter, and the Rust side grows one registration per slice) and the 5 stubs
  above, each of which matched a real use. 96 uses of unported code, 0 without a named
  replacement.
- **Scrub ordering.** The senders of free text (`#note`, `#terminalize` in 13.3;
  `reportSubagent` in 13.6) are not earlier than the scrub (13.3). The local transcript
  (`#record`) is 13.9.

**Sum of 13.1–13.10 = 6,957 = bucket (b).** This is a partition check, not a
measurement: it says no line was dropped or counted twice. It does not say the
assignment is right. That is what the "why" column, the dependency check and the stubs
are for. `RuntimeControlBackend` (264 lines) is replaced by the forwarding of §3.7, not
ported. The rest of storage (3,176 + 379 SQL) is the cloud's.

**Smallest end-to-end first.** 13.1 is useful on its own: an orchestrator can claim,
keep a work list and ask against the live broker, with no worker. 13.3 adds one provider
end to end. Codex goes first even though claude ran **1,002 of 1,050** jobs. Codex's seam
is a published protocol (MCP), while claude's needs OD5's first measurement and, under
OD5-B, a private one.

---

## 8. Owner decisions

The owner decided OD1–OD15 on **2026-10-05**: OD1, OD8, OD9 and OD10 in their own words,
and the rest by accepting this document's recommendation. The release question (R0) was
decided the same day. OD16 came out of measuring OD9 and OD10; the owner decided it the same day: **B**, a leaseless owner door in the cloud for filing and moving work, under the `answer` verb, which agents never hold.

| # | decision | status | what was decided, and what it does to the plan |
|---|---|---|---|
| **OD1** | Access service tokens per machine | **DECIDED 2026-10-05** | **One token**, `wapps-broker-agents`, the one provision mints. Both orchestrators are one principal, so the cloud refuses every handoff (`handoff_to_self`), and none was ever made: `handoff_packages` is 0 in all 9 stores. **The daemon does not serve `orchestrator_prepare_handoff` and `orchestrator_takeover`** (24 tools, §3.7, §5): kept and refused, they would be two tools that fail on every call. The launcher handshake is (d); the orchestrator's provider is declared by the install, as it is today. P-b keeps only the roster grant `read claim report` |
| **OD2** | Where the daemon's token secret lives at run time | **DECIDED 2026-10-05** (recommendation) | **B**: a 0600 runtime file, provision's default sink on the provisioning machine (`~/.config/wapps-broker/agents.secret`), written by a human `wapps broker enroll` elsewhere. The gate stays the place to rotate from. Never in env (Finding 4.2) |
| **OD3** | Forward to the Worker's MCP endpoint, or call the HTTP routes | **DECIDED 2026-10-05** (recommendation) | **A**: forward `tools/list` and the Worker's answers; act on 7, rewrite 3, observe 1, pass 13 verbatim, serve 24 (after OD1). The rules of validity stay the Worker's; the daemon holds a second `inputSchema` for 3 tools. P12 is a hard prerequisite of 13.1 and must settle where `attention` is appended and who builds `agent_running` |
| **OD4** | `agent_await` | **DECIDED 2026-10-05** (recommendation) | **A**: poll `GET …/attention?since=` every 2 s up to 55 s (≤ 28 requests per call). Request cost not measured (§10) |
| **OD5** | How the daemon drives a claude worker | **DECIDED 2026-10-05** (recommendation, conditional) | **A** (public flags + a command PreToolUse hook) **if 13.5's first measurement shows `--agents` carries `effort` and `skills`; otherwise B** (the SDK's control protocol) |
| **OD6** | Which `claude` binary | **DECIDED 2026-10-05** (recommendation) | **A**: `claude` on `PATH`, with a version floor checked at daemon start |
| **OD7** | Where the role spawn spec lives | **DECIDED 2026-10-05** (recommendation) | **A**: local per project, without `tools`; the ceiling comes from the cloud. `od7.py`: the `tools` set agrees across the 10 enrolled projects for all 23 keys, while model/effort differ for 3 keys, skills for 1, and 11 of 23 prompt files have more than one content. Dispatch fails closed when a role has no cloud ceiling. P-c is not needed |
| **OD8** | Transcript, explorer, quota | **DECIDED 2026-10-05** | **Port the explorer** as `wapps broker explore` (13.10): work items and jobs read from the cloud, each job's transcript kept **local**, scrubbed before it is stored (13.9), because transcripts are large (98% of navlun's 781 MB store). **Quota stays in daemon memory** (13.3 reads it, 13.6 merges it). `#record` is ported, in 13.9; 13.3 calls a no-op. The explorer reads a job's report from the local transcript, because the cloud's result route marks it read |
| **OD9** | The owner's terminal | **DECIDED 2026-10-05** | **The human subset only**, as `wapps broker …` with the owner's SSO principal (13.8): `list questions running accept answer confirm relayed` + `project enroll pause unpause role apply`. The flow stays as it is: an agent records an answer the owner gave in conversation with `work_relay_answer` (stored as relayed, a `claim` route, the item unblocks), and the owner confirms it later with `wapps broker confirm` (an `answer` route; the cloud refuses a confirm by the principal that relayed). The daemon's principal holds relay and never `answer`, `accept` or `confirm`; the roster could not store `claim` with `answer` anyway. `relayed` is in the subset because confirming needs the list. `file` and `move` are not: see OD16 |
| **OD10** | Open work at cut-over | **DECIDED 2026-10-05** | **Replay** the open items of navlun (203), ecommerce (4), kick-clip-analyzer (4) and real-estate-analysis (15) through `work_add` (title, intent, parent, horizon), plus navlun's 1 open question through `work_ask`. **Not wapps-platform** (its 19 items are tracked in its docs). Priced in 13.11: 226 items, 6 `work_add` calls, 19 tool calls in all; 57 navlun titles over the cloud's 500 are cut, losslessly (title = intent); the question fits (2,055 and 280 characters, ceiling 4,000) |
| **OD11** | `tokio` | **DECIDED 2026-10-05** (recommendation) | **Stays banned.** Sync with threads; `ureq` is blocking |
| **OD12** | Native hand-back lane | **DECIDED 2026-10-05** (recommendation) | **Keep** (13.6): 16 of 1,050 jobs, 36 + 55 lines |
| **OD13** | MCP server name and install target | **DECIDED 2026-10-05** (recommendation) | **`wapps-broker`**, installed by `wapps broker install` into Claude Code user scope and Codex `config.toml`; the hook matcher becomes `mcp__wapps-broker__.*` |
| **OD14** | Ship the orchestrator skill through `wapps skill` | **DECIDED 2026-10-05** (recommendation) | **Yes** |
| **OD15** | What the scrub covers, and how strongly | **DECIDED 2026-10-05** (recommendation, refined by measurement) | **A**: the daemon's own words (note, finish output, finish error, and the local transcript) go through the plugin's 5 patterns, with `ASSIGNMENT` anchored at the start of a line **or of the command in a `Bash: ` note** (§4.5). The recommendation said "anywhere on a line"; an unanchored variant matches 13 of 452 replayed work-item texts, which are prose, so the anchor is widened only as far as the measured hole. Orchestrator-authored text is forwarded as written. **It does not need the owner:** the owner already decided that this text lives in the cloud (slice 13) and is replayed there (OD10), and the plugin's scrub changes 0 of the 454 texts OD10 sends |
| **R0** | How the Rust binary ships | **DECIDED 2026-10-05** | The Rust `wapps` replaces Go in the Homebrew release when the CLI port is done; the release slice runs on `wapps-cli` `lane/cli-s10` (§7) |
| **OD16** | How the owner files and moves work, now that only the lease holder writes the work list | **OPEN** | (A) through an orchestrator session: no code; (B) a leaseless owner door in the cloud, `work/file` and `work/move` under the `answer` verb (P-e), used by `wapps broker file/move` and the explorer's move key. **Why it needs the owner:** the plugin gave the owner a leaseless door on purpose (`work.ts:518-519`: "the same leaseless door as `agent-broker move`"), and the cloud gave work writes to `claim` on purpose (`broker_routes.rs:306`, "YAZMA `claim`"). The owner uses it: 57 of navlun's open items have titles longer than 500 characters, created 2026-08-25 to 2026-09-18, after `work_add`'s 500 cap landed (`a155df0`, 2026-08-12), so they came through `agent-broker work file`; 98 of 203 have the `file` shape (title = intent). The owner principal is an admin and so reaches `claim` routes, but a write also needs the orchestrator's lease capability, which the owner does not hold. **Recommendation: B**, because the measured use is the owner's own filing, and A turns each of those into a conversation. Until decided, 13.8 and 13.10 ship without `file`, `move` and the move key |

---

## 9. Findings, collected

1. **0.1** The plugin's test suite reads `~/.claude`. With an isolated `HOME`, 17/585 fail.
2. **0.2** The task's "52 test files" does not reproduce: 107 files, 585 tests.
3. **3.6** The cloud's dispatch body has no `answersQuestionId`, so delegated answers cannot be reached over HTTP. Read, not run.
4. **4.2** Claude workers inherit the daemon's whole environment (74 names recorded). Codex workers get 9.
5. **4.2b** The plugin runs the SDK-bundled `claude` 2.1.228, not the `PATH` 2.1.289.
6. **4.3** The cloud orphans a job after 5 min of silence, and codex may be silent for 10. The daemon must heartbeat every running job.
7. **5.1** A single agents token puts both orchestrators behind one principal, so a handoff always gets `handoff_to_self`; and `handoff_packages` is 0 in all 9 stores, so it was never used. Under OD1 the two handoff tools are not served.
8. **R0** The shipped `wapps` is still the Go binary: one `builds:` entry (`./main.go`) and 0 `cargo` mentions in CI. Being handled by `lane/cli-s10` (owner decision 2026-10-05).
9. `wapps-platform` `main` moved during measurement (`7cf2d20` → `57b8bbb` → `cac8ede`). `src/http` was deleted and every cloud citation was re-measured; `cac8ede` changed none of the cited broker files.
10. **3.5** The plugin's schemas and the cloud's bodies differ in 44 of 51 comparable fields (capability floor 14, id ceilings 17 + 4, content ceilings 7, role name 1, handoff target 1), plus whole-body shapes, trim and the mission-id pattern; 41 of 48 on the 24 served tools. Found by `schema_diff.py`, not left to the differential.
11. **3.7** The daemon acts on 11 of the 26 tools (7 acted on, 3 rewritten, 1 observed), passes 13 verbatim, does not serve 2, and publishes a second `inputSchema` for at least 3. "One schema definition" holds for the rules of validity, not for the shapes.
12. **4.5** The plugin scrubbed only its local transcript. Progress notes, finish output and finish error had `redact` alone, which removes nothing from text. All three leave the machine from 13.3, so the scrub is a 13.3 dependency. `scrubForTranscript` truncates to 8,192 and cannot be used for output. The line-anchored `ASSIGNMENT` pattern misses `Bash: NAME=secret …` (measured).
13. **7.1** The first per-slice line figures could not be audited, and the slice order ignored what the 13.3 codex worker imports (`skills.ts`, `rulebook.ts`, `owner_pause.ts` and `shell.ts`, `scratch.ts` and the `worktree.ts` helper it needs, `path_containment.ts`) and the scrub it needs. The second revision's check skipped the split files as importers; checked at symbol level, `runtime.ts` also needs `readQuota` and `#quota` in 13.3 (`runtime.ts:447,459`: quota decides which codex events are notes), and declares five stubs. 13.3 is 2,416 lines.
14. **7.1b** The cloud does not choose a worker's provider and does not check review independence (`review_bind_refusal`, read). `roles/route.ts` and `#route` are (b), in 13.3; only routing directives stay open.
15. **4.3b** The attach answer carries the worker's task (the cloud builds the review and delegated briefs at attach), so the daemon attaches before it spawns, with the job id as run id. The second revision had codex attach after its first event.
16. **3.3b** The plugin's attention digest includes the quota status per provider, so `agent_await` wakes on it. The cloud's has no quota; the daemon folds its own in (13.6).
17. **13.10** The cloud's `GET …/jobs/:job/result` marks the result read; the explorer read results without marking. The ported explorer reads the report from the local transcript.
18. **OD10** 57 of navlun's 203 open items have titles over the cloud's 500 (up to 1,528), all with title = intent, filed by `agent-broker work file` after the MCP cap existed. The replay cuts the title losslessly. Navlun's open question fits `work_ask`.
19. **OD16** The owner's `file` and `move` were a leaseless door; in the cloud only the lease holder writes the work list. Open.
20. **OD15** An unanchored `ASSIGNMENT` matches 13 of 452 replayed work-item texts; the plugin's patterns change 0 of 454.

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
9. **The broker provision** was read at `cac8ede` and run by its author with `--plan`
   only. Nothing was deployed, so no token exists yet and no roster grant was tried.
10. **What `hardening.test.ts`'s 30 tests split into.** Not split.
11. **Whether the daemon can run on Linux unchanged.** Everything is POSIX and
    `ps -o lstart=` exists on both, but only darwin/arm64 was run.
12. **Live-state contents beyond counts and lengths.** `od10.py` and `od15_probe.ts`
    read the open items' and the open question's text to measure lengths, depths and
    what the scrub would change; no text was printed or stored.
13. **What the Worker's MCP endpoint (P12) will answer.** It is unbuilt. §3.7 and the P12
    row state what OD3 needs from it (where `attention` is appended, `agent_running`'s
    projection, whether `claim` keeps `provider` as an argument). The
    platform doc does not say, and there is nothing to run.
14. **The scrub's recall.** §4.5 ran one sample text and three command lines. That shows
    one hole and says nothing about how many others there are. The seam-3 planted-secret
    scenario is the only guard proposed.
15. **How many of the divergences in §3.5 an agent would hit in practice.** The list is
    complete for fields that carry a ceiling on both sides. How often a real orchestrator
    sends a 4,001-character question was not measured.
16. **The replay (13.11) was not run**, not even against a fake. Its inputs were measured;
    its size (about 150 lines) is judgment.
17. **The explorer's data contract was read, not run.** Which `JobView` and
    `WorkItemView` fields cover each column of the explorer (§7, 13.10) was checked by
    reading `payload.rs` and `explorer.ts`; the terminal plumbing in Rust (raw mode, window
    size) was not tried.
18. **The JSONL transcript store** (13.9) was not built or timed. Its read pattern (one
    job at a time, the newest page) is the plugin's.

Scratch artifacts (ephemeral, not committed): `/tmp/broker-oracle.mw98/` holds
`bun-test.log`, `bun-test2.log`, `mcp-transcript.jsonl`, `rec/` (the claude spawn
recording), `rustcopy/` (crate-delta runs), and from this revision `tools.json` and
`diff.txt` (the rerun of `tools_list.ts` and `schema_diff.py`) and the outputs of
`slices.py` and its two mutation runs. The scripts of §0 are committed in
`docs/broker-daemon-port.measure/` and regenerate everything else in this document
that is not named here.
