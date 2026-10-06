---
name: agent-broker
description: Use when working with the wapps broker MCP mission ledger, work items, blocking questions, relayed human decisions, or job attention.
---

# Working through the wapps broker

This is a **source-only** reference asset: not installed, registered, or shipped
as a selectable broker skill. Preparing this file grants no capability or owner
authority. The existing skill lifecycle still manages only wapps-secrets.

Use the current wapps broker interfaces, not the original plugin's executable
or runtime promises. Cloud state is authoritative; the local bridge routes each
MCP call to an explicitly named mission. Enrollment does not establish a cloud
mission binding. Obtain the intended mission from the authorized task context;
if that binding is missing, ask rather than infer it from the project directory.
Do not create a mission or bootstrap configuration automatically.

## What is usable now

| Surface | Effect |
| --- | --- |
| `orchestrator_status` | observational |
| `work_list` | observational |
| `roles_list` | observational |
| `agent_list` | observational |
| `agent_running` | observational |
| `agent_status` | observational |
| `agent_await` | observational |
| `agent_result` | consumes unread result |
| `agent_submit` | ACTION_UNAVAILABLE |
| `agent_attach` | ACTION_UNAVAILABLE |
| `agent_report` | ACTION_UNAVAILABLE |
| `agent_cancel` | ACTION_UNAVAILABLE |
| pause / unpause | refuse; nothing changed |
| role apply | refuse; nothing changed |
| project enroll | root registry only |
| explore / broker install | absent |

The four execution tools remain in discovery, but refuse without launching a
worker or changing cloud state. Do not dispatch, attach, report, cancel, resume,
or promise a reviewer or delegated-answer worker through this slice. Local
pause enforcement, provider containment, transcripts, quota storage, and worker
recovery are not established by this reference. A running cloud row is not
proof that this local daemon launched or supervises its process.

Cloud `roles_propose` validates proposed tool ceilings without declaring them;
it is not a local spawn-spec schema or a working role installer. Leave model,
effort, backend, authentication, spend, role schema, quota persistence, and
bootstrap policy to their separately authorized contracts. No defaults for
those decisions are supplied here.

Local project enrollment registers only a canonical root in the version-1
registry. It does not install a harness, create a mission, declare roles, or
change pause state. There is no explorer or broker installation command in the
accepted command tree. Do not repurpose the secrets skill installer for this
asset or alter its registry, fingerprint, refresh, or uninstall behavior.

## Identity and authority

Store intent and decisions; read derived readiness and attention instead of
inventing a status or progress field. Re-read the ledger after a reconnect or
human action. Use exact returned work item, job, and question IDs, never a title,
list position, latest-job guess, or another mission's ID.

The following fenced JSON examples are MCP tools/call **params**, not shell
commands. All values are illustrative: replace demo-mission and the exact
selectors with those from the authorized mission. Replace the fixture
capability and fencing token only with the authority returned by a successful
claim. Never copy credentials into intent, questions, command arguments, or
chat. The provider in the claim example identifies that illustrative caller;
it is not a worker routing or provider-selection policy.

```json
{"name": "orchestrator_status", "arguments": {"missionId": "demo-mission"}}
```

```json
{"name": "orchestrator_claim", "arguments": {"missionId": "demo-mission", "provider": "claude"}}
```

One mission has one live lease. A conflicting claim is not permission to steal
it. Lease writes present the exact capability and fencing token; use the
returned deadline and `orchestrator_heartbeat` to renew when needed. Do not
assume every call renews a lease. A stale fence is a refusal, not a retry policy.
The current catalog provides no handoff-package or takeover tools; do not
reproduce the plugin's handoff workflow with shell commands.

## File full intent, then ask only for genuine decisions

```json
{"name": "work_list", "arguments": {"missionId": "demo-mission"}}
```

Use a short title plus the full brief in intent. Do not shorten intent to fit
a title limit. Root horizons are now, next, later, or someday; omitting placement
leaves work unplaced rather than making an invented commitment. Parts inherit
placement from their whole. Follow-on findings are distinct from parts needed
to deliver the whole. `work_adopt` requires the exact completed source job and
an explicit relation for every item; it does not dispatch the source job.

```json
{"name": "work_add", "arguments": {"missionId": "demo-mission", "authority": {"capability": "fixture-claim-capability", "fencingToken": 1}, "items": [{"title": "Validate catalog examples", "intent": "Validate every documented tool name, argument, mission route, and exact selector against the accepted source catalog. Preserve the full brief and report unsupported execution separately.", "horizon": "now"}]}}
```

File only authorized scope. Horizon placement is a commitment, not automatic
promotion. If ready work needs unavailable execution, report the limitation;
a ledger entry is not a worker launch. Do not turn a drained round into authority
to promote work. `work_close` is an explicit delivered, dropped, or superseded
decision, not a job-count measurement. Verify the intent before declaring delivery.

Raise a question when scope, priority, money, or policy truly needs a decision.
Keep its exact workItemId and the returned questionId together. A proposal is a
recommendation, not an answer or consent. Park that branch and read the work
list for other authorized, usable work; do not fabricate dispatch success.

```json
{"name": "work_ask", "arguments": {"missionId": "demo-mission", "authority": {"capability": "fixture-claim-capability", "fencingToken": 1}, "workItemId": "work-17", "question": "Should this round include only source-reference validation?", "proposal": "Validate the source asset only; leave installation and execution out of scope."}}
```

`work_withdraw` records that a question was withdrawn with a reason, not that
someone answered it. `work_delegate` records delegation, but cannot make the
unavailable dispatch path run. Do not use either to disguise a missing human
decision.

## Relay a real answer; the HUMAN confirms separately

Only relay words the human actually gave for this exact question. An agent
cannot answer as the owner, accept its own proposal, or confirm its own relay.
Conversation text attributed by an agent remains a relay, not witnessed owner
authority. Do not route around this via shell, token extraction, environment
overrides, or another session.

```json
{"name": "work_relay_answer", "arguments": {"missionId": "demo-mission", "authority": {"capability": "fixture-claim-capability", "fencingToken": 1}, "questionId": "question-5", "answer": "Validate the source asset only; do not install it or enable execution."}}
```

The relay records the answer and can unblock work, but leaves confirmation debt
that prevents release. The separate **HUMAN** reads the exact relay and runs
these commands in their own terminal. These are commands to explain to the human,
not commands for an agent to execute.

```sh
wapps broker relayed --mission demo-mission --work-item work-17
wapps broker confirm --mission demo-mission --work-item work-17 question-5
```

Human owner commands require a human terminal and use the owner's cached SSO
session, not an agent service credential or a lease. Context hints and TTY checks
are not cryptographic proof of human presence; cloud refusal remains authoritative.
Missing owner authentication is not permission to read tokens, borrow agent
credentials, change grants, or disable the guard.

## Other HUMAN actions, not MCP authority

Each example selects its mission explicitly. Question actions also bind the
work item and question. The following are alternative actions, not a script
to run sequentially on the same question.

A human reads the open question and its full proposal before choosing an answer:

```sh
wapps broker questions --mission demo-mission --work-item work-17
wapps broker answer --mission demo-mission --work-item work-17 question-5 "Validate source only."
```

Alternatively, acceptance supplies the exact proposalDigest from that read.
The illustrative digest below is not a digest to reuse: replace it with the
opaque value returned for this question. Do not recompute it from a summary,
accept without it, or substitute a new digest silently after a refusal. If the
proposal changes, the human must read it again and decide again.

```sh
wapps broker accept --mission demo-mission --work-item work-17 question-5 fd785d45
```

The human can file and place work without an orchestrator lease. Keep the
explicit short title and full filing intent separate. The title is limited to
500 UTF-16 units and intent to 100000; long intent without --title is refused,
never silently truncated. Moving a part detaches it from its former whole.

```sh
wapps broker file --mission demo-mission --title "Validate catalog examples" --horizon now "Validate every documented tool name, argument, mission route, and exact selector against the accepted source catalog. Preserve the full brief and report unsupported execution separately."
wapps broker move --mission demo-mission next work-17
```

A refused mutation is not success. A malformed acknowledgment or connection
loss after sending may leave the outcome unknown. Do not automatically retry,
pick a replacement target, claim completion, or switch to the agent door.
Read authoritative state and have the human resolve the ambiguity.

## Observe without consuming; consume only when acting on a result

```json
{"name": "agent_status", "arguments": {"missionId": "demo-mission", "jobId": "job-23"}}
```

Status, list, running, work-list, and attention reads do not discharge unread
results. The human running command lists cloud reserved/running rows; it does
not invent local quota or consume a job result. For changed attention, pass the
last returned digest; the local bridge polls every two seconds for at most
55000 milliseconds. Without sinceDigest it returns immediately. A timeout is
not evidence of completion, and progress lines are not a terminal outcome.

```json
{"name": "agent_await", "arguments": {"missionId": "demo-mission", "sinceDigest": "fixture-attention-digest", "waitMs": 55000}}
```

By contrast, this next call **consumes unread result** state: use it deliberately
for the exact settled job whose result you are ready to read and act on, not as
an observational probe, explorer, or background status check.

```json
{"name": "agent_result", "arguments": {"missionId": "demo-mission", "jobId": "job-23"}}
```

Read attention and act on what is actually returned. Do not manufacture a pass
verdict or report. `orchestrator_release` requires current authority and is
refused for live work, unread settled results, or unconfirmed relays. A ledger
read does not clear those debts and unavailable execution does not settle them.

For secret consumption, the separate wapps-secrets apply-only rules still
apply: agents never read or print raw values. This broker reference neither
changes those semantics nor authorizes deployment, release, installation,
migration, or credential changes.
