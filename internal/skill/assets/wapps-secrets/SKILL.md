---
name: wapps-secrets
description: Use when the repo has a .wapps.yaml file and you need a secret value (database password, API token, build arg, etc.). Apply-only safety pattern — agents never see raw secret values. Values live in the server-decrypt gate; nothing encrypted is stored in the repo.
---

# wapps-secrets skill

This repo uses [wapps-cli](https://github.com/wappsdev/wapps-cli) to reach team
secrets. Agents (Claude Code, Cursor, Aider) interact with them through
**apply-only** commands. You will never need to see a secret value to use it —
that rule is the whole point of this skill.

## Where the values live

Nothing encrypted is stored in the repo. Values live in Cloudflare (R2 behind a
thin gate at `gw.meapps.dev`) and are decrypted server-side; access follows your
**Google Workspace group** via CF Access. There is no shared passphrase and
nothing to `git pull` before a read.

`.wapps.yaml` names the project this repo reads from — that is all it contains.

**One-time auth:** `wapps login` opens CF Access SSO in the browser (needs
`cloudflared`: `brew install cloudflared`). The session is cached; re-run it when
a command fails with a session error.

## The rule: apply-only

When you need a secret to do something, use one of these. Each applies secrets
without ever printing values to your tool output:

| Command | What it does | When to use |
|---|---|---|
| `wapps secrets apply` | Writes every `targets:` declared in `.wapps.yaml` (atomic, 0600, idempotent). No values printed. | Repo declares targets — preferred over `env --write`. Used in `predev` scripts. |
| `wapps secrets env --write <path>` | Writes one env file to disk (0600, atomic). Stdout stays empty. | One-off / ad-hoc path not declared in `targets:`. |
| `wapps secrets exec -- <cmd>` | Injects secrets as env vars into the subprocess. Stdout from `wapps` is silent. | A one-shot command that needs creds: `wapps secrets exec -- ./scripts/deploy.sh` |
| `wapps tofu <args>` (wapps ≥ v0.19.0) | Runs `tofu <args>` with the project's secrets injected verbatim (project resolved from cwd `.wapps.yaml`). Same scrubber + binding-pin as `exec`. | Any tofu run: `wapps tofu plan`, `wapps tofu apply`. Preferred over `secrets exec -- tofu …`. |

After `env --write`, the file on disk DOES contain plaintext secrets. **Do NOT
read it with the Read tool** — that would put values back into your transcript.
Treat `.env.local` as opaque: it exists so the runtime tool (node, pnpm, rails,
etc.) can load it.

## What NOT to do

These put raw secret values into your tool output, which gets logged by
Anthropic / OpenAI / your IDE host. Avoid them:

❌ `wapps secrets get <KEY>` — prints the value to stdout. Operator-only. (In an
   agent/CI context the CLI refuses it — `AGENT_MODE_REFUSED` — but don't try.)
❌ `wapps secrets list` — prints key NAMES (names are OK; never combine with `get`).
❌ `cat .env.local`, `Read tool on .env.*`, `bat .env.shared` — plaintext secrets.
❌ Echoing what you fetched back at the user. If you ran `secrets get` by mistake,
   do NOT repeat the value in chat — apologize and ask the operator to rotate it.
❌ Passing secrets as positional args to a subprocess (they land in `ps aux` /
   shell history). Use `exec --` (env injection) instead.
❌ `wapps projects rm <PROJECT>` — removes a whole project. Admin-only,
   control-plane, refused in agent mode. `wapps projects list` IS fine —
   it prints project names only, same class as `secrets list`.
❌ `wapps secrets rm <KEY>` — removes a key from the store, irreversibly. The CLI
   refuses it in agent/CI context (`AGENT_MODE_REFUSED`) and the gate requires a
   separate `delete` grant that agents don't hold. If a key is orphaned (the
   service account / provider it pointed at is gone), TELL the operator which key
   and why — they run `rm` themselves.

## Common flows

### "Start the dev server"

If `.wapps.yaml` declares `targets:` (recommended), the `predev` script handles
it — `pnpm dev` triggers `wapps secrets apply` automatically. Manually:

```bash
wapps secrets apply     # materialize declared targets (no stdout)
pnpm dev                # pnpm/next/rails picks up .env.local
```

One-off, no declared target:

```bash
wapps secrets env --write .env.local
pnpm dev
# or no file at all:
wapps secrets exec -- pnpm dev
```

If any of these fail with a session/auth error on the **store** backend, run
`wapps login` first (see the backend table above).

### "Run a one-shot script that needs creds"

```bash
wapps secrets exec -- ./scripts/migrate-db.sh
```

### "Run tofu (plan / apply)"

Use `wapps tofu` — it resolves the project from the cwd `.wapps.yaml` and injects
secrets verbatim into `tofu`, with the same scrubber + binding-pin as `exec`:

```bash
wapps tofu plan
wapps tofu apply
```

This replaces the older `wapps secrets exec -- tofu …` form. Non-tofu
wrappers (e.g. `wapps secrets exec -- ./scripts/drift-check.sh`) stay on `exec`.

## Adding / changing a secret (operator action)

Uses a masked prompt — the operator types the value; never ask them to paste it
into chat.

```bash
wapps secrets set <KEY>     # operator types value at the masked prompt
```

The write goes straight to the gate and is audited; there is nothing to commit.
It needs `write` on that key in the group policy. Declared targets are
regenerated by `apply` — never commit them.

## Other commands worth knowing

- `wapps secrets sync` — push declared `sources:` into the store. Add `--dry-run`
  to see which key NAMES would be added or changed without writing anything.
- `wapps projects list` — which projects exist in the store (names only).
- `wapps login --check` — is my session live? (never prints token bytes)
- `wapps whoami` — my groups + effective grants.
- `wapps secrets rotate <KEY>` — typed value rotation (operator ceremony).

## Working from another directory

Every verb accepts `--project <name>` or `--config <path>/.wapps.yaml`, so you do
not have to `cd` into the project first — use these instead of asking the
operator to change directory for you.

Two things WILL be refused in your context, and neither is a bug to work around:

- A bare `--project <name>` with no local checkout. A human may target a project
  this way; you may not. Work inside the project's repo, or ask the operator.
- An unbound repo. A human gets asked inline whether to bind it; you get
  `BINDING_UNPINNED`. That guard exists so a `.wapps.yaml` — a file you can
  write — cannot claim a project on its own. If you hit it, tell the operator to
  run the command once themselves (or `wapps secrets trust-repo`); do not try to
  create or edit a `.wapps.yaml` to get around it.

## If something looks broken

```bash
wapps doctor              # deps + gate session + tofu/Coolify reachability
wapps login --check       # is my session live? (never prints token bytes)
```

Read the error fully — `wapps` errors carry a copy-pasteable recovery line.

## Safety canary (operator side)

There's a canary value that always starts with `WAPPS_AI_CANARY_`. If it ever
appears in your chat transcript, your tool integration is leaking secrets —
tell the operator immediately so they can rotate.
