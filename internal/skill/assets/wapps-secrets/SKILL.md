---
name: wapps-secrets
description: Use when the repo has a .wapps.yaml file and you need a secret value (database password, API token, build arg, etc.). Apply-only safety pattern — agents never see raw secret values. Works with BOTH backends — the server-decrypt gate (current) and the legacy git-age archive.
---

# wapps-secrets skill

This repo uses [wapps-cli](https://github.com/wappsdev/wapps-cli) to manage
encrypted team secrets. Agents (Claude Code, Cursor, Aider) interact with
secrets through **apply-only** commands. You will never need to see a secret
value to use it — that rule is the whole point of this skill and it holds no
matter which backend the repo uses.

## Two backends — same commands, different one-time auth

`.wapps.yaml` declares a `backend:`. You almost never care which it is: the
apply-only commands below are **identical**. The only difference is how YOU
authenticate once per machine.

| backend | what it is | one-time auth |
|---|---|---|
| **`store`** (current) | secrets live in Cloudflare (R2 + a thin gate at `gw.meapps.dev`); access follows your **Google Workspace group** via CF Access SSO. No shared passphrase, no git pull. | **`wapps login`** — opens CF Access SSO in the browser (needs `cloudflared` installed: `brew install cloudflared`). Session is cached; re-run when it expires. |
| **`legacy-git`** | secrets live in a git-committed `secrets/all.enc.age` with one shared passphrase. | `WAPPS_SECRETS_PASSPHRASE` env (Apple Passwords → "Wapps Master"). |

**If a secret read fails with a session / auth error:**
- **store backend** → your CF Access session expired: run `wapps login`, then retry.
- **legacy-git backend** → `WAPPS_SECRETS_PASSPHRASE` is unset or wrong.

## The rule: apply-only

When you need a secret to do something, use one of these. Each applies secrets
without ever printing values to your tool output:

| Command | What it does | When to use |
|---|---|---|
| `wapps secrets apply` | Writes every `targets:` declared in `.wapps.yaml` (atomic, 0600, idempotent). No values printed. | Repo declares targets — preferred over `env --write`. Used in `predev` scripts. |
| `wapps secrets env --write <path>` | Writes one env file to disk (0600, atomic). Stdout stays empty. | One-off / ad-hoc path not declared in `targets:`. |
| `wapps secrets exec -- <cmd>` | Injects secrets as env vars into the subprocess. Stdout from `wapps` is silent. | A one-shot command that needs creds: `wapps secrets exec -- ./scripts/deploy.sh` |
| `wapps tofu <args>` (wapps ≥ v0.19.0) | Runs `tofu <args>` with the project's secrets injected verbatim (project resolved from cwd `.wapps.yaml`). Same scrubber + binding-pin as `exec`. | Any tofu run: `wapps tofu plan`, `wapps tofu apply`. Preferred over `secrets exec --prefix '' -- tofu …`. |

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
wapps secrets env --write .env.local --prefix ''
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

This replaces the older `wapps secrets exec --prefix '' -- tofu …` form. Non-tofu
wrappers (e.g. `wapps secrets exec -- ./scripts/drift-check.sh`) stay on `exec`.

## Adding / changing a secret (operator action)

Uses a masked prompt — the operator types the value; never ask them to paste it
into chat. Works the same on both backends:

```bash
wapps secrets set <KEY>     # operator types value at the masked prompt
```

- **store backend**: the write goes straight to the gate (audited); nothing to
  git-commit. Needs `write` on that key in the group policy.
- **legacy-git backend**: the archive + the file source in `.wapps.yaml` + every
  declared target update atomically. Commit the archive + file source; do NOT
  commit targets (they're regenerated by `apply`).

## Backend-specific commands (don't guess the backend — read `.wapps.yaml`)

- **legacy-git only**: `wapps secrets sync` (rebuild the archive from sources +
  auto-apply), `wapps secrets diff [ref]` (added/changed/removed vs a git ref),
  `wapps secrets rotate-master` (rotate the shared passphrase).
- **store only**: `wapps login` / `wapps login --check` (session), `wapps whoami`
  (your groups + effective grants), `wapps secrets rotate <KEY>` (typed value
  rotation). Migration between backends is an operator ceremony:
  `wapps secrets migrate import` (TTY-only, refused in agent mode).

## If something looks broken

```bash
wapps doctor              # full env (checks cloudflared, tofu, R2, Coolify, git)
wapps login --check       # store backend: is my session live? (no token bytes)
```

Read the error fully — `wapps` errors carry a copy-pasteable recovery line.

## Safety canary (operator side)

There's a canary value that always starts with `WAPPS_AI_CANARY_`. If it ever
appears in your chat transcript, your tool integration is leaking secrets —
tell the operator immediately so they can rotate.
