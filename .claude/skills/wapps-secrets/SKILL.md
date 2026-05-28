---
name: wapps-secrets
description: Use when the repo has a .wapps.yaml file and you need a secret value from secrets/all.enc.age (database password, API token, build arg, etc.). Apply-only safety pattern — agents never see raw secret values.
---

# wapps-secrets skill

This repo uses [wapps-cli](https://github.com/wappsdev/wapps-cli) to manage
encrypted team secrets. Agents (Claude Code, Cursor, Aider) interact with
secrets through **apply-only** commands. You will never need to see a
secret value to use it.

## The rule: apply-only

When you need a secret to do something, use one of these commands. Each
applies secrets without ever printing values to your tool output:

| Command | What it does | When to use |
|---|---|---|
| `wapps secrets env --write <path>` | Writes env file to disk (0600, atomic). Stdout stays empty. | Need an `.env.local` for `next dev`, `pnpm start`, etc. |
| `wapps secrets exec -- <cmd>` | Injects secrets as env vars into the subprocess. Stdout from `wapps` is silent. | Running a one-shot command that needs creds: `wapps secrets exec -- ./scripts/deploy.sh` |
| `wapps secrets sync` | Rebuilds the archive from declared sources. No values printed. | After someone added a new tofu output or edited `.env.shared` |

After `env --write`, the file on disk DOES contain plaintext secrets. **Do
NOT read it with the Read tool** — that would put values back into your
transcript. Treat `.env.local` as opaque: it exists so the runtime tool
(node, pnpm, rails, etc.) can load it.

## What NOT to do

These commands or patterns will put raw secret values into your tool
output, which gets logged by Anthropic / OpenAI / your IDE host. Avoid them:

❌ `wapps secrets get <KEY>` — prints the value to stdout. Operator-only.
❌ `wapps secrets list` — prints key names AND counts (key names OK, but
   never combine with `get`).
❌ `cat .env.local`, `Read tool on .env.*`, `bat .env.shared` — file
   contents are plaintext secrets.
❌ Echoing what you fetched back at the user. If you ran `secrets get` by
   mistake, do NOT repeat the value in chat. Apologize, ask the user to
   rotate the secret (`wapps secrets rotate-master`).
❌ Passing secrets as positional arguments to a subprocess. Argument
   lists end up in `ps aux` output and shell history. Use `exec --` (env
   injection) instead.

## Common flows

### "Start the dev server"

```bash
# 1. Write env to local file (no stdout).
wapps secrets env --write .env.local

# 2. Start as normal — pnpm/next/rails picks up .env.local.
pnpm dev
```

Or, in one step:

```bash
wapps secrets exec -- pnpm dev
```

### "Run a one-shot script that needs creds"

```bash
wapps secrets exec -- ./scripts/migrate-db.sh
```

### "Push the archive to Coolify after I added a key"

```bash
wapps secrets sync --target=coolify --app <UUID>           # dry-run diff
wapps secrets sync --target=coolify --app <UUID> --force   # apply
```

### "The team rotated the passphrase, I need the new one"

The new passphrase is in your Apple Passwords under "Wapps Master" (or
your team's equivalent). The operator should tell you to update your
`WAPPS_SECRETS_PASSPHRASE` env var — never share the passphrase in chat.

## Adding a new secret

This is an operator action (uses a no-echo prompt). If you're an agent
and the user asks you to add a secret, run the command and let them type
the value at the prompt — do NOT ask them to paste it into your chat:

```bash
wapps secrets set <KEY>
# operator types value at the masked prompt
```

After `set`, both the archive and the file source declared in
`.wapps.yaml` are updated. Commit both.

## If something looks broken

```bash
wapps doctor --for tofu   # validates env without running sync
wapps doctor              # full env (tofu + R2 + Coolify + git)
```

The error messages from `wapps secrets sync` include a copy-pasteable
recovery snippet when env vars are missing. Read the error fully before
asking the operator.

## Safety canary (operator side)

There's a canary value in `.env.shared` that always starts with
`WAPPS_AI_CANARY_`. If you ever see this value appear in your chat
transcript, your tool integration is leaking secrets. Tell the operator
immediately so they can rotate.
