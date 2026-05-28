# wapps-cli — Operator Onboarding

Welcome. This guide walks you through using `wapps-cli` for team secrets
the first time. Budget: 10 minutes including the install. If you hit
something not covered here, run `wapps doctor` first — the error is
usually a missing env var with a copy-pasteable recovery snippet.

## What wapps does for you

- One CLI to read, write, and distribute team secrets via git
- Encrypted-at-rest (age) — `secrets/all.enc.age` lives in the repo
- Multiple sources merge into one archive: Tofu output, `.env.shared`, etc.
- AI-safe: agents (Claude Code, Cursor) use apply-only commands, never
  see raw values

No SaaS account. No central server. The only shared secret is the
master passphrase (one per team, distributed via Signal E2E).

## Step 1 — Install

```bash
brew tap wappsdev/tap
brew install wapps
wapps --version
```

If you're not on macOS, build from source:

```bash
go install github.com/wappsdev/wapps-cli@latest
```

## Step 2 — Get the master passphrase

Ask the operator who runs your team's rotations (currently the founder).
They will send you the passphrase via **Signal end-to-end encrypted
message**. Save it to **Apple Passwords** as a new entry titled
`Wapps Master`.

Never paste the passphrase into:
- Slack / Teams / Discord
- Email
- A chat with any AI assistant
- Issue trackers / PR descriptions
- Any file outside Apple Passwords / 1Password

## Step 3 — Export the passphrase

In every shell session where you'll run `wapps`:

```bash
export WAPPS_SECRETS_PASSPHRASE="$(security find-generic-password -w -s 'Wapps Master')"
```

If you don't use the macOS keychain CLI:

```bash
# Paste the value once (typing it visibly won't hit shell history if your
# shell is in zsh's "histignorespace" mode — set HISTCONTROL=ignorespace
# and prefix the command with a space).
 export WAPPS_SECRETS_PASSPHRASE='paste-here'
```

Add to your shell rc (`.zshrc` etc.) for persistence. Never commit it
to a dotfile in git.

## Step 4 — Verify your local setup

```bash
wapps doctor
```

Resolves the following:
- ✓ tofu, age, git, jq, gh binaries
- ✓ R2 env vars (for repos that use Tofu sources)
- ✓ Coolify API reachable
- ✓ git remote configured

If you only care about Tofu-source repos (no Coolify):

```bash
wapps doctor --for tofu
```

## Step 5 — Use secrets in your dev loop

You'll touch one of three commands daily:

### Read into an env file (for `next dev`, `pnpm start`, etc.)

```bash
wapps secrets env --write .env.local
```

Atomic write, mode 0600. Stdout is silent. Your runtime tool loads
`.env.local` as normal.

### Run a one-shot command with creds injected

```bash
wapps secrets exec -- ./scripts/deploy.sh
wapps secrets exec -- pnpm db:migrate
```

Env injected into the child process. No values touch your terminal or
shell history.

### Sync (after pulling new tofu outputs or editing `.env.shared`)

```bash
wapps secrets sync
```

Rebuilds the encrypted archive from sources. Commit the resulting
`secrets/all.enc.age` change.

## Step 6 — Add a new secret

You generated a fresh token (Stripe, GitHub, whatever). Capture it
**immediately** — every minute it sits in your clipboard is a minute it
might leak.

```bash
wapps secrets set NEW_TOKEN_NAME
# masked prompt appears — paste the value, press enter
```

This updates both `secrets/all.enc.age` AND `.env.shared` (the file
source declared in `.wapps.yaml`). Commit both:

```bash
git add secrets/all.enc.age .env.shared
git commit -m "chore: capture NEW_TOKEN_NAME"
git push
```

Your teammates run `git pull` and immediately have the new token.

### Bulk import from an existing `.env` file

```bash
wapps secrets import-env legacy.env
```

Merges every key from `legacy.env` into the archive. Override warnings
go to stderr.

## Step 7 — Bootstrap a new repo

For a fresh repo (e.g., adding wapps to `vaulter-api`):

```bash
cd vaulter-api/
wapps secrets init --with-file-source
# creates .wapps.yaml, secrets/, secrets/.gitignore
```

The template uses a `file` source by default with `--with-file-source`,
or `tofu` source without it. Edit `.wapps.yaml` if you need both.

Then populate via either `wapps secrets set <KEY>` (one at a time) or
`wapps secrets import-env <file>` (bulk).

## Step 8 — Server-side env (Coolify deploys)

After you've updated the archive, sync it to your Coolify app:

```bash
# Dry-run first — see what would change without applying.
wapps secrets sync --target=coolify --app <APP_UUID>

# Apply if the diff looks right.
wapps secrets sync --target=coolify --app <APP_UUID> --force
```

You need `COOLIFY_API_TOKEN` set. `--force` is destructive — it deletes
Coolify-only keys that aren't in the archive. The dry-run output shows
exactly what will happen.

## Working with AI tools

Claude Code, Cursor, and Aider use the `.claude/skills/wapps-secrets/`
skill and `.cursorrules` to learn the apply-only pattern. **You don't
need to explain it to them** — they'll automatically pick the right
command.

If you see a secret value appear in your AI agent's chat output, treat
it as a leak:
1. Rotate the affected secret in the originating system (Stripe console, etc.)
2. Run `wapps secrets rotate-master` to rotate the team passphrase
3. File an issue so we can patch the leak path

## Rotation drill (once a quarter)

The team passphrase is rotated periodically. The flow:

```bash
# Operator running the rotation:
export WAPPS_SECRETS_PASSPHRASE='current-passphrase'
export WAPPS_SECRETS_PASSPHRASE_NEW='new-passphrase-from-password-manager'
wapps secrets rotate-master
git add secrets/all.enc.age && git commit -m "chore: rotate master passphrase"
git push

# Then via Signal E2E, distribute the new passphrase to each operator.
# Each operator updates their Apple Passwords entry + shell export.
```

Audit trail lives in `secrets/rotation.log` (gitignored — pp
fingerprints are sensitive). Schema is versioned (`schema_version: 1`).

## Common errors

**"WAPPS_SECRETS_PASSPHRASE not set"**
You forgot Step 3. Run the export, or add to your shell rc.

**"secrets.sync preflight: required environment not set"**
For Tofu-source repos. The error includes a copy-pasteable recovery
snippet — read it.

**"archive has drift or uncommitted changes — run 'git pull' first"**
Someone else pushed a `secrets/all.enc.age` change. `git pull` and retry.

**"file source missing required field 'path'"**
Edit `.wapps.yaml` and add `path: .env.shared` (or your chosen file).

## Where to learn more

- `wapps --help` — every command has built-in docs
- `wapps secrets --help` — secrets subcommands
- `.claude/skills/wapps-secrets/SKILL.md` — AI integration details
- Source: github.com/wappsdev/wapps-cli
