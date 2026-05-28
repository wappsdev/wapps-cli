# wapps-cli — Architecture & Reference

> How the system works. For getting started, see [onboarding.md](onboarding.md);
> for what shipped when, see [CHANGELOG.md](../CHANGELOG.md).

`wapps` is a team secret manager built on three principles:

- **Git-native.** The source of truth is an age-encrypted archive committed to
  the repo (`secrets/all.enc.age`). No SaaS, no central server. Sharing a
  secret = `git push`; receiving one = `git pull`.
- **AI-safe.** No command prints a secret *value* to stdout on the default
  path. Agents (Claude Code, Cursor) apply secrets without ever seeing them.
  The one exception (`get`) is operator-only and documented as such.
- **Single passphrase.** One master passphrase per team (`WAPPS_SECRETS_PASSPHRASE`),
  distributed out-of-band (Signal E2E), held in Apple Passwords / 1Password.

---

## 1. Data model

Everything flows through one encrypted archive. There are two directions:
**ingest** (sources → archive) and **materialize** (archive → consumers).

```
   INGEST (sync)                ARCHIVE                 MATERIALIZE
 ┌───────────────┐                                  ┌──────────────────────┐
 │ tofu output   │──┐                                │ targets:  .env.local │  ← apply / env --write
 │ (tofu source) │  │      ┌──────────────────────┐  │           apps/api/.env│
 └───────────────┘  ├─────▶│  secrets/all.enc.age │──┤                       │
 ┌───────────────┐  │      │  (age, committed)    │  │ coolify:  app envs    │  ← sync --target=coolify
 │ .env.shared   │──┘      └──────────────────────┘  │           (per app)   │
 │ (file source) │              ▲        │            └──────────────────────┘
 └───────────────┘              │        │
                                │        └─▶ exec -- <cmd>  (env injected, no file)
              set / import-env ─┘            get / list / diff  (read)
```

- **Sources** are *inputs* — where archive contents come from. Declared in
  `.wapps.yaml` `sources:`. Two kinds: `tofu` (shells out to `tofu output
  -json`) and `file` (parses a `.env`-style file).
- **The archive** is the single encrypted blob. Its internal shape mirrors
  `tofu output -json`: `{"KEY": {"value": ..., "type": ..., "sensitive": ...}}`.
  Non-string values (lists, maps, numbers, bools) round-trip as JSON.
- **Consumers** are *outputs* — where plaintext is materialized. Three kinds:
  `targets:` (local files like `.env.local`), Coolify app envs, and ephemeral
  subprocess env (`exec`).

The key mental model: **`set`/`import-env`/`sync` write the archive; `apply`/
`env`/`exec`/`sync --target` read it.** Writing the archive never auto-leaks
plaintext anywhere except declared `targets:` (and only because the operator
declared them).

---

## 2. `.wapps.yaml` — full schema

Lives at the repo root. Read from the current working directory.

```yaml
version: 1                          # only 1 supported; omitted → defaults to 1
dest: secrets/all.enc.age           # archive path (default shown)
default_prefix: ""                  # prefix used by `apply` targets (default "")

sources:                            # INPUT — at least one required
  - type: tofu
    workdir: .                      # dir holding .tf files
    prefix: "TF_VAR_"               # reserved (applied at env-emit time)
  - type: file
    path: .env.shared               # required for file sources

targets:                            # OUTPUT (local files) — optional
  - path: .env.local                # uses default_prefix
  - path: terraform.tfvars.json
    prefix: "TF_VAR_"               # per-target override (nil = use default)

coolify_sync:                       # OUTPUT (Coolify multi-app) — optional
  delete_unmanaged: false           # default: never delete Coolify-only keys
  exclude_keys:                     # stripped names never pushed/diffed
    - SENTRY_RELEASE                # (deploy-pipeline-owned, perpetual drift)
  apps:
    - uuid: vaesbm45up4jyk7hhk77ka74
      name: kreeva-web              # comment-only, for readability
      archive_prefix: "KREEVA_WEB_" # matched keys pushed with prefix STRIPPED

redact_in_logs: true                # policy knobs
require_clean_git: true
```

Validation runs at load time (typos fail loudly, not silently):
- `version != 1` → error.
- empty `sources` → error.
- source field mismatch (e.g. `tofu` with `path`) → error.
- `targets[].path`: required, no duplicates, no `..` (path traversal).
- `coolify_sync.apps[]`: `uuid` + `archive_prefix` required, no duplicate
  uuid, **no overlapping prefixes** (`ROYCO_` vs `ROYCO_API_` is an error —
  explicit beats silent misrouting of a secret to the wrong app).

A repo with no `.wapps.yaml` falls back to legacy single-tofu mode for `sync`
(reads `tofu output`, writes `secrets/all.enc.age`). `set`/`import-env`/
`apply` require the file.

---

## 3. Command surface

### `wapps secrets`

| Command | Direction | What it does |
|---|---|---|
| `init [--with-file-source] [--force]` | — | Scaffold `.wapps.yaml` + `secrets/` + gitignore. Idempotent. |
| `sync` | ingest | Read sources, merge, write archive. Auto-applies `targets:` after. |
| `sync --target=coolify --app <uuid> [--force]` | materialize | Single-app: push WHOLE archive to one app, destructive mirror. Dry-run unless `--force`. |
| `sync --target=coolify --all-apps [--force]` | materialize | Multi-app: each `coolify_sync.apps` entry gets its prefix-matched subset (stripped), non-destructive by default. |
| `set <KEY>` | ingest | Capture one secret (no-echo prompt). Writes archive + file source + targets. Git drift preflight. |
| `import-env <file>` | ingest | Bulk-import a `.env` into the archive. Auto-applies targets. |
| `apply` | materialize | Write every `targets:` file atomically. Idempotent (byte-equal → no mtime touch). |
| `env [--write <f>] [--prefix P]` | materialize | Emit `export` lines. `--write` → file (silent); no flag → stdout (operator). |
| `exec -- <cmd>` | materialize | Run a subprocess with archive env injected. No file, no stdout leak. |
| `get <KEY>` | read | Print one value to stdout. **Operator-only** (breaks AI-safe rule by design). |
| `list` | read | Print key names (no values). |
| `diff [ref]` | read | Added/changed/removed key names vs a git ref (default `HEAD~1`). Values never printed. |
| `rotate-master` | admin | Re-encrypt archive under a new passphrase + JSONL audit log. |
| `verify` | read | Drift check: Tofu output sha vs archive sha. |

### Other top-level

| Command | What it does |
|---|---|
| `doctor [--for tofu]` | Dependency + access preflight. `--for tofu` checks only the sync env. |
| `coolify <...>` | Coolify v4 API shim (deploy-app, deploy-app-git, set-labels, update-env, import-app). |
| `git <...>` | git status + manual sync. |
| `--version` | Print version (ldflag-injected on releases, `dev`/`main-<sha>` locally). |

Persistent flags: `--no-sync` (skip git auto-sync preflight), `--verbose`,
`--config`.

---

## 4. The two Coolify sync modes

Both read the archive and push to Coolify; they differ in scope and blast radius.

### Single-app (`--app <uuid>`)

Pushes the **whole archive** to one app. `--prefix` *prepends* to each key.
`--force` is a **destructive mirror** — Coolify keys absent from the archive
are deleted. Used by vaulter; behavior is frozen.

### Multi-app (`--all-apps`)

Requires `coolify_sync.apps`. For each app:
1. Filter archive to keys starting with `archive_prefix`.
2. **Strip** the prefix (`KREEVA_WEB_VITE_API_URL` → `VITE_API_URL`).
3. Diff against live Coolify state.
4. `remove` bucket is empty unless `delete_unmanaged: true` (**non-destructive
   default**).

Keys matching no app's prefix (Tofu outputs like `lab_01_*`, other apps'
keys) are silently excluded. A prefix matching zero keys warns and skips.
One app failing (e.g. 404 on a stale UUID) doesn't stop the others; the
command exits non-zero. Apply is fail-fast but recovery is a plain idempotent
re-run (the diff is recomputed from live state each time).

### Keys that are never touched

Two classes are filtered out of **both sides** of the diff (never add/change/
remove), with a `(skipped N …)` visibility line:

- **Coolify-managed** (`is_coolify=true`) — magic envs Coolify generates
  (`SERVICE_FQDN_*`, `SERVICE_URL_*`). They're read-only; a PATCH would 422.
  Filtering them from `desired` too means a stale archive copy can't get
  re-added. Applies to **both** single-app and multi-app (it's a property of
  the live data, not config).
- **`coolify_sync.exclude_keys`** — operator deny-list of stripped names for
  pipeline-owned keys (`SENTRY_RELEASE` etc.) that CI rewrites every deploy
  and would otherwise show perpetual drift. Multi-app only.

---

## 5. Safety model

The whole point is that secrets don't leak through the tool. Layers:

- **AI-safe boundary at the process level.** `env --write` and `apply` write
  files (silent stdout); `exec` injects env into a subprocess. The agent
  skill (`.claude/skills/wapps-secrets/SKILL.md`) teaches agents not to `Read`
  the resulting `.env` files. `get` is the only stdout-printing path and is
  flagged operator-only.
- **Key-only diffs.** `diff` compares sha256 of canonical value JSON
  in-process; only key names reach stdout. `list` prints names, never values.
- **Atomic writes everywhere.** Every archive write and every materialized
  file goes through `ageutil.WriteFileAtomic` (temp + fsync + rename, unique
  temp name). A power loss or two concurrent processes can never leave a torn
  or half-written archive/file.
- **Redaction primitives.** `internal/safelog` provides an explicit `Wrap()`
  marker so secret-bearing values are redacted in error/log output.
- **Error-body discipline.** The Coolify client truncates HTTP error bodies
  to 200 bytes (a server may echo request context, including tokens) and
  strips `Authorization` on redirects.
- **UUID validation.** Coolify app/env UUIDs are validated before path
  concatenation (closes a URL-injection vector from `.wapps.yaml`).
- **Update notice can't inject escapes.** The version notice is reconstructed
  from parsed integers, never echoed from the GitHub response.
- **Git drift preflight.** `set` refuses to write if the archive is behind
  origin, preventing two operators racing into a non-fast-forward push.

---

## 6. What's committed vs gitignored

| Path | Git | Why |
|---|---|---|
| `secrets/all.enc.age` | **committed** | The encrypted source of truth. |
| `.wapps.yaml` | **committed** | Declares sources/targets/coolify mapping. |
| `secrets/rotation.log` | gitignored | Passphrase fingerprints (sensitive). |
| `.env.local`, `targets:` files | gitignored | Plaintext, regenerated by `apply`. |
| `.env.shared` (file source) | team choice | Plaintext input; gitignore unless the team wants it versioned. |

A file source (`.env.shared`) is an *input* the operator edits via
`set`/`import-env` — distinct from a consumption *target* (`.env.local`) that
the tool generates. Don't confuse the two: editing a target by hand loses the
change on the next `apply`.

---

## 7. Versioning & distribution

- Released via GoReleaser on a `vX.Y.Z` tag → GitHub release (multi-arch
  darwin/linux × amd64/arm64) + auto-updated Homebrew tap (`wappsdev/tap`).
- `cmd.Version` is ldflag-injected at release; local `go build` carries `dev`
  or `main-<sha>`.
- Released binaries print a daily update-available notice (interactive TTY
  only; opt-out `WAPPS_NO_UPDATE_CHECK=1`). Local dev builds never nag.

---

## 8. Package layout

```
cmd/
  root.go            umbrella command, git auto-sync preflight, update notice
  doctor.go          dependency/access preflight
  secrets/           the secrets subcommands (one file per command)
  coolify/           Coolify v4 API shim subcommands
  git/               git status + manual sync
internal/
  ageutil/           Encrypt/Decrypt + atomic write helpers
  config/            .wapps.yaml parse + validation
  source/            Source interface, tofu + file adapters, Merge
  coolify/           Coolify v4 REST client (typed HTTPError, UUID validation)
  tofu/              tofu output + preflight env check
  safelog/           explicit redaction (Wrap)
  git/               drift detection, pull
  updatecheck/       daily release-available check (cached, best-effort)
```

Testability pattern throughout: external effects (HTTP, subprocess, clock,
prompt) are injected via interfaces/funcs so unit tests run without a network,
a real Coolify, or a TTY.
