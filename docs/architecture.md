# wapps-cli — Architecture & Reference

> How the system works. For getting started, see [onboarding.md](onboarding.md);
> for what shipped when, see [CHANGELOG.md](../CHANGELOG.md).

`wapps` is a team secret manager built on three principles:

- **Nothing encrypted in the repo.** The source of truth is a server-side store
  (Cloudflare R2 behind a thin Worker gate). Values are decrypted **on the
  server**, per request, per key — the client holds no key material. Sharing a
  secret is a write to the gate, not a `git push`.
- **AI-safe.** No command prints a secret *value* to stdout on the default path.
  Agents apply secrets without ever seeing them. The value-printing verb (`get`)
  and the irreversible ones (`rm`, `projects rm`) are structurally refused in an
  agent/CI context.
- **Identity, not a shared passphrase.** Access follows your Google Workspace
  group via Cloudflare Access. There is no team-wide secret to distribute or
  rotate, and every read and write is audited by principal.

---

## 1. Data model

There are two directions: **ingest** (sources → store) and **materialize**
(store → consumers). The store sits in the middle and is remote.

```
   INGEST                        THE GATE                   MATERIALIZE
 ┌───────────────┐                                     ┌──────────────────────┐
 │ tofu output   │──┐                                   │ targets: .env.local  │ ← apply / env --write
 │ (tofu source) │  │      ┌───────────────────────┐    │          apps/api/.env│
 └───────────────┘  ├─────▶│  gw.meapps.dev        │────┤                      │
 ┌───────────────┐  │      │  R2 + server-decrypt  │    │ coolify: app envs    │ ← sync --target=coolify
 │ .env.shared   │──┘      │  policy.json authz    │    │          (per app)   │
 │ (file source) │         └───────────────────────┘    └──────────────────────┘
 └───────────────┘              ▲          │
                                │          └─▶ exec -- <cmd>  (env injected, no file)
              set / import-env ─┘              get / list      (read)
```

- **Sources** are *inputs* — where values come from when you run `sync`. Declared
  in `.wapps.yaml` `sources:`. Two kinds: `tofu` (shells out to `tofu output
  -json`) and `file` (parses a `.env`-style file). They are not storage.
- **The store** holds each key as its own encrypted blob, referenced by a
  per-project manifest chain. Each write produces a new **epoch** (epoch+1,
  chained by hash), serialized by a per-project Durable Object. Values move as
  plaintext over TLS inside Cloudflare Access; the client never unwraps anything.
- **Consumers** are *outputs* — where plaintext is materialized. Three kinds:
  `targets:` (local files like `.env.local`), Coolify app envs, and ephemeral
  subprocess env (`exec`).

The mental model: **`set`/`import-env`/`sync` write the store; `apply`/`env`/
`exec`/`sync --target` read it.** A write never materializes plaintext anywhere
except the `targets:` the operator declared.

Values only ever exist in process memory on the client. Nothing is cached to
disk — there is no offline mode, and a transport failure is a loud
`NETWORK_REQUIRED`, not a silent stale read.

## 2. `.wapps.yaml` — full schema

Lives at the repo root. Read from the current working directory unless
`--config`/`--project` points elsewhere.

```yaml
version: 2                          # 1 and 2 parse; 2 is what init writes
project: vaulter                    # REQUIRED — names the project in the gate
default_prefix: ""                  # prefix used by `apply` targets (default "")

sources:                            # INPUT — optional (only `sync` reads these)
  - type: tofu
    workdir: .                      # dir holding .tf files
    prefix: "TF_VAR_"               # reserved (applied at env-emit time)
  - type: file
    path: .env.shared               # required for file sources

targets:                            # OUTPUT (local files) — optional
  - path: .env.local                # uses default_prefix
  - path: terraform.tfvars.json
    prefix: "TF_VAR_"               # per-target override (nil = use default)

profiles:                           # optional named key subsets
  ci: [DEPLOY_TOKEN, DB_URL]

coolify_sync:                       # OUTPUT (Coolify multi-app) — optional
  delete_unmanaged: false           # default: never delete Coolify-only keys
  exclude_keys:                     # stripped names never pushed/diffed
    - SENTRY_RELEASE                # (deploy-pipeline-owned, perpetual drift)
  apps:
    - uuid: vaesbm45up4jyk7hhk77ka74
      name: kreeva-web              # comment-only, for readability
      archive_prefix: "KREEVA_WEB_" # matched keys pushed with prefix STRIPPED
```

Validation runs at load time (typos fail loudly, not silently):
- `version` other than 1 or 2 → error.
- missing `project` → error. It is the gate's address; guessing it would be
  guessing whose secrets to read.
- `backend: legacy-git` → error naming the migration. The field is still parsed
  so old files produce that message instead of silently writing to the gate;
  absent or `store` both mean the gate.
- source field mismatch (e.g. `tofu` with `path`) → error.
- `targets[].path`: required, no duplicates, no `..` (path traversal).
- `coolify_sync.apps[]`: `uuid` + `archive_prefix` required, no duplicate
  uuid, **no overlapping prefixes** (`ROYCO_` vs `ROYCO_API_` is an error —
  explicit beats silent misrouting of a secret to the wrong app).

`sources:` and `targets:` are the only reason a verb needs this file at all.
Read verbs that need nothing but the project name (`list`, `get`, `rm`,
`projects`) accept a bare `--project <name>` and work with no local checkout.

---

## 3. Command surface

### `wapps secrets`

| Command | Direction | What it does |
|---|---|---|
| `init [--project-name N] [--force]` | — | Scaffold `.wapps.yaml`. Writes nothing else — there is no local store. |
| `trust-repo` | — | Pin this repo → project in your home dir. TTY-only; what confines an agent to one project. |
| `sync [--dry-run]` | ingest | Read sources, merge, write to the store in ONE epoch. `--dry-run` reports which key names would be added/changed, without writing. |
| `sync --target=coolify --app <uuid> [--force]` | materialize | Single-app: push the WHOLE key set to one app, destructive mirror. Dry-run unless `--force`. |
| `sync --target=coolify --all-apps [--force]` | materialize | Multi-app: each `coolify_sync.apps` entry gets its prefix-matched subset (stripped), non-destructive by default. |
| `set <KEY> [--from-file F]` | ingest | Capture one secret (no-echo prompt) and PUT it. Server resolves CAS. |
| `import-env <file>` | ingest | Bulk-import a `.env` in one atomic epoch. Reports which names it overwrote. |
| `rm <KEY>` | ingest | Remove a key. Irreversible → needs a `delete` grant (not `write`), a typed `yes`, and is refused in agent mode. |
| `apply` | materialize | Write every `targets:` file atomically. Idempotent (byte-equal → no mtime touch). |
| `env [--write <f>] [--prefix P]` | materialize | Emit `export` lines. `--write` → file (silent); no flag → stdout (operator-only). |
| `exec -- <cmd>` | materialize | Run a subprocess with the project's env injected. No file, no stdout leak. |
| `get <KEY>` | read | Print one value to stdout. **Operator-only** (breaks the AI-safe rule by design). |
| `list` | read | Print key names (no values). Filtered server-side to what you may read. |
| `projects list` | read | Which projects exist in the store, filtered to what you may see. Names only. |
| `projects rm <P>` | admin | Remove a project and all its data. Needs the global `admin` verb + write-AUD. |
| `policy show \| set \| lint` | admin | Read/edit `policy.json` (the authz document). Write-AUD; refused in agent mode. |
| `rotate-plan` | admin | Audit-ledger oracle: what must rotate after an offboard. |
| `status` | read | Machine-readable gate/session state. Safe in every mode. |

### Other top-level

| Command | What it does |
|---|---|
| `login [--write] [--check]` | CF Access SSO. `--write` targets the admin app (15 min, separate session). `--check` prints both sessions, never token bytes. |
| `whoami` | The gate's view of you: groups + effective grants. The fastest answer to "why was that denied?". |
| `doctor [--for tofu]` | Dependency + access preflight. |
| `tofu <args>` | Run tofu with the project's secrets injected as `TF_VAR_*`. |
| `deploy <service>` | Deploy through the company deploy-proxy. |
| `dr <...>` | Disaster recovery against the B2 ciphertext replica. |
| `coolify <...>` | Coolify v4 API shim (deploy-app, deploy-app-git, set-labels, update-env, import-app). |
| `skill install` | Install the AI-safe `wapps-secrets` skill for coding agents. |
| `--version` | Print version (ldflag-injected on releases, `dev`/`main-<sha>` locally). |

Persistent flags: `--verbose`, `--config`/`-c`, `--project`/`-p`.

### Running from any cwd (`--config` / `--project`)

Two flags mean you never have to `cd` into a project:

- `--config <path>/.wapps.yaml` — load that config and resolve all its relative
  paths (`targets`, `sources`) against **its own directory** (configRoot), not
  cwd. This is what stops a `--project` run from writing a plaintext `.env.local`
  into whatever directory you happened to be in.
- `--project <name>` / `-p` — looks `<name>` up in
  `~/.config/wapps/projects.yaml` (a `name: dir` map) and uses
  `<dir>/.wapps.yaml`. Mutually exclusive with `--config`.

If the name is **not** in the registry it is still accepted for the read verbs
that need nothing but a project name (`list`, `get`, `rm`, `projects`) — the gate
only needs the name, so no local checkout is required. That form is refused in
agent/CI context: the repo→project pin exists precisely to stop an agent in one
repo from reaching another project, and an agent typing `--project` is not
authority. A human on a terminal is.

Verbs that read `targets:`/`sources:` (`apply`, `sync`, `exec`, `env`) always
need a real config and say so plainly when there isn't one.

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
- **Preview entries** (`is_preview=true`) — Coolify returns the same key twice
  when it's defined for both runtime and preview deployments. Only the runtime
  copy is managed; the preview entry is ignored (per-entry, not per-key, so the
  key still diffs against its runtime value). Universal.

Combined rule: a live Coolify entry is eligible for the diff only when
`is_coolify == false AND is_preview == false`.

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
- **Atomic writes everywhere.** Every materialized file goes through
  `atomicfile.Write` (temp + fsync + rename, unique temp name). A power loss or
  two concurrent processes can never leave a torn `.env.local` — a half-written
  env file breaks a dev server silently.
- **Atomic writes server-side too.** A store write is one epoch or none: the
  per-project Durable Object serializes commits and the manifest chain advances
  by hash, so there is no half-applied `import`.
- **Redaction primitives.** `internal/safelog` provides an explicit `Wrap()`
  marker so secret-bearing values are redacted in error/log output.
- **Error-body discipline.** The Coolify client truncates HTTP error bodies
  to 200 bytes (a server may echo request context, including tokens) and
  strips `Authorization` on redirects.
- **UUID validation.** Coolify app/env UUIDs are validated before path
  concatenation (closes a URL-injection vector from `.wapps.yaml`).
- **Update notice can't inject escapes.** The version notice is reconstructed
  from parsed integers, never echoed from the GitHub response.
- **No client-side key material.** The gate decrypts; the CLI holds no KEK, does
  no unwrapping, and verifies no signatures. Losing a laptop leaks a session, not
  the estate.
- **Audit-before-destroy.** An irreversible server-side op writes its audit row
  *before* acting. If the ledger is unavailable, the delete does not happen —
  the same fail-closed rule the gate already applies to plaintext reads.

---

## 6. What's committed vs gitignored

| Path | Git | Why |
|---|---|---|
| `.wapps.yaml` | **committed** | Names the project; declares sources/targets/coolify mapping. |
| `.env.local`, `targets:` files | gitignored | Plaintext, regenerated by `apply`. |
| `.env.shared` (file source) | team choice | Plaintext input; gitignore unless the team wants it versioned. |

**No secret ciphertext is committed, ever.** There is no encrypted archive to
share, pull, or leave behind in history — a repo carries only the project's
*name*. This is the single biggest change from the pre-v0.21 design, where a
a git-committed encrypted archive under one shared passphrase was the source
of truth.

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
  root.go            umbrella command, config resolution, update notice
  login.go           CF Access SSO (read + --write admin session)
  doctor.go          dependency/access preflight
  secrets/           the secrets subcommands (one file per command)
  coolify/           Coolify v4 API shim subcommands
  deploy/            deploy-proxy client
internal/
  store/             the gate client — the ONLY read/write abstraction
  session/           CF Access sessions, gate URLs, mTLS transport
  config/            .wapps.yaml parse + validation
  source/            Source interface, tofu + file adapters, Merge
  policy/            client-side policy.json validation + lint
  rotation/          rotation worklist engine + ledger
  binding/           repo→project pin store
  agentmode/         agent/CI detection + per-verb gating
  clierr/            typed CLI errors with recovery lines
  atomicfile/        all-or-nothing file writes (targets)
  coolify/           Coolify v4 REST client (typed HTTPError, UUID validation)
  tofu/              tofu output + preflight env check
  safelog/           explicit redaction (Wrap)
  updatecheck/       daily release-available check (cached, best-effort)
worker/              the gate itself (TypeScript, Cloudflare Worker)
```

Testability pattern throughout: external effects (HTTP, subprocess, clock,
prompt) are injected via interfaces/funcs so unit tests run without a network,
a real Coolify, or a TTY.
