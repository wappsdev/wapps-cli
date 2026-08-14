# Changelog

All notable changes to wapps-cli. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Dates ISO 8601 (YYYY-MM-DD).

## [v0.21.0] - 2026-08-14

### Removed — BREAKING
- **The legacy git-age backend is gone.** `backend: legacy-git`, `dest:`, `WAPPS_SECRETS_PASSPHRASE`, the git-committed `secrets/all.enc.age` and everything that read or wrote it. `internal/ageutil` is deleted. A config still carrying `backend: legacy-git` now fails with a message naming the migration rather than silently writing to the gate; absent and `store` both mean the gate. `project:` is now required — it is the gate's address, and guessing it would mean guessing whose secrets to read.
- Verbs removed with it: `migrate` (import/export/tombstone — the migration is done), `rotate-master` (rotated the shared passphrase), `verify` and `diff` (both compared against the archive), and the whole `wapps git` family (it existed only to report drift on `all.enc.age`). Dead config knobs `redact_in_logs` and `require_clean_git` are gone too — nothing had ever read them.
- **The git auto-sync preflight is gone**, along with `--no-sync`. It existed to `git pull` the archive before a read. With no archive it was pure noise — it ran on *every* command and emitted `⚠ git fetch failed: … origin/main:secrets/all.enc.age` even on store-backed projects where no such file could exist. That warning is what made a working CLI look broken.

### Added
- `wapps secrets sync --dry-run` — reports which key **names** the declared sources would add (`+`) or change (`~`), then stops. This is what the retired `verify` was reaching for: `verify` compared one sha of the whole blob and could only say "drift / no drift", so on any repo with a file source it said "drift" forever. Values are compared but never printed.
- **Read verbs no longer need a repo.** `list`, `get`, `rm` and `projects` need nothing but a project name, so `--project <name>` now accepts a name with no local checkout instead of erroring with `unknown project`. Refused in agent/CI context: the repo→project pin is what stops an agent in one repo from reading another project's secrets, and an agent typing `--project` is not authority — a human on a terminal is. Verbs that read local `targets:`/`sources:` (`apply`, `sync`, `exec`, `env`) still need a real config and now say so plainly.

### Changed
- `wapps doctor` now checks what actually gates a secret read. It was still requiring the `age` binary (nothing shells out to it any more, so it sent operators to install a tool this CLI no longer uses) and asserting "are you inside the `wappsdev/infra-tofu` monorepo?" — a question that stopped meaning anything once secrets left git. Both are replaced by the secrets-gate session check, with the admin session reported but never failing the run. The R2 credential check is relabelled as the **tofu state backend**: reading a secret needs no R2 credentials on the client, so an unset `AWS_ACCESS_KEY_ID` said nothing about whether secrets work.
- Every user-facing string was rewritten. `wapps secrets` was still described as "Manage encrypted secret archive (age + Tofu state)"; `apply` as materializing "from the archive"; the root command advertised "age encryption" and "git auto-sync preflight". `docs/onboarding.md` still taught a two-step flow for obtaining and exporting a shared master passphrase. `SKILL.md` — which ships embedded in the binary and is what coding agents read — still documented both backends and told agents to check which one a repo used.
- `internal/ageutil.WriteFileAtomic` became `internal/atomicfile.Write`. The helper has nothing to do with encryption: it is what keeps a half-written `.env.local` from silently breaking a dev server. It survives; the age crypto around it does not.

## [v0.20.0] - 2026-08-14

### Added
- `wapps secrets rm <KEY>` — removes a key from the store. Until now no verb could remove one: `set` only writes, `rotate` changes a value, `migrate tombstone` works at archive level. When the thing a secret pointed at disappeared (deleted service account, retired provider, revoked integration) the entry stayed in the store forever, and bootstrap scripts that correctly refuse a "credential exists but account doesn't" state had no way out. Store backend only (legacy-git refuses with `NOT_AVAILABLE` + the sync-based recovery hint). Contract mirrors the `get`/`list` split — **name visible, value never**: refused in agent mode (`AGENT_MODE_REFUSED`, deletion is irreversible), requires typing `yes` unless `--yes`, prints only the key name, and a missing key is a named `NOT_FOUND` rather than a silent success. The gate route (`DELETE /v1/projects/{p}/keys/{KEY}`), its `key.delete` audit row, and the Go client `store.Delete` already existed and had no caller.

- `wapps secrets projects list` — the store had no way to answer "which projects exist". A project is an *implicit* namespace: no registry, it comes into being the moment the first key is written under `secrets/<name>/`, and its only constraint is a name regex. The local `~/.config/wapps/projects.yaml` is a hand-maintained name→dir map for `--project` and knows nothing about the store. So under a `projects: ["*"]` grant, a command that typed `navlun-ap` instead of `navlun-app` silently created a second project and nothing surfaced it. New gate route `GET /v1/projects` derives the names from the R2 prefix and filters them to the projects the caller holds project-metadata `read` on — a project you cannot read is a project whose *name* you do not see either. Names only, never values; agent-safe, same class as `secrets list`.
- `wapps secrets projects rm <PROJECT>` — removes a project and all of its data (every key, manifest and blob). Deliberately **not** covered by the per-key `delete` grant: deleting a project is the sum of deleting every key in it, and since projects are implicit, a mistyped name silently destroys something else. It requires the global `admin` verb plus a write-AUD session (`DELETE /v1/admin/projects/{p}`), the request body must repeat the project name, and the CLI additionally requires typing `yes`. The audit row is written **before** the deletion, not after: the gate already refuses to serve plaintext when the ledger is down, and that rule applies with more force to an irreversible delete — if audit is unavailable nothing is deleted, and a half-finished delete leaves an intent record instead of vanishing unrecorded. The append-only `pointer-events/<p>/` trail is kept: it is the tamper-evident record that the project existed, and purging it would forge a clean history. Epoch reset comes for free — the writer DO reads the epoch from the R2 `current` pointer, so a project recreated under the same name starts cleanly at epoch 1.

- `wapps login --write` — there was no way to obtain a write-AUD session, so **every control-plane verb was unreachable from the CLI** (`secrets policy show/set`, `rotate-plan`, `rewrap-kek`, and the new `projects rm`). `wapps login` only ran the SSO against the gate root, which is the READ Access application; the control plane needs the WRITE application's AUD. `--write` runs the SSO against `<gate>/v1/admin` (the WRITE app's domain: 15 min + WebAuthn) and caches the token under a separate session key, so it does not evict the long-lived read session. `wapps login --check` now reports both sessions and says plainly when the admin one is missing.

### Changed
- **`GET|PUT /v1/policy` moved to `/v1/admin/policy`.** This is a fix, not a preference. In CF Access the WRITE application covers `gw.meapps.dev/v1/admin` while the READ application covers the whole host; the more specific path wins, so a request to `/v1/policy` always arrived carrying a **read**-AUD assertion while the Worker demanded write — a permanent, unescapable `AUD_MISMATCH`. `wapps secrets policy show/set` had therefore never worked against the live gate. The Access applications are hand-created (`manage_access_apps = false` in `infra-tofu/projects/secrets-gate`), so realigning the edge would be a manual change with lockout risk; moving the route under the prefix that is already write-AUD-protected costs nothing and needs no new AUD. `/v1/policy` now falls through to 404, and a test pins it so the route cannot drift back. **The Worker must be redeployed before the new CLI's policy verbs work.**
- **policy.json gained a `delete` verb** (`worker/src/policy.ts` + the client-side mirror in `internal/policy`). `POLICY_VERBS` is now `read · write · rotate · delete · admin`. Deletion previously rode on `write`; it no longer does, and **no verb implies it** — the `rotate ⊃ write` chain does not extend to `delete`, so removal comes only from an explicit `delete` (or `"*"`) grant. Rationale: a write is recoverable (re-set the old value), a delete is not. Existing policy documents keep working unchanged — the delete route had no CLI caller before this release — but **a principal that should be able to run `wapps secrets rm` needs `delete` added to its rule**; `"*"` rules (e.g. admins) get it automatically. Policy lint rule (b) now also flags non-admin group rules that can `delete` a `*_PROD_*`-matching key.

### Fixed
- CLI errors now print the underlying cause. `clierr.Error()` dropped the wrapped error, so a failed `wapps secrets policy set /tmp/x.json` reported only `INTERNAL: read policy file /tmp/x.json` — file missing? permissions? malformed? The operator could not tell. The cause is appended (through `safelog`, so a wrapped error can never carry a raw secret).
- `npm install` works again in `worker/`. There was no lockfile, and the floating `^` ranges had drifted into a conflict: `wrangler: ^4.90.0` resolved to 4.123.0, which peer-requires `@cloudflare/workers-types@^5`, while `@cloudflare/vitest-pool-workers@^0.9.0` pulled its own `wrangler@4.44.0` (types `^4`) — `ERESOLVE`, so the worker test suite could not be installed at all in a fresh checkout. Pinned to the last coherent vitest-3 set (`vitest-pool-workers ~0.12.21`, `wrangler ~4.72.0` — the exact version pool-workers bundles, so the tree holds one wrangler —, `workers-types ~4.20260702.1`, `typescript ~5.9.3`) and **`package-lock.json` is now committed** so the ranges cannot drift again. 179 tests pass, `tsc --noEmit` clean. Not upgraded to vitest 4 / workers-types v5: `cloudflare:test` dropped the `fetchMock` export that this suite's JWKS / get-identity / Discord / B2 mocking is built on, so that upgrade is a test-harness rewrite, tracked separately.

> Note: no changelog entries were ever written for v0.17.0 – v0.19.0 (store pivot, `wapps login`, `wapps tofu`); `git log` is the source for that range.

## [v0.16.1] - 2026-07-01

### Fixed
- `wapps secrets exec` / `wapps secrets env` no longer double-prefix a key that already carries the source prefix. The `.wapps.yaml` prefix (default `TF_VAR_`) was prepended unconditionally, so an archive key stored already-prefixed (e.g. `TF_VAR_gemini_api_key`, set directly into the archive rather than derived from a Tofu output) was emitted as `TF_VAR_TF_VAR_gemini_api_key` and never reached Tofu. Prefixing is now idempotent (`envName`): a key that already starts with the prefix is emitted verbatim; bare keys still gain it; `--prefix ''` is unchanged. Fixes `wapps secrets exec -- tofu …` on mixed archives that hold both bare Tofu outputs and already-`TF_VAR_`-prefixed apply-input secrets.

## [v0.16.0] - 2026-06-28

### Added
- `wapps deploy <service>` — first-class client for the company-deploy-proxy, the only supported path to redeploy the root-level vaulter trio (proxy/db-admin/migrator) + gateway (whose scoped Coolify tokens 403 on the direct API by design). Implements the full proxy contract (validated against the server's `deploy-proxy/main.go`): `POST /v1/deploy/<service>` → `--wait` polls `/v1/deployments/<uuid>` with the exact `ci.yml` status classification (finished→ok, failed/cancelled*/error→fail), `--poll-interval`/`--timeout`, `--repo` (vaulter→vaulter-api alias), `--json`, and local `serviceNameRe` pre-validation. **9 distinct exit codes** (0 ok · 1 usage · 2 creds · 3 auth/scope · 4 CF Access edge · 5 network · 6 proxy/upstream · 7 timeout · 8 failed), with a proxy-403-vs-Cloudflare-edge-403 discriminator. Credentials (proxy token + CF Access service-token) resolve **env-first then the config-resolved archive** (`DEPLOY_PROXY_TOKEN_<REPO>` + `DEPLOY_PROXY_CF_ACCESS_*`, with legacy `PROXY_TOKEN`/`CF_ACCESS_*` fallbacks); never printed (AI-safe in human, `-v`, and `--json` output). `docs/coolify-tokens.md` documents the token model + exit codes.

## [v0.15.0] - 2026-06-09

### Added
- `wapps skill install` — installs the AI-safe `wapps-secrets` Claude Code skill, which ships embedded in the binary (`go:embed`), so a Homebrew install with no repo checkout works. Default is user-wide (`~/.claude/skills`, file-symlink into a real dir — the layout Claude Code's loader accepts); `--local --copy` writes committable files into a repo's `.claude/skills`. `wapps skill status` / `uninstall` round it out. After `brew upgrade wapps`, an existing symlink install auto-refreshes in place on the next run (gated, opt-out via `WAPPS_NO_UPDATE_CHECK`). Brew caveats prompt the one-time `wapps skill install`.

## [v0.14.1] - 2026-06-04

### Fixed
- `wapps secrets get <key>` no longer crashes when a *different* key in the archive holds a non-string value (e.g. the array `vaulter_traefik_cert_paths`). `get` previously unmarshaled the whole archive into a value-is-string struct and failed before reaching the requested key. It now reads each value as raw JSON and renders only the requested one (string verbatim, array/map/number/bool as compact JSON, null/absent as empty). `BUG-secrets-read-broken` #1.

## [v0.14.0] - 2026-06-03

### Added
- `wapps secrets` works from any cwd. All relative paths in `.wapps.yaml` (`dest`, `targets[].path`, `sources[].path`, tofu `workdir`) now resolve against the **.wapps.yaml's directory** (configRoot), not cwd. `--config <abs>/.wapps.yaml` and the new `--project <name>` flag let you `get`/`list`/`exec`/`env`/`apply`/`sync` without `cd`-ing into the project. Previously `--config` was a dead flag and the archive always resolved against cwd.
- `--project <name>` / `-p` resolves a registered project from `~/.config/wapps/projects.yaml` (name → dir) to its `.wapps.yaml`. Mutually exclusive with `--config`. Unknown project → `unknown project "x" (add to ~/.config/wapps/projects.yaml or use --config)`. `--config` gained the `-c` shorthand.
- git auto-sync preflight runs against configRoot (the project repo) when `--config`/`--project` is set, and skips cleanly when that dir isn't a git work tree.

### Changed
- `apply` writes targets under configRoot (e.g. `<project>/.env.local`), never scattering plaintext into whatever cwd you ran from. `set`/`import-env`/`sync` resolve the archive + file source + targets against configRoot too. Display/commit hints keep the raw repo-relative paths. Single-app `diff` git-ref comparison and `verify`'s tofu-output stay cwd-bound (their archive reads are config-aware; the git/tofu sides are a documented limitation, outside the from-anywhere acceptance set).

## [v0.13.2] - 2026-05-29

### Fixed
- Coolify sync now ignores per-PR preview-deployment env copies (`is_preview=true`). Coolify returns the same key twice (runtime + preview) with possibly different values; the diff now compares the archive against the RUNTIME entry only, so preview-duplicated keys no longer show perpetual false drift. A key existing only as preview is treated as absent. Prints `(skipped N preview-context entries)`. Combined filter: a current entry diffs only when `is_coolify=false AND is_preview=false`.

## [v0.13.1] - 2026-05-28

### Added
- Coolify sync skips Coolify-managed envs (`is_coolify=true`, e.g. `SERVICE_FQDN_*`/`SERVICE_URL_*`): they're read-only, filtered from both sides of the diff so a `--force` never PATCHes a read-only env (422) and a stale archive copy can't be re-added. Applies to single-app and multi-app. Prints `(skipped N Coolify-managed keys)`.
- `coolify_sync.exclude_keys` — operator deny-list of stripped key names (e.g. `SENTRY_RELEASE`) never pushed/changed/deleted, for keys owned by the deploy pipeline rather than the archive.

## [v0.13.0] - 2026-05-28

### Added
- `wapps secrets sync --target=coolify --all-apps` — multi-app push. Each app declared in `.wapps.yaml`'s new `coolify_sync.apps` block receives only the archive keys matching its `archive_prefix`, with the prefix STRIPPED (opposite of single-app `--prefix` which prepends). Unmapped keys (Tofu outputs like `lab_01_*`, other apps' keys) are excluded automatically.
- `.wapps.yaml` `coolify_sync` block: `apps[]` (uuid, name, archive_prefix) + `delete_unmanaged` (default false). Non-destructive by default — Coolify keys absent from an app's mapped set are left alone unless `delete_unmanaged: true`. Config-load rejects missing uuid/prefix, duplicate uuid, and overlapping prefixes (explicit over silent longest-match).
- Update-available notice: released binaries check GitHub once a day (cached in `~/.cache/wapps/version-check.json`) and print a one-line upgrade hint on stderr. Interactive-only, opt-out via `WAPPS_NO_UPDATE_CHECK=1`, skips local `dev`/`main-<sha>` builds. Display version reconstructed from parsed integers so a compromised release can't inject terminal escapes.
- `cmd/coolify` test coverage for `deploy-app` (collectEnvFromShell), `deploy-app-git` (shouldDeferDeploy), `update-env` (parseEnvKVs); 50.0% → 61.7%.

### Changed
- Single-app `--app` Coolify sync unchanged (whole-archive destructive mirror). `--app` and `--all-apps` are mutually exclusive.

### Fixed (hardening sweep)
- `internal/coolify`: validate UUIDs before URL concat (path-injection), truncate `HTTPError` body to 200 bytes (token leak), strip `Authorization` on redirect, `UpdateAppEnvs` loops upsert instead of append-only `/envs/bulk`.
- `internal/ageutil`: `WriteFileAtomic` uses unique temp names (concurrent-writer safe).
- `internal/source`: `WriteFileSource` fsyncs; `parseEnvFile` error no longer echoes raw line content.
- `cmd/secrets`: `rotate-master` rejects passphrases < 16 chars; `set` names the inconsistent-state recovery path; `sync_coolify` writes through the injected writer.
- `cmd/coolify`: `set-labels` refuses an empty label set (was a silent wipe).
- `cmd/doctor`: appends `/health` to a set `COOLIFY_URL`.
- `internal/git`: `HasDrift` resolves `origin/HEAD` instead of hardcoded `origin/main`.

## [v0.12.0] - 2026-05-28

### Added (diff + apply + targets)
- `wapps secrets apply` — materializes every consumption target declared in `.wapps.yaml`'s `targets:` block. Idempotent (byte-equal files keep their mtime so file watchers don't reload). Auto-invoked after `set`/`import-env`/`sync`.
- `wapps secrets diff [ref]` — key-level diff vs a git ref (default `HEAD~1`). AI-safe: values never reach stdout; change detection via in-process sha256. Refuses flag-shaped refs (argv-injection guard).
- `.wapps.yaml`: `default_prefix` + `targets:` (path, optional per-target prefix override).

## [v0.11.1] - 2026-05-28

### Fixed
- `wapps --version` flag now works. Earlier releases returned "unknown flag" because `.goreleaser.yml` injected `-X main.version` against a var that didn't exist. Now targets `cmd.Version` and wires `rootCmd.Version` for cobra's auto-generated `--version` flag.

## [v0.11.0] - 2026-05-28

### Added (T9, T10, T11, T13, T14, T15)
- `wapps secrets init [--with-file-source] [--force]` — scaffold `.wapps.yaml` + `secrets/` + gitignore for a fresh repo. Idempotent.
- `wapps doctor --for tofu` — validate only the env required by `secrets sync` (AWS_*, TF_VAR_state_passphrase, tofu binary). Decoupled from the full doctor.
- `wapps secrets sync --target=coolify --app <UUID> [--force] [--prefix <p>]` — push archive contents to a Coolify application's env vars. Dry-run by default; `--force` mirrors archive→Coolify destructively (deletes Coolify-only keys).
- `wapps secrets rotate-master` writes JSONL audit log to `<archive-dir>/rotation.log` (gitignored). Schema versioned (`schema_version: 1`), records actor, timestamp, archive paths, key count, truncated pp fingerprints.
- `.claude/skills/wapps-secrets/SKILL.md` — Claude Code skill teaching agents the apply-only pattern.
- `.cursorrules` — Cursor-flavored summary of the same rules.
- `docs/onboarding.md` — 8-step operator onboarding from brew install through rotation drill.
- MIT LICENSE.
- `internal/coolify`: `EnvEntry` struct + `ListAppEnvs`, `UpsertAppEnv`, `DeleteAppEnv` methods.
- `internal/tofu/preflight.go`: `RequiredEnvVars` + `PreflightEnv` (extracted from cmd/secrets so doctor + sync share one source of truth).

### Changed
- `SetBuildArgs` refactored to use `UpsertAppEnv(isBuildtime=true)` — one upsert implementation shared with `sync --target=coolify`.

### Fixed
- `archiveToFlatMap` slice-aliasing bug: an earlier draft pre-populated `envelope.Value=raw` which silently corrupted `raw` mid-loop via `json.RawMessage.UnmarshalJSON`'s append-on-backing-array behavior. Fix: declare a fresh envelope struct per iteration. Regression test in place.

## [v0.10.0] - 2026-05-28

### Added (T8, T12)
- `internal/ageutil.EncryptWriteAtomic` and `WriteFileAtomic` — atomic write helpers (temp + fsync + rename). Critical for catastrophic-to-corrupt files like the encrypted archive.
- `internal/safelog` package — explicit redaction via `Wrap(value)` marker for secret-bearing args. `Errorf`, `Sprintf`, `Printf`, `RedactPatterns` helpers. Defense-in-depth: `Wrap` returns `fmt.Stringer` so accidental misuse with `fmt.Errorf` still redacts.

### Changed
- All five archive-writing paths (sync legacy, sync config-driven, set, import-env, rotate-master) refactored to use `ageutil.EncryptWriteAtomic`. Previously sync and rotate-master used bare `os.WriteFile` (non-atomic).
- `rotate-master` now resolves archive path via `.wapps.yaml.dest` instead of hard-coded `secrets/all.enc.age`.

## [v0.9.0] - 2026-05-28

### Added (T7)
- `wapps secrets env --write <file>` — write env file (atomic, 0600), stdout silent. AI-safe.
- `wapps secrets env --prefix <p>` — control env var prefix (default `TF_VAR_`, pass `''` for plain).
- `wapps secrets exec -- <cmd>` — run subprocess with archive env injected via `exec.Cmd.Env`. argv-style, no shell layer. Archive entries appended after `os.Environ()` so they win on collision (operator intent).

## [v0.8.0] - 2026-05-28

### Added (T5, T6)
- `wapps secrets set <KEY>` — interactive capture command using `golang.org/x/term` for no-echo prompt. Writes to BOTH the encrypted archive AND the file source declared in `.wapps.yaml`. Pre-flight git drift check refuses to write if archive is behind origin (P7 from design doc).
- `wapps secrets import-env <file>` — bulk import an existing env file into the archive. Reuses the file-source parser for consistent quote/comment/export handling.
- `internal/source.WriteFileSource` — naive sorted KEY='VALUE' write with `# wapps-managed` header at top, 0600 mode, atomic temp+rename.

## [v0.7.0] - 2026-05-28

### Added (T4)
- `internal/source` package — `Source` interface with `Name()`, `Type()`, `Read(ctx)`. Implementations: `tofu` (shells out to `tofu output -json`), `file` (parses `.env`-style file). `Merge` helper with override tracking.
- `internal/config` package — `.wapps.yaml` parser (`Load`, `Parse`). Validates version=1, source types, per-source field requirements. Sources[N] index in error messages.
- `cmd/secrets/sync` dispatcher: no `.wapps.yaml` → legacy single-tofu path; `.wapps.yaml` present → load + multi-source merge + write to configured dest. Broken `.wapps.yaml` halts loudly (no silent fallback).

### Dependencies
- `gopkg.in/yaml.v3 v3.0.1`

## [v0.6.0] - 2026-05-28

### Fixed (T1, T2, T3)
- `secrets env` no longer crashes on non-string Tofu outputs (e.g., `vaulter_traefik_cert_paths` `[]string`). Uses `json.RawMessage` with type-aware dispatch: strings emit unquoted, non-string types emit compact JSON inside single quotes (Tofu re-parses on read).
- `git.HasDrift` works from subdirectory cwd. Previously `git rev-parse HEAD:secrets/all.enc.age` was interpreted as git-root-relative and failed with "path exists, but not" when invoked from a subdirectory. Fix: prepend `./` so git treats path as cwd-relative.

### Added
- `secrets sync` preflight env check: validates AWS_*, TF_VAR_state_passphrase before invoking `tofu output`. Emits human-readable error + copy-pasteable recovery snippet.

## [v0.5.1] - 2026-05-26

### Fixed
- `coolify.SetBuildArgs` uses POST-then-PATCH-on-409 idempotent upsert instead of PATCH-only. Earlier PATCH-only fix returned 404 when env key didn't yet exist.
- `coolify.SetBuildArgs` uses typed `*HTTPError` returned by `doBytes` + `errors.As` for status-code matching instead of brittle `strings.Contains(err.Error(), "HTTP 409")`.

(Earlier releases v0.4.x and earlier predate this changelog.)
