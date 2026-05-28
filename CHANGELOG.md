# Changelog

All notable changes to wapps-cli. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Dates ISO 8601 (YYYY-MM-DD).

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
