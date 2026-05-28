# PROGRESS

**Status:** B.1 + B.2 + B.3 codebase complete · v0.11.1 released · awaiting first teammate rollout
**Last Updated:** 2026-05-28

## 🟢 Recent (this sprint)

- v0.11.1 — `wapps --version` flag wired through cobra; fixed `.goreleaser.yml` ldflag target (was no-op `main.version`, now `cmd.Version`).
- v0.11.0 — B.2 + B.3 closed: `secrets init` scaffolder, `doctor --for tofu`, `secrets sync --target=coolify`, `rotate-master` audit log JSONL, AI skill + .cursorrules, operator onboarding doc, MIT LICENSE.
- v0.10.0 — B.1 polish: `internal/ageutil` atomic writes (fsync+rename), `internal/safelog` package with explicit Wrap pattern.
- v0.9.0 — B.1 Step 4 (T7): `env --write` and `exec --` apply primitives (AI-safe — zero stdout).
- v0.8.0 — B.1 Step 3 (T5+T6): `secrets set` (no-echo capture, dual-write archive + file source), `import-env` bulk.
- v0.7.0 — B.1 Step 2 (T4): `internal/source` package with `Source` interface, `tofu` + `file` adapters, `internal/config` `.wapps.yaml` parser, `sync` config-driven dispatch.
- v0.6.0 — B.1 Step 1 (T1+T2+T3): env Bug 1 fix (non-string Tofu outputs), git drift cwd fix, sync preflight env check.
- Pre-rollout: Coolify SetBuildArgs POST-then-PATCH idempotent upsert + typed HTTPError (PR #1).

Counts: ~17 atomic commits on main, 8 PRs shipped, ~169 tests, v0.5.1 → v0.11.1.

## 🔴 Open items

None in the eng-review T1-T15 backlog. Everything planned is shipped.

## 🔮 Next up

**Operational (not code):**
- Run first teammate onboarding session — observe where they get stuck (Codex: "watch don't demo"). Update `docs/onboarding.md` based on the gaps you see, not on your guess.
- Run rotation drill once for real on the vaulter archive. Verify audit log entry written, distribute new pp via Signal E2E to one teammate, confirm both old archive history and new pp behave as expected.
- Bootstrap platform repo (`~/Documents/Projects/infra-tofu/projects/platform/`). Use `wapps secrets init` template, populate from `tofu output -json`, commit `secrets/all.enc.age` to infra-tofu. This unlocks Coolify token + GH PAT for downstream repo bootstraps.
- Roll out to vaulter-api (file-source only). Use `wapps secrets init --with-file-source`, `import-env` from existing `.env` if any.

**Code (only if rollout surfaces a need — do not pre-build):**
- Capture-first daemon (office-hours Approach C) — clipboard auto-capture, post-commit hooks. Defer until at least one teammate explicitly asks for it.
- Per-tier passphrase escalation (`--prod-pp` / `--lab-pp`) — defer until contractor or compliance scenario forces it.
- GH Actions secrets as TARGET (push direction) — defer until needed.
- Multi-archive rotation (rotate-master --all-archives) — defer until >1 archive exists in real use.

**Public release (post-rollout):**
- README polish for v1.0.0
- CONTRIBUTING.md
- Anonymize internal team-specific examples
- Repo public toggle

## Design artifacts

- `~/.gstack/projects/wappsdev-wapps-cli/adnankurt-main-design-20260528-020132.md` (design doc, 8.5/10)
- `~/.gstack/projects/wappsdev-wapps-cli/adnankurt-main-eng-review-test-plan-20260528-032137.md` (eng review test plan)
- `~/.gstack/projects/wappsdev-wapps-cli/learnings.jsonl` (14 cross-model + observed learnings)

## Distribution status

- Brew tap: `wappsdev/tap/wapps` at v0.11.1
- Local binary: `~/.local/bin/wapps` (main HEAD with ldflag); shadows brew installed v0.5.1
- GoReleaser pipeline: working (60s typical run), multi-arch linux/darwin × amd64/arm64
