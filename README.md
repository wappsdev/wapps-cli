# wapps-cli

Umbrella CLI for the wappsdev estate. Wraps:

- **the secrets gate** — values are decrypted server-side and fetched on demand;
  nothing encrypted is ever stored in a repo
- **Tofu** — `wapps tofu` runs it with the project's secrets injected
- **Coolify v4 REST API** — gap shim for the SierraJC Tofu provider's limits
- **deploys** — through the company deploy-proxy
- **doctor** — end-to-end dependency + access check

Secrets are AI-safe by construction: agents use apply-only commands and never
see a raw value. Value-printing and irreversible verbs refuse to run in an
agent/CI context.

## Install

```bash
brew tap wappsdev/tap
brew install wapps
```

Or:

```bash
go install github.com/wappsdev/wapps-cli@latest
```

## First run

```bash
wapps doctor              # check deps + access
wapps login               # CF Access SSO (needs cloudflared)
wapps secrets trust-repo  # pin this repo to its project (one-time, TTY)
```

## Usage

```bash
wapps secrets list                        # key names (never values)
wapps secrets apply                       # write declared targets (.env.local, …)
wapps secrets exec -- pnpm dev            # inject secrets into a subprocess
wapps tofu plan                           # tofu with TF_VAR_* injected
wapps secrets set <KEY>                   # masked prompt → straight to the gate
wapps secrets sync --dry-run              # what would change, by name
wapps secrets projects list                # which projects exist
wapps deploy gateway --wait               # deploy through the proxy
```

Every read verb takes `--project <name>` or `--config <path>/.wapps.yaml`, so you
never have to `cd` into the project first.

## Docs

- [onboarding.md](docs/onboarding.md) — first 10 minutes, operator-facing
- [architecture.md](docs/architecture.md) — how the system works
- [CHANGELOG.md](CHANGELOG.md) — what shipped when
