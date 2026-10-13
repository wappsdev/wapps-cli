# wapps-cli

This repository holds the **secrets gate**: the Cloudflare Worker
(`secrets-gate`, `gw.meapps.dev`) under [`worker/`](worker/). It decrypts
secret values server-side, after CF Access and Google-group policy checks.
Nothing encrypted is stored in a project repository.

The `wapps` CLI is no longer here. It moved to the private `wapps-platform`
repository (`crates/cli`), and it is installed from there. The Go CLI and the
earlier Rust copy were removed from this repository on 2026-10-13. The git
history still contains them.

## Worker

```bash
cd worker
npm ci
npm run typecheck
npm test            # local workerd pool; no Cloudflare account needed
```

Deploys come only from an admin workstation, never from CI.

## Docs

- [architecture.md](docs/architecture.md) — how the system works
- [CHANGELOG.md](CHANGELOG.md) — what shipped when
