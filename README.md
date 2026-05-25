# wapps-cli

Umbrella CLI for the wapps infra-tofu monorepo. Wraps:
- **age** encryption (secret archive sync)
- **Coolify v4 REST API** (gap shim for SierraJC Tofu provider limits)
- **git auto-sync** preflight (pull latest secrets/all.enc.age before any read)
- **doctor** end-to-end dependency check

## Install

```bash
brew tap wappsdev/tap
brew install wapps
```

Or:
```bash
go install github.com/wappsdev/wapps-cli@latest
```

## Usage

```bash
wapps doctor                              # check all deps + access
wapps secrets sync                        # tofu output → secrets/all.enc.age
wapps secrets get <key>                   # decrypt single key (auto git-pull)
wapps coolify deploy-app --name gateway --compose-file gateway.yaml
wapps git status                          # show drift summary
```

See DESIGN.md (forthcoming) for architecture.
