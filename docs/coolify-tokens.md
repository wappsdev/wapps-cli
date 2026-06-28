# Coolify deploy token model — why `wapps deploy`, not the Coolify API

> Companion to the `infra-tofu` request `docs/deploy-tooling-gaps.md`. Saves the
> next operator/agent the discovery cost of finding out that direct Coolify
> deploys of the trio are intentionally dead.

## TL;DR

There is **one supported way** to redeploy the root-level vaulter trio
(proxy / db-admin / migrator) and the gateway from outside CI:

```bash
wapps deploy <service> --project vaulter --wait
```

The **direct Coolify API will 403** for these — by design. Don't burn time on it.

## The token model

The B1 security redesign moved the instance-admin Coolify token **server-side**
into `company-deploy-proxy` and gave each repo a **scoped token + Cloudflare
Access service-token**. As a result:

| Token | Lives | Can it deploy the trio/gateway directly via Coolify? |
|---|---|---|
| Old instance-admin token | removed | — (gone) |
| `TF_VAR_coolify_token` (repo-scoped) | repo / archive | **No — 403** (cannot even GET the migrator app) |
| `COOLIFY_API_TOKEN` (read-ish) | env | Can **read** the app (200) but **deploy → 403** |
| `company-deploy-proxy` repo token + CF Access | proxy / archive | **Yes** — the only path |

So a scoped token hitting `GET {coolify}/deploy?uuid=…` → **403**. That is
intentional (instance-admin scope was removed in B1), just not obvious. The
proxy holds the privileged token server-side and enforces per-repo scope +
network admission (Cloudflare Access).

## The deploy-proxy contract (what `wapps deploy` speaks)

```
POST  {EP}/v1/deploy/{service}     → {"deployment_uuid": "..."}   (403 if out of scope)
GET   {EP}/v1/deployments/{uuid}   → {"status": "finished|failed|cancelled*|error|…"}
```

Three headers on every request:

- `Authorization: Bearer <repo-scoped proxy token>`
- `CF-Access-Client-Id: <service-token id>`
- `CF-Access-Client-Secret: <service-token secret>`

The proxy resolves service **name → Coolify UUID** and enforces scope, so a
client only ever sends a service name. `wapps deploy` and the apps'
`.woodpecker/ci.yml` use the **same** contract — one definition, two callers.

`finished` → success; `failed` / `cancelled*` / `error` → failure; anything
else keeps polling (15s) until the `--timeout` deadline (default 1200s).

## Exit codes

`wapps deploy` returns a distinct code so CI / scripts can branch precisely:

| Code | Class | When |
|---|---|---|
| 0 | ok | triggered (no `--wait`), or `--wait` reached `finished` |
| 1 | usage | unknown `--repo`, bad service-name shape, wrong arg count (no network) |
| 2 | creds | proxy token and/or CF Access id+secret unresolved (env, archive) |
| 3 | auth/scope | proxy `401 unauthorized` or `403 not-allowlisted` (has the proxy `{"error":...}` JSON) |
| 4 | CF Access | blocked at the Cloudflare edge (403/302/5xx with **no** proxy JSON) — CF Access creds wrong/missing |
| 5 | network | DNS / refused / TLS / client timeout — the call never completed |
| 6 | proxy/upstream | proxy 400/502/404, or a 200 with an empty/invalid `deployment_uuid` |
| 7 | timeout | `--wait` deadline elapsed, last status non-terminal |
| 8 | failed | `--wait` saw `failed` / `error` / `cancelled*` |

The **3-vs-4 discriminator**: a response body that parses to the proxy's
`{"error":...}` JSON reached Go (auth/scope → 3); anything else (HTML / redirect
/ CF block page) was stopped at the edge (CF Access → 4).

## Where `wapps deploy` gets the three credentials

Resolved **env-first, then the config-resolved archive** (never printed). Per
credential the candidate keys are tried in order, env tier fully before archive:

| Credential | Keys (env tier, then archive tier — first non-empty wins) | Tofu source |
|---|---|---|
| Proxy token (repo-scoped) | `DEPLOY_PROXY_TOKEN_<REPO>`, `DEPLOY_PROXY_TOKEN`, `PROXY_TOKEN` | `deploy_proxy_repo_tokens["vaulter-api"]` (vaulter state) |
| CF Access client id | `DEPLOY_PROXY_CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_ID` | `deploy_proxy_cf_access_client_id` (platform state) |
| CF Access client secret | `DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET`, `CF_ACCESS_CLIENT_SECRET` | `deploy_proxy_cf_access_client_secret` (platform state) |
| Endpoint | `--ep` flag, `DEPLOY_PROXY_EP` | — (default `https://deploy-proxy.meapps.dev`) |

`<REPO>` is the `--repo` value upper-cased with `-`→`_` (e.g. `--repo vaulter` →
`DEPLOY_PROXY_TOKEN_VAULTER`). The archive is selected by `--project`/`--config`
(config-dir-relative, works from any cwd). With no archive creds it uses env —
how CI runs it. The legacy `PROXY_TOKEN` / `CF_ACCESS_*` names (today's
`.woodpecker/ci.yml`) are accepted as fallbacks so the command works in the
current and the refactored pipeline.

> **Note — tier-3 (auto `tofu output`) is intentionally not implemented.** The
> spec proposes a third tier that shells out to `tofu -chdir=<state> output` for
> the two states. That would couple `wapps` to the operator's infra-tofu
> checkout layout (two specific state dirs) — fragile and machine-specific. The
> **archive (via the P2 mirror) is the operator single-source**; env covers CI.
> If neither has a value, the exit-2 message names the missing key and the
> operator runs `tofu output` themselves once. Adding tier-3 later is additive.

Mirroring the four `DEPLOY_PROXY_*` keys into the vaulter archive (so
`--project vaulter` resolves them with no env) is the `infra-tofu` **P2**
follow-up.

## Usage

```bash
# From anywhere, creds resolved from the vaulter archive (after P2 mirror):
export WAPPS_SECRETS_PASSPHRASE="$(security find-generic-password -w -s 'Wapps Master')"
wapps deploy migrator --repo vaulter --project vaulter --wait
wapps deploy gateway  --repo vaulter --project vaulter --wait

# CI / quick shell run, creds from env (no archive needed):
DEPLOY_PROXY_TOKEN_VAULTER=… DEPLOY_PROXY_CF_ACCESS_CLIENT_ID=… \
DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET=… wapps deploy migrator --repo vaulter --wait

# Machine-readable (CI / agents):
wapps deploy auth --repo vaulter --json
# {"service":"auth","repo":"vaulter","deployment_uuid":"…","outcome":"triggered","exit_code":0}
```

The migrator run is idempotent — a failed attempt leaves the previous healthy
container in place.
