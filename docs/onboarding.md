# wapps-cli — Operator Onboarding

Welcome. This walks you through using `wapps-cli` for team secrets the first
time. Budget: 10 minutes including the install. If you hit something not covered
here, run `wapps doctor` first — its errors carry a copy-pasteable recovery line.

## What wapps does for you

- One CLI to read and write team secrets, from any directory
- **Values never enter a repo.** They live in Cloudflare (R2 behind a thin gate)
  and are decrypted server-side, per request, per key
- Access follows your **Google Workspace group** — no shared passphrase to
  distribute, rotate, or lose
- Every read and write is **audited** (who, when, which key — never the value)
- **AI-safe:** agents use apply-only commands and never see a raw value

There is no shared secret to hand you. Your Google account *is* your access.

## Step 1 — Install

```bash
brew tap wappsdev/tap
brew install wapps
brew install cloudflared   # required by `wapps login`
```

Verify:

```bash
wapps --version
wapps doctor        # checks binaries + gate reachability + session
```

## Step 2 — Log in

```bash
wapps login
```

This opens Cloudflare Access SSO in your browser. Sign in with your `@wapps.co`
Google account. The session token is cached at
`~/.config/wapps/session/<gate-host>.json` (mode 0600) and is **never printed**.

Check it any time:

```bash
wapps login --check     # subject + remaining TTL, no token bytes
wapps whoami            # your groups + the grants they give you
```

`whoami` is the fastest way to understand *why* a read was denied — it prints
the policy rules that matched you.

### Admin operations need a second login

Control-plane verbs (`secrets policy`, `projects rm`, `rotate-plan`)
sit behind a separate, short-lived Access application:

```bash
wapps login --write     # 15-minute admin session; kept separate from the read one
```

You only need this when editing policy or removing a project. Logging in for
admin does not evict your normal session.

## Step 3 — There is no step 3

The first time you run a secrets command in a repo, wapps asks once:

```
This repo is not bound to a project yet.
  repo:    https://github.com/wappsdev/navlun.git
  project: navlun-app
Bind them? [y/N]:
```

Answer `y` and it is recorded in your home directory — not in the repo — and
never asked again. `wapps secrets trust-repo` still exists for the explicit or
scripted form.

**What the binding is for, stated plainly.** It stops a repo's own committed
`.wapps.yaml` from unilaterally claiming a project: the config lives inside the
repo, the binding lives outside it, so a config cannot authorize itself. Seeing
*which* project is being claimed, before you answer, is the whole point.

It does **not** confine an agent — an agent can `cd` into another checkout that
is already bound. Real confinement is server-side scoping in `policy.json`. So:
agents are never prompted (a prompt an agent can answer is not a guard) and a
non-TTY session is never prompted either. Changing an *existing* binding also
still requires an explicit `trust-repo` — a new binding is routine, changing one
is not.

One repo can hold several projects (a monorepo binds each `.wapps.yaml`
separately) and one project can be reached from several repos.

## Daily use

### Start the dev server

If the repo declares `targets:`, the `predev` script handles it and `pnpm dev` is
all you need. Manually:

```bash
wapps secrets apply     # writes .env.local etc. — atomic, 0600, idempotent
pnpm dev
```

No declared target? Either write one file, or skip the file entirely:

```bash
wapps secrets env --write .env.local
wapps secrets exec -- pnpm dev
```

### Run tofu

```bash
wapps tofu plan
wapps tofu apply
```

Secrets are injected verbatim from the project resolved via the cwd
`.wapps.yaml`. Tofu inputs are stored already carrying their `TF_VAR_` name, so
nothing is prepended — a key is injected under exactly the name it is stored
under.

### Add or change a secret

```bash
wapps secrets set DB_PASSWORD
```

Masked prompt; the value goes straight to the gate and is audited. Nothing to
commit. For a value you cannot type (a long PEM, a generated token), avoid argv
and shell history:

```bash
umask 077
printf %s "$VALUE" > /tmp/v && wapps secrets set DB_PASSWORD --from-file /tmp/v && rm /tmp/v
```

### See what would change

```bash
wapps secrets sync --dry-run
```

Reports which key **names** the declared `sources:` would add or change, without
writing. Re-run without the flag to commit.

### Remove a key

```bash
wapps secrets rm STALE_KEY
```

Irreversible, so it asks you to type `yes`, and it needs a `delete` grant —
a `write` grant is deliberately not enough.

## Working from another directory

You never have to `cd` first:

```bash
wapps secrets list --project vaulter                        # registered project
wapps secrets list --config ~/Projects/navlun/.wapps.yaml   # explicit path
wapps secrets set KEY --project brand-new                   # no repo at all
```

`--project` reads `~/.config/wapps/projects.yaml`, a name→directory map you
maintain by hand. A name that isn't in it still works — for reads *and* writes.
Projects are implicit server-side (the first write creates one), so no local
checkout is needed to create or populate one. Refused in agent/CI context.

Verbs that read local `targets:` or `sources:` (`apply`, `sync`, `exec`, `env`)
always need a real `.wapps.yaml`.

## `.wapps.yaml` reference

```yaml
version: 2
project: vaulter            # the project in the gate — required

default_prefix: ""          # prepended to emitted names; default none, since
                            # keys are stored under their final env-var name

targets:                    # `apply` materializes these; gitignore them
  - path: .env.local
    prefix: ""              # per-target override

sources:                    # optional: inputs `sync` pushes INTO the gate
  - type: tofu
    workdir: .
  - type: file
    path: .env.shared
```

`sources:` are inputs, not storage — `sync` reads them and writes the values to
the gate. `targets:` are outputs your runtime consumes. Both resolve relative to
the `.wapps.yaml` directory, never to your cwd, so a `--project` run can never
scatter a plaintext `.env.local` into whatever directory you happened to be in.

## For agents

Install the skill so Claude Code / Cursor know the apply-only rules:

```bash
wapps skill install
```

Agents get `apply`, `env --write`, `exec`, `list`, `sync`. They are structurally
refused `get` (prints values), `rm` and `projects rm` (irreversible), and the
whole control plane.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `SESSION_EXPIRED` | read session lapsed | `wapps login` |
| `AUD_MISMATCH` on a policy/admin command | no write-AUD session | `wapps login --write` |
| `BINDING_UNPINNED` | declined the bind prompt, or no TTY / agent context | answer `y` next time, or run `wapps secrets trust-repo` |
| `GRANT_DENIED` | your groups don't grant that key | `wapps whoami`, then ask an admin |
| `NOT_FOUND: no .wapps.yaml found` | verb needs a project config | run inside the project, or pass `--config` |
| `AGENT_MODE_REFUSED` | value-printing or irreversible verb in an agent/CI context | run it yourself in a terminal |

```bash
wapps doctor          # full dependency + access check
wapps login --check   # both sessions at a glance
```
