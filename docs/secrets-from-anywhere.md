# wapps secrets — running from anywhere (`--config` / `--project`)

> Shipped in **v0.14.0**. Implements `docs/SPEC-secrets-from-anywhere.md`.
> Reference: `docs/architecture.md` §3.

`wapps secrets` no longer requires you to `cd` into the project. Point it at a
config file or a registered project name and it works from any directory.

---

## TL;DR

```bash
# By config path — works from anywhere:
wapps secrets get coolify_token --config /abs/.../vaulter/.wapps.yaml

# By registered project name (cleaner) — one-time setup in
# ~/.config/wapps/projects.yaml, then:
wapps secrets get  coolify_token --project vaulter
wapps secrets list                --project vaulter
wapps secrets exec                --project vaulter -- terraform plan
```

In the project directory with no flag, **everything works exactly as before.**

---

## What changed

### Before (≤ v0.13.x)

The archive path resolved against the **current working directory**. So:

```bash
cd infra-tofu/projects/vaulter      # MANDATORY
wapps secrets get coolify_token     # ./secrets/all.enc.age → found
```

From anywhere else it failed:

```bash
cd /tmp
wapps secrets get coolify_token --config /abs/vaulter/.wapps.yaml
# Error: open secrets/all.enc.age: no such file or directory
```

Two reasons:

1. **`--config` was a dead flag** — declared but never read by any secrets
   command. Each command loaded a hardcoded `./.wapps.yaml` (cwd-relative).
2. Even if it had been read, `config.Load` returned `dest` verbatim and never
   joined the config-file directory — so the archive still resolved against cwd.

On top of that, `list` / `get` / `verify` bypassed even `cfg.Dest` and used a
literal `"secrets/all.enc.age"`.

Net effect: you had to `cd <project>` every single time. The "secrets feel
lost" sensation came from this — everything was always there in the three
age-encrypted, git-committed archives; you just couldn't see it unless your cwd
was right.

### Now (v0.14.0)

**All relative paths in `.wapps.yaml`** — `dest`, `targets[].path`,
`sources[].path`, and the tofu `workdir` — resolve against **the `.wapps.yaml`'s
own directory** (`configRoot`), not cwd.

```
--config /abs/vaulter/.wapps.yaml
        │  (or --project vaulter → registry → /abs/vaulter/.wapps.yaml)
        ▼
config.Load(path) → configRoot = "/abs/vaulter"   (the file's absolute dir)
        ▼
cfg.ResolveDest() = "/abs/vaulter/secrets/all.enc.age"   ← correct from any cwd
```

The resolution rule, in one line:

```
relative path  → filepath.Join(configRoot, path)
absolute path  → used verbatim (no join)
no --config    → configRoot == cwd → byte-identical to the old behavior
```

---

## The `--project` registry

`--project <name>` / `-p` is sugar over `--config`: it looks the name up in a
registry and uses that project's `.wapps.yaml`.

```yaml
# ~/.config/wapps/projects.yaml   (honors XDG_CONFIG_HOME; ~ is expanded)
projects:
  vaulter:  /Users/you/Documents/Projects/infra-tofu/projects/vaulter
  vibe-pro: /Users/you/Documents/Projects/infra-tofu/projects/vibe-pro
  lab:      /Users/you/Documents/Projects/infra-tofu/projects/lab
```

- `--project vaulter` ≡ `--config <vaulter-dir>/.wapps.yaml`.
- `--config` and `--project` are **mutually exclusive**.
- Unknown name →
  `unknown project "x" (add to ~/.config/wapps/projects.yaml or use --config)`.
- `--config` also gained a `-c` shorthand.

The registry is optional. Without it, `--config` (and the in-project default)
work as usual.

---

## Per-command behavior

| Command | Behavior under `--config`/`--project` |
|---|---|
| `get` / `list` / `env` / `exec` | Reads the archive resolved against configRoot. Fully from-anywhere. |
| `apply` | Writes targets **under configRoot** (e.g. `<project>/.env.local`) — never scatters plaintext into the cwd you ran from. |
| `sync` / `set` / `import-env` | Resolve the archive + file source + targets against configRoot. tofu `workdir` resolves too (an omitted workdir defaults to configRoot). |
| git auto-sync preflight | Runs in configRoot (the project repo); skips cleanly when that dir isn't a git work tree. |
| `diff <ref>` | Current-archive read is config-aware; the **git-ref comparison** (`git show`) stays cwd-bound — `git show` takes a repo pathspec, not a filesystem path. |
| `verify` | Archive read is config-aware; `tofu output` stays cwd-bound. |

Display strings and commit hints keep the **raw repo-relative** paths (so
`git add secrets/all.enc.age` stays copy-pasteable).

---

## Backward compatibility

- In the project directory with no flag: `configRoot == cwd`, so the resolved
  path opens the exact same file as the old cwd-relative read. Byte-identical.
- Absolute `dest`/`path` values are used verbatim (the join is skipped).
- No `projects.yaml`? Only `--project` errors; everything else is unaffected.

---

## Two intentional limitations

`diff`'s git-ref comparison and `verify`'s `tofu output` remain cwd-bound. Their
**archive read** honors `--config`, but `git show` / `tofu output` run in the
process cwd by nature. Using `--project` for those two sub-operations is outside
the from-anywhere acceptance set; documented rather than silently wrong.

---

## Operator runbook

```bash
# 1. (optional, once) register your projects:
mkdir -p ~/.config/wapps
cat > ~/.config/wapps/projects.yaml <<'YAML'
projects:
  vaulter:  /Users/you/Documents/Projects/infra-tofu/projects/vaulter
  vibe-pro: /Users/you/Documents/Projects/infra-tofu/projects/vibe-pro
  lab:      /Users/you/Documents/Projects/infra-tofu/projects/lab
YAML

# 2. use from anywhere:
wapps secrets list --project vaulter
wapps secrets get coolify_uuid_vaulter_app --project vaulter

# exec defaults to a TF_VAR_ prefix; pass --prefix '' for the bare name:
wapps secrets exec --project vaulter --prefix '' -- printenv coolify_uuid_vaulter_app
```

### Optional: a shell alias to drop the flag

```bash
# ~/.zshrc — even shorter than --project for the common get:
wsget() { wapps secrets get "$2" --project "$1"; }
# wsget vaulter coolify_uuid_vaulter_app
```

---

## Under the hood (for maintainers)

- `internal/config`: `Load` records an unexported absolute `configRoot`;
  `ResolveDest` / `Target.ResolvePath` / `ResolvedSources` / `Resolve` join
  relative paths to it. `Parse`-built configs (tests) have `configRoot == ""`
  and pass paths through unchanged.
- `cmd/secrets`: a package-global `configPathOverride` (set by
  `SetConfigPath` from root's `PersistentPreRunE`) makes `wappsConfigPath()`
  return the `--config`/`--project` path; `config.Load(that)` sets the root.
- `internal/projects`: the `~/.config/wapps/projects.yaml` loader behind
  `--project`.
- `cmd/root.go`: resolves `--project` → `cfgFile`, wires `SetConfigPath`, and
  runs the git preflight against configRoot with an `IsRepo` guard.
