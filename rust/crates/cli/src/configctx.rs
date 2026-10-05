// configctx carries the "which `.wapps.yaml`" question and the BINDING gate
// derived from it.
//
// ORACLE: cmd/root.go (resolveProjectFlag), cmd/secrets/sync.go
// (wappsConfigPath, loadOrNil), cmd/secrets/store_backend.go
// (requireStoreConfig, storeProject), cmd/secrets/agentgate.go
// (checkRepoBinding, repoIdentity, bindPromptText, syncReadsBlock).
//
// The two gates `exec`/`apply` sat behind:
//
//   1. `--project` does NOT bypass the config requirement. get/set need only
//      the project NAME (storeProject); exec/apply READ targets/sources, so
//      the local file is REQUIRED (requireStoreConfig).
//   2. With a config and no `--project`, an unpinned binding asks for inline
//      CONFIRMATION on the human/TTY path.
use crate::binding;
use crate::clierr::{Code, Error};
use crate::gostrconv;
use crate::projects;
use crate::wappsyaml::{self, WappsYaml};
use std::io::Write;
use std::path::{Path, PathBuf};

/// WAPPS_YAML_PATH is the default (cwd-relative) file name used when there is
/// no --config/--project override.
pub const WAPPS_YAML_PATH: &str = ".wapps.yaml";

/// Ctx is the resolved config context.
///
/// `project_override`: `--project <name>` was GIVEN but is NOT in the
/// registry. The store needs only the name (list/get/rm/projects never look at
/// a local file), so such a call works without a repo. It is NOT enough for
/// exec/apply, which give their own clear "no .wapps.yaml found" errors.
pub struct Ctx {
    pub config_path: Option<PathBuf>,
    pub project_override: Option<String>,
}

/// MUTUALLY_EXCLUSIVE is the ONE text source of the `--config` + `--project`
/// refusal.
///
/// A CONSTANT, not a function, because its two callers WRAP it DIFFERENTLY and
/// the difference was MEASURED:
///
///   * dispatch (main.rs) → `CmdError::Plain`. In Go this error comes back from
///     the root's `PersistentPreRunE` as a PLAIN `fmt.Errorf`, so the human
///     path prints "Error: <sentence>" with NO code prefix and NO recovery
///     line. The first fix used `Error::new(Code::Internal, ...)` here; the
///     agent path became EQUAL but the HUMAN path stayed divergent
///     (differential DIFFERENT=1): Rust printed "Error: INTERNAL: ... → run
///     wapps doctor". `Plain` is already wrapped as Internal in agent mode, so
///     the ENVELOPE stays right too.
///   * `Ctx::resolve` → a structured `Error`. That path exists for
///     programmatic/test calls (like Go's own check in `resolveProjectFlag`)
///     and is UNREACHABLE from the field because dispatch catches it first.
///
/// Had the text been COPIED to two places, one would drift from the other.
pub const MUTUALLY_EXCLUSIVE: &str = "--config and --project are mutually exclusive";

impl Ctx {
    /// resolve turns the --config/--project flags into a context.
    ///
    /// `--project` is TRIED against the registry to resolve to
    /// <dir>/.wapps.yaml. Not being in the registry is NOT an ERROR: the name is
    /// carried as project_override.
    pub fn resolve(config: Option<&str>, project: Option<&str>) -> Result<Ctx, Error> {
        if let Some(c) = config {
            if project.is_some() {
                return Err(Error::new(Code::Internal, MUTUALLY_EXCLUSIVE));
            }
            let abs = abs_path(Path::new(c))
                .map_err(|e| Error::new(Code::Internal, format!("resolve --config path: {e}")))?;
            return Ok(Ctx {
                config_path: Some(abs),
                project_override: None,
            });
        }
        match project {
            None => Ok(Ctx {
                config_path: None,
                project_override: None,
            }),
            Some(name) => match projects::resolve(name) {
                Ok(dir) => Ok(Ctx {
                    config_path: Some(Path::new(&dir).join(WAPPS_YAML_PATH)),
                    project_override: None,
                }),
                // NOT in the registry: continue with the name itself.
                Err(_) => Ok(Ctx {
                    config_path: None,
                    project_override: Some(name.to_string()),
                }),
            },
        }
    }

    /// path returns the `.wapps.yaml` path to load: the override when set,
    /// else the cwd-relative default.
    pub fn path(&self) -> PathBuf {
        match &self.config_path {
            Some(p) => p.clone(),
            None => PathBuf::from(WAPPS_YAML_PATH),
        }
    }

    /// load_or_none returns None when the file DOES NOT EXIST and propagates
    /// parse errors LOUDLY. Telling "no file" from "broken file" is the
    /// difference between silently taking another path and showing the
    /// operator their typo.
    pub fn load_or_none(&self) -> Result<Option<WappsYaml>, Error> {
        let p = self.path();
        if !p.exists() {
            return Ok(None);
        }
        match wappsyaml::load(&p) {
            Ok(c) => Ok(Some(c)),
            Err(e) => Err(Error::new(Code::Internal, e)),
        }
    }

    /// store_project is for the verbs that need ONLY the project NAME
    /// (list/get/rm/projects): reaching the gate needs NO local `.wapps.yaml`,
    /// directory or repo.
    ///
    /// When `--project` did not resolve to a directory the NAME ITSELF is
    /// enough; otherwise the local config is loaded and its ABSENCE is an error.
    ///
    /// This must stay separate from `require_store_config`, which exec/apply
    /// use: those verbs READ `targets`/`sources`, so the local file is REQUIRED.
    pub fn store_project(&self, verb: &str) -> Result<String, Error> {
        if let Some(p) = &self.project_override {
            return Ok(p.clone());
        }
        Ok(self.require_store_config(verb)?.project)
    }

    /// require_store_config loads the local `.wapps.yaml` and REQUIRES it to
    /// exist. Verbs that READ targets or sources (apply/sync/exec/env) call
    /// it; verbs that need only the project NAME (list/get/rm/projects) do not.
    ///
    /// `verb` places the error ("apply: ...").
    pub fn require_store_config(&self, verb: &str) -> Result<WappsYaml, Error> {
        match self.load_or_none()? {
            Some(c) => Ok(c),
            None => Err(Error::new(Code::NotFound, format!("{verb}: no .wapps.yaml found"))
                .with_recovery(
                    "run this from a project directory, or pass --config <path>/.wapps.yaml (see 'wapps secrets init')",
                )),
        }
    }
}

fn abs_path(p: &Path) -> std::io::Result<PathBuf> {
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    Ok(std::env::current_dir()?.join(p))
}

/// check_repo_binding verifies that a config's repo→project binding is
/// pinned in the TRUSTED home dir (SPEC §7.1 trust-repo).
///
/// `errw` is where the human path's confirmation dialogue and success line go
/// (os.Stderr in Go). `ask` receives the repo identity and the loaded config,
/// so the prompt can show every source a sync would read.
pub fn check_repo_binding<W: Write>(
    ctx: &Ctx,
    is_agent: bool,
    stdin_is_tty: bool,
    errw: &mut W,
    ask: &dyn Fn(&str, &WappsYaml, &mut W) -> bool,
) -> Result<(), Error> {
    // A bare `--project <name>` (not in the registry): there is NO repo to
    // bind. For a HUMAN this names the target explicitly on the command line,
    // not the confused-deputy case the pin guards. For an AGENT it is: the pin
    // exists precisely so that an agent in repo A cannot read project B, and
    // being able to type `--project` does NOT authorize it → fail-closed.
    if let Some(p) = &ctx.project_override {
        if is_agent {
            // The recovery line is overridden: there is NO repo to pin, so the
            // default "run trust-repo" would be meaningless here.
            return Err(Error::new(
                Code::BindingUnpinned,
                format!(
                    "--project {} names a project with no local repo; an agent may not target a project this way",
                    crate::gojson::quote(p)
                ),
            )
            .with_recovery("a human must run this in a terminal, or work inside the project's repo"));
        }
        return Ok(());
    }

    // No config (or an unreadable one): no binding check. A parse error is
    // SWALLOWED here, as Go swallows it, and comes back loudly one step later
    // from require_store_config.
    let Ok(Some(cfg)) = ctx.load_or_none() else {
        return Ok(());
    };

    // Service principal (CI): when the CF Access service-token PAIR is set in
    // the env, the repo-pin check is SKIPPED. trust-repo (TTY) is impossible in
    // a fresh CI container; without this exemption EVERY step that consumes
    // the store would die with BINDING_UNPINNED. With only HALF of the pair set
    // there is NO bypass; fail-closed stays as is.
    //
    // SECURITY CONSTRAINT: this exemption removes the per-repo confused-deputy
    // containment; only the server-side per-key policy is left. It is safe
    // ONLY while service tokens are PER-PROJECT scoped.
    if service_token_pair_set() {
        return Ok(());
    }

    let repo_id = repo_identity(&cfg);
    let fp = binding::fingerprint(&repo_id);

    let path = binding::default_path().map_err(|e| Error::new(Code::Internal, e))?;
    let mut store = binding::load(&path)
        .map_err(|e| Error::new(Code::Internal, format!("load repo pins: {e}")))?;

    match store.check(&fp, &cfg.project) {
        Ok(()) => return Ok(()),
        Err(binding::CheckError::Mismatch) => {
            // A MISMATCH is NEVER resolved inline. The config claiming a
            // project OTHER than the pinned one is the very reason the pin
            // exists. A new binding is ordinary and harmless; CHANGING a
            // binding takes a deliberate decision.
            return Err(Error::new(
                Code::BindingUnpinned,
                format!(
                    "repo is pinned to a different project than {}; re-pin required",
                    crate::gojson::quote(&cfg.project)
                ),
            )
            .with_recovery("if this is intended, run: wapps secrets trust-repo"));
        }
        Err(binding::CheckError::Unpinned) => {}
    }

    // From here on the binding is UNPINNED: it has never been set up.
    //
    // Agent/CI → fail-closed. This is where the pin REALLY works: a forged or
    // compromised `.wapps.yaml` must not CLAIM a project on its own. An agent
    // being able to write that file does not authorize it.
    if is_agent || !stdin_is_tty {
        // A human without a TTY (pipe/script): we CANNOT ask, so we do not
        // pretend to either.
        return Err(Error::new(
            Code::BindingUnpinned,
            format!(
                "repo→project binding for {} is not pinned",
                crate::gojson::quote(&cfg.project)
            ),
        ));
    }

    // A human at a terminal: coming to this directory and typing the command
    // is a STATEMENT OF INTENT. We ask HERE instead of teaching a separate
    // command; the security is the same (a human still confirms) and the
    // friction is one key per repo. The project is shown BY NAME, because
    // seeing WHICH project is claimed is exactly what is protected, and so is
    // every source a sync would read (owner decision B, see sync_reads_block).
    if !ask(&repo_id, &cfg, errw) {
        return Err(Error::new(
            Code::BindingUnpinned,
            format!(
                "not pinned; binding declined for {}",
                crate::gojson::quote(&cfg.project)
            ),
        ));
    }
    store.pin(
        &fp,
        binding::Pin {
            repo: repo_id,
            project: cfg.project.clone(),
            backend: cfg.backend.clone(),
        },
    );
    store
        .save(&path)
        .map_err(|e| Error::new(Code::Internal, format!("save repo pin: {e}")))?;
    let _ = writeln!(
        errw,
        "✓ bound this repo to project {} (change it later with: wapps secrets trust-repo)",
        crate::gojson::quote(&cfg.project)
    );
    Ok(())
}

/// bind_prompt asks a human to confirm an unpinned binding INLINE.
pub fn bind_prompt<W: Write>(repo_id: &str, cfg: &WappsYaml, errw: &mut W) -> bool {
    let _ = write!(errw, "{}", bind_prompt_text(repo_id, cfg));
    let _ = errw.flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 {
        return false;
    }
    let a = line.trim().to_lowercase();
    a == "y" || a == "yes"
}

/// bind_prompt_text is the inline binding question: the repo, the project it
/// claims, and every source a sync of this config would read.
pub fn bind_prompt_text(repo_id: &str, cfg: &WappsYaml) -> String {
    format!(
        "This repo is not bound to a project yet.\n  repo:    {repo_id}\n  project: {}\n{}Bind them? [y/N]: ",
        cfg.project,
        sync_reads_block(cfg)
    )
}

/// sync_reads_block lists the sources `wapps secrets sync` would read for
/// cfg, resolved against the config root and cleaned, one per line, with the
/// ones outside the config root marked. Empty when no source is declared.
///
/// Owner decision (B), 2026-10-05: a source may name any file (a relative
/// "../" path or an absolute one is deliberate, "secrets-from-anywhere"), so
/// a cloned repository's `.wapps.yaml` can point sync at `~/.ssh/id_rsa`.
/// Pinning a binding is what lets a later sync (or an agent) run without
/// asking, so the human who pins is shown exactly what that sync will read.
/// Shared by the inline prompt and `trust-repo`'s.
///
/// Containment is decided on the RESOLVED path (`real_path` of the source
/// and of the root), so a symlink inside the root that points out is marked.
/// When the path resolves somewhere other than where it reads, the resolved
/// target is shown after "->". Every string in the block passes through
/// `visible`, so a path cannot carry a terminal escape that redraws the
/// prompt.
pub fn sync_reads_block(cfg: &WappsYaml) -> String {
    let srcs = cfg.resolved_sources();
    if srcs.is_empty() {
        return String::new();
    }
    let root = cfg.config_root();
    let real_root = real_path(root);
    let mut b = String::from("  sync reads:\n");
    for s in &srcs {
        let raw = if s.r#type == "tofu" {
            &s.workdir
        } else {
            &s.path
        };
        let p = wappsyaml::go_clean(raw);
        // The kernel resolves the RAW path (an absolute source reaches the
        // reader uncleaned, and "link/.." is the link target's parent).
        let real = real_path(raw);
        b.push_str(&format!("    {} {}", visible(&s.r#type), visible(&p)));
        if real != expected_real_path(&p, root, &real_root) {
            b.push_str(&format!(" -> {}", visible(&real)));
        }
        if !within_root(&real, &real_root) {
            b.push_str(" (outside the config root)");
        }
        b.push('\n');
    }
    b
}

// expected_real_path is where p would resolve if no symlink below the root
// were involved: under the resolved root when p is lexically inside it, p
// itself otherwise. A resolved path that differs from it is shown.
fn expected_real_path(p: &str, root: &str, real_root: &str) -> String {
    if !within_root(p, root) {
        return p.to_string();
    }
    let rest = p.strip_prefix(root).unwrap_or_default();
    wappsyaml::go_clean(&format!("{real_root}/{rest}"))
}

/// within_root reports whether the cleaned path p is root or lies under it,
/// component-wise ("/ab" is not under "/a"). It is lexical: callers that
/// need symlinks resolved pass `real_path` results.
pub fn within_root(p: &str, root: &str) -> bool {
    if root == "/" {
        return p.starts_with('/');
    }
    p == root || p.strip_prefix(root).is_some_and(|r| r.starts_with('/'))
}

// MAX_LINK_HOPS bounds the symlinks real_path follows past a missing
// component (Linux's MAXSYMLINKS), so a link loop ends.
const MAX_LINK_HOPS: u32 = 40;

/// real_path resolves every symlink in the absolute path p, the way the
/// kernel does when sync opens it. An existing path is
/// `std::fs::canonicalize`d. A path that does not exist yet is resolved
/// through its longest existing ancestor: the parent is resolved, and the
/// last component is followed when it is a (dangling) symlink or appended
/// when it is absent, so a link to a file that appears later still shows
/// where it points. A relative path, or a link chain longer than
/// MAX_LINK_HOPS, falls back to the lexical `go_clean`. The Go twin
/// (agentgate.go realPath) is the same walk.
pub fn real_path(p: &str) -> String {
    real_path_hops(p, 0)
}

fn real_path_hops(p: &str, hops: u32) -> String {
    if let Ok(r) = std::fs::canonicalize(p) {
        return r.to_string_lossy().into_owned();
    }
    if hops > MAX_LINK_HOPS || !p.starts_with('/') {
        return wappsyaml::go_clean(p);
    }
    let i = p.rfind('/').unwrap_or_default();
    let (dir, base) = (if i == 0 { "/" } else { &p[..i] }, &p[i + 1..]);
    let d = real_path_hops(dir, hops);
    match base {
        "" | "." => return d,
        ".." => return wappsyaml::go_clean(&format!("{d}/..")),
        _ => {}
    }
    let c = wappsyaml::go_clean(&format!("{d}/{base}"));
    if let Ok(t) = std::fs::read_link(&c) {
        let t = t.to_string_lossy();
        let t = if t.starts_with('/') {
            t.into_owned()
        } else {
            format!("{d}/{t}")
        };
        return real_path_hops(&t, hops + 1);
    }
    c
}

/// visible renders s for a terminal: printable text is kept, and every
/// control character (C0, DEL, C1), Unicode space other than ' ', and format
/// character (Cf, which holds the bidi overrides) becomes a Go-style escape
/// (`\n`, `\x1b`, `\u202e`, `\U000e0041`). A path from a cloned repository's
/// `.wapps.yaml` cannot then erase or forge a line of the prompt. A
/// backslash is printable and is kept as is. The set is spelled out so the
/// Go twin (agentgate.go visible) escapes exactly the same code points.
pub fn visible(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            _ if c < ' ' || c == '\x7f' => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            _ if c.is_ascii() => out.push(c),
            _ if c.is_control() || c.is_whitespace() || gostrconv::is_format(c) => {
                if (c as u32) < 0x10000 {
                    let _ = write!(out, "\\u{:04x}", c as u32);
                } else {
                    let _ = write!(out, "\\U{:08x}", c as u32);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

// service_token_pair_set reports whether BOTH halves of the CF Access service
// token pair are set. The read matches the non-interactive auth path's
// TrimSpace EXACTLY, so "auth passes but the pin exemption does not" cannot
// happen.
fn service_token_pair_set() -> bool {
    let get = |k: &str| std::env::var(k).unwrap_or_default().trim().to_string();
    !get("CF_ACCESS_CLIENT_ID").is_empty() && !get("CF_ACCESS_CLIENT_SECRET").is_empty()
}

/// repo_identity returns the stable identity of the BOUND unit.
///
/// That unit is NOT the repo but "this `.wapps.yaml`": the origin URL plus the
/// config's path relative to the repo root.
///
/// WHY THE PATH IS INCLUDED: the identity used to be the origin URL alone, so
/// EVERY project in a monorepo collapsed onto one fingerprint. Once one was
/// pinned the others became UNREACHABLE with "repo is pinned to a different
/// project". Adding the path makes the relation many-to-many.
///
/// When the config sits at the repo ROOT the identity stays the BARE URL, so
/// EXISTING pins of single-project repos stay valid.
pub fn repo_identity(cfg: &WappsYaml) -> String {
    let root = if cfg.config_root().is_empty() {
        "."
    } else {
        cfg.config_root()
    };
    let sub = git_repo_subpath(root);

    // With an origin the identity binds to it: every checkout of the repo
    // SHARES the pin.
    if let Some(url) = git_remote_url(root) {
        return match sub {
            Some(s) if !s.is_empty() => format!("{url}#{s}"),
            _ => url,
        };
    }
    // WITHOUT an origin (a local repo) the MAIN repo root is used, NOT the
    // worktree's own root. Otherwise every worktree would get its own
    // identity: 25 worktrees, 25 binding questions and 25 separate
    // BINDING_UNPINNED refusals on the agent side.
    if let Some(main) = git_main_repo_root(root) {
        return match sub {
            Some(s) if !s.is_empty() => format!("{main}#{s}"),
            _ => main,
        };
    }
    match abs_path(Path::new(root)) {
        Ok(a) => a.to_string_lossy().into_owned(),
        Err(_) => root.to_string(),
    }
}

fn git_out(dir: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// git_main_repo_root returns the root of the MAIN working tree (even when
// called from a worktree). git --git-common-dir points at the SAME .git from a
// worktree and from the main repo, so they all meet in one pin.
fn git_main_repo_root(dir: &str) -> Option<String> {
    let git_dir = git_out(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    if git_dir.is_empty() {
        return None;
    }
    Some(Path::new(&git_dir).parent()?.to_string_lossy().into_owned())
}

// git_repo_subpath returns dir's path relative to its git root ("" = the root itself).
fn git_repo_subpath(dir: &str) -> Option<String> {
    let p = git_out(dir, &["rev-parse", "--show-prefix"])?;
    Some(p.trim_end_matches('/').to_string())
}

// git_remote_url returns `git -C <dir> remote get-url origin`; None on error or empty output.
fn git_remote_url(dir: &str) -> Option<String> {
    let u = git_out(dir, &["remote", "get-url", "origin"])?;
    if u.is_empty() {
        None
    } else {
        Some(u)
    }
}
