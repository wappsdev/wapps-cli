// skill, the `wapps skill` family: install, status and uninstall of the
// "wapps-secrets" Claude Code skill that ships inside the binary, and the
// auto-refresh main runs after every other command.
//
// ORACLE: internal/skill/skill.go and cmd/skill/skill.go.
//
// The skill text travels INSIDE the binary (a Homebrew install has no repo
// checkout). Symlink mode (the default) materializes it under
// $HOME/.config/wapps/skills/wapps-secrets with a `.fingerprint` marker and
// FILE-symlinks it into `.claude/skills/wapps-secrets` (user: under $HOME,
// project: under --dir or the cwd); copy mode writes real, committable files.
//
// Every path is built as a STRING and cleaned like Go's filepath.Join. Rust's
// Path::join does not clean, and here the difference is not cosmetic: the
// symlink TARGET is a string written to disk, so `HOME=/x//h/` would produce a
// different link than Go's. For the same reason an existing link is compared
// to the wanted target as a string (Go: `cur == target`), not as a Path, whose
// equality ignores `/./`.
//
// This module never reads or prints a secret value; it only writes the
// skill's documentation file.
use std::io::Write;
use std::path::Path;

use crate::goerr::path_error;
use crate::wappsyaml::go_clean;

/// SKILL_NAME is the directory name under `.claude/skills/`.
pub const SKILL_NAME: &str = "wapps-secrets";

/// SKILL_MD is the embedded skill, the Go asset itself (one file, so Go's
/// embed.FS walk reduces to this table).
pub const SKILL_MD: &str = include_str!("../../../../internal/skill/assets/wapps-secrets/SKILL.md");

// FILES, relative path -> content, in name order (Go sorts before hashing).
const FILES: &[(&str, &str)] = &[("SKILL.md", SKILL_MD)];

const FINGERPRINT_FILE: &str = ".fingerprint";

/// Scope selects where the skill is installed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    User,
    Project,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Scope::User => "user",
            Scope::Project => "project",
        }
    }
}

/// Options configures one install/status/uninstall call.
pub struct Options {
    pub scope: Scope,
    /// Repo root for Scope::Project; empty means the cwd.
    pub project_dir: String,
    /// Real files instead of symlinks.
    pub copy: bool,
}

impl Options {
    /// from_flags maps --local/--dir/--copy like Go's optsFromFlags: --dir
    /// only matters with --local.
    pub fn from_flags(local: bool, dir: Option<String>, copy: bool) -> Options {
        Options {
            scope: if local { Scope::Project } else { Scope::User },
            project_dir: if local {
                dir.unwrap_or_default()
            } else {
                String::new()
            },
            copy,
        }
    }
}

/// fingerprint is sha256 over every embedded file in name order, each framed
/// as `name NUL content NUL`, in lowercase hex.
pub fn fingerprint() -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    for (name, content) in FILES {
        ctx.update(name.as_bytes());
        ctx.update(&[0]);
        ctx.update(content.as_bytes());
        ctx.update(&[0]);
    }
    ctx.finish()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// join is Go's filepath.Join for two non-empty parts.
fn join(a: &str, b: &str) -> String {
    go_clean(&format!("{a}/{b}"))
}

// home is Go's os.UserHomeDir on Unix: $HOME, and an empty $HOME is unset.
fn home() -> Result<String, String> {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => Ok(h),
        _ => Err("$HOME is not defined".to_string()),
    }
}

fn source_dir() -> Result<String, String> {
    Ok(join(
        &home()?,
        &format!(".config/wapps/skills/{SKILL_NAME}"),
    ))
}

fn cwd() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| format!("getwd: {}", crate::goerr::bare_errno(&e)))
}

// skills_base resolves the `.claude/skills` directory for a scope. The
// project dir goes through filepath.Abs: absolute and CLEANED.
fn skills_base(opts: &Options) -> Result<String, String> {
    match opts.scope {
        Scope::Project => {
            let dir = if opts.project_dir.is_empty() {
                cwd()?
            } else {
                opts.project_dir.clone()
            };
            let abs = if dir.starts_with('/') {
                go_clean(&dir)
            } else {
                join(&cwd()?, &dir)
            };
            Ok(join(&abs, ".claude/skills"))
        }
        Scope::User => Ok(join(&home()?, ".claude/skills")),
    }
}

// mkdir_all is Go's os.MkdirAll(path, 0o755), including WHICH path its error
// names: the first existing component that is not a directory.
fn mkdir_all(path: &str) -> Result<(), String> {
    if let Ok(m) = std::fs::metadata(path) {
        if m.is_dir() {
            return Ok(());
        }
        let enotdir = std::io::Error::from(std::io::ErrorKind::NotADirectory);
        return Err(path_error("mkdir", path, &enotdir));
    }
    let trimmed = path.trim_end_matches('/');
    if let Some(i) = trimmed.rfind('/') {
        if i > 0 {
            mkdir_all(&trimmed[..i])?;
        }
    }
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(0o755).create(path) {
        Ok(()) => Ok(()),
        Err(_) if std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) => Ok(()),
        Err(e) => Err(path_error("mkdir", path, &e)),
    }
}

// write_file is Go's writeFileAtomic: temp + rename, mode 0644 regardless of
// the umask (Go chmods explicitly).
fn write_file(path: &str, data: &[u8]) -> Result<(), String> {
    crate::atomicfile::write(Path::new(path), data, 0o644)
        .and_then(|()| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
        })
        .map_err(|e| path_error("open", path, &e))
}

// remove is Go's os.Remove: unlink, and if that fails, rmdir (so an EMPTY
// directory in a file's place goes too).
fn remove(path: &str) -> std::io::Result<()> {
    std::fs::remove_file(path).or_else(|_| std::fs::remove_dir(path))
}

// materialize writes the embedded files into the source dir plus the
// fingerprint marker (whose write error is ignored, as in Go).
fn materialize() -> Result<String, String> {
    let dir = source_dir()?;
    mkdir_all(&dir)?;
    for (rel, content) in FILES {
        let dst = join(&dir, rel);
        mkdir_all(parent(&dst))?;
        write_file(&dst, content.as_bytes())?;
    }
    let _ = write_file(&join(&dir, FINGERPRINT_FILE), fingerprint().as_bytes());
    Ok(dir)
}

/// auto_refresh, Go's AutoRefresh: after an upgrade, bring an existing
/// SYMLINK install up to date in place by re-materializing the source the
/// links point at. Only the fingerprint marker decides: no marker means no
/// symlink install (copy installs are the user's to update), an equal marker
/// means current. True when it refreshed; every failure is false.
pub fn auto_refresh() -> bool {
    let Ok(dir) = source_dir() else {
        return false;
    };
    let Ok(marker) = std::fs::read(join(&dir, FINGERPRINT_FILE)) else {
        return false;
    };
    if marker == fingerprint().as_bytes() {
        return false;
    }
    materialize().is_ok()
}

fn parent(p: &str) -> &str {
    match p.rfind('/') {
        Some(0) => "/",
        Some(i) => &p[..i],
        None => ".",
    }
}

/// Installed describes what an install did.
pub struct Installed {
    pub scope: Scope,
    pub destination: String,
    /// The symlink source; empty in copy mode.
    pub source: String,
    pub copy: bool,
}

/// install materializes the embedded skill and installs it for the scope.
/// Idempotent: a correct link is kept, anything else in its place replaced.
pub fn install(opts: &Options) -> Result<Installed, String> {
    let dest = join(&skills_base(opts)?, SKILL_NAME);
    mkdir_all(&dest)?;
    let mut res = Installed {
        scope: opts.scope,
        destination: dest.clone(),
        source: String::new(),
        copy: opts.copy,
    };
    if opts.copy {
        for (rel, content) in FILES {
            let p = join(&dest, rel);
            mkdir_all(parent(&p))?;
            write_file(&p, content.as_bytes())?;
        }
        return Ok(res);
    }
    let src = materialize()?;
    for (rel, _) in FILES {
        let link = join(&dest, rel);
        let target = join(&src, rel);
        mkdir_all(parent(&link))?;
        if std::fs::read_link(&link).is_ok_and(|cur| cur.as_os_str() == target.as_str()) {
            continue;
        }
        let _ = remove(&link);
        std::os::unix::fs::symlink(&target, &link).map_err(|e| {
            // Go's *os.LinkError: "symlink <old> <new>: <errno>".
            path_error("symlink", &format!("{target} {link}"), &e)
        })?;
    }
    res.source = src;
    Ok(res)
}

/// State is the installed status for one scope.
pub struct State {
    pub scope: Scope,
    pub destination: String,
    pub installed: bool,
    /// "symlink" or "copy" when installed.
    pub mode: &'static str,
    pub up_to_date: bool,
}

/// status reports whether the skill is installed for the scope and whether
/// its content (read through any symlink) matches the embedded copy.
pub fn status(opts: &Options) -> Result<State, String> {
    let dest = join(&skills_base(opts)?, SKILL_NAME);
    let (mut all_present, mut all_match, mut saw_symlink) = (true, true, false);
    for (rel, content) in FILES {
        let p = join(&dest, rel);
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            all_present = false;
            all_match = false;
            continue;
        };
        if m.file_type().is_symlink() {
            saw_symlink = true;
        }
        if std::fs::read(&p).map_or(true, |got| got != content.as_bytes()) {
            all_match = false;
        }
    }
    let mode = match (all_present, saw_symlink) {
        (false, _) => "",
        (true, true) => "symlink",
        (true, false) => "copy",
    };
    Ok(State {
        scope: opts.scope,
        destination: dest,
        installed: all_present,
        mode,
        up_to_date: all_present && all_match,
    })
}

/// uninstall removes `.claude/skills/wapps-secrets` for the scope (Go's
/// RemoveAll: a directory recursively, anything else — a file, a symlink —
/// itself). The materialized source stays. None when nothing was there.
pub fn uninstall(opts: &Options) -> Result<Option<String>, String> {
    let dest = join(&skills_base(opts)?, SKILL_NAME);
    let Ok(m) = std::fs::symlink_metadata(&dest) else {
        return Ok(None);
    };
    let res = if m.is_dir() {
        std::fs::remove_dir_all(&dest)
    } else {
        std::fs::remove_file(&dest)
    };
    res.map_err(|e| path_error("unlinkat", &dest, &e))?;
    Ok(Some(dest))
}

// --- the verbs: cmd/skill/skill.go's RunE bodies -----------------------------

/// run_install prints what `wapps skill install` did.
pub fn run_install<W: Write>(out: &mut W, opts: &Options) -> Result<(), String> {
    let res = install(opts).map_err(|e| format!("install skill: {e}"))?;
    let mode = if res.copy { "copy" } else { "symlink" };
    let _ = writeln!(
        out,
        "✓ wapps-secrets skill installed ({}, {mode})",
        res.scope.name()
    );
    let _ = writeln!(out, "  → {}", res.destination);
    if !res.copy {
        let _ = writeln!(
            out,
            "  source: {} (refreshed; re-run after `brew upgrade wapps`)",
            res.source
        );
        if res.scope == Scope::Project {
            let _ = writeln!(
                out,
                "  note: symlinks point at a machine-local path — use --copy if you intend to commit them"
            );
        }
    }
    Ok(())
}

/// run_status prints one line per scope, user first. status has no flags:
/// the project scope is always the cwd. An error is returned bare.
pub fn run_status<W: Write>(out: &mut W) -> Result<(), String> {
    for scope in [Scope::User, Scope::Project] {
        let st = status(&Options {
            scope,
            project_dir: String::new(),
            copy: false,
        })?;
        let name = st.scope.name();
        if !st.installed {
            let _ = writeln!(out, "✗ {name:<8} not installed ({})", st.destination);
        } else if st.up_to_date {
            let _ = writeln!(
                out,
                "✓ {name:<8} installed, up to date ({}, {})",
                st.mode, st.destination
            );
        } else {
            let local = if scope == Scope::Project {
                " --local"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "⚠ {name:<8} installed but OUT OF DATE — run `wapps skill install`{local} ({})",
                st.destination
            );
        }
    }
    Ok(())
}

/// run_uninstall prints what `wapps skill uninstall` removed.
pub fn run_uninstall<W: Write>(out: &mut W, opts: &Options) -> Result<(), String> {
    match uninstall(opts).map_err(|e| format!("uninstall skill: {e}"))? {
        None => {
            let _ = writeln!(out, "nothing to remove (not installed)");
        }
        Some(removed) => {
            let _ = writeln!(out, "✓ removed {removed}");
        }
    }
    Ok(())
}
