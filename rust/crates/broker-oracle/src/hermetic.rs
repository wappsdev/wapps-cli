//! Hermetic skill and rulebook roots (Finding 0.1).
//!
//! The plugin resolves a role's declared skills from `<home>/.claude/skills` and
//! from every `<home>/.claude/plugins/cache/<market>/<plugin>/<version>/skills`
//! (`roles/skills.ts`), and reads the project's `CLAUDE.md` with its `@path`
//! includes as the rulebook (`roles/rulebook.ts`). Run with the owner's home,
//! 17 of its 585 tests passed or failed depending on what was installed on the
//! machine. Here both come from the fixture: a home that holds exactly the
//! named skills, with fixed bytes, and a project that is a git repository with
//! a two-file rulebook and a commit id that is the same on every machine.

use std::fs;
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A fresh, empty directory `/tmp/bo-<tag>-<pid>`, created by [`create_root`].
///
/// Under `/tmp` and not `std::env::temp_dir()`: the daemon's unix socket lives
/// below this root, and macOS limits a socket path to 104 bytes, which the
/// per-user `/var/folders/...` directory nearly spends on its own. Not inside
/// any git repository either, so a `git` run in a fixture never climbs into the
/// tree that holds the harness.
///
/// Panics if anything already sits at the path (a run kept after a failure
/// under a reused pid, or something another user planted): remove it and rerun.
pub fn temp_root(tag: &str) -> PathBuf {
    let root = PathBuf::from(format!("/tmp/bo-{tag}-{}", std::process::id()));
    create_root(&root).expect("cannot create the oracle's temp root");
    root
}

/// Creates `root` as a new directory with mode 0700, or fails.
///
/// The path is predictable and `/tmp` is shared, so the directory must be one
/// this process made: `mkdir(2)` fails with `EEXIST` on anything already there,
/// a directory or a symlink (dangling or not), and follows neither. Nothing at
/// the path is removed or reused. The parent must exist (`/tmp` does).
pub fn create_root(root: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", root.display())))
}

/// The fixed text of a fixture skill.
pub fn skill_text(name: &str) -> String {
    let leaf = name.rsplit(':').next().unwrap_or(name);
    format!(
        "---\nname: {leaf}\ndescription: Oracle fixture skill {name}.\n---\n\n# {name}\n\n\
         The oracle's stand-in for the skill {name}. Its bytes are fixed, so a worker \
         prompt that carries it is the same on every machine.\n"
    )
}

fn plain_name(part: &str) -> bool {
    let mut bytes = part.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The plugin's own rule for a skill name (`roles/skills.ts`): a plain name,
/// or `plugin:name`. Anything else would become a path.
fn split_skill(name: &str) -> io::Result<(Option<&str>, &str)> {
    let refuse = || io::Error::other(format!("skill name is not a plain name: {name:?}"));
    match name.split_once(':') {
        Some((plugin, leaf)) if plain_name(plugin) && plain_name(leaf) => Ok((Some(plugin), leaf)),
        None if plain_name(name) => Ok((None, name)),
        _ => Err(refuse()),
    }
}

/// Writes every named skill under `home`, where the plugin's resolver finds it.
pub fn build_home(home: &Path, skills: &[String]) -> io::Result<()> {
    for name in skills {
        let (plugin, leaf) = split_skill(name)?;
        let dir = match plugin {
            Some(plugin) => home
                .join(".claude/plugins/cache/oracle")
                .join(plugin)
                .join("0.0.0/skills")
                .join(leaf),
            None => home.join(".claude/skills").join(leaf),
        };
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("SKILL.md"), skill_text(name))?;
    }
    fs::create_dir_all(home)
}

const RULEBOOK: &str =
    "# Oracle project rules\n\nThese rules are the oracle's fixture.\n\n@docs/RULES.md\n";
const RULES: &str = "Rule one: say what was measured.\n";
const README: &str = "The oracle's fixture project.\n";

/// A git repository at `project` holding a rulebook, committed with a fixed
/// identity and date. Returns the commit id, which is the same on every
/// machine. git runs without the owner's configuration (no global or system
/// config), so neither a signing key nor a hook of theirs reaches the fixture.
pub fn build_project(project: &Path) -> io::Result<String> {
    fs::create_dir_all(project.join("docs"))?;
    fs::write(project.join("CLAUDE.md"), RULEBOOK)?;
    fs::write(project.join("docs/RULES.md"), RULES)?;
    fs::write(project.join("README.md"), README)?;
    let git = |args: &[&str]| -> io::Result<String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(project)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", project)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "oracle")
            .env("GIT_AUTHOR_EMAIL", "oracle@invalid")
            .env("GIT_COMMITTER_NAME", "oracle")
            .env("GIT_COMMITTER_EMAIL", "oracle@invalid")
            .env("GIT_AUTHOR_DATE", "2026-10-05T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2026-10-05T00:00:00Z")
            .output()?;
        if !out.status.success() {
            return Err(io::Error::other(format!(
                "git {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    git(&["init", "-q", "-b", "main"])?;
    git(&["add", "."])?;
    git(&["commit", "-q", "-m", "oracle fixture"])?;
    git(&["rev-parse", "HEAD"])
}
