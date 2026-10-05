//! The bun/TypeScript plugin, run as the oracle.
//!
//! Nothing runs in the plugin's repository. It is copied to a temp root
//! (without its git-ignored `state/`, and without the Agent SDK's bundled
//! `claude` binary, whose place the fake takes), and run there with:
//!
//! - `HOME` = a hermetic home: the enrollment, the scenario's role table and
//!   prompts, and exactly the skills that table declares;
//! - the cwd = a fixture git project with a rulebook;
//! - `PATH` = the fake `codex` first, then `bun`'s directory, then
//!   `/usr/bin:/bin`. No real worker binary is reachable.
//!
//! The scenario (`fixtures/plugin/scenario.json`) names the plugin commit it
//! was recorded at, the role table, the MCP script and both worker scripts. A
//! recording is the MCP transcript plus one file per worker launch, each
//! normalized with [`normalizer`].

use crate::hermetic::{build_home, build_project, temp_root};
use crate::mcp::{self, Server};
use crate::normalize::Normalizer;
use crate::peer::{self, PeerConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub plugin_commit: String,
    pub project_id: String,
    pub launcher_provider: String,
    pub roles: Value,
    pub prompts: BTreeMap<String, String>,
    pub mcp: Vec<mcp::Step>,
    pub codex: Vec<peer::Step>,
    pub claude: Vec<peer::Step>,
}

impl Scenario {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// Every skill a role table declares, sorted and once each.
pub fn declared_skills(roles: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    if let Some(table) = roles.get("roles").and_then(Value::as_object) {
        for role in table.values() {
            if let Some(variants) = role.get("variants").and_then(Value::as_object) {
                for variant in variants.values() {
                    for skill in variant
                        .get("skills")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        if let Some(name) = skill.as_str() {
                            names.insert(name.to_string());
                        }
                    }
                }
            }
        }
    }
    names.into_iter().collect()
}

/// The plugin checkout's HEAD, read with `git rev-parse` (which writes nothing).
pub fn plugin_commit(repo: &Path) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// What varies between two runs of the same scenario and nothing else: the
/// temp root (both spellings, `/tmp` is a symlink on macOS), random ids, the
/// lease capability, digests (they hash the random ids) and waited times.
pub fn normalizer(root: &Path) -> Normalizer {
    let mut n = Normalizer::new();
    if let Ok(real) = fs::canonicalize(root) {
        n = n.literal(&real.to_string_lossy(), "<root>");
    }
    n.literal(&root.to_string_lossy(), "<root>")
        .uuids()
        .key("capability")
        .key("attachCapability")
        .key("digest")
        .key("waitedMs")
        .key("settledAgoMs")
        .key("at")
        .key("lastSeen")
        .key("request_id")
}

/// One normalized recording: `(file name, text)` in a fixed order.
pub struct Recording {
    pub files: Vec<(String, String)>,
}

/// The Agent SDK's bundled `claude` binaries, relative to the plugin root.
fn bundled_claude(repo: &Path) -> Vec<PathBuf> {
    let scope = repo.join("node_modules/@anthropic-ai");
    let mut found: Vec<PathBuf> = fs::read_dir(&scope)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("claude-agent-sdk-")
        })
        .map(|e| {
            PathBuf::from("node_modules/@anthropic-ai")
                .join(e.file_name())
                .join("claude")
        })
        .filter(|rel| repo.join(rel).is_file())
        .collect();
    found.sort();
    found
}

fn find_on_path(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
}

/// Copies the plugin to `to`, leaving out `state/` and the bundled `claude`.
pub fn copy_plugin(repo: &Path, to: &Path) -> Result<Vec<PathBuf>, String> {
    let bundled = bundled_claude(repo);
    let mut rsync = Command::new("rsync");
    rsync.arg("-a").arg("--exclude").arg("/state");
    for rel in &bundled {
        rsync.arg("--exclude").arg(format!("/{}", rel.display()));
    }
    let status = rsync
        .arg(format!("{}/", repo.display()))
        .arg(format!("{}/", to.display()))
        .status()
        .map_err(|e| format!("rsync: {e}"))?;
    if !status.success() {
        return Err(format!("rsync failed: {status}"));
    }
    Ok(bundled)
}

/// Stops the plugin's daemon however the run ends. It is started detached in
/// its own process group, so closing the stdio server does not stop it, and
/// left alone it would idle for ten minutes.
struct Daemon {
    record: PathBuf,
}

impl Daemon {
    fn pid(&self) -> Option<String> {
        let text = fs::read_to_string(&self.record).ok()?;
        let record: Value = serde_json::from_str(&text).ok()?;
        record.get("pid").map(|p| p.to_string())
    }
}

fn alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let Some(pid) = self.pid() else { return };
        let _ = Command::new("kill").args(["-TERM", &pid]).status();
        let deadline = Instant::now() + Duration::from_secs(5);
        while alive(&pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if alive(&pid) {
            let _ = Command::new("kill").args(["-KILL", &pid]).status();
        }
    }
}

/// Waits until every worker record has its `end` line: a worker may still be
/// draining its stdin when the job is already settled.
fn settled_records(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let records = peer::records(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let done = records
            .iter()
            .all(|(_, text)| text.lines().last().is_some_and(|l| l.starts_with("end ")));
        if done || Instant::now() > deadline {
            return Ok(records);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs the scenario against a fresh copy of the plugin at `repo`.
///
/// A failed run keeps its temp root and names it; a successful one deletes the
/// plugin copy (about 94 MB) and keeps the rest, the normalized recording among it.
pub fn record(
    repo: &Path,
    fake: &Path,
    scenario: &Scenario,
    tag: &str,
) -> Result<Recording, String> {
    let root = temp_root(tag);
    let recording = run_in(&root, repo, fake, scenario)
        .map_err(|e| format!("{e} (the run is kept at {})", root.display()))?;
    let _ = fs::remove_dir_all(root.join("plugin"));
    Ok(recording)
}

fn run_in(root: &Path, repo: &Path, fake: &Path, scenario: &Scenario) -> Result<Recording, String> {
    let plugin = root.join("plugin");
    let home = root.join("home");
    let project = root.join("proj");
    let bin = root.join("bin");
    let records = root.join("records");
    let tmp = root.join("tmp");
    for dir in [&plugin, &bin, &tmp] {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }

    let bundled = copy_plugin(repo, &plugin)?;
    if bundled.is_empty() {
        return Err("no bundled claude binary found in the plugin's node_modules".to_string());
    }
    let config = |kind: &str, script: &[peer::Step]| PeerConfig {
        kind: kind.to_string(),
        record_dir: records.clone(),
        script: script.to_vec(),
        idle_ms: 2_000,
        expect_timeout_ms: 30_000,
    };
    peer::install(fake, &bin.join("codex"), &config("codex", &scenario.codex))
        .map_err(|e| e.to_string())?;
    for rel in &bundled {
        peer::install(fake, &plugin.join(rel), &config("claude", &scenario.claude))
            .map_err(|e| e.to_string())?;
    }

    build_home(&home, &declared_skills(&scenario.roles)).map_err(|e| e.to_string())?;
    build_project(&project).map_err(|e| e.to_string())?;
    let state_home = home.join(".agent-broker");
    let table = state_home.join("projects").join(&scenario.project_id);
    fs::create_dir_all(&table).map_err(|e| e.to_string())?;
    let enrollment = json!({"version": 1, "projects": {&scenario.project_id: {"root": project}}});
    fs::write(state_home.join("projects.json"), enrollment.to_string())
        .map_err(|e| e.to_string())?;
    fs::write(
        table.join("roles.json"),
        serde_json::to_string_pretty(&scenario.roles).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    for (rel, text) in &scenario.prompts {
        let path = table.join(rel);
        fs::create_dir_all(path.parent().unwrap_or(&table)).map_err(|e| e.to_string())?;
        fs::write(path, text).map_err(|e| e.to_string())?;
    }

    let bun = find_on_path("bun").ok_or("bun is not on PATH")?;
    let bun_dir = bun.parent().unwrap_or(Path::new("/"));
    let path = format!("{}:{}:/usr/bin:/bin", bin.display(), bun_dir.display());
    let server = Server {
        program: bun.clone(),
        args: vec![plugin.join("src/main.ts").to_string_lossy().into_owned()],
        cwd: project.clone(),
        env: vec![
            ("HOME".to_string(), home.to_string_lossy().into_owned()),
            ("PATH".to_string(), path),
            ("TMPDIR".to_string(), tmp.to_string_lossy().into_owned()),
            (
                "AGENT_BROKER_LAUNCHER_PROVIDER".to_string(),
                scenario.launcher_provider.clone(),
            ),
        ],
    };
    let transcript = {
        let _daemon = Daemon {
            record: state_home
                .join("state")
                .join(&scenario.project_id)
                .join("broker.daemon.json"),
        };
        mcp::run(&server, &scenario.mcp)?
    };
    let workers = settled_records(&records)?;

    let n = normalizer(root);
    let mut files = vec![("mcp-transcript.txt".to_string(), n.apply(&transcript))];
    files.extend(
        workers
            .into_iter()
            .map(|(name, text)| (name, n.apply(&text))),
    );
    // Kept beside the run, so a difference can be read in full.
    let kept = root.join("recording");
    fs::create_dir_all(&kept).map_err(|e| e.to_string())?;
    for (name, text) in &files {
        fs::write(kept.join(name), text).map_err(|e| e.to_string())?;
    }
    Ok(Recording { files })
}
