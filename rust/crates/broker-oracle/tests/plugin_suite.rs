// Finding 0.1, closed: the plugin's own suite under an isolated home fails on
// skills it reads from the owner's ~/.claude, and passes under the hermetic
// home this crate builds from the role tables' declared skills. The empty-home
// run is the control: it shows the hermetic home is what makes the difference.
//
//   BROKER_ORACLE_PLUGIN=<plugin checkout> cargo test -p broker-oracle \
//     --test plugin_suite -- --ignored --nocapture
use broker_oracle::hermetic::{build_home, temp_root};
use broker_oracle::peer::{self, PeerConfig};
use broker_oracle::plugin::{copy_plugin, declared_skills};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

struct Tally {
    pass: u32,
    fail: u32,
    seconds: f64,
    /// Failing test names, once each.
    failed: Vec<String>,
    /// How many failures were a skill the run could not resolve.
    unresolved_skills: usize,
}

/// The one plugin test the hermetic home cannot satisfy, declared with its
/// reason: it asserts a sentence of the owner's INSTALLED
/// `superpowers:test-driven-development` (`provider-contract.test.ts:92`,
/// "NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST"). That is a test of what
/// is installed on the machine, which is Finding 0.1 itself; a fixture could
/// pass it only by copying the owner's file, and it does not.
const DECLARED: &str =
    "official provider runtime contract > builds Claude Code preset options from registry policy";

fn failed_names(output: &str) -> Vec<String> {
    let mut names: Vec<String> = output
        .lines()
        .filter_map(|line| line.strip_prefix("(fail) "))
        .map(|rest| match rest.rfind(" [") {
            Some(at) => rest[..at].to_string(),
            None => rest.to_string(),
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

fn count(output: &str, word: &str) -> u32 {
    output
        .lines()
        .filter_map(|line| line.trim().strip_suffix(word))
        .find_map(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

fn suite(plugin: &Path, home: &Path, tmp: &Path) -> Tally {
    let bun = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|d| d.join("bun"))
        .find(|p| p.is_file())
        .expect("bun on PATH");
    let path = format!("{}:/usr/bin:/bin", bun.parent().unwrap().display());
    let started = Instant::now();
    let out = Command::new(&bun)
        .arg("test")
        .current_dir(plugin)
        .env_clear()
        .env("HOME", home)
        .env("PATH", path)
        .env("TMPDIR", tmp)
        .output()
        .unwrap();
    // bun writes its summary to stderr.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::write(tmp.join("bun-test.log"), &text).unwrap();
    Tally {
        pass: count(&text, " pass"),
        fail: count(&text, " fail"),
        seconds: started.elapsed().as_secs_f64(),
        failed: failed_names(&text),
        unresolved_skills: text
            .lines()
            .filter(|l| l.starts_with("error: declared skill not found in any skill root"))
            .count(),
    }
}

fn role_table_skills(repo: &Path) -> Vec<String> {
    let mut all = Vec::new();
    for entry in std::fs::read_dir(repo.join("projects")).unwrap().flatten() {
        let table = entry.path().join("roles.json");
        if let Ok(text) = std::fs::read_to_string(&table) {
            all.extend(declared_skills(&serde_json::from_str(&text).unwrap()));
        }
    }
    all.sort();
    all.dedup();
    all
}

#[test]
#[ignore = "runs the plugin's bun suite twice (about two minutes); needs BROKER_ORACLE_PLUGIN"]
fn the_plugins_suite_passes_under_the_hermetic_home_and_not_without_it() {
    let repo = PathBuf::from(std::env::var("BROKER_ORACLE_PLUGIN").expect("BROKER_ORACLE_PLUGIN"));
    let root = temp_root("suite");
    let plugin = root.join("plugin");
    std::fs::create_dir_all(&plugin).unwrap();
    let bundled = copy_plugin(&repo, &plugin).unwrap();
    // Any test that launches the SDK's bundled claude reaches the fake, which
    // records the launch, instead of a real model.
    for rel in &bundled {
        let config = PeerConfig {
            kind: "claude".to_string(),
            record_dir: root.join("records"),
            script: vec![],
            idle_ms: 200,
            expect_timeout_ms: 1_000,
        };
        peer::install(
            &PathBuf::from(env!("CARGO_BIN_EXE_broker-oracle-fake")),
            &plugin.join(rel),
            &config,
        )
        .unwrap();
    }
    let skills = role_table_skills(&repo);
    println!("skills declared by the plugin's role tables: {skills:?}");

    let empty = root.join("empty-home");
    let empty_tmp = root.join("empty-tmp");
    std::fs::create_dir_all(&empty).unwrap();
    std::fs::create_dir_all(&empty_tmp).unwrap();
    let control = suite(&plugin, &empty, &empty_tmp);
    println!(
        "empty home:    {} pass, {} fail ({} unresolved skill), {:.1} s; failed: {:?}",
        control.pass, control.fail, control.unresolved_skills, control.seconds, control.failed
    );

    let hermetic = root.join("hermetic-home");
    let hermetic_tmp = root.join("hermetic-tmp");
    build_home(&hermetic, &skills).unwrap();
    std::fs::create_dir_all(&hermetic_tmp).unwrap();
    let fixed = suite(&plugin, &hermetic, &hermetic_tmp);
    println!(
        "hermetic home: {} pass, {} fail ({} unresolved skill), {:.1} s; failed: {:?}",
        fixed.pass, fixed.fail, fixed.unresolved_skills, fixed.seconds, fixed.failed
    );
    // The suite starts detached daemons of its own, which outlive it by their
    // ten-minute idle window. They are counted and stopped here.
    let root_name = root.file_name().unwrap().to_string_lossy().into_owned();
    let daemons = format!("{root_name}/plugin/src/daemon.ts");
    let left = Command::new("pgrep")
        .args(["-f", &daemons])
        .output()
        .unwrap();
    let left = String::from_utf8_lossy(&left.stdout).lines().count();
    let _ = Command::new("pkill")
        .args(["-TERM", "-f", &daemons])
        .status();
    println!("daemons the suite left running across both runs (stopped now): {left}");
    let launches = peer::records(&root.join("records"))
        .map(|r| r.len())
        .unwrap_or(0);
    println!("bundled claude launches recorded across both runs: {launches}");
    // The copy is about 94 MB; the logs and records beside it are kept.
    let _ = std::fs::remove_dir_all(&plugin);

    assert!(
        control.unresolved_skills > 0,
        "the control must reproduce Finding 0.1"
    );
    assert_eq!(
        fixed.unresolved_skills, 0,
        "every declared skill resolves in the fixture"
    );
    assert_eq!(
        fixed.failed,
        [DECLARED],
        "only the declared test may fail; see {}",
        hermetic_tmp.join("bun-test.log").display()
    );
    assert_eq!(
        fixed.pass + fixed.fail,
        control.pass + control.fail,
        "same suite, every test accounted for"
    );
}
