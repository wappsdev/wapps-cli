// The plugin, run as the oracle. The recordings this produces are what every
// daemon slice is compared against; the run itself needs bun and a checkout of
// the plugin, so it is ignored by default and run with:
//
//   BROKER_ORACLE_PLUGIN=<plugin checkout> cargo test -p broker-oracle \
//     --test plugin_oracle -- --ignored --nocapture
//
// BROKER_ORACLE_BLESS=1 rewrites the committed recordings instead of comparing.
use broker_oracle::compare::first_difference;
use broker_oracle::plugin::{plugin_commit, record, Scenario};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/plugin")
}

fn plugin_repo() -> PathBuf {
    PathBuf::from(
        std::env::var("BROKER_ORACLE_PLUGIN")
            .expect("BROKER_ORACLE_PLUGIN must name a checkout of dual-orchestrator-agent-broker"),
    )
}

#[test]
#[ignore = "runs the bun plugin; needs bun and BROKER_ORACLE_PLUGIN"]
fn the_plugin_recording_is_stable_and_matches_the_committed_one() {
    let repo = plugin_repo();
    let scenario = Scenario::load(&fixtures().join("scenario.json")).unwrap();
    assert_eq!(
        plugin_commit(&repo).unwrap(),
        scenario.plugin_commit,
        "the oracle moved: re-record at the new commit and update scenario.json"
    );
    let fake = PathBuf::from(env!("CARGO_BIN_EXE_broker-oracle-fake"));
    let first = record(&repo, &fake, &scenario, "oracle-a").unwrap();
    let second = record(&repo, &fake, &scenario, "oracle-b").unwrap();
    let names = |r: &broker_oracle::plugin::Recording| -> Vec<String> {
        r.files.iter().map(|(n, _)| n.clone()).collect()
    };
    assert_eq!(names(&first), names(&second));
    for ((name, a), (_, b)) in first.files.iter().zip(&second.files) {
        if let Some(d) = first_difference(a, b) {
            panic!("{name} differs between two runs:\n{d}");
        }
        println!(
            "{name}: {} bytes, {} lines, two runs byte-equal",
            a.len(),
            a.lines().count()
        );
    }
    let recorded = fixtures().join("recorded");
    if std::env::var_os("BROKER_ORACLE_BLESS").is_some() {
        let _ = std::fs::remove_dir_all(&recorded);
        std::fs::create_dir_all(&recorded).unwrap();
        for (name, text) in &first.files {
            std::fs::write(recorded.join(name), text).unwrap();
        }
        return;
    }
    for (name, text) in &first.files {
        let golden = std::fs::read_to_string(recorded.join(name))
            .unwrap_or_else(|e| panic!("{name}: no committed recording ({e})"));
        if let Some(d) = first_difference(&golden, text) {
            panic!("{name} differs from the committed recording:\n{d}");
        }
    }
}
