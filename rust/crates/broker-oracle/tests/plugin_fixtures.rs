// Guards on what is committed, run on every `cargo test` (no bun needed):
// the scenario parses, and the recordings carry nothing of the machine that
// made them, so a later slice compares against the plugin's behaviour and not
// against a temp path or a random id.
use broker_oracle::normalize::Normalizer;
use broker_oracle::plugin::{declared_skills, normalizer, Scenario};
use std::path::{Path, PathBuf};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/plugin")
}

#[test]
fn the_scenario_declares_one_plain_and_one_plugin_skill() {
    let scenario = Scenario::load(&fixtures().join("scenario.json")).unwrap();
    assert_eq!(
        declared_skills(&scenario.roles),
        ["oracle-method", "superpowers:test-driven-development"]
    );
    assert_eq!(scenario.plugin_commit.len(), 40);
}

#[test]
fn the_committed_recordings_are_the_three_expected_files() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures().join("recorded"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["claude-1.txt", "codex-1.txt", "mcp-transcript.txt"]);
}

#[test]
fn the_committed_recordings_hold_no_machine_detail() {
    for entry in std::fs::read_dir(fixtures().join("recorded")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap();
        for leak in ["/tmp/", "/private/", "/Users/", "/var/folders/"] {
            assert!(!text.contains(leak), "{} holds {leak}", path.display());
        }
        // The fixture's own home is `<root>/home`; a Linux home would not be.
        for (at, _) in text.match_indices("/home/") {
            assert!(
                text[..at].ends_with("<root>"),
                "{} holds a real /home/",
                path.display()
            );
        }
        assert_eq!(
            Normalizer::new().uuids().apply(&text),
            text,
            "{} holds a raw uuid",
            path.display()
        );
    }
}

#[test]
fn the_plugin_normalizer_collapses_both_spellings_of_the_root() {
    let root = broker_oracle::hermetic::temp_root("normalizer");
    let real = std::fs::canonicalize(&root).unwrap();
    let n = normalizer(&root);
    let text = format!("{}/proj {}/proj", root.display(), real.display());
    assert_eq!(n.apply(&text), "<root>/proj <root>/proj");
}

#[test]
fn the_tools_list_in_the_recording_has_the_plugins_26_tools() {
    let text = std::fs::read_to_string(fixtures().join("recorded/mcp-transcript.txt")).unwrap();
    let answer = text
        .lines()
        .filter_map(|l| l.strip_prefix("out "))
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .find(|f| f["result"]["tools"].is_array())
        .expect("a tools/list answer");
    assert_eq!(answer["result"]["tools"].as_array().unwrap().len(), 26);
}
