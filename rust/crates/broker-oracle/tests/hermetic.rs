// Finding 0.1: the plugin's suite resolved skills from the owner's real
// ~/.claude, so its verdict depended on the machine. These roots put every
// skill and every rule a run reads inside the fixture.
use broker_oracle::hermetic::{build_home, build_project, skill_text, temp_root};
use std::process::Command;

#[test]
fn plain_and_plugin_qualified_skills_land_where_the_plugin_looks() {
    let root = temp_root("hermetic-home");
    let home = root.join("home");
    build_home(
        &home,
        &[
            "superpowers:test-driven-development".to_string(),
            "oracle-method".to_string(),
        ],
    )
    .unwrap();
    // roles/skills.ts: `<home>/.claude/skills`, then every
    // `<home>/.claude/plugins/cache/<market>/<plugin>/<version>/skills`, and a
    // qualified name only from a root with the plugin as a path segment.
    let qualified = home.join(
        ".claude/plugins/cache/oracle/superpowers/0.0.0/skills/test-driven-development/SKILL.md",
    );
    let plain = home.join(".claude/skills/oracle-method/SKILL.md");
    assert_eq!(
        std::fs::read_to_string(qualified).unwrap(),
        skill_text("superpowers:test-driven-development")
    );
    assert_eq!(
        std::fs::read_to_string(plain).unwrap(),
        skill_text("oracle-method")
    );
}

#[test]
fn a_skill_name_that_is_a_path_is_refused() {
    let root = temp_root("hermetic-bad");
    for bad in ["../escape", "a/b", "Upper", "x:../y", ""] {
        assert!(
            build_home(&root.join("home"), &[bad.to_string()]).is_err(),
            "{bad:?} must be refused"
        );
    }
}

#[test]
fn the_project_is_a_git_repository_with_a_rulebook_and_a_stable_commit() {
    let first = temp_root("hermetic-proj-a").join("proj");
    let second = temp_root("hermetic-proj-b").join("proj");
    let head_a = build_project(&first).unwrap();
    let head_b = build_project(&second).unwrap();
    assert_eq!(head_a, head_b, "same fixture, same commit id");
    assert_eq!(head_a.len(), 40);
    let rules = std::fs::read_to_string(first.join("CLAUDE.md")).unwrap();
    assert!(rules.contains("\n@docs/RULES.md\n"), "{rules}");
    assert!(first.join("docs/RULES.md").is_file());
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&first)
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(String::from_utf8_lossy(&status.stdout), "", "a clean tree");
}
