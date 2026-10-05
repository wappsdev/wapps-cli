// Finding 0.1: the plugin's suite resolved skills from the owner's real
// ~/.claude, so its verdict depended on the machine. These roots put every
// skill and every rule a run reads inside the fixture.
use broker_oracle::hermetic::{build_home, build_project, create_root, skill_text, temp_root};
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

// The temp root sits at a predictable path under the shared /tmp, so it must
// be created by this process and nobody else: a directory or a symlink already
// at the path is refused and left as it was.
fn scratch(tag: &str) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(format!("/tmp/bo-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&path);
    path
}

#[test]
fn a_pre_existing_directory_at_the_root_path_is_refused() {
    let path = scratch("existing-dir");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("planted"), "theirs").unwrap();
    assert!(
        create_root(&path).is_err(),
        "an existing directory must be refused"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("planted")).unwrap(),
        "theirs",
        "the refused directory is left untouched"
    );
    std::fs::remove_dir_all(&path).unwrap();
}

#[test]
fn a_pre_existing_symlink_at_the_root_path_is_refused() {
    let path = scratch("existing-link");
    let target = scratch("existing-link-target");
    std::fs::create_dir(&target).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(create_root(&path).is_err(), "a symlink must be refused");
    assert!(std::fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&target).unwrap();

    let dangling = scratch("dangling-link");
    let nowhere = scratch("dangling-link-target");
    std::os::unix::fs::symlink(&nowhere, &dangling).unwrap();
    assert!(
        create_root(&dangling).is_err(),
        "a dangling symlink must be refused"
    );
    assert!(!nowhere.exists(), "mkdir must not follow the link");
    std::fs::remove_file(&dangling).unwrap();
}

#[test]
fn a_fresh_root_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;
    let path = scratch("fresh");
    create_root(&path).unwrap();
    let meta = std::fs::symlink_metadata(&path).unwrap();
    assert!(meta.is_dir());
    assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    std::fs::remove_dir(&path).unwrap();
}
