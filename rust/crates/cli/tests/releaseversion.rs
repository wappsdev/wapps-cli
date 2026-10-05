// The Rust binary's version is Cargo.toml's (`wapps --version` prints
// CARGO_PKG_VERSION), and the owner's rule (2026-10-05) is that it equals the
// release tag. The release builds from a tag through GoReleaser, so the guard
// is a GoReleaser `before` hook: rust/check-version.sh fails the release when
// the tag's version and Cargo.toml's differ, before anything is built.
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf()
}

fn check(version: &str) -> std::process::Output {
    Command::new("sh")
        .arg("rust/check-version.sh")
        .arg(version)
        .current_dir(repo_root())
        .output()
        .expect("check-version.sh could not run")
}

#[test]
fn the_crate_version_passes_the_release_check() {
    let out = check(env!("CARGO_PKG_VERSION"));
    assert!(
        out.status.success(),
        "rejected its own version: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn another_version_fails_the_release_check_and_names_both() {
    let out = check("9.9.9");
    assert!(
        !out.status.success(),
        "accepted a tag Cargo.toml does not carry"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("9.9.9") && err.contains(env!("CARGO_PKG_VERSION")),
        "the message must name the tag and Cargo.toml's version: {err}"
    );
}

// A prefix is not a match: tag 0.23.0 against a crate at 0.23.0-rc1 (or the
// reverse) must fail.
#[test]
fn a_prefix_of_the_version_fails_the_release_check() {
    let v = env!("CARGO_PKG_VERSION");
    assert!(!check(&v[..v.len() - 1]).status.success());
    assert!(!check(&format!("{v}-rc1")).status.success());
}

// The hook is what makes the check run at release time; without it the script
// guards nothing.
#[test]
fn goreleaser_runs_the_check_with_the_tag_version() {
    let cfg = std::fs::read_to_string(repo_root().join(".goreleaser.yml")).unwrap();
    assert!(
        cfg.contains("before:\n  hooks:\n    - sh rust/check-version.sh {{ .Version }}\n"),
        ".goreleaser.yml does not run the version check:\n{cfg}"
    );
}
