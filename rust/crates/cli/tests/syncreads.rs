// Owner decision (B) of 2026-10-05: a source may still name a file outside the
// repository (relative "../" or absolute), but a human asked to bind an
// unpinned repository is shown every source a sync will read, resolved, with
// the ones outside the config root marked.
//
// ORACLE: cmd/secrets/agentgate.go (syncReadsBlock, withinRoot,
// bindPromptText) and cmd/secrets/trustrepo.go (trustRepoCore); the same
// vectors as cmd/secrets/syncreads_test.go.
use std::path::{Path, PathBuf};
use wapps::{configctx, trustrepo, wappsyaml};

const OUTSIDE: &str = " (outside the config root)";

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-syncreads-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

fn load_in(dir: &Path, yaml: &str) -> wappsyaml::WappsYaml {
    let p = dir.join(".wapps.yaml");
    std::fs::write(&p, yaml).expect("write .wapps.yaml");
    wappsyaml::load(&p).expect("load")
}

#[test]
fn every_source_is_resolved_and_the_outside_ones_are_marked() {
    let base = scratch("all");
    std::fs::create_dir_all(base.join("repo")).unwrap();
    let cfg = load_in(
        &base.join("repo"),
        "version: 2\nproject: p\nsources:\n\
         \x20 - type: file\n    path: sync.env\n\
         \x20 - type: file\n    path: ./sub/../inside.env\n\
         \x20 - type: file\n    path: ../other/.env\n\
         \x20 - type: file\n    path: /nonexistent-wapps/../abs/x.env\n\
         \x20 - type: tofu\n\
         \x20 - type: tofu\n    workdir: /tf\n",
    );
    let root = cfg.config_root().to_string();
    let parent = Path::new(&root).parent().unwrap().display().to_string();
    let want = format!(
        "  sync reads:\n    file {root}/sync.env\n    file {root}/inside.env\n    \
         file {parent}/other/.env{OUTSIDE}\n    file /abs/x.env{OUTSIDE}\n    \
         tofu {root}\n    tofu /tf{OUTSIDE}\n"
    );
    assert_eq!(configctx::sync_reads_block(&cfg), want);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn no_sources_prints_nothing() {
    let d = scratch("none");
    let cfg = load_in(&d, "version: 2\nproject: p\n");
    assert_eq!(configctx::sync_reads_block(&cfg), "");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn within_root_is_lexical_and_component_wise() {
    for (p, root, want) in [
        ("/a", "/a", true),
        ("/a/b", "/a", true),
        ("/ab", "/a", false),
        ("/", "/a", false),
        ("/x/y", "/", true),
    ] {
        assert_eq!(
            configctx::within_root(p, root),
            want,
            "within_root({p:?}, {root:?})"
        );
    }
}

#[test]
fn the_bind_prompt_lists_what_sync_reads() {
    let d = scratch("bind");
    let cfg = load_in(
        &d,
        "version: 2\nproject: testproj\nsources:\n  - type: file\n    path: /abs.env\n",
    );
    assert_eq!(
        configctx::bind_prompt_text("R", &cfg),
        format!(
            "This repo is not bound to a project yet.\n  repo:    R\n  project: testproj\n  \
             sync reads:\n    file /abs.env{OUTSIDE}\nBind them? [y/N]: "
        )
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_bind_prompt_without_sources_is_unchanged() {
    let d = scratch("bindnone");
    let cfg = load_in(&d, "version: 2\nproject: testproj\n");
    assert_eq!(
        configctx::bind_prompt_text("R", &cfg),
        "This repo is not bound to a project yet.\n  repo:    R\n  project: testproj\nBind them? [y/N]: "
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn trust_repo_lists_what_sync_reads_before_asking() {
    let d = scratch("trust");
    let cfg = load_in(
        &d,
        "version: 2\nproject: testproj\nsources:\n  - type: file\n    path: ../up.env\n",
    );
    let parent = Path::new(cfg.config_root())
        .parent()
        .unwrap()
        .display()
        .to_string();
    let block = trustrepo::prompt_block("R", &cfg);
    let want =
        format!("  backend: store\n  sync reads:\n    file {parent}/up.env{OUTSIDE}\nPin this binding? [y/N]: ");
    assert!(
        block.ends_with(&want),
        "got {block:?}\nwant suffix {want:?}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

// --- hardening: symlinks and terminal escapes --------------------------------
//
// The same vectors as cmd/secrets/syncreads_test.go.

// real_scratch is scratch() with its symlinks resolved (macOS: /var ->
// /private/var), so paths built from it are the paths the kernel opens.
fn real_scratch(name: &str) -> PathBuf {
    std::fs::canonicalize(scratch(name)).expect("canonical scratch")
}

/// symlink_fixture builds base/repo (the config root) next to base/outside
/// (holding secret.env), with these links inside the root:
///
///   link.env     -> base/outside/secret.env   (absolute, target exists)
///   dangling.env -> ../missing/id_rsa         (relative, target absent)
///   sub          -> base/outside              (a directory)
///   alias.env    -> sync.env                  (stays inside)
fn symlink_fixture(name: &str) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::symlink;
    let base = real_scratch(name);
    let root = base.join("repo");
    let out = base.join("outside");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("secret.env"), "K=v\n").unwrap();
    std::fs::write(root.join("sync.env"), "K=v\n").unwrap();
    symlink(out.join("secret.env"), root.join("link.env")).unwrap();
    symlink("../missing/id_rsa", root.join("dangling.env")).unwrap();
    symlink(&out, root.join("sub")).unwrap();
    symlink("sync.env", root.join("alias.env")).unwrap();
    (base, root)
}

#[test]
fn containment_is_decided_on_the_resolved_path() {
    let (base, root) = symlink_fixture("links");
    let cfg = load_in(
        &root,
        "version: 2\nproject: p\nsources:\n\
         \x20 - type: file\n    path: link.env\n\
         \x20 - type: file\n    path: dangling.env\n\
         \x20 - type: file\n    path: sub/deeper/x.env\n\
         \x20 - type: file\n    path: alias.env\n\
         \x20 - type: file\n    path: sync.env\n",
    );
    let (b, r) = (base.display(), root.display());
    let want = format!(
        "  sync reads:\n\
         \x20   file {r}/link.env -> {b}/outside/secret.env{OUTSIDE}\n\
         \x20   file {r}/dangling.env -> {b}/missing/id_rsa{OUTSIDE}\n\
         \x20   file {r}/sub/deeper/x.env -> {b}/outside/deeper/x.env{OUTSIDE}\n\
         \x20   file {r}/alias.env -> {r}/sync.env\n\
         \x20   file {r}/sync.env\n"
    );
    assert_eq!(configctx::sync_reads_block(&cfg), want);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn control_and_bidi_characters_are_escaped() {
    let root = real_scratch("escapes");
    let cfg = load_in(
        &root,
        "version: 2\nproject: p\nsources:\n\
         \x20 - type: file\n    path: \"a\\x1b[2K\\rfile ok.env\"\n\
         \x20 - type: file\n    path: \"b\\nc.env\"\n\
         \x20 - type: file\n    path: \"d\\u202eenv.txt\"\n",
    );
    let r = root.display();
    let want = format!(
        "  sync reads:\n\
         \x20   file {r}/a\\x1b[2K\\rfile ok.env\n\
         \x20   file {r}/b\\nc.env\n\
         \x20   file {r}/d\\u202eenv.txt\n"
    );
    assert_eq!(configctx::sync_reads_block(&cfg), want);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn visible_keeps_printable_text_and_escapes_the_rest() {
    for (input, want) in [
        ("plain/path-1.env", "plain/path-1.env"),
        ("back\\slash", "back\\slash"),
        ("caf\u{e9} \u{1f600}", "caf\u{e9} \u{1f600}"),
        ("\x1b[2K\r", "\\x1b[2K\\r"),
        ("a\nb\tc", "a\\nb\\tc"),
        ("\x07\x08\x0c\x0b\x00\x7f", "\\a\\b\\f\\v\\x00\\x7f"),
        ("\u{85}\u{9b}", "\\u0085\\u009b"),
        (
            "\u{a0}\u{2028}\u{2029}\u{3000}",
            "\\u00a0\\u2028\\u2029\\u3000",
        ),
        (
            "x\u{202e}y\u{2066}z\u{200b}\u{feff}",
            "x\\u202ey\\u2066z\\u200b\\ufeff",
        ),
        ("\u{e0041}", "\\U000e0041"),
    ] {
        assert_eq!(configctx::visible(input), want, "visible({input:?})");
    }
}

#[test]
fn a_link_loop_ends() {
    use std::os::unix::fs::symlink;
    let root = real_scratch("loop");
    symlink("loop2", root.join("loop1")).unwrap();
    symlink("loop1", root.join("loop2")).unwrap();
    let cfg = load_in(
        &root,
        "version: 2\nproject: p\nsources:\n  - type: file\n    path: loop1\n",
    );
    let r = root.display();
    assert_eq!(
        configctx::sync_reads_block(&cfg),
        format!("  sync reads:\n    file {r}/loop1 -> {r}/loop2\n")
    );
    let _ = std::fs::remove_dir_all(&root);
}

// --- hardening: the repo and project lines -------------------------------------
//
// The same vectors as cmd/secrets/syncreads_test.go. project comes from the
// cloned repo's .wapps.yaml and repo is a remote URL or a directory path, so
// both are attacker-controlled text.

const HOSTILE: &str = "a\x1b[2K\rproject: forged\nb\u{202e}c";
const HOSTILE_ESCAPED: &str = "a\\x1b[2K\\rproject: forged\\nb\\u202ec";

#[test]
fn the_bind_prompt_escapes_repo_and_project() {
    let d = scratch("bindhostile");
    let mut cfg = load_in(&d, "version: 2\nproject: testproj\n");
    cfg.project = HOSTILE.to_string();
    assert_eq!(
        configctx::bind_prompt_text(HOSTILE, &cfg),
        format!(
            "This repo is not bound to a project yet.\n  repo:    {HOSTILE_ESCAPED}\n  \
             project: {HOSTILE_ESCAPED}\nBind them? [y/N]: "
        )
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn trust_repo_escapes_every_user_controlled_line() {
    let d = scratch("trusthostile");
    let mut cfg = load_in(
        &d,
        "version: 2\nproject: testproj\nprofiles:\n  dev: [\"x\"]\n",
    );
    cfg.project = HOSTILE.to_string();
    cfg.profiles = std::collections::BTreeMap::from([(HOSTILE.to_string(), vec!["x".to_string()])]);
    assert_eq!(
        trustrepo::prompt_block(HOSTILE, &cfg),
        format!(
            "Pin repo→project binding:\n  repo:    {HOSTILE_ESCAPED}\n  project: {HOSTILE_ESCAPED}\n  \
             backend: store\n  profiles: {HOSTILE_ESCAPED}\nPin this binding? [y/N]: "
        )
    );
    assert_eq!(
        trustrepo::success_line(HOSTILE, HOSTILE),
        format!("pinned {HOSTILE_ESCAPED} → {HOSTILE_ESCAPED}\n")
    );
    let _ = std::fs::remove_dir_all(&d);
}
