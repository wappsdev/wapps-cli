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
         \x20 - type: file\n    path: /etc/../abs/x.env\n\
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
