// YAML ingress semantics: what `wapps::yaml` decodes for the file types this
// binary reads (.wapps.yaml through WappsYaml, projects.yaml through
// projects::resolve_in).
//
// ORACLE: Go's gopkg.in/yaml.v3, measured with a probe against the same
// inputs, and the previous parser (serde_yaml_ng). An unmarked case is one
// where all three agree. Where the previous parser and yaml.v3 disagreed, a
// case is marked "yaml.v3" (it now follows yaml.v3) or "previous" (it keeps
// the previous result, which refuses an input yaml.v3 coerces). Three
// degenerate inputs are refused although both accepted them; they fail
// closed and are marked "refused".
use wapps::wappsyaml::WappsYaml;
use wapps::{projects, wappsyaml, yaml};

fn de(src: &str) -> WappsYaml {
    yaml::from_slice(src.as_bytes()).unwrap_or_else(|e| panic!("refused: {e}\n{src}"))
}

fn de_err(src: &str) -> String {
    match yaml::from_slice::<WappsYaml>(src.as_bytes()) {
        Ok(v) => panic!("accepted, expected a refusal: {v:?}\n{src}"),
        Err(e) => e.to_string(),
    }
}

// --- strings ---------------------------------------------------------------

#[test]
fn a_null_string_field_is_empty() {
    // yaml.v3 leaves a string at "" for every null spelling.
    for src in [
        "project:\n",
        "project: ~\n",
        "project: null\n",
        "project: NULL\n",
    ] {
        assert_eq!(de(src).project, "", "{src}");
    }
    let cfg =
        de("default_prefix:\nbackend: ~\nsources:\n  - type:\n    workdir: ~\n    prefix: null\n");
    assert_eq!(cfg.default_prefix, "");
    assert_eq!(cfg.backend, "");
    assert_eq!(cfg.sources[0].r#type, "");
    assert_eq!(cfg.sources[0].workdir, "");
    assert_eq!(cfg.sources[0].prefix, "");
}

#[test]
fn quoted_null_is_text() {
    assert_eq!(de("project: \"null\"\n").project, "null");
    assert_eq!(de("project: '~'\n").project, "~");
}

#[test]
fn plain_scalars_into_a_string_keep_their_text() {
    for (src, want) in [
        ("project: 123\n", "123"),
        ("project: true\n", "true"),
        ("project: 1.5\n", "1.5"),
        ("project: .inf\n", ".inf"),
        ("project: !!str 123\n", "123"),
        ("project: !foo bar\n", "bar"),
    ] {
        assert_eq!(de(src).project, want, "{src}");
    }
    let cfg = de("profiles:\n  deploy: [1, true, 2.5]\n");
    assert_eq!(cfg.profiles["deploy"], ["1", "true", "2.5"]);
}

#[test]
fn quoting_and_block_scalars_decode_as_yaml_specifies() {
    assert_eq!(de("project: 'it''s'\n").project, "it's");
    assert_eq!(de("project: \"a\\tb\\u00e9\"\n").project, "a\tb\u{e9}");
    assert_eq!(de("project: |\n  multi\n  line\n").project, "multi\nline\n");
    assert_eq!(de("project: >-\n  a\n  b\n").project, "a b");
    assert_eq!(de("project: p   \n").project, "p");
}

// --- the target prefix: absent, explicit empty, null ------------------------

#[test]
fn target_prefix_keeps_absent_and_explicit_empty_apart() {
    let prefix = |src: &str| de(src).targets[0].prefix.clone();
    assert_eq!(prefix("targets:\n  - path: a\n"), None);
    assert_eq!(
        prefix("targets:\n  - path: a\n    prefix: \"\"\n"),
        Some(String::new())
    );
    assert_eq!(
        prefix("targets:\n  - path: a\n    prefix: ''\n"),
        Some(String::new())
    );
    assert_eq!(prefix("targets:\n  - path: a\n    prefix:\n"), None);
    assert_eq!(prefix("targets:\n  - path: a\n    prefix: ~\n"), None);
    assert_eq!(prefix("targets:\n  - path: a\n    prefix: null\n"), None);
    assert_eq!(
        prefix("targets:\n  - path: a\n    prefix: 12\n"),
        Some("12".into())
    );
}

// --- integers and booleans ---------------------------------------------------

#[test]
fn version_accepts_only_an_unquoted_integer() {
    for (src, want) in [
        ("version: 2\n", 2),
        ("version: 0x2\n", 2),
        ("version: 0o2\n", 2),
        ("version: +2\n", 2),
        ("version: -1\n", -1),
        ("version: !!int \"2\"\n", 2), // yaml.v3
        ("version: 1_0\n", 10),        // yaml.v3
    ] {
        assert_eq!(de(src).version, want, "{src}");
    }
    for src in [
        "version: \"2\"\n",
        "version: '2'\n",
        "version: true\n",
        "version: 99999999999999999999\n",
        "version: 2.0\n", // previous
        "version: 2.5\n", // previous
        "version: 02\n",  // previous
        "version:\n",     // previous
    ] {
        de_err(src);
    }
}

#[test]
fn delete_unmanaged_accepts_only_an_unquoted_boolean() {
    let flag = |src: &str| {
        de(&format!("coolify_sync:\n  delete_unmanaged: {src}\n"))
            .coolify_sync
            .unwrap()
            .delete_unmanaged
    };
    assert!(flag("true"));
    assert!(flag("True"));
    assert!(!flag("false"));
    assert!(flag("yes")); // yaml.v3
    assert!(flag("on")); // yaml.v3
    assert!(!flag("off")); // yaml.v3
    assert!(flag("!!bool \"true\"")); // yaml.v3

    // An empty value is null: previous (yaml.v3 reads it as false).
    for src in ["\"true\"", "\"yes\"", "1", ""] {
        de_err(&format!("coolify_sync:\n  delete_unmanaged: {src}\n"));
    }
}

// --- collections ------------------------------------------------------------

#[test]
fn null_and_empty_collections_are_empty() {
    assert!(de("targets:\n").targets.is_empty());
    assert!(de("targets: []\n").targets.is_empty());
    assert!(de("profiles:\n").profiles.is_empty());
    assert!(de("profiles:\n  deploy:\n").profiles["deploy"].is_empty());
    assert!(de("coolify_sync:\n").coolify_sync.is_none());
    let cs = de("coolify_sync: {}\n").coolify_sync.unwrap();
    assert!(!cs.delete_unmanaged && cs.apps.is_empty() && cs.exclude_keys.is_empty());
}

#[test]
fn wrong_collection_shapes_are_refused() {
    for src in [
        "targets:\n  a: b\n",
        "targets:\n  - a\n",
        "profiles:\n  deploy: A\n",
        "project: [a]\n",
        "- a\n- b\n",
        "hello\n",
    ] {
        de_err(src);
    }
}

#[test]
fn anchors_aliases_and_merge_keys_expand() {
    let cfg = de("profiles:\n  a: &k [A, B]\n  b: *k\n");
    assert_eq!(cfg.profiles["b"], ["A", "B"]);
    // yaml.v3: the merged `path` is present.
    let cfg = de("base: &b\n  path: x\ntargets:\n  - <<: *b\n    prefix: P\n");
    assert_eq!(cfg.targets[0].path, "x");
    assert_eq!(cfg.targets[0].prefix.as_deref(), Some("P"));
}

// --- unknown and duplicate keys ----------------------------------------------

#[test]
fn unknown_fields_are_ignored_at_every_level() {
    let cfg = de(
        "version: 2\nproject: p\ndest: secrets/all.enc.age\nnested:\n  a: [1, 2]\ntargets:\n  - path: a\n    mode: 0600\n",
    );
    assert_eq!(cfg.project, "p");
    assert_eq!(cfg.targets[0].path, "a");
}

#[test]
fn a_duplicate_key_is_refused() {
    de_err("project: a\nproject: b\n");
    de_err("profiles:\n  d: [A]\n  d: [B]\n"); // yaml.v3
    de_err("x: 1\nx: 2\nproject: p\n"); // yaml.v3
}

// --- documents ---------------------------------------------------------------

#[test]
fn an_empty_document_is_all_defaults() {
    for src in ["", "# just a comment\n", "---\n", "~\n"] {
        let cfg = de(src);
        assert_eq!((cfg.version, cfg.project.as_str()), (0, ""), "{src:?}");
    }
    assert_eq!(de("---\nversion: 2\nproject: p\n...\n").project, "p");
    assert_eq!(de("{version: 2, project: p}\n").project, "p");
    assert_eq!(de("version: 2\r\nproject: p\r\n").project, "p");
    assert_eq!(de("project: p").project, "p");
}

#[test]
fn a_leading_byte_order_mark_is_skipped() {
    // yaml.v3
    assert_eq!(de("\u{feff}version: 2\nproject: p\n").project, "p");
}

#[test]
fn more_than_one_document_is_refused() {
    de_err("version: 2\n---\nproject: p\n");
}

#[test]
fn bytes_that_are_not_utf8_are_refused() {
    assert!(yaml::from_slice::<WappsYaml>(b"project: caf\xe9\n").is_err());
}

// --- refused although yaml.v3 accepts them (fail closed) ---------------------

#[test]
fn degenerate_inputs_fail_closed() {
    // refused: a null mapping key (yaml.v3 ignores the entry).
    de_err("~: a\nproject: p\n");
    // refused: a null item in a list of strings (yaml.v3 drops it, the
    // previous parser kept the literal "~").
    de_err("profiles:\n  d: [~, A]\n");
    de_err("coolify_sync:\n  exclude_keys: [~, x]\n");
    // refused: nesting deeper than the parser's depth budget (64), even in
    // an ignored field.
    de_err(&format!("x: {}{}\n", "[".repeat(65), "]".repeat(65)));
    de(&format!("x: {}{}\n", "[".repeat(60), "]".repeat(60)));
}

// --- error text ---------------------------------------------------------------

#[test]
fn a_parse_error_is_one_line_without_the_input_or_position() {
    let e = wappsyaml::parse(b"version: 2\nproject: a: b\n").unwrap_err();
    assert_eq!(
        e,
        "config: parse yaml: mapping values are not allowed in this context"
    );
    let e = wappsyaml::parse(b"version: 2\nproject: [visible-text]\n").unwrap_err();
    assert!(e.starts_with("config: parse yaml: "), "{e}");
    assert!(
        !e.contains('\n') && !e.contains("visible-text") && !e.contains(" at line "),
        "{e}"
    );
}

// --- projects.yaml -------------------------------------------------------------

fn registry(tag: &str, body: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-yaml-ingress-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    let p = d.join("projects.yaml");
    std::fs::write(&p, body).unwrap();
    p
}

#[test]
fn a_null_registry_entry_is_unregistered() {
    // yaml.v3 reads every null spelling as "", which resolve treats as
    // unregistered. `~` must not expand to the home directory.
    let reg = registry("null", "projects:\n  a:\n  b: ~\n  c: null\n  d: /srv/d\n");
    for name in ["a", "b", "c"] {
        let e = projects::resolve_in(&reg, name).unwrap_err();
        assert!(e.starts_with("unknown project"), "{name}: {e}");
    }
    assert_eq!(projects::resolve_in(&reg, "d").unwrap(), "/srv/d");
}

#[test]
fn registry_keys_and_values_keep_their_text() {
    let reg = registry(
        "text",
        "projects:\n  1: /one\n  true: /t\n  \"a b\": '/x y'\n  n: 12\n",
    );
    assert_eq!(projects::resolve_in(&reg, "1").unwrap(), "/one");
    assert_eq!(projects::resolve_in(&reg, "true").unwrap(), "/t");
    assert_eq!(projects::resolve_in(&reg, "a b").unwrap(), "/x y");
    assert_eq!(projects::resolve_in(&reg, "n").unwrap(), "12");
}

#[test]
fn a_malformed_registry_is_a_one_line_parse_error() {
    for (tag, body) in [
        ("seq", "projects: [visible-text, b]\n"),
        ("dup", "projects:\n  a: /x\n  a: /y\n"), // yaml.v3
        ("map", "projects:\n  a: {x: visible-text}\n"),
    ] {
        let reg = registry(tag, body);
        let e = projects::resolve_in(&reg, "a").unwrap_err();
        assert!(e.starts_with("projects: parse "), "{tag}: {e}");
        assert!(
            !e.contains('\n') && !e.contains("visible-text"),
            "{tag}: {e}"
        );
    }
}
