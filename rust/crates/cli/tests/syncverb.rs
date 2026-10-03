// `secrets sync` (without --target): read the declared sources, merge them,
// and turn the tofu-output-shaped envelopes into the plain strings the store
// import takes.
//
// ORACLE: cmd/secrets/sync.go, cmd/secrets/store_backend.go (runSyncStore,
// mergedToSets, reportSyncPlan), cmd/secrets/get.go (rawValueToString) and
// internal/source. Every expected string below was measured from the Go
// binary or follows from the Go source line it names.
//
// NO REAL SECRET: every value here is a made-up test string.
use std::collections::BTreeMap;
use wapps::syncverb;

fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// --- rawValueToString -----------------------------------------------------------

#[test]
fn a_json_string_is_unquoted() {
    assert_eq!(
        syncverb::raw_value_to_string(r#""a \"b\" c""#),
        r#"a "b" c"#
    );
}

#[test]
fn null_becomes_the_empty_string_not_the_word_null() {
    // json.Unmarshal(null, &s) is a no-op: s stays "". `secrets env` prints
    // 'null' for the same input, which is a different function.
    assert_eq!(syncverb::raw_value_to_string("null"), "");
}

#[test]
fn an_absent_value_is_the_empty_string() {
    assert_eq!(syncverb::raw_value_to_string(""), "");
}

#[test]
fn non_strings_are_compacted_keeping_key_order_and_number_text() {
    // json.Compact only drops insignificant whitespace: `2.50` and `1e3` keep
    // their text and `{"b":..,"a":..}` keeps its order. A port that
    // re-serializes through a map reorders the keys and rewrites numbers.
    assert_eq!(
        syncverb::raw_value_to_string(r#"["a b", 1, 2.50]"#),
        r#"["a b",1,2.50]"#
    );
    assert_eq!(syncverb::raw_value_to_string("1e3"), "1e3");
    assert_eq!(syncverb::raw_value_to_string("true"), "true");
    assert_eq!(
        syncverb::raw_value_to_string("{\"b\": 1,\n \"a\": {\"c\": [ ]}}"),
        r#"{"b":1,"a":{"c":[]}}"#
    );
}

#[test]
fn whitespace_inside_a_string_survives_compaction() {
    assert_eq!(
        syncverb::raw_value_to_string(r#"[ "x \" y" , "\\" ]"#),
        r#"["x \" y","\\"]"#
    );
}

// --- mergedToSets ---------------------------------------------------------------

#[test]
fn envelopes_become_plain_strings() {
    let merged = map(&[
        ("A", r#"{"value":"alpha","type":"string","sensitive":true}"#),
        ("L", r#"{"value": ["a b", 1]}"#),
        ("N", r#"{"value": null}"#),
        ("M", r#"{"type": "string"}"#),
        // encoding/json matches field names case-insensitively.
        ("F", r#"{"Value": true}"#),
    ]);
    assert_eq!(
        syncverb::merged_to_sets(&merged).unwrap(),
        map(&[
            ("A", "alpha"),
            ("F", "true"),
            ("L", r#"["a b",1]"#),
            ("M", ""),
            ("N", ""),
        ])
    );
}

#[test]
fn the_last_case_insensitive_value_field_wins() {
    let merged = map(&[("A", r#"{"value":"first","VALUE":"second"}"#)]);
    assert_eq!(
        syncverb::merged_to_sets(&merged).unwrap(),
        map(&[("A", "second")])
    );
}

#[test]
fn a_null_envelope_is_an_empty_value() {
    let merged = map(&[("A", "null")]);
    assert_eq!(
        syncverb::merged_to_sets(&merged).unwrap(),
        map(&[("A", "")])
    );
}

#[test]
fn an_envelope_that_is_not_an_object_names_go_s_anonymous_struct() {
    // Measured from the Go binary (agent_sync_tofu_envelope_is_not_an_object).
    let merged = map(&[("A", r#""bare-string""#)]);
    assert_eq!(
        syncverb::merged_to_sets(&merged).unwrap_err(),
        "store: source key A malformed: json: cannot unmarshal string into Go value of type struct { Value json.RawMessage \"json:\\\"value\\\"\" }"
    );
    let merged = map(&[("A", "5")]);
    assert!(syncverb::merged_to_sets(&merged)
        .unwrap_err()
        .contains("cannot unmarshal number into Go value"));
}

// --- tofu output ----------------------------------------------------------------

#[test]
fn tofu_output_is_an_object_of_raw_envelopes() {
    let got = syncverb::parse_tofu_output(br#"{"A": {"value": [1, 2]}, "B": null}"#).unwrap();
    assert_eq!(got, map(&[("A", r#"{"value": [1, 2]}"#), ("B", "null")]));
}

#[test]
fn tofu_output_parse_errors_are_go_s_sentences() {
    // All three measured from the Go binary.
    assert_eq!(
        syncverb::parse_tofu_output(b"").unwrap_err(),
        "unexpected end of JSON input"
    );
    assert_eq!(
        syncverb::parse_tofu_output(b"[]").unwrap_err(),
        "json: cannot unmarshal array into Go value of type map[string]json.RawMessage"
    );
    // `null` decodes into a nil map: no error, no keys.
    assert!(syncverb::parse_tofu_output(b"null").unwrap().is_empty());
}

#[test]
fn a_duplicate_tofu_key_keeps_the_last_value() {
    let got = syncverb::parse_tofu_output(br#"{"A": 1, "A": 2}"#).unwrap();
    assert_eq!(got, map(&[("A", "2")]));
}

// --- source.Merge ---------------------------------------------------------------

#[test]
fn later_sources_win_and_every_collision_is_reported() {
    let (merged, overridden) = syncverb::merge(vec![
        map(&[("A", "1"), ("B", "1")]),
        map(&[("B", "2"), ("C", "2")]),
        map(&[("A", "3")]),
    ]);
    assert_eq!(merged, map(&[("A", "3"), ("B", "2"), ("C", "2")]));
    assert_eq!(overridden, vec!["B".to_string(), "A".to_string()]);
}

// --- file source ----------------------------------------------------------------

#[test]
fn a_file_source_wraps_each_value_in_an_envelope() {
    let got = syncverb::file_envelopes("x.env", b"A=1\nexport B='two words'\n").unwrap();
    assert_eq!(
        got,
        map(&[("A", r#"{"value":"1"}"#), ("B", r#"{"value":"two words"}"#)])
    );
}

#[test]
fn source_names_follow_go() {
    use wapps::wappsyaml::SourceConfig;
    let file = SourceConfig {
        r#type: "file".into(),
        path: "/r/.env".into(),
        ..Default::default()
    };
    let tofu = SourceConfig {
        r#type: "tofu".into(),
        workdir: "/r/infra".into(),
        ..Default::default()
    };
    let tofu_cwd = SourceConfig {
        r#type: "tofu".into(),
        ..Default::default()
    };
    assert_eq!(syncverb::source_name(&file), "file (/r/.env)");
    assert_eq!(syncverb::source_name(&tofu), "tofu (workdir=/r/infra)");
    assert_eq!(syncverb::source_name(&tofu_cwd), "tofu (cwd)");
}

// --- the --dry-run report -------------------------------------------------------

#[test]
fn the_plan_lists_new_then_changed_names_sorted() {
    let sets = map(&[("Z", "1"), ("B", "x"), ("A", "new"), ("SAME", "s")]);
    let current = map(&[("B", "y"), ("A", "old"), ("SAME", "s")]);
    assert_eq!(
        syncverb::render_plan(&sets, &current),
        "+ Z\n~ A\n~ B\n\n1 new, 2 changed, 1 unchanged. Re-run without --dry-run to commit.\n"
    );
}

#[test]
fn the_plan_says_in_sync_when_nothing_differs() {
    let sets = map(&[("A", "1"), ("B", "2")]);
    assert_eq!(
        syncverb::render_plan(&sets, &sets.clone()),
        "✓ In sync — 2 keys match the store\n"
    );
}

// --- ResolvedSources ------------------------------------------------------------

#[test]
fn resolved_sources_join_and_clean_like_go() {
    // Go: filepath.Join(configRoot, p), which CLEANS the result. A tofu source
    // with no workdir runs in the config dir ("." -> root), never the cwd.
    let dir = std::env::temp_dir().join(format!("wapps-syncverb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(".wapps.yaml");
    std::fs::write(
        &f,
        "version: 2\nproject: p\nsources:\n\
         \x20 - type: file\n    path: ./a/../x.env\n\
         \x20 - type: tofu\n\
         \x20 - type: tofu\n    workdir: infra/\n\
         \x20 - type: file\n    path: /abs/y.env\n",
    )
    .unwrap();
    let cfg = wapps::wappsyaml::load(&f).unwrap();
    let root = cfg.config_root().to_string();
    let rs = cfg.resolved_sources();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(rs[0].path, format!("{root}/x.env"));
    assert_eq!(rs[1].workdir, root);
    assert_eq!(rs[2].workdir, format!("{root}/infra"));
    assert_eq!(rs[3].path, "/abs/y.env");
}

#[test]
fn trailing_data_after_the_tofu_object_is_go_s_sentence() {
    // Measured from the Go binary.
    assert_eq!(
        syncverb::parse_tofu_output(br#"{"A": {"value": [1, 2]}} x"#).unwrap_err(),
        "invalid character 'x' after top-level value"
    );
}

// --- help text ------------------------------------------------------------------

#[test]
fn the_long_help_is_go_s_text_byte_for_byte_stale_as_it_is() {
    // The Go text says "write an encrypted archive to dest"; the code writes
    // the store. The behavior follows the code, the help follows the text, so
    // `--help` does not diverge once it is measured. If the Go text is fixed,
    // this test fails and the copy follows.
    let go_src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../cmd/secrets/sync.go"),
    )
    .expect("cmd/secrets/sync.go");
    let start = go_src.find("Long: `").expect("syncCmd Long") + "Long: `".len();
    let len = go_src[start..].find('`').expect("end of Long");
    let go_long = &go_src[start..start + len];

    let mut cmd = wapps::cli::build();
    let sync = cmd
        .find_subcommand_mut("secrets")
        .unwrap()
        .find_subcommand_mut("sync")
        .expect("secrets sync");
    let rs_long = sync.get_long_about().expect("long_about").to_string();
    assert_eq!(rs_long, go_long);
    assert!(rs_long.contains("encrypted archive"));
}
