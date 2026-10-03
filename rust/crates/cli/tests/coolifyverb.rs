// coolify update-env / set-labels: the pure parts of the verbs and of the
// Coolify client, against texts measured from the Go oracle
// (`cmd/coolify/{update_env,set_labels}.go`, `internal/coolify/client.go`).
// The wire itself is measured by the pty differential against a fake Coolify
// API (fakegate.py).
use std::collections::BTreeMap;
use wapps::coolify::{http_error_text, validate_uuid};
use wapps::coolifyverb::{parse_env_kvs, string_slice, strip_cert_resolver};

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn validate_uuid_texts_match_go() {
    // Accepted: the canonical shape and the lax alphanumeric-and-dash one.
    assert_eq!(
        validate_uuid("appUUID", "123e4567-E89B-12d3-a456-426614174000"),
        Ok(())
    );
    assert_eq!(validate_uuid("appUUID", "abcdefgh"), Ok(()));
    assert_eq!(validate_uuid("appUUID", "a"), Ok(()));
    assert_eq!(validate_uuid("appUUID", "A-b-9"), Ok(()));
    // Refused, in Go's order: empty, then a traversal token, then the first
    // rune outside the lax alphabet.
    assert_eq!(
        validate_uuid("appUUID", ""),
        Err("coolify: appUUID is empty".to_string())
    );
    assert_eq!(
        validate_uuid("appUUID", "../x"),
        Err(r#"coolify: appUUID contains invalid characters: "../x""#.to_string())
    );
    for bad in ["a/b", "a\\b", "a..b", "a?b", "a&b", "a#b", "a b"] {
        assert!(
            validate_uuid("appUUID", bad)
                .unwrap_err()
                .contains("contains invalid characters"),
            "{bad:?}"
        );
    }
    assert_eq!(
        validate_uuid("appUUID", "a.b"),
        Err(r#"coolify: appUUID has invalid character '.' in "a.b""#.to_string())
    );
    assert_eq!(
        validate_uuid("appUUID", "aé"),
        Err(r#"coolify: appUUID has invalid character 'é' in "aé""#.to_string())
    );
    assert_eq!(
        validate_uuid("appUUID", "a_b\x01"),
        Err(r#"coolify: appUUID has invalid character '_' in "a_b\x01""#.to_string())
    );
}

#[test]
fn http_error_text_cuts_the_body_at_200_bytes() {
    assert_eq!(
        http_error_text("PATCH", "/applications/x", 404, br#"{"message":"nope"}"#),
        r#"PATCH /applications/x: HTTP 404: {"message":"nope"}"#
    );
    let exact = "b".repeat(200);
    assert_eq!(
        http_error_text("POST", "/p", 500, exact.as_bytes()),
        format!("POST /p: HTTP 500: {exact}")
    );
    let long = "c".repeat(201);
    assert_eq!(
        http_error_text("POST", "/p", 500, long.as_bytes()),
        format!("POST /p: HTTP 500: {}…", "c".repeat(200))
    );
    assert_eq!(
        http_error_text("POST", "/p", 502, b""),
        "POST /p: HTTP 502: "
    );
}

#[test]
fn string_slice_reads_every_value_as_csv_and_wraps_errors_like_pflag() {
    assert_eq!(
        string_slice("--env", &strings(&["A=1,B=2", "C=3"])),
        Ok(strings(&["A=1", "B=2", "C=3"]))
    );
    // An empty value contributes nothing (pflag's shortcut).
    assert_eq!(
        string_slice("--env", &strings(&["", "A=1"])),
        Ok(strings(&["A=1"]))
    );
    assert_eq!(
        string_slice("--label", &strings(&["ok", "a\"b", "\""])),
        Err(r#"invalid argument "a\"b" for "--label" flag: parse error on line 1, column 2: bare " in non-quoted-field"#.to_string())
    );
    assert_eq!(
        string_slice("--env", &strings(&["\n"])),
        Err(r#"invalid argument "\n" for "--env" flag: EOF"#.to_string())
    );
}

#[test]
fn parse_env_kvs_matches_go() {
    let mut want = BTreeMap::new();
    want.insert("A".to_string(), "2".to_string());
    want.insert("B".to_string(), "x=y".to_string());
    want.insert("C".to_string(), String::new());
    assert_eq!(
        parse_env_kvs(&strings(&["A=1", "B=x=y", "A=2", "C="])),
        Ok(want)
    );
    assert_eq!(
        parse_env_kvs(&strings(&["A=1", "FOO"])),
        Err(r#"invalid env (need KEY=VAL): "FOO""#.to_string())
    );
    assert_eq!(
        parse_env_kvs(&strings(&["=v"])),
        Err(r#"invalid env (empty KEY): "=v""#.to_string())
    );
    assert_eq!(parse_env_kvs(&[]), Ok(BTreeMap::new()));
}

#[test]
fn strip_cert_resolver_drops_only_matching_labels_when_on() {
    let labels = strings(&[
        "traefik.enable=true",
        "traefik.http.routers.x.tls.certresolver=letsencrypt",
        "certresolver=letsencrypt2",
    ]);
    assert_eq!(
        strip_cert_resolver(&labels, true),
        strings(&["traefik.enable=true"])
    );
    assert_eq!(strip_cert_resolver(&labels, false), labels);
}

// --- deploy-app, deploy-app-git, import-app (slice 6b) -------------------------

#[test]
fn go_fmt_v_prints_a_decoded_answer_like_go() {
    use wapps::coolify::go_fmt_v;
    // Measured: Go's error text for the fake's "noid" create answer.
    let v: serde_json::Value = serde_json::from_str(
        r#"{"message": "created", "id": 7, "ok": true,
            "tags": ["a b", 1.5, 1e21, 0.00001], "none": null,
            "nested": {"z": 1, "a": "x"}}"#,
    )
    .unwrap();
    assert_eq!(
        go_fmt_v(&v),
        "map[id:7 message:created nested:map[a:x z:1] none:<nil> ok:true tags:[a b 1.5 1e+21 1e-05]]"
    );
    assert_eq!(go_fmt_v(&serde_json::json!({})), "map[]");
    // float64 %v: plain up to an exponent of 20, exponent form from 21 and
    // below -4.
    for (n, want) in [
        (1e20, "100000000000000000000"),
        (123.0, "123"),
        (0.0001, "0.0001"),
        (-2.5e-7, "-2.5e-07"),
        (1.25e100, "1.25e+100"),
        (0.0, "0"),
    ] {
        assert_eq!(go_fmt_v(&serde_json::json!(n)), want, "{n}");
    }
}

#[test]
fn tofu_identifier_lowercases_rune_by_rune_like_go() {
    use wapps::coolifyverb::tofu_identifier;
    // Every expected value is what the Go binary wrote (import-app cases).
    assert_eq!(tofu_identifier("Web App"), "web_app");
    assert_eq!(tofu_identifier("api_v2.internal"), "api_v2_internal");
    assert_eq!(tofu_identifier("  Trailing--Dash!! "), "_trailing_dash_");
    // Go: unicode.ToLower('İ') == 'i'; Rust's full lowercase is "i\u{307}".
    assert_eq!(tofu_identifier("İstanbul Üni"), "istanbul_ni");
    assert_eq!(tofu_identifier("Kelvin\u{212a}"), "kelvink");
    assert_eq!(tofu_identifier("!!!"), "_");
}

#[test]
fn go_join_cleans_like_filepath_join() {
    use wapps::coolifyverb::go_join;
    assert_eq!(
        go_join("./.outputs/import", "imports.sh"),
        ".outputs/import/imports.sh"
    );
    assert_eq!(go_join("./a/../out//x/", "apps.tf"), "out/x/apps.tf");
    assert_eq!(go_join("", "imports.sh"), "imports.sh");
    assert_eq!(go_join("/abs/", "apps.tf"), "/abs/apps.tf");
}

#[test]
fn collect_env_from_shell_refuses_unset_and_empty() {
    use wapps::coolifyverb::collect_env_from_shell;
    let lookup = |k: &str| match k {
        "A" => "1".to_string(),
        "B" => "two".to_string(),
        _ => String::new(),
    };
    let got = collect_env_from_shell(&strings(&["B", "A", "B"]), lookup).unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got["A"], "1");
    assert_eq!(
        collect_env_from_shell(&strings(&["A", "EMPTY", "NOPE"]), lookup),
        Err("env EMPTY not set in current shell (expected by --env-from-shell)".to_string())
    );
    assert_eq!(collect_env_from_shell(&[], lookup), Ok(BTreeMap::new()));
}

#[test]
fn import_files_filter_by_server_and_skip_incomplete_apps() {
    use wapps::coolifyverb::import_files;
    let apps: Vec<serde_json::Map<String, serde_json::Value>> = serde_json::from_str(
        r#"[{"uuid": "u-1", "name": "One", "destination": {"server": {"uuid": "s1"}}},
            {"uuid": "u-2", "name": "Two", "destination": {"server": {"uuid": "s2"}}},
            {"uuid": "u-3", "name": ""},
            {"name": "no uuid"},
            {"uuid": "u-4", "name": "Four", "destination": {"server": "s1"}}]"#,
    )
    .unwrap();
    let (imports, hcl, n) = import_files(&apps, "s1");
    assert_eq!(n, 1);
    assert_eq!(
        imports,
        "#!/usr/bin/env bash\n# Generated by wapps coolify import-app — review before running.\nset -e\n\ntofu import 'coolify_application.one' 'u-1'\n"
    );
    assert_eq!(
        hcl,
        "# Generated stubs by wapps coolify import-app — fill in args from `tofu show <addr>` after import.\n\n\
         # Imported from Coolify: One (uuid=u-1)\n\
         resource \"coolify_application\" \"one\" {\n\
         \x20 # Run: tofu import, then fill in args from `tofu show coolify_application.one`\n\
         }\n\n"
    );
    let (_, _, all) = import_files(&apps, "");
    assert_eq!(all, 3);
}
