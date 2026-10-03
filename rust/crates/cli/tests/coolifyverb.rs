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
