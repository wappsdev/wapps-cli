// `wapps deploy`'s pure parts against Go's rules (internal/deploy/deploy.go,
// cmd/deploy/deploy.go). The verb itself — trigger, poll, every exit code — is
// measured by the pty differential against a fake deploy proxy; these pin the
// decisions that a differential case reaches only one value at a time.
use std::collections::BTreeMap;
use wapps::deployverb::{
    classify_http, classify_status, json_line, known_repos, parse_field, resolve_creds,
    store_candidates, valid_deployment_id, valid_service_name, JsonResult,
};

#[test]
fn service_names_follow_the_proxy_s_pattern() {
    // ^[a-z][a-z0-9-]{1,40}$ — Go's vectors plus the boundaries.
    let forty_one = format!("a{}", "b".repeat(40));
    let forty_two = format!("a{}", "b".repeat(41));
    for ok in [
        "auth",
        "migrator",
        "vaulter-db",
        "ai",
        "labellens-api",
        "a-",
        "a1",
        &forty_one,
    ] {
        assert!(valid_service_name(ok), "{ok:?} should pass");
    }
    let sixty = "a".repeat(60);
    for bad in [
        "", "a", "BAD_Name", "Auth", "-x", "x_y", "1ab", "auth\n", "aé", &sixty, &forty_two,
    ] {
        assert!(!valid_service_name(bad), "{bad:?} should fail");
    }
}

#[test]
fn deployment_ids_follow_the_proxy_s_pattern() {
    // ^[a-z0-9]{20,32}$
    assert!(valid_deployment_id("mq12riea3yg6169dg0gs5xxo"));
    assert!(valid_deployment_id(&"0".repeat(20)));
    assert!(valid_deployment_id(&"z".repeat(32)));
    for bad in [
        "0".repeat(19),
        "0".repeat(33),
        "UPPER-and-short".to_string(),
        format!("{}-", "a".repeat(20)),
        format!("{}A", "a".repeat(20)),
        String::new(),
    ] {
        assert!(!valid_deployment_id(&bad), "{bad:?} should fail");
    }
}

#[test]
fn status_classification_is_go_s_table() {
    for (st, term, ok) in [
        ("finished", true, true),
        ("failed", true, false),
        ("error", true, false),
        ("cancelled", true, false),
        ("cancelled-by-force", true, false),
        ("in_progress", false, false),
        ("queued", false, false),
        ("unknown", false, false),
        ("Finished", false, false),
        ("", false, false),
    ] {
        assert_eq!(classify_status(st), (term, ok), "{st:?}");
    }
}

#[test]
fn http_failures_map_to_their_exit_codes() {
    let html = b"<html><body>Cloudflare Access</body></html>".as_slice();
    let cf = "error: blocked by Cloudflare Access — check DEPLOY_PROXY_CF_ACCESS_CLIENT_ID/_SECRET";
    let table: &[(&str, u16, &[u8], u8, &str)] = &[
        // No proxy JSON: 403 / 302 / 5xx are the Cloudflare edge.
        ("deploy", 403, html, 4, cf),
        ("deploy", 302, b"", 4, cf),
        ("deploy", 500, html, 4, cf),
        ("deploy", 503, b"", 4, cf),
        (
            "deploy",
            404,
            html,
            6,
            "error: unexpected proxy response (HTTP 404)",
        ),
        (
            "deploy",
            401,
            b"nope",
            6,
            "error: unexpected proxy response (HTTP 401)",
        ),
        (
            "deploy",
            201,
            br#"{"deployment_uuid":"x"}"#,
            6,
            "error: unexpected proxy response (HTTP 201)",
        ),
        // An empty or non-string "error" is not proxy JSON.
        ("deploy", 403, br#"{"error":""}"#, 4, cf),
        (
            "deploy",
            401,
            br#"{"error":5}"#,
            6,
            "error: unexpected proxy response (HTTP 401)",
        ),
        // Proxy JSON: by status.
        (
            "deploy",
            401,
            br#"{"error":"unauthorized"}"#,
            3,
            "error: proxy rejected token (401 unauthorized) — check DEPLOY_PROXY_TOKEN_SUPPLY_PRO",
        ),
        (
            "deploy",
            403,
            br#"{"error":"service not allowlisted for this token"}"#,
            3,
            "error: \"svc\" not in scope for repo \"supply-pro\" (proxy 403)",
        ),
        (
            "deploy",
            400,
            br#"{"error":"bad"}"#,
            6,
            "error: proxy rejected request (400 bad)",
        ),
        (
            "status",
            404,
            br#"{"error":"not found"}"#,
            6,
            "error: deployment \"svc\" not known to this token (404 not found)",
        ),
        (
            "deploy",
            502,
            br#"{"error":"up"}"#,
            6,
            "error: proxy upstream error (502 up)",
        ),
        (
            "deploy",
            500,
            br#"{"error":"boom"}"#,
            6,
            "error: proxy error (HTTP 500 boom)",
        ),
        (
            "deploy",
            418,
            br#"{"error":"tea"}"#,
            6,
            "error: proxy error (HTTP 418 tea)",
        ),
        // Go matches struct fields case-insensitively; the last match wins.
        (
            "deploy",
            400,
            br#"{"ERROR":"x"}"#,
            6,
            "error: proxy rejected request (400 x)",
        ),
        (
            "deploy",
            400,
            br#"{"error":"a","Error":"b"}"#,
            6,
            "error: proxy rejected request (400 b)",
        ),
        (
            "deploy",
            400,
            br#"{"error":"a","error":null}"#,
            6,
            "error: proxy rejected request (400 a)",
        ),
    ];
    for (_route, status, body, code, msg) in table {
        let e = classify_http("svc", "supply-pro", *status, body);
        assert_eq!(
            (e.code, e.msg.as_str()),
            (*code, *msg),
            "{status} {:?}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn a_field_is_read_like_go_s_raw_map() {
    let f = |b: &str| parse_field(b.as_bytes(), "deployment_uuid");
    assert_eq!(f(r#"{"deployment_uuid":"abc"}"#), "abc");
    assert_eq!(f(r#"{"deployment_uuid":"a","deployment_uuid":"b"}"#), "b");
    assert_eq!(f(r#"{"deployment_uuid":null}"#), "");
    assert_eq!(f(r#"{"deployment_uuid":5}"#), "");
    assert_eq!(f(r#"{"Deployment_UUID":"abc"}"#), "");
    assert_eq!(f(r#"["abc"]"#), "");
    assert_eq!(f("null"), "");
    assert_eq!(f("not json"), "");
    assert_eq!(f(r#"{"deployment_uuid":"abc"} x"#), "");
    assert_eq!(f(r#"{"deployment_uuid":"a\u0062c"}"#), "abc");
}

#[test]
fn known_repos_are_sorted() {
    assert_eq!(
        known_repos(),
        "kreeva-web, labellens-api, royco, stitchsense, streamkit, supply-pro, vaulter, vibe-studio-backend"
    );
}

#[test]
fn the_store_is_asked_for_every_candidate_in_go_s_order() {
    assert_eq!(
        store_candidates("supply-pro"),
        [
            "DEPLOY_PROXY_TOKEN_SUPPLY_PRO",
            "DEPLOY_PROXY_TOKEN",
            "PROXY_TOKEN",
            "DEPLOY_PROXY_CF_ACCESS_CLIENT_ID",
            "CF_ACCESS_CLIENT_ID",
            "DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET",
            "CF_ACCESS_CLIENT_SECRET",
            "DEPLOY_PROXY_EP",
        ]
    );
}

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> String {
    let m: BTreeMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned().unwrap_or_default()
}

fn stored(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn every_env_tier_beats_every_store_tier() {
    // The LAST env candidate wins over the FIRST store candidate.
    let env = env_of(&[
        ("PROXY_TOKEN", "env-legacy"),
        ("CF_ACCESS_CLIENT_ID", "env-id"),
    ]);
    let st = stored(&[
        ("DEPLOY_PROXY_TOKEN_VAULTER", "store-token"),
        ("DEPLOY_PROXY_CF_ACCESS_CLIENT_ID", "store-id"),
        ("DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET", "store-secret"),
        ("DEPLOY_PROXY_EP", "https://store.example"),
    ]);
    let (c, missing) = resolve_creds("vaulter", "", &env, &st);
    assert_eq!(c.token, "env-legacy");
    assert_eq!(c.cf_access_id, "env-id");
    assert_eq!(c.cf_access_secret, "store-secret");
    assert_eq!(c.endpoint, "https://store.example");
    assert_eq!(missing, "");
}

#[test]
fn an_empty_env_value_counts_as_unset() {
    let env = env_of(&[
        ("DEPLOY_PROXY_TOKEN_VAULTER", ""),
        ("DEPLOY_PROXY_TOKEN", "t"),
    ]);
    let (c, _) = resolve_creds("vaulter", "", &env, &BTreeMap::new());
    assert_eq!(c.token, "t");
}

#[test]
fn the_endpoint_flag_beats_env_and_store_and_the_default_is_last() {
    let env = env_of(&[("DEPLOY_PROXY_EP", "https://env.example")]);
    let st = stored(&[("DEPLOY_PROXY_EP", "https://store.example")]);
    assert_eq!(
        resolve_creds("vaulter", "https://flag.example", &env, &st)
            .0
            .endpoint,
        "https://flag.example"
    );
    assert_eq!(
        resolve_creds("vaulter", "", &env, &st).0.endpoint,
        "https://env.example"
    );
    assert_eq!(
        resolve_creds("vaulter", "", &env_of(&[]), &BTreeMap::new())
            .0
            .endpoint,
        "https://deploy-proxy.meapps.dev"
    );
}

#[test]
fn the_first_missing_credential_is_named() {
    let none = env_of(&[]);
    let empty = BTreeMap::new();
    assert_eq!(
        resolve_creds("supply-pro", "", &none, &empty).1,
        "DEPLOY_PROXY_TOKEN_SUPPLY_PRO"
    );
    let tok = env_of(&[("PROXY_TOKEN", "t")]);
    assert_eq!(
        resolve_creds("vaulter", "", &tok, &empty).1,
        "DEPLOY_PROXY_CF_ACCESS_CLIENT_ID"
    );
    let tok_id = env_of(&[("PROXY_TOKEN", "t"), ("CF_ACCESS_CLIENT_ID", "i")]);
    assert_eq!(
        resolve_creds("vaulter", "", &tok_id, &empty).1,
        "DEPLOY_PROXY_CF_ACCESS_CLIENT_SECRET"
    );
}

#[test]
fn the_json_line_is_go_s_marshal() {
    let mut r = JsonResult::new("a<b>&c", "vaulter");
    r.outcome = "error".into();
    r.exit_code = 1;
    assert_eq!(
        json_line(&r),
        r#"{"service":"a\u003cb\u003e\u0026c","repo":"vaulter","outcome":"error","exit_code":1}"#
    );
    r.deployment_uuid = "abc".into();
    r.status = "finished".into();
    r.outcome = "success".into();
    r.exit_code = 0;
    assert_eq!(
        json_line(&r),
        r#"{"service":"a\u003cb\u003e\u0026c","repo":"vaulter","deployment_uuid":"abc","status":"finished","outcome":"success","exit_code":0}"#
    );
}

// The help texts are Go's, read out of cmd/deploy/deploy.go (both are raw or
// plain literals there, no concatenation).
fn go_deploy_field(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repo root")
        .to_path_buf();
    let src = std::fs::read_to_string(root.join("cmd/deploy/deploy.go")).expect("deploy.go");
    let at = src
        .find("var DeployCmd = &cobra.Command{")
        .expect("DeployCmd");
    let body = &src[at..];
    let f = body.find(&format!("\t{name}: ")).expect("field") + name.len() + 3;
    let rest = &body[f..];
    let q = rest.chars().next().expect("literal");
    let end = rest[1..].find(q).expect("closing quote") + 1;
    rest[1..end].to_string()
}

#[test]
fn the_help_texts_are_go_s_byte_for_byte() {
    let mut cmd = wapps::cli::build();
    let deploy = cmd.find_subcommand_mut("deploy").expect("deploy");
    assert_eq!(
        deploy.get_about().expect("about").to_string(),
        go_deploy_field("Short")
    );
    assert_eq!(
        deploy.get_long_about().expect("long_about").to_string(),
        go_deploy_field("Long")
    );
}
