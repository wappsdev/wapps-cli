// `secrets policy` ailesinin OKUNABILIR yuzeyi: dosya okuma, kural render'i,
// diff ve rapor satirlari.
//
// ORACLE: cmd/secrets/policy.go (readPolicyFile, renderRule, printRuleDiff,
// short12) — metinler Go ikilisinden pty altinda OLCULDU.
//
// KURAL RENDER'I NEDEN ONEMLI: `policy set`in bastigi diff, bir admin'in
// "neyi degistiriyorum" sorusuna verdigi TEK cevap. Diff kural METNI uzerinden
// kume farki aliyor (kurallar sira-bagimsizdir), yani render'daki bir ayrisma
// diff'i sessizce YANLIS gosterir — silinmemis bir kural silinmis gorunur.
use wapps::policy::{PolicyDoc, Rule};
use wapps::policyverb;

fn r(group: &str, projects: &[&str], keys: &[&str], verbs: &[&str]) -> Rule {
    Rule {
        group: group.to_string(),
        projects: projects.iter().map(|s| s.to_string()).collect(),
        keys: keys.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("wapps-policyverb-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// --- render ------------------------------------------------------------------

#[test]
fn a_rule_renders_its_selector_and_three_comma_joined_lists() {
    assert_eq!(
        policyverb::render_rule(&r("eng@x", &["a", "b"], &["*", "!*_PROD_*"], &["read"])),
        "group=eng@x projects=[a,b] keys=[*,!*_PROD_*] verbs=[read]"
    );
}

#[test]
fn the_selector_precedence_is_aud_then_service_then_group() {
    // Go: sel = group; service doluysa EZER; aud doluysa O EZER. Bir dokuman
    // dogrulamadan gecmisse tek selector tasir, ama render DOGRULAMADAN ONCE
    // de cagriliyor (show, gate'in dondugu dokumani basiyor) — yani sira
    // gozlemlenebilir.
    let mut rule = r("g", &["p"], &["k"], &["read"]);
    rule.service = "svc".into();
    assert!(policyverb::render_rule(&rule).starts_with("service=svc "));
    rule.aud = "AUD".into();
    assert!(policyverb::render_rule(&rule).starts_with("aud=AUD "));
}

#[test]
fn a_rule_never_renders_a_value_only_names_and_globs() {
    let text = policyverb::render_rule(&r("eng", &["p"], &["DB_*"], &["read"]));
    assert!(!text.contains('\n'), "kural TEK satir olmali: {text}");
}

// --- diff --------------------------------------------------------------------

#[test]
fn an_identical_rule_set_reports_no_changes() {
    let rules = vec![r("eng", &["*"], &["*"], &["read"])];
    assert_eq!(
        policyverb::rule_diff(&rules, &rules),
        "rule diff:\n  (no rule changes)\n"
    );
}

#[test]
fn removed_rules_come_before_added_ones() {
    let old = vec![r("eng", &["*"], &["*"], &["read"])];
    let new = vec![r("ops", &["*"], &["*"], &["write"])];
    assert_eq!(
        policyverb::rule_diff(&old, &new),
        "rule diff:\n  - group=eng projects=[*] keys=[*] verbs=[read]\n  + group=ops projects=[*] keys=[*] verbs=[write]\n"
    );
}

#[test]
fn reordering_the_same_rules_is_not_a_change() {
    // Kurallar SIRA-BAGIMSIZ (§4.3): diff RENDER EDILMIS metin uzerinden kume
    // farki aliyor, dizi karsilastirmasi DEGIL.
    let a = r("eng", &["*"], &["*"], &["read"]);
    let b = r("ops", &["*"], &["*"], &["write"]);
    assert_eq!(
        policyverb::rule_diff(&[a.clone(), b.clone()], &[b, a]),
        "rule diff:\n  (no rule changes)\n"
    );
}

// --- short12 -----------------------------------------------------------------

#[test]
fn a_sha_longer_than_twelve_chars_is_elided() {
    assert_eq!(policyverb::short12("0123456789abcdef"), "0123456789ab…");
    assert_eq!(policyverb::short12("0123456789ab"), "0123456789ab"); // TAM 12
    assert_eq!(policyverb::short12("short"), "short");
}

// --- show render -------------------------------------------------------------

#[test]
fn the_show_report_names_version_sha_and_every_rule() {
    let doc = PolicyDoc {
        schema: wapps::policy::SCHEMA_POLICY.to_string(),
        version: 3,
        rules: vec![r(
            "developers@wapps.co",
            &["*"],
            &["*", "!*_PROD_*"],
            &["read"],
        )],
    };
    assert_eq!(
        policyverb::render_show(3, "abc123", &doc),
        "version: 3\nsha256:  abc123\nrules:   1\n  [0] group=developers@wapps.co projects=[*] keys=[*,!*_PROD_*] verbs=[read]\n"
    );
}

// --- read_policy_file --------------------------------------------------------

#[test]
fn a_missing_file_is_internal_not_policy_invalid() {
    let d = tmpdir("missing");
    let p = d.join("nope.json");
    let err = policyverb::read_policy_file(&p).unwrap_err();
    assert_eq!(err.code, wapps::clierr::Code::Internal);
    assert_eq!(
        err.message,
        format!(
            "read policy file {}: open {}: no such file or directory",
            p.display(),
            p.display()
        )
    );
}

#[test]
fn an_unknown_field_is_reported_with_gos_sentence() {
    let d = tmpdir("unknown");
    let p = d.join("p.json");
    std::fs::write(
        &p,
        r#"{"schema":"wapps-secrets/policy/v1","version":1,"rules":[],"extra":1}"#,
    )
    .unwrap();
    let err = policyverb::read_policy_file(&p).unwrap_err();
    assert_eq!(err.code, wapps::clierr::Code::PolicyInvalid);
    assert_eq!(
        err.message,
        format!(
            "policy file {} not valid JSON: json: unknown field \"extra\"",
            p.display()
        )
    );
}

#[test]
fn an_unknown_field_inside_a_rule_is_caught_too() {
    let d = tmpdir("unknownrule");
    let p = d.join("p.json");
    std::fs::write(
        &p,
        r#"{"schema":"wapps-secrets/policy/v1","version":1,"rules":[{"group":"g","bogus":1,"projects":["p"],"keys":["*"],"verbs":["read"]}]}"#,
    )
    .unwrap();
    let err = policyverb::read_policy_file(&p).unwrap_err();
    assert!(
        err.message.ends_with("json: unknown field \"bogus\""),
        "ic ice alanlar da DisallowUnknownFields kapsaminda: {}",
        err.message
    );
}

#[test]
fn an_absent_version_defaults_to_one_and_passes() {
    // Go: doc.Version == 0 -> 1 (set yolu sunucudan current+1 ile degistirir).
    let d = tmpdir("noversion");
    let p = d.join("p.json");
    std::fs::write(&p, r#"{"schema":"wapps-secrets/policy/v1","rules":[]}"#).unwrap();
    let doc = policyverb::read_policy_file(&p).expect("kabul edilmeli");
    assert_eq!(doc.version, 1);
}

#[test]
fn a_schema_violation_becomes_policy_invalid_with_the_validator_sentence() {
    let d = tmpdir("badschema");
    let p = d.join("p.json");
    std::fs::write(&p, r#"{"schema":"nope","version":1,"rules":[]}"#).unwrap();
    let err = policyverb::read_policy_file(&p).unwrap_err();
    assert_eq!(err.code, wapps::clierr::Code::PolicyInvalid);
    assert_eq!(
        err.message,
        format!(
            "policy file {} invalid: policy: schema must be wapps-secrets/policy/v1",
            p.display()
        )
    );
}

#[test]
fn an_aud_rule_is_refused_offline_because_the_topology_is_primary() {
    let d = tmpdir("aud");
    let p = d.join("p.json");
    std::fs::write(
        &p,
        r#"{"schema":"wapps-secrets/policy/v1","version":1,"rules":[{"aud":"a","projects":["p"],"keys":["*"],"verbs":["read"]}]}"#,
    )
    .unwrap();
    let err = policyverb::read_policy_file(&p).unwrap_err();
    assert!(
        err.message.contains("rejected in PRIMARY"),
        "{}",
        err.message
    );
}

// --- tel bicimi (gate'e giden BAYTLAR) ---------------------------------------

#[test]
fn the_document_serialises_in_go_struct_order_with_empty_selectors_omitted() {
    // BU TEST `keyName` SINIFINDANDIR, yazim tarafinda: `policy set` bu
    // dokumani gate'e AYNEN gonderiyor ve gate aldigi BAYTLARIN sha256'sini
    // geri veriyor. Alan sirasi ya da omitempty bir yerde ayrisirsa basilan
    // sha ayrisir. Oracle: internal/store/store.go:92-106 struct etiketleri.
    let doc = PolicyDoc {
        schema: wapps::policy::SCHEMA_POLICY.to_string(),
        version: 4,
        rules: vec![r("eng", &["p"], &["*"], &["read"])],
    };
    assert_eq!(
        serde_json::to_string(&doc).unwrap(),
        r#"{"schema":"wapps-secrets/policy/v1","version":4,"rules":[{"group":"eng","projects":["p"],"keys":["*"],"verbs":["read"]}]}"#
    );
}

#[test]
fn a_service_rule_omits_group_and_aud_but_keeps_the_three_lists() {
    let mut rule = Rule {
        service: "ci".into(),
        ..Default::default()
    };
    rule.projects = vec!["p".into()];
    rule.keys = vec!["*".into()];
    rule.verbs = vec!["read".into()];
    assert_eq!(
        serde_json::to_string(&rule).unwrap(),
        r#"{"service":"ci","projects":["p"],"keys":["*"],"verbs":["read"]}"#
    );
}
