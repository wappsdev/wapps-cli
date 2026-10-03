// policy.json'un ISTEMCI-TARAFI dogrulamasi + lint'i.
//
// ORACLE: internal/policy/policy.go ve internal/policy/policy_test.go.
//
// NEDEN ISTEMCIDE BIR KOPYA VAR — ve neden bu bir "kaynak" DEGIL: yetkilendirme
// kaynagi SUNUCUDUR; Worker ayni semayi PUT'ta ZORLUYOR. Buradaki kopya
// yalnizca `policy lint`/`set`in hizli, cevrimdisi on-kontrolu. Bu yuzden
// buradaki testlerin konusu "dogru mu karar veriyor" degil, "GO ILE AYNI
// karari AYNI CUMLEYLE mi veriyor": bu metinleri bir insan okuyor ve reddedilen
// bir policy dosyasinda elindeki tek ipucu o cumle.
use wapps::policy::{self, Rule};

fn rule(sel: (&str, &str), projects: &[&str], keys: &[&str], verbs: &[&str]) -> Rule {
    let mut r = Rule {
        projects: projects.iter().map(|s| s.to_string()).collect(),
        keys: keys.iter().map(|s| s.to_string()).collect(),
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    };
    match sel.0 {
        "group" => r.group = sel.1.to_string(),
        "service" => r.service = sel.1.to_string(),
        "aud" => r.aud = sel.1.to_string(),
        _ => {}
    }
    r
}

fn doc(rules: Vec<Rule>) -> policy::PolicyDoc {
    policy::PolicyDoc {
        schema: policy::SCHEMA_POLICY.to_string(),
        version: 1,
        rules,
    }
}

// --- glob (§4.2 pinli sozdizimi) --------------------------------------------

#[test]
fn glob_match_is_full_string_and_case_sensitive() {
    for (g, s, want) in [
        ("*", "", true),
        ("*", "anything", true),
        ("DB_*", "DB_URL", true),
        ("DB_*", "db_url", false), // case-SENSITIVE
        ("*_PROD_*", "APP_PROD_KEY", true),
        ("*_PROD_*", "APP_PRODKEY", false),
        ("?", "a", true),
        ("?", "", false),
        ("A?C", "ABC", true),
        ("A?C", "AC", false),
        ("literal", "literal", true),
        ("literal", "literalx", false), // TAM-string
        ("a*b*c", "aXXbYYc", true),
    ] {
        assert_eq!(policy::glob_match(g, s), want, "glob_match({g:?},{s:?})");
    }
}

// --- verb genisletme ---------------------------------------------------------

#[test]
fn a_star_expands_to_all_five_verbs() {
    let all = policy::expand_verbs(&["*".to_string()]);
    for v in ["read", "write", "rotate", "delete", "admin"] {
        assert!(all.contains(v), "\"*\" {v} icermeli");
    }
}

#[test]
fn rotate_implies_write_but_delete_is_never_implied() {
    let rot = policy::expand_verbs(&["rotate".to_string()]);
    assert!(rot.contains("write"), "rotate ⊃ write");
    assert!(!rot.contains("admin") && !rot.contains("read"));
    // SILME GERI ALINAMAZ: hicbir verb onu ima etmez.
    assert!(!rot.contains("delete"), "rotate delete VERMEZ");
    assert!(!policy::expand_verbs(&["write".to_string()]).contains("delete"));
    assert!(policy::expand_verbs(&["delete".to_string()]).contains("delete"));
    // ...ve delete geriye dogru write de vermez.
    assert!(!policy::expand_verbs(&["delete".to_string()]).contains("write"));
}

// --- Validate (§4.4) ---------------------------------------------------------

#[test]
fn a_well_formed_document_passes() {
    let d = doc(vec![rule(
        ("group", "dev@wapps.co"),
        &["*"],
        &["*", "!*_PROD_*"],
        &["read"],
    )]);
    assert_eq!(policy::validate(&d, "primary"), Ok(()));
}

#[test]
fn every_rejection_names_the_rule_index_and_the_reason() {
    let bad_schema = policy::PolicyDoc {
        schema: "nope".into(),
        version: 1,
        rules: vec![],
    };
    for (name, d, want) in [
        ("schema", bad_schema, "policy: schema must be wapps-secrets/policy/v1"),
        (
            "no selector",
            doc(vec![rule(("", ""), &["*"], &["*"], &["read"])]),
            "policy: rule[0]: exactly one of group/service/aud required",
        ),
        (
            "aud in primary",
            doc(vec![rule(("aud", "aud1"), &["*"], &["*"], &["read"])]),
            "policy: rule[0]: aud selectors are valid only in the FALLBACK topology; rejected in PRIMARY",
        ),
        (
            "bad service name",
            doc(vec![rule(("service", "bad name!"), &["*"], &["*"], &["read"])]),
            "policy: rule[0].service not a valid common_name",
        ),
        (
            "empty projects",
            doc(vec![rule(("group", "g@x"), &[], &["*"], &["read"])]),
            "policy: rule[0].projects must be a non-empty array",
        ),
        (
            "deny project glob",
            doc(vec![rule(("group", "g@x"), &["!x"], &["*"], &["read"])]),
            "policy: rule[0].projects: invalid glob \"!x\"",
        ),
        (
            "empty keys",
            doc(vec![rule(("group", "g@x"), &["*"], &[], &["read"])]),
            "policy: rule[0].keys must be a non-empty array",
        ),
        (
            "deny-only keys",
            doc(vec![rule(("group", "g@x"), &["*"], &["!*"], &["read"])]),
            "policy: rule[0].keys: at least one positive glob required",
        ),
        (
            "empty verbs",
            doc(vec![rule(("group", "g@x"), &["*"], &["*"], &[])]),
            "policy: rule[0].verbs must be a non-empty array",
        ),
        (
            "unknown verb",
            doc(vec![rule(("group", "g@x"), &["*"], &["*"], &["deploy"])]),
            "policy: rule[0].verbs: unknown verb \"deploy\"",
        ),
    ] {
        assert_eq!(policy::validate(&d, "primary"), Err(want.to_string()), "{name}");
    }
}

#[test]
fn two_selectors_are_as_wrong_as_none() {
    let mut r = rule(("group", "g@x"), &["*"], &["*"], &["read"]);
    r.service = "svc".into();
    assert_eq!(
        policy::validate(&doc(vec![r]), "primary"),
        Err("policy: rule[0]: exactly one of group/service/aud required".to_string())
    );
}

#[test]
fn version_zero_is_refused_as_not_positive() {
    let d = policy::PolicyDoc {
        schema: policy::SCHEMA_POLICY.to_string(),
        version: 0,
        rules: vec![],
    };
    assert_eq!(
        policy::validate(&d, "primary"),
        Err("policy: version must be a positive integer".to_string())
    );
}

#[test]
fn an_aud_selector_is_valid_in_the_fallback_topology() {
    let d = doc(vec![rule(("aud", "aud1"), &["*"], &["*"], &["read"])]);
    assert_eq!(policy::validate(&d, "fallback"), Ok(()));
}

#[test]
fn the_index_in_the_message_is_the_failing_rule_not_the_first() {
    let d = doc(vec![
        rule(("group", "ok@x"), &["*"], &["*"], &["read"]),
        rule(("group", "g@x"), &["*"], &["*"], &["deploy"]),
    ]);
    assert_eq!(
        policy::validate(&d, "primary"),
        Err("policy: rule[1].verbs: unknown verb \"deploy\"".to_string())
    );
}

// --- Lint (§7.3 a–e) ---------------------------------------------------------

fn lint_texts(d: &policy::PolicyDoc) -> Vec<String> {
    policy::lint(d).iter().map(|w| w.to_string()).collect()
}

#[test]
fn rule_b_warns_when_a_group_can_reach_prod_keys() {
    let d = doc(vec![rule(
        ("group", "eng"),
        &["vaulter"],
        &["*"],
        &["read"],
    )]);
    assert_eq!(
        lint_texts(&d),
        vec!["lint(b) rule[0]: group \"eng\" can reach *_PROD_*-matching keys via \"*\" — plaintext read is the MOST dangerous verb in a server-decrypt model; consider a \"!*_PROD_*\" deny glob"]
    );
}

#[test]
fn rule_b_is_silenced_by_a_deny_glob_in_the_same_rule() {
    let d = doc(vec![rule(
        ("group", "eng"),
        &["vaulter"],
        &["*", "!*_PROD_*"],
        &["read"],
    )]);
    assert!(
        lint_texts(&d).is_empty(),
        "kural-ici deny (b)'yi susturur: {:?}",
        lint_texts(&d)
    );
}

#[test]
fn rule_b_does_not_fire_for_an_admin_rule() {
    // admin GLOBAL bir op; (b) admin-DISI grup kurallari icin.
    let d = doc(vec![rule(("group", "admins"), &["*"], &["*"], &["admin"])]);
    assert!(lint_texts(&d).is_empty());
}

#[test]
fn rule_d_warns_on_a_service_row_with_star_verbs() {
    let d = doc(vec![rule(("service", "ci"), &["*"], &["*"], &["*"])]);
    assert_eq!(
        lint_texts(&d),
        vec!["lint(d) rule[0]: service row \"ci\" grants verbs [\"*\"] — scope service tokens to the narrowest verb set"]
    );
}

#[test]
fn rule_e_warns_when_admin_is_scoped_because_the_scope_is_dead() {
    let d = doc(vec![rule(
        ("group", "admins"),
        &["vaulter"],
        &["*"],
        &["admin"],
    )]);
    assert_eq!(
        lint_texts(&d),
        vec!["lint(e) rule[0]: rule grants `admin` with project/key scoping — admin ops are GLOBAL (§4.2); the scoping is dead and misleads reviewers"]
    );
}

#[test]
fn an_unscoped_admin_rule_draws_no_warning() {
    let d = doc(vec![rule(("group", "admins"), &["*"], &["*"], &["admin"])]);
    assert!(lint_texts(&d).is_empty());
}

#[test]
fn rules_a_and_c_fire_together_when_a_broad_rule_shadows_a_narrow_one() {
    // OLCULDU (Go ikilisi, pty): sira (d) rule[1], (a) rule[2], (c) rule[2].
    // (c) AYRI bir dongude kostugu icin en sona dusuyor — bu sira sozlesmenin
    // parcasi, cunku uyarilar bu sirayla basiliyor.
    let d = doc(vec![
        rule(("group", "eng"), &["*"], &["*"], &["*"]),
        rule(("service", "ci"), &["*"], &["*"], &["*"]),
        rule(("group", "eng"), &["p"], &["A*", "!*_PROD_*"], &["read"]),
    ]);
    assert_eq!(
        lint_texts(&d),
        vec![
            "lint(d) rule[1]: service row \"ci\" grants verbs [\"*\"] — scope service tokens to the narrowest verb set",
            "lint(a) rule[2]: deny glob \"!*_PROD_*\" is overridden for the same principal set by rule[0]'s allow \"*\" (deny is rule-scoped, §4.3.2)",
            "lint(c) rule[2]: rule appears unreachable: rule[0] already grants a superset for the same selector",
        ]
    );
}

#[test]
fn a_deny_is_not_overridden_by_a_different_principal_set() {
    // (a) YALNIZCA AYNI selector icin. Baska bir grubun allow'u deny'i
    // gecersiz kilmaz — deny kural-KAPSAMLI.
    let d = doc(vec![
        rule(("group", "other"), &["*"], &["*"], &["read"]),
        rule(("group", "eng"), &["*"], &["A*", "!*_PROD_*"], &["read"]),
    ]);
    let texts = lint_texts(&d);
    assert!(!texts.iter().any(|t| t.starts_with("lint(a)")), "{texts:?}");
}

#[test]
fn a_valid_empty_document_lints_clean() {
    assert!(lint_texts(&doc(vec![])).is_empty());
}
