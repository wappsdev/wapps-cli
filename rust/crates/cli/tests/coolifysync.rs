// secrets sync --target=coolify: the diff, its report and the key mapping,
// against the vectors of cmd/secrets/sync_coolify_test.go and texts measured
// from the Go oracle. The apply and the per-app isolation are measured by the
// pty differential against the fake Coolify API (its write journal).
use std::collections::BTreeMap;
use wapps::coolify::EnvEntry;
use wapps::coolifysync::{app_desired, compute_diff, render_diff, single_app_desired, Diff};

fn map(kv: &[(&str, &str)]) -> BTreeMap<String, String> {
    kv.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn env(uuid: &str, key: &str, value: &str) -> EnvEntry {
    EnvEntry {
        uuid: uuid.to_string(),
        key: key.to_string(),
        value: value.to_string(),
        ..EnvEntry::default()
    }
}

fn managed(uuid: &str, key: &str, value: &str) -> EnvEntry {
    EnvEntry {
        is_coolify: true,
        ..env(uuid, key, value)
    }
}

fn preview(uuid: &str, key: &str, value: &str) -> EnvEntry {
    EnvEntry {
        is_preview: true,
        ..env(uuid, key, value)
    }
}

#[test]
fn empty_on_both_sides_is_an_empty_diff() {
    assert_eq!(compute_diff(&map(&[]), &[], true, &[]), Diff::default());
}

#[test]
fn add_change_unchanged_and_remove() {
    let d = compute_diff(
        &map(&[("NEW", "n"), ("CHG", "new"), ("SAME", "s")]),
        &[
            env("u1", "CHG", "old"),
            env("u2", "SAME", "s"),
            env("u3", "GONE", "g"),
        ],
        true,
        &[],
    );
    assert_eq!(d.add, map(&[("NEW", "n")]));
    assert_eq!(d.change, map(&[("CHG", "new")]));
    assert_eq!(d.remove, map(&[("GONE", "u3")]));
    assert_eq!(d.unchanged, 1);
}

#[test]
fn delete_unmanaged_false_never_removes() {
    let d = compute_diff(&map(&[]), &[env("u1", "GONE", "g")], false, &[]);
    assert!(d.remove.is_empty());
}

#[test]
fn managed_keys_are_dropped_from_both_sides() {
    // Go: TestComputeCoolifyDiff_SkipsCoolifyManaged and _ManagedCoolifyOnly.
    let d = compute_diff(
        &map(&[("SERVICE_URL_API", "https://stale"), ("REAL", "v")]),
        &[
            managed("u1", "SERVICE_URL_API", "https://live"),
            managed("u2", "SERVICE_FQDN_API", "x.sslip.io"),
            env("u3", "REAL", "old"),
        ],
        true,
        &[],
    );
    assert_eq!(d.add, map(&[]));
    assert_eq!(d.change, map(&[("REAL", "v")]));
    assert!(d.remove.is_empty());
    assert_eq!(d.skipped_managed, 2);
}

#[test]
fn preview_entries_are_ignored_whatever_their_order() {
    for current in [
        vec![env("r1", "K", "rt"), preview("p1", "K", "pv")],
        vec![preview("p1", "K", "pv"), env("r1", "K", "rt")],
    ] {
        let d = compute_diff(&map(&[("K", "rt")]), &current, true, &[]);
        assert!(d.change.is_empty(), "{current:?}");
        assert_eq!(d.unchanged, 1);
        assert_eq!(d.skipped_preview, 1);
    }
    // A key held only as a preview is absent: an add, never a removal.
    let d = compute_diff(
        &map(&[("PREVIEW_ONLY", "v")]),
        &[
            preview("p1", "PREVIEW_ONLY", "other"),
            preview("p2", "OTHER", "x"),
        ],
        true,
        &[],
    );
    assert_eq!(d.add, map(&[("PREVIEW_ONLY", "v")]));
    assert!(d.remove.is_empty());
}

#[test]
fn a_key_held_twice_at_runtime_keeps_its_last_entry() {
    let d = compute_diff(
        &map(&[("A", "new")]),
        &[
            env("a1", "A", "new"),
            env("a2", "A", "old"),
            env("o1", "O", "x"),
            env("o2", "O", "y"),
        ],
        true,
        &[],
    );
    assert_eq!(d.change, map(&[("A", "new")]));
    assert_eq!(d.remove, map(&[("O", "o2")]));
}

#[test]
fn exclusions_count_only_present_unmanaged_keys() {
    // Go: TestComputeCoolifyDiff_ExcludeKeys, plus a managed key on the list
    // (not counted twice) and a duplicate entry (counted once).
    let d = compute_diff(
        &map(&[
            ("SENTRY_RELEASE", "v2"),
            ("REAL", "v"),
            ("ONLY_DESIRED", "d"),
        ]),
        &[
            env("u1", "SENTRY_RELEASE", "v1"),
            env("u2", "REAL", "v"),
            managed("u3", "SERVICE_FQDN_WEB", "w"),
        ],
        true,
        &[
            "SENTRY_RELEASE".to_string(),
            "NEVER_PRESENT".to_string(),
            "SERVICE_FQDN_WEB".to_string(),
            "SENTRY_RELEASE".to_string(),
            "ONLY_DESIRED".to_string(),
        ],
    );
    assert!(d.change.is_empty());
    assert!(d.add.is_empty());
    assert!(d.remove.is_empty());
    assert_eq!(d.skipped_excluded, 2);
    assert_eq!(d.skipped_managed, 1);
}

#[test]
fn render_names_keys_and_counts_never_values() {
    // Measured: Go's report for the corpus's single-app case, shortened.
    let d = compute_diff(
        &map(&[
            ("ALPHA", "same"),
            ("BETA", "secret-new"),
            ("NEWKEY", "secret-add"),
        ]),
        &[
            env("e1", "ALPHA", "same"),
            env("e2", "BETA", "secret-old"),
            env("e3", "OLD_KEY", "secret-gone"),
            managed("e4", "MANAGED_URL", "m"),
            preview("e5", "PREVONLY", "p"),
        ],
        true,
        &[],
    );
    let text = render_diff(&d);
    assert_eq!(
        text,
        "Coolify env diff:\n  + 1 to ADD\n      NEWKEY\n  ~ 1 to CHANGE\n      BETA\n  - 1 to REMOVE\n      OLD_KEY\n  = 1 unchanged\n  (skipped 1 Coolify-managed keys)\n  (skipped 1 preview-context entries)\n"
    );
    assert!(!text.contains("secret"));
    assert_eq!(
        render_diff(&Diff::default()),
        "Coolify env diff:\n  + 0 to ADD\n  ~ 0 to CHANGE\n  - 0 to REMOVE\n  = 0 unchanged\n"
    );
    let excluded = Diff {
        skipped_excluded: 3,
        ..Diff::default()
    };
    assert!(render_diff(&excluded).ends_with("  (skipped 3 excluded keys)\n"));
}

#[test]
fn single_app_prepends_and_multi_app_strips_the_prefix() {
    let values = map(&[("WEB_PORT", "1"), ("WEB_", "x"), ("API_PORT", "2")]);
    assert_eq!(
        single_app_desired(&values, "X_"),
        map(&[("X_WEB_PORT", "1"), ("X_WEB_", "x"), ("X_API_PORT", "2")])
    );
    assert_eq!(single_app_desired(&values, ""), values);
    // A key equal to the prefix would be an empty name: dropped.
    assert_eq!(app_desired(&values, "WEB_"), map(&[("PORT", "1")]));
    assert_eq!(app_desired(&values, "NOPE_"), map(&[]));
}
