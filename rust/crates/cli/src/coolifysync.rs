// coolifysync, the Coolify arm of `wapps secrets sync` (`--target=coolify`) —
// the port of cmd/secrets/sync_coolify.go after the store read: the diff
// between the store's values and an app's live Coolify env, its report, and
// the apply.
//
// Two modes, both dry-run unless `--force`:
//   single-app (`--app`): the WHOLE store, `--prefix` prepended to every key;
//     Coolify keys absent from it are REMOVED (always, the documented
//     destructive mirror). exclude_keys does not apply.
//   multi-app (`--all-apps`): per `coolify_sync.apps` entry, only the keys
//     under its archive_prefix, the prefix STRIPPED; removal only with
//     `delete_unmanaged`; exclude_keys applies. One app failing does not stop
//     the others; any failure fails the command.
//
// The report names KEYS and counts, never values. Go ranges over maps in
// several places here; every place it prints from is sorted in Go too, so no
// output order is random.
use crate::coolify::{Client, EnvEntry};
use crate::gostrconv::quote;
use crate::wappsyaml::CoolifySync;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

/// Diff, Go's `coolifyDiff`: what an apply would do to one app.
#[derive(Debug, Default, PartialEq)]
pub struct Diff {
    /// key → value to POST.
    pub add: BTreeMap<String, String>,
    /// key → new value (POST, then PATCH on the 409).
    pub change: BTreeMap<String, String>,
    /// key → the Coolify env uuid to DELETE.
    pub remove: BTreeMap<String, String>,
    pub unchanged: usize,
    pub skipped_managed: usize,
    pub skipped_excluded: usize,
    pub skipped_preview: usize,
}

/// compute_diff, Go's `computeCoolifyDiff`.
///
/// Coolify-managed keys (`is_coolify`, counted per ENTRY) and the excluded
/// keys are dropped from both sides. An exclusion is counted only when the
/// key is present on either side and is not already managed. Preview entries
/// are ignored (counted unless their key is skipped), so a key held only as
/// a preview is absent from the current state. A key held twice at runtime
/// keeps its LAST entry.
pub fn compute_diff(
    desired: &BTreeMap<String, String>,
    current: &[EnvEntry],
    delete_unmanaged: bool,
    exclude_keys: &[String],
) -> Diff {
    let mut diff = Diff::default();
    let mut skip = BTreeSet::new();
    for e in current.iter().filter(|e| e.is_coolify) {
        skip.insert(e.key.as_str());
        diff.skipped_managed += 1;
    }
    let excluded: BTreeSet<&str> = exclude_keys.iter().map(String::as_str).collect();
    for k in excluded {
        let present = desired.contains_key(k) || current.iter().any(|e| e.key == k);
        if present && !skip.contains(k) {
            diff.skipped_excluded += 1;
        }
        skip.insert(k);
    }

    let mut current_by_key: BTreeMap<&str, &EnvEntry> = BTreeMap::new();
    for e in current {
        if skip.contains(e.key.as_str()) {
            continue;
        }
        if e.is_preview {
            diff.skipped_preview += 1;
            continue;
        }
        current_by_key.insert(&e.key, e);
    }

    for (key, val) in desired {
        if skip.contains(key.as_str()) {
            continue;
        }
        match current_by_key.get(key.as_str()) {
            Some(e) if e.value == *val => diff.unchanged += 1,
            Some(_) => {
                diff.change.insert(key.clone(), val.clone());
            }
            None => {
                diff.add.insert(key.clone(), val.clone());
            }
        }
    }
    if delete_unmanaged {
        for (key, e) in current_by_key {
            if !desired.contains_key(key) {
                diff.remove.insert(key.to_string(), e.uuid.clone());
            }
        }
    }
    diff
}

/// render_diff, Go's `writeCoolifyDiff`: names and counts, never values.
pub fn render_diff(diff: &Diff) -> String {
    let mut s = String::from("Coolify env diff:\n");
    let mut bucket = |sign: &str, verb: &str, keys: Vec<&String>| {
        s.push_str(&format!("  {sign} {} to {verb}\n", keys.len()));
        for k in keys {
            s.push_str(&format!("      {k}\n"));
        }
    };
    bucket("+", "ADD", diff.add.keys().collect());
    bucket("~", "CHANGE", diff.change.keys().collect());
    bucket("-", "REMOVE", diff.remove.keys().collect());
    s.push_str(&format!("  = {} unchanged\n", diff.unchanged));
    if diff.skipped_managed > 0 {
        s.push_str(&format!(
            "  (skipped {} Coolify-managed keys)\n",
            diff.skipped_managed
        ));
    }
    if diff.skipped_excluded > 0 {
        s.push_str(&format!(
            "  (skipped {} excluded keys)\n",
            diff.skipped_excluded
        ));
    }
    if diff.skipped_preview > 0 {
        s.push_str(&format!(
            "  (skipped {} preview-context entries)\n",
            diff.skipped_preview
        ));
    }
    s
}

/// single_app_desired, Go's `archiveToFlatMap`: every store key with
/// `prefix` prepended.
pub fn single_app_desired(
    values: &BTreeMap<String, String>,
    prefix: &str,
) -> BTreeMap<String, String> {
    values
        .iter()
        .map(|(k, v)| (format!("{prefix}{k}"), v.clone()))
        .collect()
}

/// app_desired, Go's `archiveToAppMap`: the store keys under
/// `archive_prefix`, the prefix stripped; a key equal to the prefix is
/// dropped (an empty env name is never valid).
pub fn app_desired(
    values: &BTreeMap<String, String>,
    archive_prefix: &str,
) -> BTreeMap<String, String> {
    values
        .iter()
        .filter_map(|(k, v)| match k.strip_prefix(archive_prefix) {
            Some(stripped) if !stripped.is_empty() => Some((stripped.to_string(), v.clone())),
            _ => None,
        })
        .collect()
}

/// apply, Go's `applyCoolifyDiff`: adds, then changes, then removes, each in
/// key order, stopping at the first failure; on success the counts line.
fn apply<W: Write>(client: &Client, app: &str, diff: &Diff, out: &mut W) -> Result<(), String> {
    for (key, val) in &diff.add {
        client
            .upsert_app_env(app, key, val, false)
            .map_err(|e| format!("apply ADD {key}: {e}"))?;
    }
    for (key, val) in &diff.change {
        client
            .upsert_app_env(app, key, val, false)
            .map_err(|e| format!("apply CHANGE {key}: {e}"))?;
    }
    for (key, env_uuid) in &diff.remove {
        client
            .delete_app_env(app, env_uuid)
            .map_err(|e| format!("apply REMOVE {key}: {e}"))?;
    }
    let _ = writeln!(
        out,
        "✓ Applied: {} added, {} changed, {} removed",
        diff.add.len(),
        diff.change.len(),
        diff.remove.len()
    );
    Ok(())
}

/// run_single, single-app mode (`--app`): diff, report, and apply with
/// `force`.
pub fn run_single<W: Write>(
    client: &Client,
    app: &str,
    values: &BTreeMap<String, String>,
    prefix: &str,
    force: bool,
    out: &mut W,
) -> Result<(), String> {
    let desired = single_app_desired(values, prefix);
    let current = client
        .list_app_envs(app)
        .map_err(|e| format!("sync --target=coolify: {e}"))?;
    let diff = compute_diff(&desired, &current, true, &[]);
    let _ = write!(out, "{}", render_diff(&diff));
    if !force {
        let _ = writeln!(out, "\nDry-run only. Re-run with --force to apply.");
        return Ok(());
    }
    apply(client, app, &diff, out)
}

/// run_all_apps, multi-app mode (`--all-apps`): every `coolify_sync.apps`
/// entry in order. A list or apply failure is reported on `out` and the next
/// app runs; the command fails at the end naming every failed app.
pub fn run_all_apps<W: Write>(
    client: &Client,
    sync: Option<&CoolifySync>,
    values: &BTreeMap<String, String>,
    force: bool,
    out: &mut W,
) -> Result<(), String> {
    let Some(cs) = sync.filter(|cs| !cs.apps.is_empty()) else {
        return Err("sync --target=coolify --all-apps: no apps configured (add a coolify_sync.apps block to .wapps.yaml)".to_string());
    };
    let mut failed = Vec::new();
    for app in &cs.apps {
        let label = if app.name.is_empty() {
            &app.uuid
        } else {
            &app.name
        };
        let desired = app_desired(values, &app.archive_prefix);
        if desired.is_empty() {
            let _ = writeln!(
                out,
                "\n⚠ {label}: 0 keys matched prefix {} — skipping",
                quote(&app.archive_prefix)
            );
            continue;
        }
        let current = match client.list_app_envs(&app.uuid) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(out, "\n✗ {label} ({}): list envs failed: {e}", app.uuid);
                failed.push(app.uuid.as_str());
                continue;
            }
        };
        let diff = compute_diff(&desired, &current, cs.delete_unmanaged, &cs.exclude_keys);
        let _ = write!(
            out,
            "\n=== {label} ({}) ===\n{}",
            app.uuid,
            render_diff(&diff)
        );
        if force {
            if let Err(e) = apply(client, &app.uuid, &diff, out) {
                let _ = writeln!(
                    out,
                    "✗ {label} apply failed (partial — re-run 'sync --all-apps --force' to finish; it's idempotent): {e}"
                );
                failed.push(app.uuid.as_str());
            }
        }
    }
    if !force {
        let _ = writeln!(
            out,
            "\nDry-run only. Re-run with --all-apps --force to apply."
        );
    }
    if !failed.is_empty() {
        return Err(format!(
            "sync --target=coolify --all-apps: {} app(s) failed: {}",
            failed.len(),
            failed.join(", ")
        ));
    }
    Ok(())
}
