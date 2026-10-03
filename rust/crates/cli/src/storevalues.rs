// storevalues, the port of `cmd/secrets/archive_values.go` — a LIBRARY
// FUNCTION, not a verb.
//
// The name is historical: the file once read an age-encrypted ARCHIVE
// (`ArchiveValues`). The P1.7 re-point deleted the archive reader and the
// source became the server-decrypt store; the name stayed. Its one consumer is
// `wapps deploy`'s credential fallback (main.rs `run_deploy`): the caller looks
// at the env first and falls back here only for keys the env lacks.
//
// Measured both ways: the contract is pinned against Go's own tests
// (cmd/secrets/archive_values_test.go) in tests/storevalues.rs, and the deploy
// cases of the pty differential walk it end to end (the pin advances through
// the key listing; an empty intersection reads nothing).
//
// THREE CONTRACTS, all three a security property:
//
//  1. BEST-EFFORT REACHABILITY: no `.wapps.yaml` returns `Ok(None)` — NOT an
//     error. The caller (deploy) then falls back to the env. An error here
//     would break deploy in every project that does not use the store.
//  2. NAME-PLANE INTERSECTION FIRST: a bulk read is all-or-nothing, so a single
//     candidate name that does NOT exist would fail the whole read with
//     NOT_FOUND. The value-free `Keys` is called first (no `value.read` audit
//     row) and only the names that EXIST are read — minimum blast radius.
//  3. EMPTY INTERSECTION, NO READ: when no candidate exists the gate is never
//     asked for values, so no read row lands in the audit ledger. "Asking for
//     nothing" is not a read, and rotate-plan uses that ledger as its oracle.
//
// AI-safe: values go back to the CALLER only; this module writes nowhere.
use crate::clierr::Error;
use std::collections::BTreeMap;

/// wanted_subset, the requested candidate names that EXIST in the store, in
/// the REQUESTED order and without duplicates.
///
/// No duplicates is Go's `present[k] = false` trick: a candidate listed twice
/// does not enter the bulk request twice. The order is KEPT (not sorted),
/// because Go keeps it too.
pub fn wanted_subset(present: &[String], keys: &[String]) -> Vec<String> {
    let mut avail: std::collections::BTreeSet<&str> = present.iter().map(String::as_str).collect();
    let mut want = Vec::with_capacity(keys.len());
    for k in keys {
        if avail.remove(k.as_str()) {
            want.push(k.clone());
        }
    }
    want
}

/// KeysFn, the NAME-plane reader (value-free; no `value.read` audit row).
///
/// `+ 'a` so the caller can pass a borrowing closure. With the default
/// `'static` the test fake (a closure borrowing a struct on the stack) would
/// not compile and the seam would be unusable.
pub type KeysFn<'a> = dyn Fn(&str) -> Result<Vec<String>, Error> + 'a;

/// ReadFn, the VALUE-plane reader (bulk, all-or-nothing).
pub type ReadFn<'a> = dyn Fn(&str, &[String]) -> Result<BTreeMap<String, String>, Error> + 'a;

/// store_values, the VALUES of the requested keys from the store when a
/// `.wapps.yaml` names a project (`project`). Go does not check `backend:`
/// here: any loadable config is read.
///
/// `keys_of` and `read_of` are INJECTED — the counterpart of Go's `openStore`
/// test seam. The production caller passes the real `store::keys`/`store::read`;
/// a test walks the same flow without a network.
///
/// Returns:
///   - `Ok(None)`      → NO config; the caller falls back to the env (NOT an error)
///   - `Ok(Some(map))` → the resolved values (possibly an empty map)
///   - `Err(e)`        → a REAL read failure (session, network, grant denied)
pub fn store_values(
    project: Option<&str>,
    keys: &[String],
    keys_of: &KeysFn<'_>,
    read_of: &ReadFn<'_>,
) -> Result<Option<BTreeMap<String, String>>, Error> {
    // No config → (None). The caller falls back to env-only resolution.
    let Some(project) = project else {
        return Ok(None);
    };

    let present = keys_of(project)?;
    let want = wanted_subset(&present, keys);
    if want.is_empty() {
        // The gate is NEVER asked: a read row for an empty intersection would
        // record a read that never happened in the audit ledger.
        return Ok(Some(BTreeMap::new()));
    }
    Ok(Some(read_of(project, &want)?))
}
