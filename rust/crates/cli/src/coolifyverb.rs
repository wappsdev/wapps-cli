// coolifyverb, `wapps coolify update-env` and `wapps coolify set-labels` — the
// port of cmd/coolify/{coolify,update_env,set_labels}.go.
//
// Order, measured from the Go oracle (tests/pty/cases.py, COOLIFY_CASES):
//
//   1. flag VALUES (pflag): every `--env`/`--label` value is read as CSV and
//      `--strip-cert-resolver` by strconv.ParseBool; the first bad value from
//      the left is the error. This is PARSE time in Go, so it beats the root's
//      `--config`/`--project` check — main.rs calls `parse_flags` before it;
//   2. the required `--app-uuid` (cobra, after the root hook);
//   3. COOLIFY_API_TOKEN;
//   4. the verb's own checks, then the client (uuid check, then HTTP).
//
// No agent gate, no binding, no `Ctx`: the root `-c`/`-p` are inert.
use crate::coolify::Client;
use crate::gocsv;
use crate::gostrconv::{parse_bool, quote};
use std::collections::BTreeMap;
use std::io::Write;

// DEFAULT_ENDPOINT, Go's getEndpoint fallback when COOLIFY_URL is unset/empty.
const DEFAULT_ENDPOINT: &str = "https://coolify.meapps.dev/api/v1";

/// Leaf, one parsed `coolify` subcommand.
pub enum Leaf {
    UpdateEnv {
        app_uuid: Option<String>,
        envs: Vec<String>,
    },
    SetLabels {
        app_uuid: Option<String>,
        labels: Vec<String>,
        strip: bool,
    },
}

/// string_slice, the values of a pflag `StringSliceVar` given as `flag`:
/// each value read as CSV (gocsv), the results concatenated; a bad value is
/// refused with pflag's sentence.
pub fn string_slice(flag: &str, values: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for v in values {
        out.extend(gocsv::read_as_csv(v).map_err(|e| invalid_argument(v, flag, &e))?);
    }
    Ok(out)
}

// invalid_argument, pflag's `*InvalidValueError` text.
fn invalid_argument(value: &str, flag: &str, cause: &str) -> String {
    format!(
        "invalid argument {} for {} flag: {cause}",
        quote(value),
        quote(flag)
    )
}

/// parse_env_kvs, Go's `parseEnvKVs`: "KEY=VAL" entries into a map (last
/// value of a key wins); an entry without '=' or with an empty key is refused.
pub fn parse_env_kvs(pairs: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for kv in pairs {
        let Some((k, v)) = kv.split_once('=') else {
            return Err(format!("invalid env (need KEY=VAL): {}", quote(kv)));
        };
        if k.is_empty() {
            return Err(format!("invalid env (empty KEY): {}", quote(kv)));
        }
        out.insert(k.to_string(), v.to_string());
    }
    Ok(out)
}

/// strip_cert_resolver, set-labels' filter: with `strip` on, every label
/// containing "certresolver=letsencrypt" is dropped.
pub fn strip_cert_resolver(labels: &[String], strip: bool) -> Vec<String> {
    labels
        .iter()
        .filter(|l| !strip || !l.contains("certresolver=letsencrypt"))
        .cloned()
        .collect()
}

// valued, every value of a repeatable arg with its command-line index.
fn valued(m: &clap::ArgMatches, id: &str) -> Vec<(usize, String)> {
    match (m.get_many::<String>(id), m.indices_of(id)) {
        (Some(vals), Some(idx)) => idx.zip(vals.cloned()).collect(),
        _ => Vec::new(),
    }
}

// first_error, the error of the value pflag would hit first (leftmost).
fn first_error(errs: impl IntoIterator<Item = (usize, String)>) -> Result<(), String> {
    match errs.into_iter().min_by_key(|(i, _)| *i) {
        Some((_, e)) => Err(e),
        None => Ok(()),
    }
}

/// parse_flags, a `coolify` leaf's flags as pflag would have parsed them;
/// None for a leaf this binary does not have.
pub fn parse_flags(leaf: &str, m: &clap::ArgMatches) -> Option<Result<Leaf, String>> {
    // `--app-uuid` is a StringVar: the last one wins.
    let app_uuid = valued(m, "app-uuid").pop().map(|(_, v)| v);
    Some(match leaf {
        // One slice flag: string_slice already stops at the leftmost bad value.
        "update-env" => {
            string_slice("--env", &values(m, "env")).map(|envs| Leaf::UpdateEnv { app_uuid, envs })
        }
        "set-labels" => {
            let strip_vals = valued(m, "strip-cert-resolver");
            let strip_errors = strip_vals.iter().filter_map(|(i, v)| {
                parse_bool(v)
                    .err()
                    .map(|e| (*i, invalid_argument(v, "--strip-cert-resolver", &e)))
            });
            // Two flags: the error is the leftmost bad value across both.
            let mut errs: Vec<(usize, String)> = valued(m, "label")
                .into_iter()
                .filter_map(|(i, v)| string_slice("--label", &[v]).err().map(|e| (i, e)))
                .collect();
            errs.extend(strip_errors);
            first_error(errs).and_then(|()| {
                Ok(Leaf::SetLabels {
                    app_uuid,
                    labels: string_slice("--label", &values(m, "label"))?,
                    // Default true; the last occurrence wins.
                    strip: match strip_vals.last() {
                        Some((_, v)) => parse_bool(v)?,
                        None => true,
                    },
                })
            })
        }
        _ => return None,
    })
}

fn values(m: &clap::ArgMatches, id: &str) -> Vec<String> {
    m.get_many::<String>(id)
        .map(|v| v.cloned().collect())
        .unwrap_or_default()
}

/// run, the leaf's RunE after the root hook. Errors are Go's plain texts.
pub fn run<W: Write>(leaf: Leaf, out: &mut W) -> Result<(), String> {
    let (Leaf::UpdateEnv { app_uuid, .. } | Leaf::SetLabels { app_uuid, .. }) = &leaf;
    let Some(app_uuid) = app_uuid.clone() else {
        return Err("required flag(s) \"app-uuid\" not set".to_string());
    };
    let token = std::env::var("COOLIFY_API_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return Err("COOLIFY_API_TOKEN not set".to_string());
    }
    let endpoint = match std::env::var("COOLIFY_URL") {
        Ok(e) if !e.is_empty() => e,
        _ => DEFAULT_ENDPOINT.to_string(),
    };
    match leaf {
        Leaf::UpdateEnv { envs, .. } => {
            let envs = parse_env_kvs(&envs)?;
            Client::new(&endpoint, &token).update_app_envs(&app_uuid, &envs)?;
            let _ = writeln!(out, "✓ Updated {} env vars on {app_uuid}", envs.len());
        }
        Leaf::SetLabels { labels, strip, .. } => {
            let filtered = strip_cert_resolver(&labels, strip);
            // Coolify treats an empty custom_labels as "clear all labels".
            if filtered.is_empty() {
                return Err("set-labels: no labels to set (pass --label at least once); refusing to wipe existing labels".to_string());
            }
            Client::new(&endpoint, &token).set_custom_labels(&app_uuid, &filtered)?;
            let _ = writeln!(out, "✓ Set {} labels on {app_uuid}", filtered.len());
        }
    }
    Ok(())
}
