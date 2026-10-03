// syncverb, `wapps secrets sync` without `--target`: read every source
// declared in `.wapps.yaml`, merge them, and hand the store import plain
// strings.
//
// ORACLE: cmd/secrets/sync.go (readAndMerge), cmd/secrets/store_backend.go
// (runSyncStore, mergedToSets, reportSyncPlan), cmd/secrets/get.go
// (rawValueToString) and internal/source (file.go, tofu.go, tofu_exec.go,
// source.go).
//
// THE HELP TEXT IS NOT THE ORACLE. It says sync writes "an encrypted archive
// to dest"; the code writes the store in one epoch. This module follows the
// code; cli.rs copies the help text byte for byte, wrong as it is, so `--help`
// does not diverge once it is measured.
//
// The wire between a source and the store is the `tofu output -json` shape:
// one raw JSON envelope per key, `{"value": ..., "type": ..., ...}`. Both
// source kinds produce it (the file source wraps each value), and
// `merged_to_sets` turns it into the plain string the import carries.
use crate::gojson;
use crate::wappsyaml::SourceConfig;
use std::collections::BTreeMap;

/// A source's output: key -> raw JSON envelope text.
pub type Envelopes = BTreeMap<String, String>;

/// source_name, Go's `Source.Name()`: the label every read error carries.
pub fn source_name(src: &SourceConfig) -> String {
    match src.r#type.as_str() {
        "tofu" if src.workdir.is_empty() => "tofu (cwd)".to_string(),
        "tofu" => format!("tofu (workdir={})", src.workdir),
        _ => format!("file ({})", src.path),
    }
}

/// read_source, one source's `Read`, with Go's full error chain:
/// `secrets.sync: sources[i] (<name>): source[<name>]: <cause>`.
///
/// `src` is already resolved against the config root (resolved_sources) and
/// validated by the config loader, so the adapter constructors' own
/// rejections (a file source with a workdir, ...) cannot reach this point.
pub fn read_source(index: usize, src: &SourceConfig) -> Result<Envelopes, String> {
    let name = source_name(src);
    let read = match src.r#type.as_str() {
        "tofu" => read_tofu(&src.workdir),
        _ => read_file(&src.path),
    };
    read.map_err(|cause| {
        format!("secrets.sync: sources[{index}] ({name}): source[{name}]: {cause}")
    })
}

// read_file, internal/source/file.go: os.ReadFile + the .env parser shared
// with `import-env`. The parser's errors already carry `source[file (...)]`,
// so they are unwrapped back to the bare cause here and re-wrapped once by
// read_source, giving Go's exact chain.
fn read_file(path: &str) -> Result<Envelopes, String> {
    let data = std::fs::read(path).map_err(|e| crate::goerr::open_error(path, &e))?;
    file_envelopes(path, &data).map_err(|e| {
        let prefix = format!("source[file ({path})]: ");
        e.strip_prefix(&prefix).map(str::to_string).unwrap_or(e)
    })
}

/// file_envelopes, a .env file as envelopes: each value wrapped as
/// `{"value":"..."}` so it merges with tofu output.
pub fn file_envelopes(path: &str, data: &[u8]) -> Result<Envelopes, String> {
    let pairs = crate::importenv::parse_env_file(path, data)?;
    Ok(pairs
        .into_iter()
        .map(|(k, v)| (k, serde_json::json!({ "value": v }).to_string()))
        .collect())
}

// read_tofu, internal/source/tofu_exec.go: `tofu output -json` in the
// workdir. Three Go behaviors are observable and carried:
//   * the program is looked up on PATH BEFORE the workdir matters, so a
//     missing binary and a missing workdir are two different sentences;
//   * the child's stderr is DISCARDED (cmd.Output with Stderr unset): a tofu
//     diagnostic never reaches the terminal, only "exit status N" does;
//   * stdin is /dev/null.
fn read_tofu(workdir: &str) -> Result<Envelopes, String> {
    let path_env = std::env::var("PATH").unwrap_or_default();
    let Some(prog) = crate::goexec::look_path("tofu", &path_env) else {
        return Err(format!(
            "tofu output -json: exec: {}: executable file not found in $PATH",
            gojson::quote("tofu")
        ));
    };
    let mut cmd = std::process::Command::new(prog);
    cmd.args(["output", "-json"]);
    if !workdir.is_empty() {
        cmd.current_dir(workdir);
    }
    let out = cmd.output().map_err(|e| {
        let cause = if workdir.is_empty() {
            crate::goerr::spawn_error("tofu", &e)
        } else {
            // The program was found above, so a failed spawn with a workdir
            // is Go's chdir error.
            crate::goerr::path_error("chdir", workdir, &e)
        };
        format!("tofu output -json: {cause}")
    })?;
    if let Some(text) = crate::goexec::exit_text(out.status) {
        return Err(format!("tofu output -json: {text}"));
    }
    parse_tofu_output(&out.stdout).map_err(|e| format!("parse tofu output: {e}"))
}

/// parse_tofu_output, `json.Unmarshal(raw, &map[string]json.RawMessage{})`:
/// the top-level object as raw envelopes, the last duplicate winning, `null`
/// as no keys. Errors are Go's sentences (without the "parse tofu output: "
/// context, which read_tofu adds).
pub fn parse_tofu_output(raw: &[u8]) -> Result<Envelopes, String> {
    let entries = gojson::decode_raw_object(raw, "map[string]json.RawMessage")?;
    Ok(entries
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v)| (k, v.get().to_string()))
        .collect())
}

/// merge, Go's `source.Merge`: later sources override earlier ones, and each
/// collision is reported (in source order) so the caller can warn.
///
/// Go iterates each source's MAP to report collisions, so when one source
/// overrides SEVERAL keys Go prints them in a random order; here they come
/// out sorted within that source.
pub fn merge(parts: Vec<Envelopes>) -> (Envelopes, Vec<String>) {
    let mut out = Envelopes::new();
    let mut overridden = Vec::new();
    for part in parts {
        for (k, v) in part {
            if out.insert(k.clone(), v).is_some() {
                overridden.push(k);
            }
        }
    }
    (out, overridden)
}

/// The Go type `mergedToSets` decodes each envelope into, as Go names it in a
/// type error.
const ENVELOPE_GO_TYPE: &str = "struct { Value json.RawMessage \"json:\\\"value\\\"\" }";

/// merged_to_sets, Go's `mergedToSets`: each envelope's `value` as the plain
/// string the store import takes. Field matching is Go's (case-insensitive,
/// last match wins); a value that is absent or null becomes "".
pub fn merged_to_sets(merged: &Envelopes) -> Result<BTreeMap<String, String>, String> {
    let mut sets = BTreeMap::new();
    for (k, raw) in merged {
        let entries = gojson::decode_raw_object(raw.as_bytes(), ENVELOPE_GO_TYPE)
            .map_err(|e| format!("store: source key {k} malformed: {e}"))?;
        let value = entries
            .unwrap_or_default()
            .into_iter()
            .rev()
            .find(|(name, _)| name.eq_ignore_ascii_case("value"))
            .map(|(_, v)| v.get().to_string())
            .unwrap_or_default();
        sets.insert(k.clone(), raw_value_to_string(&value));
    }
    Ok(sets)
}

/// raw_value_to_string, Go's `rawValueToString`: a JSON string unquoted, null
/// and absent as "", anything else compacted (json.Compact: whitespace only,
/// key order and number text kept).
pub fn raw_value_to_string(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let t = raw.trim();
    if t == "null" {
        return String::new();
    }
    if let Ok(s) = serde_json::from_str::<String>(t) {
        return s;
    }
    if serde_json::from_str::<serde::de::IgnoredAny>(t).is_ok() {
        return gojson::compact(t);
    }
    t.to_string()
}

/// render_plan, the `--dry-run` report: key NAMES only, new ("+") then
/// changed ("~"), each sorted. Values are compared, never printed.
pub fn render_plan(sets: &BTreeMap<String, String>, current: &BTreeMap<String, String>) -> String {
    let (mut added, mut changed, mut same) = (Vec::new(), Vec::new(), 0usize);
    for (k, v) in sets {
        match current.get(k) {
            None => added.push(k),
            Some(cur) if cur != v => changed.push(k),
            Some(_) => same += 1,
        }
    }
    let mut out = String::new();
    for k in &added {
        out.push_str(&format!("+ {k}\n"));
    }
    for k in &changed {
        out.push_str(&format!("~ {k}\n"));
    }
    if added.is_empty() && changed.is_empty() {
        out.push_str(&format!("✓ In sync — {same} keys match the store\n"));
        return out;
    }
    out.push_str(&format!(
        "\n{} new, {} changed, {same} unchanged. Re-run without --dry-run to commit.\n",
        added.len(),
        changed.len()
    ));
    out
}

/// override_line, the warning for a key a later source replaced (STDERR).
pub fn override_line(key: &str) -> String {
    format!("⚠ key overridden by later source: {key}\n")
}

/// committed_line, the success line (STDOUT): a COUNT, never a value.
pub fn committed_line(count: usize, project: &str) -> String {
    format!("✓ Committed {count} keys to the store for {project}\n")
}
