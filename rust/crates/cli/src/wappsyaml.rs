// wappsyaml loads and VALIDATES the per-repo `.wapps.yaml` file.
//
// ORACLE: internal/config/wapps_yaml.go. The contract of this file is not only
// "refuse the same things" but "refuse them WITH THE SAME TEXT": a HUMAN reads
// these errors, and the text is the operator's only clue in a misconfigured
// repo.
//
// The schema is kept SMALL and FIXED on purpose (source types are fixed at
// compile time, no plugin is loaded at run time): a typo then surfaces as a
// parse error, not silently as an EMPTY set.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// BACKEND_STORE is the ONLY backend. The `backend:` field is read only so that
// existing files keep working (absent == store).
pub const BACKEND_STORE: &str = "store";
pub const BACKEND_LEGACY_GIT: &str = "legacy-git";

const DEFAULT_VERSION: i64 = 1;

/// Target is a plaintext consumer file generated from the archive.
///
/// Why `prefix` is `Option<String>`: "absent" and "explicitly empty" are
/// DIFFERENT. A target that asks for '' while default_prefix='TF_VAR_' is a
/// real case (TF_VAR_ for terraform.tfvars, none for .env.local). In Go this
/// is `*string`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Target {
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub path: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

impl Target {
    /// effective_prefix is the prefix ACTUALLY used for this target: the
    /// explicit one when given (even if EMPTY), else the repo-wide default.
    pub fn effective_prefix<'a>(&'a self, default_prefix: &'a str) -> &'a str {
        match &self.prefix {
            Some(p) => p,
            None => default_prefix,
        }
    }

    /// resolve_path resolves this target's path against config_root.
    pub fn resolve_path(&self, config_root: &str) -> String {
        resolve_rel(config_root, &self.path)
    }
}

/// SourceConfig is a declared source (only for tofu-sync inputs; sources are
/// OPTIONAL with the store backend).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SourceConfig {
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub r#type: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub path: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub workdir: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub prefix: String,
}

/// CoolifyApp maps an archive key prefix to a single Coolify application.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CoolifyApp {
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub uuid: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub name: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub archive_prefix: String,
}

/// CoolifySync is the multi-app push configuration (optional).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CoolifySync {
    #[serde(default, deserialize_with = "crate::yaml::boolean")]
    pub delete_unmanaged: bool,
    #[serde(default)]
    pub exclude_keys: Vec<String>,
    #[serde(default)]
    pub apps: Vec<CoolifyApp>,
}

/// WappsYaml is the parsed schema. Defaults are applied at load time, so
/// callers can rely on the fields being set.
///
/// UNKNOWN FIELDS ARE SILENTLY SKIPPED, on purpose: Go's yaml.v3 does NOT
/// enable KnownFields, so old fields in deployed files such as `dest:`,
/// `redact_in_logs:` and `require_clean_git:` produce no error. Adding
/// `deny_unknown_fields` would break those files.
///
/// String, integer and boolean fields decode through the `crate::yaml`
/// helpers, which keep yaml.v3's null and quoting rules.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WappsYaml {
    #[serde(default, deserialize_with = "crate::yaml::int")]
    pub version: i64,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub backend: String,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub project: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Vec<String>>,
    #[serde(default, deserialize_with = "crate::yaml::string")]
    pub default_prefix: String,
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub coolify_sync: Option<CoolifySync>,

    // config_root is the ABSOLUTE directory of the loaded file. `load` sets
    // it, `parse` does NOT (there is no file on disk); relative paths then
    // stay as they are (cwd-relative, the old behavior).
    #[serde(skip)]
    config_root: String,
}

impl WappsYaml {
    /// config_root is the absolute directory of the loaded `.wapps.yaml`
    /// ("" when built by parse).
    pub fn config_root(&self) -> &str {
        &self.config_root
    }

    /// profile_keys returns the key list of a named profile.
    /// Empty name → Some(empty list) = "all granted keys" (§7.6).
    pub fn profile_keys(&self, name: &str) -> Option<Vec<String>> {
        if name.is_empty() {
            return Some(Vec::new());
        }
        self.profiles.get(name).cloned()
    }

    /// resolved_sources, Go's `ResolvedSources`: a copy of `sources` with
    /// `path` and `workdir` joined to the config root. A tofu source with no
    /// workdir maps to "." first, so it runs in the config dir and never in
    /// the operator's cwd.
    pub fn resolved_sources(&self) -> Vec<SourceConfig> {
        self.sources
            .iter()
            .map(|s| {
                let mut s = s.clone();
                s.path = resolve_rel(&self.config_root, &s.path);
                if s.r#type == "tofu" && s.workdir.is_empty() {
                    s.workdir = ".".to_string();
                }
                s.workdir = resolve_rel(&self.config_root, &s.workdir);
                s
            })
            .collect()
    }
}

// resolve_rel joins a relative p to config_root. Absolute paths and an empty
// config_root pass through unchanged. This is the one rule of
// secrets-from-anywhere: a relative path is relative to the `.wapps.yaml`'s
// directory, an absolute path is taken as is.
//
// The join is Go's `filepath.Join`, which CLEANS the result: "./x" and "a/../x"
// both become "<root>/x", and "." becomes the root itself. Rust's `Path::join`
// does not clean, and the difference is printed (a sync source's name carries
// the resolved path).
fn resolve_rel(config_root: &str, p: &str) -> String {
    if p.is_empty() || config_root.is_empty() || Path::new(p).is_absolute() {
        return p.to_string();
    }
    go_clean(&format!("{config_root}/{p}"))
}

// go_clean, Go's `filepath.Clean` on a Unix path: lexical only (no symlinks).
pub fn go_clean(p: &str) -> String {
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|l| *l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            _ => out.push(part),
        }
    }
    let body = out.join("/");
    match (rooted, body.is_empty()) {
        (true, _) => format!("/{body}"),
        (false, true) => ".".to_string(),
        (false, false) => body,
    }
}

/// load reads and validates the `.wapps.yaml` at `path`.
pub fn load(path: &Path) -> Result<WappsYaml, String> {
    let data = std::fs::read(path).map_err(|e| {
        format!(
            "config: read {}: {}",
            path.display(),
            crate::goerr::open_error(&path.display().to_string(), &e)
        )
    })?;
    let mut y = parse(&data)?;
    // The loaded file's ABSOLUTE directory is recorded so that every relative
    // path under dest/targets/sources resolves against IT, not the cwd.
    let abs: PathBuf = std::fs::canonicalize(path)
        .or_else(|_| std::env::current_dir().map(|c| c.join(path)))
        .map_err(|e| format!("config: resolve abs path {}: {}", path.display(), e))?;
    y.config_root = abs
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(y)
}

/// parse is the testable half of load. The SAME validation runs on both paths.
pub fn parse(data: &[u8]) -> Result<WappsYaml, String> {
    let mut y: WappsYaml = crate::yaml::from_slice(data)
        .map_err(|e| format!("config: parse yaml: {}", yaml_error_text(&e)))?;
    apply_defaults_and_validate(&mut y)?;
    Ok(y)
}

// yaml_error_text reduces the parser error to its message.
//
// HONESTY NOTE: this text is NOT byte-identical to Go's, and that was
// measured. yaml.v3 says "yaml: mapping values are not allowed in this
// context"; serde-saphyr says "mapping values are not allowed in this context
// at line N, column M", and for type errors it uses its own wording. The
// position suffix is STRIPPED (below) because the two parsers do not report
// the same position for the same byte; the remaining divergence is recorded in
// the report, NOT in tests/wappsyaml.rs. Imitating Go's internal error table
// would be fake fidelity: the next malformed file would diverge again.
fn yaml_error_text(e: &serde_saphyr::Error) -> String {
    let s = e.to_string();
    match s.find(" at line ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

fn apply_defaults_and_validate(y: &mut WappsYaml) -> Result<(), String> {
    // ABSENT version → v1 (the new binary is a byte-equivalent drop-in for
    // old v1 files). Anything but v1|v2 → LOUD fail-closed (§7.12 parser
    // matrix).
    if y.version == 0 {
        y.version = DEFAULT_VERSION;
    }
    if y.version != 1 && y.version != 2 {
        return Err(format!(
            "config: unsupported version {} (only 1 and 2 are supported by this CLI)",
            y.version
        ));
    }

    // v2 fields (backend/project/profiles) REQUIRE version 2: the version
    // bump makes OLD binaries fail loudly instead of silently misparsing.
    let carries_v2 = !y.backend.is_empty() || !y.project.is_empty() || !y.profiles.is_empty();
    if carries_v2 && y.version != 2 {
        return Err(format!(
            "config: backend/project/profiles require version: 2 (got version {})",
            y.version
        ));
    }

    // Backend: absent == store. legacy-git is an EXPLICIT error: silently
    // falling back to store would mean writing to the server where the
    // operator believes a git-committed archive is used.
    match y.backend.as_str() {
        "" | BACKEND_STORE => y.backend = BACKEND_STORE.to_string(),
        BACKEND_LEGACY_GIT => {
            return Err(
                "config: backend: legacy-git was removed — the git-committed age archive is gone; \
                 drop the 'backend:' and 'dest:' lines and set 'project: <name>' (values live in the gate)"
                    .to_string(),
            )
        }
        other => {
            return Err(format!(
                "config: unknown backend {} (the only backend is 'store')",
                crate::gojson::quote(other)
            ))
        }
    }

    // project is REQUIRED: it is the gate's address. sources are OPTIONAL.
    if y.project.is_empty() {
        return Err(
            "config: 'project: <name>' is required — it names the project in the secrets gate"
                .to_string(),
        );
    }
    for (i, cfg) in y.sources.iter().enumerate() {
        validate_source(cfg).map_err(|e| format!("config: sources[{i}]: {e}"))?;
    }

    validate_targets(&y.targets)?;
    validate_coolify_sync(y.coolify_sync.as_ref())?;
    Ok(())
}

// validate_source checks that the source adapter can be built (source.New
// itself in Go). Adapter selection is fixed at COMPILE TIME: an unknown type
// fails loudly instead of looking for a plugin at run time.
fn validate_source(cfg: &SourceConfig) -> Result<(), String> {
    match cfg.r#type.as_str() {
        "tofu" => {
            if !cfg.path.is_empty() {
                return Err("source[tofu]: unexpected field 'path' (use 'workdir')".to_string());
            }
            Ok(())
        }
        "file" => {
            if !cfg.workdir.is_empty() {
                return Err("source[file]: unexpected field 'workdir' (use 'path')".to_string());
            }
            if cfg.path.is_empty() {
                return Err("source[file]: missing required field 'path'".to_string());
            }
            Ok(())
        }
        "" => Err("source: missing required field 'type'".to_string()),
        other => Err(format!(
            "source: unknown type {} (allowed: tofu, file)",
            crate::gojson::quote(other)
        )),
    }
}

// validate_targets: a path cannot be empty, cannot repeat, and cannot CONTAIN
// '..', so a misconfigured yaml cannot write OUTSIDE the repo root.
fn validate_targets(targets: &[Target]) -> Result<(), String> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, t) in targets.iter().enumerate() {
        if t.path.is_empty() {
            return Err(format!(
                "config: targets[{i}]: missing required field 'path'"
            ));
        }
        if t.path.contains("..") {
            return Err(format!(
                "config: targets[{i}]: path {} contains '..' (path traversal not allowed)",
                crate::gojson::quote(&t.path)
            ));
        }
        if let Some(j) = seen.get(t.path.as_str()) {
            return Err(format!(
                "config: targets[{i}]: duplicate path {} (also at targets[{j}])",
                crate::gojson::quote(&t.path)
            ));
        }
        seen.insert(&t.path, i);
    }
    Ok(())
}

// validate_coolify_sync: every app needs a uuid and an archive_prefix, a uuid
// must not repeat, and prefixes must NOT OVERLAP.
//
// An overlap is REFUSED, not resolved by longest match: a silent longest
// match could send a secret to the WRONG app ("ROYCO_" and "ROYCO_API_"). For
// secret material, being explicit beats being clever.
fn validate_coolify_sync(cs: Option<&CoolifySync>) -> Result<(), String> {
    let Some(cs) = cs else { return Ok(()) };
    let mut seen_uuid: BTreeMap<&str, usize> = BTreeMap::new();
    for (i, app) in cs.apps.iter().enumerate() {
        if app.uuid.is_empty() {
            return Err(format!(
                "config: coolify_sync.apps[{i}]: missing required field 'uuid'"
            ));
        }
        if app.archive_prefix.is_empty() {
            return Err(format!(
                "config: coolify_sync.apps[{i}] ({}): missing required field 'archive_prefix'",
                app.uuid
            ));
        }
        if let Some(j) = seen_uuid.get(app.uuid.as_str()) {
            return Err(format!(
                "config: coolify_sync.apps[{i}]: duplicate uuid {} (also at apps[{j}])",
                crate::gojson::quote(&app.uuid)
            ));
        }
        seen_uuid.insert(&app.uuid, i);
    }
    for i in 0..cs.apps.len() {
        for j in 0..cs.apps.len() {
            if i == j {
                continue;
            }
            if cs.apps[j]
                .archive_prefix
                .starts_with(&cs.apps[i].archive_prefix)
            {
                return Err(format!(
                    "config: coolify_sync.apps: overlapping archive_prefix {} (apps[{i}]) and {} (apps[{j}]) — prefixes must be mutually exclusive so a key routes to exactly one app",
                    crate::gojson::quote(&cs.apps[i].archive_prefix),
                    crate::gojson::quote(&cs.apps[j].archive_prefix)
                ));
            }
        }
    }
    Ok(())
}
