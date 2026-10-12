// projects is the OPTIONAL registry behind `--project <name>`
// (~/.config/wapps/projects.yaml):
//
//   projects:
//     vaulter:  /Users/me/Documents/Projects/infra-tofu/projects/vaulter
//     vibe-pro: /Users/me/Documents/Projects/infra-tofu/projects/vibe-pro
//
// The registry is a thin CONVENIENCE layer over `--config`: `--project`
// resolves to <dir>/.wapps.yaml, and from there on it is the same config-root
// path resolution. The operator then does not have to `cd` into the project.
//
// ORACLE: internal/projects/projects.go.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
struct Registry {
    // Option: yaml.v3 reads a null entry (`name:`, `~`, `null`) as an empty
    // directory, which resolves as unregistered.
    #[serde(default)]
    projects: BTreeMap<String, Option<String>>,
}

/// default_path_from resolves the registry path from XDG/HOME values (pure form).
pub fn default_path_from(xdg: Option<String>, home: Option<String>) -> Result<PathBuf, String> {
    if let Some(x) = xdg.filter(|v| !v.is_empty()) {
        return Ok(Path::new(&x).join("wapps").join("projects.yaml"));
    }
    match home.filter(|v| !v.is_empty()) {
        Some(h) => Ok(Path::new(&h)
            .join(".config")
            .join("wapps")
            .join("projects.yaml")),
        None => Err("projects: resolve home dir: $HOME is not set".to_string()),
    }
}

/// default_path returns ~/.config/wapps/projects.yaml (XDG is honored).
pub fn default_path() -> Result<PathBuf, String> {
    default_path_from(
        std::env::var("XDG_CONFIG_HOME").ok(),
        std::env::var("HOME").ok(),
    )
}

/// resolve returns the registered directory for `name`.
///
/// When the registry is ABSENT or the name is not registered, it returns a
/// TYPED "unknown project" error; a REAL read or parse error surfaces AS IS, so
/// the operator fixes a broken file instead of seeing a misleading "unknown
/// project".
pub fn resolve(name: &str) -> Result<String, String> {
    let Ok(path) = default_path() else {
        return Err(unknown_project(name));
    };
    resolve_in(&path, name)
}

/// resolve_in is resolve with an EXPLICIT registry path (so it can be tested
/// without touching the real home).
pub fn resolve_in(path: &Path, name: &str) -> Result<String, String> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(unknown_project(name)),
        Err(e) => return Err(format!("projects: read {}: {e}", path.display())),
    };
    let r: Registry = crate::yaml::from_slice(&data)
        .map_err(|e| format!("projects: parse {}: {e}", path.display()))?;
    match r.projects.get(name) {
        Some(Some(dir)) if !dir.is_empty() => Ok(expand_home(dir)),
        _ => Err(unknown_project(name)),
    }
}

// expand_home turns a leading `~/` into the absolute home directory, so that
// operators can write PORTABLE entries in projects.yaml.
fn expand_home(p: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Path::new(&home)
                    .join(p.trim_start_matches('~').trim_start_matches('/'))
                    .to_string_lossy()
                    .into_owned();
            }
        }
    }
    p.to_string()
}

fn unknown_project(name: &str) -> String {
    format!(
        "unknown project {} (add to ~/.config/wapps/projects.yaml or use --config)",
        crate::gojson::quote(name)
    )
}
