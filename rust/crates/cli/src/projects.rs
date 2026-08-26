// projects, `--project <ad>`i besleyen OPSIYONEL kayit defteridir
// (~/.config/wapps/projects.yaml):
//
//   projects:
//     vaulter:  /Users/me/Documents/Projects/infra-tofu/projects/vaulter
//     vibe-pro: /Users/me/Documents/Projects/infra-tofu/projects/vibe-pro
//
// Defter, `--config` uzerine ince bir KOLAYLIK katmanidir: `--project`
// <dir>/.wapps.yaml'a cozulur, oradan sonrasi ayni config-koku yol
// cozumlemesidir. Boylece operator projeye `cd` etmek zorunda kalmaz.
//
// ORACLE: internal/projects/projects.go.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Default)]
struct Registry {
    #[serde(default)]
    projects: BTreeMap<String, String>,
}

/// default_path_from, XDG/HOME degerlerinden defter yolunu cozer (saf bicim).
pub fn default_path_from(xdg: Option<String>, home: Option<String>) -> Result<PathBuf, String> {
    if let Some(x) = xdg.filter(|v| !v.is_empty()) {
        return Ok(Path::new(&x).join("wapps").join("projects.yaml"));
    }
    match home.filter(|v| !v.is_empty()) {
        Some(h) => Ok(Path::new(&h).join(".config").join("wapps").join("projects.yaml")),
        None => Err("projects: resolve home dir: $HOME is not set".to_string()),
    }
}

/// default_path, ~/.config/wapps/projects.yaml doner (XDG onurlandirilir).
pub fn default_path() -> Result<PathBuf, String> {
    default_path_from(std::env::var("XDG_CONFIG_HOME").ok(), std::env::var("HOME").ok())
}

/// resolve, `name` icin kayitli dizini doner.
///
/// Defter YOKSA ya da ad kayitli degilse TIPLI bir "bilinmeyen proje" hatasi
/// doner; GERCEK bir okuma/ayristirma hatasi ise AYNEN yuzeye cikar — operator
/// bozuk bir dosyayi duzeltsin, yaniltici bir "unknown project" gormesin.
pub fn resolve(name: &str) -> Result<String, String> {
    let Ok(path) = default_path() else { return Err(unknown_project(name)) };
    resolve_in(&path, name)
}

/// resolve_in, resolve'un ACIK defter yollu bicimidir (gercek home'a
/// dokunmadan test edilebilsin diye).
pub fn resolve_in(path: &Path, name: &str) -> Result<String, String> {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(unknown_project(name)),
        Err(e) => return Err(format!("projects: read {}: {e}", path.display())),
    };
    let r: Registry = serde_yaml_ng::from_slice(&data)
        .map_err(|e| format!("projects: parse {}: {e}", path.display()))?;
    match r.projects.get(name) {
        Some(dir) if !dir.is_empty() => Ok(expand_home(dir)),
        _ => Err(unknown_project(name)),
    }
}

// expand_home, bastaki `~/`i mutlak home dizinine cevirir ki operatorler
// projects.yaml'a TASINABILIR girdiler yazabilsin.
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
