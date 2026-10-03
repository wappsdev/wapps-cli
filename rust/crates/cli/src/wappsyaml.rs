// wappsyaml, depo basina `.wapps.yaml` dosyasini yukler ve DOGRULAR.
//
// ORACLE: internal/config/wapps_yaml.go. Bu dosyanin sozlesmesi yalnizca "ayni
// seyleri reddet" degil, "AYNI METINLE reddet": bu hatalari bir INSAN okuyor ve
// metin, yanlis yapilandirilmis bir depoda operatorun elindeki tek ipucu.
//
// Semanin KUCUK ve SABIT tutulmasi bilincli (kaynak tipleri derleme zamaninda
// sabit, calisma zamaninda eklenti yuklenmiyor): boylece bir yazim hatasi
// ayristirma hatasi olarak yuzeye cikar, sessizce BOS bir kume olarak degil.
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// BACKEND_STORE, TEK backend'dir. `backend:` alani yalnizca mevcut dosyalari
// kirmamak icin okunuyor (absent == store).
pub const BACKEND_STORE: &str = "store";
pub const BACKEND_LEGACY_GIT: &str = "legacy-git";

const DEFAULT_VERSION: i64 = 1;

/// Target, arsivden uretilen duz metin tuketim dosyasidir.
///
/// `prefix` neden `Option<String>`: "yok" ile "acikca bos" FARKLI seyler.
/// default_prefix='TF_VAR_' iken bir target'in '' istemesi gercek bir senaryo
/// (terraform.tfvars icin TF_VAR_, .env.local icin duz). Go'da bu `*string`.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Target {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub prefix: Option<String>,
}

impl Target {
    /// effective_prefix, bu target icin FIILEN kullanilan onektir: acikca
    /// verilmisse o (BOS olsa bile), yoksa depo genelindeki varsayilan.
    pub fn effective_prefix<'a>(&'a self, default_prefix: &'a str) -> &'a str {
        match &self.prefix {
            Some(p) => p,
            None => default_prefix,
        }
    }

    /// resolve_path, bu target'in yolunu config_root'a gore cozer.
    pub fn resolve_path(&self, config_root: &str) -> String {
        resolve_rel(config_root, &self.path)
    }
}

/// SourceConfig, bildirilen bir kaynaktir (yalnizca tofu-sync girdileri icin;
/// store backend'de sources OPSIYONEL).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SourceConfig {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub workdir: String,
    #[serde(default)]
    pub prefix: String,
}

/// CoolifyApp, bir arsiv anahtar-onekini tek bir Coolify uygulamasina esler.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CoolifyApp {
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub archive_prefix: String,
}

/// CoolifySync, cok-uygulamali push yapilandirmasidir (opsiyonel).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CoolifySync {
    #[serde(default)]
    pub delete_unmanaged: bool,
    #[serde(default)]
    pub exclude_keys: Vec<String>,
    #[serde(default)]
    pub apps: Vec<CoolifyApp>,
}

/// WappsYaml, ayristirilmis semadir. Varsayilanlar yukleme sirasinda
/// uygulanir, yani cagiranlar alanlarin dolu olduguna guvenebilir.
///
/// BILINMEYEN ALANLAR SESSIZCE ATLANIR ve bu bilincli: Go'nun yaml.v3'u
/// KnownFields ACIK DEGIL, yani sahadaki dosyalarda duran `dest:`,
/// `redact_in_logs:`, `require_clean_git:` gibi eski alanlar hata uretmiyor.
/// `deny_unknown_fields` eklemek o dosyalari kirardi.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct WappsYaml {
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub default_prefix: String,
    #[serde(default)]
    pub sources: Vec<SourceConfig>,
    #[serde(default)]
    pub targets: Vec<Target>,
    #[serde(default)]
    pub coolify_sync: Option<CoolifySync>,

    // config_root, yuklenen dosyanin MUTLAK dizinidir. `load` doldurur,
    // `parse` DOLDURMAZ (diskte dosya yok) — o durumda goreli yollar oldugu
    // gibi birakilir (cwd-goreli, eski davranis).
    #[serde(skip)]
    config_root: String,
}

impl WappsYaml {
    /// config_root, yuklenen `.wapps.yaml`in mutlak dizini (parse ile
    /// kurulmussa "").
    pub fn config_root(&self) -> &str {
        &self.config_root
    }

    /// profile_keys, adlandirilmis bir profilin anahtar listesini doner.
    /// Bos ad → Some(bos liste) = "tum granted anahtarlar" (§7.6).
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

/// load, `path`teki `.wapps.yaml`i okur ve dogrular.
pub fn load(path: &Path) -> Result<WappsYaml, String> {
    let data = std::fs::read(path).map_err(|e| {
        format!(
            "config: read {}: {}",
            path.display(),
            crate::goerr::open_error(&path.display().to_string(), &e)
        )
    })?;
    let mut y = parse(&data)?;
    // Yuklenen dosyanin MUTLAK dizini kaydediliyor ki dest/targets/sources
    // altindaki tum goreli yollar cwd'ye degil ONA gore cozulsun.
    let abs: PathBuf = std::fs::canonicalize(path)
        .or_else(|_| std::env::current_dir().map(|c| c.join(path)))
        .map_err(|e| format!("config: resolve abs path {}: {}", path.display(), e))?;
    y.config_root = abs
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(y)
}

/// parse, load'un test edilebilir yarisidir. AYNI dogrulama iki yolda da kosar.
pub fn parse(data: &[u8]) -> Result<WappsYaml, String> {
    let mut y: WappsYaml = serde_yaml_ng::from_slice(data)
        .map_err(|e| format!("config: parse yaml: {}", yaml_error_text(&e)))?;
    apply_defaults_and_validate(&mut y)?;
    Ok(y)
}

// yaml_error_text, ayristirici hatasini tek satira indirger.
//
// DURUSTLUK NOTU: bu metin Go ile BIREBIR AYNI DEGIL ve olculdu. yaml.v3
// "yaml: mapping values are not allowed in this context" diyor; serde_yaml_ng
// ayni durumu kendi diziyle ve bir konum ekiyle ("at line N column M")
// anlatiyor. Konum eki SOYULUYOR (asagida) cunku iki ayristirici ayni bayta
// ayni konumu vermiyor; geri kalan ayrisma tests/wappsyaml.rs'te DEGIL
// raporda yaziliyor. Go'nun ic hata tablosunu taklit etmek sahte bir sadakat
// olurdu — bir sonraki bozuk dosyada yine ayrisirdi.
fn yaml_error_text(e: &serde_yaml_ng::Error) -> String {
    let s = e.to_string();
    match s.find(" at line ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

fn apply_defaults_and_validate(y: &mut WappsYaml) -> Result<(), String> {
    // ABSENT version → v1 (yeni ikili, eski v1 dosyalari icin bayt-esdeger
    // drop-in). v1|v2 disi → YUKSEK SESLE fail-closed (§7.12 parser matrisi).
    if y.version == 0 {
        y.version = DEFAULT_VERSION;
    }
    if y.version != 1 && y.version != 2 {
        return Err(format!(
            "config: unsupported version {} (only 1 and 2 are supported by this CLI)",
            y.version
        ));
    }

    // v2 alanlari (backend/project/profiles) varsa version 2 ZORUNLU: surum
    // bump'i, ESKI ikililerin sessiz misparse yerine yuksek sesle hata
    // vermesini saglar.
    let carries_v2 = !y.backend.is_empty() || !y.project.is_empty() || !y.profiles.is_empty();
    if carries_v2 && y.version != 2 {
        return Err(format!(
            "config: backend/project/profiles require version: 2 (got version {})",
            y.version
        ));
    }

    // Backend: absent == store. legacy-git ACIK hata — sessizce store'a
    // dusmek, operatorun git'e commit edilen bir arsiv sandigi yerde sunucuya
    // yazmasi demek olurdu.
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

    // project ZORUNLU: gate'in adresi o. sources OPSIYONEL.
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

// validate_source, kaynak adaptorunun kurulabilirligini dogrular (Go'da
// source.New'in kendisi). Adaptor secimi DERLEME ZAMANINDA sabit: tanimadigi
// tip, calisma zamaninda bir eklenti aramak yerine yuksek sesle duser.
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

// validate_targets: yol bos olamaz, tekrar edemez, ve '..' TASIYAMAZ — yanlis
// yapilandirilmis bir yaml depo kokunun DISINA yazamasin.
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

// validate_coolify_sync: her uygulamanin uuid + archive_prefix'i dolu olmali,
// uuid tekrar etmemeli, ve onekler CAKISMAMALI.
//
// Cakismada en-uzun-eslesme SECILMIYOR, REDDEDILIYOR: sessiz bir
// en-uzun-eslesme bir sirri YANLIS uygulamaya yollayabilir ("ROYCO_" ve
// "ROYCO_API_"). Sir materyali icin acik olmak, zekice olmaktan iyidir.
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
