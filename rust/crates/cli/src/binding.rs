// binding, depo→proje baglama PINLERINI yonetir (SPEC §7.7).
//
// NE ISE YARADIGI: bir depodaki `.wapps.yaml` bir proje ADI verir, ama depo
// icindeki bir dosya SALDIRGAN-YAZILABILIR icerktir (confused-deputy dikisi,
// §2 dikis 4). Bu yuzden baglama GUVENILEN home-dir'de pinlenir, depoda DEGIL:
// ~/.config/wapps/repo-pins.json.
//
//   - ILK INSAN KULLANIMINDA (TTY) CLI baglamayi pinler;
//   - Pinlenmemis bir baglamaya carpan bir AJAN (veya non-TTY) BINDING_UNPINNED
//     ile durur — asla pinleyemez, asla pinsiz ilerleyemez;
//   - Pinli bir deponun `.wapps.yaml`i sonradan FARKLI bir proje isimlerse tum
//     modlarda hard fail (re-pin bir insanin trust-repo kosmasini ister).
//
// DOSYA GO ILE PAYLASILIYOR: ayni kullanicinin makinesinde iki ikili de bunu
// okuyup yaziyor, o yuzden bicim BAYT duzeyinde Go'nunkiyle ayni tutuldu ve
// Go ikilisinden OLCULDU (tests/binding.rs).
use crate::atomicfile;
use crate::gojson;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// SCHEMA, pin deposunun sema etiketidir.
pub const SCHEMA: &str = "wapps-repo-pins/v1";

/// Pin, tek bir depo→proje baglamasidir.
/// Alan SIRASI Go struct'iyla ayni (repo, project, backend) — MarshalIndent
/// ciktisi bu siraya gore uretiliyor ve dosya paylasiliyor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// insan-okunur depo kimligi (remote URL veya yol)
    pub repo: String,
    /// pinlenmis proje
    pub project: String,
    /// "store" (baglama yalnizca store icin anlamli)
    pub backend: String,
}

/// CheckError, baglama kontrolunun IKI ayri reddidir. Ayri olmalari sart:
/// cagiran taraf ikisine FARKLI davraniyor (pinsiz → insan/TTY'de satir ici
/// onay; uyusmazlik → her modda hard fail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckError {
    /// baglama hic pinlenmemis (BINDING_UNPINNED)
    Unpinned,
    /// pinli baglama FARKLI bir proje isimliyor (re-pin gerekir)
    Mismatch,
}

/// Store, home-dir pin deposudur; depo parmak iziyle anahtarlanir.
#[derive(Debug, Clone)]
pub struct Store {
    pub schema: String,
    pub pins: BTreeMap<String, Pin>,
}

// wire, diskteki bicimdir. deny_unknown_fields, Go'nun
// DisallowUnknownFields'inin karsiligi: tanimadigi bir alan HATA, sessiz kabul
// DEGIL — ileride eklenen bir alan (ornegin bir kapsam kisiti) eski bir ikilide
// gorunmez kalmasin.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[serde(default)]
    schema: String,
    #[serde(default)]
    pins: Option<BTreeMap<String, Pin>>,
}

// Out, yazim bicimidir. Alan sirasi Go struct'iyla AYNI (schema, pins);
// BTreeMap, Go'nun map anahtarlarini siralamasiyla ayni sirayi verir.
#[derive(Serialize)]
struct Out<'a> {
    schema: &'a str,
    pins: &'a BTreeMap<String, Pin>,
}

impl Store {
    /// empty, bos bir defter doner (ilk kullanim).
    pub fn empty() -> Self {
        Store { schema: SCHEMA.to_string(), pins: BTreeMap::new() }
    }

    /// check, bir depo parmak izi + `.wapps.yaml`in verdigi proje icin
    /// baglamayi dogrular.
    pub fn check(&self, fingerprint: &str, project: &str) -> Result<(), CheckError> {
        match self.pins.get(fingerprint) {
            None => Err(CheckError::Unpinned),
            Some(p) if p.project != project => Err(CheckError::Mismatch),
            Some(_) => Ok(()),
        }
    }

    /// pin, bir baglamayi pinler (YALNIZCA insan/TTY yolundan cagrilir).
    /// Ayni depo icin farkli bir projeye uzerine yazmak ACIK bir re-pin'dir
    /// ve serbesttir (trust-repo'nun yaptigi).
    pub fn pin(&mut self, fingerprint: &str, p: Pin) {
        self.pins.insert(fingerprint.to_string(), p);
    }

    /// save, pin deposunu ATOMIK olarak 0600 modunda yazar.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let schema = if self.schema.is_empty() { SCHEMA } else { self.schema.as_str() };
        let raw = gojson::to_string_indent(&Out { schema, pins: &self.pins })
            .map_err(|e| format!("binding.Store.Save: {e}"))?;
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        atomicfile::create_dir_0700(dir).map_err(|e| format!("binding.Store.Save: mkdir: {e}"))?;
        atomicfile::write(path, raw.as_bytes(), 0o600)
            .map_err(|e| format!("binding.Store.Save: {e}"))
    }
}

/// fingerprint, bir depo baglaminin KARARLI parmak izini doner: kimligin
/// SHA-256 hex'i. Pin deposunun anahtari budur, yani iki ikilinin ayni girdiyi
/// ayni gozde bulmasi buna bagli.
pub fn fingerprint(repo_identity: &str) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, repo_identity.as_bytes());
    let mut out = String::with_capacity(64);
    for b in d.as_ref() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// load, pin deposunu okur. Dosya YOKSA bos bir depo doner (ilk kullanim) —
/// ENOENT bir hata sayilmaz.
pub fn load(path: &Path) -> Result<Store, String> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Store::empty()),
        Err(e) => return Err(format!("binding.Load: read {}: {e}", path.display())),
    };
    let w: Wire = serde_json::from_slice(&raw)
        .map_err(|e| format!("binding.Load: parse {}: {e}", path.display()))?;
    if w.schema != SCHEMA {
        return Err(format!("binding.Load: unexpected schema {}", gojson::quote(&w.schema)));
    }
    Ok(Store { schema: w.schema, pins: w.pins.unwrap_or_default() })
}

/// default_path_from, XDG/HOME degerlerinden pin yolunu cozer (saf bicim).
pub fn default_path_from(xdg: Option<String>, home: Option<String>) -> Result<PathBuf, String> {
    if let Some(x) = xdg.filter(|v| !v.is_empty()) {
        return Ok(Path::new(&x).join("wapps").join("repo-pins.json"));
    }
    match home.filter(|v| !v.is_empty()) {
        Some(h) => Ok(Path::new(&h).join(".config").join("wapps").join("repo-pins.json")),
        None => Err("binding: resolve home dir: $HOME is not set".to_string()),
    }
}

/// default_path, ~/.config/wapps/repo-pins.json doner (XDG onurlandirilir).
pub fn default_path() -> Result<PathBuf, String> {
    default_path_from(std::env::var("XDG_CONFIG_HOME").ok(), std::env::var("HOME").ok())
}
