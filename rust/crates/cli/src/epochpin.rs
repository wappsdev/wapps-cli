// epochpin, sunulan epoch'un yerel pin'e karsi MONOTONLUGUNU zorlar.
//
// NE ISE YARADIGI: gate'ten donen `epoch`, store'un veri surumudur. Bir
// saldirgan (ya da bozuk bir yedekten donmus bir store) daha ESKI bir epoch
// sunarsa, istemci daha eski degerleri "guncel" saymaya baslar — bu bir
// rollback saldirisidir. Pin, proje basina en son GORULEN epoch'u diske yazar
// ve ondan asagi bir epoch'u REDDEDER. Reddin adi EPOCH_DOWNGRADE.
//
// Bu bir davranis degil bir REDDETME: "yardimsever" olup daha eski epoch'u
// kabul etmek, korumanin kendisini kaldirir. Bu yuzden ileri-yonlu ve kalici:
//   served <  pinned  → EPOCH_DOWNGRADE (hard fail, pin'e DOKUNULMAZ)
//   served == pinned  → kabul, dosyaya yazim YOK
//   served >  pinned  → kabul, pin ilerletilir ve kaydedilir
//
// TEK mesru istisna, `accept_reset`: pin sunulan (daha dusuk) epoch'a INDIRILIR.
// Go tarafinda bu bayragi yalnizca `wapps dr accept-epoch-reset` seremoni
// verb'u — kagit zarftaki audit-head hash'inin out-of-band dogrulanmasindan
// SONRA — kuruyor, ve get/exec/apply yollarina ASLA threadlenmiyor. Bu dilimde
// o verb yok; tek cagri yeri (store::read) daima `false` geciyor. Mekanizma
// yine de tasindi, cunku onu atlamak `dr` portlandiginda sessizce eksik
// kalabilecek bir istisnayi yeniden kesfettirirdi.
//
// GO ILE PAYLASILAN DOSYA: ~/.config/wapps/epochs.json (XDG onurlandirilir).
// Ayni kullanicinin makinesinde iki ikili de bunu okuyup yaziyor, o yuzden
// bicim BAYT duzeyinde Go'nunkiyle ayni (gojson::to_string_indent).
//
// TASINMAYAN: Go'nun `pinnedEpoch` okuyucusu (`secrets status` icin) ve
// Config.EpochPinPath yonlendirmesi. Ikisinin de bu dilimde cagirani yok;
// yol dogrudan parametre olarak geciyor, ki testler gercek $HOME'a dokunmasin.
//
// BILINEN AYRISMA: yukleme/kaydetme HATA METINLERI Go'nunkiyle bire bir DEGIL
// (Go net/os hata dizelerini gomuyor, burada std::io'nunkiler var). Kodlar ve
// fail-closed yon ayni; metin ayristigi icin bu yollar differential'a
// KONULMADI — sahte bir sadakat olurdu.
use crate::clierr::{Code, Error};
use crate::gojson;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// SCHEMA, pin dosyasinin sema etiketidir (Go'daki epochPinSchema).
pub const SCHEMA: &str = "wapps-epoch-pins/v1";

// wire, diskteki bicimdir. deny_unknown_fields, Go'nun
// DisallowUnknownFields'inin karsiligi: tanimadigi bir alan HATA, sessiz kabul
// degil.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[serde(default)]
    schema: String,
    // Go'da nil map bos map gibi davraniyor; `null` da eksik alan da bos.
    #[serde(default)]
    pins: Option<BTreeMap<String, u64>>,
}

// Out, yazim bicimidir. Alan sirasi Go struct'iyla AYNI (schema, pins);
// BTreeMap, Go'nun map anahtarlarini siralamasiyla ayni sirayi verir.
#[derive(Serialize)]
struct Out<'a> {
    schema: &'a str,
    pins: &'a BTreeMap<String, u64>,
}

struct Pins {
    schema: String,
    pins: BTreeMap<String, u64>,
}

/// default_path_from, XDG/HOME degerlerinden pin yolunu cozer (saf bicim).
pub fn default_path_from(xdg: Option<String>, home: Option<String>) -> Result<PathBuf, Error> {
    if let Some(x) = xdg.filter(|v| !v.is_empty()) {
        return Ok(Path::new(&x).join("wapps").join("epochs.json"));
    }
    match home.filter(|v| !v.is_empty()) {
        Some(h) => Ok(Path::new(&h)
            .join(".config")
            .join("wapps")
            .join("epochs.json")),
        None => Err(Error::new(
            Code::Internal,
            "store: resolve home dir: $HOME is not set",
        )),
    }
}

/// default_path, uretim yolunu cozer.
pub fn default_path() -> Result<PathBuf, Error> {
    default_path_from(
        std::env::var("XDG_CONFIG_HOME").ok(),
        std::env::var("HOME").ok(),
    )
}

fn load(path: &Path) -> Result<Pins, Error> {
    let raw = match std::fs::read(path) {
        Ok(r) => r,
        // Dosya yoksa pin de yok: bos kume. Bu fail-open DEGIL — pin 0 demek,
        // ve 0'in altinda bir epoch yok.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Pins {
                schema: SCHEMA.to_string(),
                pins: BTreeMap::new(),
            })
        }
        Err(e) => {
            return Err(Error::new(
                Code::Internal,
                format!("store.loadEpochPins: {e}"),
            ))
        }
    };
    let w: Wire = serde_json::from_slice(&raw)
        .map_err(|e| Error::new(Code::Internal, format!("store.loadEpochPins: parse: {e}")))?;
    Ok(Pins {
        schema: w.schema,
        pins: w.pins.unwrap_or_default(),
    })
}

fn save(path: &Path, p: &Pins) -> Result<(), Error> {
    let schema = if p.schema.is_empty() {
        SCHEMA
    } else {
        p.schema.as_str()
    };
    let raw = gojson::to_string_indent(&Out {
        schema,
        pins: &p.pins,
    })
    .map_err(|e| Error::new(Code::Internal, format!("store.epochPins.save: {e}")))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    create_dir_0700(dir)
        .map_err(|e| Error::new(Code::Internal, format!("store.epochPins.save: mkdir: {e}")))?;
    write_atomic_0600(path, raw.as_bytes())
        .map_err(|e| Error::new(Code::Internal, format!("store.epochPins.save: {e}")))
}

// Dizin kurma ve atomik yazim artik PAYLASILAN atomicfile modulunde. Uc ayri
// kopya (epoch pini, baglama defteri, apply hedefleri) hepsi "atomik" der ama
// zamanla ayrisirdi; garanti tek yerde duruyor.
use crate::atomicfile::{create_dir_0700, write as write_atomic};

fn write_atomic_0600(path: &Path, data: &[u8]) -> std::io::Result<()> {
    write_atomic(path, data, 0o600)
}

/// check_and_advance, sunulan epoch'un yerel pin'e karsi monotonlugunu zorlar.
///
/// `accept_reset` YALNIZCA seremoni verb'unun kurabilecegi bayraktir; sirasi
/// onemli: kontrol once, indirme sonra, ve indirme de KAYDEDILIR (tek
/// non-monotonik gecis).
pub fn check_and_advance(
    path: &Path,
    project: &str,
    served: u64,
    accept_reset: bool,
) -> Result<(), Error> {
    let mut p = load(path)?;
    let pinned = p.pins.get(project).copied().unwrap_or(0);
    if served < pinned {
        if accept_reset {
            p.pins.insert(project.to_string(), served);
            return save(path, &p).map_err(|e| {
                Error::new(Code::Internal, format!("persist epoch pin (reset): {e}"))
            });
        }
        return Err(Error::new(
            Code::EpochDowngrade,
            format!("served epoch {served} < pinned {pinned} for {}", gojson::quote(project)),
        )
        .with_recovery(format!(
            "possible rollback attack — do NOT force; if the store was LEGITIMATELY rebuilt, a human must run the paper-verified ceremony: wapps dr accept-epoch-reset --project {project}"
        )));
    }
    if served > pinned {
        p.pins.insert(project.to_string(), served);
        return save(path, &p)
            .map_err(|e| Error::new(Code::Internal, format!("persist epoch pin: {e}")));
    }
    Ok(())
}
