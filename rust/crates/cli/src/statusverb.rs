// statusverb, `wapps secrets status` — makine-okunur oturum/store durumu.
//
// SOZLESMESI ALISILMADIK: status'un isi "dogru cevap vermek" degil, ASLA
// HARD-FAIL ETMEMEK. Bir ajan baska her sey hata verdiginde ILK bunu kosuyor,
// yani her adim fail-safe: bilinmeyen alanlar false/0 kalir, hicbir okuma hata
// FIRLATMAZ. Bu yuzden buradaki fonksiyonlarin hicbiri Result donmuyor.
//
// v2'de (server-decrypt SPEC §7) ciphertext cache SILINDI (cache_age yok) ve
// yerel kimlik deposu SILINDI (identity_present yok — kimlik = CF Access
// oturumu). Kalan sema dort alan.
//
// ORACLE: cmd/secrets/status.go, internal/session/session.go (Load, Expired,
// TTL, hostFile), internal/session/auth.go (GateHost).
//
// KAPI: status ajan modunda SERBEST (agentPolicy["status"] = allow) ve
// baglama kontrolunden MUAF (bindingExempt). Ikisi birlikte "her modda
// guvenli" vaadinin ta kendisi — biri kalkarsa vaat de kalkar.
use crate::gojson;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// StatusReport, makine-okunur durum semasidir.
///
/// `session_expires_in` SANIYE; `epoch_pin` per-proje pinlenmis data epoch'u
/// (rollback tripwire'i, §7.4). Alan SIRASI Go struct'iyla ayni — JSON bicimi
/// bir sozlesme.
#[derive(Debug, Serialize, Default)]
pub struct StatusReport {
    pub online: bool,
    pub session_valid: bool,
    pub session_expires_in: i64,
    pub epoch_pin: u64,
}

/// render_text, insan-okunur dort satiri uretir (Go'daki Fprintf hizalamasi).
pub fn render_text(r: &StatusReport) -> String {
    format!(
        "online:           {}\nsession_valid:    {}\nsession_expires:  {}s\nepoch_pin:        {}\n",
        r.online, r.session_valid, r.session_expires_in, r.epoch_pin
    )
}

/// render_json, tek satir JSON + newline uretir.
///
/// HTML kacisi KAPALI (Go: enc.SetEscapeHTML(false)) — gojson::to_string zaten
/// bu davranisi tasiyor. Encoder'in ekledigi son newline de sozlesmenin
/// parcasi.
pub fn render_json(r: &StatusReport) -> String {
    match gojson::to_string(r) {
        Ok(s) => format!("{s}\n"),
        // status ASLA hard-fail etmez; kodlama coksa bile bir sema basilir.
        Err(_) => "{\"online\":false,\"session_valid\":false,\"session_expires_in\":0,\"epoch_pin\":0}\n"
            .to_string(),
    }
}

// PinsWire, status'un pin okuyucusudur.
//
// `deny_unknown_fields` BILINCLI OLARAK YOK ve bu epochpin.rs'ten bir AYRISMA
// degil, olculmus bir fark: Go'da okuma yolu DisallowUnknownFields kullaniyor
// (bozuk/ileri surumlu bir dosya `exec`i dusurur) ama status kendi anonim
// struct'iyla okuyor ve o kisitlama orada YOK. status'un hicbir kosulda
// dusmemesi tam olarak bu demek. Olcusu: tests/statusverb.rs
// (status_tolerates_pin_fields_that_the_read_path_would_reject).
#[derive(Deserialize, Default)]
struct PinsWire {
    #[serde(default)]
    pins: std::collections::BTreeMap<String, u64>,
}

/// read_epoch_pin, projenin data epoch pin'ini doner (yoksa/bozuksa 0).
pub fn read_epoch_pin(path: &Path, project: &str) -> u64 {
    if project.is_empty() {
        return 0;
    }
    let Ok(raw) = std::fs::read(path) else { return 0 };
    let Ok(w) = serde_json::from_slice::<PinsWire>(&raw) else { return 0 };
    w.pins.get(project).copied().unwrap_or(0)
}

// SessionWire, diskteki oturum dosyasidir. Deger (token) ASLA basilmaz;
// yalnizca BOS olup olmadigina bakilir.
#[derive(Deserialize, Default)]
struct SessionWire {
    #[serde(default)]
    token: String,
    #[serde(default)]
    expires_at: i64,
}

/// read_session_from, oturum gecerliligini + kalan saniyeyi doner.
///
/// SIRA Go ile ayni (session.Load): once out-of-band env jetonu, sonra dosya.
/// `now_unix` disaridan geliyor ki test gercek saate bagli olmasin.
///
/// `expires_at == 0` → expiry BILINMIYOR (out-of-band jeton) → dolmaz sayilir
/// ve kalan 0 raporlanir. Gate yine de kenarda dogruluyor, yani bu "sonsuz
/// oturum" demek DEGIL.
pub fn read_session_from(
    env: &dyn Fn(&str) -> Option<String>,
    session_path: &Path,
    now_unix: i64,
) -> (bool, i64) {
    let state = match env("WAPPS_SESSION_TOKEN").filter(|t| !t.is_empty()) {
        Some(_) => {
            let exp = env("WAPPS_SESSION_EXPIRES")
                .and_then(|e| e.parse::<i64>().ok())
                .unwrap_or(0);
            SessionWire { token: "present".to_string(), expires_at: exp }
        }
        None => {
            let Ok(raw) = std::fs::read(session_path) else { return (false, 0) };
            match serde_json::from_slice::<SessionWire>(&raw) {
                Ok(s) if !s.token.is_empty() => s,
                _ => return (false, 0),
            }
        }
    };
    // Expired: expires_at != 0 && expires_at <= now.
    if state.expires_at != 0 && state.expires_at <= now_unix {
        return (false, 0);
    }
    if state.expires_at == 0 {
        return (true, 0);
    }
    (true, state.expires_at - now_unix)
}

// The session-file key helpers moved to session.rs, where `wapps login`
// writes the file they name; re-exported so status keeps its call sites.
pub use crate::session::{host_file, host_of};
