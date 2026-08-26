// store, gate'in HTTP tasimasi + hata eslemesidir.
// Ham gate govdesi ASLA transcript'e yayilmaz — hatalar clierr sozlesmesine
// eslenir, yalnizca kod + kisa alanlar tasinir.
use crate::clierr::{Code, Error};
use crate::epochpin;
use crate::session;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// WorkerError, gate'in makine-okunur hata govdesidir.
#[derive(Debug, Default, Deserialize)]
pub struct WorkerError {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub dimension: String,
    #[serde(default)]
    pub rule_index: Option<i64>,
    #[serde(default)]
    pub current_version: u64,
}

#[derive(Debug, Deserialize)]
pub struct ReadResult {
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub values: BTreeMap<String, String>,
}

// safe_code, disaridan gelen bir kod/alan dizesini transcript'e girmeden once
// budar: yalnizca kisa, tek satirlik bir isaret tasinir.
fn safe_code(s: &str) -> String {
    let one: String = s.replace(['\n', '\r'], " ");
    let t = one.trim();
    if t.len() > 64 {
        t.chars().take(64).collect()
    } else {
        t.to_string()
    }
}

fn parse_worker_error(body: &str) -> WorkerError {
    serde_json::from_str(body).unwrap_or_default()
}

/// map_http_error, non-2xx bir gate yanitini CLI hata sozlesmesine esler.
/// Go'daki mapHTTPError'in portu — dallanma sirasi ve metinler ORACLE'dan.
pub fn map_http_error(status: u16, body: &str, retry_after: u64, ctx: &str) -> Error {
    let we = parse_worker_error(body);
    match status {
        401 => Error::new(
            Code::SessionExpired,
            format!("{ctx}: gate rejected the session ({})", safe_code(&we.error)),
        ),
        403 => match we.error.as_str() {
            "MACHINE_TOKEN_REQUIRED" | "TOKEN_EXPIRED" | "TOKEN_REVOKED"
            | "TOKEN_SCOPE_EXCEEDED" => Error::new(
                Code::SessionExpired,
                format!("{ctx}: machine token invalid ({})", safe_code(&we.error)),
            ),
            _ => {
                let e = if !we.key.is_empty() {
                    Error::new(
                        Code::GrantDenied,
                        format!(
                            "{ctx}: denied on key {} (dimension {})",
                            safe_code(&we.key),
                            safe_code(&we.dimension)
                        ),
                    )
                } else {
                    Error::new(
                        Code::GrantDenied,
                        format!(
                            "{ctx}: {} (dimension {})",
                            safe_code(&we.error),
                            safe_code(&we.dimension)
                        ),
                    )
                };
                e.with_recovery("ask an admin to extend policy.json (wapps secrets policy set)")
            }
        },
        404 => {
            if !we.key.is_empty() {
                Error::new(Code::NotFound, format!("{ctx}: key {} not found", safe_code(&we.key)))
            } else {
                Error::new(Code::NotFound, format!("{ctx}: not found ({})", safe_code(&we.error)))
            }
        }
        409 => Error::new(Code::CasConflict, format!("{ctx}: {}", safe_code(&we.error))),
        412 => {
            if we.error == "POLICY_CONFLICT" {
                Error::new(
                    Code::PolicyConflict,
                    format!("{ctx}: policy version conflict (current {})", we.current_version),
                )
            } else {
                Error::new(Code::CasConflict, format!("{ctx}: epoch conflict"))
            }
        }
        413 => {
            if we.error == "RESPONSE_TOO_LARGE" {
                Error::new(Code::ActionUnavailable, format!("{ctx}: read response too large"))
                    .with_recovery(
                        "this bulk read exceeds the gate's response cap — request fewer keys at a time",
                    )
            } else {
                Error::new(Code::BlobTooLarge, format!("{ctx}: {}", safe_code(&we.error)))
            }
        }
        422 => {
            if we.error == "POLICY_INVALID" {
                let idx = we.rule_index.map(|i| i.to_string()).unwrap_or_else(|| "?".to_string());
                Error::new(Code::PolicyInvalid, format!("{ctx}: policy invalid (rule index {idx})"))
            } else {
                Error::new(Code::Internal, format!("{ctx}: {}", safe_code(&we.error)))
            }
        }
        429 => Error::new(
            Code::RateLimited,
            format!("{ctx}: rate limited (retry after {retry_after}s)"),
        ),
        503 => match we.error.as_str() {
            "AUDIT_UNAVAILABLE" => Error::new(
                Code::AuditUnavailable,
                format!("{ctx}: audit ledger unavailable — plaintext refused"),
            ),
            "IDENTITY_UNAVAILABLE" => {
                Error::new(Code::IdentityUnavailable, format!("{ctx}: identity/groups unresolvable"))
            }
            _ => Error::new(Code::ServiceMisconfig, format!("{ctx}: {}", safe_code(&we.error))),
        },
        400 => Error::new(Code::Internal, format!("{ctx}: bad request ({})", safe_code(&we.error))),
        s => Error::new(Code::Internal, format!("{ctx}: unexpected status {s}")),
    }
}

// DEFAULT_RETRY_AFTER, Retry-After header'i yoksa kullanilan saniyedir
// (Go tarafiyla ayni varsayilan).
const DEFAULT_RETRY_AFTER: u64 = 60;

// --- KOK GUVEN DEPOSU (plan §9.5, sik C) ---------------------------------
//
// Taban GOMULU (`webpki-roots`), ustune `SSL_CERT_FILE` ve `SSL_CERT_DIR`
// ayarliysa ONLAR DA ekleniyor. Neden env: TLS denetleyen bir proxy arkasindaki
// CI runner'in kendi CA'sini surece tanitmasinin tek tasinabilir yolu bu, ve Go
// tarafi (crypto/x509, root_unix.go) Linux'ta zaten ayni iki degiskeni okuyor.
//
// DURUSTLUK NOTU — bu parite DEGIL, iki yerde:
//  * darwin'de root_unix.go'nun build etiketi devrede DEGIL, yani Go orada bu
//    degiskenleri HIC okumuyor. Rust artik okuyor: ayrisma kapanmiyor, YONU
//    degisiyor (once Rust katiydi, simdi Go kati).
//  * Linux'ta bile Go env degiskenini gorunce sistem demetinin YERINE koyuyor;
//    burada ise gomulu tabana EKLENIYOR, yani kabul yuzeyi daha genis kaliyor.
// Ikisi de tests/tlstrust.rs'te olculuyor ve orada yaziliyor.
//
// Bozuk/okunamayan girdi SESSIZCE atlanir, ret sebebi olmaz: bir CA demetindeki
// tek cursuk sertifika butun HTTPS'i kapatmamali (Go'nun AppendCertsFromPEM'i de
// boyle davraniyor). Yol adlari ve ayristirma hatalari transcript'e YAZILMAZ.

// add_pem_file, tek bir PEM dosyasindaki sertifikalari depoya ekler.
fn add_pem_file(store: &mut rustls::RootCertStore, path: &std::path::Path) {
    let Ok(iter) = rustls_pki_types::CertificateDer::pem_file_iter(path) else { return };
    for der in iter.flatten() {
        let _ = store.add(der);
    }
}

// root_store, gomulu tabani kurar ve env ile bildirilen koklerin USTUNE ekler.
fn root_store() -> rustls::RootCertStore {
    let mut store =
        rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    if let Some(f) = std::env::var_os("SSL_CERT_FILE") {
        add_pem_file(&mut store, std::path::Path::new(&f));
    }
    if let Some(d) = std::env::var_os("SSL_CERT_DIR") {
        // OpenSSL'in c_rehash duzeni uzantisiz `<hash>.0` dosyalari birakiyor,
        // yani ada gore filtreleme YAPILMIYOR: her girdi PEM olarak denenir.
        if let Ok(entries) = std::fs::read_dir(&d) {
            for e in entries.flatten() {
                add_pem_file(&mut store, &e.path());
            }
        }
    }
    store
}

// agent, kok deposu ELDE KURULMUS bir ureq ajani doner. `ureq::post` yerine bunu
// kullanmak zorunlu: serbest fonksiyon ureq'in kendi varsayilan yapilandirmasina
// gidiyor ve oraya ekleme yapmanin yolu yok.
fn agent() -> ureq::Agent {
    // builder_with_provider, builder()'in aksine surec genelinde bir kripto
    // saglayicisi kurulmus olmasini SART kosmuyor — ureq'in kendi yolunun aynisi.
    let cfg = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
    .expect("ring saglayicisi TLS1.2+1.3 ile uyumlu")
    .with_root_certificates(root_store())
    .with_no_client_auth();
    ureq::AgentBuilder::new().tls_config(Arc::new(cfg)).build()
}

/// read, POST /v1/projects/{p}/read cagirir ve degerleri doner.
pub fn read(project: &str, keys: &[String]) -> Result<ReadResult, Error> {
    let headers = session::auth_headers()?;
    let mut sorted: Vec<String> = keys.to_vec();
    sorted.sort();
    let body = serde_json::json!({ "keys": sorted });
    let url = format!(
        "{}/v1/projects/{}/read",
        session::gate_url(),
        urlencode_path_segment(project)
    );
    let mut req = agent().post(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = format!("read {project}");
    match req.send_json(body) {
        Ok(resp) => {
            let text = resp.into_string().map_err(|e| {
                Error::new(Code::NetworkRequired, format!("secrets gate response truncated: {e}"))
            })?;
            let out = serde_json::from_str::<ReadResult>(&text)
                .map_err(|e| Error::new(Code::Internal, format!("decode {ctx}: {e}")))?;
            // EPOCH PIN — cozumden SONRA, deger dondurulmeden ONCE (Go'daki
            // sira). Sunulan epoch yerel pin'in altindaysa bu cagri
            // EPOCH_DOWNGRADE ile duser: daha eski bir store'un degerleri
            // cagirana HIC ulasmaz. `accept_reset` daima false, cunku onu
            // kuran seremoni verb'u (`wapps dr accept-epoch-reset`) bu dilimde
            // yok ve Go tarafinda da get/exec/apply yollarina ASLA
            // threadlenmiyor.
            epochpin::check_and_advance(&epochpin::default_path()?, project, out.epoch, false)?;
            Ok(out)
        }
        Err(ureq::Error::Status(status, resp)) => {
            let retry_after = resp
                .header("Retry-After")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_RETRY_AFTER);
            let text = resp.into_string().unwrap_or_default();
            Err(map_http_error(status, &text, retry_after, &ctx))
        }
        // Tasima hatasi → NETWORK_REQUIRED (cevrimdisi mod YOK).
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// set, PUT /v1/projects/{p}/keys/{KEY} cagirir — TEK anahtar yazimi.
///
/// EPOCH PIN'E DOKUNMAZ, ve bu bir eksiklik degil Go'nun sozlesmesi: pin
/// yalnizca Keys/Read yollarinda (checkAndAdvanceEpochPin) ilerliyor. Bir yazim
/// sunulan bir epoch OKUMUYOR, dolayisiyla pinleyecek bir sey de yok. Bunu
/// "tamamlamak" — yazim sonrasi pin'i oynatmak — sahadaki ikiliyle ayrisirdi;
/// differential pin dosyasinin son halini de karsilastirdigi icin gorunurdu
/// (human_set_leaves_pin_alone).
///
/// HATA BAGLAMI "set <KEY>" (read'deki "read <proje>" DEGIL) — Go'daki
/// mapHTTPError(r, "set "+key) ile ayni.
pub fn set(project: &str, key: &str, value: &str) -> Result<(), Error> {
    let headers = session::auth_headers()?;
    let body = serde_json::json!({ "value": value });
    let url = format!(
        "{}/v1/projects/{}/keys/{}",
        session::gate_url(),
        urlencode_path_segment(project),
        urlencode_path_segment(key)
    );
    let mut req = agent().put(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = format!("set {key}");
    match req.send_json(body) {
        // Govde OKUNMUYOR: Go tarafi da 200'de govdeye bakmiyor. Bir yazim
        // yanitinin icerigi transcript'e tasinacak bir sey tasimaz.
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(status, resp)) => {
            let retry_after = resp
                .header("Retry-After")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_RETRY_AFTER);
            let text = resp.into_string().unwrap_or_default();
            Err(map_http_error(status, &text, retry_after, &ctx))
        }
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

// urlencode_path_segment, proje adini tek bir yol segmentine kacirir.
fn urlencode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
