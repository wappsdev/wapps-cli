// store, gate'in HTTP tasimasi + hata eslemesidir.
// Ham gate govdesi ASLA transcript'e yayilmaz — hatalar clierr sozlesmesine
// eslenir, yalnizca kod + kisa alanlar tasinir.
use crate::clierr::{Code, Error};
use crate::epochpin;
use crate::session;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
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

// safe_code, gate'ten gelen bir kod/alan dizesini transcript'e girmeden once
// budar: kisa, tek satirlik, alfanumerik bir isaret kalir.
//
// ORACLE internal/store/worker.go safeCode, ve bu fonksiyon bir sure BASKA
// bir sey yapiyordu (satirsonu -> bosluk, trim, 64 karakter). Ayrisma
// GORUNMUYORDU cunku korpustaki her hata govdesi zaten temiz bir
// `SCREAMING_SNAKE` kodu tasiyordu; `whoami`nin 403 dali ile
// `token exchange`in 400 dali BOS bir kod gorebildigi anda ayrildi.
//
// UC KURAL VE SIRALARI ONEMLI:
//   1. BOS girdi -> "unknown" (bos dize DEGIL);
//   2. once 48 BAYTA kirp, SONRA temizle — ters sira daha uzun bir dize
//      birakirdi;
//   3. `[A-Za-z0-9_-.]` disindaki her bayt ATILIR (bosluga cevrilmez,
//      kacisla yazilmaz), ve geriye hicbir sey kalmazsa yine "unknown".
//
// Bayt duzeyinde calisiyor, Go'daki gibi: sinif tamamen ASCII oldugu icin
// cok baytli bir karakterin parcalari zaten atilir.
fn safe_code(s: &str) -> String {
    if s.is_empty() {
        return "unknown".to_string();
    }
    let b = s.as_bytes();
    let head = &b[..b.len().min(48)];
    let out: Vec<u8> = head
        .iter()
        .copied()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        .collect();
    if out.is_empty() {
        return "unknown".to_string();
    }
    // Kalan baytlarin hepsi yukaridaki ASCII siniftan; UTF-8 gecerliligi kesin.
    String::from_utf8(out).expect("ASCII sinif")
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
            format!(
                "{ctx}: gate rejected the session ({})",
                safe_code(&we.error)
            ),
        ),
        403 => match we.error.as_str() {
            "MACHINE_TOKEN_REQUIRED"
            | "TOKEN_EXPIRED"
            | "TOKEN_REVOKED"
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
                Error::new(
                    Code::NotFound,
                    format!("{ctx}: key {} not found", safe_code(&we.key)),
                )
            } else {
                Error::new(
                    Code::NotFound,
                    format!("{ctx}: not found ({})", safe_code(&we.error)),
                )
            }
        }
        409 => Error::new(
            Code::CasConflict,
            format!("{ctx}: {}", safe_code(&we.error)),
        ),
        412 => {
            if we.error == "POLICY_CONFLICT" {
                Error::new(
                    Code::PolicyConflict,
                    format!(
                        "{ctx}: policy version conflict (current {})",
                        we.current_version
                    ),
                )
            } else {
                Error::new(Code::CasConflict, format!("{ctx}: epoch conflict"))
            }
        }
        413 => {
            if we.error == "RESPONSE_TOO_LARGE" {
                Error::new(
                    Code::ActionUnavailable,
                    format!("{ctx}: read response too large"),
                )
                .with_recovery(
                    "this bulk read exceeds the gate's response cap — request fewer keys at a time",
                )
            } else {
                Error::new(
                    Code::BlobTooLarge,
                    format!("{ctx}: {}", safe_code(&we.error)),
                )
            }
        }
        422 => {
            if we.error == "POLICY_INVALID" {
                let idx = we
                    .rule_index
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "?".to_string());
                Error::new(
                    Code::PolicyInvalid,
                    format!("{ctx}: policy invalid (rule index {idx})"),
                )
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
            "IDENTITY_UNAVAILABLE" => Error::new(
                Code::IdentityUnavailable,
                format!("{ctx}: identity/groups unresolvable"),
            ),
            _ => Error::new(
                Code::ServiceMisconfig,
                format!("{ctx}: {}", safe_code(&we.error)),
            ),
        },
        400 => Error::new(
            Code::Internal,
            format!("{ctx}: bad request ({})", safe_code(&we.error)),
        ),
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
    let Ok(iter) = rustls_pki_types::CertificateDer::pem_file_iter(path) else {
        return;
    };
    for der in iter.flatten() {
        let _ = store.add(der);
    }
}

// root_store, gomulu tabani kurar ve env ile bildirilen koklerin USTUNE ekler.
fn root_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
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
                Error::new(
                    Code::NetworkRequired,
                    format!("secrets gate response truncated: {e}"),
                )
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

/// committed_epoch, bir 200 commit yanitindan yeni epoch'u cikarir.
///
/// PUR ve `pub`, cunku `set` ag I/O yapiyor: karar burada dursun ki testten
/// ERISILEBILSIN. Testten erisilemeyen bir guvenlik kapisi kimsenin
/// savunamayacagi bir kapidir.
///
/// epoch 0 GECERLI BIR COMMIT DEGIL (writer-do: epoch = prevEpoch+1 >= 1), yani
/// 0 "alan yoktu" demektir; pin kontroluna verilseydi operatore
/// "served epoch 0 < pinned N — possible rollback attack" der ve onu GEREKSIZ
/// bir DR seremonisine yollardi. Kapi yine KAPALI, suclama DOGRU sinifta.
pub fn committed_epoch(body: &str, ctx: &str) -> Result<u64, Error> {
    #[derive(serde::Deserialize)]
    struct Commit {
        #[serde(default)]
        epoch: u64,
    }
    let out: Commit = serde_json::from_str(body)
        .map_err(|e| Error::new(Code::Internal, format!("{ctx}: decode response: {e}")))?;
    if out.epoch == 0 {
        return Err(Error::new(
            Code::Internal,
            format!("{ctx}: gate returned no epoch on a committed write"),
        ));
    }
    Ok(out.epoch)
}

/// set, PUT /v1/projects/{p}/keys/{KEY} cagirir — TEK anahtar yazimi.
///
/// EPOCH PIN'I ILERLETIR. Eski yorum burada "bir yazim sunulan bir epoch
/// OKUMUYOR" diyordu; bu OLCULDU ve YANLIS cikti. Tel epoch'u tasiyor:
/// worker/src/writer-do.ts commit yanitini
/// `{project, epoch, manifestSha256, keyVersions}` olarak donduruyor ve
/// index.ts'teki dispatchWrite DO yanitini istemciye AYNEN geciriyor. Yani
/// `set` epoch'u ZATEN aliyordu, JSON sinirinda ATIYORDU.
///
/// Kontrol yazimdan SONRA, cunku epoch ancak commit'le dogar. Yazimi geri
/// ALMAZ; isi, geri sarilmis bir store'a yazildigini operatore BAGIRMAK ve
/// pin'i yuksekte tutmak (yoksa sonraki okumalar da sessizlesirdi).
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
        // Govde OKUNUYOR: commit yaniti yeni epoch'u tasiyor ve o epoch pin
        // kontrolunun GIRDISI. Govdede sir YOK (proje adi, epoch, manifest
        // hash, keyVersion'lar), yani okumak transcript'e deger tasimaz.
        Ok(resp) => {
            let text = resp.into_string().unwrap_or_default();
            let epoch = committed_epoch(&text, &ctx)?;
            epochpin::check_and_advance(&epochpin::default_path()?, project, epoch, false)
        }
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

/// KeysResult, GET /keys yanitidir (METADATA duzlemi — deger DONMEZ).
#[derive(Debug, Deserialize)]
pub struct KeysResult {
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub keys: Vec<KeyInfo>,
}

#[derive(Debug, Deserialize)]
pub struct KeyInfo {
    // TEL ADI `keyName` (camelCase) — Rust'in alan adi DEGIL. Oracle:
    // internal/store/store.go:54 `json:"keyName"`, ve gate'in kendisi
    // (worker/test/admin-policy.test.ts). Yanlis alan sessizce BOS ad uretir
    // ve `read_all` gate'e `["",""]` gonderir; olcusu tests/storewire.rs.
    #[serde(rename = "keyName", default)]
    pub key_name: String,
}

/// keys, GET /v1/projects/{p}/keys cagirir: anahtar ADLARINI metadata
/// duzleminden ceker. Store::read CAGRILMAZ, yani audit'e value.read DUSMEZ;
/// liste Worker'da principal'in read grant'ina filtrelenir (§4.3.3).
///
/// HATA BAGLAMI "list <proje>" (read'deki "read <proje>" DEGIL) — Go'daki
/// mapHTTPError(r, "list "+project) ile ayni.
pub fn keys(project: &str) -> Result<KeysResult, Error> {
    keys_inner(project, false)
}

/// HEADER_INTENT, Worker'a giden BILGILENDIRICI niyet basligidir (Go:
/// internal/intent.HeaderIntent). Bir YETKILENDIRME girdisi DEGIL: audit
/// satirini etiketler, strip edilirse satir sirdan bir listelemeye duser.
pub const HEADER_INTENT: &str = "X-Wapps-Intent";

/// INTENT_EPOCH_RESET, HeaderIntent'in epoch-reset degeridir. YALNIZCA
/// `wapps dr accept-epoch-reset` seremonisinin pin-INDIREN tek okumasi tasir.
pub const INTENT_EPOCH_RESET: &str = "epoch-reset";

/// INTENT_SYNC, HeaderIntent's sync value: `secrets sync`'s import carries it
/// so the audit row reads key.sync (Go: WriteOpts{Sync: true}).
pub const INTENT_SYNC: &str = "sync";

/// keys_accepting_epoch_reset, `keys` ile AYNI rotayi cagirir ama IKI seyi
/// degistirir, ve ikisi de yalnizca seremoniye aittir:
///   * istek `X-Wapps-Intent: epoch-reset` tasir (audit etiketi, §6.4);
///   * epoch pini sunulan DAHA DUSUK epoch'a INDIRILEBILIR.
///
/// AYRI BIR GIRIS OLMASI BILINCLI. Go tarafinda bu bir Config alani
/// (`AcceptEpochReset`) ve orada da kural sert: bayrak exec/apply/get
/// yollarina ASLA threadlenmiyor, yalnizca seremoninin 4. adiminda kurulan
/// TEK store'da yasiyor. Burada bir parametre yerine ayri bir fonksiyon
/// olmasi ayni kurali TIP duzeyinde tutuyor: `keys` cagiran hicbir yol
/// yanlislikla `true` geciremez, cunku gececek bir yer yok.
pub fn keys_accepting_epoch_reset(project: &str) -> Result<KeysResult, Error> {
    keys_inner(project, true)
}

fn keys_inner(project: &str, accept_reset: bool) -> Result<KeysResult, Error> {
    let headers = session::auth_headers()?;
    let url = format!(
        "{}/v1/projects/{}/keys",
        session::gate_url(),
        urlencode_path_segment(project)
    );
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    if accept_reset {
        req = req.set(HEADER_INTENT, INTENT_EPOCH_RESET);
    }
    let ctx = format!("list {project}");
    match req.call() {
        Ok(resp) => {
            let text = resp.into_string().map_err(|e| {
                Error::new(
                    Code::NetworkRequired,
                    format!("secrets gate response truncated: {e}"),
                )
            })?;
            let out = serde_json::from_str::<KeysResult>(&text)
                .map_err(|e| Error::new(Code::Internal, format!("decode {ctx}: {e}")))?;
            epochpin::check_and_advance(
                &epochpin::default_path()?,
                project,
                out.epoch,
                accept_reset,
            )?;
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
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// audit_head, GET /v1/audit/head cagirir: global audit zincirinin head'i
/// ({seq, hash}).
///
/// `dr accept-epoch-reset` seremonisinin CANLI referansidir — donen hash,
/// operatorun kagit zarftaki degerle out-of-band karsilastirdigi degerdir.
/// METADATA okumasi: duz metin donmez ve epoch pinine DOKUNMAZ (bu yuzden
/// burada `check_and_advance` cagrisi YOK; `keys`in aksine).
///
/// HATA BAGLAMI "audit head" — Go'daki mapHTTPError(r, "audit head") ile ayni.
pub fn audit_head() -> Result<(u64, String), Error> {
    #[derive(Deserialize)]
    struct Head {
        #[serde(default)]
        seq: u64,
        #[serde(default)]
        hash: String,
    }
    let headers = session::auth_headers()?;
    let url = format!("{}/v1/audit/head", session::gate_url());
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "audit head";
    match req.call() {
        Ok(resp) => {
            let text = resp.into_string().map_err(|e| {
                Error::new(
                    Code::NetworkRequired,
                    format!("secrets gate response truncated: {e}"),
                )
            })?;
            let out = serde_json::from_str::<Head>(&text)
                .map_err(|e| Error::new(Code::Internal, format!("decode {ctx}: {e}")))?;
            Ok((out.seq, out.hash))
        }
        Err(ureq::Error::Status(status, resp)) => {
            let retry_after = resp
                .header("Retry-After")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_RETRY_AFTER);
            let text = resp.into_string().unwrap_or_default();
            Err(map_http_error(status, &text, retry_after, ctx))
        }
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// read_all, principal'in OKUYABILDIGI tum anahtarlari ceker.
///
/// IKI ADIMLI ve bu OLCULDU (Go: WorkerStore.Read, keys bos dali): once
/// GET /keys ile ad kumesi cozulur, SONRA o adlarla POST /read yapilir.
/// `POST /read` govdesine BOS bir liste gondermek AYNI SEY DEGILDIR — gate
/// farkli davranir, ve differential bunu 501 olarak yuzeye cikardi.
///
/// Kume BOSSA read cagrisi HIC yapilmaz (ve dolayisiyla epoch pini de
/// read yolundan ilerlemez — yalnizca keys yolundan ilerlemis olur).
pub fn read_all(project: &str) -> Result<BTreeMap<String, String>, Error> {
    let kr = keys(project)?;
    let names: Vec<String> = kr.keys.iter().map(|k| k.key_name.clone()).collect();
    if names.is_empty() {
        return Ok(BTreeMap::new());
    }
    Ok(read(project, &names)?.values)
}

/// import_body, POST /import govdesini uretir: `{"values": {...}}`.
///
/// AYRI BIR FONKSIYON, ve sebebi olculmus bir sinif: bu zarfin ADI tel
/// bicimidir (Go: `map[string]any{"values": values}`), Rust'in bir alan adi
/// DEGIL. Ayri durunca AG'A CIKMADAN test edilebiliyor (tests/storewire.rs) —
/// tipki okuma tarafindaki `keyName` gibi, yanlis bir ad burada da sessizce
/// gecerdi.
pub fn import_body(values: &BTreeMap<String, String>) -> String {
    // BTreeMap: Go'nun map'i sirasiz ama JSON nesnesi olarak esdeger. Sirali
    // olmasi govdeyi DETERMINISTIK yapar, yani testte bayt karsilastirilabilir.
    serde_json::json!({ "values": values }).to_string()
}

/// import_values, POST /v1/projects/{p}/import cagirir — TOPLU atomik yazim.
///
/// TEK EPOCH: yarim bir import diye bir sey yoktur. Bu, `set`i N kez
/// cagirmaktan farkli bir GARANTI, ve import-env'in var olma sebebi.
///
/// EPOCH PIN'E DOKUNMAZ (`set`/`delete` gibi): bir yazim sunulan bir epoch
/// OKUMUYOR. import-env'in pini yine de ilerletebilir — ama o, ONCESINDE
/// cagrilan GET /keys yuzundendir, bu fonksiyon yuzunden DEGIL.
///
/// HATA BAGLAMI "import <proje>".
///
/// `sync` tags the write `X-Wapps-Intent: sync` (Go: WriteOpts{Sync: true}).
/// It is informational: the audit row reads key.sync instead of key.write.
pub fn import_values(
    project: &str,
    values: &BTreeMap<String, String>,
    sync: bool,
) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::new(Code::Internal, "import: no values"));
    }
    let headers = session::auth_headers()?;
    let url = format!(
        "{}/v1/projects/{}/import",
        session::gate_url(),
        urlencode_path_segment(project)
    );
    let mut req = agent().post(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    if sync {
        req = req.set(HEADER_INTENT, INTENT_SYNC);
    }
    let ctx = format!("import {project}");
    // send_string: govde import_body ile ELDE uretiliyor ki tel bicimi tek bir
    // yerde dursun ve test edilebilsin.
    match req.send_string(&import_body(values)) {
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, &ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// delete, DELETE /v1/projects/{p}/keys/{KEY} cagirir — TEK anahtar silme.
///
/// EPOCH PIN'E DOKUNMAZ, ve bu bir eksiklik degil Go'nun sozlesmesi: pin
/// yalnizca Keys/Read yollarinda ilerliyor (internal/store/worker.go:273,316).
/// Bir silme sunulan bir epoch OKUMUYOR, dolayisiyla pinlenecek bir sey de yok.
/// Differential pin dosyasinin son halini de karsilastirdigi icin, bir tarafin
/// burada pin'i oynatmasi GORUNUR (human_rm_leaves_pin_alone).
///
/// HATA BAGLAMI "delete <KEY>" — Go'daki mapHTTPError(r, "delete "+key).
pub fn delete(project: &str, key: &str) -> Result<(), Error> {
    let headers = session::auth_headers()?;
    let url = format!(
        "{}/v1/projects/{}/keys/{}",
        session::gate_url(),
        urlencode_path_segment(project),
        urlencode_path_segment(key)
    );
    let mut req = agent().delete(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = format!("delete {key}");
    match req.call() {
        // Govde OKUNMUYOR: Go tarafi da 200'de govdeye bakmiyor.
        Ok(_) => Ok(()),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, &ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

// null_as_default, tel'deki bir `null`u tipin SIFIR DEGERINE cevirir.
//
// NEDEN GEREKLI — OLCULDU: Go'nun `encoding/json`'i `null`u HER hedef tipe
// sessizce kabul ediyor (dilim -> nil, dize -> "", sayi -> 0), serde ise
// `Vec<String>`/`String` icin HATA veriyor. Bir grant satirinin `"keys":
// null` ile gelmesi Go'da bos bir sutun, portta ise "malformed gate
// response" uretiyordu; differential'in `who-edge` vakasi tam olarak bunu
// yakaladi.
//
// KAPSAM `whoami`nin TIPLERI. Ayni tolerans farki gate'in DIGER rotalarinda
// da duruyor (KeysResult, PolicyResult, ...) ve orada OLCULMEMIS bir dal —
// bu dilim onu acmiyor, adlandiriyor.
fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

/// Grant, `whoami`nin dondugu efektif kural satiridir.
///
/// NEDEN `policy::Rule` DEGIL: Go'da IKISI DE `store.Rule` — ayni tip. Ama
/// Rust'ta `policy::Rule` `deny_unknown_fields` tasiyor (yerel policy
/// dosyasinin KATI okumasi icin: Go orada `dec.DisallowUnknownFields()`
/// cagiriyor). Go'da katilik DECODER'in bir ayari, tipin degil; burada tipe
/// yazili. `whoami` govdesi GATE'ten geliyor ve Go orada duz
/// `json.Unmarshal` kullaniyor — yani TOLERANT. Ayni tipi kullanmak
/// gate'in ekledigi yeni bir alani sessizce bir INTERNAL'a cevirirdi.
///
/// Bu tip yalnizca OKUNUYOR (whoami hicbir sey geri gondermiyor), yani iki
/// sekil arasinda bir serilestirme sozlesmesi de yok.
#[derive(Debug, Default, Deserialize)]
pub struct Grant {
    #[serde(default, deserialize_with = "null_as_default")]
    pub group: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub service: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub aud: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub projects: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub keys: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub verbs: Vec<String>,
}

/// WhoamiResult, GET /v1/whoami yanitidir.
///
/// `kind` alani TASINIYOR ama BASILMIYOR — Go'nun `WhoamiResult`inda da oyle.
/// Cikartmak, gate bir gun onu basmaya karar verdiginde iki tarafi ayirirdi.
#[derive(Debug, Default, Deserialize)]
pub struct WhoamiResult {
    #[serde(default, deserialize_with = "null_as_default")]
    pub principal: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub kind: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub email: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub common_name: String,
    #[serde(default, deserialize_with = "null_as_default")]
    pub groups: Vec<String>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub policy_version: u64,
    #[serde(default, deserialize_with = "null_as_default")]
    pub grants: Vec<Grant>,
    #[serde(default, deserialize_with = "null_as_default")]
    pub is_root_admin: bool,
}

/// whoami, GET /v1/whoami cagirir: principal + gruplar + efektif grant'ler.
///
/// KIMLIK HEADER'LARI OKUMA OTURUMUNDAN (`auth_headers`, `auth_headers_admin`
/// DEGIL) ve bu bir tercih degil rotanin adresi: `/v1/whoami` `/v1/admin`
/// onegi ALTINDA DEGIL, yani kenarda READ uygulamasinin kapsaminda. Admin
/// oturumu istemek, oturumu olan bir operatore "wapps login --write" dedirtirdi.
///
/// EPOCH PIN'E DOKUNMAZ: bir PROJE degil bir PRINCIPAL sorgulanıyor.
///
/// HATA BAGLAMI "whoami" — Go'daki mapHTTPError(r, "whoami") ile ayni.
pub fn whoami() -> Result<WhoamiResult, Error> {
    let headers = session::auth_headers()?;
    let url = format!("{}/v1/whoami", session::gate_url());
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "whoami";
    match req.call() {
        Ok(resp) => decode_body::<WhoamiResult>(resp, ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// token_mint, POST /v1/token cagirir — kisa omurlu makine jetonu (§5.3).
///
/// DONEN JETON BIR SIRDIR ve bu fonksiyon onu HICBIR YERE yazmaz: ne log, ne
/// hata metni, ne dosya. Cagirana verilir, cagiran stdout'a basar.
///
/// GOVDE ALAN SIRASI GO'NUN `map[string]any`'sinden geliyor: `encoding/json`
/// bir haritayi ALFABETIK yaziyor, yani `project`, `scope`, `ttl_seconds` ve
/// scope icinde `keys`, `verbs`. Burada `serde_json::json!` de ayni sirayi
/// veriyor (nesne alanlari yazildigi sirada); sira ONEMLI cunku sahte gate
/// govdeyi cozup jetonu ONDAN uretiyor.
///
/// `ttl_seconds` YALNIZCA > 0 iken govdeye giriyor (Go: `if ttlSeconds > 0`).
/// Sifir "gate varsayilani" demek, "sifir saniye" degil.
///
/// 400 AYRI BIR DAL ve mapHTTPError'a DUSMUYOR: mint'in reddi bir taşıma
/// hatasi degil bir KAPSAM reddi, o yuzden kodu TOKEN_EXCHANGE_FAILED ve
/// kurtarma satiri service-token ciftini isaret ediyor. Diger statuler
/// (403/503/…) ortak esleyiciye gidiyor.
///
/// HATA BAGLAMI "token exchange".
pub fn token_mint(
    project: &str,
    keys: &[String],
    verbs: &[String],
    ttl_seconds: i64,
) -> Result<(String, i64), Error> {
    #[derive(Deserialize)]
    struct Minted {
        #[serde(default, deserialize_with = "null_as_default")]
        token: String,
        #[serde(default, deserialize_with = "null_as_default")]
        exp: i64,
    }
    let headers = session::auth_headers()?;
    let mut body = serde_json::json!({
        "project": project,
        "scope": { "keys": keys, "verbs": verbs },
    });
    if ttl_seconds > 0 {
        body["ttl_seconds"] = serde_json::json!(ttl_seconds);
    }
    let url = format!("{}/v1/token", session::gate_url());
    let mut req = agent().post(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "token exchange";
    let out: Minted = match req.send_json(body) {
        Ok(resp) => decode_body::<Minted>(resp, ctx)?,
        Err(ureq::Error::Status(400, resp)) => {
            let text = resp.into_string().unwrap_or_default();
            return Err(Error::new(
                Code::TokenExchangeFailed,
                format!(
                    "token exchange rejected ({})",
                    safe_code(&parse_worker_error(&text).error)
                ),
            ));
        }
        Err(ureq::Error::Status(status, resp)) => return Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => {
            return Err(Error::new(
                Code::NetworkRequired,
                format!("secrets gate unreachable: {t}"),
            ))
        }
    };
    // BOSLUKTAN IBARET bir jeton BOS sayilir (Go: strings.TrimSpace). Bir
    // pipeline adimina bosluk vermek, ona gecerli bir jeton vermis gibi
    // gorunurdu.
    if out.token.trim().is_empty() {
        return Err(Error::new(
            Code::TokenExchangeFailed,
            "gate returned an empty token",
        ));
    }
    Ok((out.token, out.exp))
}

/// PolicyResult, GET /v1/admin/policy yanitidir.
///
/// Alan sirasi Go struct'i ile AYNI (version, sha256, policy): `policy show
/// --json` bu yapiyi girintili basiyor ve cikti bayt-bayt karsilastiriliyor.
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct PolicyResult {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub policy: crate::policy::PolicyDoc,
}

/// policy_get, GET /v1/admin/policy cagirir.
///
/// `/v1/admin` oneki KASITLI: kenarda bu AYRI bir CF Access uygulamasidir
/// (write-AUD, 15 dk + WebAuthn), o yuzden kimlik header'lari admin
/// oturumundan geliyor — bir okuma oturumu GECERLI olsa bile yetmez, ve
/// oturum yoklugunda basilan kurtarma satiri "wapps login" DEGIL
/// "wapps login --write" olmali.
///
/// EPOCH PIN'E DOKUNMAZ: policy bir PROJE degil, GLOBAL bir dokuman; sunulan
/// bir veri epoch'u OKUNMUYOR.
///
/// HATA BAGLAMI "policy show".
pub fn policy_get() -> Result<PolicyResult, Error> {
    let headers = session::auth_headers_admin()?;
    let url = format!("{}/v1/admin/policy", session::gate_url());
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "policy show";
    match req.call() {
        Ok(resp) => decode_body::<PolicyResult>(resp, ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// PolicyPutResult, PUT /v1/admin/policy yanitidir.
#[derive(Debug, Deserialize, Default)]
pub struct PolicyPutResult {
    #[serde(default)]
    pub version: u64,
    #[serde(default)]
    pub sha256: String,
}

/// policy_put, PUT /v1/admin/policy cagirir — CAS'li policy yazimi.
///
/// GONDERILEN BAYTLAR SOZLESMENIN PARCASI: gate aldigi govdenin sha256'sini
/// geri veriyor ve istemci onu basiyor. Alan sirasi ya da omitempty bir yerde
/// ayrisirsa basilan sha ayrisir — bu yuzden govde `policy::PolicyDoc`un
/// serde etiketleriyle uretiliyor ve o etiketler Go struct etiketlerinin
/// AYNISI (tests/policyverb.rs bunu ag'a cikmadan olcuyor, sahte gate'in PUT
/// rotasi da canli olcuyor).
///
/// HATA BAGLAMI "policy set".
pub fn policy_put(doc: &crate::policy::PolicyDoc) -> Result<PolicyPutResult, Error> {
    let headers = session::auth_headers_admin()?;
    let body = serde_json::to_string(doc)
        .map_err(|e| Error::new(Code::Internal, format!("encode policy: {e}")))?;
    let url = format!("{}/v1/admin/policy", session::gate_url());
    let mut req = agent().put(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "policy set";
    match req.send_string(&body) {
        Ok(resp) => decode_body::<PolicyPutResult>(resp, ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// ProjectsResult, GET /v1/projects yanitidir: principal'in GOREBILDIGI proje
/// ADlari. Deger duzlemi DEGIL — burada yalnizca adlar var.
#[derive(Debug, Deserialize, Default)]
pub struct ProjectsResult {
    #[serde(default)]
    pub projects: Vec<String>,
}

/// projects, GET /v1/projects cagirir.
///
/// Sonuc SIRALANMAZ: filtreleme sunucuda yapiliyor ve istemcide gizli bir
/// siralama, sunucunun sirasini sessizce yok ederdi (`secrets list`in aksine —
/// orada sort ISTEMCIDE, Go: sort.Strings).
///
/// HATA BAGLAMI "list projects".
pub fn projects() -> Result<ProjectsResult, Error> {
    let headers = session::auth_headers()?;
    let url = format!("{}/v1/projects", session::gate_url());
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "list projects";
    match req.call() {
        Ok(resp) => decode_body::<ProjectsResult>(resp, ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

/// ProjectDeleteResult, DELETE /v1/admin/projects/{p} yanitidir.
#[derive(Debug, Deserialize, Default)]
pub struct ProjectDeleteResult {
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub deleted_objects: i64,
    #[serde(default)]
    pub pointer_events_kept: bool,
}

/// project_delete, DELETE /v1/admin/projects/{p} cagirir — projenin TUM
/// verisini kaldirir.
///
/// IKI SEY BURADA KASITLI:
///
///  1. `/v1/admin` oneki. Kenarda bu AYRI bir CF Access uygulamasidir
///     (write-AUD, §3.2), o yuzden kimlik header'lari da admin oturumundan
///     geliyor — read oturumu GECERLI olsa bile yetmez.
///  2. Govdedeki `confirm` proje adini TEKRAR eder. Sunucu eslesmezse 400
///     verir; istemci onu buradan dolduruyor ki YANLIS HEDEFLI bir cagri aga
///     hic cikmasin.
///
/// HATA BAGLAMI "delete project <p>".
pub fn project_delete(project: &str) -> Result<ProjectDeleteResult, Error> {
    let headers = session::auth_headers_admin()?;
    let body = serde_json::json!({ "confirm": project });
    let url = format!(
        "{}/v1/admin/projects/{}",
        session::gate_url(),
        urlencode_path_segment(project)
    );
    let mut req = agent().delete(&url).set("Content-Type", "application/json");
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = format!("delete project {project}");
    match req.send_json(body) {
        Ok(resp) => decode_body::<ProjectDeleteResult>(resp, &ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, &ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}

// status_error, bir non-2xx yaniti Retry-After'i da okuyarak hata sozlesmesine
// esler. Uc yeni rota da ayni sekli kullaniyor — kopyalanmis bir dal zamanla
// ayrisirdi.
fn status_error(status: u16, resp: ureq::Response, ctx: &str) -> Error {
    let retry_after = resp
        .header("Retry-After")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETRY_AFTER);
    let text = resp.into_string().unwrap_or_default();
    map_http_error(status, &text, retry_after, ctx)
}

// decode_body, 200 govdesini cozer. Bozuk govde INTERNAL (fail-closed) —
// Go'daki decodeJSON ile ayni sinif.
fn decode_body<T: serde::de::DeserializeOwned>(
    resp: ureq::Response,
    ctx: &str,
) -> Result<T, Error> {
    let text = resp.into_string().map_err(|e| {
        Error::new(
            Code::NetworkRequired,
            format!("secrets gate response truncated: {e}"),
        )
    })?;
    serde_json::from_str::<T>(&text)
        .map_err(|_| Error::new(Code::Internal, format!("{ctx}: malformed gate response")))
}

/// RotatePlanItem, rotate-plan oracle'inin BIR satiridir.
///
/// DEGER ALANI YOK ve olmamali: rotate-plan "neyin dondurulmesi gerekiyor"
/// sorusunu (project, key) ADLARIYLA cevapliyor. Buraya bir deger alani
/// eklemek, offboard raporunu bir sir dokumune cevirirdi.
///
/// Alan SIRASI Go struct'iyla ayni — `--json` ciktisi bir sozlesme.
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct RotatePlanItem {
    #[serde(default)]
    pub project: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub last_read: String,
    #[serde(default)]
    pub reads: u64,
}

/// RotatePlanResult, GET /v1/admin/rotate-plan yanitidir.
#[derive(Debug, Deserialize, Serialize, Default)]
pub struct RotatePlanResult {
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub items: Vec<RotatePlanItem>,
}

/// rotate_plan, GET /v1/admin/rotate-plan cagirir.
///
/// `/v1/admin` oneki KASITLI (policy ile ayni sebep): kenarda bu AYRI bir CF
/// Access uygulamasidir (write-AUD), yani kimlik header'lari admin
/// oturumundan geliyor ve oturum yoklugunda basilan kurtarma satiri
/// "wapps login" DEGIL "wapps login --write".
///
/// EPOCH PIN'E DOKUNMAZ: bir PROJE degil bir PRINCIPAL sorgulanıyor, sunulan
/// bir veri epoch'u OKUNMUYOR.
///
/// Sorgu dizesi `rotateplan::query_string` ile kuruluyor (Go'nun
/// url.Values.Encode'u): kacilmamis bir `&` gate'e bambaska bir `identity`
/// gosterirdi.
///
/// HATA BAGLAMI "rotate-plan".
pub fn rotate_plan(
    identity: &str,
    since: &str,
    assume_policy: bool,
) -> Result<RotatePlanResult, Error> {
    let headers = session::auth_headers_admin()?;
    let mut pairs: Vec<(&str, String)> = vec![("identity", identity.to_string())];
    // BOS `since` sorguya HIC girmiyor (Go: `if since != ""`). Bos bir
    // parametre gondermek gate'te "alt sinir var" demek olurdu.
    if !since.is_empty() {
        pairs.push(("since", since.to_string()));
    }
    if assume_policy {
        pairs.push(("assume_policy", "1".to_string()));
    }
    let url = format!(
        "{}/v1/admin/rotate-plan?{}",
        session::gate_url(),
        crate::rotateplan::query_string(&pairs)
    );
    let mut req = agent().get(&url);
    for (k, v) in &headers {
        req = req.set(k, v);
    }
    let ctx = "rotate-plan";
    match req.call() {
        Ok(resp) => decode_body::<RotatePlanResult>(resp, ctx),
        Err(ureq::Error::Status(status, resp)) => Err(status_error(status, resp, ctx)),
        Err(ureq::Error::Transport(t)) => Err(Error::new(
            Code::NetworkRequired,
            format!("secrets gate unreachable: {t}"),
        )),
    }
}
