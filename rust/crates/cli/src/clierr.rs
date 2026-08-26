// clierr, CLI'nin makine-okunur hata sozlesmesidir: ajan/CI baglaminda her hata
// stderr'e TEK bir JSON satiri yayar:
//
//   {"error":"<CODE>","message":"<cumle>","recovery":"<tam komut>","retryable":false}
//
// Bu dosya Go'daki internal/clierr'in portudur ve Go ORACLE'dir: kodlar,
// kurtarma metinleri ve bayraklar oradan bire bir alinmistir. Bir metni burada
// "duzeltmek" sahadaki ikililerle ayrisma demektir.
use crate::gojson;
use crate::safelog;
use serde::Serialize;
use std::fmt;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BindingUnpinned,
    AgentModeRefused,
    EpochDowngrade,
    CasConflict,
    GrantDenied,
    RateLimited,
    BlobHashMismatch,
    ControlPlaneRequired,
    BreakGlassRefused,
    LegacyArchiveRetired,
    LegacyWriteBlocked,
    ArchiveMigrated,
    TokenExchangeFailed,
    BlobTooLarge,
    // ActionUnavailable: BU CAGRI yurutulemez — eksik bayrak, verilmemis onay ya
    // da bu build'in tasimadigi yetenek. SERVISIN sagligiyla ilgisi YOK; adi bu
    // yuzden NOT_AVAILABLE degil (estate'te o ad memory tarafinin).
    ActionUnavailable,
    Internal,
    SessionExpired,
    NetworkRequired,
    NotFound,
    PolicyInvalid,
    PolicyConflict,
    AuditUnavailable,
    IdentityUnavailable,
    ServiceMisconfig,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        use Code::*;
        match self {
            BindingUnpinned => "BINDING_UNPINNED",
            AgentModeRefused => "AGENT_MODE_REFUSED",
            EpochDowngrade => "EPOCH_DOWNGRADE",
            CasConflict => "CAS_CONFLICT",
            GrantDenied => "GRANT_DENIED",
            RateLimited => "RATE_LIMITED",
            BlobHashMismatch => "BLOB_HASH_MISMATCH",
            ControlPlaneRequired => "CONTROL_PLANE_REQUIRED",
            BreakGlassRefused => "BREAK_GLASS_REFUSED",
            LegacyArchiveRetired => "LEGACY_ARCHIVE_RETIRED",
            LegacyWriteBlocked => "LEGACY_WRITE_BLOCKED",
            ArchiveMigrated => "ARCHIVE_MIGRATED",
            TokenExchangeFailed => "TOKEN_EXCHANGE_FAILED",
            BlobTooLarge => "BLOB_TOO_LARGE",
            ActionUnavailable => "ACTION_UNAVAILABLE",
            Internal => "INTERNAL",
            SessionExpired => "SESSION_EXPIRED",
            NetworkRequired => "NETWORK_REQUIRED",
            NotFound => "NOT_FOUND",
            PolicyInvalid => "POLICY_INVALID",
            PolicyConflict => "POLICY_CONFLICT",
            AuditUnavailable => "AUDIT_UNAVAILABLE",
            IdentityUnavailable => "IDENTITY_UNAVAILABLE",
            ServiceMisconfig => "SERVICE_MISCONFIGURED",
        }
    }

    /// registry, kodun normatif kurtarma metni + retryable bayragidir.
    /// Go'daki `registry` map'inin AYNISI.
    pub fn spec(self) -> (&'static str, bool) {
        use Code::*;
        match self {
            BindingUnpinned => ("run wapps secrets trust-repo in a terminal", false),
            AgentModeRefused => ("use exec/apply; a human can run get in a terminal", false),
            EpochDowngrade => ("possible rollback attack; verify with wapps secrets status and contact the admin; do not force", false),
            CasConflict => ("re-run the original command; conflicting writers are shown above", true),
            GrantDenied => ("ask an admin to extend policy.json (wapps secrets policy set) or fix the Google group membership", false),
            RateLimited => ("wait for the Retry-After window and retry", true),
            BlobHashMismatch => ("integrity failure — do not proceed; run wapps doctor and contact the admin", false),
            ControlPlaneRequired => ("this is an admin ceremony: a human must run it in a terminal (write-AUD session)", false),
            BreakGlassRefused => ("a human must run this in a terminal (double-confirm required)", false),
            LegacyArchiveRetired => ("this project migrated to the store; pull latest .wapps.yaml and use wapps secrets set", false),
            LegacyWriteBlocked => ("this project reads from the store; use wapps secrets set", false),
            ArchiveMigrated => ("run wapps secrets exec in this repo; the git archive is retired", false),
            TokenExchangeFailed => ("verify the pipeline's CF Access service-token pair; an admin can re-issue it at the edge", false),
            BlobTooLarge => ("store a pointer/reference instead; the store caps values at 64KB", false),
            ActionUnavailable => ("the message names what is missing — a required flag, a confirmation, or a capability this build lacks; supply it and re-run, because an identical retry cannot change the result", false),
            Internal => ("run wapps doctor; if it persists contact the admin", false),
            SessionExpired => ("run wapps login in a terminal (CI uses CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET)", false),
            NetworkRequired => ("reconnect and retry; the store has no offline mode (values are server-decrypted)", true),
            NotFound => ("check the key/project name with wapps secrets list", false),
            PolicyInvalid => ("fix the policy file (see the named rule index) and re-run wapps secrets policy lint", false),
            PolicyConflict => ("another admin updated the policy; re-run policy show, rebase your edit, retry", true),
            AuditUnavailable => ("the audit ledger is down — plaintext is refused fail-closed; retry shortly", true),
            IdentityUnavailable => ("identity/groups unresolvable at the edge; retry shortly", true),
            ServiceMisconfig => ("the secrets gate is misconfigured; contact the admin (alert A8 fired)", false),
        }
    }
}

/// Error, makine-okunur bir CLI hatasidir.
#[derive(Debug, Clone)]
pub struct Error {
    pub code: Code,
    pub message: String,
    pub recovery: String,
    pub retryable: bool,
}

impl Error {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        let (recovery, retryable) = code.spec();
        Error { code, message: message.into(), recovery: recovery.to_string(), retryable }
    }

    /// with_recovery, kurtarma metnini override eder (or. GRANT_DENIED'da).
    pub fn with_recovery(mut self, recovery: impl Into<String>) -> Self {
        self.recovery = recovery.into();
        self
    }
}

// Error(), insan-okunur ozet doner: "CODE: mesaj". Go'daki (*Error).Error() ile
// AYNI sekil — insan yolundaki "Error: %v" bunu basiyor.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.code.as_str())
        } else {
            write!(f, "{}: {}", self.code.as_str(), self.message)
        }
    }
}

impl std::error::Error for Error {}

#[derive(Serialize)]
struct Envelope<'a> {
    error: &'a str,
    message: &'a str,
    recovery: &'a str,
    retryable: bool,
}

// max_message_len, mesaj/kurtarma metninin ust siniri — dis hata govdelerinin
// (HTML sayfasi vb.) transcript'e tasinmasini engeller.
const MAX_MESSAGE_LEN: usize = 400;

// clip, tek satira indirger ve MAX_MESSAGE_LEN'e kisaltir. Go tarafi bayt
// uzunluguna gore kesiyor; burada da BAYT sayilir (karakter degil) ve kesim
// karakter sinirina hizalanir — Go gecerli UTF-8'i bozabilecegi icin degil,
// Rust'ta bir dizeyi karakter ortasindan kesmek panik oldugu icin.
fn clip(s: &str) -> String {
    let one_line: String = s.replace(['\n', '\r'], " ");
    let t = one_line.trim();
    if t.len() <= MAX_MESSAGE_LEN {
        return t.to_string();
    }
    let mut end = MAX_MESSAGE_LEN;
    while !t.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &t[..end])
}

/// emit, hatayi zarf olarak w'ye TEK satir JSON yazar.
///
/// SIRA Go ile AYNI ve onemli: once safelog::redact_patterns, SONRA clip.
/// Ters sirada, 400 bayta kisaltilmis bir jetonun kuyrugu desene uymaz ve
/// maskelenmeden gecerdi.
///
/// Kurtarma satiri da redakte edilir: Go'nun Emit'i her iki alani da
/// geciriyor ve kurtarma metni dis bir kaynagi isimlendirebiliyor.
pub fn emit<W: Write>(w: &mut W, e: &Error) {
    let message = clip(&safelog::redact_patterns(&e.message));
    let recovery = clip(&safelog::redact_patterns(if e.recovery.is_empty() {
        e.code.spec().0
    } else {
        &e.recovery
    }));
    let env = Envelope {
        error: e.code.as_str(),
        message: &message,
        recovery: &recovery,
        retryable: e.retryable,
    };
    match gojson::to_string(&env) {
        // json.Marshal newline eklemez; tek satir + '\n'.
        Ok(raw) => {
            let _ = writeln!(w, "{raw}");
        }
        Err(_) => {
            let _ = writeln!(
                w,
                "{{\"error\":\"{}\",\"message\":\"error serialization failed\",\"recovery\":\"\",\"retryable\":false}}",
                e.code.as_str()
            );
        }
    }
}
