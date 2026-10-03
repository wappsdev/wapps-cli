// doctorverb, `wapps doctor` — onboarding preflight.
//
// TESHIS FIILI, yani ciktisi bir OPERATOR ARAYUZUDUR ve NE YAZMADIGI en az ne
// yazdigi kadar sozlesmedir. Fiil bir CF Access oturumunu ve bir CI
// service-token ciftini OKUYOR; ikisi de kimlik bilgisidir. Buradan disari
// cikan tek sey bir VARLIK/SURE ozetidir — jetonun KENDISI hicbir kolda
// basilmaz. Olcusu tests/doctorleak.rs, ve o test differential'da DEGIL cunku
// differential iki ikiliyi karsilastiriyor: IKISI DE sizdirsaydi vaka "esit"
// gorunurdu ve hicbir sey kanitlanmazdi.
//
// KAPI: doctor'un ajan-modu kapisi YOKTUR. Kokte mount'lu (SecretsCmd.
// PersistentPreRunE kosmaz) ve RunE'de de bir kontrol yok — yani ajan modunda
// da AYNEN kosar. Bu bir bosluk degil bir karar: teshis, "baska her sey hata
// veriyor" anindaki ilk komut, ve deger BASMADIGI icin kisitlanmasi gerekmiyor
// (`secrets status` ile ayni gerekce).
//
// ORACLE: cmd/doctor.go, internal/tofu/preflight.go (RequiredEnvVars),
// internal/session/session.go (Load/Expired/TTL).

// RequiredEnvVar + REQUIRED_ENV_VARS ARTIK BURADA TANIMLI DEGIL.
//
// Go'da bu kontrat `internal/tofu`ya ait ve UC cagiran onu paylasiyor. Rust'ta
// tek cagiran `doctor` oldugu surece burada durmasi dogruydu; `dr bootstrap`
// IKINCI cagiran olunca sahiplik Go'daki yerine geri tasindi. KOPYA
// CIKARILMADI: iki liste ayri ayri yasasaydi, kontrata eklenen bir degisken
// birinde gorunup digerinde gorunmeyebilir ve `tofu.rs`teki superset
// degismezi SESSIZCE anlamsizlasirdi.
pub use crate::tofu::{RequiredEnvVar, REQUIRED_ENV_VARS};

/// FULL_TOOLS, tam bataryanin aradigi CLI araclari.
///
/// `age` BILEREK YOK: sifreli arsivle birlikte dusuruldu ve hicbir sey ona
/// shell out etmiyor. Raporlanmaya devam etseydi operatorleri bu CLI'nin
/// artik kullanmadigi bir ikiliyi kurmaya gonderirdi.
///
/// `opentofu` GORUNEN ad, `tofu` ARANAN ad — tek ayrisan cift.
pub const FULL_TOOLS: &[(&str, &str)] = &[
    ("opentofu", "tofu"),
    ("git", "git"),
    ("jq", "jq"),
    ("gh", "gh"),
    ("cloudflared", "cloudflared"),
];

/// look_path, Go'nun `exec.LookPath`i gibi PATH'te calistirilabilir bir dosya
/// arar.
///
/// Adda AYIRAC varsa PATH'e HIC bakilmaz (Go ile ayni): dogrudan o yol denenir.
/// Bir DIZIN esleşme SAYILMAZ — aksi halde PATH'te `git/` adli bir dizin,
/// eksik bir ikiliyi "var" gosterirdi.
pub fn look_path(
    name: &str,
    path_env: &str,
    is_executable: &dyn Fn(&std::path::Path) -> bool,
) -> bool {
    if name.contains('/') {
        return is_executable(std::path::Path::new(name));
    }
    for dir in path_env.split(':') {
        // Go: bos bir PATH girdisi "." demektir.
        let dir = if dir.is_empty() { "." } else { dir };
        if is_executable(&std::path::Path::new(dir).join(name)) {
            return true;
        }
    }
    false
}

/// is_executable_file, bir yolun VAR olan, DIZIN OLMAYAN ve calistirilabilir
/// bit tasiyan bir dosya oldugunu soyler.
pub fn is_executable_file(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// go_duration, Go'nun `time.Duration.String()`inin SANIYE cozunurluklu
/// halidir (cagiran zaten `Round(time.Second)` uyguluyor).
///
/// BICIM TAHMIN EDILMEDI, Go'dan OLCULDU (tests/doctorverb.rs'teki tablo o
/// olcumun kendisi). Sasirtan uc nokta:
///   - 3599 → "59m59s": saat hanesi SIFIRSA HIC yazilmaz;
///   - 3600 → "1h0m0s": ama saat varsa dakika ve saniye SIFIR olsa da yazilir;
///   - 86400 → "24h0m0s": saatler GUNE cevrilmez, buyumeye devam eder.
pub fn go_duration(secs: i64) -> String {
    if secs == 0 {
        return "0s".to_string();
    }
    let sign = if secs < 0 { "-" } else { "" };
    let a = secs.unsigned_abs();
    let (h, m, s) = (a / 3600, (a % 3600) / 60, a % 60);
    if h > 0 {
        format!("{sign}{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{sign}{m}m{s}s")
    } else {
        format!("{sign}{s}s")
    }
}

/// coolify_health_endpoint, operatorun taban COOLIFY_URL'inden /health URL'ini
/// turetir.
///
/// TABANI OLDUGU GIBI KULLANMAK BIR HATAYDI ve duzeltmesi burada duruyor:
/// COOLIFY_URL sozlesme geregi TABAN url'dir (cmd/coolify ile paylasilan
/// konvansiyon), o yuzden prob tabana degil `/health`e gitmeli. Aksi halde
/// tabani duz bir GET'e 2xx donmeyen her operator SAHTE bir hata gorurdu.
pub fn coolify_health_endpoint(base: &str) -> String {
    if base.is_empty() {
        return "https://coolify.meapps.dev/api/v1/health".to_string();
    }
    if base.ends_with("/health") {
        return base.to_string();
    }
    if base.ends_with('/') {
        return format!("{base}health");
    }
    format!("{base}/health")
}

/// tofu_env_report, `--for tofu` govdesini uretir ve hepsinin hazir olup
/// olmadigini doner.
///
/// SIRA GOZLEMLENEBILIR: once MEVCUT degiskenler kontrat sirasinda, SONRA
/// eksikler yine kontrat sirasinda. Iki blok Go'da ayri dongulerden geliyor.
pub fn tofu_env_report(tofu_present: bool, get: &dyn Fn(&str) -> String) -> (String, bool) {
    let mut out = String::new();
    let mut all_ok = true;
    if tofu_present {
        out.push_str("✓ tofu binary present\n");
    } else {
        out.push_str("✗ tofu binary not found in PATH\n");
        all_ok = false;
    }
    let mut missing = Vec::new();
    for r in REQUIRED_ENV_VARS {
        if get(r.name).is_empty() {
            missing.push(r);
        } else {
            out.push_str(&format!("✓ {} set\n", r.name));
        }
    }
    for r in &missing {
        out.push_str(&format!("✗ {} not set ({})\n", r.name, r.hint));
        all_ok = false;
    }
    if !all_ok {
        out.push_str("\nRun: wapps secrets sync (will print recovery snippet for missing env)\n");
        return (out, false);
    }
    out.push_str("\n✓ Tofu environment ready for sync.\n");
    (out, true)
}

/// SessionState, bir oturumun UC DURUMUDUR — ve uc olmasi sart.
///
/// `secrets status` bunu IKI durumda topluyor (`session_valid` bool) ve orada
/// dogru: makine-okunur sema yalnizca "kullanilabilir mi" soruyor. doctor bir
/// OPERATOR arayuzu ve Go burada UC AYRI cumle basiyor: oturum YOK, oturum
/// DOLMUS, oturum CANLI. Ilk ikisi ayni komutla cozuluyor ama operator
/// hangisinin oldugunu bilmeli — "hic giris yapmadim" ile "girisim dustu"
/// ayni teshis degil.
///
/// VARYANTLARDA JETON YOK ve bu yapisal: bu tipe bir jeton koymamak, teshis
/// yolunun bir jetonu yanlislikla bicimlendirmesini IMKANSIZ kilar.
#[derive(Debug, PartialEq, Eq)]
pub enum SessionState {
    Absent,
    Expired,
    Live { ttl_secs: i64 },
}

/// session_state, bir oturumu UC durumdan birine cozer (env → dosya).
///
/// SIRA Go ile ayni (session.Load): once out-of-band env jetonu, sonra dosya.
/// Env jetonu HOST'TAN BAGIMSIZ okunuyor — yani WAPPS_SESSION_TOKEN doluyken
/// okuma VE admin oturumlarinin IKISI de canli gorunur. Bu Go'nun davranisi
/// ve olculdu; bir "duzeltme" sahadaki ikiliyle ayrisma demek olurdu.
///
/// `expires_at == 0` → expiry BILINMIYOR (out-of-band jeton) → dolmaz sayilir,
/// kalan 0 raporlanir. Gate yine de kenarda dogruluyor.
pub fn session_state(
    env: &dyn Fn(&str) -> Option<String>,
    session_path: &std::path::Path,
    now_unix: i64,
) -> SessionState {
    let expires_at = match env("WAPPS_SESSION_TOKEN").filter(|t| !t.is_empty()) {
        Some(_) => env("WAPPS_SESSION_EXPIRES")
            .and_then(|e| e.parse::<i64>().ok())
            .unwrap_or(0),
        None => {
            let Ok(raw) = std::fs::read(session_path) else {
                return SessionState::Absent;
            };
            // Bozuk JSON ya da BOS jeton → oturum YOK (Go: Unmarshal hatasi
            // veya s.Token == "" → ok=false).
            match serde_json::from_slice::<SessionFile>(&raw) {
                Ok(f) if !f.token.is_empty() => f.expires_at,
                _ => return SessionState::Absent,
            }
        }
    };
    if expires_at != 0 && expires_at <= now_unix {
        return SessionState::Expired;
    }
    if expires_at == 0 {
        return SessionState::Live { ttl_secs: 0 };
    }
    SessionState::Live {
        ttl_secs: expires_at - now_unix,
    }
}

// SessionFile, diskteki oturum dosyasidir. `token` YALNIZCA bos olup
// olmadigina bakilmak icin okunuyor; degeri hicbir yere gitmiyor.
#[derive(serde::Deserialize)]
struct SessionFile {
    #[serde(default)]
    token: String,
    #[serde(default)]
    expires_at: i64,
}

/// render_session_lines, iki oturum satirini uretir (okuma + admin) ve okuma
/// oturumunun kosumu dusurup dusurmedigini doner.
///
/// ADMIN OTURUMU OPSIYONEL: yoklugu `·` ile raporlanir ve kosumu DUSURMEZ.
/// Isin cogu kontrol duzlemine hic dokunmuyor, o yuzden "admin oturumu yok"
/// bir hata degil bir NOT. `all_ok`a KATKI VERMEZ — ve admin DOLMUS olsa bile
/// ayni `·` satiri basilir (Go: `ok && !Expired` tek dala bakiyor).
pub fn render_session_lines(
    host: &str,
    read: &SessionState,
    admin: &SessionState,
) -> (String, bool) {
    let mut out = String::new();
    let mut ok = true;
    match read {
        SessionState::Absent => {
            out.push_str(&format!(
                "✗ no secrets-gate session for {host} — run 'wapps login'\n"
            ));
            ok = false;
        }
        SessionState::Expired => {
            out.push_str(&format!(
                "✗ secrets-gate session for {host} expired — run 'wapps login'\n"
            ));
            ok = false;
        }
        SessionState::Live { ttl_secs } => {
            out.push_str(&format!(
                "✓ secrets-gate session live ({})\n",
                go_duration(*ttl_secs)
            ));
        }
    }
    match admin {
        SessionState::Live { ttl_secs } => out.push_str(&format!(
            "✓ admin (write-AUD) session live ({})\n",
            go_duration(*ttl_secs)
        )),
        _ => out.push_str("· no admin session — 'wapps login --write' when editing policy\n"),
    }
    (out, ok)
}
