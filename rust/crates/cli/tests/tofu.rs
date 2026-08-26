// tofu — `internal/tofu` portunun OLCUSU.
//
// NEDEN BU DOSYA VAR: `dr bootstrap`in Rust'ta olmamasinin GEREKCESI
// "internal/tofu portu gerekiyor, Rust'ta tofu modulu YOK" idi (drverb.rs
// basligi). O gerekce YARISI BAYATTI ve bu serit onu OLCEREK curuttu:
// `REQUIRED_ENV_VARS` (bes girdi, adlar VE ipuclari) `doctorverb.rs` icinde
// ZATEN duruyordu. Eksik olan yalnizca iki sey vardi: `PreflightEnv`in METNI
// ve `BootstrapEnvVars` katalogu. Ikisi de SAF veri/bicimleme — ag yok,
// disk yok.
//
// ORACLE: internal/tofu/preflight.go. Asagidaki iki metin ELLE YAZILMADI;
// Go'nun KENDI `PreflightEnv` ciktisindan (gecici bir Go testiyle hex olarak)
// dokuldu, yani bir transkripsiyon hatasi tasiyamazlar.
//
// NEGATIF DAL UYARISI: bu dosya POZITIF vektorleri tutuyor. `preflight_env`in
// EKSIK-degisken dali (yani reddin kendisi) `preflight_env_*_missing_*`
// testleriyle YURUNUYOR; `bootstrap`in reddi ise differential korpusunda
// (`dr_bootstrap_preflight_fails`) olculuyor.
use wapps::tofu;

fn lookup_from<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> String + 'a {
    move |k: &str| {
        pairs
            .iter()
            .find(|(n, _)| *n == k)
            .map(|(_, v)| v.to_string())
            .unwrap_or_default()
    }
}

const FULL: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY_ID", "key"),
    ("AWS_SECRET_ACCESS_KEY", "secret"),
    ("AWS_ENDPOINT_URL_S3", "https://r2.example.com"),
    ("AWS_REGION", "auto"),
    ("TF_VAR_state_passphrase", "passphrase"),
];

/// Go: TestPreflightEnv_AllPresent.
#[test]
fn preflight_env_passes_when_every_required_var_is_set() {
    let get = lookup_from(FULL);
    assert_eq!(tofu::preflight_env(&get), None);
}

// GO'NUN KENDI CIKTISI (hex dokumunden). Tek bir bayti bile degistirmek
// sahadaki ikiliden AYRISMA demektir.
const GO_PREFLIGHT_NOTHING_SET: &str = r#"tofu preflight: required environment not set.

Missing:
  - AWS_ACCESS_KEY_ID (R2 backend credentials (map from WAPPS_R2_ACCESS_KEY_ID))
  - AWS_SECRET_ACCESS_KEY (R2 backend credentials (map from WAPPS_R2_SECRET_ACCESS_KEY))
  - AWS_ENDPOINT_URL_S3 (R2 backend endpoint (map from WAPPS_R2_ENDPOINT))
  - AWS_REGION (R2 backend region (must be 'auto' for Cloudflare R2))
  - TF_VAR_state_passphrase (Tofu encryption block (map from WAPPS_TOFU_STATE_PASSPHRASE))

Recovery (paste into your shell, sourcing your project secrets first):

  set -a
  source ~/.config/<project>/secrets.env
  set +a
  export AWS_ACCESS_KEY_ID="$WAPPS_R2_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$WAPPS_R2_SECRET_ACCESS_KEY"
  export AWS_ENDPOINT_URL_S3="$WAPPS_R2_ENDPOINT"
  export AWS_REGION=auto
  export TF_VAR_state_passphrase="$WAPPS_TOFU_STATE_PASSPHRASE""#;

const GO_PREFLIGHT_ONE_MISSING: &str = r#"tofu preflight: required environment not set.

Missing:
  - TF_VAR_state_passphrase (Tofu encryption block (map from WAPPS_TOFU_STATE_PASSPHRASE))

Recovery (paste into your shell, sourcing your project secrets first):

  set -a
  source ~/.config/<project>/secrets.env
  set +a
  export AWS_ACCESS_KEY_ID="$WAPPS_R2_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$WAPPS_R2_SECRET_ACCESS_KEY"
  export AWS_ENDPOINT_URL_S3="$WAPPS_R2_ENDPOINT"
  export AWS_REGION=auto
  export TF_VAR_state_passphrase="$WAPPS_TOFU_STATE_PASSPHRASE""#;

/// Go: TestPreflightEnv_NamesMissingVarsInOrder + _IncludesRecoverySnippet.
/// Parcaci degil TAM METIN: Go'nun kendi testi yalnizca FRAGMAN ariyor, yani
/// kurtarma parcacigindaki bir satir sessizce degisebilirdi.
#[test]
fn preflight_env_text_is_byte_identical_to_go_when_nothing_is_set() {
    let get = |_: &str| String::new();
    let got = tofu::preflight_env(&get).expect("hicbir sey set degilken hata BEKLENIYOR");
    assert_eq!(got, GO_PREFLIGHT_NOTHING_SET);
}

/// Go: TestPreflightEnv_SingleMissingVarNamedSpecifically.
#[test]
fn preflight_env_text_is_byte_identical_to_go_for_a_single_missing_var() {
    let get = lookup_from(&FULL[..4]); // TF_VAR_state_passphrase BILEREK yok
    let got = tofu::preflight_env(&get).expect("eksik degisken icin hata BEKLENIYOR");
    assert_eq!(got, GO_PREFLIGHT_ONE_MISSING);
    // Eksik OLMAYAN degiskenler eksik listesinde GORUNMEMELI.
    let missing_section = got.split("Recovery").next().unwrap();
    assert!(!missing_section.contains("AWS_ACCESS_KEY_ID"));
}

// GO KATALOGU (ad, ipucu, sabit) — `BootstrapEnvVars`tan dokuldu.
const GO_BOOTSTRAP_CATALOG: &[(&str, &str, &str)] = &[
    (
        "AWS_ACCESS_KEY_ID",
        "R2 backend credentials (dashboard-mint R2 access key)",
        "",
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        "R2 backend credentials (dashboard-mint R2 secret key)",
        "",
    ),
    (
        "AWS_ENDPOINT_URL_S3",
        "R2 backend endpoint (https://<account_id>.r2.cloudflarestorage.com)",
        "",
    ),
    (
        "AWS_REGION",
        "R2 backend region (Cloudflare R2 için sabit 'auto' — promptlanmaz)",
        "auto",
    ),
    (
        "TF_VAR_state_passphrase",
        "Tofu state encryption passphrase (paper envelope — kağıt custody)",
        "",
    ),
    (
        "TF_VAR_cloudflare_api_token",
        "Cloudflare API token (dashboard-mint; scope-policy dokümanına uygun)",
        "",
    ),
    (
        "TF_VAR_cloudflare_r2_api_token",
        "Cloudflare R2 API token (dashboard-mint)",
        "",
    ),
    (
        "TF_VAR_hcloud_token",
        "Hetzner Cloud API token (console-mint)",
        "",
    ),
    (
        "TF_VAR_coolify_token",
        "Coolify API token (dashboard-mint)",
        "",
    ),
];

/// Katalog Go ile BIREBIR: ad, ipucu ve sabit. Sira da dahil, cunku prompt
/// akisi bu sirayi izliyor ve operator onu GORUYOR.
#[test]
fn bootstrap_catalog_matches_go_byte_for_byte() {
    let got: Vec<(&str, &str, &str)> = tofu::BOOTSTRAP_ENV_VARS
        .iter()
        .map(|v| (v.name, v.hint, v.constant))
        .collect();
    assert_eq!(got.as_slice(), GO_BOOTSTRAP_CATALOG);
}

/// Go'nun SUPERSET degismezi (preflight_test.go yorumu): kontrata eklenen her
/// yeni degisken kataloga da girmek ZORUNDA, yoksa bootstrap'lanan bir apply
/// kendi preflight'inda duser.
#[test]
fn bootstrap_catalog_is_a_superset_of_the_backend_contract() {
    for r in tofu::REQUIRED_ENV_VARS {
        assert!(
            tofu::BOOTSTRAP_ENV_VARS.iter().any(|b| b.name == r.name),
            "kontrat degiskeni {} katalogda YOK",
            r.name
        );
    }
}

/// Sabit degerli girdi PROMPTLANAMAZ, ve tam olarak BIR tane var.
#[test]
fn aws_region_is_the_only_non_promptable_entry() {
    let constants: Vec<&str> = tofu::BOOTSTRAP_ENV_VARS
        .iter()
        .filter(|v| !v.promptable())
        .map(|v| v.name)
        .collect();
    assert_eq!(constants, vec!["AWS_REGION"]);
    let r = tofu::BOOTSTRAP_ENV_VARS
        .iter()
        .find(|v| v.name == "AWS_REGION")
        .unwrap();
    assert_eq!(r.constant, "auto");
}
