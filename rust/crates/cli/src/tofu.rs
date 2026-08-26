// tofu, `internal/tofu` portudur: `tofu output -json`in istedigi env
// KONTRATI, `wapps dr bootstrap`in env KATALOGU ve ikisini de kullanan
// `preflight_env`.
//
// NEDEN AYRI BIR MODUL: Go'da bu uc sey `internal/tofu` icinde TEK bir
// dogruluk kaynagi ve UC ayri cagiran onu paylasiyor (`secrets sync`,
// `doctor --for tofu`, `dr bootstrap`). Rust'ta kontrat parcasi
// (`REQUIRED_ENV_VARS`) `doctorverb.rs` icine gomulmustu — tek cagirani o
// oldugu surece dogru bir yerlestirmeydi. `dr bootstrap` IKINCI cagiran
// olunca Go'nun sahipligi geri kuruldu: katalog burada yasiyor, `doctorverb`
// onu YENIDEN IHRAC ediyor. Kopyalanmadi; kopyalansaydi iki liste sessizce
// ayrisabilirdi ve superset degismezi ANLAMINI yitirirdi.
//
// ORACLE: internal/tofu/preflight.go.

/// RequiredEnvVar, `tofu output -json`in baslangicta istedigi TEK bir degisken.
pub struct RequiredEnvVar {
    pub name: &'static str,
    pub hint: &'static str,
}

/// REQUIRED_ENV_VARS, backend env KONTRATI.
///
/// SIRA ONEMLI ve gozlemlenebilir: hem `doctor`un ✓/✗ satirlari hem
/// `preflight_env`in eksik listesi bu sirayi izliyor — kurtarma parcacigi
/// yukaridan asagi okunabilsin diye (Go yorumu: "Order matters").
pub const REQUIRED_ENV_VARS: &[RequiredEnvVar] = &[
    RequiredEnvVar {
        name: "AWS_ACCESS_KEY_ID",
        hint: "R2 backend credentials (map from WAPPS_R2_ACCESS_KEY_ID)",
    },
    RequiredEnvVar {
        name: "AWS_SECRET_ACCESS_KEY",
        hint: "R2 backend credentials (map from WAPPS_R2_SECRET_ACCESS_KEY)",
    },
    RequiredEnvVar {
        name: "AWS_ENDPOINT_URL_S3",
        hint: "R2 backend endpoint (map from WAPPS_R2_ENDPOINT)",
    },
    RequiredEnvVar {
        name: "AWS_REGION",
        hint: "R2 backend region (must be 'auto' for Cloudflare R2)",
    },
    RequiredEnvVar {
        name: "TF_VAR_state_passphrase",
        hint: "Tofu encryption block (map from WAPPS_TOFU_STATE_PASSPHRASE)",
    },
];

/// BootstrapEnvVar, `dr bootstrap`in cocuk env'ine enjekte ettigi TEK bir
/// degisken. IKI SINIF var ve ayrim GUVENLIKTIR:
///
///   - promptable (`constant` BOS): deger operatorden YANKISIZ istenir;
///   - sabit (`constant` DOLU): deger asla promptlanmaz, oldugu gibi enjekte
///     edilir (AWS_REGION=auto — Cloudflare R2 sozlesmesi).
///
/// Bir sabiti promptlamak operatore "bunu sen uydur" demek olurdu; bir
/// promptable'i sabitlemek ise bir TOKEN'i kaynak koda gommek.
pub struct BootstrapEnvVar {
    pub name: &'static str,
    pub hint: &'static str,
    pub constant: &'static str,
}

impl BootstrapEnvVar {
    /// promptable, degiskenin operatorden interaktif istenip istenmeyecegi.
    pub fn promptable(&self) -> bool {
        self.constant.is_empty()
    }
}

/// BOOTSTRAP_ENV_VARS, `dr bootstrap` katalogu: backend kontratinin TAMAMI +
/// dashboard-mint provisioning girdileri.
///
/// SUPERSET DEGISMEZI (BOOTSTRAP_ENV_VARS ⊇ REQUIRED_ENV_VARS) tests/tofu.rs'te
/// korunuyor: kontrata eklenen bir degisken buraya girmezse, bootstrap'lanan
/// apply KENDI preflight'inda duser — yani hata operatore seremoninin
/// ORTASINDA, token'lar zaten mint edilmisken gorunur.
///
/// Sira Go ile AYNI (once kontrat, sonra provisioning) ve GOZLEMLENEBILIR:
/// prompt akisi bu sirada iliyor.
pub const BOOTSTRAP_ENV_VARS: &[BootstrapEnvVar] = &[
    // Backend env kontrati (REQUIRED_ENV_VARS aynasi).
    BootstrapEnvVar {
        name: "AWS_ACCESS_KEY_ID",
        hint: "R2 backend credentials (dashboard-mint R2 access key)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "AWS_SECRET_ACCESS_KEY",
        hint: "R2 backend credentials (dashboard-mint R2 secret key)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "AWS_ENDPOINT_URL_S3",
        hint: "R2 backend endpoint (https://<account_id>.r2.cloudflarestorage.com)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "AWS_REGION",
        hint: "R2 backend region (Cloudflare R2 için sabit 'auto' — promptlanmaz)",
        constant: "auto",
    },
    BootstrapEnvVar {
        name: "TF_VAR_state_passphrase",
        hint: "Tofu state encryption passphrase (paper envelope — kağıt custody)",
        constant: "",
    },
    // Provisioning girdileri: dashboard/console'da INSAN mint ediyor, TTY'den
    // giriliyor; diske/store'a YAZILMIYOR (§3.3).
    BootstrapEnvVar {
        name: "TF_VAR_cloudflare_api_token",
        hint: "Cloudflare API token (dashboard-mint; scope-policy dokümanına uygun)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "TF_VAR_cloudflare_r2_api_token",
        hint: "Cloudflare R2 API token (dashboard-mint)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "TF_VAR_hcloud_token",
        hint: "Hetzner Cloud API token (console-mint)",
        constant: "",
    },
    BootstrapEnvVar {
        name: "TF_VAR_coolify_token",
        hint: "Coolify API token (dashboard-mint)",
        constant: "",
    },
];

/// preflight_env, kontrattaki her degiskenin set oldugunu dogrular.
///
/// `None` = gecti. `Some(metin)` = eksik var; metin hem EKSIK ADLARI hem
/// operatorun kabuguna yapistirabilecegi KURTARMA parcacigini tasir.
///
/// Go `error` donduruyor, burada `Option<String>`: Rust'ta bu deger bir
/// `clierr::Error` degil, cagiranin kendi onekiyle sardigi DUZ bir metin
/// (Go'da da `fmt.Errorf("%s", b.String())` — kodsuz).
///
/// `lookup` dependency-injected: cagiran taraf ebeveyn env'ini MUTASYONA
/// UGRATMADAN "enjekte edilen + kalitilan" birlesik gorunumu verebiliyor.
pub fn preflight_env(lookup: &dyn Fn(&str) -> String) -> Option<String> {
    let missing: Vec<&RequiredEnvVar> = REQUIRED_ENV_VARS
        .iter()
        .filter(|r| lookup(r.name).is_empty())
        .collect();
    if missing.is_empty() {
        return None;
    }

    let mut b = String::new();
    b.push_str("tofu preflight: required environment not set.\n\n");
    b.push_str("Missing:\n");
    for r in &missing {
        b.push_str(&format!("  - {} ({})\n", r.name, r.hint));
    }
    b.push_str("\nRecovery (paste into your shell, sourcing your project secrets first):\n\n");
    b.push_str("  set -a\n");
    b.push_str("  source ~/.config/<project>/secrets.env\n");
    b.push_str("  set +a\n");
    b.push_str("  export AWS_ACCESS_KEY_ID=\"$WAPPS_R2_ACCESS_KEY_ID\"\n");
    b.push_str("  export AWS_SECRET_ACCESS_KEY=\"$WAPPS_R2_SECRET_ACCESS_KEY\"\n");
    b.push_str("  export AWS_ENDPOINT_URL_S3=\"$WAPPS_R2_ENDPOINT\"\n");
    b.push_str("  export AWS_REGION=auto\n");
    // SON satirda `\n` YOK — Go'nun son WriteString'i de tasimiyor. Bir
    // yenisatir eklemek differential'da AYRISMA olurdu.
    b.push_str("  export TF_VAR_state_passphrase=\"$WAPPS_TOFU_STATE_PASSPHRASE\"");
    Some(b)
}
