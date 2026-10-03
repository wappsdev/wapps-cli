// `doctor`in DIFFERENTIAL'DA OLCULEMEYEN yuzeyi.
//
// Iki sey buraya dustu ve ikisinin de sebebi harness'in bir sinirinda:
//
//  1. SIFIR OLMAYAN oturum TTL'i. Bicim `time.Duration.String()`, ama deger
//     `expires_at - now` ve iki probe kosumu arasinda ~40 sn geciyor: AYNI env
//     Go tarafinda "59m59s", Rust tarafinda "59m20s" uretirdi ve vaka sahte
//     bir ayrisma verirdi. Bicim bu yuzden burada, GO'DAN OLCULMUS bir tabloyla
//     pinleniyor (bkz. asagidaki DURATIONS).
//
//  2. "okuma oturumu CANLI ama admin YOK" bilesimi. session.Load env jetonunu
//     HOST'TAN BAGIMSIZ okuyor, yani WAPPS_SESSION_TOKEN doluyken ikisi de
//     canli gorunur; ayrik hale ancak dosya-tabanli oturumla gelinir ve
//     probe.py XDG altina dosya tohumlamiyor.
use wapps::doctorverb::{
    coolify_health_endpoint, go_duration, look_path, session_state, tofu_env_report, SessionState,
};

// GO'DAN OLCULEN TABLO: `time.Duration(n) * time.Second` uzerinde
// `.Round(time.Second).String()`.
const DURATIONS: &[(i64, &str)] = &[
    (0, "0s"),
    (1, "1s"),
    (59, "59s"),
    // Dakika esigi: saniye SIFIR olsa bile yaziliyor.
    (60, "1m0s"),
    (61, "1m1s"),
    (90, "1m30s"),
    (600, "10m0s"),
    // SASIRTICI: saat hanesi SIFIRSA HIC yazilmiyor — "0h59m59s" DEGIL.
    (3599, "59m59s"),
    // ...ama saat varsa dakika ve saniye sifir olsa da yaziliyor.
    (3600, "1h0m0s"),
    (3661, "1h1m1s"),
    (86399, "23h59m59s"),
    // SASIRTICI: saatler GUNE cevrilmiyor, buyumeye devam ediyor.
    (86400, "24h0m0s"),
    (90061, "25h1m1s"),
    (360000, "100h0m0s"),
    (1000000, "277h46m40s"),
    // Negatif: isaret EN BASTA, her hanenin basinda DEGIL.
    (-1, "-1s"),
    (-61, "-1m1s"),
    (-3661, "-1h1m1s"),
];

#[test]
fn duration_is_formatted_the_way_go_formats_it() {
    for (secs, want) in DURATIONS {
        assert_eq!(&go_duration(*secs), want, "{secs} saniye icin");
    }
}

// COOLIFY_URL sozlesme geregi TABAN url'dir; prob tabana degil `/health`e
// gitmeli. Tabani oldugu gibi kullanmak, tabana duz bir GET'e 2xx donmeyen her
// operatore SAHTE bir hata gosterirdi — bu duzeltmenin kendisi Go tarafinda
// bir yorum olarak duruyor.
#[test]
fn the_coolify_probe_targets_health_not_the_base_url() {
    assert_eq!(
        coolify_health_endpoint(""),
        "https://coolify.meapps.dev/api/v1/health",
        "bos taban VARSAYILANA dusmeli"
    );
    assert_eq!(
        coolify_health_endpoint("https://x.invalid/api/v1"),
        "https://x.invalid/api/v1/health"
    );
    // Sondaki egik cizgi CIFTLENMEMELI.
    assert_eq!(
        coolify_health_endpoint("https://x.invalid/api/v1/"),
        "https://x.invalid/api/v1/health"
    );
    // Zaten /health ile bitiyorsa IKINCI kez eklenmemeli.
    assert_eq!(
        coolify_health_endpoint("https://x.invalid/health"),
        "https://x.invalid/health"
    );
}

fn exec_set<'a>(paths: &'a [&'a str]) -> impl Fn(&std::path::Path) -> bool + 'a {
    move |p| paths.iter().any(|x| std::path::Path::new(x) == p)
}

#[test]
fn look_path_walks_the_path_in_order() {
    let f = exec_set(&["/b/git"]);
    assert!(look_path("git", "/a:/b:/c", &f));
    assert!(!look_path("gh", "/a:/b:/c", &f));
}

// Adda AYIRAC varsa PATH'e HIC bakilmaz (Go ile ayni): dogrudan o yol denenir.
#[test]
fn a_name_with_a_separator_bypasses_the_path() {
    let f = exec_set(&["/b/git", "./tofu"]);
    assert!(look_path("./tofu", "/nowhere", &f));
    assert!(!look_path("/b/gh", "/b", &f));
}

// Bos bir PATH girdisi Go'da "." demektir. Bunu atlayan bir port, `PATH=:/b`
// gibi bir cevrede sessizce farkli davranirdi.
#[test]
fn an_empty_path_entry_means_the_current_directory() {
    let f = exec_set(&["./tofu"]);
    assert!(look_path("tofu", ":/b", &f));
}

// UC DURUM, IKI DEGIL: "oturum yok" ile "oturum dolmus" AYNI cumle degil.
// `secrets status` bunlari tek bir bool'da topluyor ve orada dogru; doctor bir
// OPERATOR arayuzu ve operator hangisinin oldugunu bilmeli.
#[test]
fn a_session_resolves_to_three_states_not_two() {
    let missing = std::path::Path::new("/nonexistent/session.json");
    let none = |_: &str| None;
    assert_eq!(session_state(&none, missing, 1000), SessionState::Absent);

    // Jeton var, expiry BILINMIYOR → canli, kalan 0.
    let unknown = |k: &str| (k == "WAPPS_SESSION_TOKEN").then(|| "t".to_string());
    assert_eq!(
        session_state(&unknown, missing, 1000),
        SessionState::Live { ttl_secs: 0 }
    );

    let with = |exp: &'static str| {
        move |k: &str| match k {
            "WAPPS_SESSION_TOKEN" => Some("t".to_string()),
            "WAPPS_SESSION_EXPIRES" => Some(exp.to_string()),
            _ => None,
        }
    };
    assert_eq!(
        session_state(&with("2000"), missing, 1000),
        SessionState::Live { ttl_secs: 1000 }
    );
    // `<=` : tam esitlik DOLMUS sayilir (Go: ExpiresAt <= now).
    assert_eq!(
        session_state(&with("1000"), missing, 1000),
        SessionState::Expired
    );
    assert_eq!(
        session_state(&with("999"), missing, 1000),
        SessionState::Expired
    );
    // AYRISTIRILAMAYAN bir expiry "bilinmiyor"a duser (Go: ParseInt hatasinda
    // exp 0 kalir) — oturumu DUSURMEZ.
    assert_eq!(
        session_state(&with("not-a-number"), missing, 1000),
        SessionState::Live { ttl_secs: 0 }
    );
}

// `--for tofu` raporunda SIRA sozlesme: once MEVCUT degiskenler kontrat
// sirasinda, SONRA eksikler yine kontrat sirasinda. Iki blok Go'da AYRI
// dongulerden geliyor, yani tek dongude basan bir port burada ayrisir.
#[test]
fn the_tofu_report_prints_present_vars_before_missing_ones() {
    let set = |k: &str| {
        // Kontratin 1. ve 4. degiskeni dolu; digerleri bos.
        if k == "AWS_ACCESS_KEY_ID" || k == "AWS_REGION" {
            "fake-not-a-secret".to_string()
        } else {
            String::new()
        }
    };
    let (out, ok) = tofu_env_report(false, &set);
    assert!(!ok);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "✗ tofu binary not found in PATH");
    assert_eq!(lines[1], "✓ AWS_ACCESS_KEY_ID set");
    assert_eq!(lines[2], "✓ AWS_REGION set");
    assert!(
        lines[3].starts_with("✗ AWS_SECRET_ACCESS_KEY not set"),
        "{out}"
    );
    assert!(
        lines[4].starts_with("✗ AWS_ENDPOINT_URL_S3 not set"),
        "{out}"
    );
    assert!(
        lines[5].starts_with("✗ TF_VAR_state_passphrase not set"),
        "{out}"
    );
}

// HEPSI hazir → tek sifir-cikisli doctor dali, ve KAPANIS satiri basiliyor.
#[test]
fn a_ready_tofu_environment_is_the_only_zero_exit_branch() {
    let (out, ok) = tofu_env_report(true, &|_| "fake-not-a-secret".to_string());
    assert!(ok);
    assert!(
        out.ends_with("\n✓ Tofu environment ready for sync.\n"),
        "{out}"
    );
    assert!(!out.contains('✗'), "{out}");
    // Kurtarma ipucu YALNIZCA basarisizlikta.
    assert!(!out.contains("wapps secrets sync"), "{out}");
}

// TESHIS CIKTISI BIR SIR TASIMAZ — ve bu tip duzeyinde yapisal: SessionState'in
// hicbir varyantinda jeton alani YOKTUR, yani teshis yolu bir jetonu
// bicimlendiremez. Bu testin kirilmasi, o kapinin acildigi anlamina gelir.
#[test]
fn the_session_state_type_carries_no_token() {
    let with = |k: &str| {
        (k == "WAPPS_SESSION_TOKEN").then(|| "canary-token-not-a-real-secret".to_string())
    };
    let st = session_state(&with, std::path::Path::new("/nonexistent"), 0);
    assert!(
        !format!("{st:?}").contains("canary-token"),
        "oturum durumu jetonu TASIMAMALI: {st:?}"
    );
}
